"""
MCP Client Bridge — connects the sync SecurityAgent to async MCP servers.

Architecture:
  - Each MCP server runs as a subprocess (stdio transport)
  - A background asyncio event loop manages all server connections
  - Sync wrapper methods queue coroutines and return results via futures

Usage:
  bridge = MCPBridge()
  bridge.start()   # Launches servers and connects
  result = bridge.call("splunk-query", "splunk_search", {"query": "..."})
  bridge.stop()
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import Future
from typing import Optional

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

# ── Server configurations ─────────────────────────────────────────────────

SERVERS = {
    "splunk-query": {
        "module": "analyst.servers.splunk_mcp",
        "env": {},
    },
    "gateway-control": {
        "module": "analyst.servers.gateway_mcp",
        "env": {},
    },
    "rule-engine": {
        "module": "analyst.servers.rule_mcp",
        "env": {},
    },
}

# ── MCP Bridge ────────────────────────────────────────────────────────────

class MCPBridge:
    """
    Manages connections to multiple MCP servers.

    Launches each server as a subprocess, connects via stdio,
    and provides synchronous tool-calling methods.
    """

    def __init__(self, server_names: list[str] | None = None):
        """
        Args:
            server_names: List of server names to connect to.
                          Defaults to all SERVERS keys.
        """
        self._server_names = server_names or list(SERVERS.keys())
        self._sessions: dict[str, ClientSession] = {}
        self._processes: dict[str, subprocess.Popen] = {}
        self._write_streams: dict[str, any] = {}
        self._read_streams: dict[str, any] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._running = False
        self._last_error: dict[str, str] = {}

    # ── Public API ────────────────────────────────────────────────────

    def start(self, timeout: float = 30.0) -> bool:
        """
        Launch all MCP servers and establish connections.

        Returns True if at least one server connected successfully.
        """
        if self._running:
            return True

        self._running = True
        self._thread = threading.Thread(target=self._run_event_loop,
                                        daemon=True)
        self._thread.start()

        # Wait for connections
        connected = self._ready.wait(timeout=timeout)
        if not connected:
            print("[MCP] Warning: Connection timeout — some servers may be unavailable")
        return any(
            name in self._sessions for name in self._server_names
        )

    def stop(self):
        """Disconnect from all servers and terminate processes."""
        self._running = False

        # Close session and stdio contexts (schedule on event loop)
        if self._loop and not self._loop.is_closed():
            async def _cleanup():
                for name in list(getattr(self, '_session_ctxs', {}).keys()):
                    try:
                        await self._session_ctxs[name].__aexit__(None, None, None)
                    except Exception:
                        pass
                for name in list(getattr(self, '_stdio_ctxs', {}).keys()):
                    try:
                        await self._stdio_ctxs[name].__aexit__(None, None, None)
                    except Exception:
                        pass
            try:
                asyncio.run_coroutine_threadsafe(_cleanup(), self._loop).result(timeout=5)
            except Exception:
                pass

            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass

        self._sessions.clear()

    def call(self, server: str, tool: str, args: dict | None = None,
             timeout: float = 30.0) -> str:
        """
        Call a tool on an MCP server synchronously.

        Args:
            server: Server name (e.g., "splunk-query")
            tool: Tool name (e.g., "splunk_search")
            args: Tool arguments dict
            timeout: Maximum wait time in seconds

        Returns:
            JSON result string from the tool
        """
        if server not in self._sessions:
            return json.dumps({
                "error": f"Server '{server}' not connected",
                "_mcp_error": True,
            })

        try:
            future = asyncio.run_coroutine_threadsafe(
                self._call_async(server, tool, args or {}),
                self._loop,
            )
            return future.result(timeout=timeout)
        except TimeoutError:
            self._last_error[server] = f"Timeout calling {tool}"
            return json.dumps({
                "error": f"MCP call '{tool}' timed out after {timeout}s",
                "_mcp_error": True,
                "_timeout": True,
            })
        except Exception as e:
            self._last_error[server] = str(e)
            return json.dumps({
                "error": f"MCP call failed: {e}",
                "_mcp_error": True,
            })

    def is_connected(self, server: str) -> bool:
        """Check if a specific server is connected."""
        return server in self._sessions

    def get_errors(self) -> dict:
        """Return the last error for each server."""
        return dict(self._last_error)

    # ── Internal ──────────────────────────────────────────────────────

    def _run_event_loop(self):
        """Background thread: runs the asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect_all())
            # Keep the loop running for future tasks
            self._loop.run_forever()
        except Exception as e:
            print(f"[MCP] Event loop error: {e}")
        finally:
            self._loop.close()

    async def _connect_all(self):
        """Connect to all configured servers."""
        project_root = os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)
        ))
        python_exe = sys.executable

        for name in self._server_names:
            config = SERVERS.get(name)
            if not config:
                print(f"[MCP] Unknown server: {name}")
                continue

            try:
                session, streams = await self._connect_server(
                    name, config, python_exe, project_root
                )
                self._sessions[name] = session
                self._write_streams[name] = streams[0]
                self._read_streams[name] = streams[1]
                print(f"[MCP] Connected to {name}")
            except Exception as e:
                print(f"[MCP] Failed to connect {name}: {e}")
                self._last_error[name] = str(e)

        self._ready.set()

    async def _connect_server(self, name: str, config: dict,
                              python_exe: str, project_root: str):
        """Connect to a single MCP server via subprocess."""
        module_path = config["module"]
        env = os.environ.copy()
        env.update(config.get("env", {}))
        env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")

        server_params = StdioServerParameters(
            command=python_exe,
            args=["-m", module_path],
            env=env,
        )

        # Each server gets its own context managers, stored in per-server dicts
        if not hasattr(self, '_stdio_ctxs'):
            self._stdio_ctxs = {}
        if not hasattr(self, '_session_ctxs'):
            self._session_ctxs = {}

        self._stdio_ctxs[name] = stdio_client(server_params)
        read_stream, write_stream = await self._stdio_ctxs[name].__aenter__()

        self._session_ctxs[name] = ClientSession(read_stream, write_stream)
        session = await self._session_ctxs[name].__aenter__()
        await session.initialize()

        return session, (read_stream, write_stream)

    async def _call_async(self, server: str, tool: str, args: dict) -> str:
        """Execute an MCP tool call asynchronously."""
        session = self._sessions.get(server)
        if not session:
            return json.dumps({"error": f"Server {server} not connected"})

        result = await session.call_tool(tool, args)
        # result.content is a list of content blocks
        if result.content:
            for block in result.content:
                if hasattr(block, "text"):
                    return block.text
                elif isinstance(block, dict) and "text" in block:
                    return block["text"]
            # Return all content if no text found
            return json.dumps(
                [b.text if hasattr(b, "text") else str(b) for b in result.content],
                ensure_ascii=False,
            )
        return json.dumps({"result": "ok"})


# ── Standalone test ───────────────────────────────────────────────────────

def _test():
    """Quick connectivity test."""
    print("Testing MCP Bridge...")
    bridge = MCPBridge(["splunk-query"])
    ok = bridge.start(timeout=15.0)
    print(f"Start result: {ok}")

    if bridge.is_connected("splunk-query"):
        print("\n--- splunk_search ---")
        r = bridge.call("splunk-query", "splunk_search",
                        {"query": "injection", "earliest": "-24h"})
        print(r[:300])

        print("\n--- splunk_list_indexes ---")
        r = bridge.call("splunk-query", "splunk_list_indexes")
        print(r[:200])

        print("\n--- splunk_health ---")
        r = bridge.call("splunk-query", "splunk_health")
        print(r[:200])

    bridge.stop()
    print("Test complete.")


if __name__ == "__main__":
    _test()
