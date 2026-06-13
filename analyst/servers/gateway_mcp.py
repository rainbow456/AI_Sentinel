"""
Gateway Control MCP Server — simulated block/mode commands with block list.

Tools:
  - send_block_command(gateway_id, target, reason) → block record
  - set_mode(mode) → new mode state
  - gateway_status() → health check + block count
  - list_blocks(target) → query block history (optional target filter)
  - unblock_target(target) → release a previously blocked target
"""

import asyncio
import json
import os
import sys
from datetime import datetime

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from analyst.config import get_config

_gateway_cfg = get_config().gateway

server = Server("gateway-control-server")

# ── In-memory state ───────────────────────────────────────────────────────

_gateway_state: dict = {
    "mode": "observe",
    "blocks_issued": 0,
    "block_history": [],
    "last_error": None,
}


# ── Tool implementations ──────────────────────────────────────────────────

async def _do_block(gateway_id: str, target: str, reason: str) -> str:
    """Simulate sending a block command to a gateway."""
    block_id = f"BLK-{datetime.now().strftime('%Y%m%d%H%M%S')}-{_gateway_state['blocks_issued']+1:04d}"

    record = {
        "block_id": block_id,
        "gateway_id": gateway_id,
        "target": target,
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
        "status": "blocked",
        "simulated": True,
    }

    _gateway_state["blocks_issued"] += 1
    _gateway_state["block_history"].append(record)

    # Keep only last 200
    if len(_gateway_state["block_history"]) > 200:
        _gateway_state["block_history"] = _gateway_state["block_history"][-200:]

    print(f"[Gateway MCP] Block issued: {block_id} → {target} @ {gateway_id} ({reason})",
          file=sys.stderr)
    return json.dumps(record, ensure_ascii=False)


async def _do_unblock(target: str) -> str:
    """Release a previously blocked target."""
    released = []
    remaining = []
    for rec in _gateway_state["block_history"]:
        if rec["target"] == target and rec["status"] == "blocked":
            rec["status"] = "released"
            rec["released_at"] = datetime.now().isoformat()
            released.append(rec)
        remaining.append(rec)

    _gateway_state["block_history"] = remaining

    if released:
        return json.dumps({
            "success": True,
            "target": target,
            "released_count": len(released),
            "released_at": datetime.now().isoformat(),
        }, ensure_ascii=False)
    return json.dumps({
        "success": False,
        "target": target,
        "error": "No active block found for this target",
    }, ensure_ascii=False)


async def _do_list_blocks(target: str = "") -> str:
    """List block history, optionally filtered by target."""
    blocks = _gateway_state["block_history"]
    if target:
        blocks = [b for b in blocks if target.lower() in b["target"].lower()]

    # Summarize active vs total
    active = sum(1 for b in blocks if b["status"] == "blocked")
    return json.dumps({
        "total": len(blocks),
        "active": active,
        "blocks": blocks[-50:],  # newest 50
        "truncated": len(blocks) > 50,
    }, ensure_ascii=False)


async def _do_set_mode(mode: str) -> str:
    """Set gateway operation mode."""
    if mode not in ("auto", "observe"):
        return json.dumps({"error": f"Invalid mode: {mode}. Use 'auto' or 'observe'."})

    old_mode = _gateway_state["mode"]
    _gateway_state["mode"] = mode
    print(f"[Gateway MCP] Mode changed: {old_mode} → {mode}", file=sys.stderr)
    return json.dumps({
        "success": True,
        "old_mode": old_mode,
        "new_mode": mode,
        "timestamp": datetime.now().isoformat(),
    })


async def _do_status() -> str:
    """Return gateway health status."""
    active_blocks = sum(1 for b in _gateway_state["block_history"] if b["status"] == "blocked")
    return json.dumps({
        "status": "healthy",
        "backend": "real" if _gateway_cfg.use_real else "simulated",
        "mode": _gateway_state["mode"],
        "blocks_issued": _gateway_state["blocks_issued"],
        "active_blocks": active_blocks,
        "host": _gateway_cfg.host,
        "port": _gateway_cfg.port,
        "use_real": _gateway_cfg.use_real,
        "is_configured": _gateway_cfg.is_configured(),
        "timestamp": datetime.now().isoformat(),
    }, ensure_ascii=False)


# ── MCP Tool definitions & handler ────────────────────────────────────────

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="send_block_command",
            description="Send a block command to a gateway. Returns block confirmation with block_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "gateway_id": {"type": "string", "description": "Target gateway ID"},
                    "target": {"type": "string", "description": "Target to block (IP, user, event_id)"},
                    "reason": {"type": "string", "description": "Reason for blocking"},
                },
                "required": ["gateway_id", "target", "reason"],
            },
        ),
        Tool(
            name="set_mode",
            description="Set gateway operation mode (auto or observe).",
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "description": "Mode: 'auto' or 'observe'"},
                },
                "required": ["mode"],
            },
        ),
        Tool(
            name="gateway_status",
            description="Get gateway health and status, including active block count.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="list_blocks",
            description="List all block history, optionally filtered by target. Returns active block count.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Optional target filter (partial match)", "default": ""},
                },
            },
        ),
        Tool(
            name="unblock_target",
            description="Release a previously blocked target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target to unblock (exact match)"},
                },
                "required": ["target"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "send_block_command":
        result = await _do_block(
            arguments.get("gateway_id", "gw-default"),
            arguments.get("target", arguments.get("event_id", "")),
            arguments.get("reason", "Rule triggered"),
        )
    elif name == "set_mode":
        result = await _do_set_mode(arguments.get("mode", "observe"))
    elif name == "gateway_status":
        result = await _do_status()
    elif name == "list_blocks":
        result = await _do_list_blocks(arguments.get("target", ""))
    elif name == "unblock_target":
        result = await _do_unblock(arguments.get("target", ""))
    else:
        result = json.dumps({"error": f"Unknown tool: {name}"})

    return [TextContent(type="text", text=result)]


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream,
                server.create_initialization_options(),
            )
    asyncio.run(_run())


if __name__ == "__main__":
    main()