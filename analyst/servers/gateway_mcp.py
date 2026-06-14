"""
Gateway Control MCP Server — block/mode commands with real API fallback.

When GATEWAY_USE_REAL=true (and host/port/api_key configured), all block
and unblock commands are forwarded to the real AI Sentinel gateway's
/bans API. Otherwise, operations are simulated in-memory.

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
from typing import Optional

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from analyst.config import get_config

_gateway_cfg = get_config().gateway

server = Server("gateway-control-server")

# ── In-memory state (simulated mode) ────────────────────────────────────────

_gateway_state: dict = {
    "mode": "observe",
    "blocks_issued": 0,
    "block_history": [],
    "last_error": None,
}

# ── HTTP client for real gateway API ────────────────────────────────────────

_http_client: Optional[httpx.AsyncClient] = None


def _gateway_base_url() -> str:
    """Build the gateway base URL from config."""
    scheme = "https" if _gateway_cfg.port in (443, 8443) else "http"
    return f"{scheme}://{_gateway_cfg.host}:{_gateway_cfg.port}"


async def _get_http_client() -> httpx.AsyncClient:
    """Lazy-init the shared async HTTP client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        headers = {}
        if _gateway_cfg.api_key:
            headers["Authorization"] = f"Bearer {_gateway_cfg.api_key}"
        _http_client = httpx.AsyncClient(
            base_url=_gateway_base_url(),
            headers=headers,
            timeout=5.0,
            trust_env=False,  # Avoid proxy issues for local gateway
        )
    return _http_client


async def _call_real_gateway(method: str, path: str, payload: dict = None) -> Optional[dict]:
    """
    Call the real AI Sentinel gateway API.

    Args:
        method: HTTP method ("GET", "POST", "DELETE")
        path: API path (e.g., "/bans", "/health", "/policy")
        payload: JSON body for POST requests

    Returns:
        Response dict on success, None on failure.
    """
    if not _gateway_cfg.use_real or not _gateway_cfg.is_configured():
        return None

    client = await _get_http_client()
    try:
        if method == "GET":
            resp = await client.get(path)
        elif method == "POST":
            resp = await client.post(path, json=payload)
        elif method == "DELETE":
            resp = await client.delete(path)
        else:
            return None

        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        print(f"[Gateway MCP] Real API error: {e.response.status_code} {e.response.text}",
              file=sys.stderr)
        return None
    except httpx.ConnectError as e:
        print(f"[Gateway MCP] Cannot connect to gateway: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Gateway MCP] Real API call failed: {e}", file=sys.stderr)
        return None


# ── Tool implementations ──────────────────────────────────────────────────

async def _do_block(gateway_id: str, target: str, reason: str) -> str:
    """
    Block a target — tries real gateway /bans API first, then simulated.

    Real gateway mapping: POST /bans {ip=target, type="temp", ttl_seconds=3600, reason=reason}
    """
    # Try real gateway first
    real_result = await _call_real_gateway("POST", "/bans", {
        "ip": target,
        "type": "temp",
        "ttl_seconds": 3600,
        "reason": reason,
    })
    if real_result is not None:
        # Transform gateway response to MCP format
        record = {
            "block_id": real_result.get("ip", target),
            "gateway_id": gateway_id,
            "target": target,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "status": "blocked",
            "simulated": False,
            "real_api": True,
            "ban_record": real_result,
        }
        _gateway_state["blocks_issued"] += 1
        _gateway_state["block_history"].append(record)
        if len(_gateway_state["block_history"]) > 200:
            _gateway_state["block_history"] = _gateway_state["block_history"][-200:]
        print(f"[Gateway MCP] Real block: {target} @ {gateway_id} ({reason})",
              file=sys.stderr)
        return json.dumps(record, ensure_ascii=False)

    # Fallback: simulated
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
    if len(_gateway_state["block_history"]) > 200:
        _gateway_state["block_history"] = _gateway_state["block_history"][-200:]
    print(f"[Gateway MCP] Simulated block: {block_id} → {target} @ {gateway_id} ({reason})",
          file=sys.stderr)
    return json.dumps(record, ensure_ascii=False)


async def _do_unblock(target: str) -> str:
    """
    Unblock a target — tries real gateway DELETE /bans/{ip} first, then simulated.
    """
    # Try real gateway first
    real_result = await _call_real_gateway("DELETE", f"/bans/{target}")
    if real_result is not None:
        # Update local history
        for rec in _gateway_state["block_history"]:
            if rec["target"] == target and rec["status"] == "blocked":
                rec["status"] = "released"
                rec["released_at"] = datetime.now().isoformat()
                rec["real_api"] = True

        return json.dumps({
            "success": True,
            "target": target,
            "real_api": True,
            "gateway_response": real_result,
            "released_at": datetime.now().isoformat(),
        }, ensure_ascii=False)

    # Fallback: simulated
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
    """
    List block history — tries real gateway GET /bans first, merges with local.
    """
    # Try real gateway first
    real_result = await _call_real_gateway("GET", "/bans")
    if real_result is not None:
        real_bans = real_result.get("bans", [])
        # Merge: real bans + local simulated history
        all_blocks = []
        for ban in real_bans:
            all_blocks.append({
                "block_id": ban.get("ip", ""),
                "gateway_id": _gateway_cfg.host,
                "target": ban.get("ip", ""),
                "reason": ban.get("reason", ""),
                "timestamp": ban.get("created_at", ""),
                "status": "blocked",
                "simulated": False,
                "real_api": True,
                "ban_record": ban,
            })
        # Add simulated blocks not yet synced to real
        for rec in _gateway_state["block_history"]:
            if not rec.get("real_api"):
                all_blocks.append(rec)

        if target:
            all_blocks = [b for b in all_blocks if target.lower() in b.get("target", "").lower()]
        active = sum(1 for b in all_blocks if b.get("status") == "blocked")
        return json.dumps({
            "total": len(all_blocks),
            "active": active,
            "blocks": all_blocks[-50:],
            "truncated": len(all_blocks) > 50,
            "backend": "real",
        }, ensure_ascii=False)

    # Fallback: simulated
    blocks = _gateway_state["block_history"]
    if target:
        blocks = [b for b in blocks if target.lower() in b["target"].lower()]
    active = sum(1 for b in blocks if b["status"] == "blocked")
    return json.dumps({
        "total": len(blocks),
        "active": active,
        "blocks": blocks[-50:],
        "truncated": len(blocks) > 50,
    }, ensure_ascii=False)


async def _do_set_mode(mode: str) -> str:
    """
    Set gateway operation mode — tries real gateway PUT /policy first, then simulated.
    """
    if mode not in ("auto", "observe"):
        return json.dumps({"error": f"Invalid mode: {mode}. Use 'auto' or 'observe'."})

    # Try real gateway: map mode to policy preset
    preset_map = {"auto": "strict", "observe": "balanced"}
    real_result = await _call_real_gateway("POST", f"/policy/preset/{preset_map[mode]}")
    if real_result is not None:
        old_mode = _gateway_state["mode"]
        _gateway_state["mode"] = mode
        print(f"[Gateway MCP] Real mode change: {old_mode} → {mode}", file=sys.stderr)
        return json.dumps({
            "success": True,
            "old_mode": old_mode,
            "new_mode": mode,
            "real_api": True,
            "gateway_response": real_result,
            "timestamp": datetime.now().isoformat(),
        }, ensure_ascii=False)

    # Fallback: simulated
    old_mode = _gateway_state["mode"]
    _gateway_state["mode"] = mode
    print(f"[Gateway MCP] Simulated mode change: {old_mode} → {mode}", file=sys.stderr)
    return json.dumps({
        "success": True,
        "old_mode": old_mode,
        "new_mode": mode,
        "timestamp": datetime.now().isoformat(),
    })


async def _do_status() -> str:
    """Return gateway health status — probes real gateway if configured."""
    active_blocks = sum(1 for b in _gateway_state["block_history"] if b["status"] == "blocked")

    # Try real gateway health check
    real_result = await _call_real_gateway("GET", "/health")
    real_health = None
    if real_result is not None:
        real_health = real_result

    return json.dumps({
        "status": "healthy" if real_health or not _gateway_cfg.use_real else "degraded",
        "backend": "real" if _gateway_cfg.use_real else "simulated",
        "mode": _gateway_state["mode"],
        "blocks_issued": _gateway_state["blocks_issued"],
        "active_blocks": active_blocks,
        "host": _gateway_cfg.host,
        "port": _gateway_cfg.port,
        "use_real": _gateway_cfg.use_real,
        "is_configured": _gateway_cfg.is_configured(),
        "gateway_health": real_health,
        "timestamp": datetime.now().isoformat(),
    }, ensure_ascii=False)


async def _do_resolve_hold(hold_id: str, decision: str, reason: str, operator: str) -> str:
    """
    Resolve a gray-zone hold at the gateway (release / block), so the held
    front-end agent can proceed (release) or abort (block).
    Calls real gateway POST /hold/{id}/resolve when configured; else simulated.
    """
    real = await _call_real_gateway("POST", f"/hold/{hold_id}/resolve", {
        "decision": decision, "reason": reason, "operator": operator,
    })
    if real is not None:
        return json.dumps({"resolved": True, "hold_id": hold_id, "decision": decision,
                           "real_api": True, "gateway": real}, ensure_ascii=False)
    return json.dumps({"resolved": True, "hold_id": hold_id, "decision": decision,
                       "simulated": True,
                       "note": "gateway-control not connected to a real gateway; resolve simulated"}, ensure_ascii=False)


async def _do_add_gateway_rule(rule: dict) -> str:
    """
    Add/optimize a GATEWAY detection rule (rule_store) — the real 'optimize gateway
    policy' disposition. Calls real gateway POST /rules when configured; else simulated.
    `rule` is a partial rule dict; we normalize to the gateway RuleIn shape.
    """
    rid = rule.get("id") or rule.get("rule_id") or f"analyst-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    payload = {
        "id": rid,
        "name": rule.get("name", rid),
        "category": rule.get("category", "analyst_optimized"),
        "owasp_ast": rule.get("owasp_ast", "LLM01: Prompt Injection"),
        "severity_score": int(rule.get("severity_score", 75)),
        "engine": rule.get("engine", "keyword"),
        "patterns": rule.get("patterns", []),
        "flags": rule.get("flags", ["IGNORECASE"]),
        "enabled": True,
        "tags": rule.get("tags", ["analyst", "held_optimized"]),
        "description_zh": rule.get("description", rule.get("description_zh", "Gateway rule generated by analyst disposition")),
        "test_cases": rule.get("test_cases", {}),
    }
    # keyword engine needs params.keywords; regex engine uses patterns
    if payload["engine"] == "keyword":
        payload["params"] = {"keywords": payload["patterns"]}
    real = await _call_real_gateway("POST", "/rules", payload)
    if real is not None:
        return json.dumps({"added": True, "rule_id": rid, "real_api": True,
                           "rule": real}, ensure_ascii=False)
    return json.dumps({"added": True, "rule_id": rid, "simulated": True,
                       "rule": payload,
                       "note": "gateway-control not connected to a real gateway; rule addition simulated"}, ensure_ascii=False)


# ── MCP Tool definitions & handler ────────────────────────────────────────

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="send_block_command",
            description="Send a block command to a gateway. Connects to real gateway API when GATEWAY_USE_REAL=true, otherwise simulated.",
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
            description="Set gateway operation mode (auto or observe). Maps to policy preset on real gateway.",
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
            description="Get gateway health and status, including active block count. Probes real gateway when configured.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="list_blocks",
            description="List all block history, optionally filtered by target. Merges real gateway bans with local history.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Optional target filter (partial match)", "default": ""},
                },
            },
        ),
        Tool(
            name="unblock_target",
            description="Release a previously blocked target. Calls real gateway DELETE /bans/{ip} when configured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target to unblock (exact match)"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="resolve_hold",
            description="Resolve a gray-zone HELD request at the gateway so the held front-end agent can proceed (release) or abort (block). Calls POST /hold/{id}/resolve.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hold_id": {"type": "string", "description": "Hold id (== gateway event_id)"},
                    "decision": {"type": "string", "description": "'release' or 'block'"},
                    "reason": {"type": "string", "description": "Disposition reason", "default": ""},
                    "operator": {"type": "string", "description": "Who resolved it", "default": "analyst"},
                },
                "required": ["hold_id", "decision"],
            },
        ),
        Tool(
            name="add_gateway_rule",
            description="Optimize gateway policy: add a new detection rule to the gateway rule_store (POST /rules), so this attack pattern is cheaply blocked next time.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule": {"type": "object", "description": "Rule draft: {name, patterns[], engine, severity_score, description}"},
                },
                "required": ["rule"],
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
    elif name == "resolve_hold":
        result = await _do_resolve_hold(
            arguments.get("hold_id", ""),
            arguments.get("decision", "release"),
            arguments.get("reason", ""),
            arguments.get("operator", "analyst"),
        )
    elif name == "add_gateway_rule":
        result = await _do_add_gateway_rule(arguments.get("rule", {}) or {})
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
