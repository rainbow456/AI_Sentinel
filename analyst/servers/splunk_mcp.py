"""
Splunk Query MCP Server — standalone process exposing Splunk operations.

Tools:
  - splunk_search(query, earliest, latest) → event list
  - splunk_list_indexes() → index list
  - splunk_get_event(event_id, trace_id, query) → single event detail
  - splunk_health() → connection health check

Configuration is read from analyst/config.py (env-overridable):
  SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USERNAME, SPLUNK_PASSWORD, SPLUNK_TOKEN
  SPLUNK_USE_REAL=true to connect to real Splunk (default: simulated)

When SPLUNK_USE_REAL=true:
  - Uses splunk-sdk (splunklib) to connect to real Splunk instance
  - All search/list/health operations go through Splunk REST API
  - Falls back to simulated data on connection failure
"""

import asyncio
import json
import os
import re
import sys
import traceback
from datetime import datetime, timedelta

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Add project root for imports ──────────────────────────────────────────
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from analyst.config import get_config

# ── Load config ───────────────────────────────────────────────────────────

_splunk_cfg = get_config().splunk

# ── Server setup ──────────────────────────────────────────────────────────

server = Server("splunk-query-server")

# ── Real Splunk connection (lazy) ─────────────────────────────────────────

_splunk_service = None  # cached splunklib.client.Service


def _get_splunk_service():
    """
    Connect to real Splunk via splunk-sdk, if configured.
    Returns a splunklib.client.Service or None.
    """
    global _splunk_service
    if _splunk_service is not None:
        return _splunk_service

    if not _splunk_cfg.use_real:
        return None

    if not _splunk_cfg.is_configured():
        print("[Splunk MCP] use_real=true but host/password/token not configured", file=sys.stderr)
        return None

    try:
        import splunklib.client as client

        kwargs = {
            "host": _splunk_cfg.host,
            "port": _splunk_cfg.port,
            "scheme": "https" if _splunk_cfg.use_ssl else "http",
            "verify": _splunk_cfg.verify_ssl,
        }

        if _splunk_cfg.token:
            kwargs["token"] = _splunk_cfg.token
        else:
            kwargs["username"] = _splunk_cfg.username
            kwargs["password"] = _splunk_cfg.password

        print(f"[Splunk MCP] Connecting to {kwargs['scheme']}://{kwargs['host']}:{kwargs['port']}...",
              file=sys.stderr)
        _splunk_service = client.connect(**kwargs)
        print(f"[Splunk MCP] Connected to real Splunk: {_splunk_cfg.host}:{_splunk_cfg.port}",
              file=sys.stderr)
        return _splunk_service
    except ImportError:
        print("[Splunk MCP] splunk-sdk not installed ('pip install splunk-sdk') — fallback to simulated",
              file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Splunk MCP] Connection failed: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None


# ── HEC configuration (for write-back) ────────────────────────────────────────

_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
_HEC_VERIFY = os.getenv("SPLUNK_HEC_VERIFY", "0") not in ("0", "false", "False")


def _send_to_hec(event_payload: dict) -> bool:
    """
    Send an event to Splunk HEC (HTTP Event Collector).
    Returns True on success, False on failure (fail-soft).
    """
    if not _HEC_URL or not _HEC_TOKEN:
        return False
    try:
        import urllib.request
        import urllib.error
        data = json.dumps({
            "sourcetype": "ai_sentinel:disposition",
            "event": event_payload,
        }, ensure_ascii=False, default=str).encode("utf-8")
        req = urllib.request.Request(
            _HEC_URL,
            data=data,
            headers={
                "Authorization": f"Splunk {_HEC_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"[Splunk MCP] HEC write failed: {e}", file=sys.stderr)
        return False


# ── Simulated event store (fallback when Splunk is unreachable) ────────────────

_EVENT_STORE: list[dict] = []
_INDEXES = ["gateway_events", "ai_sentinel_disposition", "agent_spans", "audit_logs"]


def _init_store():
    """Initialize the event store. When Splunk is reachable, events come from real
    Splunk searches. The in-memory store starts empty — no more CSV/demo fallback."""
    global _EVENT_STORE
    if not _EVENT_STORE:
        _EVENT_STORE = []


# ── SPL helpers (simulated) ───────────────────────────────────────────────

def _parse_time(earliest: str, latest: str = "now") -> tuple[datetime, datetime]:
    """Parse Splunk-style time modifiers into datetime range (UTC-aware)."""
    now = datetime.now().astimezone()
    end = now
    start = now - timedelta(hours=1)
    if earliest:
        m = re.match(r"-(\d+)([smhd])", earliest.strip())
        if m:
            n, u = int(m.group(1)), m.group(2)
            delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
                     "h": timedelta(hours=n), "d": timedelta(days=n)}.get(u)
            if delta:
                start = now - delta
    return start, end


def _match_event(event: dict, query: str, start: datetime, end: datetime) -> bool:
    """Check if an event matches the query within a time range."""
    ts = event.get("_raw_timestamp")
    if ts is None:
        try:
            ts = datetime.fromisoformat(event["timestamp"])
        except (ValueError, KeyError):
            ts = datetime.now().astimezone()
    # Make ts offset-aware if it's naive
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=start.tzinfo)
    if ts < start or ts > end:
        return False
    if not query or query.strip() in ("*", "index=*", "search index=*",
                                      "search index=gateway_events"):
        return True
    q = query.lower()
    searchable = json.dumps(event, default=str).lower()
    terms = re.findall(r'"([^"]*)"', q)
    extra = [t.strip() for t in re.sub(r'["\']', '', q).split()
             if t.strip() and len(t.strip()) > 2
             and t.strip() not in ("search", "sort", "by", "the", "and")
             # 索引/源类型是过滤器，不作内容关键词（否则模拟库匹配不到）
             and not t.strip().startswith(("index=", "sourcetype="))]
    terms.extend(t.lower() for t in extra)
    if not terms:
        return True
    return all(t in searchable for t in terms)


# ── Real Splunk query helpers ─────────────────────────────────────────────

def _build_spl_search(query: str, earliest: str = "", latest: str = "") -> str:
    """
    规整为合法 SPL。时间范围不拼进字符串（拼在 | 之后会破坏 head 等命令），
    改由 jobs.create 的 earliest_time/latest_time 参数下发。
    """
    q = query.strip()
    if q.lower().startswith("search "):
        q = q[7:].strip()
    # 默认搜全部索引；用户没写 index= 时自动补 index=*，
    # 否则真实 Splunk 只搜默认索引，sourcetype=... 这类查询会返回空。
    if not q or q == "*":
        q = "index=*"
    elif not q.startswith("|") and "index=" not in q.lower():
        q = "index=* " + q
    if q.startswith("|"):          # 生成型命令（| tstats 等），不加 search 前缀
        return q
    return f"search {q}"


def _execute_real_search(spl: str, earliest: str = "-24h", latest: str = "now",
                         max_results: int = 1000) -> list[dict]:
    """
    Execute a search on real Splunk via splunk-sdk and return parsed events.
    时间范围作为 job 参数下发，避免拼进 SPL 字符串。
    """
    service = _get_splunk_service()
    if service is None:
        return []

    try:
        # 结果用 output_mode="json" 直接解析，无需 ResultsReader
        # （splunk-sdk 2.x 已移除 ResultsReader，旧导入会让真实搜索整体失败）

        # oneshot：同步阻塞直到完成并直接返回结果。
        # 不用 create+轮询：原轮询读 job["isDone"] 不会 refresh，永远是 "0"，
        # 会干等满 60s 超过桥接超时，导致前端拿不到结果。
        kw = {"count": max_results, "output_mode": "json"}
        if earliest:
            kw["earliest_time"] = earliest
        if latest:
            kw["latest_time"] = latest
        stream = service.jobs.oneshot(spl, **kw)
        raw = stream.read()
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")

        # Parse JSON results
        results = json.loads(raw)
        events = results.get("results", [])

        # Normalize field names
        normalized = []
        for ev in events:
            entry = {}
            for key, val in ev.items():
                # Splunk JSON output wraps values as {"fieldname": {"content": value}}
                if isinstance(val, dict) and "content" in val:
                    entry[key] = val["content"]
                else:
                    entry[key] = val
            normalized.append(entry)
        return normalized

    except Exception as e:
        print(f"[Splunk MCP] Real search error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return []


# ── Tool implementations ──────────────────────────────────────────────────

async def _do_search(query: str, earliest: str, latest: str) -> str:
    """
    Execute a search — goes to real Splunk if configured, otherwise simulated.
    """
    # Try real Splunk first
    if _splunk_cfg.use_real:
        service = _get_splunk_service()
        if service is not None:
            try:
                spl = _build_spl_search(query)
                print(f"[Splunk MCP] Real search: {spl} (earliest={earliest}, latest={latest})", file=sys.stderr)
                events = _execute_real_search(spl, earliest, latest)
                if events:
                    return json.dumps({
                        "total": len(events),
                        "earliest": earliest,
                        "latest": latest,
                        "events": events[:50],
                        "truncated": len(events) > 50,
                        "backend": "real",
                    }, ensure_ascii=False, default=str)
                else:
                    return json.dumps({
                        "total": 0,
                        "earliest": earliest,
                        "latest": latest,
                        "events": [],
                        "backend": "real",
                        "note": "No results from real Splunk",
                    }, ensure_ascii=False)
            except Exception as e:
                error_msg = f"Real Splunk search failed: {e}"
                print(f"[Splunk MCP] {error_msg}", file=sys.stderr)
                # Fall through to simulated

    # Fallback: simulated search
    _init_store()
    start, end = _parse_time(earliest, latest)
    results = []
    for event in _EVENT_STORE:
        if _match_event(event, query, start, end):
            r = dict(event)
            r.pop("_raw_timestamp", None)
            results.append(r)
    results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return json.dumps({
        "total": len(results),
        "earliest": start.isoformat(),
        "latest": end.isoformat(),
        "events": results[:50],
        "truncated": len(results) > 50,
        "backend": "simulated",
    }, ensure_ascii=False, default=str)


async def _do_list_indexes() -> str:
    """List indexes — from real Splunk if configured, otherwise simulated."""
    if _splunk_cfg.use_real:
        service = _get_splunk_service()
        if service is not None:
            try:
                indexes = service.indexes
                index_list = []
                for idx in indexes:
                    index_list.append({
                        "name": idx.name,
                        "event_count": int(idx.get("totalEventCount", 0)),
                        "status": "active" if idx.get("disabled", "0") == "0" else "disabled",
                        "backend": "real",
                    })
                return json.dumps({"indexes": index_list}, ensure_ascii=False)
            except Exception as e:
                print(f"[Splunk MCP] Real list_indexes error: {e}", file=sys.stderr)
                # Fall through to simulated

    # Fallback
    _init_store()
    indexes = [
        {"name": n, "event_count": len(_EVENT_STORE) if n == "gateway_events" else 0,
         "status": "active", "backend": "simulated"}
        for n in _INDEXES
    ]
    return json.dumps({"indexes": indexes}, ensure_ascii=False)


async def _do_get_event(event_id: str, trace_id: str, query: str) -> str:
    """Get a single event by ID — from real Splunk if configured, otherwise simulated."""
    search_id = event_id or trace_id or query
    if not search_id:
        return json.dumps({"error": "No event_id, trace_id, or query provided"})

    # Try real Splunk
    if _splunk_cfg.use_real:
        service = _get_splunk_service()
        if service is not None:
            try:
                # Construct a search that finds the specific event
                spl = f'search "{search_id}" | head 1'
                events = _execute_real_search(spl)
                if events:
                    return json.dumps(events[0], ensure_ascii=False, default=str)
            except Exception as e:
                print(f"[Splunk MCP] Real get_event error: {e}", file=sys.stderr)
                # Fall through to simulated

    # Fallback: simulated
    _init_store()
    for event in _EVENT_STORE:
        if event["event_id"] == search_id:
            r = dict(event)
            r.pop("_raw_timestamp", None)
            return json.dumps(r, ensure_ascii=False, default=str)
    for event in _EVENT_STORE:
        if search_id.lower() in event["event_id"].lower():
            r = dict(event)
            r.pop("_raw_timestamp", None)
            return json.dumps(r, ensure_ascii=False, default=str)
    return json.dumps({"error": f"Event not found: {search_id}"})


async def _do_health() -> str:
    """Check health — probes real Splunk if configured, otherwise simulated."""
    response = {
        "backend": "simulated",
        "host": _splunk_cfg.host,
        "port": _splunk_cfg.port,
        "use_real": _splunk_cfg.use_real,
        "is_configured": _splunk_cfg.is_configured(),
    }

    if _splunk_cfg.use_real and _splunk_cfg.is_configured():
        service = _get_splunk_service()
        if service is not None:
            try:
                # Quick health check: fetch server info
                info = service.info
                response.update({
                    "status": "healthy",
                    "backend": "real",
                    "server_name": info.get("serverName", ""),
                    "version": info.get("version", ""),
                    "events_available": None,
                    "indexes": None,
                })
                return json.dumps(response, ensure_ascii=False)
            except Exception as e:
                response.update({
                    "status": "error",
                    "error": str(e),
                })
                return json.dumps(response, ensure_ascii=False)

    # Simulated health
    _init_store()
    response.update({
        "status": "healthy",
        "backend": "simulated",
        "events_available": len(_EVENT_STORE),
        "indexes": len(_INDEXES),
    })
    return json.dumps(response, ensure_ascii=False)


# ── New tools for real Splunk pipeline ──────────────────────────────────────

async def _do_search_passed(earliest: str, latest: str) -> str:
    """
    Query only PASSED events (blocked=false) — events that passed Gateway
    detection but may contain subtle attacks needing analyst review.
    Uses real Splunk when configured, falls back to simulated.
    """
    if _splunk_cfg.use_real:
        service = _get_splunk_service()
        if service is not None:
            try:
                spl = "search index=* blocked=false sourcetype=\"ai_sentinel:gateway\""
                print(f"[Splunk MCP] Real search_passed: {spl} (earliest={earliest}, latest={latest})", file=sys.stderr)
                events = _execute_real_search(spl, earliest=earliest, latest=latest)
                if events:
                    return json.dumps({
                        "total": len(events),
                        "earliest": earliest,
                        "latest": latest,
                        "events": events[:50],
                        "truncated": len(events) > 50,
                        "backend": "real",
                        "filter": "passed_only",
                    }, ensure_ascii=False, default=str)
            except Exception as e:
                print(f"[Splunk MCP] Real search_passed error: {e}", file=sys.stderr)

    # Fallback: simulated
    _init_store()
    start, end = _parse_time(earliest, latest)
    results = []
    for event in _EVENT_STORE:
        if not event.get("blocked", True):
            ts = event.get("_raw_timestamp")
            if ts:
                if ts < start or ts > end:
                    continue
            r = dict(event)
            r.pop("_raw_timestamp", None)
            results.append(r)
    results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return json.dumps({
        "total": len(results),
        "earliest": start.isoformat(),
        "latest": end.isoformat(),
        "events": results[:50],
        "truncated": len(results) > 50,
        "backend": "simulated",
        "filter": "passed_only",
    }, ensure_ascii=False, default=str)


async def _do_ingest_disposition(event_id: str, disposition_id: str, status: str,
                                  mode: str, operator: str, action: str,
                                  command: str, detail: str, triggered_rule: str,
                                  risk_level: str) -> str:
    """
    Write a disposition status event to Splunk HEC, linking back to the
    original SecurityEvent via event_id. Also stores locally for fallback.
    """
    payload = {
        "disposition_id": disposition_id,
        "original_event_id": event_id,
        "status": status,
        "mode": mode,
        "operator": operator,
        "action": action,
        "command": command,
        "detail": detail,
        "triggered_rule": triggered_rule,
        "risk_level": risk_level,
        "timestamp": datetime.now().isoformat(),
    }
    success = _send_to_hec(payload)
    if success:
        # Also store locally for fallback queries
        _EVENT_STORE.append({
            **payload,
            "event_id": f"DISP-{disposition_id}",
            "timestamp": payload["timestamp"],
            "blocked": True,
            "module": "disposition",
            "handler": "analyst",
            "risk_score": 100 if status == "blocked" else 0,
            "user_input": command,
            "subject_name": operator,
            "agent_id": "analyst",
            "findings": [{"rule_hit": triggered_rule, "severity": risk_level}],
            "gateway_id": "analyst",
            "llm_provider": "",
            "_raw_timestamp": datetime.now(),
        })
        return json.dumps({"success": True, "disposition_id": disposition_id}, ensure_ascii=False)
    return json.dumps({"success": False, "error": "HEC write failed"}, ensure_ascii=False)


# ── MCP Tool definitions & handler ────────────────────────────────────────

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="splunk_search",
            description="Execute a Splunk search query and return matching events. Supports keywords and quoted terms. Connects to real Splunk when configured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SPL search query (supports keywords, quoted terms)", "default": "*"},
                    "earliest": {"type": "string", "description": "Time range start, e.g. '-1h', '-30m', '-7d'", "default": "-1h"},
                    "latest": {"type": "string", "description": "Time range end", "default": "now"},
                },
            },
        ),
        Tool(
            name="splunk_list_indexes",
            description="List all available Splunk indexes with event counts. Connects to real Splunk when configured.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="splunk_get_event",
            description="Get a single event by ID. Connects to real Splunk when configured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {"type": "string", "description": "Exact event ID", "default": ""},
                    "trace_id": {"type": "string", "description": "Alternative trace ID", "default": ""},
                    "query": {"type": "string", "description": "Optional SPL filter", "default": ""},
                },
            },
        ),
        Tool(
            name="splunk_health",
            description="Check Splunk connection health and event counts. Probes real Splunk when configured.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="splunk_search_passed",
            description="Search for PASSED events (blocked=false) — events that passed Gateway detection but need analyst review. Connects to real Splunk when configured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "earliest": {"type": "string", "description": "Time range start, e.g. '-1h', '-30m'", "default": "-1h"},
                    "latest": {"type": "string", "description": "Time range end", "default": "now"},
                },
            },
        ),
        Tool(
            name="splunk_ingest_disposition",
            description="Write a disposition status event to Splunk HEC, linking back to the original event. Records the analyst's decision and gateway interaction result.",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {"type": "string", "description": "Original event ID this disposition relates to"},
                    "disposition_id": {"type": "string", "description": "Unique disposition ID"},
                    "status": {"type": "string", "description": "Disposition status: blocked, released, observed, failed"},
                    "mode": {"type": "string", "description": "Agent mode: auto or observe"},
                    "operator": {"type": "string", "description": "Who made the decision: auto or admin"},
                    "action": {"type": "string", "description": "Action taken: block, unblock"},
                    "command": {"type": "string", "description": "Gateway command sent"},
                    "detail": {"type": "string", "description": "Human-readable detail"},
                    "triggered_rule": {"type": "string", "description": "Rule that triggered this action"},
                    "risk_level": {"type": "string", "description": "Risk level: critical, high, medium, low"},
                },
                "required": ["event_id", "disposition_id", "status"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "splunk_search":
        result = await _do_search(
            arguments.get("query", "*"),
            arguments.get("earliest", "-1h"),
            arguments.get("latest", "now"),
        )
    elif name == "splunk_list_indexes":
        result = await _do_list_indexes()
    elif name == "splunk_get_event":
        result = await _do_get_event(
            arguments.get("event_id", ""),
            arguments.get("trace_id", ""),
            arguments.get("query", ""),
        )
    elif name == "splunk_health":
        result = await _do_health()
    elif name == "splunk_search_passed":
        result = await _do_search_passed(
            arguments.get("earliest", "-1h"),
            arguments.get("latest", "now"),
        )
    elif name == "splunk_ingest_disposition":
        result = await _do_ingest_disposition(
            arguments.get("event_id", ""),
            arguments.get("disposition_id", ""),
            arguments.get("status", "observed"),
            arguments.get("mode", "observe"),
            arguments.get("operator", "admin"),
            arguments.get("action", ""),
            arguments.get("command", ""),
            arguments.get("detail", ""),
            arguments.get("triggered_rule", ""),
            arguments.get("risk_level", "medium"),
        )
    else:
        result = json.dumps({"error": f"Unknown tool: {name}"})

    return [TextContent(type="text", text=result)]


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    asyncio.run(_run())


if __name__ == "__main__":
    main()