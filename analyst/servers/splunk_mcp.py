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


# ── CSV data path ─────────────────────────────────────────────────────────

_CSV_DIR = os.path.join(_project_root, "data")


def _load_csv_events(data_dir: str = _CSV_DIR) -> list[dict]:
    """
    Load gateway events from CSV files in the data/ directory.
    Each row's _raw column contains a JSON object with the event data.
    Returns a list of event dicts ready to be stored in _EVENT_STORE.
    """
    events = []
    if not os.path.isdir(data_dir):
        return events

    import csv
    for fname in sorted(os.listdir(data_dir)):
        if not fname.endswith(".csv"):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw_json = row.get("_raw", "")
                    if not raw_json:
                        continue
                    try:
                        ev = json.loads(raw_json)
                    except json.JSONDecodeError:
                        continue

                    # Parse timestamp — use _time if event timestamp missing
                    ts_str = ev.get("timestamp") or row.get("_time", "")
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        ts = datetime.now()

                    # Map findings — keep as list of dicts
                    findings = ev.get("findings", [])

                    events.append({
                        "event_id": ev.get("event_id", f"CSV-{len(events):04d}"),
                        "timestamp": ts.isoformat(),
                        "module": ev.get("module", "unknown"),
                        "blocked": bool(ev.get("blocked", False)),
                        "handler": ev.get("handler", ""),
                        "risk_score": int(ev.get("risk_score", 0)),
                        "user_input": ev.get("user_input", ""),
                        "subject_name": ev.get("subject_name", ""),
                        "agent_id": ev.get("agent_id", ""),
                        "findings": findings,
                        "gateway_id": ev.get("gateway_id", "gateway-01"),
                        "llm_provider": ev.get("llm_provider", "anthropic"),
                        "_raw_timestamp": ts,
                    })
        except Exception as exc:
            print(f"[Splunk MCP] Error reading CSV {fname}: {exc}", file=sys.stderr)

    print(f"[Splunk MCP] Loaded {len(events)} events from CSV", file=sys.stderr)
    return events


# ── Simulated event store (fallback) ──────────────────────────────────────

_EVENT_STORE: list[dict] = []
_INDEXES = ["gateway_events", "agent_spans", "audit_logs", "block_history"]


def _init_store():
    """Populate the simulated event store — first from CSV, then fallback to demo data."""
    global _EVENT_STORE
    if _EVENT_STORE:
        return

    # 1. Try loading from CSV files in data/
    csv_events = _load_csv_events()
    if csv_events:
        _EVENT_STORE.extend(csv_events)
        return

    # 2. Fallback: hardcoded demo data
    try:
        from analyst.agent import _demo_gateway_events
        events = _demo_gateway_events()
        for e in events:
            _EVENT_STORE.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "module": getattr(e, "module", "input_guard"),
                "blocked": getattr(e, "blocked", e.event_type == "blocked"),
                "handler": getattr(e, "handler", "gateway"),
                "risk_score": int(getattr(e, "risk_score", 90)),
                "user_input": e.user_input,
                "findings": getattr(e, "findings", [{"rule_hit": e.triggered_rule or "unknown"}]),
                "gateway_id": e.gateway_id,
                "llm_provider": e.llm_provider,
                "_raw_timestamp": e.timestamp,
            })
    except ImportError:
        now = datetime.now()
        _EVENT_STORE.extend([
            {
                "event_id": "GW-FALLBACK-001",
                "timestamp": (now - timedelta(minutes=10)).isoformat(),
                "module": "input_guard", "blocked": True, "handler": "gateway",
                "risk_score": 90,
                "user_input": "1' UNION SELECT * FROM users--",
                "findings": [{"rule_hit": "injection_detected", "severity": "critical"}],
                "gateway_id": "gw-prod-01", "llm_provider": "anthropic",
                "_raw_timestamp": now - timedelta(minutes=10),
            },
        ])


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