"""
Multi-Agent Command Center — Flask API (v3).
Adds NL dual-intent parsing, command execution, rule search, demo triggers.
"""

import json
import os
import sys
import threading
import time

# Make stdout/stderr tolerant of consoles that can't encode emoji (e.g. Windows
# GBK/cp936): replace unencodable chars instead of crashing the process.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from flask import Flask, jsonify, render_template, request

from analyst.agent import SecurityAgent
from analyst.models import AgentMode
from analyst.report_engine import (
    generate_batch_report,
    generate_single_report,
)
app = Flask(__name__)

# ── Global agent instance ─────────────────────────────────────────────────

_agent: SecurityAgent = SecurityAgent(mode=AgentMode.OBSERVE)
_lock = threading.Lock()
_initialized = False


def _init_agent():
    """Start polling loop on first request."""
    global _initialized
    if _initialized:
        return
    with _lock:
        if _initialized:
            return
        print("[UI] Starting Splunk polling...")
        _agent._start_polling()
        _initialized = True
        # Give polling a moment to fetch initial events
        time.sleep(1)
        stats = _agent.get_stats()
        print(f"[UI] Ready — mode={stats['mode']}, alerts={stats['total_alerts']}, "
              f"events={stats['total_events']}, "
              f"rules={stats['rules_active']}/{stats['rules_total']}, "
              f"mcp={'on' if stats['mcp_enabled'] else 'off'}")


# ── Page ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    _init_agent()
    return render_template("dashboard.html")


# ── Alert & stats APIs ────────────────────────────────────────────────────

@app.route("/api/stats")
def get_stats():
    _init_agent()
    return jsonify(_agent.get_stats())


@app.route("/api/alerts")
def get_alerts():
    _init_agent()
    return jsonify(_agent.get_alerts())


@app.route("/api/alerts/<alert_id>")
def get_alert(alert_id):
    _init_agent()
    alert = _agent.get_alert(alert_id)
    if alert:
        return jsonify(alert)
    return jsonify({"error": "Alert not found"}), 404


# ── Report APIs ───────────────────────────────────────────────────────────

@app.route("/api/report/<alert_id>")
def get_report(alert_id):
    _init_agent()
    with _lock:
        for a in _agent.alerts:
            if a.alert_id == alert_id:
                report = generate_single_report(a, _agent.anomalies)
                return jsonify(report)
    return jsonify({"error": "Alert not found"}), 404


@app.route("/api/report/batch")
def get_batch_report():
    _init_agent()
    with _lock:
        report = generate_batch_report(
            list(_agent.alerts),
            list(_agent.trees),
            list(_agent.anomalies),
        )
        return jsonify(report)


# ── Mode control ──────────────────────────────────────────────────────────

@app.route("/api/mode", methods=["GET", "POST"])
def mode_control():
    _init_agent()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        mode_str = data.get("mode", "observe")
        try:
            new_mode = AgentMode(mode_str)
            _agent.set_mode(new_mode)
            return jsonify({"success": True, "mode": new_mode.value})
        except ValueError:
            return jsonify({"error": f"Invalid mode: {mode_str}"}), 400
    return jsonify({"mode": _agent.mode.value})


# ── Block confirmation (OBSERVE mode) ─────────────────────────────────────

@app.route("/api/block/<alert_id>", methods=["POST"])
def confirm_block(alert_id):
    _init_agent()
    result = _agent.confirm_block(alert_id)
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════
# NL Query — Dual Intent (v3)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/query", methods=["POST"])
def nl_query():
    """
    Process a natural language command with dual-intent parsing.
    Returns structured response with intent classification.
    """
    _init_agent()
    data = request.get_json(silent=True) or {}
    query_text = data.get("query", "").strip()
    if not query_text:
        return jsonify({"error": "Empty query"}), 400
    result = _agent.process_nl_query(query_text)
    return jsonify(result)


@app.route("/api/action/execute", methods=["POST"])
def execute_action():
    """
    Execute a confirmed action (called after user confirms in OBSERVE mode).
    Accepts a parsed action dict.
    """
    _init_agent()
    data = request.get_json(silent=True) or {}
    action = data.get("action", {})
    if not action:
        return jsonify({"error": "No action provided"}), 400
    result = _agent.execute_action(action)
    return jsonify(result)


# ── Disposition Records ───────────────────────────────────────────────────

@app.route("/api/dispositions")
def get_dispositions():
    """Return all disposition records, newest first."""
    _init_agent()
    return jsonify(_agent.get_dispositions())


@app.route("/api/dispositions/<disposition_id>")
def get_disposition(disposition_id):
    """Return a single disposition record."""
    _init_agent()
    d = _agent.get_disposition(disposition_id)
    if d:
        return jsonify(d)
    return jsonify({"error": "Disposition not found"}), 404


@app.route("/api/dispositions/by-alert/<alert_id>")
def get_dispositions_by_alert(alert_id):
    """Return disposition records for a specific alert."""
    _init_agent()
    return jsonify(_agent.get_dispositions_by_alert(alert_id))


# ── Block list (via gateway MCP) ──────────────────────────────────────────

@app.route("/api/blocks")
def get_blocks():
    """List all active blocks from gateway MCP."""
    _init_agent()
    result = _agent._mcp_call("gateway-control", "list_blocks", {"target": ""}, fallback=None)
    if result:
        return jsonify(result)
    return jsonify({"total": 0, "active": 0, "blocks": []})


# ═══════════════════════════════════════════════════════════════════════════
# Rule management (v3) — with semantic search
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/rules")
def get_rules():
    _init_agent()
    return jsonify(_agent.get_rules())


@app.route("/api/rules/search", methods=["POST"])
def search_rules_endpoint():
    """
    Search rules by natural language query.
    Body: {"query": "关于共谋的规则"}
    Returns ranked rules with relevance scores.
    """
    _init_agent()
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "Empty query"}), 400
    from analyst.nl_engine import search_rules
    rules = _agent.get_rules()
    ranked = search_rules(query, rules)
    return jsonify({
        "query": query,
        "total": len(ranked),
        "rules": ranked[:20],
        "summary": f"找到 {len(ranked)} 条相关规则" if ranked else "未找到匹配规则",
    })


@app.route("/api/rules/<rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    _init_agent()
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", True)
    ok = _agent.toggle_rule_mcp(rule_id, enabled)
    return jsonify({"success": ok, "rule_id": rule_id, "enabled": enabled})


@app.route("/api/rules/upsert", methods=["POST"])
def upsert_rule():
    _init_agent()
    data = request.get_json(silent=True) or {}
    ok = _agent.upsert_rule_mcp(data)
    return jsonify({"success": ok})


# ═══════════════════════════════════════════════════════════════════════════
# Splunk 原始日志查询（经 splunk-query MCP，真实 Splunk / 模拟回退）
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/splunk/search", methods=["POST"])
def splunk_search():
    """Run an SPL search via the Splunk MCP server; returns raw events."""
    _init_agent()
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "*").strip()
    earliest = data.get("earliest", "-24h")
    latest = data.get("latest", "now")
    result = _agent._mcp_call(
        "splunk-query", "splunk_search",
        {"query": query, "earliest": earliest, "latest": latest},
        fallback={"total": 0, "events": [], "backend": "unavailable",
                  "note": "Splunk MCP 未连接（agent MCP 未启用或服务器未就绪）"},
    )
    return jsonify(result)


@app.route("/api/splunk/health")
def splunk_health():
    """Splunk connection health (real / simulated)."""
    _init_agent()
    result = _agent._mcp_call(
        "splunk-query", "splunk_health", {},
        fallback={"status": "unavailable", "backend": "none",
                  "note": "Splunk MCP 未连接"},
    )
    return jsonify(result)


@app.route("/api/splunk/indexes")
def splunk_indexes():
    """List Splunk indexes (real / simulated)."""
    _init_agent()
    result = _agent._mcp_call(
        "splunk-query", "splunk_list_indexes", {},
        fallback={"indexes": []},
    )
    return jsonify(result)


# ── Real-time event stream ───────────────────────────────────────────────────

@app.route("/api/events/recent")
def get_recent_events():
    """Return recent events from Splunk for the dashboard event stream."""
    _init_agent()
    limit = request.args.get("limit", 50, type=int)
    events = _agent.get_recent_events(limit=limit)
    return jsonify({
        "total": len(events),
        "events": events,
    })


@app.route("/api/gateway/health")
def gateway_health():
    """Check Gateway MCP connection status."""
    _init_agent()
    result = _agent._mcp_call("gateway-control", "gateway_status", {}, fallback=None)
    if result:
        return jsonify(result)
    return jsonify({"status": "disconnected", "active_blocks": 0})


# ── MCP & LLM status ──────────────────────────────────────────────────────

@app.route("/api/mcp/status")
def mcp_status():
    _init_agent()
    return jsonify(_agent.mcp_status)


@app.route("/api/llm/config", methods=["POST"])
def configure_llm():
    _init_agent()
    data = request.get_json(silent=True) or {}
    provider = data.get("provider", "")
    api_key = data.get("api_key", "")
    model = data.get("model", "")
    if not provider or not api_key:
        return jsonify({"error": "provider and api_key required"}), 400
    _agent.configure_llm(provider, api_key, model)
    return jsonify({"success": True, "provider": provider, "model": model or "default"})


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    print("[STARTUP] AI Sentinel Analyst Command Center starting...")
    print("[STARTUP] Dashboard: http://localhost:5000")
    print("[STARTUP] Real Splunk pipeline mode — events polled from Splunk")
    try:
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass