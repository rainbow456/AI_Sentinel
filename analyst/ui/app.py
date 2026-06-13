"""
Multi-Agent Command Center — Flask API (v3).
Adds NL dual-intent parsing, command execution, rule search, demo triggers.
"""

import json
import os
import sys
import threading
import time

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
from analyst.nl_engine import get_demo_scenarios

app = Flask(__name__)

# ── Global agent instance ─────────────────────────────────────────────────

_agent: SecurityAgent = SecurityAgent(mode=AgentMode.OBSERVE)
_lock = threading.Lock()
_initialized = False


def _init_agent():
    """Load events from CSV and generate alerts on first request."""
    global _initialized
    if _initialized:
        return
    with _lock:
        if _initialized:
            return
        print("[UI] Loading events from CSV...")
        count = _agent._load_events_from_csv()
        print(f"[UI] Loaded {count} events from CSV, generating alerts...")
        _initialized = True
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


@app.route("/api/query/demo-scenarios")
def demo_scenarios():
    """Return preset demo NL commands for quick testing."""
    return jsonify(get_demo_scenarios())


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
    print("[STARTUP] Multi-Agent Command Center v3 starting...")
    print("[STARTUP] Dashboard: http://localhost:5000")
    print("[STARTUP] Demo scenarios available at /api/query/demo-scenarios")
    try:
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass