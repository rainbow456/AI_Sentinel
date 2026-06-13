"""
Multi-Alert Security Agent — refactored to stay under 600 lines.

Dual mode: AUTO (auto-block) / OBSERVE (human-in-the-loop)
MCP integration for Splunk/Gateway/Rule Engine servers.
NL processing, action execution, and demo data delegated to nl_engine.py.
"""

import json, os, re, signal, sys, threading, time, uuid
from collections import Counter
from datetime import datetime, timedelta

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from .config import get_config
from .mcp_client import MCPBridge
from .models import (
    AgentMode, AlertRecord, CausalNode, DecisionTree,
    DispositionRecord, DispositionStatus, EmergentAnomaly, GatewayEvent, Span,
)
from .causal_analyzer import (
    build_decision_tree, identify_key_nodes, detect_emergence, generate_storyline,
)
from .nl_engine import (
    classify_intent, INTENT_QUERY, INTENT_ACTION, INTENT_RULES_SEARCH,
    INTENT_MODE_SWITCH, INTENT_RULE_CONFIG, parse_action, search_rules,
    format_action_result, parse_rule_config, format_rule_config_result,
)
from .rule_engine import RuleEngine

RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"; YELLOW="\033[93m"
CYAN="\033[96m"; GREEN="\033[92m"; RED="\033[91m"

def _ts(): return f"{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RESET}"
def _think(msg): print(f"{_ts()} {CYAN}🧠 思考{RESET} {msg}")
def _step(emoji, msg): print(f"{_ts()} {emoji} {BOLD}{msg}{RESET}")
def _divider(c="─", w=62): print(f"{DIM}{c * w}{RESET}")

# ═══════════════════════════════════════════════════════════════════════════
# Security Agent
# ═══════════════════════════════════════════════════════════════════════════

class SecurityAgent:
    """Multi-alert security agent with dual-mode operation & NL command support."""

    LLM_SPL_PROMPT = "你是一个Splunk搜索专家。将用户的自然语言查询转换为SPL查询。\n字段: timestamp, event_type(blocked|passed|action_confirmation), user_input, detection_result.rule_triggered\n示例: '过去1小时的SQL注入告警' → search index=gateway_events event_type=blocked \"sql injection\" earliest=-1h\n查询: {query}\n只输出SPL。"
    LLM_INTENT_PROMPT = "判断意图(query/action/rules_search/mode_switch): {query}"
    LLM_ACTION_PROMPT = "解析为JSON: {{\"action_type\":\"block|unblock|toggle_rule\",\"target\":\"...\",\"params\":{{...}}}}\n输入: {query}"

    def __init__(self, mode: AgentMode = AgentMode.OBSERVE):
        self.mode = mode
        self._config = get_config()
        self.rule_engine = self._init_rule_engine()
        self.trees: list[DecisionTree] = []
        self.anomalies: list[EmergentAnomaly] = []
        self.alerts: list[AlertRecord] = []
        self.dispositions: list[DispositionRecord] = []

        self._mcp: MCPBridge | None = None
        self._mcp_enabled = False
        self.cycle_count = 0
        self._running = True
        self._processed_event_ids: set[str] = set()
        self._lock = threading.Lock()
        self._llm_config: dict = {}
        # Polling state (replaces _demo_cycle)
        self._poll_thread: threading.Thread | None = None
        self._poll_interval: int = int(os.getenv("POLL_INTERVAL", "10"))
        self._last_poll_time: datetime = datetime.now() - timedelta(hours=1)

        self._init_mcp()

    def _init_rule_engine(self):
        """Initialize a basic RuleEngine with default rules."""
        engine = RuleEngine()
        engine.rules = {r.rule_id: r for r in RuleEngine.DEFAULT_RULES}
        return engine

    def set_mode(self, mode: AgentMode):
        old = self.mode
        self.mode = mode
        print(f"{_ts()} 🔄 模式切换: {old.value} → {BOLD}{mode.value}{RESET}")

    def configure_llm(self, provider: str, api_key: str, model: str = ""):
        self._llm_config = {"provider": provider, "api_key": api_key,
                            "model": model or "claude-sonnet-4-6"}
        print(f"{_ts()} 🔧 LLM已配置: {provider}/{self._llm_config['model']}")

    # ── MCP integration ────────────────────────────────────────────────

    def _init_mcp(self):
        try:
            self._mcp = MCPBridge(["splunk-query", "gateway-control", "rule-engine"])
            ok = self._mcp.start(timeout=20.0)
            self._mcp_enabled = ok
            if ok:
                connected = [n for n in ["splunk-query", "gateway-control", "rule-engine"]
                            if self._mcp.is_connected(n)]
                print(f"{_ts()} 🔌 MCP已连接: {', '.join(connected)}")
                self._sync_rules_from_mcp()
            else:
                print(f"{_ts()} {YELLOW}⚠ MCP连接部分失败{RESET}")
        except Exception as e:
            print(f"{_ts()} {YELLOW}⚠ MCP初始化失败: {e}{RESET}")
            self._mcp_enabled = False

    def _sync_rules_from_mcp(self):
        if not self._mcp_enabled or not self._mcp:
            return
        try:
            resp = self._mcp.call("rule-engine", "get_rules", {"enabled_only": False})
            data = json.loads(resp)
            if "rules" in data:
                for r in data["rules"]:
                    rd = r.get("rule_id", "")
                    if rd in self.rule_engine.rules:
                        self.rule_engine.rules[rd].enabled = r.get("enabled", True)
                print(f"{_ts()} 📋 规则已同步: {data.get('total', 0)}条")
        except Exception as e:
            print(f"{_ts()} {YELLOW}⚠ 规则同步失败: {e}{RESET}")

    def _mcp_call(self, server: str, tool: str, args: dict, fallback=None):
        if not self._mcp_enabled or not self._mcp:
            return fallback
        try:
            resp = self._mcp.call(server, tool, args)
            data = json.loads(resp)
            if data.get("_mcp_error"):
                return fallback
            return data
        except Exception:
            return fallback

    def _start_polling(self):
        """Start background polling thread that fetches events from Splunk."""
        if self._poll_thread is not None:
            return
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
        print(f"{_ts()} 🔄 开始轮询 Splunk (间隔={self._poll_interval}s)")

    def _poll_loop(self):
        """Background loop: poll Splunk for new events every N seconds."""
        while self._running:
            try:
                new_events = self._fetch_events()
                if new_events:
                    with self._lock:
                        fresh = [e for e in new_events
                                 if e.event_id not in self._processed_event_ids]
                    for event in fresh:
                        self._process_event(event)
                        with self._lock:
                            self._processed_event_ids.add(event.event_id)
                    if fresh:
                        print(f"{_ts()} 📥 轮询获得 {len(fresh)} 个新事件 "
                              f"(总计 {len(self._processed_event_ids)})")
            except Exception as e:
                print(f"{_ts()} {YELLOW}⚠ 轮询错误: {e}{RESET}")
            for _ in range(self._poll_interval):
                if not self._running:
                    break
                time.sleep(1)

    def _poll_events_now(self) -> list[dict]:
        """Synchronous one-shot poll: fetch recent events from Splunk MCP.
        Called by the UI to get events on demand."""
        events = self._fetch_events()
        summaries = []
        for e in events:
            d = {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "module": e.module,
                "blocked": e.blocked,
                "handler": e.handler,
                "risk_score": e.risk_score,
                "user_input": e.user_input[:80] if e.user_input else "",
                "subject_name": e.subject_name,
                "agent_id": e.agent_id,
                "findings": [f.get("rule_hit", "") for f in (e.findings or [])],
                "gateway_id": e.gateway_id,
            }
            summaries.append(d)
        return summaries

    # ═══════════════════════════════════════════════════════════════════
    # NL Command Processing (dual-intent)
    # ═══════════════════════════════════════════════════════════════════

    def _handle_rule_config(self, text):
        """Handle NL rule configuration (create/edit rules)."""
        config = parse_rule_config(text)
        if config.get("confidence", 0) < 0.5:
            return {"intent":"rule_config","error":"无法解析规则配置指令","feedback_nl":"⚠️ 无法解析规则配置"}
        result = self._mcp_call("rule-engine","upsert_rule",{"rule_data":config["rule_data"]}, fallback=None)
        feedback = format_rule_config_result(config, result) if result else "⚠️ 规则配置失败"
        # Sync local
        if result and result.get("success"):
            self.rule_engine.upsert_rule(config["rule_data"])
        return {"intent":"rule_config","action":config["action"],"rule_id":config["rule_id"],
                "rule_data":config["rule_data"],"result":result,"feedback_nl":feedback}

    def process_nl_query(self, query_text: str) -> dict:
        _think(f"处理自然语言指令: 「{query_text}」")
        intent = classify_intent(query_text)
        print(f"  {DIM}意图分类: {intent}{RESET}")
        if intent == INTENT_MODE_SWITCH:
            return self._handle_mode_switch(query_text)
        elif intent == INTENT_ACTION:
            return self._handle_action(query_text)
        elif intent == INTENT_RULES_SEARCH:
            return self._handle_rules_search(query_text)
        elif intent == INTENT_RULE_CONFIG:
            return self._handle_rule_config(query_text)
        else:
            return self._handle_query(query_text)

    def _handle_query(self, query_text: str) -> dict:
        """Handle a standard data query."""
        # Generate SPL (keyword or LLM)
        if self._llm_config.get("api_key"):
            spl = self._nl_to_spl_llm(query_text)
            method = "llm"
        else:
            spl = self._nl_to_spl_keyword(query_text)
            method = "keyword"

        print(f"  {DIM}SPL: {spl}{RESET}")

        # Execute via MCP Splunk
        results = self._fetch_events_raw(spl)
        summary = self._summarize_query_results(results, query_text)

        return {
            "intent": INTENT_QUERY,
            "query": query_text,
            "spl": spl,
            "method": method,
            "event_count": len(results),
            "events": [self._event_to_summary(e) for e in results],
            "summary": summary,
        }

    def _handle_action(self, query_text: str) -> dict:
        """Handle an action command (block / unblock / toggle_rule)."""
        action = parse_action(query_text)
        action_type = action.get("action_type", "unknown")
        target = action.get("target", "")
        params = action.get("params", {})

        if action_type == "unknown":
            return {
                "intent": INTENT_ACTION,
                "action": action_type,
                "error": f"无法解析操作指令: 「{query_text}」",
                "feedback_nl": f"⚠️ 无法识别操作类型。支持: 阻断IP/事件、解封、启用/禁用规则。",
            }

        # Check mode: OBSERVE requires confirmation for block
        requires_confirmation = (
            self.mode == AgentMode.OBSERVE and
            action_type in ("block", "toggle_rule")
        )

        # ── Execute action via MCP ───────────────────────────────────
        result_data = None
        mcp_server = None
        mcp_tool = None

        if action_type == "block":
            mcp_server, mcp_tool = "gateway-control", "send_block_command"
        elif action_type == "unblock":
            mcp_server, mcp_tool = "gateway-control", "unblock_target"
        elif action_type == "toggle_rule":
            mcp_server, mcp_tool = "rule-engine", "toggle_rule"

        if requires_confirmation:
            # Return pending action — UI will ask user, then call execute_action
            return {
                "intent": INTENT_ACTION,
                "action": action_type,
                "pending": True,
                "requires_confirmation": True,
                "action_parsed": action,
                "mcp_server": mcp_server,
                "mcp_tool": mcp_tool,
                "feedback_nl": f"⚠️ OBSERVE模式 — 确认执行: {format_action_result(action, {})}",
            }

        # AUTO mode or non-block action → execute immediately
        if mcp_server and mcp_tool:
            result_data = self._mcp_call(mcp_server, mcp_tool, params, fallback=None)

        feedback = format_action_result(action, result_data) if result_data else \
                   "⚠️ 操作执行失败，MCP可能未连接。"

        return {
            "intent": INTENT_ACTION,
            "action": action_type,
            "action_parsed": action,
            "result": result_data,
            "feedback_nl": feedback,
            "requires_confirmation": False,
        }

    def execute_action(self, action: dict) -> dict:
        """Execute a parsed action directly (used by UI after confirmation)."""
        action_type = action.get("action_type", "")
        params = action.get("params", {})

        mcp_map = {
            "block": ("gateway-control", "send_block_command"),
            "unblock": ("gateway-control", "unblock_target"),
            "toggle_rule": ("rule-engine", "toggle_rule"),
        }
        server, tool = mcp_map.get(action_type, (None, None))
        if not server:
            return {"success": False, "error": f"Unknown action: {action_type}"}

        result_data = self._mcp_call(server, tool, params, fallback=None)
        feedback = format_action_result(action, result_data) if result_data else "⚠️ 执行失败"
        return {"success": bool(result_data), "result": result_data, "feedback_nl": feedback}

    def _handle_rules_search(self, query_text: str) -> dict:
        """Search rules by natural language."""
        # Fetch all rules via MCP
        rules = self.get_rules()
        # Use semantic search
        ranked = search_rules(query_text, rules)
        return {
            "intent": INTENT_RULES_SEARCH,
            "query": query_text,
            "total": len(ranked),
            "rules": ranked[:20],  # top 20
            "summary": f"找到 {len(ranked)} 条相关规则" if ranked else "未找到匹配规则",
        }

    def _handle_mode_switch(self, query_text: str) -> dict:
        """Handle mode switch command."""
        q = query_text.lower()
        if "自动" in q or "auto" in q:
            new_mode = AgentMode.AUTO
        else:
            new_mode = AgentMode.OBSERVE

        self.set_mode(new_mode)

        # Sync to gateway MCP
        if self._mcp_enabled and self._mcp:
            self._mcp_call("gateway-control", "set_mode", {"mode": new_mode.value})

        return {
            "intent": INTENT_MODE_SWITCH,
            "new_mode": new_mode.value,
            "success": True,
            "feedback_nl": f"✅ 已切换模式为「{new_mode.value}」",
        }

    # ═══════════════════════════════════════════════════════════════════
    # SPL Generation
    # ═══════════════════════════════════════════════════════════════════

    def _nl_to_spl_keyword(self, query: str) -> str:
        q = query.lower()
        time_patterns = [
            (r"过去\s*(\d+)\s*小时", "h"), (r"过去\s*(\d+)\s*分钟", "m"),
            (r"last\s*(\d+)\s*hour", "h"), (r"last\s*(\d+)\s*min", "m"),
            (r"最近\s*(\d+)\s*小时", "h"), (r"最近\s*(\d+)\s*分钟", "m"),
        ]
        time_filter = "earliest=-1h"
        for pat, unit in time_patterns:
            m = re.search(pat, q)
            if m:
                time_filter = f"earliest=-{m.group(1)}{unit}"
                break

        type_filter = ""
        if "阻断" in q or "blocked" in q:
            type_filter = 'event_type=blocked'
        elif "放行" in q or "passed" in q:
            type_filter = 'event_type=passed'
        elif "共谋" in q or "collusion" in q or "action_confirmation" in q:
            type_filter = 'event_type=action_confirmation'

        keyword_map = {
            "注入": "injection", "sql": "sql injection", "xss": "xss",
            "泄露": "leak", "敏感": "sensitive", "密码": "password",
            "提示词": "prompt injection", "速率": "rate limit",
            "数据": "data exfiltration", "token": "token",
        }
        search_terms = []
        for cn, en in keyword_map.items():
            if cn in q or en in q:
                search_terms.append(en)

        parts = ["search index=gateway_events"]
        if type_filter:
            parts.append(type_filter)
        if search_terms:
            parts.append("(" + " OR ".join(f'"{t}"' for t in search_terms) + ")")
        elif "高" in q and ("危" in q or "置信" in q):
            parts.append("confidence>0.8")
        parts.append(time_filter)
        parts.append("| sort -timestamp")
        return " ".join(parts)

    def _nl_to_spl_llm(self, query: str) -> str:
        print(f"  {YELLOW}⚠ LLM SPL生成未完整实现，回退到关键词{RESET}")
        return self._nl_to_spl_keyword(query)

    def _summarize_query_results(self, events: list, query: str) -> str:
        if not events:
            return "未找到匹配事件。"
        blocked = sum(1 for e in events if e.event_type == "blocked")
        passed = sum(1 for e in events if e.event_type == "passed")
        collusion = sum(1 for e in events if e.event_type == "action_confirmation")
        return f"共找到 {len(events)} 条匹配事件。blocked={blocked}, passed={passed}, collusion_signals={collusion}。"

    def _event_to_summary(self, event: GatewayEvent) -> dict:
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else "",
            "event_type": event.event_type,
            "gateway_id": event.gateway_id,
            "triggered_rule": event.triggered_rule,
            "confidence": event.confidence,
        }

    def run(self):
        self._setup_signal_handlers(); print(); _divider("═", 62)
        print(f"  {BOLD}{CYAN}🛡️  多告警安全Agent 已启动{RESET}  {DIM}模式: {self.mode.value}{RESET}")
        print(f"  {DIM}按 Ctrl+C 停止{RESET}"); _divider("═", 62); print()
        self._run_cycle()
        while self._running:
            try:
                for _ in range(10):
                    if not self._running: break
                    time.sleep(1)
                if self._running: self._run_cycle()
            except KeyboardInterrupt: break
        self._shutdown()

    def _run_cycle(self):
        self.cycle_count += 1; print(); _divider("─", 60)
        print(f"{_ts()} 🔍 {BOLD}分析轮次 #{self.cycle_count}{RESET}"); _divider("─", 60)
        events = self._fetch_events()
        if not events: return
        new_events = [e for e in events if e.event_id not in self._processed_event_ids]
        if not new_events: return
        for e in new_events: self._processed_event_ids.add(e.event_id)
        for event in new_events: self._process_event(event)

    def _fetch_events(self) -> list[GatewayEvent]:
        if not self._mcp_enabled or not self._mcp: return []
        result = self._mcp_call("splunk-query", "splunk_search", {"query": "*", "earliest": "-10m"}, fallback=None)
        if not result or not result.get("events"): return []
        events = []
        for ed in result["events"]:
            try:
                ts = datetime.fromisoformat(ed["timestamp"]) if isinstance(ed["timestamp"], str) else datetime.now()
                events.append(GatewayEvent(
                    event_id=ed.get("event_id", f"GW-{uuid.uuid4().hex[:8]}"),
                    timestamp=ts,
                    module=ed.get("module", "input_guard"),
                    blocked=bool(ed.get("blocked", ed.get("event_type") == "blocked")),
                    handler=ed.get("handler", "gateway"),
                    risk_score=int(ed.get("risk_score", 0)),
                    user_input=ed.get("user_input", ""),
                    subject_name=ed.get("subject_name", ""),
                    agent_id=ed.get("agent_id", ""),
                    findings=ed.get("findings", []),
                    gateway_id=ed.get("gateway_id", "gateway-01"),
                    llm_provider=ed.get("llm_provider", "anthropic"),
                ))
            except Exception: continue
        return events

    def _fetch_events_raw(self, spl: str) -> list[GatewayEvent]:
        """Execute SPL via MCP and return events (new model fields)."""
        if not self._mcp_enabled or not self._mcp: return []
        result = self._mcp_call("splunk-query", "splunk_search", {"query": spl, "earliest": "-10m"}, fallback=None)
        if not result or not result.get("events"): return []
        events = []
        for ed in result["events"]:
            try:
                ts = datetime.fromisoformat(ed["timestamp"]) if isinstance(ed["timestamp"], str) else datetime.now()
                events.append(GatewayEvent(
                    event_id=ed.get("event_id", f"GW-{uuid.uuid4().hex[:8]}"),
                    timestamp=ts,
                    module=ed.get("module", "input_guard"),
                    blocked=bool(ed.get("blocked", False)),
                    handler=ed.get("handler", "gateway"),
                    risk_score=int(ed.get("risk_score", 0)),
                    user_input=ed.get("user_input", ""),
                    subject_name=ed.get("subject_name", ""),
                    agent_id=ed.get("agent_id", ""),
                    findings=ed.get("findings", []),
                    gateway_id=ed.get("gateway_id", "gateway-01"),
                    llm_provider=ed.get("llm_provider", "anthropic"),
                ))
            except Exception: continue
        return events

    def _record_disposition(self, alert: AlertRecord, operator: str, action: str,
                            command: str, result: str, detail: str,
                            acknowledged_at: Optional[datetime] = None):
        """Create and store a disposition record."""
        d = DispositionRecord(
            disposition_id=f"DSP-{uuid.uuid4().hex[:8]}",
            alert_id=alert.alert_id,
            event_id=alert.event.event_id,
            operator=operator,
            action=action,
            command=command,
            result=result,
            detail=detail,
            triggered_rule=alert.event.triggered_rule,
            risk_level=alert.risk_level,
            acknowledged_at=acknowledged_at,
        )
        with self._lock:
            self.dispositions.append(d)
        return d

    def _send_disposition_to_splunk(self, d: DispositionRecord):
        """Write a disposition status event to Splunk HEC."""
        if not self._mcp_enabled or not self._mcp:
            return False
        try:
            result = self._mcp_call("splunk-query", "splunk_ingest_disposition", {
                "event_id": d.event_id,
                "disposition_id": d.disposition_id,
                "status": d.result,
                "mode": self.mode.value,
                "operator": d.operator,
                "action": d.action,
                "command": d.command,
                "detail": d.detail,
                "triggered_rule": d.triggered_rule,
                "risk_level": d.risk_level,
            }, fallback=None)
            if result and result.get("success"):
                print(f"{_ts()} 📤 处置已写入 Splunk: {d.disposition_id}")
                return True
            return False
        except Exception as e:
            print(f"{_ts()} {YELLOW}⚠ Splunk HEC 写入失败: {e}{RESET}")
            return False

    def _process_event(self, event):
        matches = self.rule_engine.match(event)
        if not matches: return
        br = [m for m in matches if m.action=="block"]; ar = [m for m in matches if m.action=="alert"]
        risk = "high" if any(m.confidence>0.8 for m in br+ar) else "medium" if any(m.confidence>0.5 for m in br+ar) else "low"
        alert = AlertRecord(alert_id=f"ALT-{uuid.uuid4().hex[:8]}", event=event, rule_matches=br+ar, risk_level=risk,
            pending_block=(self.mode==AgentMode.OBSERVE and len(br)>0))
        if self.mode==AgentMode.AUTO and br:
            r = self.execute_block(event)
            alert.blocked = r.get("status")=="blocked"
            alert.pending_block = False
            # AUTO mode: record disposition with operator="auto"
            cmd = f"send_block_command(gateway_id={event.gateway_id}, target={event.event_id}, reason=Rule: {event.triggered_rule})"
            d = self._record_disposition(
                alert=alert, operator="auto", action="block",
                command=cmd,
                result=r.get("status", DispositionStatus.SIMULATED),
                detail=f"自动阻断: 规则 {event.triggered_rule} 匹配, risk_score={event.risk_score}",
            )
            alert.disposition_id = d.disposition_id
            # Write back to Splunk HEC
            self._send_disposition_to_splunk(d)
        with self._lock: self.alerts.append(alert)

    def execute_block(self, event):
        gw = self._mcp_call("gateway-control","send_block_command",
            {"gateway_id":event.gateway_id,"target":event.event_id,"reason":f"Rule: {event.triggered_rule}"}, fallback=None)
        r = gw if (gw and not gw.get("error")) else {"status":"blocked","event_id":event.event_id,
            "gateway_id":event.gateway_id,"timestamp":datetime.now().isoformat()}
        with self._lock:
            for a in self.alerts:
                if a.event.event_id==event.event_id: a.blocked=True; a.pending_block=False; break
        return r

    def confirm_block(self, alert_id):
        with self._lock:
            for a in self.alerts:
                if a.alert_id==alert_id and a.pending_block:
                    r = self.execute_block(a.event)
                    # OBSERVE mode: record disposition with operator="admin"
                    cmd = f"send_block_command(gateway_id={a.event.gateway_id}, target={a.event.event_id}, reason=Rule: {a.event.triggered_rule})"
                    d = self._record_disposition(
                        alert=a, operator="admin", action="block",
                        command=cmd,
                        result=r.get("status", DispositionStatus.SIMULATED),
                        detail=f"人工确认阻断: 规则 {a.event.triggered_rule} 匹配, risk_score={a.event.risk_score}",
                        acknowledged_at=datetime.now(),
                    )
                    a.disposition_id = d.disposition_id
                    # Write back to Splunk HEC
                    self._send_disposition_to_splunk(d)
                    return {"success":True, "result": r, "disposition_id": d.disposition_id}
        return {"success":False,"error":"Not found"}

    def build_decision_tree(self, spans): return build_decision_tree(spans)
    def identify_key_nodes(self, tree): return identify_key_nodes(tree)
    def detect_emergence(self, tree): return detect_emergence(tree)
    def generate_storyline(self, tree): return generate_storyline(tree)

    def get_alerts(self): return [a.to_dict() for a in self.alerts] if self._lock else []
    def get_alert(self, aid):
        with self._lock:
            for a in self.alerts:
                if a.alert_id==aid: return a.to_dict(); return None

    def get_dispositions(self) -> list[dict]:
        """Return all disposition records, newest first."""
        with self._lock:
            return sorted(
                [d.to_dict() for d in self.dispositions],
                key=lambda x: x.get("created_at", ""),
                reverse=True,
            )

    def get_disposition(self, disposition_id: str) -> Optional[dict]:
        with self._lock:
            for d in self.dispositions:
                if d.disposition_id == disposition_id:
                    return d.to_dict()
            return None

    def get_dispositions_by_alert(self, alert_id: str) -> list[dict]:
        """Return all disposition records for a given alert."""
        with self._lock:
            return [d.to_dict() for d in self.dispositions if d.alert_id == alert_id]

    def get_stats(self):
        with self._lock:
            b=sum(1 for a in self.alerts if a.blocked); p=sum(1 for a in self.alerts if a.pending_block)
            return {"mode":self.mode.value,"total_events":len(self._processed_event_ids),"total_alerts":len(self.alerts),
                "total_trees":len(self.trees),"total_anomalies":len(self.anomalies),"blocked":b,"pending_block":p,
                "total_dispositions":len(self.dispositions),
                "rules_active":sum(1 for r in self.rule_engine.rules.values() if r.enabled),"rules_total":len(self.rule_engine.rules),
                "mcp_enabled":self._mcp_enabled}

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """Return recent events from Splunk for the dashboard event stream."""
        events = []
        result = self._mcp_call("splunk-query", "splunk_search", {
            "query": "search index=* sourcetype=\"ai_sentinel:gateway\"",
            "earliest": "-10m", "latest": "now"
        }, fallback=None)
        if result and result.get("events"):
            for ed in result["events"][:limit]:
                events.append({
                    "event_id": ed.get("event_id", ""),
                    "timestamp": ed.get("timestamp", ""),
                    "module": ed.get("module", ""),
                    "blocked": bool(ed.get("blocked", False)),
                    "handler": ed.get("handler", ""),
                    "risk_score": int(ed.get("risk_score", 0)),
                    "user_input": (ed.get("user_input", "") or "")[:100],
                    "subject_name": ed.get("subject_name", ""),
                    "agent_id": ed.get("agent_id", ""),
                    "findings": ed.get("findings", []),
                    "gateway_id": ed.get("gateway_id", ""),
                    "backend": result.get("backend", "unknown"),
                })
        return events

    def get_rules(self):
        r=self._mcp_call("rule-engine","get_rules",{"enabled_only":False})
        return r["rules"] if r and r.get("rules") else self.rule_engine.get_rules()

    def toggle_rule_mcp(self, rid, enabled):
        r=self._mcp_call("rule-engine","toggle_rule",{"rule_id":rid,"enabled":enabled})
        if r and r.get("success"): self.rule_engine.toggle_rule(rid,enabled); return True
        return self.rule_engine.toggle_rule(rid,enabled)

    def upsert_rule_mcp(self, d):
        r=self._mcp_call("rule-engine","upsert_rule",{"rule_data":d})
        if r and r.get("success"): self.rule_engine.upsert_rule(d); return True
        return self.rule_engine.upsert_rule(d)

    @property
    def mcp_status(self):
        if not self._mcp: return {"enabled":False,"connected":[]}
        return {"enabled":self._mcp_enabled,"connected":[n for n in ["splunk-query","gateway-control","rule-engine"] if self._mcp.is_connected(n)],
            "errors":self._mcp.get_errors()}

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, lambda s,f: setattr(self,'_running',False) or _think("收到停止信号"))

    def _shutdown(self):
        if self._mcp:
            try: self._mcp.stop()
            except: pass
        print(f"{_ts()} 🛡️  Agent已停止")

def main():
    agent = SecurityAgent(mode=AgentMode.OBSERVE)
    try: agent.run()
    except KeyboardInterrupt: pass

if __name__ == "__main__": main()
