"""
Natural Language Engine — intent classification, action parsing, rule search,
SPL generation, demo data, display helpers, and rule configuration parsing.

Extracted from agent.py to keep individual files under 600 lines.

Architecture:
  1. User NL input -> intent classifier (keyword or LLM)
  2. Intent = query | action | rules_search | mode_switch | rule_config
  3. Action commands -> structured JSON -> MCP tool call
  4. Rule searches -> get_rules -> LLM/keyword filter -> ranked results
  5. Rule config commands -> structured RuleDef -> MCP upsert_rule
"""

import json
import re
from datetime import datetime
from typing import Any, Optional

# ── Intent types ──────────────────────────────────────────────────────────

INTENT_QUERY = "query"
INTENT_ACTION = "action"
INTENT_RULES_SEARCH = "rules_search"
INTENT_MODE_SWITCH = "mode_switch"
INTENT_RULE_CONFIG = "rule_config"
INTENT_UNKNOWN = "unknown"

# ── Keyword patterns for intent classification ────────────────────────────

_ACTION_PATTERNS = [
    (r"阻断|封锁|屏蔽|拒绝|block|ban", "action_block"),
    (r"解封|解除|放行|unblock|release|allow", "action_unblock"),
    (r"切换.*(自动|auto)|进入.*(自动|auto)|设为.*(自动|auto)", "mode_auto"),
    (r"切换.*(观察|observe)|进入.*(观察|observe)|设为.*(观察|observe)", "mode_observe"),
    (r"开启.*自动|自动.*模式|auto.*mode|切换模式", "mode_auto"),
    (r"禁用.*规则|关闭.*规则|停用.*规则|disable.*rule|rule.*off", "rule_disable"),
    (r"启用.*规则|开启.*规则|激活.*规则|enable.*rule|rule.*on", "rule_enable"),
]

_RULE_CONFIG_PATTERNS = [
    r"添加规则|创建规则|新增规则|add.*rule|create.*rule|new.*rule",
    r"修改规则|更新规则|编辑规则|update.*rule|edit.*rule|modify.*rule",
    r"规则.*模式.*包含|规则.*patterns.*=|rule.*patterns",
]

_QUERY_PATTERNS = [
    r"查看|列出|搜索|查询|显示|统计|report|search|show|list|find|query",
    r"过去.*小时|最近.*分钟|今天|昨天|last.*hour|recent",
]

_RULES_SEARCH_PATTERNS = [
    r"规则.*关于|有哪些规则|显示.*规则|搜索.*规则|rule.*about|find.*rule|list.*rule",
    r"什么规则|规则搜索|rules about|rules for",
]

_MODE_PATTERNS = [
    r"切换.*模式|模式切换|set.*mode|change.*mode|switch.*mode",
]


def classify_intent(text: str) -> str:
    """Classify a natural language input into one of the defined intents."""
    q = text.lower().strip()

    # 1. Mode switch (highest priority)
    if any(re.search(p, q) for p in _MODE_PATTERNS):
        return INTENT_MODE_SWITCH

    # 2. Rule config (add / modify / create rule)
    if any(re.search(p, q) for p in _RULE_CONFIG_PATTERNS):
        return INTENT_RULE_CONFIG

    # 3. Action commands
    for pat, _ in _ACTION_PATTERNS:
        if re.search(pat, q):
            if re.search(r"查看|显示|列出|查询|历史|记录|list|show|history", q) and \
               re.search(r"阻断|block|拦截", q):
                return INTENT_QUERY
            return INTENT_ACTION

    # 4. Rules search
    if any(re.search(p, q) for p in _RULES_SEARCH_PATTERNS):
        return INTENT_RULES_SEARCH

    # 5. Query (default)
    if any(re.search(p, q) for p in _QUERY_PATTERNS):
        return INTENT_QUERY

    return INTENT_QUERY


# ── Action parsing ────────────────────────────────────────────────────────

def parse_action(text: str) -> dict:
    """Parse a natural language action command into structured form."""
    q = text.lower().strip()
    result = {"action_type": "unknown", "target": "", "params": {}, "confidence": 0.0, "original_text": text}

    # Block IP
    block_match = re.search(
        r"(?:阻断|封锁|屏蔽|拒绝|block|ban)\s*(?:IP\s*)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", q)
    if block_match:
        ip = block_match.group(1)
        reason = "user request"
        reason_m = re.search(r"原因[：:为]?\s*(.+?)(?:$|，|。)", text)
        if reason_m:
            reason = reason_m.group(1).strip()
        result.update({"action_type": "block", "target": ip,
                       "params": {"gateway_id": "gw-prod-01", "target": ip, "reason": reason}, "confidence": 0.95})
        return result

    # Block event
    block_event = re.search(r"(?:阻断|封锁|block)\s*(?:事件|event|ID\s*)?([A-Za-z0-9\-]+)", q)
    if block_event:
        result.update({"action_type": "block", "target": block_event.group(1),
                       "params": {"gateway_id": "gw-prod-01", "target": block_event.group(1), "reason": "user request"},
                       "confidence": 0.85})
        return result

    # Unblock IP
    unblock_match = re.search(
        r"(?:解封|解除|放行|unblock|release)\s*(?:IP\s*)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", q)
    if unblock_match:
        result.update({"action_type": "unblock", "target": unblock_match.group(1),
                       "params": {"target": unblock_match.group(1)}, "confidence": 0.95})
        return result

    # Unblock any
    unblock_any = re.search(r"(?:解封|解除|放行|unblock|release)\s*(.+?)(?:$|，|。)", text)
    if unblock_any:
        result.update({"action_type": "unblock", "target": unblock_any.group(1).strip(),
                       "params": {"target": unblock_any.group(1).strip()}, "confidence": 0.8})
        return result

    # Toggle rule
    disable_rule = re.search(r"(?:禁用|关闭|停用|disable)\s*(?:规则|rule)\s*[#：: ]*([A-Za-z0-9\-]+)", q)
    if disable_rule:
        result.update({"action_type": "toggle_rule", "target": disable_rule.group(1).upper(),
                       "params": {"rule_id": disable_rule.group(1).upper(), "enabled": False}, "confidence": 0.9})
        return result

    enable_rule = re.search(r"(?:启用|开启|激活|enable)\s*(?:规则|rule)\s*[#：: ]*([A-Za-z0-9\-]+)", q)
    if enable_rule:
        result.update({"action_type": "toggle_rule", "target": enable_rule.group(1).upper(),
                       "params": {"rule_id": enable_rule.group(1).upper(), "enabled": True}, "confidence": 0.9})
        return result

    return result


# ── Rule configuration parsing (NEW) ──────────────────────────────────────

def parse_rule_config(text: str) -> dict:
    """
    Parse a natural language rule configuration command.

    Supported patterns (commands may be issued in Chinese or English):
      "add rule: detect XXX, patterns include a/b/c, action block, severity critical"
      "modify rule R003: patterns are ignore/forget/jailbreak"
      "create rule: name sensitive_data, description detect sensitive data..."

    Returns:
      {"action": "create"|"update", "rule_id": str|None, "rule_data": dict, "confidence": float}
    """
    q = text.lower().strip()
    result = {"action": "unknown", "rule_id": None, "rule_data": {}, "confidence": 0.0, "original_text": text}

    # Detect create vs update
    is_create = bool(re.search(r"添加|创建|新增|add|create|new", q))
    is_update = bool(re.search(r"修改|更新|编辑|update|edit|modify", q))

    if not (is_create or is_update):
        return result

    # Extract rule_id from update commands: "修改规则 R003"
    rule_id = None
    if is_update:
        rid_match = re.search(r"(?:规则|rule)\s*[#：: ]*([A-Za-z0-9\-]+)", q)
        if rid_match:
            rule_id = rid_match.group(1).upper()

    if is_create:
        # Auto-generate rule_id for new rules
        rule_id = rule_id or "R007"

    # Build rule_data dict from NL patterns
    rule_data = {"rule_id": rule_id}

    # Extract name
    name_match = re.search(r"名称[：:为]?\s*(\S+)", text)
    if name_match:
        rule_data["name"] = name_match.group(1).strip()
    elif is_create:
        # Infer name from description
        desc_match = re.search(r"检测[：:到]?\s*(.+?)(?:，|,|$)", text)
        if desc_match:
            rule_data["name"] = desc_match.group(1).strip()[:30]

    # Extract description
    desc_match = re.search(r"(?:检测|描述)[：:到]?\s*(.+?)(?:，模式|，动作|$)", text)
    if desc_match:
        rule_data["description"] = desc_match.group(1).strip()

    # Extract patterns
    patterns = []
    patterns_match = re.search(r"模式[：:包含为]?\s*(.+?)(?:，动作|，严重|$)", text)
    if patterns_match:
        raw = patterns_match.group(1)
        # Split by / and , and remove whitespace
        for sep in ["/", "、", "，", ","]:
            if sep in raw:
                patterns = [p.strip().strip("'\"") for p in raw.split(sep) if p.strip()]
                break
        if not patterns:
            # Space-separated
            patterns = [p.strip().strip("'\"") for p in raw.split() if p.strip() and len(p.strip()) > 1]
    if not patterns and is_create:
        patterns = ["default_pattern"]  # placeholder

    rule_data["patterns"] = patterns or ["default_pattern"]

    # Extract action
    action_match = re.search(r"动作[：:为]?\s*(block|alert|阻断|告警)", q)
    if action_match:
        action_raw = action_match.group(1)
        rule_data["action"] = "block" if action_raw in ("block", "阻断") else "alert"
    else:
        rule_data["action"] = "block"  # default for new rules

    # Extract severity
    sev_match = re.search(r"严重[：:级别]?\s*(critical|high|medium|low|严重|高危|中危|低危)", q)
    if sev_match:
        sev_map = {"critical": "critical", "严重": "critical", "high": "high",
                   "高危": "high", "medium": "medium", "中危": "medium",
                   "low": "low", "低危": "low"}
        rule_data["severity"] = sev_map.get(sev_match.group(1), "medium")
    else:
        rule_data["severity"] = "high"

    # Extract nl_config (store the original NL description)
    if not rule_data.get("description"):
        rule_data["description"] = f"Created via NL: {text[:80]}"
    rule_data["nl_config"] = text

    result.update({
        "action": "create" if is_create else "update",
        "rule_id": rule_id,
        "rule_data": rule_data,
        "confidence": 0.85 if (is_create or is_update) else 0.0,
    })
    return result


# ── Rule semantic search ─────────────────────────────────────────────────

def search_rules(query: str, rules: list[dict]) -> list[dict]:
    """Search rules by natural language query using keyword-based semantic matching."""
    q = query.lower().strip()
    scored = []

    topic_keywords = {
        "injection": ["注入", "sql", "xss", "命令注入", "injection", "脚本", "union", "select"],
        "sensitive_data": ["敏感", "泄露", "密钥", "密码", "token", "credential", "secret", "leak", "password"],
        "prompt_injection": ["提示词", "prompt", "jailbreak", "系统指令", "ignore", "覆盖指令"],
        "collusion": ["共谋", "collusion", "agent", "协作", "私信", "私下", "非授权", "合伙"],
        "rate_limit": ["频率", "速率", "限流", "rate", "429", "too many"],
        "data_exfiltration": ["外泄", "导出", "批量", "exfil", "dump", "export", "select *"],
    }

    for rule in rules:
        score = 0.0
        match_reasons = []
        searchable = " ".join(str(v) for v in [
            rule.get("name", ""), rule.get("description", ""), rule.get("rule_id", ""),
            " ".join(rule.get("patterns", [])), rule.get("nl_config", ""),
        ]).lower()

        for topic, keywords in topic_keywords.items():
            kw_hits = sum(1 for kw in keywords if kw in q)
            if kw_hits > 0:
                desc_hits = sum(1 for kw in keywords if kw in searchable)
                topic_score = (kw_hits / max(len(keywords), 1)) * 0.4 + \
                              (desc_hits / max(len(keywords), 1)) * 0.6
                if topic_score > 0:
                    score = max(score, topic_score)
                    match_reasons.append(topic)

        query_words = set(re.findall(r'[a-z\u4e00-\u9fff]+', q))
        rule_words = set(re.findall(r'[a-z\u4e00-\u9fff]+', searchable))
        overlap = query_words & rule_words
        if len(query_words) > 0 and len(overlap) > 0:
            word_score = len(overlap) / len(query_words) * 0.8
            score = max(score, word_score)
            match_reasons.extend(list(overlap)[:3])

        if score > 0:
            scored.append({**rule, "_score": round(score, 3), "_match_reasons": list(set(match_reasons))})

    scored.sort(key=lambda r: r["_score"], reverse=True)
    return scored


# ── Natural language feedback generators ─────────────────────────────────

def format_action_result(action: dict, raw_result: Any) -> str:
    """Convert an action execution result into natural language feedback."""
    if isinstance(raw_result, str):
        try:
            raw_result = json.loads(raw_result)
        except json.JSONDecodeError:
            pass

    action_type = action.get("action_type", "unknown")
    target = action.get("target", "")
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    if action_type == "block":
        if isinstance(raw_result, dict):
            block_id = raw_result.get("block_id", "N/A")
            if raw_result.get("status") == "blocked":
                return (f"✅ Successfully blocked target \"{target}\"\n   · Block ID: {block_id}\n"
                        f"   · Reason: {raw_result.get('reason', 'user request')}\n"
                        f"   · Effective at: {raw_result.get('timestamp', ts)}")
        return f"⚠️ Failed to block target \"{target}\"; please check the MCP connection status."

    elif action_type == "unblock":
        if isinstance(raw_result, dict) and raw_result.get("success"):
            count = raw_result.get("released_count", 0)
            return f"✅ Unblocked target \"{target}\", released {count} block record(s)\n   · Unblocked at: {raw_result.get('released_at', ts)}"
        return f"⚠️ No active block records found for target \"{target}\"."

    elif action_type == "toggle_rule":
        rid = action.get("target", "")
        enabled = action["params"].get("enabled", True)
        state_str = "enabled" if enabled else "disabled"
        if isinstance(raw_result, dict) and raw_result.get("success", True):
            return f"✅ Rule {rid} {state_str}"
        return f"⚠️ Failed to set rule {rid} to {state_str}."

    return f"Executed action: {action_type} -> {target}"


def format_rule_config_result(config: dict, raw_result: Any) -> str:
    """Format the result of a rule configuration command."""
    action = config.get("action", "unknown")
    rid = config.get("rule_id", "?")
    if isinstance(raw_result, dict):
        if raw_result.get("success"):
            if action == "create":
                return f"✅ Created new rule {rid} with {len(config.get('rule_data', {}).get('patterns', []))} detection pattern(s)"
            return f"✅ Updated rule {rid}"
        return f"⚠️ Rule operation failed: {raw_result.get('error', 'unknown')}"
    return f"⚠️ Rule operation result unknown"


# ── Demo scenarios ───────────────────────────────────────────────────────

DEMO_SCENARIOS = [
    {"title": "Simulate collusion attack and auto-block", "query": "模拟一次共谋攻击并自动阻断",
     "description": "Trigger action_confirmation event -> rule R004 matches -> auto-block"},
    {"title": "View injection attacks in the last hour", "query": "查看过去1小时的注入攻击",
     "description": "View all block events related to SQL injection / XSS"},
    {"title": "List collusion alerts", "query": "列出所有共谋告警",
     "description": "List all events flagged as collusion"},
    {"title": "Search rules about data leakage", "query": "有哪些关于数据泄露的规则",
     "description": "Search the rule engine for rules related to sensitive data leakage"},
    {"title": "Switch to AUTO mode", "query": "切换到自动模式",
     "description": "Switch the gateway mode to AUTO"},
    {"title": "Add rule", "query": "添加规则：检测SQL注入，模式包含 select/union/drop，动作 block",
     "description": "Create a new rule via natural language"},
    {"title": "View current block list", "query": "查看当前已阻断的目标",
     "description": "List all active block records"},
]


def get_demo_scenarios() -> list[dict]:
    return DEMO_SCENARIOS