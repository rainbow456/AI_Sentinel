# -*- coding: utf-8 -*-
"""
Analyst LLM client — Claude-backed NL→SPL and intent classification.

Mirrors the Gateway's llm_semantic integration (raw HTTP to /v1/messages with
tool_use for structured output, fail-soft on any error). Uses urllib (stdlib)
so it adds no new dependency.

Env vars:
  ANTHROPIC_API_KEY   Claude API Key. If missing, this module is inert and
                      callers fall back to keyword heuristics.
  ANALYST_LLM_MODEL   Model id. Falls back to LLM_DETECT_MODEL (the project's
                      existing fast-path choice), then claude-opus-4-8.
  ANTHROPIC_BASE_URL  Override the API endpoint (self-host/proxy). Default official.
  ANALYST_LLM_TIMEOUT Per-call timeout in seconds (default 8).
"""

# Load .env before reading env vars
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

import os
import json
import urllib.request
import urllib.error

_API_VERSION = "2023-06-01"


def _api_url() -> str:
    # `or` (not getenv default) so an empty ANTHROPIC_BASE_URL= in .env still
    # falls back to the official endpoint instead of yielding "/v1/messages".
    base = (os.getenv("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").strip().rstrip("/")
    return base + "/v1/messages"


def _api_key() -> str:
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


def _model() -> str:
    # Skill default is claude-opus-4-8; reuse the project's fast-path model
    # (LLM_DETECT_MODEL) when present so the interactive NL path stays low-latency.
    return (os.getenv("ANALYST_LLM_MODEL")
            or os.getenv("LLM_DETECT_MODEL")
            or "claude-opus-4-8").strip()


def _timeout() -> float:
    try:
        return float(os.getenv("ANALYST_LLM_TIMEOUT", "8"))
    except ValueError:
        return 8.0


def is_enabled() -> bool:
    """True only when an API key is configured."""
    return bool(_api_key())


def _call_tool(system: str, user: str, tool: dict) -> dict | None:
    """
    Force a single tool call and return its validated input dict.
    Returns None on any error / non-200 / missing tool block (fail-soft).
    """
    key = _api_key()
    if not key:
        return None
    body = {
        "model": _model(),
        "max_tokens": 1024,
        "system": system,
        "tools": [tool],
        "tool_choice": {"type": "tool", "name": tool["name"]},
        "messages": [{"role": "user", "content": user}],
    }
    req = urllib.request.Request(
        _api_url(),
        data=json.dumps(body).encode("utf-8"),
        headers={
            "x-api-key": key,
            "anthropic-version": _API_VERSION,
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for block in data.get("content", []) or []:
            if block.get("type") == "tool_use" and block.get("name") == tool["name"]:
                return block.get("input") or {}
        return None
    except Exception:
        # timeout / network / HTTP error / parse — fail-soft
        return None


# ── NL → SPL ────────────────────────────────────────────────────────────────

_SPL_SYSTEM = (
    "你把分析员的自然语言请求转换成一条合法的 Splunk SPL，用于查询 AI Sentinel 网关安全事件。\n"
    "数据：index=main，sourcetype=\"ai_sentinel:gateway\"。\n"
    "字段：timestamp、module(input_guard|action_guard|skill_scanner)、blocked(true|false)、"
    "risk_score(0-100)、user_input、agent_id、gateway_id、findings{}.rule_hit。\n"
    "findings{}.rule_hit 的取值即网关检测 taxonomy，例如：prompt_injection、"
    "system_instruction_override、role_play、high_risk_action_keyword、destructive_command、"
    "shell_process_exec、api_key、high_entropy_blob、email、phone、presidio:URL、multilingual。\n"
    "时间范围由外部 earliest/latest 单独下发——SPL 里【不要】写 earliest=/latest=。\n"
    "示例：\n"
    "  '最近被拦截的提示词注入' -> search index=main sourcetype=\"ai_sentinel:gateway\" "
    "blocked=true \"findings{}.rule_hit\"=prompt_injection\n"
    "  '放行但高风险的事件' -> search index=main sourcetype=\"ai_sentinel:gateway\" "
    "blocked=false risk_score>=70\n"
    "  '按 module 统计数量' -> search index=main sourcetype=\"ai_sentinel:gateway\" | stats count by module\n"
    "只通过 emit_spl 工具返回最终 SPL。"
)

_SPL_TOOL = {
    "name": "emit_spl",
    "description": "Return the final Splunk SPL query string for the user's request.",
    "input_schema": {
        "type": "object",
        "properties": {
            "spl": {"type": "string", "description": "A single valid SPL search string"},
        },
        "required": ["spl"],
    },
}


def nl_to_spl(query: str) -> str | None:
    """Convert NL to SPL via Claude. Returns None on failure (caller falls back)."""
    if not query or not query.strip():
        return None
    out = _call_tool(_SPL_SYSTEM, query.strip(), _SPL_TOOL)
    if out and isinstance(out.get("spl"), str) and out["spl"].strip():
        return out["spl"].strip()
    return None


# ── Intent classification ────────────────────────────────────────────────────

_INTENT_SYSTEM = (
    "你是安全分析平台的指令意图分类器。把操作员的自然语言指令归为唯一意图：\n"
    "  query        —— 查询/检索事件、统计、日志\n"
    "  action       —— 封禁/解封 IP、启停某条规则等处置动作\n"
    "  rules_search —— 查找/检索安全规则\n"
    "  mode_switch  —— 切换 AUTO/OBSERVE 运行模式\n"
    "  rule_config  —— 新建/修改一条规则\n"
    "只通过 emit_intent 工具返回。"
)

_INTENT_TOOL = {
    "name": "emit_intent",
    "description": "Classify the operator's command into exactly one intent.",
    "input_schema": {
        "type": "object",
        "properties": {
            "intent": {
                "type": "string",
                "enum": ["query", "action", "rules_search", "mode_switch", "rule_config"],
            },
        },
        "required": ["intent"],
    },
}

_VALID_INTENTS = {"query", "action", "rules_search", "mode_switch", "rule_config"}


def classify_intent(query: str) -> str | None:
    """Classify intent via Claude. Returns one of the 5 intents, or None on failure."""
    if not query or not query.strip():
        return None
    out = _call_tool(_INTENT_SYSTEM, query.strip(), _INTENT_TOOL)
    if out and out.get("intent") in _VALID_INTENTS:
        return out["intent"]
    return None
