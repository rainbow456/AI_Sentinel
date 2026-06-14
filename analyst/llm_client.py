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


def _provider() -> str:
    return (os.getenv("LLM_PROVIDER") or "anthropic").strip().lower()


def _is_anthropic() -> bool:
    return _provider() in ("anthropic", "claude", "")


def _api_key() -> str:
    if _is_anthropic():
        return os.getenv("ANTHROPIC_API_KEY", "").strip()
    # Domestic / OpenAI-compatible providers (DeepSeek, etc.)
    return (os.getenv("LLM_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
            or os.getenv("OPENAI_API_KEY") or "").strip()


def _base_url() -> str:
    if _is_anthropic():
        return (os.getenv("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").strip().rstrip("/")
    default = "https://api.deepseek.com" if _provider() == "deepseek" else "https://api.openai.com"
    return (os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL") or default).strip().rstrip("/")


def _model() -> str:
    return (os.getenv("ANALYST_LLM_MODEL")
            or os.getenv("LLM_DETECT_MODEL")
            or ("claude-opus-4-8" if _is_anthropic() else "deepseek-chat")).strip()


def _timeout() -> float:
    try:
        return float(os.getenv("ANALYST_LLM_TIMEOUT", "8"))
    except ValueError:
        return 8.0


def is_enabled() -> bool:
    """True only when an API key is configured for the active provider."""
    return bool(_api_key())


def _http_post_json(url: str, body: dict, headers: dict) -> dict | None:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None  # timeout / network / HTTP / parse — fail-soft


def _extract_json(s: str) -> dict | None:
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        pass
    i, j = s.find("{"), s.rfind("}")
    if i != -1 and j != -1 and j > i:
        try:
            return json.loads(s[i:j + 1])
        except Exception:
            return None
    return None


def _call_tool(system: str, user: str, tool: dict) -> dict | None:
    """Force a single structured output and return its field dict; fail-soft to None on any error.
    provider=anthropic → /v1/messages + tool_use;
    provider=deepseek/openai → OpenAI-compatible /chat/completions + JSON mode."""
    key = _api_key()
    if not key:
        return None
    if _is_anthropic():
        body = {
            "model": _model(), "max_tokens": 1024, "system": system,
            "tools": [tool], "tool_choice": {"type": "tool", "name": tool["name"]},
            "messages": [{"role": "user", "content": user}],
        }
        data = _http_post_json(_base_url() + "/v1/messages", body, {
            "x-api-key": key, "anthropic-version": _API_VERSION, "content-type": "application/json"})
        if not data:
            return None
        for block in data.get("content", []) or []:
            if block.get("type") == "tool_use" and block.get("name") == tool["name"]:
                return block.get("input") or {}
        return None
    # OpenAI-compatible (DeepSeek, etc.): JSON mode to force structured output
    keys = list((tool.get("input_schema", {}).get("properties") or {}).keys())
    sys_prompt = system + f"\n\nOutput a single JSON object only (no markdown, no explanation), with fields: {', '.join(keys)}."
    body = {
        "model": _model(),
        "messages": [{"role": "system", "content": sys_prompt},
                     {"role": "user", "content": user}],
        "response_format": {"type": "json_object"},
        "max_tokens": 1024, "temperature": 0, "stream": False,
    }
    data = _http_post_json(_base_url() + "/chat/completions", body, {
        "Authorization": f"Bearer {key}", "content-type": "application/json"})
    if not data:
        return None
    content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
    return _extract_json(content)


# ── NL → SPL ────────────────────────────────────────────────────────────────

_SPL_SYSTEM = (
    "You convert an analyst's natural-language request into a single valid Splunk SPL query "
    "for AI Sentinel gateway security events.\n"
    "Data: index=main, sourcetype=\"ai_sentinel:gateway\".\n"
    "Fields: timestamp, module(input_guard|action_guard|skill_scanner), blocked(true|false), "
    "risk_score(0-100), user_input, agent_id, gateway_id, findings{}.rule_hit.\n"
    "The values of findings{}.rule_hit are the gateway detection taxonomy, e.g.: prompt_injection, "
    "system_instruction_override, role_play, high_risk_action_keyword, destructive_command, "
    "shell_process_exec, api_key, high_entropy_blob, email, phone, presidio:URL, multilingual.\n"
    "The time range is supplied separately via earliest/latest — do NOT write earliest=/latest= in the SPL.\n"
    "Examples:\n"
    "  'recently blocked prompt injections' -> search index=main sourcetype=\"ai_sentinel:gateway\" "
    "blocked=true \"findings{}.rule_hit\"=prompt_injection\n"
    "  'passed but high-risk events' -> search index=main sourcetype=\"ai_sentinel:gateway\" "
    "blocked=false risk_score>=70\n"
    "  'count by module' -> search index=main sourcetype=\"ai_sentinel:gateway\" | stats count by module\n"
    "Return the final SPL only via the emit_spl tool."
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
    "You are the command-intent classifier for a security analysis platform. "
    "Classify the operator's natural-language command into exactly one intent:\n"
    "  query        — query/retrieve events, statistics, logs\n"
    "  action       — disposition actions such as ban/unban IP, enable/disable a rule\n"
    "  rules_search — find/search security rules\n"
    "  mode_switch  — switch the AUTO/OBSERVE operating mode\n"
    "  rule_config  — create/modify a rule\n"
    "Return only via the emit_intent tool."
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


# ── Disposition recommendation (held gray-zone alerts) ───────────────────────

_DISPO_SYSTEM = (
    "You are the disposition advisor for an AI security analysis platform. You are given a security "
    "event that the gateway did NOT block but flagged as suspicious and held for human adjudication. "
    "Judge its real risk and recommend dispositions from a fixed set (multiple allowed).\n"
    "Disposition keys:\n"
    "  block            — block this request (the front-end agent does not execute it)\n"
    "  ban_ip           — ban the source IP / agent\n"
    "  optimize_gateway — optimize gateway policy: distill this attack into a new cheap gateway rule\n"
    "  optimize_mcp     — optimize the agent's own tool/MCP policy (e.g. add re-authorization to an action, disable a tool)\n"
    "  accept_risk      — accept the risk and allow it (only when confirmed false-positive/low-risk)\n"
    "Principles: truly malicious → include at least block; reusable attack pattern → add optimize_gateway; "
    "clear false-positive → accept_risk only. Give reasoning as one English sentence; do not echo raw sensitive content. "
    "Return only via emit_disposition."
)

_DISPO_TOOL = {
    "name": "emit_disposition",
    "description": "Recommend a disposition for a held (gray-zone) security event.",
    "input_schema": {
        "type": "object",
        "properties": {
            "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
            "category": {"type": "string",
                         "description": "e.g. social_engineering / indirect_injection / benign"},
            "reasoning": {"type": "string", "description": "one-sentence English rationale"},
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string",
                          "enum": ["block", "ban_ip", "optimize_gateway",
                                   "optimize_mcp", "accept_risk"]},
            },
            "suggested_rule": {
                "type": "object",
                "description": "Draft gateway rule to provide when recommending optimize_gateway",
                "properties": {
                    "name": {"type": "string"},
                    "patterns": {"type": "array", "items": {"type": "string"}},
                    "description": {"type": "string"},
                },
            },
        },
        "required": ["risk_score", "category", "reasoning", "recommended_actions"],
    },
}


def recommend_disposition(summary: str) -> dict | None:
    """
    Ask Claude to recommend a disposition for a held event. Returns the validated
    emit_disposition dict, or None on failure (caller falls back to rule-based).
    """
    if not summary or not summary.strip():
        return None
    return _call_tool(_DISPO_SYSTEM, summary.strip(), _DISPO_TOOL)
