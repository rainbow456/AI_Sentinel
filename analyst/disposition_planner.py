# -*- coding: utf-8 -*-
"""
Disposition Planner — translates "matched rules" into "actionable disposition plans".

Each matched rule → one plan dict:
  rule_id / rule_name / severity / disp_action(block|observe) / title / plan_text / command

Design constraint: the gateway only has /bans (ban/unban) capability.
- block-type rules → disp_action="block": truly actionable, bans the source agent/IP.
- alert-type rules → disp_action="observe": no gateway action; execution = log +
  redaction/notification recommendation. Only writes a status disposition log back to
  Splunk (faithfully reflecting that the gateway has no corresponding ban capability).
"""

from typing import Any

# rule name → (title, disposition description); falls back to a generic template by action.
_RULE_PLAN = {
    "prompt_injection":            ("Block prompt injection", "Ban the source agent/IP, drop this request, and add to the watchlist."),
    "system_instruction_override": ("Block system instruction override", "Ban the source and intercept requests attempting to rewrite/leak system instructions."),
    "role_play":                   ("Block role-play jailbreak", "Ban the source and reject privilege-escalating role-play requests."),
    "abnormal_collaboration":      ("Block agent collusion", "Suspend the involved agents' permissions, ban the unauthorized actions they exchange, and manually audit the communication chain."),
    "high_risk_action_keyword":    ("Intercept high-risk action", "Ban the source, block high-risk actions such as delete/transfer/authorize, and require a second confirmation."),
    "destructive_command":         ("Intercept destructive command", "Immediately ban the source and block execution of destructive commands such as drop/delete/rm."),
    "sql_injection":               ("Intercept SQL injection", "Ban the source, block UNION/tautology/stacked queries, use parameterized queries, and audit data access."),
    "shell_process_exec":          ("Intercept command execution", "Ban the source and block shell/process execution attempts."),
    "api_key":                     ("Block secret leak", "Ban the source, block requests containing keys/credentials, and trigger the key rotation process."),
    "high_entropy_blob":           ("Review high-entropy payload", "Log and flag for review: suspected key/encoded payload; manually confirm whether a leak occurred."),
    "pii_email":                   ("Redact email PII", "Log and redact the email address; notify per compliance requirements."),
    "pii_phone":                   ("Redact phone PII", "Log and redact the phone number; notify per compliance requirements."),
    "pii_url":                     ("Review URL", "Log the matched URL and flag for review of possible exfiltration/phishing."),
    "multilingual_evasion":        ("Review multilingual evasion", "Log the mixed-language evasion and escalate to manual semantic review."),
}


def plan_for_match(match: Any, event: Any) -> dict:
    """Given one RuleMatch + event, produce an actionable disposition plan."""
    rule_name = getattr(match, "rule_name", "") or ""
    rule_id = getattr(match, "rule_id", "") or ""
    rule_action = getattr(match, "action", "alert") or "alert"

    target = getattr(event, "agent_id", "") or getattr(event, "gateway_id", "") or getattr(event, "event_id", "")
    sev = "high" if rule_action == "block" else "medium"

    title, desc = _RULE_PLAN.get(
        rule_name,
        ("Intercept and ban the source" if rule_action == "block" else "Log and manually review",
         "Ban the source agent/IP." if rule_action == "block" else "Log this hit and escalate to manual review."),
    )

    if rule_action == "block":
        disp_action = "block"
        command = f"send_block_command(target={target}, reason=Rule:{rule_name})"
    else:
        disp_action = "observe"
        command = f"observe(rule={rule_name}, target={target})"

    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": sev,
        "disp_action": disp_action,   # block | observe
        "title": title,
        "plan_text": desc,
        "command": command,
        "target": target,
    }


def plans_for_alert(alert: Any) -> list[dict]:
    """Generate disposition plans for all matched rules of one alert (block first, then alert)."""
    matches = list(getattr(alert, "rule_matches", []) or [])
    matches.sort(key=lambda m: 0 if getattr(m, "action", "") == "block" else 1)
    return [plan_for_match(m, alert.event) for m in matches]


# ── AI disposition recommendations for gray-zone held alerts (multi-select) ──────────
# Fixed disposition menu. Items with real=True are actually applied this round; real=False only logs the recommendation.
DISPOSITION_OPTIONS = [
    {"key": "block", "label": "Intercept this request",
     "desc": "Adjudicate as intercept → the frontend agent does not perform this action.", "real": True},
    {"key": "ban_ip", "label": "Ban source IP / agent",
     "desc": "Add the source to the gateway ban list (recommendation only this round).", "real": False},
    {"key": "optimize_gateway", "label": "Optimize gateway policy (AI-generated rule)",
     "desc": "Distill this attack class into a new cheap gateway rule that blocks on literal match next time.", "real": True},
    {"key": "optimize_mcp", "label": "Optimize the agent's own MCP policy",
     "desc": "Add second-factor authorization or disable the agent's tools/actions (recommendation only this round).", "real": False},
    {"key": "accept_risk", "label": "Accept risk and allow",
     "desc": "Confirmed as a false positive/acceptable → allow this request and let the agent continue.", "real": True},
]
_VALID_KEYS = {o["key"] for o in DISPOSITION_OPTIONS}


def _fallback_recommendation(alert: Any) -> dict:
    """Rule-based fallback recommendation when no LLM is available: suggest dispositions based on matched rules/risk."""
    matches = list(getattr(alert, "rule_matches", []) or [])
    has_block = any(getattr(m, "action", "") == "block" for m in matches)
    score = int(getattr(getattr(alert, "event", None), "risk_score", 0) or 0)
    rule = getattr(getattr(alert, "event", None), "triggered_rule", "") or ""
    if has_block or score >= 60:
        rec = ["block", "optimize_gateway"]
        reasoning = f"Hit a block-level rule / high risk (score={score}); recommend intercepting and distilling the pattern into a gateway rule."
    elif score >= 40:
        rec = ["block"]
        reasoning = f"Gray-zone suspicious (score={score}); recommend intercepting this request first for manual review."
    else:
        rec = ["accept_risk"]
        reasoning = f"Low risk (score={score}); risk can be accepted and the request allowed."
    return {"risk_score": score, "category": rule or "suspicious",
            "reasoning": reasoning, "recommended_actions": rec,
            "suggested_rule": None, "source": "rule"}


def build_recommendation(alert: Any, llm_result: dict | None) -> dict:
    """
    Merge the "LLM recommendation" with the "fixed disposition menu" into a structure the
    frontend can render directly:
      {risk_score, category, reasoning, source, suggested_rule,
       options:[{key,label,desc,real,recommended}]}
    llm_result is the return value of llm_client.recommend_disposition (may be None → rule fallback).
    """
    if llm_result and isinstance(llm_result.get("recommended_actions"), list):
        rec = {
            "risk_score": int(llm_result.get("risk_score", 0) or 0),
            "category": str(llm_result.get("category", "suspicious")),
            "reasoning": str(llm_result.get("reasoning", "")).strip()[:400],
            "recommended_actions": [a for a in llm_result["recommended_actions"]
                                    if a in _VALID_KEYS],
            "suggested_rule": llm_result.get("suggested_rule"),
            "source": "llm",
        }
        if not rec["recommended_actions"]:
            rec["recommended_actions"] = _fallback_recommendation(alert)["recommended_actions"]
    else:
        rec = _fallback_recommendation(alert)

    recset = set(rec["recommended_actions"])
    options = [{**o, "recommended": o["key"] in recset} for o in DISPOSITION_OPTIONS]
    return {
        "risk_score": rec["risk_score"],
        "category": rec["category"],
        "reasoning": rec["reasoning"],
        "source": rec["source"],
        "suggested_rule": rec.get("suggested_rule"),
        "recommended_actions": rec["recommended_actions"],
        "options": options,
    }
