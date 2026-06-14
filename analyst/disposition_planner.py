# -*- coding: utf-8 -*-
"""
Disposition Planner — 把"匹配到的规则"翻译成"可执行处置方案"。

每条匹配规则 → 一个方案 dict：
  rule_id / rule_name / severity / disp_action(block|observe) / title / plan_text / command

设计约束：网关只有 /bans(封禁/解封) 能力。
- block 类规则 → disp_action="block"：真·可执行，封禁来源 agent/IP。
- alert 类规则 → disp_action="observe"：无网关动作，执行=记录+脱敏/通知建议，
  仅写一条 status 处置日志回 Splunk（如实反映网关无对应封禁能力）。
"""

from typing import Any

# 规则名 → (中文标题, 处置说明)；找不到时按 action 走通用模板。
_RULE_PLAN = {
    "prompt_injection":            ("阻断提示词注入", "封禁来源 agent/IP，丢弃本次请求，加入观察名单。"),
    "system_instruction_override": ("阻断系统指令覆盖", "封禁来源，拦截试图改写/泄露系统指令的请求。"),
    "role_play":                   ("阻断角色扮演越狱", "封禁来源，拒绝越权角色扮演请求。"),
    "abnormal_collaboration":      ("阻断 Agent 共谋", "暂停涉事 Agent 权限，封禁其互发的非授权动作，人工审计通信链。"),
    "high_risk_action_keyword":    ("拦截高危动作", "封禁来源，阻断删除/转账/授权等高危动作，要求二次确认。"),
    "destructive_command":         ("拦截破坏性命令", "立即封禁来源，阻断 drop/delete/rm 等破坏性命令执行。"),
    "shell_process_exec":          ("拦截命令执行", "封禁来源，阻断 shell/进程执行尝试。"),
    "api_key":                     ("阻断密钥泄露", "封禁来源，阻断含密钥/凭据的请求，触发密钥轮换流程。"),
    "high_entropy_blob":           ("复核高熵载荷", "记录并标记复核：疑似密钥/编码载荷，人工确认是否泄露。"),
    "pii_email":                   ("脱敏邮箱 PII", "记录并对邮箱做脱敏处理，按合规要求通知。"),
    "pii_phone":                   ("脱敏电话 PII", "记录并对电话号码做脱敏处理，按合规要求通知。"),
    "pii_url":                     ("复核 URL", "记录命中的 URL，标记复核是否为外泄/钓鱼。"),
    "multilingual_evasion":        ("复核多语种规避", "记录多语种混写规避，转人工复核语义。"),
}


def plan_for_match(match: Any, event: Any) -> dict:
    """根据一条 RuleMatch + 事件，产出可执行处置方案。"""
    rule_name = getattr(match, "rule_name", "") or ""
    rule_id = getattr(match, "rule_id", "") or ""
    rule_action = getattr(match, "action", "alert") or "alert"

    target = getattr(event, "agent_id", "") or getattr(event, "gateway_id", "") or getattr(event, "event_id", "")
    sev = "high" if rule_action == "block" else "medium"

    title, desc = _RULE_PLAN.get(
        rule_name,
        ("拦截并封禁来源" if rule_action == "block" else "记录并人工复核",
         "封禁来源 agent/IP。" if rule_action == "block" else "记录该命中，转人工复核。"),
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
    """对一条告警的所有匹配规则生成处置方案（按 block 优先、其次 alert）。"""
    matches = list(getattr(alert, "rule_matches", []) or [])
    matches.sort(key=lambda m: 0 if getattr(m, "action", "") == "block" else 1)
    return [plan_for_match(m, alert.event) for m in matches]
