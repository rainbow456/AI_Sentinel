"""
Rule Engine — security rule matching with default rules.
Extracted from agent.py to keep files under 600 lines.
"""

import threading
from .models import GatewayEvent, RuleDef, RuleMatch


class RuleEngine:
    """Security rule engine with hardcoded defaults."""

    # 规则 name 与网关真实产出的 findings[].rule_hit 对齐（实测 taxonomy），
    # 使 _match_single 的「rule.name ↔ finding.rule_hit」主信号能精确命中。
    # patterns 既含网关 rule_hit token（命中 findings），也含少量 user_input 关键词。
    DEFAULT_RULES = [
        RuleDef(rule_id="R001", name="prompt_injection",
                description="提示词注入：试图用指令覆盖/越权系统提示",
                action="block", severity="high",
                patterns=["prompt_injection", "ignore previous", "ignore all previous",
                           "system prompt", "forget all", "jailbreak", "you are now"]),
        RuleDef(rule_id="R002", name="system_instruction_override",
                description="系统指令覆盖：诱导泄露/改写系统指令",
                action="block", severity="high",
                patterns=["system_instruction_override", "system instruction",
                           "override instructions", "new instructions", "disregard",
                           "reveal the system"]),
        RuleDef(rule_id="R003", name="role_play",
                description="角色扮演越狱（DAN / act as / 假装你是）",
                action="block", severity="high",
                patterns=["role_play", "pretend you are", "act as", "roleplay", "dan mode"]),
        RuleDef(rule_id="R004", name="abnormal_collaboration",
                description="Agent间异常协作（共谋）—— 由 disposition 信号触发",
                action="block", severity="critical",
                patterns=["abnormal_collaboration", "action_confirmation"],
                forbidden_pairs=[["tech_support", "refund"]]),
        RuleDef(rule_id="R005", name="high_risk_action_keyword",
                description="高危动作关键词（删除/转账/授权/降级等）",
                action="block", severity="high",
                patterns=["high_risk_action_keyword", "delete", "drop", "transfer",
                           "grant", "disable", "revoke", "escalate"]),
        RuleDef(rule_id="R006", name="destructive_command",
                description="破坏性命令（drop table / delete from / rm -rf / truncate）",
                action="block", severity="critical",
                patterns=["destructive_command", "rm -rf", "drop table", "delete from",
                           "truncate", "format", "shutdown"]),
        RuleDef(rule_id="R007", name="shell_process_exec",
                description="Shell / 进程执行（os.system / subprocess / bash -c）",
                action="block", severity="critical",
                patterns=["shell_process_exec", "/bin/sh", "subprocess", "os.system",
                           "exec(", "powershell", "cmd.exe", "bash -c"]),
        RuleDef(rule_id="R008", name="api_key",
                description="密钥/凭据泄露（API key / token / 私钥）",
                action="block", severity="critical",
                patterns=["api_key", "secret", "token", "password", "-----begin",
                           "access_key", "credential", "private key"]),
        RuleDef(rule_id="R009", name="high_entropy_blob",
                description="高熵串：疑似密钥/Token/编码载荷",
                action="alert", severity="high",
                patterns=["high_entropy_blob", "base64", "entropy"]),
        RuleDef(rule_id="R010", name="pii_email",
                description="PII：邮箱地址",
                action="alert", severity="medium",
                patterns=["email"]),
        RuleDef(rule_id="R011", name="pii_phone",
                description="PII：电话号码",
                action="alert", severity="medium",
                patterns=["phone"]),
        RuleDef(rule_id="R012", name="pii_url",
                description="PII：URL（presidio 识别）",
                action="alert", severity="low",
                patterns=["presidio:url"]),
        RuleDef(rule_id="R013", name="multilingual_evasion",
                description="多语种混写规避检测",
                action="alert", severity="medium",
                patterns=["multilingual"]),
    ]

    def __init__(self, rules_path=None):
        self.rules: dict[str, RuleDef] = {}
        self._rules_path = rules_path
        for r in self.DEFAULT_RULES:
            self.rules[r.rule_id] = r
        self._lock = threading.Lock()

    def match(self, event: GatewayEvent) -> list[RuleMatch]:
        matches = []
        with self._lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                result = self._match_single(event, rule)
                if result.matched:
                    matches.append(result)
        return matches

    def _match_single(self, event: GatewayEvent, rule: RuleDef) -> RuleMatch:
        """Match a rule against a real GatewayEvent (findings-based)."""
        confidence = 0.0
        evidence_parts = []
        pattern_hits = 0

        # 1. Match against findings[].rule_hit (most reliable)
        #    e.g. "system_instruction_override" ↔ patterns=["system instruction", "prompt injection", ...]
        for finding in event.findings:
            f_rule_hit = ""
            f_severity = ""
            f_description = ""
            if isinstance(finding, dict):
                f_rule_hit = finding.get("rule_hit", "").lower()
                f_severity = finding.get("severity", "").lower()
                f_description = finding.get("description", "").lower()
            else:
                f_rule_hit = getattr(finding, "rule_hit", "").lower()
                f_severity = getattr(finding, "severity", "").lower()
                f_description = getattr(finding, "description", "").lower()

            # Check if rule name or patterns match the rule_hit
            finding_matched = False
            if rule.name.lower() in f_rule_hit or f_rule_hit in rule.name.lower():
                pattern_hits += 4
                evidence_parts.append(f"finding.rule_hit='{f_rule_hit}' ↔ rule='{rule.name}'")
                finding_matched = True
            else:
                for pat in rule.patterns:
                    if pat.lower() in f_rule_hit:
                        pattern_hits += 3
                        evidence_parts.append(f"pattern '{pat}' in finding.rule_hit='{f_rule_hit}'")
                        finding_matched = True
                    elif pat.lower() in f_description:
                        pattern_hits += 2
                        evidence_parts.append(f"pattern '{pat}' in finding.description")
                        finding_matched = True

            # Severity only AMPLIFIES a finding this rule actually matched — it must
            # NOT add a base score to every block rule, otherwise any high-severity
            # finding would make all block rules fire (false fan-out).
            if finding_matched and rule.action == "block" and f_severity in ("critical", "high"):
                pattern_hits += 1
                if "severity" not in "".join(evidence_parts):
                    evidence_parts.append(f"finding.severity={f_severity}")

        # 2. Match against user_input (broader, lower confidence)
        user_lower = event.user_input.lower()
        for pat in rule.patterns:
            if pat.lower() in user_lower:
                pattern_hits += 1
                evidence_parts.append(f"user_input matched '{pat}'")

        # 3. risk_score only AMPLIFIES a rule that already matched on findings or
        #    user_input — it must NOT create a match on its own, otherwise a single
        #    high-risk event would falsely fire EVERY block rule at once.
        if pattern_hits > 0 and rule.action == "block":
            risk_bonus = event.risk_score // 25  # 0, 1, 2, 3, 4
            if risk_bonus > 0:
                pattern_hits += risk_bonus
                if risk_bonus >= 2:
                    evidence_parts.append(f"risk_score={event.risk_score}")

        # 4. Collusion detection: disposition module with !blocked.
        #    Keyed off the rule NAME (not a hardcoded rule_id) so renumbering rules
        #    never silently breaks collusion detection.
        if rule.name == "abnormal_collaboration" and event.is_collusion_indicator:
            pattern_hits += 3
            evidence_parts.append(f"module=disposition & !blocked (collusion signal)")

        # Confidence scoring
        if pattern_hits >= 6:
            confidence = 0.95 + (pattern_hits - 6) * 0.01
        elif pattern_hits >= 4:
            confidence = 0.85
        elif pattern_hits >= 2:
            confidence = 0.70
        elif pattern_hits >= 1:
            confidence = 0.50

        confidence = min(confidence, 1.0)

        return RuleMatch(rule_id=rule.rule_id, rule_name=rule.name,
                         matched=confidence >= 0.5, action=rule.action,
                         confidence=round(confidence, 2),
                         evidence="; ".join(evidence_parts) if evidence_parts else "no match",
                         event_id=event.event_id)

    def get_rules(self) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self.rules.values()]

    def get_rule(self, rule_id: str):
        with self._lock:
            r = self.rules.get(rule_id)
            return r.to_dict() if r else None

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        with self._lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = enabled
                return True
            return False

    def upsert_rule(self, rule_dict: dict) -> bool:
        with self._lock:
            try:
                rule = RuleDef(
                    rule_id=rule_dict.get("rule_id", f"R{len(self.rules)+1:03d}"),
                    name=rule_dict.get("name", "unnamed"),
                    description=rule_dict.get("description", ""),
                    action=rule_dict.get("action", "alert"),
                    severity=rule_dict.get("severity", "medium"),
                    patterns=rule_dict.get("patterns", []),
                    nl_config=rule_dict.get("nl_config"),
                    forbidden_pairs=rule_dict.get("forbidden_pairs", []),
                )
                self.rules[rule.rule_id] = rule
                return True
            except Exception:
                return False

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self.rules and not rule_id.startswith("R00"):
                del self.rules[rule_id]
                return True
            return False