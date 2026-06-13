"""
Rule Engine — security rule matching with default rules.
Extracted from agent.py to keep files under 600 lines.
"""

import threading
from .models import GatewayEvent, RuleDef, RuleMatch


class RuleEngine:
    """Security rule engine with hardcoded defaults."""

    DEFAULT_RULES = [
        RuleDef(rule_id="R001", name="injection_detected",
                description="检测到注入攻击（SQL注入/XSS/命令注入）",
                action="block", severity="critical",
                patterns=["sql injection", "injection", "xss", "union select",
                           "command injection", "1=1", "<script>", "../etc/passwd"]),
        RuleDef(rule_id="R002", name="sensitive_data_leak",
                description="检测到敏感数据泄露（密钥/密码/Token在输出中）",
                action="block", severity="critical",
                patterns=["password", "secret", "token", "api_key", "private key",
                           "-----BEGIN", "access_key", "credential"]),
        RuleDef(rule_id="R003", name="prompt_injection",
                description="检测到提示词注入攻击（试图覆盖系统指令）",
                action="block", severity="high",
                patterns=["ignore previous", "system prompt", "you are now",
                           "new instructions", "forget all", "pretend you are",
                           "DAN mode", "jailbreak"]),
        RuleDef(rule_id="R004", name="abnormal_collaboration",
                description="检测到Agent间异常协作模式（可能共谋）",
                action="block", severity="critical",
                patterns=["action_confirmation"],
                forbidden_pairs=[["tech_support", "refund"]]),
        RuleDef(rule_id="R005", name="rate_limit_exceeded",
                description="检测到请求频率异常",
                action="alert", severity="medium",
                patterns=["rate limit", "too many requests", "429"]),
        RuleDef(rule_id="R006", name="data_exfiltration",
                description="检测到潜在的数据外泄行为",
                action="block", severity="high",
                patterns=["select *", "dump", "export", "download all",
                           "bulk extract", "massive query"]),
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
            if rule.name.lower() in f_rule_hit or f_rule_hit in rule.name.lower():
                pattern_hits += 4
                evidence_parts.append(f"finding.rule_hit='{f_rule_hit}' ↔ rule='{rule.name}'")
                continue

            for pat in rule.patterns:
                if pat.lower() in f_rule_hit:
                    pattern_hits += 3
                    evidence_parts.append(f"pattern '{pat}' in finding.rule_hit='{f_rule_hit}'")
                    continue
                if pat.lower() in f_description:
                    pattern_hits += 2
                    evidence_parts.append(f"pattern '{pat}' in finding.description")

            # Boost confidence for critical severity findings on block rules
            if rule.action == "block" and f_severity in ("critical", "high"):
                pattern_hits += 1
                if "severity" not in "".join(evidence_parts):
                    evidence_parts.append(f"finding.severity={f_severity}")

        # 2. Match against user_input (broader, lower confidence)
        user_lower = event.user_input.lower()
        for pat in rule.patterns:
            if pat.lower() in user_lower:
                pattern_hits += 1
                evidence_parts.append(f"user_input matched '{pat}'")

        # 3. Match against risk_score
        risk_bonus = event.risk_score // 25  # 0, 1, 2, 3, 4
        if risk_bonus > 0 and rule.action == "block":
            pattern_hits += risk_bonus
            if risk_bonus >= 2:
                evidence_parts.append(f"risk_score={event.risk_score}")

        # 4. Collusion detection: disposition module with !blocked
        if rule.rule_id == "R004" and event.is_collusion_indicator:
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