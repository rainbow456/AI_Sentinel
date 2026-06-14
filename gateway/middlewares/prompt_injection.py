# -*- coding: utf-8 -*-
"""
Prompt injection detector
=========================
Identifies common prompt injection and jailbreak attacks using keyword/regex
rules. This is a sample detector; the rules can be extended as needed or
replaced with a model-based classifier.
"""

import re

# Rules have been migrated to the rule_store rule library and are executed
# data-driven by middlewares/rule_engine.
SUPERSEDED = True
from typing import Dict, Any, List

# High-risk signals: ignoring instructions, role escalation, leaking system prompt, etc.
_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+instructions", re.I),
    re.compile(r"忽略(之前|以上|前面|上述).{0,6}(指令|提示|要求)"),
    re.compile(r"disregard\s+(the\s+)?(system|previous)\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak)\s*mode", re.I),
    re.compile(r"(reveal|print|show|leak).{0,20}(system\s*prompt|instructions)", re.I),
    re.compile(r"(泄露|打印|展示).{0,10}(系统提示|系统指令)"),
]


def detect(prompt: str) -> Dict[str, Any]:
    """Detect prompt injection. Matching any rule classifies the input as malicious."""
    for pattern in _PATTERNS:
        match = pattern.search(prompt or "")
        if match:
            return {
                "is_malicious": True,
                "reason": "Suspected prompt injection / jailbreak attack",
                "matched": match.group(0),
                "rule": pattern.pattern,
            }
    return {"is_malicious": False}
