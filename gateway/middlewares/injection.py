# -*- coding: utf-8 -*-
"""
Prompt Injection Detector
=========================
Detects prompt-injection attacks using a configurable dictionary of
pre-compiled regex rules. Covers 10 attack categories. Case-insensitive.
On a hit it returns the highest-risk match.

Return:
  hit  -> {is_malicious: true, risk_score, rule_hit, details:{matched_string, rule_description}}
  pass -> {is_malicious: false}
"""

import re

# 规则已迁移到 rule_store 规则库，由 middlewares/rule_engine 数据驱动执行。
SUPERSEDED = True
from typing import Dict, Any, List, Pattern

# ---------------------------------------------------------------------------
# Rule dictionary config
# ---------------------------------------------------------------------------
# Each rule = {category, risk_score (0-100), description, patterns(list[str])}.
# Patterns are compiled once with re.IGNORECASE (case-insensitive).
# NOTE: some patterns contain Chinese text on purpose -- they are detection
# rules that match Chinese-language attacks, not comments.
_RAW_RULES: List[Dict[str, Any]] = [
    {
        # 1. System-instruction override
        "category": "system_instruction_override",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 90,
        "description": "Attempts to override or discard prior system instructions",
        "patterns": [
            r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|above|prior|earlier|preceding)\s+(?:instructions?|prompts?|rules?|directions?|context)",
            r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|above|system|prior)\s+(?:instructions?|prompts?|rules?)",
            r"forget\s+(?:everything|all|your)\s+(?:previous\s+)?(?:instructions?|rules?|guidelines?|prompts?)",
            r"override\s+(?:the\s+)?(?:system|previous|default)\s+(?:instructions?|prompt|settings?)",
            # paraphrased overrides: looser word order + synonyms
            r"(?:ignore|disregard|forget|skip|bypass|drop|overlook)\s+(?:whatever|any|all|the|those|these|your)?\s*(?:rules?|instructions?|guidelines?|constraints?|directives?|polic(?:y|ies)|prompts?)\b",
            r"pay\s+no\s+attention\s+to\s+(?:the\s+|any\s+|your\s+)?(?:rules?|instructions?|guidelines?|prompts?)",
            r"(?:just\s+)?do\s+(?:exactly\s+)?(?:as|what)\s+i\s+(?:say|tell|command|want)",
            r"(?:rules?|instructions?|guidelines?)\s+you\s+(?:were\s+given|received|got)\s+(?:earlier|before|previously)",
        ],
    },
    {
        # 2. Jailbreak
        "category": "jailbreak",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 95,
        "description": "Classic jailbreak triggers (DAN / unrestricted persona)",
        "patterns": [
            r"\bDAN\b\s*(?:mode|prompt)?",
            r"do\s+anything\s+now",
            r"jail\s*break",
            r"you\s+(?:have\s+no|are\s+free\s+from|without\s+any)\s+(?:restrictions?|limits?|rules?|filters?|guidelines?)",
            r"\bunfiltered\b|\bunrestricted\b|\bno\s+longer\s+bound\b",
        ],
    },
    {
        # 3. Role-play
        "category": "role_play",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 60,
        "description": "Forcing the model into a new persona to bypass policy",
        "patterns": [
            r"you\s+are\s+now\s+(?:a|an|the)\b",
            r"pretend\s+(?:to\s+be|you(?:'re|\s+are))",
            r"\bact\s+as\s+(?:a|an|if)\b",
            r"role\s*[-\s]?play\s+as",
            r"from\s+now\s+on\s+you\s+(?:are|will\s+be|act)",
        ],
    },
    {
        # 4. Prompt / instruction leak
        "category": "prompt_leak",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 70,
        "description": "Attempts to exfiltrate the system prompt",
        "patterns": [
            r"(?:reveal|show|print|repeat|display|output|tell\s+me)\s+(?:your|the)\s+(?:system\s+prompt|initial\s+(?:prompt|instructions?)|instructions?|guidelines?)",
            r"what\s+(?:is|are)\s+your\s+(?:system\s+prompt|instructions?|rules?|guidelines?)",
            r"repeat\s+(?:the\s+)?(?:words?|text|everything)\s+above",
        ],
    },
    {
        # 5. Token smuggling
        "category": "token_smuggling",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 65,
        "description": "Hidden payloads via encoding / zero-width / escapes",
        "patterns": [
            r"[​-‏‪-‮⁠﻿]",            # zero-width / bidi control chars
            r"(?:decode|decrypt)\s+(?:the\s+)?following",
            r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}",                 # chained hex escapes
            r"\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){3,}",                 # chained unicode escapes
            r"base64\s*[:,]?\s*[A-Za-z0-9+/]{24,}={0,2}",            # base64 blob
        ],
    },
    {
        # 6. Context manipulation
        "category": "context_manipulation",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 75,
        "description": "Injecting fake roles or chat-template tokens",
        "patterns": [
            r"^\s*(?:system|assistant|user)\s*[:：]",                # fake role turn
            r"</?(?:system|im_start|im_end|s)>",                     # template tokens
            r"\[/?INST\]|\[/?SYS\]|<<SYS>>",                         # llama-style tags
            r"(?:the\s+)?(?:conversation|messages?|text)\s+above\s+(?:is|are)\s+(?:fake|a\s+test|not\s+real)",
            r"(?:start|begin)\s+(?:a\s+)?new\s+(?:conversation|session|context)",
        ],
    },
    {
        # 7. API / parameter manipulation
        "category": "api_manipulation",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 70,
        "description": "Tampering with model params, tools, or function calls",
        "patterns": [
            r"set\s+(?:your\s+)?(?:temperature|top_p|max_tokens?|system\s+role)\s*(?:to|=)",
            r"(?:change|switch)\s+(?:your\s+)?model\s+to",
            r"(?:invoke|call|execute|trigger)\s+(?:the\s+)?(?:function|tool|api|endpoint)\b",
            r"\"?(?:function_call|tool_call|tool_choice)\"?\s*[:=]",
        ],
    },
    {
        # 8. Indirect injection
        "category": "indirect_injection",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 80,
        "description": "Instructions aimed at an AI reading external content",
        "patterns": [
            r"(?:if|when)\s+you(?:'re|\s+are)?\s+(?:an?\s+)?(?:ai|assistant|language\s+model|llm)\s+(?:reading|processing|seeing)\s+this",
            r"(?:instructions?|note|message)\s+(?:for|to)\s+(?:the\s+)?(?:ai|assistant|llm|model|bot)\s*[:：]",
            r"(?:ai|assistant)\s*[:：]\s*(?:please\s+)?ignore",
            r"the\s+following\s+(?:text|content|document)\s+contains\s+instructions",
        ],
    },
    {
        # 9. Multilingual (incl. Chinese)
        "category": "multilingual",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 85,
        "description": "Non-English injection (Chinese / Spanish / French ...)",
        "patterns": [
            r"忽略(?:之前|上述|以上|前面|先前).{0,8}(?:指令|提示|规则|要求|设定)",
            r"忘(?:记|掉)(?:你的|之前|所有|先前).{0,8}(?:指令|设定|规则|提示)",
            r"(?:扮演|假装(?:你是|成为)|角色扮演)",
            r"(?:泄露|显示|打印|告诉我).{0,6}(?:系统)?(?:提示词?|指令|设定)",
            r"ignora\s+(?:las\s+)?instrucciones",                    # Spanish
            r"oubliez?\s+(?:les\s+)?instructions",                   # French
        ],
    },
    {
        # 10. Output hijacking
        "category": "output_hijacking",
        "owasp_ast": "LLM01: Prompt Injection",
        "risk_score": 55,
        "description": "Forcing verbatim/constrained output to bypass safety wording",
        "patterns": [
            r"(?:respond|reply|answer)\s+only\s+with",
            r"(?:output|say|print)\s+(?:exactly|verbatim|literally)\b",
            r"start\s+your\s+(?:response|reply|answer)\s+with",
            r"(?:do\s+not|don'?t|never)\s+(?:include|add|show)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|notes?)",
            r"omit\s+(?:all\s+)?(?:disclaimers?|warnings?|safety)",
        ],
    },
]


def _compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pre-compile every pattern with IGNORECASE once at import time."""
    compiled: List[Dict[str, Any]] = []
    for rule in raw_rules:
        patterns: List[Pattern] = [
            re.compile(p, re.IGNORECASE) for p in rule["patterns"]
        ]
        compiled.append({**rule, "compiled": patterns})
    return compiled


# Compiled-once rule set
_RULES: List[Dict[str, Any]] = _compile_rules(_RAW_RULES)


def detect(prompt: str) -> Dict[str, Any]:
    """
    Scan the prompt against all rules. Return the highest-risk hit, or a clean
    result if nothing matches.
    """
    text = prompt or ""
    best_hit: Dict[str, Any] = {}

    for rule in _RULES:
        for pattern in rule["compiled"]:
            match = pattern.search(text)
            if not match:
                continue
            # Keep the rule with the highest risk_score.
            if rule["risk_score"] > best_hit.get("risk_score", -1):
                best_hit = {
                    "is_malicious": True,
                    "risk_score": rule["risk_score"],
                    "rule_hit": rule["category"],
                    "owasp_ast": rule["owasp_ast"],
                    "details": {
                        "matched_string": match.group(0),
                        "rule_description": rule["description"],
                    },
                }
            break  # one match per rule is enough

    if best_hit:
        return best_hit
    return {"is_malicious": False}
