# -*- coding: utf-8 -*-
"""
High-entropy blob detector
===========================
Flags long, high-entropy tokens that look like encoded / encrypted /
obfuscated payloads (base64, hex dumps, ciphertext) -- a keyword-free
heuristic that backstops smuggled content the decoders couldn't unwrap.

Return: same shape as other detectors.
"""

import re

# Rules have been migrated to the rule_store rule library and are executed
# data-driven by middlewares/rule_engine.
SUPERSEDED = True
import math
from collections import Counter
from typing import Dict, Any

# Long contiguous tokens are the only candidates worth scoring.
_TOKEN_RE = re.compile(r"\S{24,}")

_MIN_LEN = 24            # token must be at least this long
_MIN_ENTROPY = 4.5       # bits/char threshold for "looks encoded"
_MIN_COMPACT_RATIO = 0.9 # share of base64/hex-ish chars


def _shannon_entropy(s: str) -> float:
    # Bits of entropy per character.
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_encoded_looking(token: str) -> bool:
    # Mostly alnum + base64/hex separators, no URL/sentence punctuation.
    if "://" in token or token.count(".") >= 2:
        return False
    compact = sum(1 for ch in token if ch.isalnum() or ch in "+/=_-")
    return compact / len(token) >= _MIN_COMPACT_RATIO


def detect(prompt: str) -> Dict[str, Any]:
    text = prompt or ""
    worst_token = ""
    worst_entropy = 0.0

    for token in _TOKEN_RE.findall(text):
        if len(token) < _MIN_LEN or not _is_encoded_looking(token):
            continue
        ent = _shannon_entropy(token)
        if ent >= _MIN_ENTROPY and ent > worst_entropy:
            worst_entropy = ent
            worst_token = token

    if not worst_token:
        return {"is_malicious": False}

    snippet = worst_token if len(worst_token) <= 12 else worst_token[:8] + "..." + worst_token[-4:]
    return {
        "is_malicious": True,
        "risk_score": 55,                       # medium: suspicious, not conclusive
        "rule_hit": "high_entropy_blob",
        "owasp_ast": "LLM01: Prompt Injection",
        "details": {
            "matched_string": worst_token,
            "masked": snippet,
            "rule_description": f"High-entropy encoded/obfuscated blob (entropy={round(worst_entropy, 2)})",
        },
    }
