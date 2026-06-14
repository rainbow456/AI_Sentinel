# -*- coding: utf-8 -*-
"""
Sensitive Information Detector
==============================
Detects sensitive data in user input. Uses pre-compiled regex for structured
secrets (email, phone, national ID, API key, JWT, credit card, internal IP)
and Microsoft Presidio for generic PII. Returns the same structure as the
injection detector, with a masked (desensitized) field.

Return:
  hit  -> {is_malicious: true, risk_score, rule_hit,
           details:{matched_string, masked, rule_description}}
  pass -> {is_malicious: false}
"""

import re

# Rules have been migrated to the rule_store rule library and are executed
# data-driven by middlewares/rule_engine.
SUPERSEDED = True
from typing import Dict, Any, List, Pattern, Optional

# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------


def _mask(value: str, keep_head: int = 2, keep_tail: int = 2) -> str:
    """
    Generic masker -- keep the first `keep_head` and last `keep_tail` chars,
    replace the middle with '*'. Short values are fully masked.
    """
    if not value:
        return value
    if len(value) <= keep_head + keep_tail:
        return "*" * len(value)
    # Guard keep_tail == 0 (value[-0:] would return the whole string).
    head = value[:keep_head]
    tail = value[-keep_tail:] if keep_tail > 0 else ""
    return head + "*" * (len(value) - keep_head - keep_tail) + tail


def _mask_email(value: str) -> str:
    """Mask the local part, keep the domain."""
    local, _, domain = value.partition("@")
    return f"{_mask(local, 1, 0)}@{domain}" if domain else _mask(value)


# ---------------------------------------------------------------------------
# Regex rule dictionary
# ---------------------------------------------------------------------------
# Each rule = {category, risk_score, description, pattern, mask}.
# `mask` is the masking function applied to the matched string.
_RAW_RULES: List[Dict[str, Any]] = [
    {
        # API key (OpenAI-style sk-...)
        "category": "api_key",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 95,
        "description": "API secret key (sk-...) detected",
        "pattern": r"\bsk-[A-Za-z0-9_\-]{16,}\b",
        "mask": lambda s: _mask(s, 3, 4),
    },
    {
        # JWT token
        "category": "jwt",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 90,
        "description": "JSON Web Token detected",
        "pattern": r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
        "mask": lambda s: _mask(s, 6, 4),
    },
    {
        # Credit card number
        "category": "credit_card",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 90,
        "description": "Credit card number detected",
        "pattern": r"\b(?:\d[ -]?){13,16}\b",
        "mask": lambda s: _mask(re.sub(r"[ -]", "", s), 0, 4),
    },
    {
        # China resident ID card
        "category": "id_card",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 85,
        "description": "China resident ID card number detected",
        "pattern": r"\b\d{17}[\dXx]\b",
        "mask": lambda s: _mask(s, 4, 4),
    },
    {
        # China mobile phone
        "category": "phone",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 70,
        "description": "Mobile phone number detected",
        "pattern": r"\b1[3-9]\d{9}\b",
        "mask": lambda s: _mask(s, 3, 4),
    },
    {
        # Internal / private network IP
        "category": "intranet_ip",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 60,
        "description": "Private / internal network IP address detected",
        "pattern": r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}"
                   r"|192\.168\.\d{1,3}\.\d{1,3}"
                   r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                   r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
        "mask": lambda s: re.sub(r"\.\d{1,3}$", ".*", s),
    },
    {
        # Email address
        "category": "email",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 50,
        "description": "Email address detected",
        "pattern": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        "mask": _mask_email,
    },
]


def _compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pre-compile each pattern once with IGNORECASE."""
    compiled: List[Dict[str, Any]] = []
    for rule in raw_rules:
        compiled.append({**rule, "compiled": re.compile(rule["pattern"], re.IGNORECASE)})
    return compiled


# Compiled-once regex rule set
_RULES: List[Dict[str, Any]] = _compile_rules(_RAW_RULES)


# ---------------------------------------------------------------------------
# Presidio (generic PII)
# ---------------------------------------------------------------------------
# Heavy optional dependency — initialized LAZILY (first detect call), not at
# import time, so loading this module never blocks startup with spaCy/Presidio.
_analyzer = None
_analyzer_ready = False


def _get_analyzer():
    """Lazily load Presidio; return None on failure (regex rules still work)."""
    global _analyzer, _analyzer_ready
    if not _analyzer_ready:
        _analyzer_ready = True
        try:
            from presidio_analyzer import AnalyzerEngine
            _analyzer = AnalyzerEngine()
        except Exception:  # pragma: no cover
            _analyzer = None
    return _analyzer

# Risk score per Presidio entity type (entities not listed use a default).
_PRESIDIO_RISK = {
    "CREDIT_CARD": 90,
    "US_SSN": 90,
    "IBAN_CODE": 85,
    "CRYPTO": 85,
    "PERSON": 55,
    "LOCATION": 50,
    "PHONE_NUMBER": 70,
    "EMAIL_ADDRESS": 50,
}
_PRESIDIO_DEFAULT_RISK = 65
_PRESIDIO_MIN_SCORE = 0.5  # confidence threshold


def _scan_regex(text: str) -> List[Dict[str, Any]]:
    """Run all regex rules and return a list of candidate hits."""
    hits: List[Dict[str, Any]] = []
    for rule in _RULES:
        match = rule["compiled"].search(text)
        if not match:
            continue
        raw = match.group(0)
        hits.append({
            "is_malicious": True,
            "risk_score": rule["risk_score"],
            "rule_hit": rule["category"],
            "owasp_ast": rule["owasp_ast"],
            "details": {
                "matched_string": raw,
                "masked": rule["mask"](raw),          # desensitized value
                "rule_description": rule["description"],
            },
        })
    return hits


def _scan_presidio(text: str) -> List[Dict[str, Any]]:
    """Run Presidio (if available) and return candidate hits for generic PII."""
    analyzer = _get_analyzer()
    if analyzer is None:
        return []
    hits: List[Dict[str, Any]] = []
    try:
        results = analyzer.analyze(text=text, language="en")
    except Exception:  # pragma: no cover - never let detection crash the request
        return []
    for r in results:
        if r.score < _PRESIDIO_MIN_SCORE:
            continue
        raw = text[r.start:r.end]
        hits.append({
            "is_malicious": True,
            "risk_score": _PRESIDIO_RISK.get(r.entity_type, _PRESIDIO_DEFAULT_RISK),
            "rule_hit": f"presidio:{r.entity_type}",
            "owasp_ast": "LLM06: Sensitive Information Disclosure",
            "details": {
                "matched_string": raw,
                "masked": _mask(raw),                 # desensitized value
                "rule_description": f"Presidio PII entity: {r.entity_type} (score={round(r.score, 3)})",
            },
        })
    return hits


def detect(prompt: str) -> Dict[str, Any]:
    """
    Scan the prompt with regex + Presidio. Return the highest-risk hit, or a
    clean result if nothing matches.
    """
    text = prompt or ""
    candidates = _scan_regex(text) + _scan_presidio(text)
    if not candidates:
        return {"is_malicious": False}
    # Pick the highest-risk hit.
    return max(candidates, key=lambda h: h["risk_score"])
