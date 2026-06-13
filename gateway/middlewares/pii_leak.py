# -*- coding: utf-8 -*-
"""
Sensitive information (PII) detector
====================================
Prefers Microsoft Presidio to identify personal sensitive information (email,
phone, credit card, national ID, etc.) in user input. If Presidio is not
installed or fails to load, falls back to built-in regex rules so the detector
is always available.
"""

import re

# 规则已迁移到 rule_store 规则库，由 middlewares/rule_engine 数据驱动执行。
SUPERSEDED = True
from typing import Dict, Any, List

# Entity types treated as high-risk on match (adjust per business needs)
_BLOCK_ENTITIES = {
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "CRYPTO",
}

# ---- Presidio 懒加载：首次 detect 才初始化，import 本模块不触发，避免拖慢启动 ----
_analyzer = None
_analyzer_ready = False


def _get_analyzer():
    global _analyzer, _analyzer_ready
    if not _analyzer_ready:
        _analyzer_ready = True
        try:
            from presidio_analyzer import AnalyzerEngine
            _analyzer = AnalyzerEngine()
        except Exception:  # pragma: no cover
            _analyzer = None
    return _analyzer


# ---- Built-in regex used for fallback -------------------------------------
_FALLBACK_PATTERNS = {
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "CHINA_ID": re.compile(r"\b\d{17}[\dXx]\b"),
}


def _detect_by_presidio(prompt: str) -> Dict[str, Any]:
    """Analyze text with Presidio and return the hit result."""
    results = _get_analyzer().analyze(text=prompt, language="en")
    hits: List[Dict[str, Any]] = [
        {"type": r.entity_type, "score": round(r.score, 3)}
        for r in results
        if r.entity_type in _BLOCK_ENTITIES
    ]
    if hits:
        return {
            "is_malicious": True,
            "reason": "Input contains high-risk sensitive information (Presidio)",
            "entities": hits,
            "engine": "presidio",
        }
    return {"is_malicious": False, "engine": "presidio"}


def _detect_by_regex(prompt: str) -> Dict[str, Any]:
    """Regex fallback used when Presidio is unavailable."""
    for entity, pattern in _FALLBACK_PATTERNS.items():
        if entity not in _BLOCK_ENTITIES and entity != "CREDIT_CARD":
            # The fallback only blocks strong-risk items like credit cards; the rest are illustrative
            continue
        if pattern.search(prompt or ""):
            return {
                "is_malicious": True,
                "reason": "Input contains high-risk sensitive information (regex fallback)",
                "entities": [{"type": entity}],
                "engine": "regex",
            }
    return {"is_malicious": False, "engine": "regex"}


def detect(prompt: str) -> Dict[str, Any]:
    """Main entry for sensitive information detection."""
    if _get_analyzer() is not None:
        return _detect_by_presidio(prompt)
    return _detect_by_regex(prompt)
