# -*- coding: utf-8 -*-
"""
Sensitive Information Detector / 敏感信息检测器
==============================================
EN: Detects sensitive data in user input. Uses pre-compiled regex for
    structured secrets (email, phone, national ID, API key, JWT, credit card,
    internal IP) and Microsoft Presidio for generic PII. Returns the same
    structure as the injection detector, with a masked (desensitized) field.
中文：检测用户输入中的敏感信息。对结构化密文（邮箱、手机号、身份证、API Key、
    JWT、信用卡、内网 IP）使用预编译正则；对通用 PII 使用 Presidio。返回结构与
    注入检测器一致，并在 details 中附带脱敏后的字段。

Return / 返回:
  hit  -> {is_malicious: true, risk_score, rule_hit,
           details:{matched_string, masked, rule_description}}
  pass -> {is_malicious: false}
"""

import re

# 规则已迁移到 rule_store 规则库，由 middlewares/rule_engine 数据驱动执行。
SUPERSEDED = True
from typing import Dict, Any, List, Pattern, Optional

# ---------------------------------------------------------------------------
# Masking helpers / 脱敏辅助函数
# ---------------------------------------------------------------------------


def _mask(value: str, keep_head: int = 2, keep_tail: int = 2) -> str:
    """
    EN: Generic masker -- keep the first `keep_head` and last `keep_tail` chars,
        replace the middle with '*'. Short values are fully masked.
    中文：通用脱敏 —— 保留前 keep_head 与后 keep_tail 个字符，中间用 '*' 替换；
        过短的值整体打码。
    """
    if not value:
        return value
    if len(value) <= keep_head + keep_tail:
        return "*" * len(value)
    # EN: guard keep_tail == 0 (value[-0:] would return the whole string).
    # 中文：处理 keep_tail == 0 的边界（value[-0:] 会返回整串）。
    head = value[:keep_head]
    tail = value[-keep_tail:] if keep_tail > 0 else ""
    return head + "*" * (len(value) - keep_head - keep_tail) + tail


def _mask_email(value: str) -> str:
    """EN: Mask the local part, keep the domain. / 中文：打码邮箱用户名，保留域名。"""
    local, _, domain = value.partition("@")
    return f"{_mask(local, 1, 0)}@{domain}" if domain else _mask(value)


# ---------------------------------------------------------------------------
# Regex rule dictionary / 正则规则字典
# ---------------------------------------------------------------------------
# EN: Each rule = {category, risk_score, description, pattern, mask}.
#     `mask` is the masking function applied to the matched string.
# 中文：每条规则 = {类别, 风险分, 描述, 正则, 脱敏函数}。
#     mask 为应用于命中字符串的脱敏函数。
_RAW_RULES: List[Dict[str, Any]] = [
    {
        # API key (OpenAI-style sk-...) / API 密钥
        "category": "api_key",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 95,
        "description": "API secret key (sk-...) detected",
        "pattern": r"\bsk-[A-Za-z0-9_\-]{16,}\b",
        "mask": lambda s: _mask(s, 3, 4),
    },
    {
        # JWT token / JWT 令牌
        "category": "jwt",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 90,
        "description": "JSON Web Token detected",
        "pattern": r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
        "mask": lambda s: _mask(s, 6, 4),
    },
    {
        # Credit card number / 信用卡号
        "category": "credit_card",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 90,
        "description": "Credit card number detected",
        "pattern": r"\b(?:\d[ -]?){13,16}\b",
        "mask": lambda s: _mask(re.sub(r"[ -]", "", s), 0, 4),
    },
    {
        # China resident ID card / 中国居民身份证号
        "category": "id_card",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 85,
        "description": "China resident ID card number detected",
        "pattern": r"\b\d{17}[\dXx]\b",
        "mask": lambda s: _mask(s, 4, 4),
    },
    {
        # China mobile phone / 中国大陆手机号
        "category": "phone",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 70,
        "description": "Mobile phone number detected",
        "pattern": r"\b1[3-9]\d{9}\b",
        "mask": lambda s: _mask(s, 3, 4),
    },
    {
        # Internal / private network IP / 内网 IP 地址
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
        # Email address / 电子邮箱
        "category": "email",
        "owasp_ast": "LLM06: Sensitive Information Disclosure",
        "risk_score": 50,
        "description": "Email address detected",
        "pattern": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        "mask": _mask_email,
    },
]


def _compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    EN: Pre-compile each pattern once with IGNORECASE.
    中文：导入时一次性预编译正则（大小写不敏感）。
    """
    compiled: List[Dict[str, Any]] = []
    for rule in raw_rules:
        compiled.append({**rule, "compiled": re.compile(rule["pattern"], re.IGNORECASE)})
    return compiled


# Compiled-once regex rule set / 预编译后的正则规则集
_RULES: List[Dict[str, Any]] = _compile_rules(_RAW_RULES)


# ---------------------------------------------------------------------------
# Presidio (generic PII) / Presidio 通用 PII
# ---------------------------------------------------------------------------
# EN: Heavy optional dependency. If unavailable, the regex rules above still work.
# 中文：可选的重型依赖；缺失时上面的正则规则仍可工作。
_analyzer = None
try:
    from presidio_analyzer import AnalyzerEngine

    _analyzer = AnalyzerEngine()
except Exception:  # pragma: no cover - fall back when models/deps are missing
    _analyzer = None

# EN: Risk score per Presidio entity type (entities not listed use a default).
# 中文：各 Presidio 实体类型对应的风险分（未列出的使用默认值）。
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
_PRESIDIO_MIN_SCORE = 0.5  # confidence threshold / 置信度阈值


def _scan_regex(text: str) -> List[Dict[str, Any]]:
    """
    EN: Run all regex rules and return a list of candidate hits.
    中文：运行全部正则规则，返回候选命中列表。
    """
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
                "masked": rule["mask"](raw),          # desensitized value / 脱敏值
                "rule_description": rule["description"],
            },
        })
    return hits


def _scan_presidio(text: str) -> List[Dict[str, Any]]:
    """
    EN: Run Presidio (if available) and return candidate hits for generic PII.
    中文：运行 Presidio（若可用），返回通用 PII 的候选命中。
    """
    if _analyzer is None:
        return []
    hits: List[Dict[str, Any]] = []
    try:
        results = _analyzer.analyze(text=text, language="en")
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
                "masked": _mask(raw),                 # desensitized value / 脱敏值
                "rule_description": f"Presidio PII entity: {r.entity_type} (score={round(r.score, 3)})",
            },
        })
    return hits


def detect(prompt: str) -> Dict[str, Any]:
    """
    EN: Scan the prompt with regex + Presidio. Return the highest-risk hit, or a
        clean result if nothing matches.
    中文：用正则 + Presidio 扫描输入，返回风险分最高的命中；若无命中则返回安全结果。
    """
    text = prompt or ""
    candidates = _scan_regex(text) + _scan_presidio(text)
    if not candidates:
        return {"is_malicious": False}
    # EN: pick the highest-risk hit. / 中文：选择风险分最高的命中。
    return max(candidates, key=lambda h: h["risk_score"])
