# -*- coding: utf-8 -*-
"""
Rule-driven detector (multi-engine)
===================================
Reads enabled rules from rule_store and dispatches by engine type:
  regex      regular expression
  sensitive  regex + declarative masking (params.mask)
  keyword    keyword boundary matching (params.keywords)
  entropy    high-entropy heuristic (params.min_len / min_entropy / compact_ratio)

Public API:
  detect(text)      return the highest-scoring hit (for single-result paths like /chat)
  detect_all(text)  return a per-rule list of hits (for /scan multi-finding)
  reload()          hot-reload after rule changes
"""

import re
import math
from collections import Counter
from typing import Dict, Any, List

try:
    from gateway.rule_store import RuleStore
except Exception:  # pragma: no cover
    from rule_store import RuleStore

_FLAG = {"IGNORECASE": re.I, "MULTILINE": re.M, "DOTALL": re.S, "UNICODE": re.U}


def _keep(v: str, head: int, tail: int) -> str:
    if not v:
        return v
    if len(v) <= head + tail:
        return "*" * len(v)
    return v[:head] + "*" * (len(v) - head - tail) + (v[-tail:] if tail else "")


def _apply_mask(value: str, desc) -> str:
    """Mask the value according to a declarative descriptor."""
    if not desc:
        return value
    if desc == "email":
        local, _, dom = value.partition("@")
        return (_keep(local, 1, 0) + "@" + dom) if dom else _keep(value, 2, 2)
    if desc == "ip_last_octet":
        return re.sub(r"\.\d{1,3}$", ".*", value)
    if desc == "cc_last4":
        return _keep(re.sub(r"[ -]", "", value), 0, 4)
    if isinstance(desc, str) and desc.startswith("keep:"):
        try:
            h, t = (int(x) for x in desc[5:].split(","))
            return _keep(value, h, t)
        except Exception:
            return value
    return value


def _entropy_scan(text: str, min_len: int, min_e: float, ratio: float):
    pick, high = "", 0.0
    for tok in text.split():
        if len(tok) < min_len or "://" in tok or tok.count(".") >= 2:
            continue
        compact = sum(1 for ch in tok if ch.isalnum() or ch in "+/=_-")
        if compact / len(tok) < ratio:
            continue
        n = len(tok)
        e = -sum((c / n) * math.log2(c / n) for c in Counter(tok).values())
        if e >= min_e and e > high:
            high, pick = e, tok
    return pick, high


class _Engine:
    def __init__(self):
        self.store = RuleStore()
        self.regex: List[tuple] = []
        self.sens: List[tuple] = []
        self.kw: List[tuple] = []
        self.ent: List[tuple] = []
        self.hits: Counter = Counter()   # per-rule hit counts (cumulative across reloads), for feedback tuning
        self.reload()

    def reload(self) -> int:
        self.regex, self.sens, self.kw, self.ent = [], [], [], []
        for r in self.store.list(enabled=True):
            eng = r.get("engine")
            sc, nm = int(r.get("severity_score", 0)), r.get("name", "")
            ow, de = r.get("owasp_ast", ""), r.get("description_zh", "")
            params = r.get("params") or {}
            flags = 0
            for f in (r.get("flags") or []):
                flags |= _FLAG.get(f, 0)
            try:
                if eng in ("regex", "sensitive"):
                    pats = [re.compile(p, flags) for p in r.get("patterns", [])]
                    if eng == "regex":
                        self.regex.append((sc, nm, ow, de, pats))
                    else:
                        self.sens.append((sc, nm, ow, de, pats, params.get("mask")))
                elif eng == "keyword":
                    kws = params.get("keywords") or []
                    if kws:
                        rx = re.compile(
                            r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(k) for k in kws)
                            + r")(?![A-Za-z0-9])", re.I)
                        self.kw.append((sc, nm, ow, de, rx))
                elif eng == "entropy":
                    self.ent.append((sc, nm, ow, de, params))
            except re.error:
                continue  # skip a bad rule rather than break the whole engine
        return self.count()

    def count(self) -> int:
        return len(self.regex) + len(self.sens) + len(self.kw) + len(self.ent)

    def _hits(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for sc, nm, ow, de, pats in self.regex:
            for p in pats:
                m = p.search(text)
                if m:
                    out.append({"is_malicious": True, "risk_score": sc, "rule_hit": nm,
                                "owasp_ast": ow, "details": {"matched_string": m.group(0),
                                                             "rule_description": de}})
                    break
        for sc, nm, ow, de, pats, mask in self.sens:
            for p in pats:
                m = p.search(text)
                if m:
                    raw = m.group(0)
                    out.append({"is_malicious": True, "risk_score": sc, "rule_hit": nm,
                                "owasp_ast": ow, "details": {"matched_string": raw,
                                                             "masked": _apply_mask(raw, mask),
                                                             "rule_description": de}})
                    break
        for sc, nm, ow, de, rx in self.kw:
            m = rx.search(text)
            if m:
                out.append({"is_malicious": True, "risk_score": sc, "rule_hit": nm,
                            "owasp_ast": ow, "details": {"matched_string": m.group(0),
                                                         "rule_description": de}})
        for sc, nm, ow, de, params in self.ent:
            tok, _ = _entropy_scan(text, params.get("min_len", 24),
                                   params.get("min_entropy", 4.5),
                                   params.get("compact_ratio", 0.9))
            if tok:
                snip = tok if len(tok) <= 16 else tok[:8] + "…" + tok[-4:]
                out.append({"is_malicious": True, "risk_score": sc, "rule_hit": nm,
                            "owasp_ast": ow, "details": {"matched_string": snip,
                                                         "rule_description": de}})
        for h in out:
            self.hits[h["rule_hit"]] += 1   # hit count, for feedback tuning
        return out

    def detect(self, text: str) -> Dict[str, Any]:
        hits = self._hits(text or "")
        return max(hits, key=lambda h: h["risk_score"]) if hits else {"is_malicious": False}

    def detect_all(self, text: str) -> List[Dict[str, Any]]:
        return self._hits(text or "")

    def stats(self) -> Dict[str, int]:
        return dict(self.hits)


ENGINE = _Engine()


def detect(prompt: str) -> Dict[str, Any]:
    return ENGINE.detect(prompt)


def detect_all(prompt: str) -> List[Dict[str, Any]]:
    return ENGINE.detect_all(prompt)


def reload() -> int:
    return ENGINE.reload()


def stats() -> Dict[str, int]:
    """Cumulative hit count per rule (rule_hit -> count), for feedback tuning."""
    return ENGINE.stats()
