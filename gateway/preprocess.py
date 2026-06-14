# -*- coding: utf-8 -*-
"""
Input preprocessing (de-obfuscation + decoding)
=================================================
De-obfuscates text BEFORE it reaches the rule detectors, so disguised attacks
(zero-width chars, full-width chars, letter-spacing, base64 / URL / HTML
encoding) get normalized back to their plain form and become matchable.
No AI / ML -- pure deterministic transforms.
"""

import re
import html
import base64
import unicodedata
from urllib.parse import unquote
from typing import List

# Zero-width and bidi-control characters used to break keyword matching.
_INVISIBLE_RE = re.compile(r"[​-‏‪-‮⁠﻿­]")

# A run of single chars separated by spaces, e.g. "i g n o r e" or split CJK characters.
_SPACED_LETTERS_RE = re.compile(r"(?:\b\w\b[ \t]+){2,}\b\w\b", re.UNICODE)

# A base64-looking blob (long enough to be worth decoding).
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _strip_invisible(text: str) -> str:
    # Drop zero-width / bidi chars.
    return _INVISIBLE_RE.sub("", text)


def _collapse_spaced_letters(text: str) -> str:
    # Re-join letter-spaced / split-character sequences.
    return _SPACED_LETTERS_RE.sub(lambda m: re.sub(r"[ \t]+", "", m.group(0)), text)


def normalize(text: str) -> str:
    """
    Canonicalize text: NFKC (full-width -> half-width, etc.), strip invisible
    chars, re-join split characters, lowercase.
    """
    if not text:
        return ""
    out = unicodedata.normalize("NFKC", text)   # full-width / compatibility -> canonical
    out = _strip_invisible(out)
    out = _collapse_spaced_letters(out)
    return out.lower()


def _printable_ratio(s: str) -> float:
    # Share of printable chars -- used to reject garbage decodes.
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable / len(s)


def _decode_once(text: str) -> List[str]:
    # Try one layer of URL / HTML / base64 decoding; return any plausible results.
    results: List[str] = []

    url_decoded = unquote(text)
    if url_decoded != text:
        results.append(url_decoded)

    html_decoded = html.unescape(text)
    if html_decoded != text:
        results.append(html_decoded)

    for blob in _B64_BLOB_RE.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8", errors="strict")
        except Exception:
            continue
        # Keep only mostly-printable decodes -- random base64 yields garbage.
        if len(decoded) >= 4 and _printable_ratio(decoded) >= 0.85:
            results.append(decoded)

    return results


def expand(text: str, max_depth: int = 3) -> str:
    """
    Build one combined "scan view": the normalized text plus every nested
    decoded payload (recursively), so detectors see hidden content too.
    """
    base = normalize(text)
    seen = {base}
    layers: List[str] = [base]

    frontier = [text, base]
    for _ in range(max_depth):
        nxt: List[str] = []
        for item in frontier:
            for decoded in _decode_once(item):
                norm = normalize(decoded)
                if norm and norm not in seen:
                    seen.add(norm)
                    layers.append(norm)
                    nxt.append(decoded)
        if not nxt:
            break
        frontier = nxt

    return "\n".join(layers)
