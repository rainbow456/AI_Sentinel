# -*- coding: utf-8 -*-
"""
Input preprocessing / 输入预处理（"洗白" + 解码）
=================================================
EN: De-obfuscates text BEFORE it reaches the rule detectors, so disguised
    attacks (zero-width chars, full-width chars, letter-spacing, base64 / URL /
    HTML encoding) get normalized back to their plain form and become matchable.
    No AI / ML -- pure deterministic transforms.
中文：在文本送进规则检测器之前先"洗白"，把伪装过的攻击（零宽字符、全角字符、
    拆字间隔、Base64 / URL / HTML 编码）还原成原形，使其重新可被规则命中。
    全程不使用 AI / 机器学习，纯确定性变换。
"""

import re
import html
import base64
import unicodedata
from urllib.parse import unquote
from typing import List

# Zero-width and bidi-control characters used to break keyword matching.
# 零宽字符与双向控制字符，常被用来打断关键词匹配。
_INVISIBLE_RE = re.compile(r"[​-‏‪-‮⁠﻿­]")

# A run of single chars separated by spaces, e.g. "i g n o r e" or "忽 略 指 令".
# 由单字符+空格反复组成的串，如 "i g n o r e" 或 "忽 略 指 令"。
_SPACED_LETTERS_RE = re.compile(r"(?:\b\w\b[ \t]+){2,}\b\w\b", re.UNICODE)

# A base64-looking blob (long enough to be worth decoding).
# 看起来像 Base64 的长串（达到一定长度才值得尝试解码）。
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _strip_invisible(text: str) -> str:
    # Drop zero-width / bidi chars. / 去掉零宽与双向控制字符。
    return _INVISIBLE_RE.sub("", text)


def _collapse_spaced_letters(text: str) -> str:
    # Re-join letter-spaced / split-character sequences. / 还原被空格拆开的字符。
    return _SPACED_LETTERS_RE.sub(lambda m: re.sub(r"[ \t]+", "", m.group(0)), text)


def normalize(text: str) -> str:
    """
    EN: Canonicalize text: NFKC (full-width -> half-width, etc.), strip invisible
        chars, re-join split characters, lowercase.
    中文：把文本规整化：NFKC（全角转半角等）、去隐藏字符、还原拆字、转小写。
    """
    if not text:
        return ""
    out = unicodedata.normalize("NFKC", text)   # full-width / compatibility -> canonical
    out = _strip_invisible(out)
    out = _collapse_spaced_letters(out)
    return out.lower()


def _printable_ratio(s: str) -> float:
    # Share of printable chars -- used to reject garbage decodes. / 可打印字符占比，用于剔除乱码解码结果。
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable / len(s)


def _decode_once(text: str) -> List[str]:
    # Try one layer of URL / HTML / base64 decoding; return any plausible results.
    # 尝试一层 URL / HTML / Base64 解码，返回看起来可信的结果。
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
        # 只保留以可打印字符为主的解码结果，随机串解出来是乱码。
        if len(decoded) >= 4 and _printable_ratio(decoded) >= 0.85:
            results.append(decoded)

    return results


def expand(text: str, max_depth: int = 3) -> str:
    """
    EN: Build one combined "scan view": the normalized text plus every nested
        decoded payload (recursively), so detectors see hidden content too.
    中文：构造一个合并的"扫描视图"：归一化文本 + 递归解出的各层隐藏载荷，
        让检测器也能看到被编码藏起来的内容。
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
