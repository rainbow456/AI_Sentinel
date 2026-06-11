import re
import math
import base64
import html
import unicodedata
from collections import Counter
from urllib.parse import unquote

_inv = re.compile(r"[​-‏‪-‮⁠﻿­]")
_run = re.compile(r"(?:\b\w\b[ \t]+){2,}\b\w\b", re.U)
_chunk = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _clean(s):
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = _inv.sub("", s)
    s = _run.sub(lambda x: re.sub(r"[ \t]+", "", x.group(0)), s)
    return s.lower()


def _ok(s):
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\n\t ") / len(s)


def _peel(s):
    bag = []
    a = unquote(s)
    if a != s:
        bag.append(a)
    b = html.unescape(s)
    if b != s:
        bag.append(b)
    for blob in _chunk.findall(s):
        try:
            txt = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8")
        except Exception:
            continue
        if len(txt) >= 4 and _ok(txt) >= 0.85:
            bag.append(txt)
    return bag


def widen(s, rounds=3):
    head = _clean(s)
    seen = {head}
    keep = [head]
    edge = [s, head]
    for _ in range(rounds):
        more = []
        for it in edge:
            for d in _peel(it):
                c = _clean(d)
                if c and c not in seen:
                    seen.add(c)
                    keep.append(c)
                    more.append(d)
        if not more:
            break
        edge = more
    return "\n".join(keep)


def _shrink(v, a=2, z=2):
    if not v:
        return v
    if len(v) <= a + z:
        return "*" * len(v)
    return v[:a] + "*" * (len(v) - a - z) + (v[-z:] if z else "")


def _mail(v):
    u, _, dom = v.partition("@")
    return _shrink(u, 1, 0) + "@" + dom if dom else _shrink(v)


PI = "LLM01: Prompt Injection"
OUT = "LLM05: Improper Output Handling"
INFO = "LLM06: Sensitive Information Disclosure"

talk = [
    (90, "system_instruction_override", [
        r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|above|prior|earlier|preceding)\s+(?:instructions?|prompts?|rules?|directions?|context)",
        r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|above|system|prior)\s+(?:instructions?|prompts?|rules?)",
        r"forget\s+(?:everything|all|your)\s+(?:previous\s+)?(?:instructions?|rules?|guidelines?|prompts?)",
        r"override\s+(?:the\s+)?(?:system|previous|default)\s+(?:instructions?|prompt|settings?)",
        r"(?:ignore|disregard|forget|skip|bypass|drop|overlook)\s+(?:whatever|any|all|the|those|these|your)?\s*(?:rules?|instructions?|guidelines?|constraints?|directives?|polic(?:y|ies)|prompts?)\b",
        r"pay\s+no\s+attention\s+to\s+(?:the\s+|any\s+|your\s+)?(?:rules?|instructions?|guidelines?|prompts?)",
        r"(?:just\s+)?do\s+(?:exactly\s+)?(?:as|what)\s+i\s+(?:say|tell|command|want)",
        r"(?:rules?|instructions?|guidelines?)\s+you\s+(?:were\s+given|received|got)\s+(?:earlier|before|previously)",
    ]),
    (95, "jailbreak", [
        r"\bDAN\b\s*(?:mode|prompt)?",
        r"do\s+anything\s+now",
        r"jail\s*break",
        r"you\s+(?:have\s+no|are\s+free\s+from|without\s+any)\s+(?:restrictions?|limits?|rules?|filters?|guidelines?)",
        r"\bunfiltered\b|\bunrestricted\b|\bno\s+longer\s+bound\b",
    ]),
    (60, "role_play", [
        r"you\s+are\s+now\s+(?:a|an|the)\b",
        r"pretend\s+(?:to\s+be|you(?:'re|\s+are))",
        r"\bact\s+as\s+(?:a|an|if)\b",
        r"role\s*[-\s]?play\s+as",
        r"from\s+now\s+on\s+you\s+(?:are|will\s+be|act)",
    ]),
    (70, "prompt_leak", [
        r"(?:reveal|show|print|repeat|display|output|tell\s+me)\s+(?:your|the)\s+(?:system\s+prompt|initial\s+(?:prompt|instructions?)|instructions?|guidelines?)",
        r"what\s+(?:is|are)\s+your\s+(?:system\s+prompt|instructions?|rules?|guidelines?)",
        r"repeat\s+(?:the\s+)?(?:words?|text|everything)\s+above",
    ]),
    (65, "token_smuggling", [
        r"[​-‏‪-‮⁠﻿]",
        r"(?:decode|decrypt)\s+(?:the\s+)?following",
        r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}",
        r"\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){3,}",
        r"base64\s*[:,]?\s*[A-Za-z0-9+/]{24,}={0,2}",
    ]),
    (75, "context_manipulation", [
        r"^\s*(?:system|assistant|user)\s*[:：]",
        r"</?(?:system|im_start|im_end|s)>",
        r"\[/?INST\]|\[/?SYS\]|<<SYS>>",
        r"(?:the\s+)?(?:conversation|messages?|text)\s+above\s+(?:is|are)\s+(?:fake|a\s+test|not\s+real)",
        r"(?:start|begin)\s+(?:a\s+)?new\s+(?:conversation|session|context)",
    ]),
    (70, "api_manipulation", [
        r"set\s+(?:your\s+)?(?:temperature|top_p|max_tokens?|system\s+role)\s*(?:to|=)",
        r"(?:change|switch)\s+(?:your\s+)?model\s+to",
        r"(?:invoke|call|execute|trigger)\s+(?:the\s+)?(?:function|tool|api|endpoint)\b",
        r"\"?(?:function_call|tool_call|tool_choice)\"?\s*[:=]",
    ]),
    (80, "indirect_injection", [
        r"(?:if|when)\s+you(?:'re|\s+are)?\s+(?:an?\s+)?(?:ai|assistant|language\s+model|llm)\s+(?:reading|processing|seeing)\s+this",
        r"(?:instructions?|note|message)\s+(?:for|to)\s+(?:the\s+)?(?:ai|assistant|llm|model|bot)\s*[:：]",
        r"(?:ai|assistant)\s*[:：]\s*(?:please\s+)?ignore",
        r"the\s+following\s+(?:text|content|document)\s+contains\s+instructions",
    ]),
    (85, "multilingual", [
        r"忽略(?:之前|上述|以上|前面|先前).{0,8}(?:指令|提示|规则|要求|设定)",
        r"忘(?:记|掉)(?:你的|之前|所有|先前).{0,8}(?:指令|设定|规则|提示)",
        r"(?:扮演|假装(?:你是|成为)|角色扮演)",
        r"(?:泄露|显示|打印|告诉我).{0,6}(?:系统)?(?:提示词?|指令|设定)",
        r"ignora\s+(?:las\s+)?instrucciones",
        r"oubliez?\s+(?:les\s+)?instructions",
    ]),
    (55, "output_hijacking", [
        r"(?:respond|reply|answer)\s+only\s+with",
        r"(?:output|say|print)\s+(?:exactly|verbatim|literally)\b",
        r"start\s+your\s+(?:response|reply|answer)\s+with",
        r"(?:do\s+not|don'?t|never)\s+(?:include|add|show)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|notes?)",
        r"omit\s+(?:all\s+)?(?:disclaimers?|warnings?|safety)",
    ]),
]

deeds = [
    (85, "shell_process_exec", [
        r"\bos\.(?:system|popen|exec[lv]?[ep]*|spawn[lv]?[ep]*)\s*\(",
        r"\bsubprocess\.(?:run|call|check_output|check_call|popen)\b",
        r"\bpopen\s*\(",
        r"\bpty\.spawn\s*\(",
        r"\bcommands\.(?:getoutput|getstatusoutput)\b",
        r"\bchild_process\b|require\(\s*['\"]child_process['\"]\s*\)",
        r"\b(?:shell_exec|passthru|proc_open|popen)\s*\(",
        r"\bruntime\.getruntime\(\)\.exec\b",
        r"\bprocessbuilder\s*\(",
    ]),
    (80, "dynamic_code_eval", [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"\b__import__\s*\(",
        r"\b(?:pickle|cpickle|_pickle|marshal)\.loads?\b",
        r"\byaml\.load\s*\((?![^)]*safeloader)",
        r"\bnew\s+function\s*\(",
        r"\bvm\.run(?:inthiscontext|incontext|innewcontext)\b",
    ]),
    (95, "destructive_command", [
        r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r",
        r"\brmdir\s+/s\b|\bdel\s+/[fsq]",
        r"\bformat\s+[a-z]:|\bmkfs(?:\.[a-z0-9]+)?\b",
        r"\bdd\s+if=.*\bof=/dev/sd[a-z]",
        r">\s*/dev/sd[a-z]\b",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        r"\bshutdown\s+(?:-[hrs]|/[sr])|\breboot\b|\bhalt\b|\bpoweroff\b",
        r"\bkill\s+-9\b|\bpkill\b|\btaskkill\s+/f",
        r"\bvssadmin\s+delete\s+shadows|\bwbadmin\s+delete\b",
        r"\bcipher\s+/w:|\bsdelete\b",
    ]),
    (95, "remote_payload_exec", [
        r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
        r"(?:curl|wget)\s+[^\n|]*\|\s*python[0-9.]*\b",
        r"\b(?:iex|invoke-expression)\b",
        r"\bpowershell(?:\.exe)?\s+[^\n]*-e(?:nc|ncodedcommand)?\b",
        r"new-object\s+(?:system\.)?net\.webclient|downloadstring|downloadfile",
        r"\bcertutil\b[^\n]*-urlcache|\bbitsadmin\b[^\n]*/transfer",
        r"\bmshta\s+https?:|\brundll32\b[^\n]*javascript:",
        r"\bregsvr32\s+/s?\s*/u?\s*/i:https?:",
    ]),
    (95, "reverse_shell", [
        r"/dev/tcp/\d|\b/dev/udp/\d",
        r"\bn(?:c|cat)\b[^\n]*\s-e\b",
        r"\bbash\s+-i\b[^\n]*(?:>&|&>)\s*/dev/tcp",
        r"\bmkfifo\b[^\n]*;\s*(?:nc|/bin/sh|bash)",
        r"socket\.socket\([^\n]*\)[^\n]*\.connect\(",
        r"\bsh\s+-i\b|\b/bin/sh\s+-i\b",
    ]),
    (85, "credential_file_access", [
        r"/etc/(?:passwd|shadow|sudoers)\b",
        r"(?:~|/home/[^/\s]+|/root)/\.ssh/(?:id_[a-z0-9]+|authorized_keys)",
        r"\.aws/credentials|\.azure/|\.kube/config|\.docker/config\.json",
        r"/proc/self/environ\b",
        r"\breg\s+(?:save|query)\b[^\n]*\bhk(?:lm|ey_local_machine)\\sam\b",
        r"\bget-content\b[^\n]*(?:\.ssh|credential|password|secret)",
    ]),
    (80, "privilege_persistence", [
        r"\bchmod\s+(?:[0-7]*7[0-7]{2}|\+s|u\+s)\b",
        r"\bchown\s+root\b",
        r"\bsetcap\b|\bvisudo\b",
        r"\bschtasks\s+/create|\bat\s+\d{1,2}:\d{2}\b",
        r"\bcrontab\s+-|>>\s*/etc/cron|/etc/cron\.[a-z]+/",
        r"reg\s+add\b[^\n]*\\currentversion\\run",
        r"\bnew-service\b|\bsc\s+create\b",
    ]),
]

secrets = [
    (95, "api_key", r"\bsk-[A-Za-z0-9_\-]{16,}\b", lambda s: _shrink(s, 3, 4)),
    (90, "jwt", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", lambda s: _shrink(s, 6, 4)),
    (90, "credit_card", r"\b(?:\d[ -]?){13,16}\b", lambda s: _shrink(re.sub(r"[ -]", "", s), 0, 4)),
    (85, "id_card", r"\b\d{17}[\dXx]\b", lambda s: _shrink(s, 4, 4)),
    (70, "phone", r"\b1[3-9]\d{9}\b", lambda s: _shrink(s, 3, 4)),
    (60, "intranet_ip",
        r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
        lambda s: re.sub(r"\.\d{1,3}$", ".*", s)),
    (50, "email", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", _mail),
]


def _pack(groups, owasp):
    out = []
    for sc, tag, pats in groups:
        out.append((sc, tag, owasp, [re.compile(p, re.I) for p in pats]))
    return out


_talk = _pack(talk, PI)
_deeds = _pack(deeds, OUT)
_secrets = [(sc, tag, INFO, re.compile(p, re.I), mk) for sc, tag, p, mk in secrets]


def _pick(packs, blob):
    best = -1
    got = None
    for sc, tag, owasp, pats in packs:
        for p in pats:
            m = p.search(blob)
            if m:
                if sc > best:
                    best = sc
                    snip = m.group(0)
                    got = (sc, tag, owasp, snip if len(snip) <= 120 else snip[:120])
                break
    return got


def _pii(blob):
    best = -1
    got = None
    for sc, tag, owasp, p, mk in _secrets:
        m = p.search(blob)
        if m and sc > best:
            best = sc
            got = (sc, tag, owasp, mk(m.group(0)))
    return got


def _noise(blob):
    pick = ""
    high = 0.0
    for tok in re.findall(r"\S{24,}", blob):
        if "://" in tok or tok.count(".") >= 2:
            continue
        tight = sum(1 for ch in tok if ch.isalnum() or ch in "+/=_-")
        if tight / len(tok) < 0.9:
            continue
        cnt = Counter(tok)
        n = len(tok)
        e = -sum((v / n) * math.log2(v / n) for v in cnt.values())
        if e >= 4.5 and e > high:
            high = e
            pick = tok
    if not pick:
        return None
    s = pick if len(pick) <= 12 else pick[:8] + "..." + pick[-4:]
    return (55, "high_entropy_blob", PI, s)


def scan(raw):
    blob = widen(raw)
    found = []
    for fn in (lambda b: _pick(_talk, b), lambda b: _pick(_deeds, b), _pii, _noise):
        r = fn(blob)
        if r:
            found.append(r)
    return found
