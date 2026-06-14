# -*- coding: utf-8 -*-
"""
Dangerous command / code execution detector
============================================
Flags skills that invoke processes, execute code dynamically, run
destructive system commands, download-and-run remote payloads, open reverse
shells, read credential files, or escalate/persist privileges. Covers
Python / shell / PowerShell / Node / PHP. Rule-based, no AI.

Return: same shape as the other detectors.
"""

import re

# Rules have been migrated to the rule_store rule library and are executed
# data-driven by middlewares/rule_engine.
SUPERSEDED = True
from typing import Dict, Any, List, Pattern

_OWASP = "LLM05: Improper Output Handling"

# Each rule = {category, risk_score, description, patterns}. Compiled IGNORECASE.
_RAW_RULES: List[Dict[str, Any]] = [
    {
        # 1. Process / shell execution
        "category": "shell_process_exec",
        "risk_score": 85,
        "description": "Process or shell execution call",
        "patterns": [
            r"\bos\.(?:system|popen|exec[lv]?[ep]*|spawn[lv]?[ep]*)\s*\(",
            r"\bsubprocess\.(?:run|call|check_output|check_call|popen)\b",
            r"\bpopen\s*\(",
            r"\bpty\.spawn\s*\(",
            r"\bcommands\.(?:getoutput|getstatusoutput)\b",
            r"\bchild_process\b|require\(\s*['\"]child_process['\"]\s*\)",  # node
            r"\b(?:shell_exec|passthru|proc_open|popen)\s*\(",              # php
            r"\bruntime\.getruntime\(\)\.exec\b",                           # java
            r"\bprocessbuilder\s*\(",                                       # java
        ],
    },
    {
        # 2. Dynamic code evaluation / deserialization
        "category": "dynamic_code_eval",
        "risk_score": 80,
        "description": "Dynamic code execution or unsafe deserialization",
        "patterns": [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"\b__import__\s*\(",
            r"\b(?:pickle|cpickle|_pickle|marshal)\.loads?\b",
            r"\byaml\.load\s*\((?![^)]*safeloader)",                        # yaml.load w/o SafeLoader
            r"\bnew\s+function\s*\(",                                       # JS Function ctor
            r"\bvm\.run(?:inthiscontext|incontext|innewcontext)\b",        # node vm
        ],
    },
    {
        # 3. Destructive system commands
        "category": "destructive_command",
        "risk_score": 95,
        "description": "Destructive filesystem / system command",
        "patterns": [
            r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r",              # rm -rf / -fr
            r"\brmdir\s+/s\b|\bdel\s+/[fsq]",                              # windows recursive delete
            r"\bformat\s+[a-z]:|\bmkfs(?:\.[a-z0-9]+)?\b",                 # format drive / mkfs
            r"\bdd\s+if=.*\bof=/dev/sd[a-z]",                             # disk overwrite
            r">\s*/dev/sd[a-z]\b",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",                   # fork bomb
            r"\bshutdown\s+(?:-[hrs]|/[sr])|\breboot\b|\bhalt\b|\bpoweroff\b",
            r"\bkill\s+-9\b|\bpkill\b|\btaskkill\s+/f",
            r"\bvssadmin\s+delete\s+shadows|\bwbadmin\s+delete\b",        # ransomware-style backup wipe
            r"\bcipher\s+/w:|\bsdelete\b",
        ],
    },
    {
        # 4. Remote payload download + execute
        "category": "remote_payload_exec",
        "risk_score": 95,
        "description": "Download-and-execute of a remote payload",
        "patterns": [
            r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",  # curl ... | sh
            r"(?:curl|wget)\s+[^\n|]*\|\s*python[0-9.]*\b",
            r"\b(?:iex|invoke-expression)\b",                              # powershell IEX
            r"\bpowershell(?:\.exe)?\s+[^\n]*-e(?:nc|ncodedcommand)?\b",   # encoded command
            r"new-object\s+(?:system\.)?net\.webclient|downloadstring|downloadfile",
            r"\bcertutil\b[^\n]*-urlcache|\bbitsadmin\b[^\n]*/transfer",
            r"\bmshta\s+https?:|\brundll32\b[^\n]*javascript:",
            r"\bregsvr32\s+/s?\s*/u?\s*/i:https?:",
        ],
    },
    {
        # 5. Reverse / bind shell
        "category": "reverse_shell",
        "risk_score": 95,
        "description": "Reverse or bind shell pattern",
        "patterns": [
            r"/dev/tcp/\d|\b/dev/udp/\d",
            r"\bn(?:c|cat)\b[^\n]*\s-e\b",                                 # nc -e
            r"\bbash\s+-i\b[^\n]*(?:>&|&>)\s*/dev/tcp",
            r"\bmkfifo\b[^\n]*;\s*(?:nc|/bin/sh|bash)",
            r"socket\.socket\([^\n]*\)[^\n]*\.connect\(",                  # python rev shell
            r"\bsh\s+-i\b|\b/bin/sh\s+-i\b",
        ],
    },
    {
        # 6. Credential / sensitive system file access
        "category": "credential_file_access",
        "risk_score": 85,
        "description": "Reading credential or sensitive system files",
        "patterns": [
            r"/etc/(?:passwd|shadow|sudoers)\b",
            r"(?:~|/home/[^/\s]+|/root)/\.ssh/(?:id_[a-z0-9]+|authorized_keys)",
            r"\.aws/credentials|\.azure/|\.kube/config|\.docker/config\.json",
            r"/proc/self/environ\b",
            r"\breg\s+(?:save|query)\b[^\n]*\bhk(?:lm|ey_local_machine)\\sam\b",
            r"\bget-content\b[^\n]*(?:\.ssh|credential|password|secret)",
        ],
    },
    {
        # 7. Privilege escalation / persistence
        "category": "privilege_persistence",
        "risk_score": 80,
        "description": "Privilege escalation or persistence mechanism",
        "patterns": [
            r"\bchmod\s+(?:[0-7]*7[0-7]{2}|\+s|u\+s)\b",                   # chmod 777 / setuid
            r"\bchown\s+root\b",
            r"\bsetcap\b|\bvisudo\b",
            r"\bschtasks\s+/create|\bat\s+\d{1,2}:\d{2}\b",                # scheduled task
            r"\bcrontab\s+-|>>\s*/etc/cron|/etc/cron\.[a-z]+/",            # cron persistence
            r"reg\s+add\b[^\n]*\\currentversion\\run",                    # run-key persistence
            r"\bnew-service\b|\bsc\s+create\b",
        ],
    },
]


def _compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled: List[Dict[str, Any]] = []
    for rule in raw_rules:
        patterns: List[Pattern] = [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
        compiled.append({**rule, "compiled": patterns})
    return compiled


_RULES: List[Dict[str, Any]] = _compile_rules(_RAW_RULES)


def detect(prompt: str) -> Dict[str, Any]:
    """Scan for dangerous execution patterns; return the highest-risk hit."""
    text = prompt or ""
    best_hit: Dict[str, Any] = {}

    for rule in _RULES:
        for pattern in rule["compiled"]:
            match = pattern.search(text)
            if not match:
                continue
            if rule["risk_score"] > best_hit.get("risk_score", -1):
                best_hit = {
                    "is_malicious": True,
                    "risk_score": rule["risk_score"],
                    "rule_hit": rule["category"],
                    "owasp_ast": _OWASP,
                    "details": {
                        "matched_string": match.group(0),
                        "rule_description": rule["description"],
                    },
                }
            break

    return best_hit or {"is_malicious": False}
