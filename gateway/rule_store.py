# -*- coding: utf-8 -*-
"""
Rule Store
==========
Extracts detection rules from hardcoded form into "data": single-file SQLite
storage with a standard schema, supporting query, create/update, enable/disable,
version history, and rollback. External security-analysis agents read and write
here through the /rules API.

See RULE_FIELDS for the standard rule fields; write operations are validated
(regex must compile + basic ReDoS protection) and carry automatic version
increment and history tracking.
"""

import os
import re
import json
import time
import sqlite3
from typing import Any, Dict, List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.db")

# Standard fields of a single rule (API contract)
RULE_FIELDS = (
    "id", "category", "name", "owasp_ast", "severity_score", "engine",
    "patterns", "flags", "params", "enabled", "tags", "description_zh", "test_cases",
    "version", "updated_by", "updated_at",
)

_LIST_JSON = ("patterns", "flags", "tags")
_DICT_JSON = ("test_cases", "params")
_JSON_COLS = _LIST_JSON + _DICT_JSON
_MAX_PATTERN_LEN = 2000
# Heuristic for catastrophic backtracking from nested quantifiers, e.g. (a+)+ / (.*)*; reject on match
_REDOS = re.compile(r"\([^)]*[+*][^)]*\)[+*]")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class RuleError(ValueError):
    """Rule validation failed."""


class RuleStore:
    def __init__(self, db_path: str = DB_PATH):
        self.path = db_path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                category TEXT, name TEXT, owasp_ast TEXT,
                severity_score INTEGER, engine TEXT,
                patterns TEXT, flags TEXT, params TEXT, enabled INTEGER DEFAULT 1,
                tags TEXT, description_zh TEXT, test_cases TEXT,
                version INTEGER DEFAULT 1,
                updated_by TEXT, updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS rule_history (
                id TEXT, version INTEGER, snapshot TEXT,
                action TEXT, actor TEXT, at TEXT
            );
            """
        )
        # Backward compat with old DBs: add the params column if missing
        cols = [r["name"] for r in self.conn.execute("PRAGMA table_info(rules)")]
        if "params" not in cols:
            self.conn.execute("ALTER TABLE rules ADD COLUMN params TEXT")
        self.conn.commit()

    # ---- serialization ----
    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> Dict[str, Any]:
        r = dict(row)
        for c in _LIST_JSON:
            r[c] = json.loads(r[c]) if r.get(c) else []
        for c in _DICT_JSON:
            r[c] = json.loads(r[c]) if r.get(c) else {}
        r["enabled"] = bool(r["enabled"])
        return r

    # ---- validation ----
    def validate(self, rule: Dict[str, Any]) -> None:
        if not rule.get("id"):
            raise RuleError("missing id")
        if not rule.get("name"):
            raise RuleError("missing name")
        engine = rule.get("engine", "regex")
        if engine not in ("regex", "sensitive", "keyword", "entropy", "ast", "model"):
            raise RuleError(f"unknown engine: {engine}")
        score = rule.get("severity_score", 0)
        if not isinstance(score, int) or not (0 <= score <= 100):
            raise RuleError("severity_score must be an integer in 0-100")
        if engine in ("regex", "sensitive"):
            pats = rule.get("patterns") or []
            if not pats:
                raise RuleError(f"{engine} rule is missing patterns")
            for p in pats:
                if len(p) > _MAX_PATTERN_LEN:
                    raise RuleError(f"pattern too long (>{_MAX_PATTERN_LEN})")
                if _REDOS.search(p):
                    raise RuleError(f"pattern rejected as likely catastrophic backtracking (ReDoS): {p[:60]}")
                try:
                    re.compile(p)
                except re.error as e:
                    raise RuleError(f"pattern failed to compile: {p[:60]} -> {e}")
        elif engine == "keyword":
            if not (rule.get("params") or {}).get("keywords"):
                raise RuleError("keyword engine is missing params.keywords")

    def run_tests(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Run the rule's own test_cases; returns {ok, fails}."""
        tc = rule.get("test_cases") or {}
        if rule.get("engine", "regex") != "regex" or not tc:
            return {"ok": True, "fails": []}
        compiled = [re.compile(p, re.I) for p in rule.get("patterns", [])]
        fails = []
        for s in tc.get("should_match", []):
            if not any(c.search(s) for c in compiled):
                fails.append({"expect": "match", "sample": s})
        for s in tc.get("should_not_match", []):
            if any(c.search(s) for c in compiled):
                fails.append({"expect": "no_match", "sample": s})
        return {"ok": not fails, "fails": fails}

    # ---- query ----
    def list(self, category=None, enabled=None, tag=None, q=None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM rules WHERE 1=1"
        args: List[Any] = []
        if category:
            sql += " AND category=?"; args.append(category)
        if enabled is not None:
            sql += " AND enabled=?"; args.append(1 if enabled else 0)
        if q:
            sql += " AND (name LIKE ? OR description_zh LIKE ? OR patterns LIKE ?)"
            args += [f"%{q}%"] * 3
        rows = self.conn.execute(sql + " ORDER BY category, name", args).fetchall()
        out = [self._row_to_rule(r) for r in rows]
        if tag:
            out = [r for r in out if tag in (r.get("tags") or [])]
        return out

    def get(self, rid: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
        return self._row_to_rule(row) if row else None

    # ---- write (with validation, versioning, history) ----
    def upsert(self, rule: Dict[str, Any], actor: str = "system",
               require_tests: bool = True) -> Dict[str, Any]:
        rule = dict(rule)
        rule.setdefault("engine", "regex")
        rule.setdefault("severity_score", 50)
        self.validate(rule)
        if require_tests:
            res = self.run_tests(rule)
            if not res["ok"]:
                raise RuleError(f"failed the rule's own test cases: {res['fails']}")

        old = self.get(rule["id"])
        version = (old["version"] + 1) if old else 1
        record = {
            "id": rule["id"],
            "category": rule.get("category", ""),
            "name": rule["name"],
            "owasp_ast": rule.get("owasp_ast", ""),
            "severity_score": int(rule.get("severity_score", 50)),
            "engine": rule["engine"],
            "patterns": json.dumps(rule.get("patterns", []), ensure_ascii=False),
            "flags": json.dumps(rule.get("flags", []), ensure_ascii=False),
            "params": json.dumps(rule.get("params", {}), ensure_ascii=False),
            "enabled": 1 if rule.get("enabled", True) else 0,
            "tags": json.dumps(rule.get("tags", []), ensure_ascii=False),
            "description_zh": rule.get("description_zh", ""),
            "test_cases": json.dumps(rule.get("test_cases", {}), ensure_ascii=False),
            "version": version,
            "updated_by": actor,
            "updated_at": _now(),
        }
        cols = ",".join(record.keys())
        ph = ",".join("?" for _ in record)
        self.conn.execute(
            f"INSERT OR REPLACE INTO rules ({cols}) VALUES ({ph})",
            list(record.values()),
        )
        self._history(rule["id"], version, "update" if old else "create", actor)
        self.conn.commit()
        return self.get(rule["id"])

    def set_enabled(self, rid: str, enabled: bool, actor: str = "system") -> Dict[str, Any]:
        cur = self.get(rid)
        if not cur:
            raise RuleError(f"rule does not exist: {rid}")
        version = cur["version"] + 1
        self.conn.execute(
            "UPDATE rules SET enabled=?, version=?, updated_by=?, updated_at=? WHERE id=?",
            (1 if enabled else 0, version, actor, _now(), rid),
        )
        self._history(rid, version, "enable" if enabled else "disable", actor)
        self.conn.commit()
        return self.get(rid)

    def delete(self, rid: str, actor: str = "system") -> bool:
        cur = self.get(rid)
        if not cur:
            return False
        self._history(rid, cur["version"], "delete", actor)
        self.conn.execute("DELETE FROM rules WHERE id=?", (rid,))
        self.conn.commit()
        return True

    def versions(self, rid: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT version, action, actor, at FROM rule_history WHERE id=? ORDER BY version DESC",
            (rid,),
        ).fetchall()
        return [dict(r) for r in rows]

    def rollback(self, rid: str, version: int, actor: str = "system") -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT snapshot FROM rule_history WHERE id=? AND version=?", (rid, version)
        ).fetchone()
        if not row or not row["snapshot"]:
            raise RuleError(f"version {version} of {rid} not found")
        snap = json.loads(row["snapshot"])
        return self.upsert(snap, actor=actor, require_tests=False)

    def _history(self, rid: str, version: int, action: str, actor: str):
        snap = json.dumps(self.get(rid), ensure_ascii=False) if action != "delete" else \
            json.dumps(self.get(rid), ensure_ascii=False)
        self.conn.execute(
            "INSERT INTO rule_history (id, version, snapshot, action, actor, at) "
            "VALUES (?,?,?,?,?,?)",
            (rid, version, snap, action, actor, _now()),
        )

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) c FROM rules").fetchone()["c"]


def seed_from_legacy(store: "RuleStore") -> int:
    """Bulk-load the regex rules from the existing hardcoded middleware into the store; returns the number imported."""
    try:
        from gateway.middlewares import injection, command_exec, prompt_injection
    except Exception:
        from middlewares import injection, command_exec, prompt_injection

    n = 0

    def put(rid, category, name, owasp, score, desc, patterns):
        nonlocal n
        store.upsert({
            "id": rid, "category": category, "name": name, "owasp_ast": owasp,
            "severity_score": score, "engine": "regex", "patterns": patterns,
            "flags": ["IGNORECASE"], "enabled": True,
            "tags": [category], "description_zh": desc, "test_cases": {},
        }, actor="seed", require_tests=False)
        n += 1

    for r in injection._RAW_RULES:
        put(f"injection-{r['category']}", "injection", r["category"],
            r.get("owasp_ast", ""), r["risk_score"], r["description"], r["patterns"])

    for r in command_exec._RAW_RULES:
        put(f"command_exec-{r['category']}", "command_exec", r["category"],
            command_exec._OWASP, r["risk_score"], r["description"], r["patterns"])

    for i, p in enumerate(prompt_injection._PATTERNS):
        put(f"prompt_injection-{i}", "prompt_injection", "prompt_injection",
            "LLM01: Prompt Injection", 75, "suspected prompt injection / jailbreak", [p.pattern])

    # Non-regex engines: entropy / keyword / sensitive, loaded into the store together
    def put_ex(rid, category, name, owasp, score, desc, engine, patterns=None, params=None):
        nonlocal n
        store.upsert({
            "id": rid, "category": category, "name": name, "owasp_ast": owasp,
            "severity_score": score, "engine": engine, "patterns": patterns or [],
            "flags": ["IGNORECASE"], "params": params or {}, "enabled": True,
            "tags": [category], "description_zh": desc, "test_cases": {},
        }, actor="seed", require_tests=False)
        n += 1

    put_ex("entropy-high-blob", "entropy", "high_entropy_blob",
           "LLM01: Prompt Injection", 55, "high-entropy blob, likely encoded/encrypted obfuscation",
           "entropy", params={"min_len": 24, "min_entropy": 4.5, "compact_ratio": 0.9})

    put_ex("keyword-high-risk-action", "keyword", "high_risk_action_keyword",
           "LLM05: Improper Output Handling", 100, "destructive high-risk operation keywords", "keyword",
           params={"keywords": [
               "delete", "drop", "truncate", "rm", "format", "destroy", "wipe",
               "shutdown", "reboot", "mkfs", "unlink", "rmdir", "del", "kill",
               "drop table", "drop database", "rm -rf"]})

    sens = [
        ("api_key", 95, r"\bsk-[A-Za-z0-9_\-]{16,}\b", "keep:3,4", "detected API key (sk-...)"),
        ("jwt", 90, r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", "keep:6,4", "detected JWT token"),
        ("credit_card", 90, r"\b(?:\d[ -]?){13,16}\b", "cc_last4", "detected credit card number"),
        ("id_card", 85, r"\b\d{17}[\dXx]\b", "keep:4,4", "detected national ID number"),
        ("phone", 70, r"\b1[3-9]\d{9}\b", "keep:3,4", "detected phone number"),
        ("intranet_ip", 60,
         r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
         r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
         "ip_last_octet", "detected internal-network IP address"),
        ("email", 50, r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "email", "detected email address"),
    ]
    for nm, score, pat, mask, desc in sens:
        put_ex(f"sensitive-{nm}", "sensitive", nm,
               "LLM06: Sensitive Information Disclosure", score, desc,
               "sensitive", patterns=[pat], params={"mask": mask})

    return n
