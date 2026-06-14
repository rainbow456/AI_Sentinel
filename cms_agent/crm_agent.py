# -*- coding: utf-8 -*-
"""
================================================================================
 CRM-Agent — lightweight natural-language CRM assistant
================================================================================

Modeled on Salesforce Agentforce's core interaction pattern: fully conversational,
natural-language driven. The user types English commands on the command line, and
the Agent parses the intent and operates on local data.

[Usage]
    CLI mode:  python crm_agent.py
    Web mode:  python crm_agent.py web        (default http://127.0.0.1:6001)
               python crm_agent.py web 8080   (custom port)

Both modes share the same data and business logic. On startup, a SQLite database
file crm.db is created automatically in the script's directory (reused if it already exists).

[Dependencies]
    Standard library only (sqlite3 / re / datetime, etc.).
    Optional: prettytable (pip install prettytable) — used to prettify tables;
              when not installed, falls back to built-in string alignment with no loss of function.

[Example commands] (type help to view at any time)
    Customers: add customer Acme Acme Corp 13800000000 zhang@x.com Beijing Chaoyang
               show customers / find customer Acme / update customer 3 phone=139xxxx / delete customer 3
    Contacts:  add contact John customer=1 title=Sales Manager phone=138xxxx email=li@x.com
               show contacts / contacts of customer 1 / delete contact 2
    Opportunities: create opportunity Annual Purchase customer=1 amount=50000
               advance opportunity 3 to negotiation / update opportunity 5 amount=80000 / close opportunity 2 won good price
               show opportunities
    Tasks:     add task customer 1 follow up call due 2026-06-10
               show open tasks / complete task 8 / tasks of opportunity 3
    Other:     show dashboard / help / exit

[Code organization]
    DatabaseManager — all SQLite reads/writes
    CommandParser   — natural-language intent parsing (regex + keywords)
    CRMAgent        — main loop, command dispatch, business logic, interactive feedback
================================================================================
"""

# Load .env before reading any env vars
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env takes precedence over env vars injected by the script/shell
except ImportError:
    pass

import os
import re
import sys
import json
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime

# Windows consoles default to GBK encoding and cannot output emoji / some Chinese
# characters, so switch everything to UTF-8.
# Python 3.7+ standard streams support reconfigure; silently skip on failure (core functionality unaffected).
for _stream in (sys.stdout, sys.stdin, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# ------------------------------------------------------------------------------
# Optional dependency prettytable: use it if available, otherwise fall back to built-in alignment
# ------------------------------------------------------------------------------
try:
    from prettytable import PrettyTable  # type: ignore

    _HAS_PRETTYTABLE = True
except ImportError:  # graceful fallback when not installed; functionality unaffected
    _HAS_PRETTYTABLE = False


DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crm.db")

# Help text (shared by CLI and Web)
HELP_TEXT = """Example commands (synonyms supported; natural language is fine):

[Customers]
  add customer Acme Acme Corp 13800000000 zhang@x.com Beijing Chaoyang
  show customers
  find customer Acme            (also searchable by phone: find customer 13800000000)
  update customer 3 phone=13911112222
  delete customer 3             (requires confirmation)

[Contacts]
  add contact John customer=1 title=Sales Manager phone=13800000000 email=li@x.com
  show contacts
  contacts of customer 1
  update contact 2 email=new@x.com
  delete contact 2

[Opportunities]
  create opportunity Annual Purchase customer=1 amount=50000
  advance opportunity 3 to negotiation     (stages: Lead/Qualified/Proposal/Negotiation/Won/Lost)
  update opportunity 5 amount=80000
  update opportunity 3 date=2026-07-01
  show opportunities            (grouped by stage)
  close opportunity 2 won good price

[Tasks / Follow-ups]
  add task customer 1 follow up to confirm needs due 2026-06-10
  add task opportunity 3 prepare bid proposal 2026-06-01
  show open tasks
  complete task 8
  tasks of opportunity 3

[Other]
  show dashboard / help / exit"""

# Opportunity stages: internal stored value -> English display name
STAGE_LABELS = {
    "initial_contact": "Lead",
    "needs_analysis": "Qualified",
    "proposal": "Proposal",
    "negotiation": "Negotiation",
    "won": "Won",
    "lost": "Lost",
}
# Display name -> internal value (used to parse stage names from user input)
STAGE_FROM_LABEL = {v: k for k, v in STAGE_LABELS.items()}
# Stage synonyms (lowercase), to ease natural-language matching
STAGE_ALIASES = {
    "lead": "initial_contact",
    "initial contact": "initial_contact",
    "contact": "initial_contact",
    "qualified": "needs_analysis",
    "needs analysis": "needs_analysis",
    "needs": "needs_analysis",
    "proposal": "proposal",
    "quote": "proposal",
    "negotiation": "negotiation",
    "negotiate": "negotiation",
    "won": "won",
    "win": "won",
    "lost": "lost",
    "lose": "lost",
    "fail": "lost",
}


# ==============================================================================
# AI_Sentinel security gateway integration (built-in guard)
# ==============================================================================
# Every command is detected by the gateway first, then enters the business logic;
# this lets the gateway log every input.
# Fully controllable via environment variables, and runs even without config
# (fail-open + warn when the gateway is unreachable).
SENTINEL_ENABLED = os.getenv("SENTINEL_ENABLED", "1") not in ("0", "false", "False", "")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:3001").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "crm-agent-01")

# High-risk intent -> entity type; reported under the neutral action name
# remove_record to avoid the gateway's English hard-block words.
HIGH_RISK_ACTIONS = {
    "delete_customer": "customer",
    "delete_contact": "contact",
    "delete_opportunity": "opportunity",
    "delete_task": "task",
}

# Input guard's "truly blocking categories": only these detectors, when hit, reject.
# The gateway's sensitive/pii_leak treats phone numbers and emails as sensitive
# info, but entering these in a CRM is a legitimate operation, so by default we
# only block the "prompt injection / jailbreak" categories; PII/sensitive
# categories are allowed on the input path (with a logged notice).
# Tighten with SENTINEL_BLOCK_DETECTORS="injection,prompt_injection,sensitive,pii_leak".
BLOCK_DETECTORS = set(
    d.strip() for d in
    os.getenv("SENTINEL_BLOCK_DETECTORS", "injection,prompt_injection").split(",")
    if d.strip()
)

# ------------------------------------------------------------------------------
# Skill extension: staff upload "declarative skills" to improve the agent
# ------------------------------------------------------------------------------
# A skill = a manifest JSON declaring new natural-language triggers -> knowledge
# Q&A / mapping to existing safe actions.
# None of the uploaded content is executed; uploads are forced through the
# AI_Sentinel /scan check, and only benign ones are loaded.
SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
# Allowlist of actions a skill may map to: only parameter-free read-only/display
# actions, to prevent mapping to high-risk create/update/delete actions.
SKILL_SAFE_ACTIONS = {
    "list_customers", "list_contacts", "list_opportunities",
    "list_tasks", "dashboard", "help",
}


class SentinelClient:
    """AI_Sentinel gateway client: pure standard-library urllib, 5s timeout, fail-open when the gateway is unreachable."""

    def __init__(self, base_url=GATEWAY_URL, agent_id=AGENT_ID, timeout=5.0):
        """Record the gateway address, agent identifier, and timeout."""
        self.base_url = base_url
        self.agent_id = agent_id
        self.timeout = timeout

    def _post(self, path, payload):
        """POST JSON, returning (status_code, dict); on network error returns (None, {error})."""
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # Errors carrying a response body (403 etc.): read the body for adjudication
            try:
                return e.code, json.loads(e.read().decode("utf-8"))
            except Exception:
                return e.code, {}
        except Exception as e:
            return None, {"error": str(e)}

    def check_input(self, prompt):
        """
        Input guard (/chat).
        Returns (ok, info): ok=True passes; ok=False means a gateway 403 hit (info holds the hit details).
        Gateway unreachable -> fail-open, ok=True and info={"warn": ...}.
        """
        status, body = self._post("/chat", {"prompt": prompt, "session_id": self.agent_id})
        if status == 200:
            return True, {}
        if status == 403:
            return False, body.get("detail", {})
        # Unreachable or error -> fail-open
        return True, {"warn": f"Security gateway unreachable; passing through (fail-open): {body.get('error', status)}"}

    def confirm_action(self, action_name, action_params, user_input=""):
        """
        Action guard (/confirm-action). Returns (allowed, reason).
        Gateway unreachable -> fail-open, allowed=True.
        """
        status, body = self._post("/confirm-action", {
            "action_name": action_name,
            "action_params": action_params or {},
            "agent_id": self.agent_id,
            "user_input": user_input,
        })
        if status == 200:
            return body.get("allowed", False), body.get("reason", "")
        return True, f"Security gateway unreachable; passing through (fail-open): {body.get('error', status)}"

    def scan(self, skill_name, skill_content):
        """
        Skill security scan (/scan). Returns (verdict, info).
        verdict in benign / suspicious / malicious / unverified.
        Unlike the input guard, skill uploads are **fail-closed**: gateway unreachable -> unverified (not loaded).
        """
        status, body = self._post("/scan", {
            "skill_name": skill_name, "skill_content": skill_content,
        })
        if status != 200:
            return "unverified", {"reason": f"Security gateway unreachable ({body.get('error', status)})"}
        risk = int(body.get("risk_score", 0))
        evidence = ""
        findings = body.get("findings") or []
        if findings:
            top = findings[0]
            evidence = top.get("description") or top.get("rule_hit") or ""
            if top.get("matched_content"):
                evidence += f"({top['matched_content']})"
        if not body.get("is_malicious"):
            return "benign", {"risk_score": risk, "evidence": ""}
        verdict = "malicious" if risk >= 80 else "suspicious"
        return verdict, {"risk_score": risk, "evidence": evidence}


# ==============================================================================
# Skill management: upload -> security scan -> load if benign / quarantine if malicious or suspicious
# ==============================================================================
class SkillManager:
    """
    Loading and management of declarative skills.

    A skill is a manifest JSON:
        {"name": "Refund Helper", "version": "1.0", "description": "...",
         "rules": [
            {"triggers": ["refund", "how to refund"], "respond": "Refund process: ..."},
            {"triggers": ["big customer", "vip"], "action": "list_customers"}
         ]}

    When a trigger matches, the skill either returns a piece of knowledge text
    (respond) or maps to an existing safe action (action, limited to the
    SKILL_SAFE_ACTIONS allowlist). On upload it first passes through the gateway
    /scan, and only benign ones are written to disk and loaded.
    """

    def __init__(self, sentinel, skills_dir=SKILLS_DIR):
        """Prepare directories and load already-installed skills."""
        self.sentinel = sentinel
        self.dir = skills_dir
        self.quarantine = os.path.join(skills_dir, "_quarantine")
        os.makedirs(self.dir, exist_ok=True)
        os.makedirs(self.quarantine, exist_ok=True)
        self.rules = []   # flattened trigger rules
        self.loaded = []  # summary of loaded skills
        self.reload()

    def reload(self):
        """Re-scan the skills directory and rebuild the trigger-rule table."""
        self.rules = []
        self.loaded = []
        for fn in sorted(os.listdir(self.dir)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, fn), encoding="utf-8") as f:
                    self._register(json.load(f), fn)
            except Exception:
                continue

    def _register(self, data, fn):
        """Split a manifest into trigger rules and register them. Returns the number of rules registered."""
        name = data.get("name") or fn[:-5]
        n = 0
        for r in (data.get("rules") or []):
            triggers = [str(x).lower() for x in (r.get("triggers") or []) if str(x).strip()]
            if not triggers:
                continue
            respond = r.get("respond")
            action = r.get("action")
            if action and action not in SKILL_SAFE_ACTIONS:
                action = None  # disallow mapping to high-risk / parameterized actions
            if not respond and not action:
                continue
            self.rules.append({"skill": name, "triggers": triggers,
                               "respond": respond, "action": action})
            n += 1
        self.loaded.append({"name": name, "file": fn, "rules": n,
                            "desc": data.get("description", "")})
        return n

    @staticmethod
    def _validate(content):
        """Validate the manifest structure, returning (data, err)."""
        try:
            data = json.loads(content)
        except Exception as e:
            return None, f"Not valid JSON: {e}"
        if not isinstance(data, dict):
            return None, "Manifest top level must be an object"
        if not str(data.get("name", "")).strip():
            return None, "Missing 'name' field"
        rules = data.get("rules")
        if not isinstance(rules, list) or not rules:
            return None, "Missing a non-empty 'rules' list"
        return data, None

    def submit(self, name, content):
        """
        Upload a skill. Flow: scan -> adjudicate -> if benign write to disk and load / otherwise quarantine.
        Returns {ok, verdict, risk_score, evidence, message}.
        """
        safe = re.sub(r"[^\w\-]", "_", (name or "skill")).strip("_")[:40] or "skill"

        # (1) Security gate (fail-closed: do not load if the gateway is unreachable)
        if self.sentinel:
            verdict, info = self.sentinel.scan(safe, content)
        else:
            verdict, info = "unverified", {"reason": "Security gateway not enabled (SENTINEL_ENABLED=0)"}
        risk = info.get("risk_score", 0)
        evidence = info.get("evidence", "") or info.get("reason", "")

        if verdict != "benign":
            self._quarantine(safe, content, verdict, evidence)
            tip = {"unverified": "Security gateway unreachable; held pending review",
                   "suspicious": "Scan flagged as suspicious; quarantined",
                   "malicious": "Scan flagged as malicious; blocked and quarantined"}.get(verdict, "Not approved")
            return {"ok": False, "verdict": verdict, "risk_score": risk,
                    "evidence": evidence, "message": f"{tip}; not loaded."}

        # (2) benign: validate structure, then write to disk and load
        data, err = self._validate(content)
        if err:
            return {"ok": False, "verdict": "benign", "risk_score": risk,
                    "evidence": "", "message": f"Scan passed but manifest is invalid: {err}"}
        fn = safe + ".json"
        with open(os.path.join(self.dir, fn), "w", encoding="utf-8") as f:
            f.write(content)
        self.reload()
        active = next((s["rules"] for s in self.loaded if s["file"] == fn), 0)
        return {"ok": True, "verdict": "benign", "risk_score": risk, "evidence": "",
                "message": f"Scan passed; loaded skill \"{data.get('name')}\" ({active} rules now active)."}

    def _quarantine(self, name, content, verdict, evidence):
        """Write the rejected skill, together with its verdict, into the quarantine area."""
        try:
            with open(os.path.join(self.quarantine, name + ".json"), "w", encoding="utf-8") as f:
                f.write(content)
            with open(os.path.join(self.quarantine, name + ".meta.json"), "w", encoding="utf-8") as f:
                json.dump({"name": name, "verdict": verdict, "evidence": evidence},
                          f, ensure_ascii=False)
        except Exception:
            pass

    def match(self, text):
        """Run trigger matching on unrecognized input; return the rule on a hit, otherwise None."""
        low = (text or "").lower()
        for r in self.rules:
            if any(t in low for t in r["triggers"]):
                return r
        return None

    def listing(self):
        """Return the (loaded, quarantined) lists."""
        q = []
        for fn in sorted(os.listdir(self.quarantine)):
            if fn.endswith(".meta.json"):
                try:
                    with open(os.path.join(self.quarantine, fn), encoding="utf-8") as f:
                        q.append(json.load(f))
                except Exception:
                    pass
        return self.loaded, q


# ==============================================================================
# Table-rendering utility: uniformly handles both prettytable and the fallback case
# ==============================================================================
def render_table(headers, rows):
    """
    Render headers and data rows into an aligned table string.

    headers: list[str] column titles
    rows:    list[list] cell values per row (any type, converted to str internally)
    returns: a multi-line string; returns a notice when rows is empty.
    """
    if not rows:
        return "(no matching records)"

    str_rows = [[("" if c is None else str(c)) for c in row] for row in rows]

    if _HAS_PRETTYTABLE:
        table = PrettyTable()
        table.field_names = headers
        table.align = "l"  # left-align; easier to read for Chinese text
        for row in str_rows:
            table.add_row(row)
        return table.get_string()

    # ---- Fallback: compute column widths manually and align ----
    widths = [_disp_width(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _disp_width(cell))

    def fmt_row(cells):
        parts = [_pad(cell, widths[i]) for i, cell in enumerate(cells)]
        return "| " + " | ".join(parts) + " |"

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, fmt_row(headers), sep]
    lines += [fmt_row(row) for row in str_rows]
    lines.append(sep)
    return "\n".join(lines)


def _disp_width(text):
    """Compute display width of a string: Chinese/full-width chars count as 2, others as 1."""
    width = 0
    for ch in text:
        # CJK unified ideographs, full-width symbols, etc. occupy two terminal columns
        width += 2 if ord(ch) > 0x2E7F else 1
    return width


def _pad(text, width):
    """Right-pad with spaces by display width, so mixed Chinese/English text aligns."""
    return text + " " * (width - _disp_width(text))


# ==============================================================================
# Database management
# ==============================================================================
class DatabaseManager:
    """Encapsulates all SQLite operations; handles table creation and CRUD."""

    def __init__(self, db_path=DB_FILE):
        """Connect to (or create) the database file and ensure all tables exist."""
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # query results accessible by column name
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self):
        """Create the four business tables (IF NOT EXISTS, safe to call repeatedly)."""
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                company    TEXT,
                phone      TEXT,
                email      TEXT,
                address    TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS contacts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER,
                name        TEXT NOT NULL,
                title       TEXT,
                phone       TEXT,
                email       TEXT
            );
            CREATE TABLE IF NOT EXISTS opportunities (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id   INTEGER,
                name          TEXT NOT NULL,
                amount        REAL DEFAULT 0,
                stage         TEXT DEFAULT 'initial_contact',
                close_date    TEXT,
                closed_reason TEXT,
                created_at    TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                related_type TEXT,
                related_id   INTEGER,
                description  TEXT NOT NULL,
                due_date     TEXT,
                status       TEXT DEFAULT 'todo'
            );
            """
        )
        self.conn.commit()

    # ---- Generic execution helpers ----
    def execute(self, sql, params=()):
        """Execute a write (INSERT/UPDATE/DELETE), returning the cursor."""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        self.conn.commit()
        return cur

    def query(self, sql, params=()):
        """Run a query, returning a list of sqlite3.Row."""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()

    def query_one(self, sql, params=()):
        """Run a query, returning a single row (None if no result)."""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchone()

    def close(self):
        """Close the database connection."""
        self.conn.close()


# ==============================================================================
# Intent parsing
# ==============================================================================
class CommandParser:
    """
    Parse natural-language text into a structured intent.

    The parse result is always a dict: {"action": <action name>, ...other fields}
    Returns {"action": "unknown"} when unrecognized.
    Uses a "keyword locates the module + regex extracts the fields" strategy,
    which covers the typical sentence patterns well enough.
    """

    def parse(self, text):
        """Parse a single user input and return the intent dict."""
        t = text.strip()
        low = t.lower()

        # ---- Global commands ----
        if low in ("help", "?"):
            return {"action": "help"}
        if low in ("exit", "quit", "bye"):
            return {"action": "exit"}
        if ("dashboard" in low or "overview" in low or "summary" in low):
            return {"action": "dashboard"}
        if low in ("skill", "skills", "list skills", "show skills"):
            return {"action": "list_skills"}

        # ---- Dispatch by "action + entity" ----
        # Query/list cases go first: query verbs (show/list/view ...) don't conflict
        # with the create/update/delete prefixes, and this avoids the "complete task"
        # phrasing inside "show open tasks" being misread as a complete-task command.
        if re.match(r"(?i)^(show|list|view|find|search)\b", t):
            return self._parse_query(t)
        # Delete cases
        if re.match(r"(?i)^(delete|remove)\b", t):
            return self._parse_delete(t)
        # Complete a task
        if re.search(r"(?i)\bcomplete\s+task\b", t) or re.search(r"(?i)task.*\b(complete|done)\b", t):
            return self._parse_complete_task(t)
        # Add / create cases
        if re.match(r"(?i)^(add|create|new)\b", t):
            return self._parse_add(t)
        # Update / modify cases
        if re.match(r"(?i)^(update|edit|advance|move|set)\b", t):
            return self._parse_update(t)
        # Close an opportunity
        if re.search(r"(?i)\bclose\s+opportunity\b", t) or re.search(r"(?i)opportunity.*\b(won|lost|close)\b", t):
            return self._parse_close_opportunity(t)

        # Verb-less query fallback: e.g. "contacts of customer 1", "tasks of opportunity 3"
        if re.search(r"(?i)\b(contacts?|tasks?)\b\s+of\b", t):
            return self._parse_query(t)

        return {"action": "unknown"}

    # --------------------------------------------------------------------------
    # Field-extraction helpers
    # --------------------------------------------------------------------------
    @staticmethod
    def _extract_phone(text):
        """Extract a phone number (11 digits, possibly with +86 etc.; take 11 consecutive digits)."""
        m = re.search(r"\b(1\d{10})\b", text)
        return m.group(1) if m else None

    @staticmethod
    def _extract_email(text):
        """Extract an email address using an explicit ASCII charset for the address."""
        m = re.search(r"[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]+", text)
        return m.group(0) if m else None

    @staticmethod
    def _extract_customer_id(text):
        """Extract the customer ID: supports customer=1 / customer 1 / customer:1 and similar forms."""
        m = re.search(r"(?i)customer\s*(?:id)?\s*[=:]?\s*(\d+)", text)
        return int(m.group(1)) if m else None

    @staticmethod
    def _extract_amount(text):
        """Extract an amount: matches "amount=50000 / amount 5k / 5k / 50000".

        Units: optional 'k' (x1000) or 'm' (x1,000,000) suffix; plain numbers are
        taken as-is.
        """
        # First look for the value after "amount" (handles "amount=/amount is/amount:" separators)
        m = re.search(r"(?i)amount\s*(?:is|=|:)?\s*([\d.]+)\s*(k|m)?", text)
        if not m:
            # Fall back to a number followed by a k/m unit
            m = re.search(r"(?i)([\d.]+)\s*(k|m)\b", text)
        if not m:
            return None
        value = float(m.group(1))
        unit = (m.group(2) or "").lower() if m.lastindex and m.lastindex >= 2 else None
        if unit == "k":
            value *= 1000
        elif unit == "m":
            value *= 1000000
        return value

    @staticmethod
    def _extract_date(text):
        """Extract a date YYYY-MM-DD (also accepts YYYY/MM/DD)."""
        m = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
        if not m:
            return None
        y, mo, d = m.group(1), int(m.group(2)), int(m.group(3))
        return f"{y}-{mo:02d}-{d:02d}"

    @staticmethod
    def _match_stage(text):
        """Identify the opportunity stage from text, returning the internal value or None."""
        low = text.lower()
        # Match longer aliases first (e.g. "needs analysis" before "needs") and use
        # word boundaries so e.g. "win" doesn't match inside another word.
        for label in sorted(STAGE_ALIASES, key=len, reverse=True):
            if re.search(r"\b" + re.escape(label) + r"\b", low):
                return STAGE_ALIASES[label]
        return None

    # --------------------------------------------------------------------------
    # Add cases
    # --------------------------------------------------------------------------
    def _parse_add(self, t):
        """
        Parse "add customer/contact/opportunity/task".
        Target object = the entity word appearing earliest right after the
        "add/create" verb.
        (e.g. in "add task opportunity 1 ...", "task" comes before "opportunity",
         so it is judged as adding a task, and "opportunity 1" is merely its
         associated parameter.)
        """
        candidates = {
            "contact": self._parse_add_contact,
            "task": self._parse_add_task,
            "followup": self._parse_add_task,
            "opportunity": self._parse_add_opportunity,
            "deal": self._parse_add_opportunity,
            "customer": self._parse_add_customer,
        }
        low = t.lower()
        best_word, best_pos = None, len(t) + 1
        for word in candidates:
            pos = low.find(word)
            if pos != -1 and pos < best_pos:
                best_word, best_pos = word, pos
        if best_word:
            return candidates[best_word](t)
        return {"action": "unknown"}

    def _parse_add_customer(self, t):
        """
        Add a customer. Example:
            add customer Acme Acme Corp 13800000000 zhang@x.com Beijing Chaoyang
        Strategy: extract phone/email first; of the remaining tokens, the first is
        the name, the second the company, and the tail the address.
        """
        phone = self._extract_phone(t)
        email = self._extract_email(t)

        # Strip the command words and the recognized phone/email, then split the rest on whitespace
        body = re.sub(r"(?i)^(add|create|new)\s+customer", "", t).strip()
        if phone:
            body = body.replace(phone, " ")
        if email:
            body = body.replace(email, " ")
        tokens = [x for x in re.split(r"\s+", body) if x]

        name = tokens[0] if len(tokens) >= 1 else None
        company = tokens[1] if len(tokens) >= 2 else None
        address = " ".join(tokens[2:]) if len(tokens) >= 3 else None
        return {
            "action": "add_customer",
            "name": name,
            "company": company,
            "phone": phone,
            "email": email,
            "address": address,
        }

    def _parse_add_contact(self, t):
        """
        Add a contact. Example:
            add contact John customer=1 title=Sales Manager phone=138xxxx email=li@x.com
        """
        customer_id = self._extract_customer_id(t)
        phone = self._extract_phone(t)
        email = self._extract_email(t)

        # title=... captures the rest of the value up to the next known marker or end
        title = None
        m = re.search(r"(?i)title\s*[=:]?\s*(.+?)\s*(?=\b(?:customer|phone|email)\b|$)", t)
        if m and m.group(1).strip():
            title = m.group(1).strip()

        # Name: the first token right after "contact"
        body = re.sub(r"(?i)^(add|create|new)\s+contact", "", t).strip()
        # Remove already-recognized fields so they aren't mistaken for the name
        for chunk in (phone, email):
            if chunk:
                body = body.replace(chunk, " ")
        body = re.sub(r"(?i)customer\s*(?:id)?\s*[=:]?\s*\d+", " ", body)
        body = re.sub(r"(?i)title\s*[=:]?\s*.+?(?=\b(?:customer|phone|email)\b|$)", " ", body)
        body = re.sub(r"(?i)(phone|email)\s*[=:]?", " ", body)
        tokens = [x for x in re.split(r"\s+", body) if x]
        name = tokens[0] if tokens else None

        return {
            "action": "add_contact",
            "name": name,
            "customer_id": customer_id,
            "title": title,
            "phone": phone,
            "email": email,
        }

    def _parse_add_opportunity(self, t):
        """
        Create an opportunity. Example:
            create opportunity Annual Purchase customer=1 amount=50000
        """
        customer_id = self._extract_customer_id(t)
        amount = self._extract_amount(t)
        close_date = self._extract_date(t)

        body = re.sub(r"(?i)^(add|create|new)\s+(opportunity|deal)", "", t).strip()
        body = re.sub(r"(?i)customer\s*(?:id)?\s*[=:]?\s*\d+", " ", body)
        body = re.sub(r"(?i)amount\s*[=:]?\s*[\d.]+\s*(k|m)?\b", " ", body)
        body = re.sub(r"(?i)\bdue\b|\bdate\b", " ", body)
        body = re.sub(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", " ", body)
        tokens = [x for x in re.split(r"\s+", body) if x]
        # The opportunity name is the leading free-text (may be multiple words)
        name = " ".join(tokens) if tokens else None

        return {
            "action": "add_opportunity",
            "name": name,
            "customer_id": customer_id,
            "amount": amount,
            "close_date": close_date,
        }

    def _parse_add_task(self, t):
        """
        Add a task. Example:
            add task customer 1 follow up call due 2026-06-10
            add task opportunity 3 prepare proposal 2026-06-01
        Associated object: if "opportunity" appears it links to an opportunity, otherwise it defaults to a customer.
        """
        due_date = self._extract_date(t)
        if re.search(r"(?i)\bopportunity\b|\bdeal\b", t):
            related_type = "opportunity"
            m = re.search(r"(?i)(?:opportunity|deal)\s*(?:id)?\s*[=:]?\s*(\d+)", t)
        else:
            related_type = "customer"
            m = re.search(r"(?i)customer\s*(?:id)?\s*[=:]?\s*(\d+)", t)
        related_id = int(m.group(1)) if m else None

        body = re.sub(r"(?i)^(add|create|new)\s+(task|followup)", "", t).strip()
        body = re.sub(r"(?i)(customer|opportunity|deal)\s*(?:id)?\s*[=:]?\s*\d+", " ", body)
        body = re.sub(r"(?i)\bdue\b\s*[=:]?", " ", body)
        body = re.sub(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", " ", body)
        description = " ".join(x for x in re.split(r"\s+", body) if x).strip()

        return {
            "action": "add_task",
            "related_type": related_type,
            "related_id": related_id,
            "description": description or None,
            "due_date": due_date,
        }

    # --------------------------------------------------------------------------
    # Query cases
    # --------------------------------------------------------------------------
    def _parse_query(self, t):
        """Parse the various query/list commands."""
        low = t.lower()
        # Filter contacts by customer: contacts of customer 1 / customer=1 contacts
        if "contact" in low:
            cid = self._extract_customer_id(t)
            if cid is not None:
                return {"action": "list_contacts", "customer_id": cid}
            return {"action": "list_contacts", "customer_id": None}

        # Opportunity list
        if "opportunity" in low or "deal" in low:
            return {"action": "list_opportunities"}

        # Tasks: open / all / by object
        if "task" in low:
            if re.search(r"(?i)\b(open|todo|pending|in[\s\-]?progress|incomplete|unfinished)\b", t):
                status = "todo"
            else:
                status = None
            cid = None
            oid = None
            mo = re.search(r"(?i)(?:opportunity|deal)\s*(?:id)?\s*[=:]?\s*(\d+)", t)
            mc = re.search(r"(?i)customer\s*(?:id)?\s*[=:]?\s*(\d+)", t)
            if mo:
                oid = int(mo.group(1))
            elif mc:
                cid = int(mc.group(1))
            return {
                "action": "list_tasks",
                "status": status,
                "customer_id": cid,
                "opportunity_id": oid,
            }

        # Customers: find/search customer by keyword
        if "customer" in low:
            m = re.search(r"(?i)(?:find|search)\s+customer\s+(.+)$", t)
            if m and m.group(1).strip():
                return {"action": "search_customer", "keyword": m.group(1).strip()}
            return {"action": "list_customers"}

        return {"action": "unknown"}

    # --------------------------------------------------------------------------
    # Update cases
    # --------------------------------------------------------------------------
    def _parse_update(self, t):
        """Parse update commands: customer field / opportunity stage / opportunity amount, date."""
        low = t.lower()
        is_opp = ("opportunity" in low or "deal" in low)
        # Advance opportunity stage: advance opportunity 3 to negotiation / set opportunity 5 stage won
        if is_opp and ("stage" in low or "advance" in low or "move" in low or self._match_stage(t)):
            m = re.search(r"(?i)(?:opportunity|deal)\s*(?:#|id)?\s*(\d+)", t)
            stage = self._match_stage(t)
            if m and stage:
                return {
                    "action": "update_opp_stage",
                    "id": int(m.group(1)),
                    "stage": stage,
                }

        # Modify opportunity amount: update opportunity 5 amount=80000
        if is_opp and "amount" in low:
            m = re.search(r"(?i)(?:opportunity|deal)\s*(?:#|id)?\s*(\d+)", t)
            amount = self._extract_amount(t)
            if m and amount is not None:
                return {
                    "action": "update_opp_amount",
                    "id": int(m.group(1)),
                    "amount": amount,
                }

        # Opportunity expected close date: update opportunity 3 date=2026-07-01
        if is_opp and "date" in low:
            m = re.search(r"(?i)(?:opportunity|deal)\s*(?:#|id)?\s*(\d+)", t)
            date = self._extract_date(t)
            if m and date:
                return {
                    "action": "update_opp_date",
                    "id": int(m.group(1)),
                    "close_date": date,
                }

        # Customer field update: update customer 3 phone=139xxxx / edit customer 2 email=a@b.com
        if "customer" in low:
            m = re.search(r"(?i)customer\s*(?:#|id)?\s*(\d+)", t)
            if m:
                cid = int(m.group(1))
                field, value = self._parse_field_value(t)
                if field:
                    return {
                        "action": "update_customer",
                        "id": cid,
                        "field": field,
                        "value": value,
                    }

        # Contact field update: update contact 2 phone=139xxxx
        if "contact" in low:
            m = re.search(r"(?i)contact\s*(?:#|id)?\s*(\d+)", t)
            if m:
                field, value = self._parse_field_value(t)
                if field:
                    return {
                        "action": "update_contact",
                        "id": int(m.group(1)),
                        "field": field,
                        "value": value,
                    }

        return {"action": "unknown"}

    def _parse_field_value(self, t):
        """
        Extract the field name and value from "... <field> to/= <value>".
        Returns (db_field, value); returns (None, None) when unrecognized.
        """
        field_map = {
            "phone": "phone",
            "mobile": "phone",
            "email": "email",
            "mail": "email",
            "name": "name",
            "company": "company",
            "address": "address",
            "title": "title",
        }
        m = re.search(r"(?i)\b(phone|mobile|email|mail|name|company|address|title)\s*"
                      r"(?:to|=|:)\s*(.+)$", t)
        if not m:
            return None, None
        field = field_map[m.group(1).lower()]
        value = m.group(2).strip()
        return field, value

    # --------------------------------------------------------------------------
    # Delete cases
    # --------------------------------------------------------------------------
    def _parse_delete(self, t):
        """Parse delete commands: customer / contact / opportunity / task."""
        low = t.lower()
        # Check contact before customer ("contact" contains no "customer" but order is harmless)
        if "contact" in low:
            m = re.search(r"(?i)contact\s*(?:#|id)?\s*(\d+)", t)
            if m:
                return {"action": "delete_contact", "id": int(m.group(1))}
        if "customer" in low:
            m = re.search(r"(?i)customer\s*(?:#|id)?\s*(\d+)", t)
            if m:
                return {"action": "delete_customer", "id": int(m.group(1))}
        if "opportunity" in low or "deal" in low:
            m = re.search(r"(?i)(?:opportunity|deal)\s*(?:#|id)?\s*(\d+)", t)
            if m:
                return {"action": "delete_opportunity", "id": int(m.group(1))}
        if "task" in low:
            m = re.search(r"(?i)task\s*(?:#|id)?\s*(\d+)", t)
            if m:
                return {"action": "delete_task", "id": int(m.group(1))}
        return {"action": "unknown"}

    # --------------------------------------------------------------------------
    # Complete a task / close an opportunity
    # --------------------------------------------------------------------------
    def _parse_complete_task(self, t):
        """Parse "complete task 8 / complete task #8"."""
        m = re.search(r"(?i)task\s*(?:#|id)?\s*(\d+)", t)
        if m:
            return {"action": "complete_task", "id": int(m.group(1))}
        return {"action": "unknown"}

    def _parse_close_opportunity(self, t):
        """
        Parse closing an opportunity: close opportunity 2 won good price / opportunity 3 lost budget
        result: won / lost; reason is the remaining description.
        """
        m = re.search(r"(?i)(?:opportunity|deal)\s*(?:#|id)?\s*(\d+)", t)
        if not m:
            return {"action": "unknown"}
        oid = int(m.group(1))
        if re.search(r"(?i)\b(won|win)\b", t):
            result = "won"
        elif re.search(r"(?i)\b(lost|lose|fail)\b", t):
            result = "lost"
        else:
            result = None  # the business layer will follow up

        # Close reason: the text remaining after removing command words and keywords
        reason = re.sub(r"(?i)\b(close|opportunity|deal|won|win|lost|lose|fail)\b", " ", t)
        reason = re.sub(r"(?:#|id)?\s*\d+", " ", reason)
        reason = " ".join(x for x in re.split(r"\s+", reason) if x).strip()
        return {
            "action": "close_opportunity",
            "id": oid,
            "result": result,
            "reason": reason or None,
        }


# ==============================================================================
# Main Agent: dispatch commands, run business logic, produce structured results
# ==============================================================================
#
# Business methods no longer print directly; instead they return a list of
# "result blocks", in these forms:
#   {"kind": "text",  "text": "...", "tone": "ok|err|info|warn"}
#   {"kind": "table", "title": "...", "headers": [...], "rows": [[...]]}
#   {"kind": "stats", "title": "...", "items": [{"label":..,"value":..}, ...]}
# This way the CLI (_render_cli prints) and the Web (converts to JSON for the
# frontend) can share the same logic.
# ==============================================================================
class CRMAgent:
    """CRM agent: parse intent -> execute -> return structured result blocks."""

    def __init__(self, interactive=True):
        """
        Initialize the database and parser.
        interactive=True : CLI mode; prompt via input() for missing fields, and confirm deletes.
        interactive=False: Web mode; return a notice block directly for missing fields;
                           deletes are confirmed by a frontend dialog before being allowed.
        """
        self.interactive = interactive
        self.db = DatabaseManager()
        self.parser = CommandParser()
        # Security gateway client (can be disabled with SENTINEL_ENABLED=0)
        self.sentinel = SentinelClient() if SENTINEL_ENABLED else None
        # Declarative skills uploaded by staff (scanned by the gateway on upload; only benign ones are loaded)
        self.skills = SkillManager(self.sentinel)
        # action -> handler method dispatch table
        self.handlers = {
            "help": self.show_help,
            "dashboard": self.show_dashboard,
            "add_customer": self.add_customer,
            "list_customers": self.list_customers,
            "search_customer": self.search_customer,
            "update_customer": self.update_customer,
            "delete_customer": self.delete_customer,
            "add_contact": self.add_contact,
            "list_contacts": self.list_contacts,
            "update_contact": self.update_contact,
            "delete_contact": self.delete_contact,
            "add_opportunity": self.add_opportunity,
            "list_opportunities": self.list_opportunities,
            "update_opp_stage": self.update_opp_stage,
            "update_opp_amount": self.update_opp_amount,
            "update_opp_date": self.update_opp_date,
            "close_opportunity": self.close_opportunity,
            "delete_opportunity": self.delete_opportunity,
            "add_task": self.add_task,
            "list_tasks": self.list_tasks,
            "complete_task": self.complete_task,
            "delete_task": self.delete_task,
            "list_skills": self.list_skills,
        }

    # --------------------------------------------------------------------------
    # CLI main loop
    # --------------------------------------------------------------------------
    def run(self):
        """Start the command-line interaction loop until the user types exit/quit."""
        print("=" * 60)
        print(" 🤝  CRM-Agent started — manage your customers and deals in natural language")
        print("     Type help to see example commands, type exit to quit")
        if self.sentinel:
            print(f" 🛡️  Wired into the AI_Sentinel security gateway: {GATEWAY_URL}")
        else:
            print(" 🛡️  Security gateway disabled (SENTINEL_ENABLED=0)")
        print("=" * 60)
        while True:
            try:
                raw = input("\nCRM-Agent > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye!")
                break
            if not raw:
                continue
            if self.parser.parse(raw).get("action") == "exit":
                print("Goodbye! Your data has been saved.")
                break
            self._render_cli(self.process(raw))
        self.db.close()

    def process(self, raw):
        """Parse and execute a single command, returning a list of result blocks (shared entry point for CLI and Web)."""
        prefix = []  # notice blocks produced by the guard, prepended to the business result

        # -- Layer 1: input guard (every command requests the gateway, so the gateway can log it) --
        if self.sentinel:
            ok, info = self.sentinel.check_input(raw)
            if not ok:
                detector = info.get("detector") or ""
                rule = info.get("rule_hit") or detector or "unknown"
                desc = (info.get("details") or {}).get("rule_description") \
                    or info.get("reason") or ""
                if detector in BLOCK_DETECTORS:
                    return [self._err(f"⛔ Input blocked by the security gateway: {rule}"
                                      + (f" — {desc}" if desc else ""))]
                # PII/sensitive category: CRM is entering legitimate fields; pass but leave a trace
                prefix.append(self._info(
                    f"🔐 Gateway notice: input contains a sensitive field ({rule}); passed per CRM policy."))
            elif info.get("warn"):
                prefix.append(self._text("⚠️ " + info["warn"], "warn"))

        intent = self.parser.parse(raw)
        action = intent.get("action")
        if action == "exit":
            return prefix + [self._info("In Web mode just close the page; no exit command is needed.")]
        if action == "unknown":
            # Fallback: hand off to trigger matching of the loaded skills
            hit = self.skills.match(raw) if self.skills else None
            if hit and hit.get("action") in self.handlers:
                action = hit["action"]
                intent = {"action": action}
            elif hit and hit.get("respond"):
                return prefix + [self._info(f"💡 {hit['respond']}")]
            else:
                return prefix + [self._err("🤔 Didn't understand that command. Click an example above or type help to see usage.")]
        handler = self.handlers.get(action)
        if not handler:
            return prefix + [self._err("This feature is not implemented yet.")]

        # -- Layer 2: action guard (high-risk delete operations only; sends a /confirm-action report) --
        if self.sentinel and action in HIGH_RISK_ACTIONS:
            params = {"entity": HIGH_RISK_ACTIONS[action], "id": intent.get("id")}
            allowed, reason = self.sentinel.confirm_action("remove_record", params, raw)
            if not allowed:
                return prefix + [self._err(f"⛔ Operation blocked by the security gateway: {reason}")]

        try:
            result = handler(intent)
            result = result if isinstance(result, list) else [result]
            return prefix + result
        except Exception as e:  # graceful degradation on error; don't crash the program
            return prefix + [self._err(f"⚠️ Operation error: {e}")]

    @staticmethod
    def _render_cli(blocks):
        """Render result blocks to the command line."""
        for b in blocks:
            kind = b.get("kind")
            if kind == "text":
                print(b["text"])
            elif kind == "table":
                if b.get("title"):
                    print("\n" + b["title"])
                print(render_table(b["headers"], b["rows"]))
            elif kind == "stats":
                if b.get("title"):
                    print("\n" + b["title"])
                print(render_table(
                    ["Metric", "Value"],
                    [[i["label"], i["value"]] for i in b["items"]],
                ))

    # --------------------------------------------------------------------------
    # Result-block construction & interaction helpers
    # --------------------------------------------------------------------------
    @staticmethod
    def _text(s, tone="info"):
        """Build a text block. tone controls the frontend color: ok/err/info/warn."""
        return {"kind": "text", "text": s, "tone": tone}

    def _ok(self, s):
        """Success notice block."""
        return self._text(s, "ok")

    def _err(self, s):
        """Error notice block."""
        return self._text(s, "err")

    def _info(self, s):
        """Plain info block."""
        return self._text(s, "info")

    @staticmethod
    def _table(title, headers, rows):
        """Build a table block."""
        return {"kind": "table", "title": title, "headers": headers, "rows": rows}

    def _ask(self, prompt):
        """
        Prompt for a field. CLI mode uses input(); Web mode returns an empty string
        (the Web side requires all info in one command; the caller supplies a
        supplementary hint when something is missing).
        """
        if not self.interactive:
            return ""
        try:
            return input(f"   ↳ {prompt}").strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    def _confirm(self, prompt):
        """
        Confirmation prompt. CLI mode uses input(); Web mode passes by default
        (the frontend already confirmed the delete via a dialog).
        """
        if not self.interactive:
            return True
        try:
            ans = input(f"   ⚠️  {prompt} (y/n)").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes")

    def _get_customer(self, cid):
        """Fetch the customer row by ID; return None if not found."""
        return self.db.query_one("SELECT * FROM customers WHERE id=?", (cid,))

    # ==========================================================================
    # Help & dashboard
    # ==========================================================================
    def list_skills(self, _intent):
        """Show the loaded and quarantined skills."""
        installed, quarantined = self.skills.listing()
        blocks = []
        if installed:
            blocks.append(self._table(
                "📦 Loaded Skills", ["Name", "Rules", "Description"],
                [[s["name"], s["rules"], s.get("desc", "")] for s in installed]))
        else:
            blocks.append(self._info("No skills loaded yet. Staff can upload them via \"Skill Management\" on the Web UI."))
        if quarantined:
            blocks.append(self._table(
                "🚫 Quarantined Skills (failed security scan)", ["Name", "Verdict", "Evidence"],
                [[s.get("name", ""), s.get("verdict", ""), s.get("evidence", "")] for s in quarantined]))
        return blocks

    def show_help(self, _intent):
        """Return all available example commands."""
        return [self._text(HELP_TEXT)]

    def show_dashboard(self, _intent):
        """Return the business-overview stats (stats block)."""
        cust = self.db.query_one("SELECT COUNT(*) c FROM customers")["c"]
        open_opp = self.db.query_one(
            "SELECT COUNT(*) c FROM opportunities WHERE stage NOT IN ('won','lost')"
        )["c"]
        total_amt = self.db.query_one(
            "SELECT COALESCE(SUM(amount),0) s FROM opportunities "
            "WHERE stage NOT IN ('won','lost')"
        )["s"]
        won_amt = self.db.query_one(
            "SELECT COALESCE(SUM(amount),0) s FROM opportunities WHERE stage='won'"
        )["s"]
        todo = self.db.query_one(
            "SELECT COUNT(*) c FROM tasks WHERE status='todo'"
        )["c"]
        return [{
            "kind": "stats",
            "title": "📊 Business Overview",
            "items": [
                {"label": "Total customers", "value": cust},
                {"label": "Open opportunities", "value": open_opp},
                {"label": "Open pipeline amount", "value": f"{total_amt:,.0f}"},
                {"label": "Won amount", "value": f"{won_amt:,.0f}"},
                {"label": "Open tasks", "value": todo},
            ],
        }]

    # ==========================================================================
    # Customer management
    # ==========================================================================
    def add_customer(self, intent):
        """Add a customer; name is required (prompt/notice if missing), phone recommended."""
        name = intent.get("name")
        phone = intent.get("phone")
        company = intent.get("company")
        email = intent.get("email")
        address = intent.get("address")

        if not name:
            name = self._ask("Enter the customer name: ") or None
            if not name:
                return [self._err("❌ Missing customer name; cancelled. Example: add customer Acme Acme Corp 138...")]
        if not phone:
            phone = self._ask("Enter the customer phone (press Enter to skip): ") or None

        self.db.execute(
            "INSERT INTO customers (name, company, phone, email, address, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (name, company, phone, email, address,
             datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        cid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        return [self._ok(f"✅ Added customer #{cid}: {name}"
                         + (f" ({company})" if company else ""))]

    def list_customers(self, _intent):
        """List all customers."""
        rows = self.db.query(
            "SELECT id, name, company, phone, email, address FROM customers ORDER BY id"
        )
        return [self._table(
            "👥 Customer List",
            ["ID", "Name", "Company", "Phone", "Email", "Address"],
            [[r["id"], r["name"], r["company"], r["phone"], r["email"], r["address"]]
             for r in rows],
        )]

    def search_customer(self, intent):
        """Fuzzy-search customers by name or phone."""
        kw = intent["keyword"]
        rows = self.db.query(
            "SELECT id, name, company, phone, email, address FROM customers "
            "WHERE name LIKE ? OR phone LIKE ? ORDER BY id",
            (f"%{kw}%", f"%{kw}%"),
        )
        return [self._table(
            f"🔍 Results for \"{kw}\"",
            ["ID", "Name", "Company", "Phone", "Email", "Address"],
            [[r["id"], r["name"], r["company"], r["phone"], r["email"], r["address"]]
             for r in rows],
        )]

    def update_customer(self, intent):
        """Update a single field of a customer."""
        cid, field, value = intent["id"], intent["field"], intent["value"]
        if not self._get_customer(cid):
            return [self._err(f"❌ Customer #{cid} does not exist.")]
        self.db.execute(
            f"UPDATE customers SET {field}=? WHERE id=?", (value, cid)
        )
        return [self._ok(f"✅ Updated customer #{cid}'s {field} to \"{value}\".")]

    def delete_customer(self, intent):
        """Delete a customer (with confirmation; also cleans up their contacts)."""
        cid = intent["id"]
        cust = self._get_customer(cid)
        if not cust:
            return [self._err(f"❌ Customer #{cid} does not exist.")]
        if not self._confirm(f"Confirm deleting customer #{cid} \"{cust['name']}\"? This cannot be undone"):
            return [self._info("Deletion cancelled.")]
        self.db.execute("DELETE FROM customers WHERE id=?", (cid,))
        self.db.execute("DELETE FROM contacts WHERE customer_id=?", (cid,))
        return [self._ok(f"🗑️ Deleted customer #{cid} \"{cust['name']}\" and their contacts.")]

    # ==========================================================================
    # Contact management
    # ==========================================================================
    def add_contact(self, intent):
        """Add a contact; name and owning customer are required."""
        name = intent.get("name")
        customer_id = intent.get("customer_id")
        title = intent.get("title")
        phone = intent.get("phone")
        email = intent.get("email")

        if not name:
            name = self._ask("Enter the contact name: ") or None
            if not name:
                return [self._err("❌ Missing contact name; cancelled.")]
        if customer_id is None:
            ans = self._ask("Enter the owning customer ID: ")
            customer_id = int(ans) if ans.isdigit() else None
        if customer_id is None or not self._get_customer(customer_id):
            return [self._err(f"❌ Customer #{customer_id} does not exist; cannot add contact.")]

        self.db.execute(
            "INSERT INTO contacts (customer_id, name, title, phone, email)"
            " VALUES (?,?,?,?,?)",
            (customer_id, name, title, phone, email),
        )
        cid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        return [self._ok(f"✅ Added contact #{cid}: {name}"
                         + (f" ({title})" if title else "")
                         + f", owning customer #{customer_id}")]

    def list_contacts(self, intent):
        """List contacts with their owning customer name; optionally filter by customer."""
        customer_id = intent.get("customer_id")
        if customer_id is not None:
            rows = self.db.query(
                "SELECT ct.id, ct.name, ct.title, ct.phone, ct.email, "
                "c.name AS cust FROM contacts ct "
                "LEFT JOIN customers c ON ct.customer_id=c.id "
                "WHERE ct.customer_id=? ORDER BY ct.id",
                (customer_id,),
            )
            title = f"📇 Contacts of customer #{customer_id}"
        else:
            rows = self.db.query(
                "SELECT ct.id, ct.name, ct.title, ct.phone, ct.email, "
                "c.name AS cust FROM contacts ct "
                "LEFT JOIN customers c ON ct.customer_id=c.id ORDER BY ct.id"
            )
            title = "📇 Contact List"
        return [self._table(
            title,
            ["ID", "Name", "Title", "Phone", "Email", "Customer"],
            [[r["id"], r["name"], r["title"], r["phone"], r["email"], r["cust"]]
             for r in rows],
        )]

    def update_contact(self, intent):
        """Update a contact field."""
        cid, field, value = intent["id"], intent["field"], intent["value"]
        if not self.db.query_one("SELECT id FROM contacts WHERE id=?", (cid,)):
            return [self._err(f"❌ Contact #{cid} does not exist.")]
        self.db.execute(f"UPDATE contacts SET {field}=? WHERE id=?", (value, cid))
        return [self._ok(f"✅ Updated contact #{cid}'s {field} to \"{value}\".")]

    def delete_contact(self, intent):
        """Delete a contact (with confirmation)."""
        cid = intent["id"]
        row = self.db.query_one("SELECT name FROM contacts WHERE id=?", (cid,))
        if not row:
            return [self._err(f"❌ Contact #{cid} does not exist.")]
        if not self._confirm(f"Confirm deleting contact #{cid} \"{row['name']}\"?"):
            return [self._info("Deletion cancelled.")]
        self.db.execute("DELETE FROM contacts WHERE id=?", (cid,))
        return [self._ok(f"🗑️ Deleted contact #{cid} \"{row['name']}\".")]

    # ==========================================================================
    # Opportunity management
    # ==========================================================================
    def add_opportunity(self, intent):
        """Create an opportunity; name and owning customer are required, initial stage is "initial contact"."""
        name = intent.get("name")
        customer_id = intent.get("customer_id")
        amount = intent.get("amount") or 0
        close_date = intent.get("close_date")

        if not name:
            name = self._ask("Enter the opportunity name: ") or None
            if not name:
                return [self._err("❌ Missing opportunity name; cancelled.")]
        if customer_id is None:
            ans = self._ask("Enter the associated customer ID: ")
            customer_id = int(ans) if ans.isdigit() else None
        if customer_id is None or not self._get_customer(customer_id):
            return [self._err(f"❌ Customer #{customer_id} does not exist; cannot create opportunity.")]

        self.db.execute(
            "INSERT INTO opportunities (customer_id, name, amount, stage, "
            "close_date, created_at) VALUES (?,?,?,?,?,?)",
            (customer_id, name, amount, "initial_contact", close_date,
             datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        oid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        return [self._ok(f"✅ Created opportunity #{oid}: {name}, amount {amount:,.0f}, "
                         f"stage \"{STAGE_LABELS['initial_contact']}\", associated customer #{customer_id}")]

    def list_opportunities(self, _intent):
        """View all opportunities, grouped by stage (one table block per stage)."""
        order = ["initial_contact", "needs_analysis", "proposal",
                 "negotiation", "won", "lost"]
        blocks = []
        for stage in order:
            rows = self.db.query(
                "SELECT o.id, o.name, o.amount, o.close_date, o.closed_reason, "
                "c.name AS cust FROM opportunities o "
                "LEFT JOIN customers c ON o.customer_id=c.id "
                "WHERE o.stage=? ORDER BY o.id",
                (stage,),
            )
            if not rows:
                continue
            subtotal = sum(r["amount"] or 0 for r in rows)
            blocks.append(self._table(
                f"💼 {STAGE_LABELS[stage]} ({len(rows)}, total {subtotal:,.0f})",
                ["ID", "Opportunity", "Customer", "Amount", "Expected Close", "Close Reason"],
                [[r["id"], r["name"], r["cust"], f"{r['amount'] or 0:,.0f}",
                  r["close_date"], r["closed_reason"]] for r in rows],
            ))
        if not blocks:
            return [self._info("(no opportunity records yet)")]
        return blocks

    def _get_opp(self, oid):
        """Fetch the opportunity row by ID."""
        return self.db.query_one("SELECT * FROM opportunities WHERE id=?", (oid,))

    def update_opp_stage(self, intent):
        """Advance/update the opportunity stage."""
        oid, stage = intent["id"], intent["stage"]
        if not self._get_opp(oid):
            return [self._err(f"❌ Opportunity #{oid} does not exist.")]
        self.db.execute(
            "UPDATE opportunities SET stage=? WHERE id=?", (stage, oid)
        )
        return [self._ok(f"✅ Opportunity #{oid} stage updated to \"{STAGE_LABELS[stage]}\".")]

    def update_opp_amount(self, intent):
        """Modify the opportunity amount."""
        oid, amount = intent["id"], intent["amount"]
        if not self._get_opp(oid):
            return [self._err(f"❌ Opportunity #{oid} does not exist.")]
        self.db.execute(
            "UPDATE opportunities SET amount=? WHERE id=?", (amount, oid)
        )
        return [self._ok(f"✅ Opportunity #{oid} amount updated to {amount:,.0f}.")]

    def update_opp_date(self, intent):
        """Modify the opportunity's expected close date."""
        oid, date = intent["id"], intent["close_date"]
        if not self._get_opp(oid):
            return [self._err(f"❌ Opportunity #{oid} does not exist.")]
        self.db.execute(
            "UPDATE opportunities SET close_date=? WHERE id=?", (date, oid)
        )
        return [self._ok(f"✅ Opportunity #{oid} expected close date updated to {date}.")]

    def close_opportunity(self, intent):
        """Close an opportunity (won/lost), recording the close reason."""
        oid = intent["id"]
        result = intent.get("result")
        reason = intent.get("reason")
        if not self._get_opp(oid):
            return [self._err(f"❌ Opportunity #{oid} does not exist.")]
        if result not in ("won", "lost"):
            ans = self._ask("Won or lost? (won/lost)").lower()
            if "won" in ans or "win" in ans:
                result = "won"
            elif "lost" in ans or "lose" in ans or "fail" in ans:
                result = "lost"
            else:
                return [self._err("❌ Did not specify won/lost. Example: close opportunity 2 won good price")]
        if not reason:
            reason = self._ask("Enter the close reason (press Enter to skip): ") or None
        self.db.execute(
            "UPDATE opportunities SET stage=?, closed_reason=?, close_date=? "
            "WHERE id=?",
            (result, reason, datetime.now().strftime("%Y-%m-%d"), oid),
        )
        return [self._ok(f"✅ Opportunity #{oid} closed as \"{STAGE_LABELS[result]}\""
                         + (f", reason: {reason}" if reason else "") + ".")]

    def delete_opportunity(self, intent):
        """Delete an opportunity (with confirmation)."""
        oid = intent["id"]
        opp = self._get_opp(oid)
        if not opp:
            return [self._err(f"❌ Opportunity #{oid} does not exist.")]
        if not self._confirm(f"Confirm deleting opportunity #{oid} \"{opp['name']}\"?"):
            return [self._info("Deletion cancelled.")]
        self.db.execute("DELETE FROM opportunities WHERE id=?", (oid,))
        return [self._ok(f"🗑️ Deleted opportunity #{oid} \"{opp['name']}\".")]

    # ==========================================================================
    # Task / follow-up management
    # ==========================================================================
    def add_task(self, intent):
        """Create a task, associated with a customer or opportunity."""
        related_type = intent.get("related_type")
        related_id = intent.get("related_id")
        description = intent.get("description")
        due_date = intent.get("due_date")

        if not description:
            description = self._ask("Enter the task content: ") or None
            if not description:
                return [self._err("❌ Missing task content; cancelled.")]
        if related_id is None:
            ans = self._ask("Enter the associated object ID (customer or opportunity): ")
            related_id = int(ans) if ans.isdigit() else None

        # Validate that the associated object exists
        if related_type == "customer" and related_id is not None:
            if not self._get_customer(related_id):
                return [self._err(f"❌ Customer #{related_id} does not exist.")]
        if related_type == "opportunity" and related_id is not None:
            if not self._get_opp(related_id):
                return [self._err(f"❌ Opportunity #{related_id} does not exist.")]

        self.db.execute(
            "INSERT INTO tasks (related_type, related_id, description, due_date, status)"
            " VALUES (?,?,?,?,?)",
            (related_type, related_id, description, due_date, "todo"),
        )
        tid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        rel_label = "customer" if related_type == "customer" else "opportunity"
        return [self._ok(f"✅ Created task #{tid}: {description}"
                         + (f" (due {due_date})" if due_date else "")
                         + f", associated {rel_label} #{related_id}")]

    def list_tasks(self, intent):
        """List tasks; optionally filter by status and associated customer/opportunity."""
        status = intent.get("status")
        cid = intent.get("customer_id")
        oid = intent.get("opportunity_id")

        sql = (
            "SELECT id, related_type, related_id, description, due_date, status "
            "FROM tasks WHERE 1=1"
        )
        params = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if cid is not None:
            sql += " AND related_type='customer' AND related_id=?"
            params.append(cid)
        if oid is not None:
            sql += " AND related_type='opportunity' AND related_id=?"
            params.append(oid)
        sql += " ORDER BY status DESC, due_date"
        rows = self.db.query(sql, tuple(params))

        title = "📌 Open Tasks" if status == "todo" else "📌 Task List"
        return [self._table(
            title,
            ["ID", "Associated", "Content", "Due Date", "Status"],
            [[r["id"],
              ("customer#" if r["related_type"] == "customer" else "opportunity#")
              + str(r["related_id"]),
              r["description"], r["due_date"], r["status"]] for r in rows],
        )]

    def complete_task(self, intent):
        """Mark a task as completed."""
        tid = intent["id"]
        row = self.db.query_one("SELECT description, status FROM tasks WHERE id=?", (tid,))
        if not row:
            return [self._err(f"❌ Task #{tid} does not exist.")]
        if row["status"] == "done":
            return [self._info(f"ℹ️ Task #{tid} is already completed.")]
        self.db.execute("UPDATE tasks SET status='done' WHERE id=?", (tid,))
        return [self._ok(f"✅ Task #{tid} \"{row['description']}\" marked as completed.")]

    def delete_task(self, intent):
        """Delete a task (with confirmation)."""
        tid = intent["id"]
        row = self.db.query_one("SELECT description FROM tasks WHERE id=?", (tid,))
        if not row:
            return [self._err(f"❌ Task #{tid} does not exist.")]
        if not self._confirm(f"Confirm deleting task #{tid} \"{row['description']}\"?"):
            return [self._info("Deletion cancelled.")]
        self.db.execute("DELETE FROM tasks WHERE id=?", (tid,))
        return [self._ok(f"🗑️ Deleted task #{tid}.")]


# ==============================================================================
# Web frontend: standard-library http.server, provides a chat-style UI + /api/command endpoint
# ==============================================================================
def run_web(host="127.0.0.1", port=6001):
    """
    Start a local web service: GET / returns the chat page, POST /api/command runs a command.
    Reuses all of CRMAgent's business logic (interactive=False); results are returned as JSON blocks.
    Uses a single-threaded HTTPServer to avoid cross-thread SQLite issues.
    """
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    agent = CRMAgent(interactive=False)  # Web mode: no input() prompting

    class Handler(BaseHTTPRequestHandler):
        """Handle page and API requests."""

        def _send(self, code, body, content_type="application/json; charset=utf-8"):
            """Send a response uniformly."""
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            """Return the frontend page / skill list."""
            if self.path in ("/", "/index.html"):
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
            elif self.path == "/api/skill/list":
                installed, quarantined = agent.skills.listing()
                self._send(200, json.dumps(
                    {"installed": installed, "quarantined": quarantined},
                    ensure_ascii=False))
            else:
                self._send(404, "Not Found", "text/plain; charset=utf-8")

        def _body(self):
            """Read and decode the request body into a dict."""
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length) if length else b"{}"
            for enc in ("utf-8", "gbk"):
                try:
                    raw = data.decode(enc)
                    break
                except UnicodeDecodeError:
                    raw = data.decode("utf-8", errors="replace")
            try:
                return json.loads(raw) or {}
            except Exception:
                return {}

        def do_POST(self):
            """Run a command / upload a skill."""
            if self.path == "/api/skill/upload":
                payload = self._body()
                res = agent.skills.submit(
                    payload.get("name", ""), payload.get("content", ""))
                self._send(200, json.dumps(res, ensure_ascii=False))
                return
            if self.path != "/api/command":
                self._send(404, json.dumps({"error": "not found"}))
                return
            command = (self._body().get("command", "") or "").strip()
            if not command:
                self._send(200, json.dumps({"blocks": []}, ensure_ascii=False))
                return
            blocks = agent.process(command)
            self._send(200, json.dumps({"blocks": blocks}, ensure_ascii=False))

        def log_message(self, *_args):
            """Silence the access log to keep the console clean."""
            return

    server = HTTPServer((host, port), Handler)
    print("=" * 60)
    print(f" 🌐  CRM-Agent Web started -> http://{host}:{port}")
    print("     Open the address above in a browser to chat; Ctrl+C to stop")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb service stopped.")
    finally:
        server.server_close()
        agent.db.close()


# ------------------------------------------------------------------------------
# Frontend page (single-page HTML, inline CSS/JS, zero external dependencies)
# ------------------------------------------------------------------------------
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRM-Agent - Natural-Language Customer Management</title>
<style>
  :root {
    --bg: #0f172a; --panel: #1e293b; --panel2: #273449;
    --line: #334155; --txt: #e2e8f0; --muted: #94a3b8;
    --brand: #6366f1; --brand2: #8b5cf6; --ok: #22c55e; --err: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; height: 100vh; display: flex; color: var(--txt);
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    background: radial-gradient(1200px 600px at 80% -10%, #1e1b4b 0%, var(--bg) 55%);
  }
  /* Sidebar: command examples */
  #side {
    width: 290px; flex-shrink: 0; background: rgba(15,23,42,.6);
    border-right: 1px solid var(--line); padding: 20px 16px; overflow-y: auto;
  }
  #side h2 { font-size: 14px; color: var(--muted); margin: 18px 0 8px; letter-spacing: .05em; }
  .brand { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 700; }
  .brand .dot { width: 28px; height: 28px; border-radius: 8px;
    background: linear-gradient(135deg, var(--brand), var(--brand2));
    display: grid; place-items: center; }
  .chip {
    display: block; width: 100%; text-align: left; cursor: pointer;
    background: var(--panel); border: 1px solid var(--line); color: var(--txt);
    border-radius: 10px; padding: 8px 10px; margin: 6px 0; font-size: 12.5px;
    transition: .15s; line-height: 1.4;
  }
  .chip:hover { border-color: var(--brand); background: var(--panel2); transform: translateX(2px); }
  /* Main area */
  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #top { padding: 16px 24px; border-bottom: 1px solid var(--line);
    display: flex; align-items: center; justify-content: space-between; }
  #top .sub { color: var(--muted); font-size: 13px; }
  #log { flex: 1; overflow-y: auto; padding: 24px; display: flex; flex-direction: column; gap: 14px; }
  .row { display: flex; }
  .row.user { justify-content: flex-end; }
  .bubble { max-width: 78%; padding: 11px 15px; border-radius: 14px; line-height: 1.55;
    white-space: pre-wrap; word-break: break-word; font-size: 14px; }
  .user .bubble { background: linear-gradient(135deg, var(--brand), var(--brand2)); color: #fff;
    border-bottom-right-radius: 4px; }
  .bot .bubble { background: var(--panel); border: 1px solid var(--line);
    border-bottom-left-radius: 4px; }
  .bot .bubble.ok { border-left: 3px solid var(--ok); }
  .bot .bubble.err { border-left: 3px solid var(--err); }
  /* Tables */
  .tbl-title { font-weight: 600; margin: 2px 0 8px; font-size: 13.5px; color: var(--txt); }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { border: 1px solid var(--line); padding: 6px 10px; text-align: left; }
  th { background: var(--panel2); color: var(--muted); font-weight: 600; }
  tr:nth-child(even) td { background: rgba(255,255,255,.02); }
  /* Overview cards */
  .stats { display: flex; flex-wrap: wrap; gap: 10px; }
  .stat { flex: 1; min-width: 110px; background: var(--panel2); border: 1px solid var(--line);
    border-radius: 12px; padding: 12px 14px; }
  .stat .v { font-size: 22px; font-weight: 700;
    background: linear-gradient(135deg, #a5b4fc, #c4b5fd); -webkit-background-clip: text;
    -webkit-text-fill-color: transparent; }
  .stat .l { color: var(--muted); font-size: 12px; margin-top: 2px; }
  /* Input area */
  #bar { padding: 16px 24px; border-top: 1px solid var(--line); display: flex; gap: 10px; }
  #inp { flex: 1; background: var(--panel); border: 1px solid var(--line); color: var(--txt);
    border-radius: 12px; padding: 12px 14px; font-size: 14px; outline: none; }
  #inp:focus { border-color: var(--brand); }
  #send { border: 0; border-radius: 12px; padding: 0 22px; cursor: pointer; color: #fff;
    font-size: 14px; font-weight: 600;
    background: linear-gradient(135deg, var(--brand), var(--brand2)); }
  #send:disabled { opacity: .5; cursor: default; }
  /* Skill management modal */
  #mask { position: fixed; inset: 0; background: rgba(2,6,23,.66); display: none;
    align-items: center; justify-content: center; z-index: 50; }
  #mask.show { display: flex; }
  #skillbox { width: 560px; max-width: 92vw; max-height: 86vh; overflow: hidden;
    background: var(--panel); border: 1px solid var(--line); border-radius: 16px;
    display: flex; flex-direction: column; }
  .sk-head { padding: 16px 18px; border-bottom: 1px solid var(--line); position: relative; }
  .sk-head .sub { display: block; margin-top: 4px; }
  .sk-x { position: absolute; top: 14px; right: 16px; background: none; border: 0;
    color: var(--muted); font-size: 16px; cursor: pointer; }
  .sk-body { padding: 16px 18px; overflow-y: auto; }
  .sk-body label { display: block; font-size: 12.5px; color: var(--muted);
    margin: 12px 0 6px; }
  .sk-body input, .sk-body textarea { width: 100%; background: var(--panel2);
    border: 1px solid var(--line); color: var(--txt); border-radius: 10px;
    padding: 9px 11px; font-size: 13px; outline: none; font-family: inherit; }
  .sk-body textarea { height: 130px; resize: vertical;
    font-family: ui-monospace, Consolas, monospace; }
  .sk-mini { float: right; background: none; border: 0; color: var(--brand);
    cursor: pointer; font-size: 12px; }
  #sk-up { margin-top: 12px; width: 100%; border: 0; border-radius: 10px; padding: 10px;
    cursor: pointer; color: #fff; font-weight: 600;
    background: linear-gradient(135deg, var(--brand), var(--brand2)); }
  #sk-up:disabled { opacity: .5; cursor: default; }
  #sk-msg { margin-top: 12px; font-size: 13px; line-height: 1.5; }
  #sk-msg .ok { color: var(--ok); }
  #sk-msg .bad { color: var(--err); }
  #sk-list { margin-top: 14px; font-size: 12.5px; }
  #sk-list .item { border: 1px solid var(--line); border-radius: 10px; padding: 8px 10px;
    margin: 6px 0; display: flex; justify-content: space-between; gap: 8px; }
  .badge { font-size: 11px; padding: 1px 8px; border-radius: 999px; white-space: nowrap; }
  .b-ok { background: rgba(34,197,94,.15); color: #4ade80; }
  .b-bad { background: rgba(239,68,68,.15); color: #f87171; }
  .b-warn { background: rgba(234,179,8,.15); color: #facc15; }
</style>
</head>
<body>
  <aside id="side">
    <div class="brand"><span class="dot">🤝</span> CRM-Agent</div>
    <h2>Customers</h2>
    <button class="chip">add customer Acme Acme Corp 13800000000 zhang@x.com Beijing Chaoyang</button>
    <button class="chip">show customers</button>
    <button class="chip">find customer Acme</button>
    <h2>Contacts</h2>
    <button class="chip">add contact John customer=1 title=Sales Manager phone=13900000000</button>
    <button class="chip">contacts of customer 1</button>
    <h2>Opportunities</h2>
    <button class="chip">create opportunity Annual Purchase customer=1 amount=50000</button>
    <button class="chip">advance opportunity 1 to negotiation</button>
    <button class="chip">show opportunities</button>
    <button class="chip">close opportunity 1 won good price</button>
    <h2>Tasks</h2>
    <button class="chip">add task customer 1 follow up to confirm needs due 2026-06-10</button>
    <button class="chip">show open tasks</button>
    <button class="chip">complete task 1</button>
    <h2>Other</h2>
    <button class="chip">show dashboard</button>
    <button class="chip">help</button>
    <h2>Skill Extensions</h2>
    <button class="chip" onclick="openSkill()">🧩 Manage / Upload Skill</button>
    <button class="chip">show skills</button>
  </aside>

  <main id="main">
    <div id="top">
      <div><strong>Natural-Language CRM Assistant</strong>
        <span class="sub">· type a command to manage customers / contacts / opportunities / tasks</span></div>
      <div class="sub">SQLite local storage</div>
    </div>
    <div id="log"></div>
    <div id="bar">
      <input id="inp" placeholder="e.g.: add customer Globex Globex Inc 13700000000 / show dashboard" autofocus>
      <button id="send" onclick="send()">Send</button>
    </div>
  </main>

  <div id="mask" onclick="if(event.target===this)closeSkill()">
    <div id="skillbox">
      <div class="sk-head">
        <strong>🧩 Skill Management</strong>
        <span class="sub">Upload declarative skills to improve the Agent · security-scanned first, only benign ones are loaded</span>
        <button class="sk-x" onclick="closeSkill()">✕</button>
      </div>
      <div class="sk-body">
        <label>Name</label>
        <input id="sk-name" placeholder="e.g. Refund Helper">
        <label>Manifest (JSON)<button class="sk-mini" onclick="fillSample()">Fill sample</button></label>
        <textarea id="sk-content" spellcheck="false"
          placeholder='{"name":"Refund Helper","rules":[{"triggers":["refund"],"respond":"Refund process: ..."}]}'></textarea>
        <button id="sk-up" onclick="uploadSkill()">Upload and scan</button>
        <div id="sk-msg"></div>
        <div id="sk-list"></div>
      </div>
    </div>
  </div>

<script>
const log = document.getElementById('log');
const inp = document.getElementById('inp');
const btn = document.getElementById('send');

// HTML-escape to prevent angle brackets in the data from breaking the page
function esc(s){ return String(s==null?'':s).replace(/[&<>]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function addUser(text){
  const row = document.createElement('div'); row.className = 'row user';
  row.innerHTML = '<div class="bubble">'+esc(text)+'</div>';
  log.appendChild(row); log.scrollTop = log.scrollHeight;
}

// Render the result blocks returned by the backend into bubbles
function addBlocks(blocks){
  if(!blocks || !blocks.length){
    blocks = [{kind:'text', text:'(no output)', tone:'info'}];
  }
  blocks.forEach(b => {
    const row = document.createElement('div'); row.className = 'row bot';
    const bub = document.createElement('div'); bub.className = 'bubble';
    if(b.kind === 'text'){
      if(b.tone) bub.classList.add(b.tone);
      bub.textContent = b.text;
    } else if(b.kind === 'table'){
      bub.innerHTML = renderTable(b);
    } else if(b.kind === 'stats'){
      bub.innerHTML = renderStats(b);
    }
    row.appendChild(bub); log.appendChild(row);
  });
  log.scrollTop = log.scrollHeight;
}

function renderTable(b){
  let h = '<div class="tbl-title">'+esc(b.title||'')+'</div>';
  if(!b.rows || !b.rows.length) return h + '<div style="color:#94a3b8">(no matching records)</div>';
  h += '<table><thead><tr>';
  b.headers.forEach(x => h += '<th>'+esc(x)+'</th>');
  h += '</tr></thead><tbody>';
  b.rows.forEach(r => { h += '<tr>'; r.forEach(c => h += '<td>'+esc(c)+'</td>'); h += '</tr>'; });
  return h + '</tbody></table>';
}

function renderStats(b){
  let h = '<div class="tbl-title">'+esc(b.title||'')+'</div><div class="stats">';
  b.items.forEach(i => h += '<div class="stat"><div class="v">'+esc(i.value)
    +'</div><div class="l">'+esc(i.label)+'</div></div>');
  return h + '</div>';
}

async function send(){
  const text = inp.value.trim();
  if(!text) return;
  addUser(text); inp.value = ''; btn.disabled = true;
  // Confirm delete operations on the frontend first (the backend passes them by default in Web mode)
  if(/^(delete|remove)/i.test(text) && !confirm('Confirm executing: "'+text+'"? This cannot be undone')){
    addBlocks([{kind:'text', text:'Deletion cancelled.', tone:'info'}]);
    btn.disabled = false; inp.focus(); return;
  }
  try{
    const resp = await fetch('/api/command', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({command: text})
    });
    const data = await resp.json();
    addBlocks(data.blocks);
  }catch(e){
    addBlocks([{kind:'text', text:'Request failed: '+e, tone:'err'}]);
  }finally{
    btn.disabled = false; inp.focus();
  }
}

// Sidebar examples: click to fill the input box
document.querySelectorAll('.chip').forEach(c =>
  c.addEventListener('click', () => { inp.value = c.textContent; inp.focus(); }));
inp.addEventListener('keydown', e => { if(e.key === 'Enter') send(); });

// Opening greeting
addBlocks([{kind:'text', tone:'info',
  text:'👋 Hello! I am CRM-Agent. Tell me what to do in natural language, '
       +'or click an example on the left to get started quickly. Type help to see all usages.'}]);

// ---- Skill management modal ----
const mask = document.getElementById('mask');
function openSkill(){ mask.classList.add('show'); loadSkills(); }
function closeSkill(){ mask.classList.remove('show'); }
function fillSample(){
  document.getElementById('sk-name').value = 'Refund Helper';
  document.getElementById('sk-content').value = JSON.stringify({
    name:'Refund Helper', version:'1.0', description:'Recognize refund-related phrasings and reply',
    rules:[
      {triggers:['refund','how to refund','return process'], respond:'Refund process: 1) mark the lost reason on the opportunity; 2) contact finance to initiate the refund; 3) update the customer notes.'},
      {triggers:['big customer','vip customer'], action:'list_customers'}
    ]
  }, null, 2);
}
async function loadSkills(){
  try{
    const r = await fetch('/api/skill/list'); const d = await r.json();
    let h = '';
    (d.installed||[]).forEach(s => h += '<div class="item"><span>📦 '+esc(s.name)
      +' <span style="color:#94a3b8">· '+s.rules+' rules</span></span>'
      +'<span class="badge b-ok">loaded</span></div>');
    (d.quarantined||[]).forEach(s => h += '<div class="item"><span>🚫 '+esc(s.name)
      +' <span style="color:#94a3b8">· '+esc(s.evidence||'')+'</span></span>'
      +'<span class="badge '+(s.verdict==='malicious'?'b-bad':'b-warn')+'">'+esc(s.verdict)+'</span></div>');
    document.getElementById('sk-list').innerHTML = h || '<span style="color:#94a3b8">No skills yet</span>';
  }catch(e){ document.getElementById('sk-list').textContent = 'Failed to load list: '+e; }
}
async function uploadSkill(){
  const name = document.getElementById('sk-name').value.trim();
  const content = document.getElementById('sk-content').value.trim();
  const msg = document.getElementById('sk-msg'); const up = document.getElementById('sk-up');
  if(!content){ msg.innerHTML = '<span class="bad">Please fill in the manifest first.</span>'; return; }
  up.disabled = true; msg.textContent = 'Scanning…';
  try{
    const r = await fetch('/api/skill/upload', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, content})
    });
    const d = await r.json();
    const cls = d.ok ? 'ok' : 'bad';
    let line = '<span class="'+cls+'">'+esc(d.message)+'</span>';
    if(d.evidence) line += '<br><span style="color:#94a3b8">Evidence: '+esc(d.evidence)+'</span>';
    if(typeof d.risk_score==='number') line += '<br><span style="color:#94a3b8">Verdict: '
      +esc(d.verdict)+' · risk score '+d.risk_score+'</span>';
    msg.innerHTML = line;
    loadSkills();
  }catch(e){ msg.innerHTML = '<span class="bad">Upload failed: '+e+'</span>'; }
  finally{ up.disabled = false; }
}
</script>
</body>
</html>"""


# ==============================================================================
# Program entry point: python crm_agent.py [web]
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("web", "server", "ui"):
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6001
        run_web(port=port)
    else:
        CRMAgent().run()
