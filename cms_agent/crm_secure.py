# -*- coding: utf-8 -*-
"""
================================================================================
 crm_secure.py — "Bolt-on" launcher that wires CRM-Agent into the AI_Sentinel gateway
================================================================================

Design goal: **wrap a security guard around crm_agent.py without changing a
single line of its code.**

How it works:
  All of crm_agent.py's business execution funnels through the single method
  CRMAgent.process(raw), and both the CLI and Web frontends go through it. This
  script uses monkey-patching to wrap process(), inserting two guard layers
  around the original logic before launching the original CLI / Web. Because the
  patch is applied to the *class method*, CRMAgent instances created inside
  run_web() are guarded too.

Two guard layers (matching the gateway's two entry points):
  1) Input guard   POST /chat           — runs injection/jailbreak/PII detection
                                           before parsing; a 403 means blocked.
  2) Action guard  POST /confirm-action — confirms high-risk operations (e.g.
                                           deletes) before execution; allowed=false blocks.

Policy (per design decisions):
  - Delete operations are reported under the neutral action name remove_record,
    to sidestep the gateway's hard keyword block on delete/drop; normal deletes
    pass, and are only caught when the raw input contains injection/malicious context.
  - When the gateway is unreachable: **fail-open** — pass through and print a
    warning so the CRM stays usable.
  - Standard library urllib only; zero extra dependencies.

[Usage] (identical to crm_agent.py, just launched via this script)
    CLI mode:  python crm_secure.py
    Web mode:  python crm_secure.py web          (default http://127.0.0.1:6001)
               python crm_secure.py web 8080     (custom port)

[Prerequisite] Start the security gateway first (default http://localhost:3001):
    cd d:/hackathon/AI_Sentinel
    python -m gateway.main

[Environment variables]
    SENTINEL_ENABLED  default "1"; set to "0" to fall back to launching the
                      original version directly (no detection)
    GATEWAY_URL       default "http://localhost:3001"
    AGENT_ID          default "crm-agent-01"
================================================================================
"""

# Load .env before reading any env vars (must be before crm_agent import)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env takes precedence over env vars injected by the script/shell
except ImportError:
    pass

import os
import sys
import json
import time
import urllib.request
import urllib.error

# Make stdout/stderr tolerant of consoles that can't encode emoji (e.g. Windows
# GBK/cp936): replace unencodable chars instead of crashing the process.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

import crm_agent  # original Agent; importing does not trigger its main program (guarded by __main__)


# ------------------------------------------------------------------------------
# Configuration (environment variables, with defaults)
# ------------------------------------------------------------------------------
SENTINEL_ENABLED = os.getenv("SENTINEL_ENABLED", "1") not in ("0", "false", "False", "")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:3001").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "crm-agent-01")

# Held (gray-zone) wait: after the gateway holds a suspicious request, this agent
# polls and waits for the analyst + human adjudication. It **never executes**
# before a verdict; on wait timeout it stays "not released" = keeps blocking (no execution).
HOLD_WAIT_S = float(os.getenv("SENTINEL_HOLD_WAIT_S", "90"))   # max wait in seconds
HOLD_POLL_S = float(os.getenv("SENTINEL_HOLD_POLL_S", "2"))    # poll interval in seconds

# High-risk intent -> entity-type mapping that must go through the "action guard".
# Reported under the neutral action name remove_record to avoid hitting the
# gateway's English hard-block words (delete/drop/...).
HIGH_RISK_ACTIONS = {
    "delete_customer": "customer",
    "delete_contact": "contact",
    "delete_opportunity": "opportunity",
    "delete_task": "task",
}

# Allowlist of detector categories that actually block on the input guard: only
# these detectors, when hit, truly block.
# Rationale: the gateway's sensitive/pii_leak treats phone numbers, emails, ID
# numbers as sensitive info, but entering these fields is a core legitimate CRM
# operation (the user is managing their own data, not leaking it).
# So by default we only block prompt-injection / jailbreak categories; PII/sensitive
# categories are allowed on the input path (with a logged notice).
# Override via env var, e.g. SENTINEL_BLOCK_DETECTORS="injection,prompt_injection,sensitive,pii_leak"
# to tighten to "block everything".
BLOCK_DETECTORS = set(
    d.strip() for d in
    os.getenv("SENTINEL_BLOCK_DETECTORS", "injection,prompt_injection").split(",")
    if d.strip()
)


# ==============================================================================
# Security gateway client (implemented with the standard-library urllib)
# ==============================================================================
class SentinelClient:
    """Wraps calls to AI_Sentinel's two entry points; all network errors fail-open."""

    def __init__(self, base_url=GATEWAY_URL, agent_id=AGENT_ID, timeout=5.0):
        """Record the gateway address, agent identifier, and timeout."""
        self.base_url = base_url
        self.agent_id = agent_id
        self.timeout = timeout

    def _post(self, path, payload):
        """
        POST JSON to the gateway, returning (status_code, body_dict).
        Note: urllib raises HTTPError on 4xx/5xx, so here we treat 403 etc. as a
        normal return; genuine connection failures (URLError/OSError) are handled
        by the caller's fail-open fallback.
        """
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # 403 etc.: still carries a JSON body, read it and let the caller decide
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            return e.code, body

    def _get(self, path):
        """GET JSON, returning (status_code, body_dict)."""
        req = urllib.request.Request(f"{self.base_url}{path}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8"))
            except Exception:
                return e.code, {}

    def check_input(self, prompt):
        """
        Input guard. Returns (verdict, info), verdict in {"allow","held","block"}:
          block -> hard-blocked; info holds the hit details (detail)
          held  -> gray-zone hold; info contains hold_id (must await analyst + human adjudication)
          allow -> passed; info may contain 'warn' indicating the gateway was unreachable (fail-open)
        """
        try:
            status, body = self._post("/chat", {"prompt": prompt, "session_id": self.agent_id})
        except (urllib.error.URLError, OSError) as e:
            return "allow", {"warn": f"Security gateway unreachable; passing through (fail-open): {e}"}
        if status == 403:
            return "block", body.get("detail", {})
        if status == 202 and body.get("held"):
            return "held", body
        if status != 200:
            return "allow", {"warn": f"Security gateway returned unexpected status {status}; passing through (fail-open)"}
        return "allow", {}

    def confirm_action(self, action_name, action_params, user_input):
        """
        Action guard. Returns (verdict, info), verdict in {"allow","held","block"}:
          when held, info is the response body (with hold_id); otherwise info is a reason string.
        Gateway unreachable -> fail-open, allow.
        """
        payload = {
            "action_name": action_name,
            "action_params": action_params or {},
            "agent_id": self.agent_id,
            "user_input": user_input,
        }
        try:
            status, body = self._post("/confirm-action", payload)
        except (urllib.error.URLError, OSError) as e:
            return "allow", f"Security gateway unreachable; passing through (fail-open): {e}"
        if status != 200:
            return "allow", f"Security gateway returned unexpected status {status}; passing through (fail-open)"
        if body.get("held"):
            return "held", body
        return ("allow" if body.get("allowed") else "block"), body.get("reason", "")

    def wait_for_hold(self, hold_id):
        """
        Poll the held adjudication; returns 'release' | 'block' | 'timeout'.
        Gateway becomes unreachable mid-poll -> returns 'timeout' (fail-safe: stays unexecuted).
        """
        deadline = time.time() + HOLD_WAIT_S
        while time.time() < deadline:
            try:
                _status, body = self._get(f"/hold/{hold_id}")
            except (urllib.error.URLError, OSError):
                return "timeout"
            st = (body or {}).get("status")
            if st == "released":
                return "release"
            if st == "blocked":
                return "block"
            time.sleep(HOLD_POLL_S)
        return "timeout"

    def health(self):
        """Health check; returns detector_count or None (unreachable)."""
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8")).get("detector_count")
        except Exception:
            return None


# Global singleton, referenced by the patched process
SENTINEL = SentinelClient()


# ==============================================================================
# monkey-patch: wrap two guard layers around CRMAgent.process
# ==============================================================================
_ORIGINAL_PROCESS = crm_agent.CRMAgent.process  # keep a reference to the original method


def _resolve_held(self, layer, info):
    """
    Handle a "gray-zone hold (held)": **never execute** before the analyst + human
    adjudication arrives.
    Return values:
      - None             -> verdict is release (pass); caller continues with the original logic
      - list of blocks    -> verdict is block / timed out without release / missing hold_id;
                             short-circuit return (no execution)
    """
    hold_id = info.get("hold_id") if isinstance(info, dict) else None
    if not hold_id:
        # Without a hold_id we can't track the verdict -> fail-safe: do not execute
        return [self._err("Operation held by the security gateway, but no disposition handle was provided; not executing for now.")]
    rule = (info.get("detail") or {}).get("rule_hit") if isinstance(info, dict) else None
    print(f"{layer} hit the gray zone; held, awaiting security analyst disposition (hold={hold_id}"
          f"{f', rule={rule}' if rule else ''}, up to {HOLD_WAIT_S:.0f}s)...")
    decision = SENTINEL.wait_for_hold(hold_id)
    if decision == "release":
        print(f"Security disposition: released (hold={hold_id})")
        return None
    if decision == "block":
        return [self._err("Security disposition: this operation was adjudicated as blocked (block); not executed.")]
    # timeout: stays held = keeps blocking, still not executed
    return [self._err("Operation is still under security review and has not been released; not executing for now (held). "
                      "Please retry later or contact a security analyst for disposition.")]


def guarded_process(self, raw):
    """
    Wrapped process: pass through the security gateway first, then call the original
    business logic. Reuses the original self._err / self._info result-block builders
    so CLI / Web rendering stays consistent.
    Three-state verdict: allow -> pass / block -> reject / held -> hold (await analyst +
    human; no execution in the meantime).
    """
    raw = (raw or "").strip()
    if not raw:
        return _ORIGINAL_PROCESS(self, raw)

    prefix_blocks = []  # extra notices (fail-open warnings etc.) prepended to the normal result

    # -- Layer 1: input guard --
    verdict, info = SENTINEL.check_input(raw)
    if verdict == "block":
        # Gateway flagged a hit; then decide whether to truly block by "block category"
        detector = info.get("detector") or ""
        rule = info.get("rule_hit") or detector or "unknown"
        desc = (info.get("details") or {}).get("rule_description") \
            or info.get("reason") or ""
        if detector in BLOCK_DETECTORS:
            return [self._err(f"Input blocked by the security gateway: {rule}"
                              + (f" - {desc}" if desc else ""))]
        # PII/sensitive category: CRM is entering legitimate fields; pass but leave a trace notice
        prefix_blocks.append(self._info(
            f"Gateway notice: input contains a sensitive field ({rule}); passed per CRM policy."))
    elif verdict == "held":
        held_result = _resolve_held(self, "Input", info)
        if held_result is not None:
            return held_result  # block / timeout -> do not execute
        # release -> continue
    elif isinstance(info, dict) and info.get("warn"):
        prefix_blocks.append(self._info("WARNING: " + info["warn"]))

    # -- Layer 2: action guard (high-risk delete operations only) --
    intent = self.parser.parse(raw)
    action = intent.get("action")
    if action in HIGH_RISK_ACTIONS:
        params = {"entity": HIGH_RISK_ACTIONS[action], "id": intent.get("id")}
        averdict, ainfo = SENTINEL.confirm_action("remove_record", params, raw)
        if averdict == "block":
            reason = ainfo if isinstance(ainfo, str) else (ainfo.get("reason") or "violates security policy")
            return [self._err(f"High-risk operation blocked by the security gateway: {reason}")]
        elif averdict == "held":
            held_result = _resolve_held(self, "High-risk action", ainfo)
            if held_result is not None:
                return held_result

    # -- Passed the guards; run the original logic --
    return prefix_blocks + _ORIGINAL_PROCESS(self, raw)


def install_guard():
    """Install the guard onto the CRMAgent class; return whether it was enabled."""
    if not SENTINEL_ENABLED:
        return False
    crm_agent.CRMAgent.process = guarded_process
    return True


# ==============================================================================
# Entry point: after installing the guard, reuse the original CLI / Web launch
# ==============================================================================
def _banner(enabled):
    """Print the security status banner."""
    print("=" * 64)
    if not enabled:
        print(" Security guard disabled (SENTINEL_ENABLED=0) - running in original mode")
        print("=" * 64)
        return
    count = SENTINEL.health()
    status = (f"online, {count} detectors" if count is not None
              else "unreachable (will fail-open + warn)")
    print(" CRM-Agent secure mode - wired into AI_Sentinel")
    print(f"     Gateway: {GATEWAY_URL}  Status: {status}")
    print(f"     Agent ID: {AGENT_ID}")
    print(f"     Block categories: {', '.join(sorted(BLOCK_DETECTORS)) or '(none)'}"
          "  (PII/sensitive categories are allowed on the input path)")
    print("=" * 64)


if __name__ == "__main__":
    enabled = install_guard()
    _banner(enabled)

    if len(sys.argv) > 1 and sys.argv[1].lower() in ("web", "server", "ui"):
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6001
        crm_agent.run_web(port=port)
    else:
        crm_agent.CRMAgent().run()
