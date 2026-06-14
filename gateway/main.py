# -*- coding: utf-8 -*-
"""
AI_Sentinel Gateway Entry
=========================
A FastAPI-based security gateway that intercepts user input and high-risk
Agent actions flowing through the system.

Core capabilities:
1. POST /chat            -- User input detection entry; runs all middleware detectors
2. POST /confirm-action  -- High-risk action confirmation entry for the victim Agent (reserved)
3. Auto-loads every detect(prompt:str)->dict function under middlewares/
4. If any detector returns is_malicious=True, the request is blocked with 403 + details
5. Structured (JSON) logging for downstream auditing and alerting
"""

# Load .env before any other imports (env vars must be set before modules are imported)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env takes precedence over env vars injected by the script/shell
except ImportError:
    pass

import os
import re
import sys
import json
import time
import uuid
import asyncio
import logging
import importlib
import pkgutil
from typing import Callable, Dict, List, Any, Optional

# Make stdout/stderr tolerant of consoles that can't encode emoji (e.g. Windows
# GBK/cp936): replace unencodable chars instead of crashing the process.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Async Splunk HEC sender (global singleton) and its event model.
# Dual import so the app runs as both `gateway.main:app` (from repo root)
# and `main:app` (from inside the gateway/ dir).
try:
    from gateway.mcp_sender import sender, sink, SecurityEvent
    from gateway.preprocess import expand as expand_input
except ImportError:  # pragma: no cover - launched from inside gateway/
    from mcp_sender import sender, sink, SecurityEvent
    from preprocess import expand as expand_input

# ---------------------------------------------------------------------------
# 1. Structured logging configuration
# ---------------------------------------------------------------------------


class JsonLogFormatter(logging.Formatter):
    """Serialize each log record into a single-line JSON for log collectors (e.g. ELK / Loki)."""

    def format(self, record: logging.LogRecord) -> str:
        # Base fields
        log_entry: Dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Pass through structured business fields injected via extra={"event": {...}}
        if hasattr(record, "event"):
            log_entry["event"] = record.event  # type: ignore[attr-defined]
        # Exception stack trace
        if record.exc_info:
            log_entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def _build_logger() -> logging.Logger:
    """Build and return the global logger that emits JSON to stdout."""
    logger = logging.getLogger("ai_sentinel.gateway")
    logger.setLevel(logging.INFO)
    # Avoid adding duplicate handlers under scenarios like uvicorn --reload
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


log = _build_logger()


# ---------------------------------------------------------------------------
# 2. Auto-loading of middleware detectors
# ---------------------------------------------------------------------------

# Registered detectors: [(detector_name, detect_callable), ...]
DETECTORS: List[tuple] = []


def load_detectors() -> List[tuple]:
    """
    Scan the gateway/middlewares package and auto-load every detection
    function of the form detect(prompt: str) -> dict.

    Convention:
      - Each middleware module defines a top-level callable named `detect`;
      - detect takes the user input string and returns a dict containing an is_malicious field.

    Returns: [(detector_name, detect_callable), ...]
    """
    detectors: List[tuple] = []

    # Lazy import so a missing package does not break loading of the main module
    try:
        from gateway import middlewares  # type: ignore
    except Exception:  # pragma: no cover - compatibility when run directly as a script
        import middlewares  # type: ignore

    for module_info in pkgutil.iter_modules(middlewares.__path__):
        module_name = module_info.name
        # Skip private modules (leading underscore)
        if module_name.startswith("_"):
            continue
        full_name = f"{middlewares.__name__}.{module_name}"
        try:
            module = importlib.import_module(full_name)
        except Exception as exc:
            log.error(
                "Failed to load middleware",
                extra={"event": {"module": full_name, "error": str(exc)}},
            )
            continue

        # Legacy hard-coded detectors replaced by the rule store are marked
        # SUPERSEDED=True; skip auto-loading them.
        if getattr(module, "SUPERSEDED", False):
            continue

        # Modules marked MANUAL=True (e.g. llm_semantic) are not part of the
        # unconditional detection chain; the tiered orchestrator
        # (run_detectors -> semantic_adjudicate) invokes them explicitly on demand.
        if getattr(module, "MANUAL", False):
            continue

        detect_fn: Optional[Callable[[str], Dict[str, Any]]] = getattr(
            module, "detect", None
        )
        if callable(detect_fn):
            detectors.append((module_name, detect_fn))
            log.info(
                "Registered detector",
                extra={"event": {"detector": module_name, "module": full_name}},
            )
        else:
            log.warning(
                "Middleware has no detect function, skipped",
                extra={"event": {"module": full_name}},
            )

    return detectors


def run_detectors(prompt: str, request_id: str) -> Optional[Dict[str, Any]]:
    """
    Run all detectors in order.

    As soon as any detector returns is_malicious=True, classify the request as
    malicious and return that hit's details; return None if all pass.

    When an individual detector raises, follow a "fail-open" policy: log the
    error and continue (do not reject a legitimate user because a detector
    itself crashed). For "fail-closed", change this to block directly.
    """
    # De-obfuscate once so every detector sees zero-width / full-width /
    # letter-spacing / base64-url-html tricks undone (same view as /scan).
    scan_view = expand_input(prompt)
    for name, fn in DETECTORS:
        try:
            result = fn(scan_view) or {}
        except Exception as exc:
            log.error(
                "Detector raised an exception",
                extra={
                    "event": {
                        "request_id": request_id,
                        "detector": name,
                        "error": str(exc),
                    }
                },
            )
            continue

        if result.get("is_malicious"):
            # Fill in the detector name in the hit details
            hit = dict(result)
            hit.setdefault("detector", name)
            log.warning(
                "Malicious input detected, blocked",
                extra={"event": {"request_id": request_id, "hit": hit}},
            )
            return hit

    return None


# ---------------------------------------------------------------------------
# Tiered LLM semantic adjudication (second layer)
# ---------------------------------------------------------------------------
# Lazily imported so a missing/disabled semantic module never breaks the gateway.
try:
    from gateway.middlewares import llm_semantic
except Exception:  # pragma: no cover
    try:
        from middlewares import llm_semantic  # type: ignore
    except Exception:
        llm_semantic = None  # type: ignore


def semantic_adjudicate(
    prompt: str, rule_hit: Optional[Dict[str, Any]], request_id: str
) -> Optional[Dict[str, Any]]:
    """
    Second-layer semantic adjudication on top of the rule-layer result.
    Tiered to control latency/cost — the LLM is consulted ONLY when the
    rules are uncertain:
      1) rules already decisive (score >= block_threshold) -> skip LLM, keep hit;
      2) gray zone or clean -> ask Claude; escalate if it finds what rules missed;
      3) optional, flag-gated -> de-escalate a low-risk false positive.
    Fail-soft: any error / disabled / timeout keeps the rule-layer result.
    """
    if llm_semantic is None or not llm_semantic.is_enabled():
        return rule_hit

    pol = policy_store.get()
    block = int(pol.get("block_threshold", 70))
    rule_score = int((rule_hit or {}).get("risk_score", 0))

    # 1) Rules already decisive -> no need to pay the LLM latency.
    if rule_hit is not None and rule_score >= block:
        return rule_hit

    # 2) Gray zone / no hit: hand off to semantic adjudication (on the de-obfuscated view).
    try:
        verdict = llm_semantic.classify(expand_input(prompt), context={"rule_hit": rule_hit})
    except Exception as exc:  # belt-and-suspenders: classify is already fail-soft, this is a backstop
        log.warning("semantic_adjudicate raised",
                    extra={"event": {"request_id": request_id, "error": str(exc)}})
        return rule_hit
    if verdict is None:
        return rule_hit

    llm_score = int(verdict.get("risk_score", 0))

    # Escalate: the LLM found an attack the rule layer missed or underestimated.
    if verdict.get("is_malicious") and llm_score > rule_score:
        hit = dict(verdict)
        hit.setdefault("detector", "llm_semantic")
        log.warning(
            "Semantic adjudication escalated input",
            extra={"event": {"request_id": request_id, "rule_score": rule_score,
                             "llm_score": llm_score, "reason": verdict.get("reason", "")}},
        )
        return hit

    # 3) De-escalate (requires LLM_DETECT_ALLOW_DEESCALATE): clear a low-risk false positive.
    if (rule_hit is not None and not verdict.get("is_malicious")
            and llm_semantic.allow_deescalate()
            and rule_score < block
            and rule_hit.get("rule_hit") in llm_semantic.DEESCALATABLE
            and float(verdict.get("confidence", 0)) >= 0.8):
        log.info(
            "Semantic adjudication de-escalated false positive",
            extra={"event": {"request_id": request_id,
                             "rule_hit": rule_hit.get("rule_hit"),
                             "reason": verdict.get("reason", "")}},
        )
        return None

    return rule_hit


# ---------------------------------------------------------------------------
# High-risk action keywords
# ---------------------------------------------------------------------------
# Gateway identity & downstream LLM provider, used in emitted events.
GATEWAY_ID = os.getenv("GATEWAY_ID", "gateway-01")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

# Destructive verbs that should hard-block an Agent action outright.
HIGH_RISK_KEYWORDS: List[str] = [
    "delete", "drop", "truncate", "rm", "format", "destroy", "wipe",
    "shutdown", "reboot", "mkfs", "unlink", "rmdir", "del", "kill",
    "drop table", "drop database", "rm -rf",
]

# One pre-compiled, case-insensitive regex over all keywords. Boundaries use
# alphanumeric lookarounds (NOT \b) so snake_case action names like
# "delete_user" / "drop_table" are still caught (underscore acts as a separator).
_HIGH_RISK_RE: re.Pattern = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(k) for k in HIGH_RISK_KEYWORDS)
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def check_high_risk_keywords(text: str) -> Optional[Dict[str, Any]]:
    """
    Scan text for destructive keywords. A hit hard-blocks the action.
    Returns a detector-shaped dict, or None when clean.
    """
    match = _HIGH_RISK_RE.search(text or "")
    if not match:
        return None
    return {
        "is_malicious": True,
        "risk_score": 100,
        "rule_hit": "high_risk_action_keyword",
        "detector": "high_risk_keywords",
        "details": {
            "matched_string": match.group(0),
            "rule_description": "Destructive high-risk action keyword detected",
        },
    }


def mask_user_input(text: str, max_len: int = 500) -> str:
    """
    Lightweight desensitization for logging/SIEM -- redact obvious secrets
    (API keys, JWTs, emails, long digit runs) and cap the length.
    """
    if not text:
        return ""
    redacted = text
    redacted = re.sub(r"\bsk-[A-Za-z0-9_\-]{8,}\b", "sk-***REDACTED***", redacted)
    redacted = re.sub(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
                      "***JWT***", redacted)
    redacted = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "***EMAIL***", redacted)
    redacted = re.sub(r"\b\d{11,}\b", "***DIGITS***", redacted)
    if len(redacted) > max_len:
        redacted = redacted[:max_len] + "...(truncated)"
    return redacted


def emit_event_async(event: SecurityEvent) -> None:
    """
    Hand the event to the reliable delivery pipeline (in-memory queue + batching
    + retry + disk spool). Non-blocking, never slows down the request; spools to
    disk when Splunk is flaky and replays on recovery, so no data is lost.
    """
    sink.submit(event)


# ---------------------------------------------------------------------------
# 3. Request / response data models
# ---------------------------------------------------------------------------


class ChatRequest(BaseModel):
    """User chat request body."""

    prompt: str = Field(..., description="User input text")
    session_id: Optional[str] = Field(None, description="Session identifier, optional")


class ConfirmActionRequest(BaseModel):
    """High-risk action confirmation request body submitted by the victim Agent."""

    action_name: str = Field(..., description="Action to confirm, e.g. delete_user / transfer_funds")
    action_params: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    agent_id: str = Field(..., description="Calling Agent identifier")
    user_input: str = Field("", description="Original user input that triggered the action")
    context: Optional[Dict[str, Any]] = Field(None, description="Extra context, optional")


class SkillScanRequest(BaseModel):
    """A skill payload to scan."""

    skill_name: str = Field(..., description="Skill identifier")
    skill_content: str = Field(..., description="Skill body to inspect")


# Short blurb per rule, surfaced in scan findings.
_RULE_BLURB_ZH: Dict[str, str] = {
    "system_instruction_override": "Attempts to override or ignore prior system instructions",
    "jailbreak": "Jailbreak trigger detected (DAN / unrestricted persona)",
    "role_play": "Forces the model into a new role to bypass policy",
    "prompt_leak": "Attempts to extract the system prompt",
    "token_smuggling": "Smuggles hidden instructions via encoding / zero-width characters",
    "context_manipulation": "Injects forged role or conversation-template markers",
    "api_manipulation": "Tampers with model parameters, tools, or function calls",
    "indirect_injection": "Hidden instructions targeting an AI that reads external content",
    "multilingual": "Non-English (Chinese / Spanish / French, etc.) injection attack",
    "output_hijacking": "Forces verbatim / constrained output to bypass safety wording",
    "api_key": "API key detected (sk-...)",
    "jwt": "JWT token detected",
    "credit_card": "Credit card number detected",
    "id_card": "National ID number detected",
    "phone": "Phone number detected",
    "intranet_ip": "Internal IP address detected",
    "email": "Email address detected",
    "high_entropy_blob": "High-entropy suspected encoded / encrypted obfuscated string detected",
    "shell_process_exec": "Process / shell execution call detected (os.system, subprocess, etc.)",
    "dynamic_code_eval": "Dynamic code execution or unsafe deserialization detected (eval / exec / pickle, etc.)",
    "destructive_command": "Destructive system command detected (rm -rf, disk format, shutdown, etc.)",
    "remote_payload_exec": "Remote payload download-and-execute detected (curl|bash, powershell -enc, etc.)",
    "reverse_shell": "Reverse / bind shell signature detected",
    "credential_file_access": "Access to credential or sensitive system files detected (/etc/shadow, .ssh, .aws, etc.)",
    "privilege_persistence": "Privilege escalation or persistence operation detected (chmod +s, scheduled tasks, Run keys, etc.)",
}


def _severity_of(score: int) -> str:
    """Map a 0-100 risk score to a severity band."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _finding_from_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single detection hit into a unified finding (6 fields)."""
    details = hit.get("details", {}) or {}
    return {
        "detector": hit.get("detector", ""),
        "rule_hit": hit.get("rule_hit", ""),
        "owasp_ast": hit.get("owasp_ast", ""),
        "severity": _severity_of(int(hit.get("risk_score", 0))),
        "matched": details.get("masked") or details.get("matched_string", ""),
        "description": details.get("rule_description", ""),
    }


# ---------------------------------------------------------------------------
# 4. FastAPI app and lifecycle
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI_Sentinel Gateway",
    description="AI security gateway: intercepts malicious user input and high-risk Agent actions",
    version="0.1.0",
)

# Rule management API (external security-analysis agent queries/modifies detection rules)
try:
    from gateway.rules_api import router as rules_router
    from gateway.disposition import (router as bans_router, policy_router,
                                     BanMiddleware, policy_store, record_block, _client_ip)
    from gateway.llm_proxy import router as llm_router
    from gateway.hold_store import create_hold, get_hold, resolve_hold, hold_stats
except ImportError:  # pragma: no cover - launched from inside gateway/
    from rules_api import router as rules_router
    from disposition import (router as bans_router, policy_router,
                             BanMiddleware, policy_store, record_block, _client_ip)
    from llm_proxy import router as llm_router
    from hold_store import create_hold, get_hold, resolve_hold, hold_stats
app.include_router(rules_router)
app.include_router(bans_router)
app.include_router(policy_router)
app.include_router(llm_router)  # OpenAI-compatible detecting proxy: /v1/chat/completions
# Pre-processing disposition: banned IPs are rejected with 403 before reaching detection.
app.add_middleware(BanMiddleware)


@app.on_event("startup")
async def on_startup() -> None:
    """Seed the rule store (first run), load engine + detectors, start sink."""
    global DETECTORS
    await sink.start()  # start the reliable-delivery background worker
    # When the rule store is empty, do a one-time import from the existing hard-coded
    # rules; then hot-reload the data-driven engine.
    try:
        from gateway.rule_store import RuleStore, seed_from_legacy
        from gateway.middlewares import rule_engine
    except ImportError:  # pragma: no cover
        from rule_store import RuleStore, seed_from_legacy
        from middlewares import rule_engine
    rs = RuleStore()
    if rs.count() == 0:
        n = seed_from_legacy(rs)
        log.info("Seeded rule store", extra={"event": {"rules_imported": n}})
    rule_engine.reload()

    DETECTORS = load_detectors()

    # LLM semantic layer: soft check. Enabled-but-missing-key only warns, does not
    # fail — the gateway starts normally and the semantic layer just stays inactive.
    if llm_semantic is not None:
        reason = llm_semantic.misconfig_reason()
        if reason:
            log.warning("LLM semantic layer inactive", extra={"event": {"reason": reason}})
        elif llm_semantic.is_enabled():
            log.info(
                "LLM semantic adjudication enabled",
                extra={"event": {"model": llm_semantic.CFG.model}},
            )

    log.info(
        "Gateway startup complete",
        extra={"event": {"detector_count": len(DETECTORS), "rule_count": rs.count(),
                         "semantic_enabled": bool(llm_semantic and llm_semantic.is_enabled())}},
    )


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """Graceful shutdown: flush the delivery pipeline first (don't drop in-flight events), then close the HTTP client."""
    await sink.drain()
    await sender.aclose()


# ---------------------------------------------------------------------------
# 5. Routes
# ---------------------------------------------------------------------------

# Gray-zone rule_hits that should NOT be held: informational categories like
# PII / sensitive data / high entropy — entering these into a CRM is a legitimate
# operation and should not suspend the front-end agent for human review. Only
# attack-class gray-zone hits are held.
_NO_HOLD_HITS = {"pii_email", "pii_phone", "pii_url", "email", "phone",
                 "intranet_ip", "id_card", "credit_card", "high_entropy_blob"}


def decide_verdict(hit, pol, allow_hold: bool = True,
                   no_hold_hits=frozenset()):
    """
    Three-state verdict: returns ('allow'|'held'|'block', score).
      - no hit / score < suspicious_threshold        -> allow (pass through)
      - score >= block_threshold                      -> block (hard block)
      - suspicious <= score < block (gray zone)       -> held (suspend, pending analyst + human review)
        unless allow_hold=False or this rule_hit is in no_hold_hits (informational) -> falls back to allow
    """
    score = int((hit or {}).get("risk_score", 0))
    if hit is None or score < int(pol.get("suspicious_threshold", 40)):
        return "allow", score
    if score >= int(pol.get("block_threshold", 70)):
        return "block", score
    rh = str((hit.get("rule_hit") or hit.get("detector") or "")).lower()
    if not allow_hold or rh in no_hold_hits:
        return "allow", score
    return "held", score


@app.post("/chat")
async def chat(req: ChatRequest, request: Request) -> JSONResponse:
    """
    User input detection entry.

    Flow:
      1. Run all middleware detectors;
      2. On a malicious hit -> return 403 + hit details;
      3. On pass -> return a simulated normal LLM response.
    """
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    log.info(
        "Received /chat request",
        extra={
            "event": {
                "request_id": request_id,
                "session_id": req.session_id,
                "prompt_len": len(req.prompt),
            }
        },
    )

    # Rule-layer detection + LLM semantic adjudication (second layer). Run in a
    # thread pool so the semantic call doesn't block the event loop.
    hit = await asyncio.to_thread(run_detectors, req.prompt, request_id)
    hit = await asyncio.to_thread(semantic_adjudicate, req.prompt, hit, request_id)
    cost_ms = round((time.perf_counter() - start) * 1000, 2)

    # Three-state verdict: block (>= threshold, hard block) / held (gray-zone hold,
    # except informational categories like PII) / allow.
    pol = policy_store.get()
    verdict, score = decide_verdict(hit, pol, no_hold_hits=_NO_HOLD_HITS)
    blocked = verdict == "block"
    held = verdict == "held"

    # On a block, accumulate this IP under the auto-ban policy; auto temp-ban once
    # the threshold is exceeded.
    auto_banned = False
    if blocked:
        auto_banned = record_block(_client_ip(request), pol)

    # Build the event first (event_id doubles as hold_id); for gray-zone, register
    # the hold, then report to Splunk asynchronously.
    event = SecurityEvent(
        module="input_guard",
        blocked=blocked,
        held=held,
        handler="gateway",
        risk_score=score,
        user_input=mask_user_input(req.prompt),
        agent_id=req.session_id,
        findings=[_finding_from_hit(hit)] if hit is not None else [],
        gateway_id=GATEWAY_ID,
        llm_provider=LLM_PROVIDER,
    )
    if held:
        create_hold(event.event_id, {"module": "input_guard", "agent_id": req.session_id,
                                     "risk_score": score,
                                     "rule_hit": (hit or {}).get("rule_hit")})
    emit_event_async(event)

    if blocked:
        # Blocked: return 403 with hit details
        return JSONResponse(
            status_code=403,
            content={
                "request_id": request_id,
                "blocked": True,
                "reason": "Input blocked by security detection",
                "detail": hit,
                "auto_banned": auto_banned,
                "cost_ms": cost_ms,
            },
        )

    if held:
        # Held: gray-zone — the front-end agent MUST NOT execute until the
        # Analyst + a human resolve this hold (release / block).
        return JSONResponse(
            status_code=202,
            content={
                "request_id": request_id,
                "blocked": False,
                "held": True,
                "status": "held",
                "hold_id": event.event_id,
                "reason": "Suspicious input held for analyst review",
                "detail": hit,
                "cost_ms": cost_ms,
            },
        )

    # Passed: simulate a normal response (in production, call the downstream LLM / Agent here)
    log.info(
        "Request passed detection, returning simulated response",
        extra={"event": {"request_id": request_id, "cost_ms": cost_ms}},
    )
    return JSONResponse(
        status_code=200,
        content={
            "request_id": request_id,
            "blocked": False,
            "reply": f"[Simulated response] Received your input: {req.prompt}",
            "cost_ms": cost_ms,
        },
    )


@app.post("/confirm-action")
async def confirm_action(req: ConfirmActionRequest, request: Request) -> JSONResponse:
    """
    High-risk action confirmation entry for the victim Agent.

    Flow:
      1. Merge user_input + action_name + action_params into one text;
      2. Hard-block on destructive high-risk keywords (delete/drop/rm/...);
      3. Otherwise run the merged text through all middleware detectors;
      4. Decide allowed/blocked and emit an action_confirmation event to Splunk.
    """
    request_id = str(uuid.uuid4())

    # Merge the three sources so detectors see the full action context.
    params_str = json.dumps(req.action_params, ensure_ascii=False, sort_keys=True)
    merged_text = f"{req.user_input}\n{req.action_name}\n{params_str}"

    log.info(
        "Received /confirm-action request",
        extra={
            "event": {
                "request_id": request_id,
                "agent_id": req.agent_id,
                "action_name": req.action_name,
            }
        },
    )

    # 1) Destructive-keyword hard block has top priority (on the de-obfuscated view).
    hit = check_high_risk_keywords(expand_input(merged_text))
    # 2) Fall through to the full detector chain (run_detectors de-obfuscates internally).
    if hit is None:
        hit = await asyncio.to_thread(run_detectors, merged_text, request_id)
    # 3) Second-layer LLM semantic adjudication (no-op unless enabled); catches
    #    semantic-level malicious actions the rules missed.
    hit = await asyncio.to_thread(semantic_adjudicate, merged_text, hit, request_id)

    # Three-state verdict: allow / held (gray-zone hold, pending analyst + human) /
    # block (hard block). The action guard exempts no category — high-risk actions
    # are inherently sensitive.
    pol = policy_store.get()
    verdict, risk_score = decide_verdict(hit, pol)
    allowed = verdict == "allow"
    held = verdict == "held"
    blocked = verdict == "block"

    if allowed:
        reason = "No risk detected"
        rule_hit: Optional[str] = None
    else:
        reason = hit.get("details", {}).get("rule_description") \
            or hit.get("reason") \
            or ("Held for analyst review" if held else "Blocked by security policy")
        # Prefer the detector's rule_hit, fall back to its name.
        rule_hit = hit.get("rule_hit") or hit.get("detector")

    # Async, fail-soft audit to Splunk (module=action_guard). Take event_id as the hold_id first.
    event = SecurityEvent(
        module="action_guard",
        blocked=blocked,
        held=held,
        handler="gateway",
        risk_score=risk_score,
        user_input=mask_user_input(req.user_input),
        subject_name=req.action_name,
        agent_id=req.agent_id,
        findings=[_finding_from_hit(hit)] if hit else [],
        gateway_id=GATEWAY_ID,
        llm_provider=LLM_PROVIDER,
    )
    if held:
        create_hold(event.event_id, {"module": "action_guard", "agent_id": req.agent_id,
                                     "action_name": req.action_name, "risk_score": risk_score,
                                     "rule_hit": rule_hit})
    emit_event_async(event)

    if not allowed:
        log.warning(
            "High-risk action held" if held else "High-risk action blocked",
            extra={"event": {"request_id": request_id, "rule_hit": rule_hit,
                             "risk_score": risk_score, "held": held}},
        )

    return JSONResponse(
        status_code=200,
        content={
            "request_id": request_id,
            "allowed": allowed,
            "held": held,
            "status": "held" if held else ("blocked" if blocked else "allowed"),
            "hold_id": event.event_id if held else None,
            "reason": reason,
            "rule_hit": rule_hit,
            "risk_score": risk_score,
        },
    )


# ---------------------------------------------------------------------------
# Hold (gray-zone) lifecycle
# ---------------------------------------------------------------------------
# The front-end agent polls GET /hold/{id} after a 'held' verdict; the Analyst
# (or a human via the dashboard) resolves it through POST /hold/{id}/resolve.
class ResolveHoldRequest(BaseModel):
    decision: str = Field(..., description="'release' or 'block'")
    reason: Optional[str] = Field("", description="Disposition reason")
    operator: Optional[str] = Field("analyst", description="Who resolved it")


@app.get("/hold/{hold_id}")
async def hold_status(hold_id: str) -> JSONResponse:
    """Poll a hold's status. 404 if unknown (agent should keep holding / fail-safe)."""
    rec = get_hold(hold_id)
    if rec is None:
        return JSONResponse(status_code=404, content={"hold_id": hold_id, "status": "unknown"})
    return JSONResponse(status_code=200, content=rec)


@app.post("/hold/{hold_id}/resolve")
async def hold_resolve(hold_id: str, req: ResolveHoldRequest, request: Request) -> JSONResponse:
    """Resolve a hold (release/block). Idempotent; called by Analyst gateway-control MCP."""
    rec = resolve_hold(hold_id, req.decision, req.reason or "", req.operator or "analyst")
    if rec is None:
        return JSONResponse(status_code=400,
                            content={"ok": False, "error": "unknown hold_id or invalid decision"})
    # When the verdict is block, accumulate this source under the policy (counts
    # toward the auto-ban tally, consistent with a hard block).
    if rec.get("status") == "blocked":
        try:
            record_block(_client_ip(request), policy_store.get())
        except Exception:
            pass
    log.info("Hold resolved",
             extra={"event": {"hold_id": hold_id, "status": rec.get("status"),
                              "operator": rec.get("operator")}})
    return JSONResponse(status_code=200, content={"ok": True, "hold": rec})


@app.get("/holds")
async def holds_overview() -> JSONResponse:
    """Lightweight overview of hold counts (for dashboards / debugging)."""
    return JSONResponse(status_code=200, content=hold_stats())


# Skill scanner endpoint
@app.post("/scan")
async def scan_skill(req: SkillScanRequest, request: Request) -> JSONResponse:
    request_id = str(uuid.uuid4())
    started_at = time.perf_counter()

    log.info(
        "Received /scan request",
        extra={
            "event": {
                "request_id": request_id,
                "skill_name": req.skill_name,
                "content_len": len(req.skill_content),
            }
        },
    )

    findings: List[Dict[str, Any]] = []
    top_score = 0

    # De-obfuscate before matching: undo zero-width / full-width / letter-spacing
    # / base64-url-html tricks so disguised payloads become detectable.
    scan_view = expand_input(req.skill_content)

    # The unified engine yields per-rule hits (multiple findings); other non-rule_engine
    # detectors still yield a single result.
    try:
        from gateway.middlewares import rule_engine as _re
    except Exception:  # pragma: no cover
        from middlewares import rule_engine as _re

    outcomes: List[Dict[str, Any]] = []
    for detector_name, detect_fn in DETECTORS:
        try:
            if detector_name == "rule_engine":
                outcomes.extend(_re.detect_all(scan_view))
            else:
                o = detect_fn(scan_view) or {}
                if o.get("is_malicious"):
                    outcomes.append(o)
        except Exception as exc:
            log.error(
                "Detector raised during scan",
                extra={"event": {"request_id": request_id,
                                 "detector": detector_name, "error": str(exc)}},
            )
            continue

    for outcome in outcomes:
        score = int(outcome.get("risk_score", 0))
        top_score = max(top_score, score)
        evidence = outcome.get("details", {})
        rule = outcome.get("rule_hit") or "rule"
        snippet = evidence.get("masked") or evidence.get("matched_string", "")

        findings.append({
            "rule_hit": rule,
            "owasp_ast": outcome.get("owasp_ast", ""),
            "severity": _severity_of(score),
            "description": _RULE_BLURB_ZH.get(rule, evidence.get("rule_description", "Suspicious content detected")),
            "matched_content": snippet,
        })

    elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    is_malicious = len(findings) > 0

    event_findings = [{
        "detector": "",
        "rule_hit": f.get("rule_hit", ""),
        "owasp_ast": f.get("owasp_ast", ""),
        "severity": f.get("severity", ""),
        "matched": f.get("matched_content", ""),
        "description": f.get("description", ""),
    } for f in findings]
    emit_event_async(
        SecurityEvent(
            module="skill_scanner",
            blocked=is_malicious,
            handler="external",
            risk_score=top_score,
            user_input=mask_user_input(req.skill_content),
            subject_name=req.skill_name,
            findings=event_findings,
            gateway_id=GATEWAY_ID,
            llm_provider=LLM_PROVIDER,
        )
    )

    if is_malicious:
        log.warning(
            "Skill scan flagged content",
            extra={"event": {"request_id": request_id, "skill_name": req.skill_name,
                             "risk_score": top_score, "finding_count": len(findings)}},
        )

    return JSONResponse(
        status_code=200,
        content={
            "is_malicious": is_malicious,
            "risk_score": top_score,
            "findings": findings,
            "scan_duration_ms": elapsed_ms,
        },
    )


@app.get("/health")
async def health() -> Dict[str, Any]:
    """Health check endpoint."""
    return {"status": "ok", "detector_count": len(DETECTORS)}


# Run directly as a script: python -m gateway.main or python gateway/main.py
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("gateway.main:app", host="0.0.0.0", port=3001, reload=True)
