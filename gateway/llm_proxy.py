# -*- coding: utf-8 -*-
"""
OpenAI-compatible detecting proxy
===================================================
Any agent, in any language, only has to point its base_url at this gateway
(OPENAI_BASE_URL=http://gateway/v1) to have LLM input/output detected, blocked,
and audited with zero code changes.

Flow: detect input -> if it hits and exceeds the threshold, block (return a safe
refusal) -> otherwise forward to the real upstream (or pass through in simulated
mode when no upstream is configured) -> optionally detect output -> emit a
normalized audit event (with agent_id).

Upstream is optional: OPENAI_UPSTREAM_URL / OPENAI_UPSTREAM_KEY; without it the
proxy runs in simulated mode (handy for getting wired up first).
"""

# Load .env before reading env vars at module scope
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env takes precedence over env vars injected by the script/shell
except ImportError:
    pass

import os
import re
import time
import uuid
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

try:
    from gateway.mcp_sender import sink, SecurityEvent
    from gateway.preprocess import expand as expand_input
    from gateway.middlewares import rule_engine
    from gateway.disposition import policy_store
except Exception:  # pragma: no cover
    from mcp_sender import sink, SecurityEvent
    from preprocess import expand as expand_input
    from middlewares import rule_engine
    from disposition import policy_store

GATEWAY_ID = os.getenv("GATEWAY_ID", "gateway-01")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")
UPSTREAM_URL = os.getenv("OPENAI_UPSTREAM_URL")   # e.g. https://api.openai.com/v1/chat/completions
UPSTREAM_KEY = os.getenv("OPENAI_UPSTREAM_KEY")

router = APIRouter(tags=["llm-proxy"])


def _sev(score: int) -> str:
    return "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"


def _finding(hit: Dict[str, Any]) -> Dict[str, Any]:
    d = hit.get("details", {}) or {}
    return {
        "detector": hit.get("detector", ""),
        "rule_hit": hit.get("rule_hit", ""),
        "owasp_ast": hit.get("owasp_ast", ""),
        "severity": _sev(int(hit.get("risk_score", 0))),
        "matched": d.get("masked") or d.get("matched_string", ""),
        "description": d.get("rule_description", ""),
    }


def _mask(text: str, n: int = 500) -> str:
    if not text:
        return ""
    t = re.sub(r"\bsk-[A-Za-z0-9_\-]{8,}\b", "sk-***", text)
    t = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "***EMAIL***", t)
    return t if len(t) <= n else t[:n] + "...(truncated)"


def _agent_id(req: Request) -> str:
    hdr = req.headers.get("x-agent-id")
    if hdr:
        return hdr
    auth = req.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return "key:" + auth[7:][:12]   # use the api-key prefix as the agent identifier
    return "anonymous-agent"


def _openai_reply(model: str, content: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:24],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "sentinel-proxy",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "x_sentinel": extra,
    }


def _gather_input(messages: List[Dict[str, Any]]) -> str:
    parts = []
    for m in messages:
        c = m.get("content")
        if isinstance(c, str) and m.get("role") in ("user", "system", "tool"):
            parts.append(c)
        elif isinstance(c, list):  # OpenAI multimodal content array
            parts += [b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"]
    return "\n".join(p for p in parts if p)


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": {"message": "invalid json"}})

    model = body.get("model", "")
    messages = body.get("messages", []) or []
    agent_id = _agent_id(request)

    # 1) Detect input (user_input channel).
    text = _gather_input(messages)
    hit = rule_engine.detect(expand_input(text))
    pol = policy_store.get()
    score = int(hit.get("risk_score", 0)) if hit.get("is_malicious") else 0
    blocked = bool(hit.get("is_malicious")) and score >= pol["block_threshold"]
    findings = [_finding(hit)] if hit.get("is_malicious") else []

    sink.submit(SecurityEvent(
        module="input_guard", blocked=blocked, handler="gateway", risk_score=score,
        user_input=_mask(text), subject_name=model, agent_id=agent_id,
        findings=findings, gateway_id=GATEWAY_ID, llm_provider=LLM_PROVIDER))

    if blocked:
        return JSONResponse(_openai_reply(
            model, "This request hit a security policy and was blocked by the AI_Sentinel gateway.",
            {"blocked": True, "risk_score": score, "rule_hit": hit.get("rule_hit", "")}))

    # 2) Forward to the upstream (pass through in simulated mode if not configured).
    if UPSTREAM_URL and UPSTREAM_KEY:
        try:
            async with httpx.AsyncClient(timeout=60, trust_env=False) as c:
                r = await c.post(UPSTREAM_URL, json=body, headers={
                    "Authorization": f"Bearer {UPSTREAM_KEY}",
                    "Content-Type": "application/json"})
            data = r.json()
        except Exception as e:
            return JSONResponse(_openai_reply(
                model, f"Upstream LLM temporarily unreachable (passed through): {e}", {"blocked": False, "upstream_error": True}))
        return JSONResponse(data)

    return JSONResponse(_openai_reply(
        model, f"[Simulated reply - passed security detection] Received {len(messages)} message(s).",
        {"blocked": False, "simulated": True, "risk_score": score}))
