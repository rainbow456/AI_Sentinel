# -*- coding: utf-8 -*-
"""
LLM 兼容检测代理 / OpenAI-compatible detecting proxy
===================================================
任何语言的 agent 只要把 base_url 指到本网关（OPENAI_BASE_URL=http://gateway/v1），
零代码即可让 LLM 输入/输出经过检测、拦截、审计。

流程：入参检测 → 命中且超阈值则拦截（返回安全拒答）→ 否则转发真上游（或无上游时
模拟放行）→ 出参可选检测 → 标准化事件审计（带 agent_id）。

上游可选：OPENAI_UPSTREAM_URL / OPENAI_UPSTREAM_KEY；不配则走模拟模式（便于先打通）。
"""

# Load .env before reading env vars at module scope
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env 优先于脚本/shell 注入的同名环境变量
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
        return "key:" + auth[7:][:12]   # api-key 前缀作 agent 标识
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
        elif isinstance(c, list):  # OpenAI 多模态 content 数组
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

    # ① 入参检测（user_input 通道）
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
            model, "请求命中安全策略，已被 AI_Sentinel 网关拦截。",
            {"blocked": True, "risk_score": score, "rule_hit": hit.get("rule_hit", "")}))

    # ② 转发上游（未配置则模拟放行）
    if UPSTREAM_URL and UPSTREAM_KEY:
        try:
            async with httpx.AsyncClient(timeout=60, trust_env=False) as c:
                r = await c.post(UPSTREAM_URL, json=body, headers={
                    "Authorization": f"Bearer {UPSTREAM_KEY}",
                    "Content-Type": "application/json"})
            data = r.json()
        except Exception as e:
            return JSONResponse(_openai_reply(
                model, f"上游 LLM 暂不可达（已放行）：{e}", {"blocked": False, "upstream_error": True}))
        return JSONResponse(data)

    return JSONResponse(_openai_reply(
        model, f"[模拟回复·已通过安全检测] 收到 {len(messages)} 条消息。",
        {"blocked": False, "simulated": True, "risk_score": score}))
