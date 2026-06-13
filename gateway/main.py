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
    load_dotenv()
except ImportError:
    pass

import os
import re
import json
import time
import uuid
import asyncio
import logging
import importlib
import pkgutil
from typing import Callable, Dict, List, Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# EN: async Splunk HEC sender (global singleton) and its event model.
#     Dual import so the app runs as both `gateway.main:app` (from repo root)
#     and `main:app` (from inside the gateway/ dir).
# 中文：异步 Splunk HEC 发送器（全局单例）及其事件模型。
#     双重导入，使应用既能以 `gateway.main:app`（仓库根目录）运行，
#     也能以 `main:app`（在 gateway/ 目录内）运行。
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

        # 被规则库取代的旧硬编码检测器标记 SUPERSEDED=True，跳过自动加载
        if getattr(module, "SUPERSEDED", False):
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
# High-risk action keywords / 高危操作关键词
# ---------------------------------------------------------------------------
# EN: Gateway identity & downstream LLM provider, used in emitted events.
# 中文：网关标识与下游 LLM 提供方，用于上报的事件中。
GATEWAY_ID = os.getenv("GATEWAY_ID", "gateway-01")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

# EN: Destructive verbs that should hard-block an Agent action outright.
# 中文：会直接硬阻断 Agent 操作的破坏性高危词。
HIGH_RISK_KEYWORDS: List[str] = [
    "delete", "drop", "truncate", "rm", "format", "destroy", "wipe",
    "shutdown", "reboot", "mkfs", "unlink", "rmdir", "del", "kill",
    "drop table", "drop database", "rm -rf",
]

# EN: One pre-compiled, case-insensitive regex over all keywords. Boundaries use
#     alphanumeric lookarounds (NOT \b) so snake_case action names like
#     "delete_user" / "drop_table" are still caught (underscore acts as a separator).
# 中文：将所有关键词预编译为一条大小写不敏感的正则。边界使用「字母数字环视」而非 \b，
#     这样像 "delete_user" / "drop_table" 这类 snake_case 操作名也能命中（下划线视作分隔符）。
_HIGH_RISK_RE: re.Pattern = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(k) for k in HIGH_RISK_KEYWORDS)
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def check_high_risk_keywords(text: str) -> Optional[Dict[str, Any]]:
    """
    EN: Scan text for destructive keywords. A hit hard-blocks the action.
        Returns a detector-shaped dict, or None when clean.
    中文：扫描文本中的破坏性关键词，命中即硬阻断操作。
        命中返回与检测器一致结构的 dict，否则返回 None。
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
    EN: Lightweight desensitization for logging/SIEM -- redact obvious secrets
        (API keys, JWTs, emails, long digit runs) and cap the length.
    中文：用于日志/SIEM 的轻量脱敏 —— 屏蔽明显的密文（API Key、JWT、邮箱、
        长数字串）并截断长度。
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
    把事件交给可靠投递管线（内存队列 + 批量 + 重试 + 磁盘 spool）。
    非阻塞，绝不拖慢请求；Splunk 抖动时落盘，恢复后回放，不丢数据。
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
    """
    EN: High-risk action confirmation request body submitted by the victim Agent.
    中文：受害者 Agent 提交的高危操作确认请求体。
    """

    action_name: str = Field(..., description="Action to confirm, e.g. delete_user / transfer_funds")
    action_params: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    agent_id: str = Field(..., description="Calling Agent identifier")
    user_input: str = Field("", description="Original user input that triggered the action")
    context: Optional[Dict[str, Any]] = Field(None, description="Extra context, optional")


class SkillScanRequest(BaseModel):
    """EN: A skill payload to scan. / 中文：待扫描的技能内容。"""

    skill_name: str = Field(..., description="Skill identifier / 技能名称")
    skill_content: str = Field(..., description="Skill body to inspect / 技能正文内容")


# EN: Short Chinese blurb per rule, surfaced in scan findings.
# 中文：每条规则对应的简短中文说明，用于扫描结果。
_RULE_BLURB_ZH: Dict[str, str] = {
    "system_instruction_override": "试图覆盖或忽略先前的系统指令",
    "jailbreak": "检测到越狱触发词（DAN / 无限制人格）",
    "role_play": "强制模型扮演新角色以绕过策略",
    "prompt_leak": "试图套取系统提示词",
    "token_smuggling": "通过编码 / 零宽字符走私隐藏指令",
    "context_manipulation": "注入伪造角色或对话模板标记",
    "api_manipulation": "篡改模型参数、工具或函数调用",
    "indirect_injection": "面向读取外部内容的 AI 的隐藏指令",
    "multilingual": "非英文（中文 / 西 / 法等）注入攻击",
    "output_hijacking": "强制逐字 / 受限输出以绕过安全措辞",
    "api_key": "检测到 API 密钥（sk-...）",
    "jwt": "检测到 JWT 令牌",
    "credit_card": "检测到信用卡号",
    "id_card": "检测到身份证号",
    "phone": "检测到手机号",
    "intranet_ip": "检测到内网 IP 地址",
    "email": "检测到电子邮箱地址",
    "high_entropy_blob": "检测到高熵的疑似编码 / 加密混淆串",
    "shell_process_exec": "检测到进程 / shell 执行调用（os.system、subprocess 等）",
    "dynamic_code_eval": "检测到动态代码执行或不安全反序列化（eval / exec / pickle 等）",
    "destructive_command": "检测到破坏性系统命令（rm -rf、格式化磁盘、关机等）",
    "remote_payload_exec": "检测到远程载荷下载并执行（curl|bash、powershell -enc 等）",
    "reverse_shell": "检测到反弹 / 绑定 shell 特征",
    "credential_file_access": "检测到读取凭据或敏感系统文件（/etc/shadow、.ssh、.aws 等）",
    "privilege_persistence": "检测到提权或持久化操作（chmod +s、计划任务、Run 键等）",
}


def _severity_of(score: int) -> str:
    """Map a 0-100 risk score to a severity band / 将风险分映射为严重等级。"""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _finding_from_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """把单条检测 hit 归一化为统一 finding（6 字段）。"""
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

# 规则管理 API（外部安全分析 agent 查询/修改检测规则）
try:
    from gateway.rules_api import router as rules_router
    from gateway.disposition import (router as bans_router, policy_router,
                                     BanMiddleware, policy_store, record_block, _client_ip)
    from gateway.llm_proxy import router as llm_router
except ImportError:  # pragma: no cover - launched from inside gateway/
    from rules_api import router as rules_router
    from disposition import (router as bans_router, policy_router,
                             BanMiddleware, policy_store, record_block, _client_ip)
    from llm_proxy import router as llm_router
app.include_router(rules_router)
app.include_router(bans_router)
app.include_router(policy_router)
app.include_router(llm_router)  # OpenAI 兼容检测代理：/v1/chat/completions
# 前置处置：被封禁 IP 在进入检测前就被 403 拦下
app.add_middleware(BanMiddleware)


@app.on_event("startup")
async def on_startup() -> None:
    """Seed the rule store (first run), load engine + detectors, start sink."""
    global DETECTORS
    await sink.start()  # 启动可靠投递后台 worker
    # 规则库为空时，从现有硬编码规则一次性导入；随后热加载数据驱动引擎
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
    log.info(
        "Gateway startup complete",
        extra={"event": {"detector_count": len(DETECTORS), "rule_count": rs.count()}},
    )


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """优雅关闭：先 flush 投递管线（不丢在途事件），再关 HTTP 客户端。"""
    await sink.drain()
    await sender.aclose()


# ---------------------------------------------------------------------------
# 5. Routes
# ---------------------------------------------------------------------------


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

    hit = run_detectors(req.prompt, request_id)
    cost_ms = round((time.perf_counter() - start) * 1000, 2)

    # 按可调阈值判定是否拦截：命中分数 >= block_threshold 才拦（低于阈值=检出但放行）
    pol = policy_store.get()
    score = int((hit or {}).get("risk_score", 0))
    blocked = hit is not None and score >= pol["block_threshold"]

    # 命中即拦时，按自动封禁策略累计该 IP，超阈值自动临时封禁
    auto_banned = False
    if blocked:
        auto_banned = record_block(_client_ip(request), pol)

    emit_event_async(
        SecurityEvent(
            module="input_guard",
            blocked=blocked,
            handler="gateway",
            risk_score=score,
            user_input=mask_user_input(req.prompt),
            agent_id=req.session_id,
            findings=[_finding_from_hit(hit)] if hit is not None else [],
            gateway_id=GATEWAY_ID,
            llm_provider=LLM_PROVIDER,
        )
    )

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
    EN: High-risk action confirmation entry for the victim Agent.

        Flow:
          1. Merge user_input + action_name + action_params into one text;
          2. Hard-block on destructive high-risk keywords (delete/drop/rm/...);
          3. Otherwise run the merged text through all middleware detectors;
          4. Decide allowed/blocked and emit an action_confirmation event to Splunk.
    中文：受害者 Agent 的高危操作确认入口。

        流程：
          1. 合并 user_input + action_name + action_params 为一段文本；
          2. 命中破坏性高危词（delete/drop/rm/...）直接硬阻断；
          3. 否则将合并文本送入全部中间件检测器；
          4. 判定放行/阻断，并向 Splunk 异步上报 action_confirmation 事件。
    """
    request_id = str(uuid.uuid4())

    # EN: merge the three sources so detectors see the full action context.
    # 中文：合并三个来源，使检测器能看到完整的操作上下文。
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

    # EN: 1) destructive-keyword hard block has top priority (on the de-obfuscated view).
    # 中文：1) 破坏性关键词硬阻断，优先级最高（在洗白后的文本上判断）。
    hit = check_high_risk_keywords(expand_input(merged_text))
    # EN: 2) fall through to the full detector chain (run_detectors de-obfuscates internally).
    # 中文：2) 未命中高危词时，运行完整检测器链（run_detectors 内部已做洗白）。
    if hit is None:
        hit = run_detectors(merged_text, request_id)

    allowed = hit is None
    if allowed:
        reason = "No risk detected"
        rule_hit: Optional[str] = None
        risk_score = 0
    else:
        reason = hit.get("details", {}).get("rule_description") \
            or hit.get("reason") or "Blocked by security policy"
        # EN: prefer the detector's rule_hit, fall back to its name.
        # 中文：优先用检测器的 rule_hit，否则回退到检测器名称。
        rule_hit = hit.get("rule_hit") or hit.get("detector")
        risk_score = hit.get("risk_score", 100)

    # EN: async, fail-soft audit to Splunk (module=action_guard).
    # 中文：异步、软失败地审计上报 Splunk（module=action_guard）。
    emit_event_async(
        SecurityEvent(
            module="action_guard",
            blocked=not allowed,
            handler="gateway",
            risk_score=int((hit or {}).get("risk_score", 0)),
            user_input=mask_user_input(req.user_input),
            subject_name=req.action_name,
            agent_id=req.agent_id,
            findings=[_finding_from_hit(hit)] if hit else [],
            gateway_id=GATEWAY_ID,
            llm_provider=LLM_PROVIDER,
        )
    )

    if not allowed:
        log.warning(
            "High-risk action blocked",
            extra={"event": {"request_id": request_id, "rule_hit": rule_hit,
                             "risk_score": risk_score}},
        )

    return JSONResponse(
        status_code=200,
        content={
            "request_id": request_id,
            "allowed": allowed,
            "reason": reason,
            "rule_hit": rule_hit,
            "risk_score": risk_score,
        },
    )


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

    # 统一引擎逐规则命中（多 finding）；其它非 rule_engine 检测器仍取单条
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
            "description": _RULE_BLURB_ZH.get(rule, evidence.get("rule_description", "检测到可疑内容")),
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
