# -*- coding: utf-8 -*-
"""
处置模块 / Disposition
=====================
IP 封禁（临时 / 永久）+ 请求前置拦截中间件 + /bans 管理 API。
封禁/解封/拦截命中都审计上报 Splunk（module=disposition）。

存储：SQLite disposition.db（bans 表）。临时封禁到点自动失效。
"""

# Load .env before reading env vars at module scope
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import os
import time
import sqlite3
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from gateway.mcp_sender import sink, SecurityEvent
    from gateway.rule_store import RuleStore, RuleError
    from gateway.middlewares import rule_engine
except Exception:  # pragma: no cover
    from mcp_sender import sink, SecurityEvent
    from rule_store import RuleStore, RuleError
    from middlewares import rule_engine

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "disposition.db")
GATEWAY_ID = os.getenv("GATEWAY_ID", "gateway-01")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

# 管理面 / 健康检查路径前缀：不受 IP 封禁影响，避免把自己锁死。
_EXEMPT = ("/health", "/bans", "/rules", "/policy", "/docs", "/openapi.json", "/redoc")


class BanStore:
    def __init__(self, db_path: str = DB_PATH):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY, type TEXT, reason TEXT,
                until_ts INTEGER, created_by TEXT, created_at TEXT
            )"""
        )
        self.conn.commit()

    @staticmethod
    def _now() -> int:
        return int(time.time())

    def ban(self, ip: str, type: str = "temp", ttl_seconds: Optional[int] = 3600,
            reason: str = "", actor: str = "external-agent") -> Dict[str, Any]:
        if not ip:
            raise ValueError("缺少 ip")
        if type not in ("temp", "permanent"):
            raise ValueError("type 必须是 temp 或 permanent")
        until = None if type == "permanent" else self._now() + int(ttl_seconds or 3600)
        self.conn.execute(
            "INSERT OR REPLACE INTO bans (ip, type, reason, until_ts, created_by, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (ip, type, reason, until, actor,
             time.strftime("%Y-%m-%dT%H:%M:%S")),
        )
        self.conn.commit()
        return self.get(ip)

    def unban(self, ip: str) -> bool:
        cur = self.conn.execute("DELETE FROM bans WHERE ip=?", (ip,))
        self.conn.commit()
        return cur.rowcount > 0

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM bans WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def is_banned(self, ip: str):
        """返回 (是否封禁, 记录)。临时封禁过期则顺手清除。"""
        rec = self.get(ip)
        if not rec:
            return False, None
        if rec["type"] == "temp" and rec["until_ts"] and rec["until_ts"] <= self._now():
            self.unban(ip)  # 到点自动失效
            return False, None
        return True, rec

    def list_active(self) -> List[Dict[str, Any]]:
        now = self._now()
        out = []
        for row in self.conn.execute("SELECT * FROM bans ORDER BY created_at DESC").fetchall():
            r = dict(row)
            if r["type"] == "temp" and r["until_ts"] and r["until_ts"] <= now:
                continue  # 已过期不展示
            r["remaining_seconds"] = (r["until_ts"] - now) if r["until_ts"] else None
            out.append(r)
        return out


store = BanStore()


# ---------------------------------------------------------------------------
# 审计 -> Splunk
# ---------------------------------------------------------------------------
def _audit(action: str, ip: str, actor: str, blocked: bool, handler: str, reason: str = ""):
    sink.submit(SecurityEvent(
        module="disposition", blocked=blocked, handler=handler, risk_score=0,
        user_input=f"{action} {ip} {reason}".strip(),
        subject_name=ip, agent_id=actor, findings=[],
        gateway_id=GATEWAY_ID, llm_provider=LLM_PROVIDER,
    ))


def _client_ip(request: Request) -> str:
    """优先取 X-Forwarded-For 首段（经代理时），否则用直连地址。"""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# 前置中间件：被封禁 IP 直接 403
# ---------------------------------------------------------------------------
class BanMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not any(path.startswith(p) for p in _EXEMPT):
            ip = _client_ip(request)
            banned, rec = store.is_banned(ip)
            if banned:
                _audit("enforce-block", ip, "gateway", blocked=True, handler="gateway",
                       reason=(rec or {}).get("reason", ""))
                return JSONResponse(status_code=403, content={
                    "blocked": True, "reason": "IP 已被封禁",
                    "ip": ip, "ban": {"type": rec["type"], "until_ts": rec["until_ts"]},
                })
        return await call_next(request)


# ---------------------------------------------------------------------------
# /bans 管理 API
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/bans", tags=["bans"])


class BanIn(BaseModel):
    ip: str
    type: Literal["temp", "permanent"] = "temp"
    ttl_seconds: Optional[int] = 3600
    reason: str = ""


@router.get("")
def list_bans():
    return {"bans": store.list_active()}


@router.get("/{ip}")
def ban_status(ip: str):
    banned, rec = store.is_banned(ip)
    return {"ip": ip, "banned": banned, "record": rec}


@router.post("")
def create_ban(body: BanIn, actor: str = "external-agent"):
    try:
        rec = store.ban(body.ip, body.type, body.ttl_seconds, body.reason, actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(f"ban({body.type})", body.ip, actor, blocked=True, handler="external",
           reason=body.reason)
    return rec


@router.delete("/{ip}")
def remove_ban(ip: str, actor: str = "external-agent"):
    if not store.unban(ip):
        raise HTTPException(404, "该 IP 未在封禁列表")
    _audit("unban", ip, actor, blocked=False, handler="external")
    return {"unbanned": ip}


# ---------------------------------------------------------------------------
# 策略 / 阈值
# ---------------------------------------------------------------------------
class PolicyStore:
    """全局检测策略（单行）：拦截阈值 + 自动封禁参数。"""

    DEFAULTS = {
        "block_threshold": 70, "suspicious_threshold": 40, "mode": "balanced",
        "auto_ban_enabled": 0, "auto_ban_max_blocks": 5,
        "auto_ban_window_s": 60, "auto_ban_ttl_s": 600,
    }

    def __init__(self, db_path: str = DB_PATH):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS policy (
                id INTEGER PRIMARY KEY CHECK (id=1),
                block_threshold INT, suspicious_threshold INT, mode TEXT,
                auto_ban_enabled INT, auto_ban_max_blocks INT,
                auto_ban_window_s INT, auto_ban_ttl_s INT,
                updated_by TEXT, updated_at TEXT)"""
        )
        self.conn.commit()
        if not self.conn.execute("SELECT 1 FROM policy WHERE id=1").fetchone():
            self._write(self.DEFAULTS, "system")

    def _write(self, vals: Dict[str, Any], actor: str):
        v = {**self.DEFAULTS, **vals}
        self.conn.execute(
            """INSERT OR REPLACE INTO policy
               (id, block_threshold, suspicious_threshold, mode, auto_ban_enabled,
                auto_ban_max_blocks, auto_ban_window_s, auto_ban_ttl_s, updated_by, updated_at)
               VALUES (1,?,?,?,?,?,?,?,?,?)""",
            (v["block_threshold"], v["suspicious_threshold"], v["mode"],
             1 if v["auto_ban_enabled"] else 0, v["auto_ban_max_blocks"],
             v["auto_ban_window_s"], v["auto_ban_ttl_s"], actor,
             time.strftime("%Y-%m-%dT%H:%M:%S")),
        )
        self.conn.commit()

    def get(self) -> Dict[str, Any]:
        row = dict(self.conn.execute("SELECT * FROM policy WHERE id=1").fetchone())
        row["auto_ban_enabled"] = bool(row["auto_ban_enabled"])
        return row

    def update(self, fields: Dict[str, Any], actor: str = "external-agent") -> Dict[str, Any]:
        cur = self.get()
        merged = {**cur, **{k: v for k, v in fields.items() if v is not None}}
        self._write(merged, actor)
        return self.get()


PRESETS = {
    "strict":   {"block_threshold": 50, "suspicious_threshold": 30, "mode": "strict",
                 "auto_ban_enabled": 1, "auto_ban_max_blocks": 3,
                 "auto_ban_window_s": 60, "auto_ban_ttl_s": 1800},
    "balanced": {"block_threshold": 70, "suspicious_threshold": 40, "mode": "balanced",
                 "auto_ban_enabled": 0, "auto_ban_max_blocks": 5,
                 "auto_ban_window_s": 60, "auto_ban_ttl_s": 600},
    "lenient":  {"block_threshold": 90, "suspicious_threshold": 60, "mode": "lenient",
                 "auto_ban_enabled": 0, "auto_ban_max_blocks": 8,
                 "auto_ban_window_s": 60, "auto_ban_ttl_s": 300},
}

policy_store = PolicyStore()

# 自动封禁：进程内滑动窗口计数（IP -> 命中时间戳）
_block_log: Dict[str, List[int]] = {}


def record_block(ip: str, pol: Dict[str, Any]) -> bool:
    """记一次该 IP 的拦截；窗口内超过阈值则自动临时封禁。返回是否触发封禁。"""
    if not pol.get("auto_ban_enabled") or not ip or ip == "unknown":
        return False
    now = int(time.time())
    win = pol["auto_ban_window_s"]
    arr = [t for t in _block_log.get(ip, []) if t > now - win]
    arr.append(now)
    _block_log[ip] = arr
    if len(arr) >= pol["auto_ban_max_blocks"]:
        store.ban(ip, "temp", pol["auto_ban_ttl_s"],
                  reason=f"auto: {len(arr)} blocks in {win}s", actor="auto-ban")
        _block_log[ip] = []
        _audit("auto-ban", ip, "auto-ban", blocked=True, handler="gateway",
               reason="block threshold exceeded")
        return True
    return False


policy_router = APIRouter(prefix="/policy", tags=["policy"])


class PolicyIn(BaseModel):
    block_threshold: Optional[int] = None
    suspicious_threshold: Optional[int] = None
    auto_ban_enabled: Optional[bool] = None
    auto_ban_max_blocks: Optional[int] = None
    auto_ban_window_s: Optional[int] = None
    auto_ban_ttl_s: Optional[int] = None


@policy_router.get("")
def get_policy():
    return policy_store.get()


@policy_router.put("")
def put_policy(body: PolicyIn, actor: str = "external-agent"):
    f = body.model_dump()
    for k in ("block_threshold", "suspicious_threshold"):
        if f.get(k) is not None and not (0 <= f[k] <= 100):
            raise HTTPException(400, f"{k} 必须 0-100")
    pol = policy_store.update(f, actor)
    _audit("policy-update", "-", actor, blocked=False, handler="external",
           reason=str({k: v for k, v in f.items() if v is not None}))
    return pol


@policy_router.post("/preset/{name}")
def apply_preset(name: str, actor: str = "external-agent"):
    if name not in PRESETS:
        raise HTTPException(404, "未知预设（strict / balanced / lenient）")
    pol = policy_store.update(PRESETS[name], actor)
    _audit(f"preset:{name}", "-", actor, blocked=False, handler="external")
    return pol


# ---------------------------------------------------------------------------
# 策略优化：批量原子调整 + 命中遥测 + 建议
# ---------------------------------------------------------------------------
_rstore = RuleStore()


class OptimizeIn(BaseModel):
    rules: List[Dict[str, Any]] = []      # 整条规则 upsert（新增/修改）
    enable: List[str] = []                # 要启用的规则 id
    disable: List[str] = []               # 要禁用的规则 id
    policy: Optional[Dict[str, Any]] = None
    dry_run: bool = False


@policy_router.post("/optimize")
def optimize(body: OptimizeIn, actor: str = "external-agent"):
    """批量原子调整：先全量预校验，任一失败则整批放弃；dry_run 只预览不写。"""
    errors: List[Dict[str, Any]] = []
    for r in body.rules:
        try:
            _rstore.validate(dict(r, engine=r.get("engine", "regex")))
            t = _rstore.run_tests(r)
            if not t["ok"]:
                errors.append({"id": r.get("id"), "test_fails": t["fails"]})
        except RuleError as e:
            errors.append({"id": r.get("id"), "error": str(e)})
    for rid in body.enable + body.disable:
        if not _rstore.get(rid):
            errors.append({"id": rid, "error": "规则不存在"})
    if body.policy:
        for k in ("block_threshold", "suspicious_threshold"):
            v = body.policy.get(k)
            if v is not None and not (0 <= v <= 100):
                errors.append({"policy": k, "error": "必须 0-100"})
    if errors:
        raise HTTPException(400, {"applied": False, "errors": errors})

    if body.dry_run:
        return {"dry_run": True, "errors": [], "would_apply": {
            "rules": [r.get("id") for r in body.rules],
            "enable": body.enable, "disable": body.disable, "policy": body.policy}}

    # 预校验通过 → 依次应用
    for r in body.rules:
        _rstore.upsert(r, actor=actor, require_tests=True)
    for rid in body.enable:
        _rstore.set_enabled(rid, True, actor)
    for rid in body.disable:
        _rstore.set_enabled(rid, False, actor)
    new_policy = policy_store.update(body.policy, actor) if body.policy else None
    active = rule_engine.reload()
    _audit("optimize", "-", actor, blocked=False, handler="external",
           reason=f"rules={len(body.rules)} enable={len(body.enable)} "
                  f"disable={len(body.disable)} policy={bool(body.policy)}")
    return {"applied": True, "active_rules": active,
            "rules": [r.get("id") for r in body.rules],
            "enabled": body.enable, "disabled": body.disable, "policy": new_policy}


@policy_router.get("/stats")
def rule_stats():
    """各规则命中次数（含从未命中的启用规则），给反馈优化用。"""
    hits = rule_engine.stats()
    rows = [{"id": r["id"], "name": r["name"], "category": r["category"],
             "enabled": r["enabled"], "hits": hits.get(r["name"], 0)}
            for r in _rstore.list()]
    rows.sort(key=lambda x: x["hits"], reverse=True)
    return {"total_rules": len(rows), "stats": rows}


@policy_router.post("/optimize/suggest")
def suggest():
    """基于命中遥测给启发式建议：从未命中的启用规则、命中量 Top。"""
    hits = rule_engine.stats()
    rules = _rstore.list()
    never = [r["id"] for r in rules if r["enabled"] and hits.get(r["name"], 0) == 0]
    top = sorted(((hits.get(r["name"], 0), r["id"]) for r in rules),
                 reverse=True)[:5]
    return {
        "never_fired_enabled": never,
        "hint_never": "启用但从未命中：可复核是否过时或可禁用以降开销",
        "top_firing": [{"id": i, "hits": h} for h, i in top if h > 0],
        "hint_top": "命中量最高：若伴随大量放行流量，可能是误报来源，复核 patterns/阈值",
    }
