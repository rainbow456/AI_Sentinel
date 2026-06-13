# -*- coding: utf-8 -*-
"""
规则管理 API / Rule management API
=================================
给外部安全分析 agent 查询与修改检测规则。所有写操作经校验 + 自带测试门禁，
版本自增并留历史，且把改动审计上报 Splunk（module=rule_admin, handler=external）。
"""

# Load .env before reading env vars at module scope
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import os
import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

try:
    from gateway.rule_store import RuleStore, RuleError
    from gateway.mcp_sender import sender, SecurityEvent
    from gateway.middlewares import rule_engine
except Exception:  # pragma: no cover
    from rule_store import RuleStore, RuleError
    from mcp_sender import sender, SecurityEvent
    from middlewares import rule_engine

GATEWAY_ID = os.getenv("GATEWAY_ID", "gateway-01")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

store = RuleStore()
router = APIRouter(prefix="/rules", tags=["rules"])
_BG: set = set()


def _audit(actor: str, action: str, rule_id: str, detail: str = ""):
    """把规则改动作为一条 rule_admin 事件异步上报 Splunk。"""
    ev = SecurityEvent(
        module="rule_admin", blocked=False, handler="external", risk_score=0,
        user_input=f"{action} {rule_id} {detail}".strip(),
        subject_name=rule_id, agent_id=actor, findings=[],
        gateway_id=GATEWAY_ID, llm_provider=LLM_PROVIDER,
    )
    try:
        t = asyncio.create_task(sender.send(ev))
        _BG.add(t)
        t.add_done_callback(_BG.discard)
    except RuntimeError:
        pass


class RuleIn(BaseModel):
    id: str
    name: str
    category: str = ""
    owasp_ast: str = ""
    severity_score: int = 50
    engine: str = "regex"
    patterns: List[str] = Field(default_factory=list)
    flags: List[str] = Field(default_factory=lambda: ["IGNORECASE"])
    enabled: bool = True
    tags: List[str] = Field(default_factory=list)
    description_zh: str = ""
    test_cases: Dict[str, List[str]] = Field(default_factory=dict)


class TestIn(BaseModel):
    samples: List[str] = Field(default_factory=list)


# ---- 查询 ----
@router.get("")
def list_rules(category: Optional[str] = None, enabled: Optional[bool] = None,
               tag: Optional[str] = None, q: Optional[str] = None):
    return {"count": store.count(), "rules": store.list(category, enabled, tag, q)}


@router.get("/{rid}")
def get_rule(rid: str):
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "规则不存在")
    return r


# ---- 校验（dry-run，不写库）----
@router.post("/validate")
def validate_rule(rule: RuleIn):
    data = rule.model_dump()
    try:
        store.validate(data)
    except RuleError as e:
        return {"valid": False, "error": str(e), "test": None}
    return {"valid": True, "error": None, "test": store.run_tests(data)}


# ---- 新增 / 修改 ----
@router.post("")
def create_rule(rule: RuleIn, actor: str = "external-agent"):
    try:
        saved = store.upsert(rule.model_dump(), actor=actor)
    except RuleError as e:
        raise HTTPException(400, str(e))
    rule_engine.reload()
    _audit(actor, "create", saved["id"], f"v{saved['version']}")
    return saved


@router.put("/{rid}")
def update_rule(rid: str, rule: RuleIn, actor: str = "external-agent"):
    data = rule.model_dump()
    data["id"] = rid
    try:
        saved = store.upsert(data, actor=actor)
    except RuleError as e:
        raise HTTPException(400, str(e))
    rule_engine.reload()
    _audit(actor, "update", rid, f"v{saved['version']}")
    return saved


# ---- 启停 ----
@router.patch("/{rid}/enable")
def enable_rule(rid: str, actor: str = "external-agent"):
    try:
        r = store.set_enabled(rid, True, actor)
    except RuleError as e:
        raise HTTPException(404, str(e))
    rule_engine.reload()
    _audit(actor, "enable", rid)
    return r


@router.patch("/{rid}/disable")
def disable_rule(rid: str, actor: str = "external-agent"):
    try:
        r = store.set_enabled(rid, False, actor)
    except RuleError as e:
        raise HTTPException(404, str(e))
    rule_engine.reload()
    _audit(actor, "disable", rid)
    return r


# ---- 删除 ----
@router.delete("/{rid}")
def delete_rule(rid: str, actor: str = "external-agent"):
    if not store.delete(rid, actor):
        raise HTTPException(404, "规则不存在")
    rule_engine.reload()
    _audit(actor, "delete", rid)
    return {"deleted": rid}


# ---- 对某规则试跑样本 ----
@router.post("/{rid}/test")
def test_rule(rid: str, body: TestIn):
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "规则不存在")
    import re
    pats = [re.compile(p, re.I) for p in r.get("patterns", [])]
    results = [{"sample": s, "matched": any(p.search(s) for p in pats)} for s in body.samples]
    return {"rule": rid, "results": results, "self_test": store.run_tests(r)}


# ---- 版本 / 回滚 ----
@router.get("/{rid}/versions")
def rule_versions(rid: str):
    return {"id": rid, "versions": store.versions(rid)}


@router.post("/{rid}/rollback/{version}")
def rollback_rule(rid: str, version: int, actor: str = "external-agent"):
    try:
        r = store.rollback(rid, version, actor)
    except RuleError as e:
        raise HTTPException(400, str(e))
    rule_engine.reload()
    _audit(actor, "rollback", rid, f"->v{version}")
    return r


# ---- 热加载 ----
@router.post("/reload")
def reload_engine():
    n = rule_engine.reload()
    return {"reloaded": True, "active_rules": n}
