# -*- coding: utf-8 -*-
"""
Async Splunk HEC Sender / 异步 Splunk HEC 发送器
================================================
EN: Ships security events to Splunk HTTP Event Collector (HEC) asynchronously
    via httpx. Failures are logged only and never block the request path.
中文：通过 httpx 异步将安全事件发送到 Splunk HTTP Event Collector (HEC)。
    发送失败只记录错误日志，绝不阻塞请求主流程。

Env vars / 环境变量:
  SPLUNK_HEC_URL   -- HEC endpoint, e.g. https://splunk:8088/services/collector
  SPLUNK_HEC_TOKEN -- HEC token

Exposes a global singleton `sender`. / 暴露全局单例 `sender`。
"""

# Load .env before reading env vars (module-scope os.getenv calls in __init__)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env 优先于脚本/shell 注入的同名环境变量
except ImportError:
    pass

import os
import json
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal

import httpx
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logger / 日志
# ---------------------------------------------------------------------------
log = logging.getLogger("ai_sentinel.mcp_sender")


def _utcnow_iso() -> str:
    """EN: Current UTC time in ISO-8601. / 中文：当前 UTC 时间（ISO-8601）。"""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Event model / 事件模型
# ---------------------------------------------------------------------------


class SecurityEvent(BaseModel):
    """
    EN: A single security event emitted by the gateway. `user_input` MUST be
        masked/desensitized by the caller before constructing this model.
    中文：网关产生的一条安全事件。`user_input` 必须由调用方在构造前完成脱敏。
    """

    # 事件唯一 ID；至少一次投递时在 Splunk 侧用它去重。
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex, description="Idempotency id")

    # 事件时间戳（ISO-8601 UTC），不传时自动填充。
    timestamp: str = Field(default_factory=_utcnow_iso, description="ISO-8601 UTC timestamp")

    # 哪个模块产生的日志：输入守卫 / 动作守卫 / skill 扫描 / 规则管理 / 处置。
    module: Literal[
        "input_guard", "action_guard", "skill_scanner", "rule_admin", "disposition"
    ] = Field(..., description="input_guard / action_guard / skill_scanner / rule_admin / disposition")

    # 是否已拦截：守卫类为网关实际拦截；skill_scanner 为「判定恶意即 true」。
    blocked: bool = Field(False, description="True if intercepted (or judged malicious for skill_scanner)")

    # 处理者：gateway 自己处理并执行 / external 外部源下指令、结论交回外部执行。
    handler: Literal["gateway", "external"] = Field(
        "gateway", description="gateway = self-enforced; external = directed by an external source"
    )

    # 最高风险分（0-100）；放行为 0。
    risk_score: int = Field(0, description="Top risk score 0-100")

    # 脱敏后的被检内容（prompt / user_input / skill_content）。
    user_input: str = Field("", description="Masked input under inspection")

    # 被判对象名：动作名 / skill 名；无则为 null。
    subject_name: Optional[str] = Field(None, description="Action name or skill name")

    # 调用方 Agent 标识；无则为 null。
    agent_id: Optional[str] = Field(None, description="Caller agent id")

    # 统一的命中列表（合并原 hit 与 findings），每条固定 6 字段。
    findings: List[Dict[str, Any]] = Field(
        default_factory=list, description="Unified detector hits")

    # 产生事件的网关实例标识。
    gateway_id: str = Field(..., description="Gateway instance id")

    # 下游 LLM 提供方名称。
    llm_provider: Optional[str] = Field(None, description="Downstream LLM provider")


# ---------------------------------------------------------------------------
# Async sender / 异步发送器
# ---------------------------------------------------------------------------


class AsyncSender:
    """
    EN: Reusable async client that POSTs SecurityEvent JSON to Splunk HEC.
        Lazily creates one httpx.AsyncClient and reuses it across calls.
    中文：可复用的异步客户端，将 SecurityEvent 的 JSON POST 到 Splunk HEC。
        懒加载一个 httpx.AsyncClient 并在多次调用间复用。
    """

    def __init__(
        self,
        hec_url: Optional[str] = None,
        hec_token: Optional[str] = None,
        sourcetype: str = "ai_sentinel:gateway",
        timeout: float = 5.0,
        verify: Optional[bool] = None,
    ) -> None:
        # EN: read config from args or environment. / 中文：从参数或环境变量读取配置。
        self.hec_url = hec_url or os.getenv("SPLUNK_HEC_URL")
        self.hec_token = hec_token or os.getenv("SPLUNK_HEC_TOKEN")
        self.sourcetype = sourcetype
        # EN: target Splunk index. Events go to `main` (the default index the HEC
        #     token can write to and that every role searches by default), so the
        #     Analyst's log module finds them without extra index permissions.
        #     Override with SPLUNK_HEC_INDEX to route to a dedicated index.
        # 中文：目标 Splunk 索引。事件写入 `main`（HEC token 默认可写、且所有角色默认
        #     都会搜索的索引），Analyst 日志模块无需额外索引权限即可查到。
        #     如需专属索引，用 SPLUNK_HEC_INDEX 覆盖。
        self.index = os.getenv("SPLUNK_HEC_INDEX", "main")
        self.timeout = timeout
        # EN: TLS verification toggle. Splunk HEC commonly uses a self-signed cert
        #     on https://:8088, which makes httpx raise SSL errors by default.
        #     Set SPLUNK_HEC_VERIFY=0 (or pass verify=False) to skip verification.
        # 中文：TLS 校验开关。Splunk HEC 默认在 https://:8088 用自签证书，
        #     httpx 默认会因证书校验失败而报错。设 SPLUNK_HEC_VERIFY=0（或传 verify=False）跳过。
        if verify is None:
            verify = os.getenv("SPLUNK_HEC_VERIFY", "1") not in ("0", "false", "False", "no", "")
        self.verify = verify
        # EN: HEC request channel (GUID). Required when the token has "Indexer
        #     Acknowledgement" enabled; harmless (ignored) when it is off.
        #     Stable per process; override with SPLUNK_HEC_CHANNEL.
        # 中文：HEC 请求 channel（GUID）。当 token 开启「索引确认」时必须携带；
        #     未开启时 Splunk 会忽略，无副作用。进程内固定，可用 SPLUNK_HEC_CHANNEL 覆盖。
        self.channel = os.getenv("SPLUNK_HEC_CHANNEL") or str(uuid.uuid4())
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def enabled(self) -> bool:
        """EN: True only when both URL and token are configured. / 中文：仅当 URL 与 token 均配置时为真。"""
        return bool(self.hec_url and self.hec_token)

    def _get_client(self) -> httpx.AsyncClient:
        """EN: Lazily build the shared async client. / 中文：懒加载共享异步客户端。"""
        if self._client is None or self._client.is_closed:
            # EN: trust_env=False so httpx ignores HTTP(S)_PROXY env vars AND the
            #     Windows system/registry proxy. Otherwise requests to a local HEC
            #     (localhost:8088) get routed through a system proxy that returns 502.
            #     The HEC endpoint is explicitly configured and never needs a proxy.
            # 中文：trust_env=False 让 httpx 忽略 HTTP(S)_PROXY 环境变量以及 Windows
            #     系统/注册表代理。否则发往本地 HEC(localhost:8088) 的请求会被系统代理
            #     拦截并返回 502。HEC 地址是显式配置的，本就不需要走代理。
            self._client = httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify, trust_env=False
            )
        return self._client

    def _build_payload(self, event: SecurityEvent) -> Dict[str, Any]:
        """将事件封装为 Splunk HEC 信封格式。"""
        payload: Dict[str, Any] = {
            "sourcetype": self.sourcetype,
            "event": event.model_dump(),
        }
        if self.index:
            payload["index"] = self.index
        return payload

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
            "X-Splunk-Request-Channel": self.channel,
        }

    async def post_body(self, body: str) -> bool:
        """
        POST 一段原始 body（可含多条以换行分隔的 HEC 事件）。2xx 返回 True，
        任何失败返回 False（不抛异常）。供可靠投递管线批量/重试使用。
        """
        if not self.enabled:
            return False
        try:
            resp = await self._get_client().post(
                self.hec_url, headers=self._headers(), content=body)
            resp.raise_for_status()
            return True
        except Exception:
            return False

    async def send(self, event: SecurityEvent) -> bool:
        """发送单条事件。2xx 返回 True，否则 False（失败软处理，绝不阻塞）。"""
        if not self.enabled:
            log.debug("Splunk HEC not configured, skip sending",
                      extra={"module": event.module})
            return False
        try:
            client = self._get_client()
            resp = await client.post(
                self.hec_url,
                headers=self._headers(),
                content=json.dumps(self._build_payload(event), ensure_ascii=False),
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            # EN: fail-soft -- log and swallow. / 中文：失败软处理 —— 记录并吞掉异常。
            log.error(
                "Failed to send event to Splunk HEC: %s",
                exc,
                extra={"module": event.module, "gateway_id": event.gateway_id},
            )
            return False

    async def aclose(self) -> None:
        """EN: Close the underlying client (call on shutdown). / 中文：关闭底层客户端（在应用关闭时调用）。"""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()


# ---------------------------------------------------------------------------
# 可靠投递管线 / Spooling sink
# ---------------------------------------------------------------------------
class SpoolingSink:
    """
    可靠投递：内存队列 + 批量 + 重试退避 + 磁盘 spool 兜底 + 优雅 flush。

    - submit() 非阻塞，绝不拖慢请求路径；队列满或网关未配置时直接落盘。
    - 后台 worker 攒批投递；失败指数退避重试，仍失败则落盘 spool 文件。
    - Splunk 恢复后自动回放 spool（至少一次，靠 event_id 在 Splunk 侧去重）。
    - drain() 在关闭时把队列剩余投递/落盘，不丢数据。
    """

    def __init__(self, sender: "AsyncSender", spool_path: Optional[str] = None,
                 max_queue: int = 10000, batch_size: int = 100,
                 flush_interval: float = 2.0, max_retries: int = 4):
        self.sender = sender
        self.spool_path = spool_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "splunk_spool.jsonl")
        self.max_queue = max_queue
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.queue: Optional[asyncio.Queue] = None
        self._task: Optional[asyncio.Task] = None
        self._stop = False
        self.spooled = 0  # 累计落盘条数（可观测）

    async def start(self) -> None:
        """在应用启动（事件循环就绪）后调用，建队列、起后台 worker。"""
        if self.queue is None:
            self.queue = asyncio.Queue(maxsize=self.max_queue)
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    def submit(self, event: SecurityEvent) -> None:
        """请求路径调用：非阻塞入队；队列未就绪/已满则落盘。"""
        env = self.sender._build_payload(event)
        if self.queue is None:
            self._spool([env]); return
        try:
            self.queue.put_nowait(env)
        except asyncio.QueueFull:
            self._spool([env])

    async def _run(self) -> None:
        idle = 0
        while not self._stop:
            batch = await self._collect()
            if batch:
                await self._deliver(batch)
                idle = 0
            else:
                idle += 1
                if idle % 25 == 0:          # 每 ~5s 尝试回放一次积压，避免空转狂连
                    await self._replay_spool()
                await asyncio.sleep(0.2)

    async def _collect(self) -> List[Dict[str, Any]]:
        batch: List[Dict[str, Any]] = []
        try:
            batch.append(await asyncio.wait_for(self.queue.get(), timeout=self.flush_interval))
        except asyncio.TimeoutError:
            return batch
        while len(batch) < self.batch_size:
            try:
                batch.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    async def _deliver(self, envs: List[Dict[str, Any]]) -> None:
        if not self.sender.enabled:
            self._spool(envs); return
        body = "\n".join(json.dumps(e, ensure_ascii=False) for e in envs)
        delay = 0.5
        for _ in range(self.max_retries):
            if await self.sender.post_body(body):
                await self._replay_spool()  # 顺手回放历史积压
                return
            await asyncio.sleep(delay)
            delay = min(delay * 2, 8.0)
        self._spool(envs)  # 多次重试仍失败 → 落盘兜底

    def _spool(self, envs: List[Dict[str, Any]]) -> None:
        try:
            with open(self.spool_path, "a", encoding="utf-8") as f:
                for e in envs:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            self.spooled += len(envs)
        except Exception as exc:  # pragma: no cover
            log.error("Spool write failed: %s", exc)

    async def _replay_spool(self) -> None:
        if not self.sender.enabled or not os.path.exists(self.spool_path):
            return
        try:
            with open(self.spool_path, encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
        except Exception:
            return
        if not lines:
            return
        delivered = 0
        for i in range(0, len(lines), self.batch_size):
            chunk = lines[i:i + self.batch_size]
            if not await self.sender.post_body("\n".join(chunk)):
                break  # 首次失败即停，保留剩余下次再试
            delivered = i + len(chunk)
        if delivered == 0:
            return  # 无进展就别重写文件，避免空转磁盘 churn
        remaining = lines[delivered:]
        try:
            if remaining:
                with open(self.spool_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(remaining) + "\n")
            else:
                os.remove(self.spool_path)
        except Exception:  # pragma: no cover
            pass

    async def drain(self) -> None:
        """优雅关闭：投递/落盘队列剩余事件，停 worker。"""
        self._stop = True
        leftover: List[Dict[str, Any]] = []
        if self.queue is not None:
            while True:
                try:
                    leftover.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
        if leftover:
            await self._deliver(leftover)
        if self._task is not None:
            self._task.cancel()


# ---------------------------------------------------------------------------
# Global singletons / 全局单例
# ---------------------------------------------------------------------------
# EN: Import and reuse these instances across the app. / 中文：在应用各处导入并复用。
sender = AsyncSender()
sink = SpoolingSink(sender)
