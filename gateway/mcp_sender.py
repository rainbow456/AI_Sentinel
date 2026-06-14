# -*- coding: utf-8 -*-
"""
Async Splunk HEC Sender
=======================
Ships security events to Splunk HTTP Event Collector (HEC) asynchronously
via httpx. Failures are logged only and never block the request path.

Env vars:
  SPLUNK_HEC_URL   -- HEC endpoint, e.g. https://splunk:8088/services/collector
  SPLUNK_HEC_TOKEN -- HEC token

Exposes a global singleton `sender`.
"""

# Load .env before reading env vars (module-scope os.getenv calls in __init__)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # .env takes precedence over env vars injected by the script/shell
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
# Logger
# ---------------------------------------------------------------------------
log = logging.getLogger("ai_sentinel.mcp_sender")


def _utcnow_iso() -> str:
    """Current UTC time in ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------


class SecurityEvent(BaseModel):
    """
    A single security event emitted by the gateway. `user_input` MUST be
    masked/desensitized by the caller before constructing this model.
    """

    # Unique event id; used on the Splunk side to dedupe under at-least-once delivery.
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex, description="Idempotency id")

    # Event timestamp (ISO-8601 UTC); auto-filled when not provided.
    timestamp: str = Field(default_factory=_utcnow_iso, description="ISO-8601 UTC timestamp")

    # Which module produced the log: input guard / action guard / skill scanner / rule admin / disposition.
    module: Literal[
        "input_guard", "action_guard", "skill_scanner", "rule_admin", "disposition"
    ] = Field(..., description="input_guard / action_guard / skill_scanner / rule_admin / disposition")

    # Whether intercepted: for guards this is an actual gateway block; for skill_scanner it means "judged malicious".
    blocked: bool = Field(False, description="True if intercepted (or judged malicious for skill_scanner)")

    # Handler: gateway = handled and enforced by the gateway itself / external = directed by an external source, conclusion handed back for external execution.
    handler: Literal["gateway", "external"] = Field(
        "gateway", description="gateway = self-enforced; external = directed by an external source"
    )

    # Top risk score (0-100); 0 when allowed.
    risk_score: int = Field(0, description="Top risk score 0-100")

    # Masked content under inspection (prompt / user_input / skill_content).
    user_input: str = Field("", description="Masked input under inspection")

    # Subject name being judged: action name / skill name; null if none.
    subject_name: Optional[str] = Field(None, description="Action name or skill name")

    # Caller agent identifier; null if none.
    agent_id: Optional[str] = Field(None, description="Caller agent id")

    # Unified hit list (merges the former hit and findings), with 6 fixed fields each.
    findings: List[Dict[str, Any]] = Field(
        default_factory=list, description="Unified detector hits")

    # Identifier of the gateway instance that produced the event.
    gateway_id: str = Field(..., description="Gateway instance id")

    # Downstream LLM provider name.
    llm_provider: Optional[str] = Field(None, description="Downstream LLM provider")

    # Gray-zone hold flag: gateway did not block but judged the request suspicious, pending analyst + human disposition.
    # The frontend agent must not execute before disposition (held). The analyst marks the alert as "held" and may resolve it.
    held: bool = Field(False, description="True if request is held pending analyst/human disposition")


# ---------------------------------------------------------------------------
# Async sender
# ---------------------------------------------------------------------------


class AsyncSender:
    """
    Reusable async client that POSTs SecurityEvent JSON to Splunk HEC.
    Lazily creates one httpx.AsyncClient and reuses it across calls.
    """

    def __init__(
        self,
        hec_url: Optional[str] = None,
        hec_token: Optional[str] = None,
        sourcetype: str = "ai_sentinel:gateway",
        timeout: float = 5.0,
        verify: Optional[bool] = None,
    ) -> None:
        # read config from args or environment.
        self.hec_url = hec_url or os.getenv("SPLUNK_HEC_URL")
        self.hec_token = hec_token or os.getenv("SPLUNK_HEC_TOKEN")
        self.sourcetype = sourcetype
        # target Splunk index. Events go to `main` (the default index the HEC
        # token can write to and that every role searches by default), so the
        # Analyst's log module finds them without extra index permissions.
        # Override with SPLUNK_HEC_INDEX to route to a dedicated index.
        self.index = os.getenv("SPLUNK_HEC_INDEX", "main")
        self.timeout = timeout
        # TLS verification toggle. Splunk HEC commonly uses a self-signed cert
        # on https://:8088, which makes httpx raise SSL errors by default.
        # Set SPLUNK_HEC_VERIFY=0 (or pass verify=False) to skip verification.
        if verify is None:
            verify = os.getenv("SPLUNK_HEC_VERIFY", "1") not in ("0", "false", "False", "no", "")
        self.verify = verify
        # HEC request channel (GUID). Required when the token has "Indexer
        # Acknowledgement" enabled; harmless (ignored) when it is off.
        # Stable per process; override with SPLUNK_HEC_CHANNEL.
        self.channel = os.getenv("SPLUNK_HEC_CHANNEL") or str(uuid.uuid4())
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def enabled(self) -> bool:
        """True only when both URL and token are configured."""
        return bool(self.hec_url and self.hec_token)

    def _get_client(self) -> httpx.AsyncClient:
        """Lazily build the shared async client."""
        if self._client is None or self._client.is_closed:
            # trust_env=False so httpx ignores HTTP(S)_PROXY env vars AND the
            # Windows system/registry proxy. Otherwise requests to a local HEC
            # (localhost:8088) get routed through a system proxy that returns 502.
            # The HEC endpoint is explicitly configured and never needs a proxy.
            self._client = httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify, trust_env=False
            )
        return self._client

    def _build_payload(self, event: SecurityEvent) -> Dict[str, Any]:
        """Wrap the event in the Splunk HEC envelope format."""
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
        POST a raw body (may contain multiple newline-separated HEC events).
        Returns True on 2xx, False on any failure (does not raise). Used by the
        reliable-delivery pipeline for batching/retries.
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
        """Send a single event. Returns True on 2xx, otherwise False (fail-soft, never blocks)."""
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
            # fail-soft -- log and swallow.
            log.error(
                "Failed to send event to Splunk HEC: %s",
                exc,
                extra={"module": event.module, "gateway_id": event.gateway_id},
            )
            return False

    async def aclose(self) -> None:
        """Close the underlying client (call on shutdown)."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()


# ---------------------------------------------------------------------------
# Spooling sink (reliable delivery pipeline)
# ---------------------------------------------------------------------------
class SpoolingSink:
    """
    Reliable delivery: in-memory queue + batching + retry backoff + disk spool fallback + graceful flush.

    - submit() is non-blocking and never slows the request path; spools to disk directly when the queue is full or the gateway is unconfigured.
    - A background worker batches and delivers; on failure it retries with exponential backoff, and on continued failure writes to the spool file.
    - Once Splunk recovers, the spool is replayed automatically (at-least-once, deduped on the Splunk side via event_id).
    - drain() delivers/spools the remaining queue on shutdown without losing data.
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
        self.spooled = 0  # cumulative spooled count (observable)

    async def start(self) -> None:
        """Call after app startup (once the event loop is ready) to build the queue and start the background worker."""
        if self.queue is None:
            self.queue = asyncio.Queue(maxsize=self.max_queue)
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    def submit(self, event: SecurityEvent) -> None:
        """Called from the request path: non-blocking enqueue; spools to disk if the queue is not ready or full."""
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
                if idle % 25 == 0:          # try replaying the backlog roughly every 5s to avoid hammering connections while idle
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
                await self._replay_spool()  # also replay any historical backlog
                return
            await asyncio.sleep(delay)
            delay = min(delay * 2, 8.0)
        self._spool(envs)  # still failing after multiple retries -> spool to disk as fallback

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
                break  # stop on the first failure, keep the rest for next time
            delivered = i + len(chunk)
        if delivered == 0:
            return  # no progress, so don't rewrite the file and avoid idle disk churn
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
        """Graceful shutdown: deliver/spool the remaining queued events, then stop the worker."""
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
# Global singletons
# ---------------------------------------------------------------------------
# Import and reuse these instances across the app.
sender = AsyncSender()
sink = SpoolingSink(sender)
