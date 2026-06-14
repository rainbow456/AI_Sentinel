# -*- coding: utf-8 -*-
"""
Hold store (gray-zone request suspension)
===========================
When the gateway decides a request is "not blocked but suspicious" (gray zone),
it neither passes it through nor hard-blocks it; instead it **holds** the request
(held) for analyst + human review. After receiving `held`, the front-end agent
**must not execute** and should poll this store until a verdict is reached
(released / blocked). Once the analyst completes the disposition, the hold is
resolved through a gateway HTTP endpoint.

Design:
  - In-process in-memory dict + lock (a hold is a short-lived state; losing it on
    restart is acceptable; resolve is accessed in-process via gateway HTTP).
  - key = SecurityEvent.event_id (naturally aligned with the event reported to
    Splunk and the analyst alert, so the same id can be used to resolve during
    manual disposition).
  - Security posture: **never auto-release**. A hold not dispositioned within the
    TTL stays pending (an agent poll timeout keeps it un-executed = continued
    blocking); only an oversized-TTL memory cleanup runs to prevent unbounded growth.

State machine: pending -> released | blocked (terminal, idempotent)
"""

import threading
import time
from typing import Any, Dict, Optional

# Oversized TTL: used only for memory cleanup (leak prevention), NOT an
# "auto-release on timeout". Defaults to 1 hour.
_TTL_S = 3600.0
_MAX = 4096


class _HoldStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # id -> {status, decision, reason, operator, created, resolved_at, meta}
        self._d: Dict[str, Dict[str, Any]] = {}

    def create(self, hold_id: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Register a hold (pending). Re-creating the same id does not overwrite an existing terminal state."""
        now = time.time()
        with self._lock:
            self._gc_locked(now)
            existing = self._d.get(hold_id)
            if existing and existing.get("status") != "pending":
                return dict(existing)  # already terminal, do not roll back
            rec = existing or {
                "hold_id": hold_id, "status": "pending", "decision": None,
                "reason": "", "operator": "", "created": now,
                "resolved_at": None, "meta": meta or {},
            }
            self._d[hold_id] = rec
            return dict(rec)

    def get(self, hold_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._d.get(hold_id)
            return dict(rec) if rec else None

    def resolve(self, hold_id: str, decision: str, reason: str = "",
                operator: str = "") -> Optional[Dict[str, Any]]:
        """Move a hold to a terminal state. decision: 'release' | 'block'. Idempotent: returns as-is if already terminal."""
        if decision not in ("release", "block"):
            return None
        status = "released" if decision == "release" else "blocked"
        with self._lock:
            rec = self._d.get(hold_id)
            if rec is None:
                return None
            if rec.get("status") != "pending":
                return dict(rec)  # already terminal, idempotent
            rec.update(status=status, decision=decision, reason=reason or "",
                       operator=operator or "", resolved_at=time.time())
            self._d[hold_id] = rec
            return dict(rec)

    def list_pending(self) -> list[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._d.values() if r.get("status") == "pending"]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            out = {"pending": 0, "released": 0, "blocked": 0, "total": len(self._d)}
            for r in self._d.values():
                out[r.get("status", "pending")] = out.get(r.get("status", "pending"), 0) + 1
            return out

    def _gc_locked(self, now: float) -> None:
        if len(self._d) <= _MAX:
            # Routine cleanup: drop terminal records past the TTL (pending is never deleted by TTL).
            stale = [k for k, r in self._d.items()
                     if r.get("status") != "pending"
                     and now - (r.get("resolved_at") or r.get("created", now)) > _TTL_S]
            for k in stale:
                self._d.pop(k, None)
            return
        # Cap-hit fallback: evict the oldest terminal records by creation time.
        finals = sorted(((r.get("created", 0.0), k) for k, r in self._d.items()
                         if r.get("status") != "pending"))
        for _, k in finals[: _MAX // 4]:
            self._d.pop(k, None)


# In-process singleton
STORE = _HoldStore()


def create_hold(hold_id: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return STORE.create(hold_id, meta)


def get_hold(hold_id: str) -> Optional[Dict[str, Any]]:
    return STORE.get(hold_id)


def resolve_hold(hold_id: str, decision: str, reason: str = "",
                 operator: str = "") -> Optional[Dict[str, Any]]:
    return STORE.resolve(hold_id, decision, reason, operator)


def hold_stats() -> Dict[str, int]:
    return STORE.stats()
