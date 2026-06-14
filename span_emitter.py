# -*- coding: utf-8 -*-
"""
Span Emitter — Plan A, Stage 1 (minimal version)

Acts as the "monitored multi-agent victim system" and reports OpenTelemetry-style
spans to Splunk. It uses the built-in 3-agent refund-collusion scenario
(analyst/demo_spans.DEMO_SPANS) as the span source and writes them to Splunk via HEC
under the new sourcetype `ai_sentinel:span` — the same pipeline as gateway security
events.

This way the span data really flows through Splunk; the only part that is still a
script is the "scenario generator" itself. Later it can be replaced with a real LLM
multi-agent orchestration without changing anything downstream (Analyst ingestion /
tree building / emergence detection).

Usage:
  python span_emitter.py                 # report the default scenario (trace-refund-001)
  python span_emitter.py --trace my-001  # override trace_id (also rewrites each span's trace_id)

Environment variables (reuse the gateway HEC config):
  SPLUNK_HEC_URL / SPLUNK_HEC_TOKEN / SPLUNK_HEC_INDEX / SPLUNK_HEC_VERIFY
"""

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

import argparse
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime

# Windows console GBK fallback: don't crash on emoji
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

_proj = os.path.dirname(os.path.abspath(__file__))
if _proj not in sys.path:
    sys.path.insert(0, _proj)

from analyst.demo_spans import DEMO_SPANS  # scenario source (a script; can be swapped for a real swarm)

SOURCETYPE = "ai_sentinel:span"


def _hec_cfg():
    url = (os.getenv("SPLUNK_HEC_URL") or "http://localhost:8088/services/collector").strip()
    token = (os.getenv("SPLUNK_HEC_TOKEN") or "").strip()
    index = (os.getenv("SPLUNK_HEC_INDEX") or "main").strip()
    verify = os.getenv("SPLUNK_HEC_VERIFY", "0") not in ("0", "false", "False", "no", "")
    return url, token, index, verify


def _span_to_event(s, trace_id_override=None) -> dict:
    """Serialize a Span into flat JSON that can be reported and reconstructed by the Analyst."""
    return {
        "trace_id": trace_id_override or s.trace_id,
        "span_id": s.span_id,
        "parent_span_id": s.parent_span_id,
        "agent_id": s.agent_id,
        "action": s.action,
        "thought": s.thought,
        "tool_call": s.tool_call,
        "message_to": s.message_to,
        "message_content": s.message_content,
        "timestamp": (s.timestamp or datetime.now()).isoformat(),
        "causality_chain": s.causality_chain,
        "context_snapshot": s.context_snapshot,
        "metadata": s.metadata,
    }


def emit_spans(spans, trace_id_override=None) -> int:
    """Report an arbitrary list of Spans to Splunk HEC (sourcetype=ai_sentinel:span).

    This is the shared sink used by the built-in refund demo AND by
    traffic_generator.py's collusion / negotiation scenarios.
    """
    url, token, index, verify = _hec_cfg()
    if not token:
        print("ERROR: SPLUNK_HEC_TOKEN not configured; cannot report spans", file=sys.stderr)
        return 0
    ctx = None
    if url.startswith("https") and not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    sent = 0
    for s in spans:
        envelope = {"sourcetype": SOURCETYPE, "index": index,
                    "event": _span_to_event(s, trace_id_override)}
        data = json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=6.0, context=ctx) as resp:
                if 200 <= resp.status < 300:
                    sent += 1
        except Exception as e:
            print(f"  span {s.span_id} failed to report: {e}", file=sys.stderr)
    return sent


def _scenarios() -> dict:
    """Registry of all span scenarios: {trace_id: [Span, ...]}.

    The refund demo lives in analyst.demo_spans; the collusion / negotiation
    scenarios live in traffic_generator.py (imported lazily to avoid a hard dep).
    """
    reg = {"trace-refund-001": list(DEMO_SPANS)}
    try:
        import traffic_generator
        reg.update(traffic_generator.get_span_scenarios())
    except Exception as e:
        print(f"  (collusion/negotiation scenarios unavailable: {e})", file=sys.stderr)
    return reg


# Logical scenario name → trace_id.
_NAME_TO_TRACE = {
    "refund": "trace-refund-001",
    "collusion": "trace-collusion-001",
    "negotiation": "trace-negotiation-001",
}


def emit(trace_id_override=None) -> int:
    """Backwards-compatible entry point: emit the built-in refund demo."""
    _, _, index, _ = _hec_cfg()
    sent = emit_spans(DEMO_SPANS, trace_id_override)
    tid = trace_id_override or (DEMO_SPANS[0].trace_id if DEMO_SPANS else "?")
    print(f"Reported {sent}/{len(DEMO_SPANS)} spans to Splunk "
          f"(sourcetype={SOURCETYPE}, index={index}, trace_id={tid})")
    return sent


def main():
    ap = argparse.ArgumentParser(description="Emit multi-agent spans to Splunk HEC")
    ap.add_argument("--scenario", default="refund",
                    choices=["refund", "collusion", "negotiation", "all"],
                    help="Which span scenario to emit (default: refund demo)")
    ap.add_argument("--trace", default=None,
                    help="override trace_id (only valid with a single scenario)")
    args = ap.parse_args()

    _, _, index, _ = _hec_cfg()
    reg = _scenarios()
    if args.scenario == "all":
        names = ["refund", "collusion", "negotiation"]
    else:
        names = [args.scenario]

    total = 0
    for nm in names:
        tid = _NAME_TO_TRACE[nm]
        spans = reg.get(tid)
        if not spans:
            print(f"  scenario '{nm}' ({tid}) unavailable; skipped", file=sys.stderr)
            continue
        override = args.trace if (args.trace and len(names) == 1) else tid
        sent = emit_spans(spans, override)
        total += sent
        print(f"Reported {sent}/{len(spans)} spans to Splunk "
              f"(sourcetype={SOURCETYPE}, index={index}, trace_id={override})")
    return total


if __name__ == "__main__":
    main()
