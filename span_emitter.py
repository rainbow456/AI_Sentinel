# -*- coding: utf-8 -*-
"""
Span Emitter — 方案 A 阶段 1（最小版）

代表"被监控的多 Agent 受害系统"向 Splunk 上报 OpenTelemetry 风格的 Span。
把内置的 3-Agent 退款共谋场景(analyst/demo_spans.DEMO_SPANS)作为 span 来源，
以新 sourcetype `ai_sentinel:span` 经 HEC 写入 Splunk —— 与网关安全事件同一条管线。

这样 span 数据是【真实流经 Splunk】的；唯一仍是脚本的是"场景生成器"本身，
后续把它换成真实的 LLM 多 Agent 编排即可，下游(Analyst 摄取/建树/涌现检测)不用改。

用法:
  python span_emitter.py                 # 上报默认场景(trace-refund-001)
  python span_emitter.py --trace my-001  # 覆盖 trace_id（同时改写 span 的 trace_id）

环境变量(复用网关 HEC 配置):
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

# Windows 控制台 GBK 兜底：emoji 不致崩
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

_proj = os.path.dirname(os.path.abspath(__file__))
if _proj not in sys.path:
    sys.path.insert(0, _proj)

from analyst.demo_spans import DEMO_SPANS  # 场景来源（脚本，可替换为真实 swarm）

SOURCETYPE = "ai_sentinel:span"


def _hec_cfg():
    url = (os.getenv("SPLUNK_HEC_URL") or "http://localhost:8088/services/collector").strip()
    token = (os.getenv("SPLUNK_HEC_TOKEN") or "").strip()
    index = (os.getenv("SPLUNK_HEC_INDEX") or "main").strip()
    verify = os.getenv("SPLUNK_HEC_VERIFY", "0") not in ("0", "false", "False", "no", "")
    return url, token, index, verify


def _span_to_event(s, trace_id_override=None) -> dict:
    """把 Span 序列化成可上报、可被 Analyst 还原的扁平 JSON。"""
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


def emit(trace_id_override=None) -> int:
    url, token, index, verify = _hec_cfg()
    if not token:
        print("ERROR: SPLUNK_HEC_TOKEN 未配置，无法上报 span", file=sys.stderr)
        return 0
    ctx = None
    if url.startswith("https") and not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    sent = 0
    for s in DEMO_SPANS:
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
            print(f"  span {s.span_id} 上报失败: {e}", file=sys.stderr)
    tid = trace_id_override or (DEMO_SPANS[0].trace_id if DEMO_SPANS else "?")
    print(f"已上报 {sent}/{len(DEMO_SPANS)} 个 span 到 Splunk "
          f"(sourcetype={SOURCETYPE}, index={index}, trace_id={tid})")
    return sent


def main():
    ap = argparse.ArgumentParser(description="Emit multi-agent spans to Splunk HEC")
    ap.add_argument("--trace", default=None, help="覆盖 trace_id")
    args = ap.parse_args()
    emit(args.trace)


if __name__ == "__main__":
    main()
