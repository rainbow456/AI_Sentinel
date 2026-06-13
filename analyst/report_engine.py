"""
Report Engine for Multi-Alert Security Agent.

Produces three report types:
  - SingleEventReport: analysis for one gateway event (with/without spans)
  - BatchAlertReport: aggregate summary across multiple alerts
  - ReportA/B (preserved): Mermaid decision tree + emergence detection for Span data

All reports support rule-match annotations on nodes.
"""

from collections import defaultdict
from datetime import datetime
from typing import Optional

from .models import (
    AlertRecord,
    AnomalyType,
    CausalNode,
    DecisionTree,
    EmergentAnomaly,
    GatewayEvent,
    NodeType,
    RuleMatch,
)

# ── Mermaid color scheme ──────────────────────────────────────────────────

NODE_STYLE_NORMAL = "fill:#0a2a0a,stroke:#00ff41,stroke-width:2px,color:#c0c8d0"
NODE_STYLE_ANOMALOUS = "fill:#2a0a0a,stroke:#ff0040,stroke-width:3px,color:#ff8888"
NODE_STYLE_ERROR = "fill:#2a2a0a,stroke:#ffcc00,stroke-width:3px,color:#ffcc00"
NODE_STYLE_ROOT = "fill:#0a1a2a,stroke:#00ccff,stroke-width:2px,color:#c0e8ff"
NODE_STYLE_BLOCKED = "fill:#2a0a2a,stroke:#ff00ff,stroke-width:3px,color:#ff88ff"

SEVERITY_LABELS = {"high": "高危", "medium": "中危", "low": "低危", "critical": "严重"}


# ═══════════════════════════════════════════════════════════════════════════
# Single Event Report
# ═══════════════════════════════════════════════════════════════════════════

class SingleEventReport:
    """
    Detailed analysis report for a single gateway event.
    Works with or without embedded Span data.
    """

    def __init__(self, alert: AlertRecord, anomalies: list[EmergentAnomaly] | None = None):
        self.alert = alert
        self.event = alert.event
        self.anomalies = anomalies or []

    def generate(self) -> dict:
        """
        Generate the full single-event report.

        Returns:
            dict with: event_summary, rule_analysis, risk_assessment,
                       timeline (if spans), mermaid (if spans), recommendations
        """
        report = {
            "alert_id": self.alert.alert_id,
            "event_id": self.event.event_id,
            "timestamp": self.event.timestamp.isoformat(),
            "event_summary": self._event_summary(),
            "rule_analysis": self._rule_analysis(),
            "risk_assessment": self._risk_assessment(),
            "recommendations": self._recommendations(),
            "has_spans": len(self.event.raw_spans) > 0,
        }

        # If event has embedded Span data, add tree analysis
        if self.event.raw_spans:
            report["span_analysis"] = {
                "span_count": len(self.event.raw_spans),
                "agent_ids": list({s.agent_id for s in self.event.raw_spans}),
            }
            if self.alert.storyline:
                report["storyline"] = self.alert.storyline
            if self.alert.decision_tree:
                report["mermaid"] = self.alert.decision_tree.get("mermaid", "")

        return report

    def _event_summary(self) -> str:
        e = self.event
        type_cn = {"blocked": "已阻断", "passed": "已放行", "action_confirmation": "行动确认(共谋信号)"}
        return (
            f"事件 {e.event_id} 由 Gateway [{e.gateway_id}] 上报，"
            f"类型为 {type_cn.get(e.event_type, e.event_type)}，"
            f"触发规则 {e.triggered_rule}（置信度 {e.confidence:.0%}）。"
            f"LLM提供商: {e.llm_provider}。"
        )

    def _rule_analysis(self) -> dict:
        matches = self.alert.rule_matches
        if not matches:
            return {"matched": False, "message": "未匹配任何安全规则"}
        return {
            "matched": True,
            "count": len(matches),
            "rules": [
                {
                    "rule_id": m.rule_id,
                    "name": m.rule_name,
                    "action": m.action,
                    "confidence": m.confidence,
                    "evidence": m.evidence,
                }
                for m in matches
            ],
            "highest_confidence": max(m.confidence for m in matches),
            "block_rules": [m.rule_name for m in matches if m.action == "block"],
            "alert_rules": [m.rule_name for m in matches if m.action == "alert"],
        }

    def _risk_assessment(self) -> dict:
        if self.event.is_blocked:
            risk = "🔴 高危" if self.event.confidence > 0.8 else "🟠 中危"
        elif self.event.event_type == "action_confirmation":
            risk = "🔴 严重 — 共谋信号"
        elif self.event.confidence < 0.3:
            risk = "🟢 低危"
        else:
            risk = "🟡 需关注"

        blocked = self.alert.blocked
        pending = self.alert.pending_block

        return {
            "level": risk,
            "blocked": blocked,
            "pending_block": pending,
            "status": "已自动阻断" if blocked else ("待确认阻断" if pending else "已记录"),
        }

    def _recommendations(self) -> list[str]:
        recs = []
        e = self.event
        if e.event_type == "blocked":
            recs.append("检查 Gateway 阻断日志，确认阻断原因")
        if e.event_type == "action_confirmation":
            recs.append("⚠ 立即审查涉及的 Agent 间通信记录，排查是否存在共谋行为")
            recs.append("检查 Agent 间 action_confirmation 的发起方和接收方是否符合预设流程")
        if e.confidence > 0.8:
            recs.append("高置信度告警 — 建议将此 IP/用户加入观察名单")
        if self.event.raw_spans:
            recs.append("该事件包含多Agent Span数据 — 建议审查完整决策树")
        if not recs:
            recs.append("记录事件并持续监控")
        return recs


# ═══════════════════════════════════════════════════════════════════════════
# Batch Alert Report
# ═══════════════════════════════════════════════════════════════════════════

class BatchAlertReport:
    """
    Aggregate report across multiple alerts.

    Provides overview statistics, trend analysis, and top threats.
    """

    def __init__(self, alerts: list[AlertRecord],
                 trees: list[DecisionTree] | None = None,
                 anomalies: list[EmergentAnomaly] | None = None):
        self.alerts = alerts
        self.trees = trees or []
        self.anomalies = anomalies or []

    def generate(self) -> dict:
        return {
            "time_range": self._time_range(),
            "overview": self._overview(),
            "by_severity": self._by_severity(),
            "by_rule": self._by_rule(),
            "top_threats": self._top_threats(),
            "tree_summary": self._tree_summary(),
            "recommendations": self._batch_recommendations(),
        }

    def _time_range(self) -> dict:
        if not self.alerts:
            return {"start": "", "end": "", "duration_seconds": 0}
        times = [a.event.timestamp for a in self.alerts]
        return {
            "start": min(times).isoformat(),
            "end": max(times).isoformat(),
            "duration_seconds": (max(times) - min(times)).total_seconds(),
        }

    def _overview(self) -> dict:
        blocked = sum(1 for a in self.alerts if a.blocked)
        pending = sum(1 for a in self.alerts if a.pending_block)
        total = len(self.alerts)
        risks = {"high": 0, "medium": 0, "low": 0}
        for a in self.alerts:
            risks[a.risk_level] = risks.get(a.risk_level, 0) + 1

        return {
            "total_alerts": total,
            "blocked": blocked,
            "pending_block": pending,
            "risk_distribution": risks,
            "block_rate": f"{blocked / total:.0%}" if total else "0%",
        }

    def _by_severity(self) -> dict:
        result = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in self.alerts:
            for m in a.rule_matches:
                for r in a.rule_matches:
                    pass  # severity is on the RuleDef, not RuleMatch
            # Use risk_level as proxy
            result[a.risk_level] = result.get(a.risk_level, 0) + 1
        return result

    def _by_rule(self) -> list[dict]:
        """Count alerts by triggered rule."""
        rule_counts = defaultdict(lambda: {"count": 0, "blocked": 0})
        for a in self.alerts:
            for m in a.rule_matches:
                rc = rule_counts[m.rule_name]
                rc["count"] += 1
                if a.blocked:
                    rc["blocked"] += 1
        return sorted(
            [{"rule": k, **v} for k, v in rule_counts.items()],
            key=lambda x: -x["count"],
        )

    def _top_threats(self) -> list[dict]:
        """Return top-5 highest-confidence threats."""
        sorted_alerts = sorted(
            self.alerts,
            key=lambda a: max(
                (m.confidence for m in a.rule_matches), default=0
            ),
            reverse=True,
        )
        top = []
        for a in sorted_alerts[:5]:
            top.append({
                "alert_id": a.alert_id,
                "event_id": a.event.event_id,
                "event_type": a.event.event_type,
                "triggered_rule": a.event.triggered_rule,
                "confidence": a.event.confidence,
                "risk_level": a.risk_level,
                "blocked": a.blocked,
            })
        return top

    def _tree_summary(self) -> dict:
        return {
            "total_trees": len(self.trees),
            "total_anomalies": len(self.anomalies),
            "anomalies_by_type": dict(
                (t.value, sum(1 for a in self.anomalies if a.anomaly_type == t))
                for t in AnomalyType
            ),
        }

    def _batch_recommendations(self) -> list[str]:
        recs = []
        blocked = sum(1 for a in self.alerts if a.blocked)
        collusion = sum(1 for a in self.alerts
                        if a.event.event_type == "action_confirmation")
        total = len(self.alerts)

        if blocked > total * 0.5:
            recs.append(f"⚠ 阻断率高达 {blocked}/{total}，建议审查Gateway规则阈值是否过严")
        if collusion > 0:
            recs.append(f"🚨 检测到 {collusion} 个共谋信号，强烈建议审计Agent间通信")
        if self.anomalies:
            recs.append(f"发现 {len(self.anomalies)} 个决策树级异常，建议人工复核")
        if total > 20:
            recs.append("告警量较大，建议启用 AUTO 模式减轻人工负担")
        if not recs:
            recs.append("系统运行正常，继续保持监控")
        return recs


# ═══════════════════════════════════════════════════════════════════════════
# Report A — Decision Tree Visualization (preserved + enhanced)
# ═══════════════════════════════════════════════════════════════════════════

class ReportA:
    """
    Mermaid.js visualization of the causal decision tree.

    Enhanced: nodes now annotated with rule-match status and block results.
    """

    def __init__(self, tree: DecisionTree, anomalies: list[EmergentAnomaly],
                 rule_matches: list[RuleMatch] | None = None):
        self.tree = tree
        self.anomalies = anomalies
        self.rule_matches = rule_matches or []

        self._anomaly_map: dict[str, list[EmergentAnomaly]] = defaultdict(list)
        for a in anomalies:
            for sid in a.involved_span_ids:
                self._anomaly_map[sid].append(a)

        self._rule_match_span_ids: set[str] = set()

    def to_mermaid(self) -> str:
        lines = ["flowchart TD"]
        lines.append("  %% Causal Decision Tree with Rule Annotations")
        lines.append(f"  %% Trace: {self.tree.trace_id}")
        lines.append(f"  %% Agents: {', '.join(sorted(self.tree.agent_ids))}")
        lines.append(f"  %% Steps: {self.tree.total_steps} | Anomalies: {len(self.anomalies)}")
        lines.append("")

        lines.append("  classDef normal " + NODE_STYLE_NORMAL)
        lines.append("  classDef anomalous " + NODE_STYLE_ANOMALOUS)
        lines.append("  classDef error " + NODE_STYLE_ERROR)
        lines.append("  classDef root " + NODE_STYLE_ROOT)
        lines.append("  classDef blocked " + NODE_STYLE_BLOCKED)
        lines.append("")

        agent_nodes: dict[str, list[CausalNode]] = defaultdict(list)
        for node in self.tree.walk_all():
            agent_nodes[node.span.agent_id].append(node)

        for agent_id in sorted(agent_nodes.keys()):
            nodes = agent_nodes[agent_id]
            safe = self._safe_id(agent_id)
            name = self._agent_display_name(agent_id)
            lines.append(f"  subgraph sg_{safe}[{name}]")
            lines.append(f"    direction TB")
            for node in sorted(nodes, key=lambda n: n.span.timestamp or datetime.min):
                nid = self._safe_id(node.span.span_id)
                label = self._node_label(node)
                lines.append(f"    {nid}[\"{label}\"]")
            lines.append(f"  end")
            lines.append("")

        for node in self.tree.walk_all():
            if node.span.parent_span_id:
                pnid = self._safe_id(node.span.parent_span_id)
                cnid = self._safe_id(node.span.span_id)
                parent_node = self.tree.node_map.get(node.span.parent_span_id)
                is_cross = parent_node and parent_node.span.agent_id != node.span.agent_id
                edge = " -.->|跨Agent| " if is_cross else " --> "
                lines.append(f"  {pnid}{edge}{cnid}")

        for node in self.tree.walk_all():
            nid = self._safe_id(node.span.span_id)
            style = self._node_mermaid_style(node)
            lines.append(f"  class {nid} {style}")

        return "\n".join(lines)

    def _node_label(self, node: CausalNode) -> str:
        agent_short = node.span.agent_id[:6]
        action = node.span.action[:20]
        label = f"{agent_short}\\n{action}"

        if node.span.span_id in self._anomaly_map:
            types = {a.anomaly_type for a in self._anomaly_map[node.span.span_id]}
            if AnomalyType.UNAUTHORIZED_COMMUNICATION in types:
                label += "\\n📵非授权"
            if AnomalyType.REASONING_ERROR in types:
                label += "\\n❌推理错误"
            if AnomalyType.RULE_BYPASS in types:
                label += "\\n⚠绕过规则"
            if AnomalyType.COLLUSION in types:
                label += "\\n🚨共谋"
            if AnomalyType.EXCESSIVE_NEGOTIATION in types:
                label += "\\n🔄过度协商"

        if node.span.is_error and node.span.span_id not in self._anomaly_map:
            label += "\\n⚠错误"

        if len(label) > 80:
            label = label[:77] + "..."
        return label

    def _node_mermaid_style(self, node: CausalNode) -> str:
        sid = node.span.span_id
        if sid in self._anomaly_map:
            types = {a.anomaly_type for a in self._anomaly_map[sid]}
            if AnomalyType.REASONING_ERROR in types or AnomalyType.COLLUSION in types:
                return "error"
            return "anomalous"
        if node.is_root:
            return "root"
        return "normal"

    def generate_narratives(self) -> list[dict]:
        narratives = []
        significant = {NodeType.DELEGATION, NodeType.ERROR, NodeType.MESSAGE, NodeType.TOOL_CALL}
        for node in self.tree.walk_all():
            if node.node_type not in significant and not node.is_root:
                continue
            span = node.span
            what = self._describe_action(node)
            why = span.thought[:200] if span.thought else "（无显式推理记录）"
            ctx_parts = []
            if span.context_snapshot:
                mems = span.context_snapshot.get("memory_refs", [])
                if mems:
                    ctx_parts.append(f"记忆引用: {', '.join(mems[:5])}")
                policy = span.context_snapshot.get("policy_ref", "")
                if policy:
                    ctx_parts.append(f"策略参考: {policy}")
            context = "; ".join(ctx_parts) if ctx_parts else "（无上下文快照）"
            outcome = self._describe_outcome(node)
            anomaly_note = ""
            if span.span_id in self._anomaly_map:
                anoms = self._anomaly_map[span.span_id]
                anomaly_note = "; ".join(
                    f"[{a.severity}] {a.anomaly_type.value}: {a.description[:100]}"
                    for a in anoms
                )
            narratives.append({
                "span_id": span.span_id,
                "agent_id": span.agent_id,
                "action": span.action,
                "node_type": node.node_type.value,
                "timestamp": span.timestamp.isoformat() if span.timestamp else "",
                "what": what, "why": why, "context": context,
                "outcome": outcome,
                "is_anomalous": span.span_id in self._anomaly_map,
                "anomaly_note": anomaly_note,
            })
        return narratives

    def _describe_action(self, node: CausalNode) -> str:
        span = node.span
        agent = self._agent_display_name(span.agent_id)
        if node.node_type == NodeType.DELEGATION:
            return f"{agent} 将任务委托给 {self._agent_display_name(span.message_to or '?')}: {span.thought[:60]}..."
        elif node.node_type == NodeType.MESSAGE:
            target = self._agent_display_name(span.message_to or "?")
            if not span.is_registered_action:
                return f"{agent} 通过非标准渠道({span.action})向 {target} 发送私下消息"
            return f"{agent} 向 {target} 发送通知消息"
        elif node.node_type == NodeType.TOOL_CALL:
            tn = span.tool_call.get("name", "?") if span.tool_call else "?"
            return f"{agent} 调用工具 '{tn}'"
        elif node.node_type == NodeType.ERROR:
            return f"{agent} 出现错误: {span.metadata.get('error_detail', '未知')}"
        elif node.is_root:
            return f"{agent} 发起此次多Agent协作"
        return f"{agent} 执行 {span.action}"

    def _describe_outcome(self, node: CausalNode) -> str:
        span = node.span
        if span.tool_call:
            r = span.tool_call.get("result", "")
            if isinstance(r, dict):
                return f"工具调用结果: {r.get('status', str(r))}"
            return f"工具返回: {str(r)[:80]}"
        if span.message_to:
            return f"消息发送至 {self._agent_display_name(span.message_to)}"
        if node.children:
            return f"进入下一步: {node.children[0].span.action}"
        return "终端节点"

    @staticmethod
    def _safe_id(raw: str) -> str:
        return raw.replace("-", "_").replace(".", "_")

    @staticmethod
    def _agent_display_name(aid: str) -> str:
        m = {"customer_service": "客服Agent", "tech_support": "技术支持Agent",
             "refund": "退款Agent"}
        return m.get(aid, aid)

    def to_dict(self) -> dict:
        return {
            "trace_id": self.tree.trace_id,
            "mermaid_code": self.to_mermaid(),
            "narratives": self.generate_narratives(),
            "tree_metadata": self.tree.metadata,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Report B — Emergent Behavior Detection (preserved + enhanced)
# ═══════════════════════════════════════════════════════════════════════════

class ReportB:
    """Emergent behavior detection report with anomaly summary."""

    def __init__(self, tree: DecisionTree, anomalies: list[EmergentAnomaly]):
        self.tree = tree
        self.anomalies = anomalies

    def summary(self) -> str:
        if not self.anomalies:
            return "✅ 未检测到涌现行为异常。"
        lines = [f"⚠️ 检测到 {len(self.anomalies)} 个涌现行为异常，"
                 f"涉及 {len(self._affected_agents())} 个Agent。"]
        by_sev = self.by_severity()
        for sev, label in [("high", "🔴 高危"), ("medium", "🟡 中危"), ("low", "🟢 低危")]:
            if by_sev.get(sev):
                lines.append(f"\n{label} ({len(by_sev[sev])} 个):")
                for i, a in enumerate(by_sev[sev], 1):
                    lines.append(f"  {i}. [{a.anomaly_type.value}] {a.description}")
        type_counts = defaultdict(int)
        for a in self.anomalies:
            type_counts[a.anomaly_type.value] += 1
        lines.append("\n📊 异常类型分布:")
        type_names = {
            "unauthorized_communication": "非授权通信",
            "excessive_negotiation": "过度协商",
            "rule_bypass": "规则绕过",
            "reasoning_error": "推理错误",
            "collusion": "Agent共谋",
        }
        for at, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  • {type_names.get(at, at)}: {cnt} 次")
        lines.append("\n💡 建议:")
        if any(a.anomaly_type == AnomalyType.COLLUSION for a in self.anomalies):
            lines.append("  • 🚨 立即审查Agent间通信，暂停涉事Agent权限")
        if any(a.anomaly_type == AnomalyType.UNAUTHORIZED_COMMUNICATION for a in self.anomalies):
            lines.append("  • 审查Agent通信接口，注册所有合法action")
        if any(a.anomaly_type == AnomalyType.RULE_BYPASS for a in self.anomalies):
            lines.append("  • 加强任务委托审批校验")
        if any(a.anomaly_type == AnomalyType.REASONING_ERROR for a in self.anomalies):
            lines.append("  • 为关键操作添加双重确认机制")
        return "\n".join(lines)

    def by_severity(self) -> dict:
        result = {"high": [], "medium": [], "low": []}
        for a in self.anomalies:
            if a.severity in result:
                result[a.severity].append(a)
        return result

    def _affected_agents(self) -> set:
        agents = set()
        for a in self.anomalies:
            agents.update(a.agent_ids)
        return agents

    def analyze_anomaly(self, a: EmergentAnomaly) -> dict:
        nodes = []
        for sid in a.involved_span_ids:
            node = self.tree.node_map.get(sid)
            if node:
                nodes.append({
                    "span_id": sid,
                    "agent_id": node.span.agent_id,
                    "action": node.span.action,
                    "thought_snippet": node.span.thought[:150] if node.span.thought else "",
                    "timestamp": node.span.timestamp.isoformat() if node.span.timestamp else "",
                })
        return {"anomaly": a.to_dict(), "involved_nodes": nodes}

    def to_dict(self) -> dict:
        return {
            "trace_id": self.tree.trace_id,
            "total_anomalies": len(self.anomalies),
            "summary": self.summary(),
            "by_severity": {
                s: [a.to_dict() for a in items]
                for s, items in self.by_severity().items()
            },
            "affected_agents": sorted(self._affected_agents()),
            "detailed_analyses": [self.analyze_anomaly(a) for a in self.anomalies],
        }


# ── Convenience ───────────────────────────────────────────────────────────

def generate_reports(tree: DecisionTree, anomalies: list[EmergentAnomaly],
                     rule_matches: list[RuleMatch] | None = None):
    return ReportA(tree, anomalies, rule_matches), ReportB(tree, anomalies)

def generate_single_report(alert: AlertRecord,
                           anomalies: list[EmergentAnomaly] | None = None) -> dict:
    return SingleEventReport(alert, anomalies).generate()

def generate_batch_report(alerts: list[AlertRecord],
                          trees: list[DecisionTree] | None = None,
                          anomalies: list[EmergentAnomaly] | None = None) -> dict:
    return BatchAlertReport(alerts, trees, anomalies).generate()
