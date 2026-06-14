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

SEVERITY_LABELS = {"high": "High", "medium": "Medium", "low": "Low", "critical": "Critical"}


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
            "log_detail": self._log_detail(),        # Raw log detail (requirement 1)
            "dispositions": self._dispositions(),     # Per-rule actionable disposition plans (requirement 2)
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
                if self.alert.decision_tree.get("emergence_summary"):
                    report["emergence"] = self.alert.decision_tree["emergence_summary"]

        return report

    def _event_summary(self) -> str:
        e = self.event
        type_cn = {"blocked": "Blocked", "passed": "Passed", "action_confirmation": "Action confirmation (collusion signal)"}
        return (
            f"Event {e.event_id} reported by Gateway [{e.gateway_id}], "
            f"type {type_cn.get(e.event_type, e.event_type)}, "
            f"triggered rule {e.triggered_rule} (confidence {e.confidence:.0%}). "
            f"LLM provider: {e.llm_provider}."
        )

    def _rule_analysis(self) -> dict:
        matches = self.alert.rule_matches
        if not matches:
            return {"matched": False, "message": "No security rules matched"}
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
            risk = "🔴 High" if self.event.confidence > 0.8 else "🟠 Medium"
        elif self.event.event_type == "action_confirmation":
            risk = "🔴 Critical — collusion signal"
        elif self.event.confidence < 0.3:
            risk = "🟢 Low"
        else:
            risk = "🟡 Needs attention"

        blocked = self.alert.blocked
        pending = self.alert.pending_block

        return {
            "level": risk,
            "blocked": blocked,
            "pending_block": pending,
            "status": "Auto-blocked" if blocked else ("Block pending confirmation" if pending else "Logged"),
        }

    def _recommendations(self) -> list[str]:
        recs = []
        e = self.event
        if e.event_type == "blocked":
            recs.append("Review the Gateway block log to confirm the block reason")
        if e.event_type == "action_confirmation":
            recs.append("⚠ Immediately review inter-agent communication records and investigate possible collusion")
            recs.append("Verify that the sender and receiver of inter-agent action_confirmation match the expected flow")
        if e.confidence > 0.8:
            recs.append("High-confidence alert — recommend adding this IP/user to the watchlist")
        if self.event.raw_spans:
            recs.append("This event contains multi-agent span data — recommend reviewing the full decision tree")
        if not recs:
            recs.append("Log the event and continue monitoring")
        return recs

    def _log_detail(self) -> dict:
        """Raw log detail (requirement 1): full inspected content + each finding."""
        e = self.event
        findings = []
        for f in (e.findings or []):
            if isinstance(f, dict):
                findings.append({
                    "detector": f.get("detector", ""),
                    "rule_hit": f.get("rule_hit", ""),
                    "severity": f.get("severity", ""),
                    "owasp_ast": f.get("owasp_ast", ""),
                    "matched": f.get("matched", ""),
                    "description": f.get("description", ""),
                })
            else:
                findings.append({
                    "detector": getattr(f, "detector", ""),
                    "rule_hit": getattr(f, "rule_hit", ""),
                    "severity": getattr(f, "severity", ""),
                    "owasp_ast": getattr(f, "owasp_ast", ""),
                    "matched": getattr(f, "matched", ""),
                    "description": getattr(f, "description", ""),
                })
        return {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "module": e.module,
            "blocked": e.blocked,
            "handler": e.handler,
            "risk_score": e.risk_score,
            "user_input": e.user_input,
            "subject_name": e.subject_name,
            "agent_id": e.agent_id,
            "gateway_id": e.gateway_id,
            "llm_provider": e.llm_provider,
            "findings": findings,
        }

    def _dispositions(self) -> list[dict]:
        """Actionable disposition plans per matched rule (requirement 2).
        Events already blocked at the gateway source produce no disposition plans —
        the analyst only previews the alert, so the dashboard's "Execute Disposition"
        button disappears accordingly."""
        if getattr(self.alert.event, "blocked", False):
            return []
        from .disposition_planner import plans_for_alert
        return plans_for_alert(self.alert)


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
            recs.append(f"⚠ Block rate is as high as {blocked}/{total}; review whether Gateway rule thresholds are too strict")
        if collusion > 0:
            recs.append(f"🚨 Detected {collusion} collusion signals; strongly recommend auditing inter-agent communication")
        if self.anomalies:
            recs.append(f"Found {len(self.anomalies)} decision-tree-level anomalies; recommend manual review")
        if total > 20:
            recs.append("High alert volume; recommend enabling AUTO mode to reduce manual workload")
        if not recs:
            recs.append("System operating normally; continue monitoring")
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
                edge = " -.->|cross-agent| " if is_cross else " --> "
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
                label += "\\n📵Unauthorized"
            if AnomalyType.REASONING_ERROR in types:
                label += "\\n❌Reasoning error"
            if AnomalyType.RULE_BYPASS in types:
                label += "\\n⚠Rule bypass"
            if AnomalyType.COLLUSION in types:
                label += "\\n🚨Collusion"
            if AnomalyType.EXCESSIVE_NEGOTIATION in types:
                label += "\\n🔄Excessive negotiation"

        if node.span.is_error and node.span.span_id not in self._anomaly_map:
            label += "\\n⚠Error"

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
            why = span.thought[:200] if span.thought else "(no explicit reasoning recorded)"
            ctx_parts = []
            if span.context_snapshot:
                mems = span.context_snapshot.get("memory_refs", [])
                if mems:
                    ctx_parts.append(f"Memory refs: {', '.join(mems[:5])}")
                policy = span.context_snapshot.get("policy_ref", "")
                if policy:
                    ctx_parts.append(f"Policy ref: {policy}")
            context = "; ".join(ctx_parts) if ctx_parts else "(no context snapshot)"
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
            return f"{agent} delegated the task to {self._agent_display_name(span.message_to or '?')}: {span.thought[:60]}..."
        elif node.node_type == NodeType.MESSAGE:
            target = self._agent_display_name(span.message_to or "?")
            if not span.is_registered_action:
                return f"{agent} sent a private message to {target} via a non-standard channel ({span.action})"
            return f"{agent} sent a notification message to {target}"
        elif node.node_type == NodeType.TOOL_CALL:
            tn = span.tool_call.get("name", "?") if span.tool_call else "?"
            return f"{agent} called tool '{tn}'"
        elif node.node_type == NodeType.ERROR:
            return f"{agent} encountered an error: {span.metadata.get('error_detail', 'unknown')}"
        elif node.is_root:
            return f"{agent} initiated this multi-agent collaboration"
        return f"{agent} executed {span.action}"

    def _describe_outcome(self, node: CausalNode) -> str:
        span = node.span
        if span.tool_call:
            r = span.tool_call.get("result", "")
            if isinstance(r, dict):
                return f"Tool call result: {r.get('status', str(r))}"
            return f"Tool returned: {str(r)[:80]}"
        if span.message_to:
            return f"Message sent to {self._agent_display_name(span.message_to)}"
        if node.children:
            return f"Proceeded to next step: {node.children[0].span.action}"
        return "Terminal node"

    @staticmethod
    def _safe_id(raw: str) -> str:
        return raw.replace("-", "_").replace(".", "_")

    @staticmethod
    def _agent_display_name(aid: str) -> str:
        m = {"customer_service": "Customer Service Agent", "tech_support": "Tech Support Agent",
             "refund": "Refund Agent"}
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
            return "✅ No emergent behavior anomalies detected."
        lines = [f"⚠️ Detected {len(self.anomalies)} emergent behavior anomalies, "
                 f"involving {len(self._affected_agents())} agents."]
        by_sev = self.by_severity()
        for sev, label in [("high", "🔴 High"), ("medium", "🟡 Medium"), ("low", "🟢 Low")]:
            if by_sev.get(sev):
                lines.append(f"\n{label} ({len(by_sev[sev])}):")
                for i, a in enumerate(by_sev[sev], 1):
                    lines.append(f"  {i}. [{a.anomaly_type.value}] {a.description}")
        type_counts = defaultdict(int)
        for a in self.anomalies:
            type_counts[a.anomaly_type.value] += 1
        lines.append("\n📊 Anomaly type distribution:")
        type_names = {
            "unauthorized_communication": "Unauthorized communication",
            "excessive_negotiation": "Excessive negotiation",
            "rule_bypass": "Rule bypass",
            "reasoning_error": "Reasoning error",
            "collusion": "Agent collusion",
        }
        for at, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  • {type_names.get(at, at)}: {cnt}")
        lines.append("\n💡 Recommendations:")
        if any(a.anomaly_type == AnomalyType.COLLUSION for a in self.anomalies):
            lines.append("  • 🚨 Immediately review inter-agent communication and suspend the involved agents' permissions")
        if any(a.anomaly_type == AnomalyType.UNAUTHORIZED_COMMUNICATION for a in self.anomalies):
            lines.append("  • Review agent communication interfaces and register all legitimate actions")
        if any(a.anomaly_type == AnomalyType.RULE_BYPASS for a in self.anomalies):
            lines.append("  • Strengthen task-delegation approval checks")
        if any(a.anomaly_type == AnomalyType.REASONING_ERROR for a in self.anomalies):
            lines.append("  • Add a dual-confirmation mechanism for critical operations")
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
