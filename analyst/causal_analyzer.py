"""
Causal Tree Analyzer — decision tree building and emergent anomaly detection.
Extracted from agent.py to keep individual files under 600 lines.
"""

from collections import Counter
from datetime import datetime
from typing import Optional

from .models import (
    AnomalyType,
    CausalNode,
    DecisionTree,
    EmergentAnomaly,
    NodeType,
    Span,
)


def build_decision_tree(spans: list[Span]) -> DecisionTree:
    """Build a causal decision tree from a list of Spans."""
    if not spans:
        return DecisionTree(trace_id="empty", metadata={"agent_count": 0})
    trace_id = spans[0].trace_id
    node_map: dict[str, CausalNode] = {}
    for span in spans:
        node_map[span.span_id] = CausalNode(span=span)
    root_nodes = []
    for span in spans:
        node = node_map[span.span_id]
        pid = span.parent_span_id
        if pid and pid in node_map:
            node_map[pid].children.append(node)
        else:
            node.is_root = True
            node.depth = 0
            root_nodes.append(node)
    for root in root_nodes:
        _compute_depth(root, 0)
    for node in node_map.values():
        node.children.sort(key=lambda c: c.span.timestamp or datetime.min)
    root_nodes.sort(key=lambda r: r.span.timestamp or datetime.min)
    all_walked = []
    for root in root_nodes:
        all_walked.extend(root.walk())
    agent_ids = {s.agent_id for s in spans}
    metadata = {
        "agent_count": len(agent_ids),
        "total_steps": len(spans),
        "time_span_seconds": (
            (max(s.timestamp for s in spans if s.timestamp) -
             min(s.timestamp for s in spans if s.timestamp)).total_seconds()
            if len(spans) >= 2 else 0
        ),
        "agent_ids": sorted(agent_ids),
        "trace_id": trace_id,
        "key_node_count": sum(1 for n in all_walked
            if n.node_type in (NodeType.DELEGATION, NodeType.ERROR, NodeType.MESSAGE)),
    }
    return DecisionTree(trace_id=trace_id, root_nodes=root_nodes,
                        node_map=node_map, all_spans=spans, metadata=metadata)


def _compute_depth(node: CausalNode, depth: int):
    node.depth = depth
    for child in node.children:
        _compute_depth(child, depth + 1)


def identify_key_nodes(tree: DecisionTree) -> list[CausalNode]:
    """Identify key nodes (errors, delegations, messages, tool calls, roots)."""
    all_nodes = tree.walk_all()
    errors = [n for n in all_nodes if n.node_type == NodeType.ERROR]
    delegations = [n for n in all_nodes if n.node_type == NodeType.DELEGATION]
    messages = [n for n in all_nodes if n.node_type == NodeType.MESSAGE]
    tool_calls = [n for n in all_nodes if n.node_type == NodeType.TOOL_CALL]
    roots = [n for n in all_nodes if n.is_root
             and n not in errors + delegations + messages + tool_calls]
    ks = lambda n: n.span.timestamp or datetime.min
    return (sorted(errors, key=ks) + sorted(delegations, key=ks) +
            sorted(messages, key=ks) + sorted(tool_calls, key=ks) +
            sorted(roots, key=ks))


def detect_emergence(tree: DecisionTree) -> list[EmergentAnomaly]:
    """Detect emergent anomalies in a decision tree."""
    anomalies = []
    all_nodes = tree.walk_all()

    for node in all_nodes:
        if node.span.message_to and not node.span.is_registered_action:
            anomalies.append(EmergentAnomaly(
                anomaly_type=AnomalyType.UNAUTHORIZED_COMMUNICATION, severity="high",
                description=f"Agent [{node.span.agent_id}] privately notified [{node.span.message_to}]",
                involved_span_ids=[node.span.span_id],
                evidence=f"action='{node.span.action}' is not in the standard action set",
                agent_ids=[node.span.agent_id, node.span.message_to],
            ))

    neg = Counter()
    neg_spans: dict[tuple, list[str]] = {}
    for node in all_nodes:
        if node.span.message_to:
            key = (node.span.agent_id, node.span.message_to, node.span.action)
            neg[key] += 1
            neg_spans.setdefault(key, []).append(node.span.span_id)
    for (a, b, act), cnt in neg.items():
        if cnt > 3:
            anomalies.append(EmergentAnomaly(
                anomaly_type=AnomalyType.EXCESSIVE_NEGOTIATION, severity="medium",
                description=f"Agent [{a}] repeatedly negotiated with [{b}] {cnt} times via '{act}'",
                involved_span_ids=neg_spans[(a, b, act)],
                evidence=f"x{cnt}", agent_ids=[a, b],
            ))

    for node in all_nodes:
        if node.span.metadata.get("rule_bypass"):
            anomalies.append(EmergentAnomaly(
                anomaly_type=AnomalyType.RULE_BYPASS, severity="high",
                description=f"Agent [{node.span.agent_id}] bypassed the workflow",
                involved_span_ids=[node.span.span_id],
                evidence=node.span.metadata.get("bypass_detail", ""),
                agent_ids=[node.span.agent_id],
            ))

    for node in all_nodes:
        if node.span.is_error and not node.span.metadata.get("correction_of"):
            anomalies.append(EmergentAnomaly(
                anomaly_type=AnomalyType.REASONING_ERROR, severity="high",
                description=f"Agent [{node.span.agent_id}] reasoning error",
                involved_span_ids=[node.span.span_id],
                evidence=f"error={node.span.metadata.get('error_detail', '')}",
                agent_ids=[node.span.agent_id],
            ))

    for node in all_nodes:
        if node.span.metadata.get("collusion_indicator"):
            anomalies.append(EmergentAnomaly(
                anomaly_type=AnomalyType.COLLUSION, severity="critical",
                description=f"Agent [{node.span.agent_id}] suspected of colluding with [{node.span.message_to or '?'}]",
                involved_span_ids=[node.span.span_id],
                evidence=node.span.metadata.get("collusion_detail", ""),
                agent_ids=[node.span.agent_id, node.span.message_to or "unknown"],
            ))

    return anomalies


def generate_storyline(tree: DecisionTree) -> str:
    """Generate a brief storyline from a decision tree."""
    timeline = tree.get_timeline()
    if not timeline:
        return "(empty decision tree)"
    agents = tree.metadata.get("agent_ids", [])
    return f"{len(agents)} agents total: {', '.join(agents)}, {tree.total_steps} steps."