"""
Core data models for the Multi-Agent Causal Decision Tree Observability platform.

Models the OpenTelemetry-style Span data emitted by a multi-agent system,
the causal decision tree built from those spans, and emergent behavior anomalies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ── Span — the atomic unit of observability ───────────────────────────────

@dataclass
class Span:
    """
    Represents a single operation within a multi-agent trace.

    Mirrors OpenTelemetry Span structure with agent-specific extensions
    for chain-of-thought, tool calls, and inter-agent messaging.
    """
    agent_id: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    action: str
    thought: str                          # Chain-of-thought reasoning (Chinese)
    tool_call: Optional[dict] = None      # {"name": str, "params": dict, "result": any}
    message_to: Optional[str] = None      # Target agent_id if this span sends a message
    message_content: Optional[str] = None # Message body
    timestamp: Optional[datetime] = None
    causality_chain: list[str] = field(default_factory=list)  # Ordered ancestor span_ids
    context_snapshot: Optional[dict] = None  # {"memory_refs": [...], "policy_ref": "..."}
    metadata: dict = field(default_factory=dict)  # {"error": bool, "registered_action": bool, ...}

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if not self.causality_chain:
            self.causality_chain = []
        if not self.metadata:
            self.metadata = {}

    @property
    def is_error(self) -> bool:
        return self.metadata.get("error", False)

    @property
    def is_registered_action(self) -> bool:
        """Whether this action is in the system's registered action set."""
        return self.metadata.get("registered_action", True)

    @property
    def has_message(self) -> bool:
        return self.message_to is not None and self.message_content is not None


# ── Node types for the decision tree ──────────────────────────────────────

class NodeType(str, Enum):
    THINKING = "thinking"        # Agent reasoning step (has thought content)
    TOOL_CALL = "tool_call"      # Agent invoked a tool
    MESSAGE = "message"          # Inter-agent message passing
    DELEGATION = "delegation"    # Task delegation to another agent
    ERROR = "error"              # Root-cause error node


# ── CausalNode — wraps a Span into the decision tree ──────────────────────

@dataclass
class CausalNode:
    """
    A node in the causal decision tree. Wraps a Span and maintains
    parent-child relationships to form the tree structure.
    """
    span: Span
    children: list["CausalNode"] = field(default_factory=list)
    depth: int = 0
    is_root: bool = False
    node_type: NodeType = NodeType.THINKING

    def __post_init__(self):
        self._classify_node_type()

    def _classify_node_type(self):
        """Determine the node's semantic type from its span data."""
        if self.span.is_error:
            self.node_type = NodeType.ERROR
        elif self.span.has_message:
            if "delegate" in self.span.action.lower() or "assign" in self.span.action.lower():
                self.node_type = NodeType.DELEGATION
            else:
                self.node_type = NodeType.MESSAGE
        elif self.span.tool_call:
            self.node_type = NodeType.TOOL_CALL
        else:
            self.node_type = NodeType.THINKING

    @property
    def is_anomalous(self) -> bool:
        """Quick check: is this node associated with anomalous behavior?"""
        if self.node_type == NodeType.ERROR:
            return True
        if self.node_type == NodeType.MESSAGE and not self.span.is_registered_action:
            return True
        return False

    def walk(self) -> list["CausalNode"]:
        """Depth-first traversal of the subtree rooted at this node."""
        result = [self]
        for child in sorted(self.children, key=lambda c: c.span.timestamp or datetime.min):
            result.extend(child.walk())
        return result


# ── DecisionTree — the assembled causal structure ─────────────────────────

@dataclass
class DecisionTree:
    """
    A complete causal decision tree for one multi-agent trace.

    Built by grouping spans by trace_id and linking them via parent_span_id.
    """
    trace_id: str
    root_nodes: list[CausalNode] = field(default_factory=list)
    node_map: dict[str, CausalNode] = field(default_factory=dict)
    all_spans: list[Span] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def agent_ids(self) -> set[str]:
        return {s.agent_id for s in self.all_spans}

    @property
    def total_steps(self) -> int:
        return len(self.all_spans)

    @property
    def time_span_seconds(self) -> float:
        if len(self.all_spans) < 2:
            return 0.0
        timestamps = [s.timestamp for s in self.all_spans if s.timestamp]
        if len(timestamps) < 2:
            return 0.0
        return (max(timestamps) - min(timestamps)).total_seconds()

    def get_node(self, span_id: str) -> Optional[CausalNode]:
        return self.node_map.get(span_id)

    def walk_all(self) -> list[CausalNode]:
        """Depth-first traversal of the entire forest."""
        result = []
        for root in sorted(self.root_nodes, key=lambda r: r.span.timestamp or datetime.min):
            result.extend(root.walk())
        return result

    def get_timeline(self) -> list[CausalNode]:
        """All nodes sorted by timestamp (chronological order)."""
        return sorted(self.walk_all(), key=lambda n: n.span.timestamp or datetime.min)


# ── Agent operation mode ──────────────────────────────────────────────────

class AgentMode(str, Enum):
    AUTO = "auto"        # Auto-block threats
    OBSERVE = "observe"  # Alert only, wait for human confirmation


# ── Gateway event (real data structure from CSV) ────────────────────────

@dataclass
class Finding:
    """A single detection finding from a gateway security module."""
    detector: str = ""
    rule_hit: str = ""
    owasp_ast: str = ""
    severity: str = "medium"   # critical / high / medium / low
    matched: str = ""
    description: str = ""


@dataclass
class GatewayEvent:
    """
    Security event reported by a gateway, matching real CSV data structure.

    Core fields:
      event_id, timestamp, module, blocked, handler, risk_score,
      user_input, subject_name, agent_id, findings[], gateway_id, llm_provider
    """
    event_id: str
    timestamp: datetime
    module: str                # "input_guard" | "disposition" | "skill_scanner" | "rule_admin"
    blocked: bool              # true = blocked, false = passed
    handler: str               # "gateway" | "external"
    risk_score: int = 0
    user_input: str = ""
    subject_name: str = ""
    agent_id: str = ""
    findings: list = field(default_factory=list)  # list of Finding or dict
    gateway_id: str = "gateway-01"
    llm_provider: str = "anthropic"
    held: bool = False         # Gateway gray-zone hold: not blocked but awaiting analyst + human adjudication; the upstream agent does not execute
    raw_spans: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def event_type(self) -> str:
        """Derive event_type from blocked flag for backwards compatibility."""
        return "blocked" if self.blocked else "passed"

    @property
    def confidence(self) -> float:
        """Derive confidence from risk_score (0-100 → 0.0-1.0)."""
        return min(self.risk_score / 100.0, 1.0)

    @property
    def triggered_rule(self) -> str:
        """Get the first rule_hit from findings."""
        if self.findings:
            f = self.findings[0]
            if isinstance(f, dict):
                return f.get("rule_hit", "unknown")
            return f.rule_hit
        return "none"

    @property
    def is_blocked(self) -> bool:
        return self.blocked

    @property
    def is_collusion_indicator(self) -> bool:
        return self.module == "disposition" and not self.blocked


# ── Rule definitions and matching ─────────────────────────────────────────

@dataclass
class RuleDef:
    """A single security rule definition."""
    rule_id: str
    name: str
    description: str
    action: str           # "block" | "alert"
    enabled: bool = True
    severity: str = "high"
    # Natural language configuration (reserved for LLM-based rule creation)
    nl_config: Optional[str] = None
    # Detection patterns (keyword-based for now)
    patterns: list[str] = field(default_factory=list)
    # For collusion: expected agent pairs that should NOT confirm each other
    forbidden_pairs: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "enabled": self.enabled,
            "severity": self.severity,
            "nl_config": self.nl_config,
            "patterns": self.patterns,
        }


@dataclass
class RuleMatch:
    """Result of matching a rule against an event."""
    rule_id: str
    rule_name: str
    matched: bool
    action: str           # "block" | "alert"
    confidence: float
    evidence: str = ""
    event_id: str = ""


# ── Alert record ──────────────────────────────────────────────────────────

@dataclass
class AlertRecord:
    """
    A recorded alert after rule matching and analysis.
    Stored in the agent's in-memory alert store for UI consumption.
    """
    alert_id: str
    event: GatewayEvent
    rule_matches: list[RuleMatch] = field(default_factory=list)
    decision_tree: Optional[dict] = None    # Serialized decision tree if spans exist
    storyline: str = ""                     # NL narrative
    risk_level: str = "medium"              # high / medium / low
    pending_block: bool = False             # True in OBSERVE mode, waiting for human
    blocked: bool = False                   # True after block executed
    held: bool = False                      # Gateway gray-zone hold: the upstream agent is stalled until a human disposes (then pass/block)
    handled: bool = False                   # True once disposed — hidden from alert list
    disposition_id: Optional[str] = None    # Linked disposition record ID after block
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "event_id": self.event.event_id,
            "event_type": self.event.event_type,
            "gateway_id": self.event.gateway_id,
            "timestamp": self.event.timestamp.isoformat(),
            "user_input": self.event.user_input,
            "triggered_rule": self.event.triggered_rule,
            "confidence": self.event.confidence,
            "risk_level": self.risk_level,
            "rule_matches": [
                {"rule_id": m.rule_id, "rule_name": m.rule_name,
                 "action": m.action, "confidence": m.confidence}
                for m in self.rule_matches
            ],
            "storyline": self.storyline[:300] if self.storyline else "",
            "pending_block": self.pending_block,
            "blocked": self.blocked,
            "held": self.held,
            "hold_id": self.event.event_id if self.held else None,
            "handled": self.handled,
            "disposition_id": self.disposition_id,
            "has_decision_tree": self.decision_tree is not None,
        }


# ── EmergentAnomaly — detected unexpected multi-agent behavior ────────────

class DispositionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SIMULATED = "simulated"
    PENDING = "pending"


@dataclass
class DispositionRecord:
    """
    Disposition record — captures the disposition action, operator, command, and result for each alert.

    Fields:
      disposition_id: Disposition ID
      alert_id: Linked alert ID
      event_id: Linked event ID
      operator: Operator — "auto" (auto mode) / "admin" (human confirmation)
      action: Disposition action — "block" / "unblock" / "ignore" / "toggle_rule"
      command: The concrete command issued
      result: Disposition result — "success" / "failed" / "simulated" / "pending"
      detail: Result detail description
      triggered_rule: ID of the triggered rule
      risk_level: Risk level
      created_at: Disposition time
      acknowledged_at: Human confirmation time (in OBSERVE mode)
    """
    disposition_id: str
    alert_id: str
    event_id: str
    operator: str                    # "auto" | "admin" | custom
    action: str                      # "block" | "unblock" | "ignore" | "toggle_rule"
    command: str                     # The concrete command issued
    result: str = DispositionStatus.SIMULATED   # success/failed/simulated/pending
    detail: str = ""
    triggered_rule: str = ""
    risk_level: str = "medium"
    alert_text: str = ""             # Original alert text (the inspected user_input), shown on the disposition records page
    mode: str = "observe"            # Disposition mode: auto / observe (human confirmation)
    created_at: datetime = field(default_factory=datetime.now)
    acknowledged_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "disposition_id": self.disposition_id,
            "alert_id": self.alert_id,
            "event_id": self.event_id,
            "operator": self.operator,
            "action": self.action,
            "command": self.command,
            "result": self.result.value if isinstance(self.result, DispositionStatus) else self.result,
            "detail": self.detail,
            "triggered_rule": self.triggered_rule,
            "risk_level": self.risk_level,
            "alert_text": self.alert_text,
            "mode": self.mode,
            "created_at": self.created_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
        }


class AnomalyType(str, Enum):
    UNAUTHORIZED_COMMUNICATION = "unauthorized_communication"
    EXCESSIVE_NEGOTIATION = "excessive_negotiation"
    RULE_BYPASS = "rule_bypass"
    REASONING_ERROR = "reasoning_error"
    COLLUSION = "collusion"  # Collusion between agents


@dataclass
class EmergentAnomaly:
    """
    Represents a detected emergent (unexpected) behavior in the multi-agent system.
    """
    anomaly_type: AnomalyType
    severity: str  # "high" | "medium" | "low"
    description: str
    involved_span_ids: list[str] = field(default_factory=list)
    evidence: str = ""
    agent_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity,
            "description": self.description,
            "involved_span_ids": self.involved_span_ids,
            "evidence": self.evidence,
            "agent_ids": self.agent_ids,
        }
