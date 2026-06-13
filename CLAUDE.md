# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains two independent systems:

1. **AI Sentinel** (root level) — Security alert monitoring agent with Splunk simulator
2. **Multi-Agent Command Center** (`analyst/`) — Causal decision tree observability & emergent behavior detection platform

## 1. AI Sentinel (legacy, root)

Security monitoring agent + Flask dashboard for Splunk alerts.

| File | Purpose |
|------|---------|
| `simulated_splunk.py` | Mock Splunk with 8 attack types, background event generation |
| `security_agent.py` | CLI agent: polls alerts → extracts IP → investigates → NL summary |
| `app.py` | Flask web dashboard (original) |
| `templates/dashboard.html` | Cyberpunk security alert dashboard |

```bash
python security_agent.py       # CLI agent
pip install flask && python app.py  # Web dashboard → localhost:5000
```

## 2. Multi-Agent Command Center (`analyst/`)

Observes OpenTelemetry-style Span data from multi-agent systems, constructs causal decision trees, detects emergent behaviors.

### Architecture

```
analyst/
├── models.py          # Span, CausalNode, DecisionTree, EmergentAnomaly
├── demo_spans.py      # 16 demo spans: 3-agent refund scenario
├── agent.py           # CausalTreeAnalyzer: spans → tree → storyline
├── report_engine.py   # ReportA (Mermaid.js tree) + ReportB (emergent behavior detection)
└── ui/
    ├── app.py         # Flask app with API endpoints
    └── templates/
        └── dashboard.html  # Interactive decision tree command center
```

### Data Flow

```
demo_spans.py → CausalTreeAnalyzer.build_decision_tree()
  → DecisionTree (16 CausalNodes, 3 agents)
  → ReportA.to_mermaid() + ReportB.summary()
  → Flask API → Mermaid.js SVG + anomaly cards + stats
```

### Key Models

- **Span**: agent_id, trace_id, span_id, parent_span_id, action, thought (CoT), tool_call, message_to, message_content, timestamp, causality_chain, context_snapshot, metadata
- **CausalNode**: wraps Span with children list, depth, node_type (thinking/tool_call/message/delegation/error)
- **DecisionTree**: root_nodes, node_map (span_id→CausalNode), agent_count, total_steps, time_span
- **EmergentAnomaly**: 4 types (unauthorized_communication, excessive_negotiation, rule_bypass, reasoning_error) × 3 severities

### Demo Scenario

3-agent refund collaboration with 3 deliberate anomalies:
- `ts-04`: tech_support → refund private message via unregistered action
- `rf-03`: refund agent misreads amount (￥199→￥299) AND bypasses cs approval
- `rf-05`: self-correction span

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Command center dashboard |
| GET | `/api/trees` | Decision tree summaries (mermaid code included) |
| GET | `/api/trees/<trace_id>` | Full tree + narratives + anomalies |
| GET | `/api/anomalies` | All detected emergent behaviors |
| GET | `/api/stats` | Agent count, steps, tree count, anomaly count |

### Running

```bash
pip install flask
python -m analyst.ui.app
# → http://localhost:5000
```

No dependencies beyond Python 3.9+ stdlib and Flask.
