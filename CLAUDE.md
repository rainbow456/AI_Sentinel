# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AI Sentinel** integrates two modules:

1. **Gateway** (`gateway/`) — Security gateway with detection middlewares and Splunk HEC reporting
2. **Analyst** (`analyst/`) — Multi-alert security agent with MCP servers, decision trees, and emergent behavior detection
3. **CMS Agent** (`cms_agent/`) — Demo CRM Agent with security guard wrapper
4. **Legacy** (`legacy/`) — Deprecated files (kept for reference, not imported by anything)

## Architecture

```
User Input → Gateway (:3001) → Splunk HEC → Analyst MCP Servers → SecurityAgent → UI (:5000)
                                  ↑                                 │
                               events CSV                     Gateway MCP → /bans API
                                                             Rule MCP → rules.yaml
```

## Gateway Module (`gateway/`)

FastAPI app on port 3001. Entry: `python -m gateway.main`

| File | Purpose |
|------|---------|
| `gateway/main.py` | FastAPI app, routes, detector loading, event emission |
| `gateway/mcp_sender.py` | Async Splunk HEC sender with spooling sink (fail-soft) |
| `gateway/disposition.py` | IP ban/policy store (SQLite), BanMiddleware, auto-ban |
| `gateway/llm_proxy.py` | OpenAI-compatible `/v1/chat/completions` proxy with detection |
| `gateway/preprocess.py` | De-obfuscation (zero-width, full-width, base64, URL) |
| `gateway/rule_store.py` | SQLite rule store with version history and test runner |
| `gateway/rules_api.py` | `/rules` REST API for rule CRUD |
| `gateway/middlewares/` | Pluggable detectors — auto-registered on startup |

**Key env vars**: `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `GATEWAY_ID`, `LLM_PROVIDER`

## Analyst Module (`analyst/`)

Flask app on port 5000. Entry: `python -m analyst.ui.app`

| File | Purpose |
|------|---------|
| `analyst/agent.py` | SecurityAgent — dual mode (AUTO/OBSERVE), NL commands, MCP integration |
| `analyst/config.py` | Unified config from env vars with sensible defaults |
| `analyst/models.py` | GatewayEvent, Span, CausalNode, DecisionTree, RuleDef, Finding, etc. |
| `analyst/rule_engine.py` | Local rule matching (findings-based + keyword) |
| `analyst/causal_analyzer.py` | Decision tree construction, emergence detection, storyline |
| `analyst/nl_engine.py` | Intent classification, SPL generation, action parsing, rule search |
| `analyst/report_engine.py` | Mermaid.js tree generation + emergent behavior reporting |
| `analyst/mcp_client.py` | MCPBridge — manages subprocess MCP servers via stdio |
| `analyst/servers/splunk_mcp.py` | Splunk Query MCP server (real Splunk or simulated) |
| `analyst/servers/gateway_mcp.py` | Gateway Control MCP server (real gateway API or simulated) |
| `analyst/servers/rule_mcp.py` | Rule Engine MCP server (YAML-backed, hot-reload) |
| `analyst/ui/app.py` | Flask app with API endpoints and dashboard |
| `analyst/ui/templates/dashboard.html` | Command center dashboard |

**Key env vars**: `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USE_REAL`, `GATEWAY_HOST`, `GATEWAY_PORT`, `GATEWAY_USE_REAL`, `RULES_PATH`

## CMS Agent (`cms_agent/`)

Demo CRM Agent used as a "victim agent" to demonstrate Gateway integration.

| File | Purpose |
|------|---------|
| `crm_agent.py` | CRM Agent with SQLite, natural language, CLI + Web modes |
| `crm_secure.py` | Monkey-patch wrapper that routes all commands through Gateway |
| `start_secure_crm.ps1` | One-click launcher (Gateway + CRM Agent) |

## Shared Resources

| File | Purpose |
|------|---------|
| `rules.yaml` | Shared security rules (source of truth for both modules) |
| `.env.example` | All environment variables with defaults |
| `start_all.ps1` | One-click startup: Gateway + Analyst + CMS Agent |
| `tests/integration_test.py` | End-to-end integration test |
| `data/` | Gateway event CSV files (loaded by Splunk MCP in simulated mode) |

## Quick Start

```powershell
# One-click: Gateway + Analyst + CMS Agent
.\start_all.ps1

# Or start individually:
python -m gateway.main        # Gateway → localhost:3001
python -m analyst.ui.app      # Analyst UI → localhost:5000
python tests/integration_test.py --quick  # Integration tests
```

## Data Format (Gateway ↔ Analyst)

Gateway emits `SecurityEvent` JSON with fields: `event_id, timestamp, module, blocked, handler, risk_score, user_input, subject_name, agent_id, findings[], gateway_id, llm_provider`

Analyst consumes the same format as `GatewayEvent`. The `findings` array uses: `detector, rule_hit, owasp_ast, severity, matched, description`

**These are already aligned — do not change field names without updating both sides.**

## Important Conventions

- Gateway detectors follow `detect(prompt: str) -> dict` convention and auto-register
- Analyst MCP servers are launched as subprocesses by `MCPBridge`
- Rule matching in analyst uses `findings[].rule_hit` as primary signal
- Gateway `mcp_sender.py` uses `SPLUNK_HEC_URL`/`SPLUNK_HEC_TOKEN` (not analyst's `SPLUNK_HOST`/`SPLUNK_PORT`)
- Legacy files in `legacy/` are deprecated and not imported by any module
- The `__pycache__/` directories are excluded via `.gitignore`
