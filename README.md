# AI Sentinel — AI Security Gateway and Intelligence Analysis Platform

> **AI Sentinel** consists of two independent modules:
> - **Gateway** (security gateway): intercepts malicious traffic between user input and high-risk agent actions
> - **Analyst** (intelligence analyst): multi-alert security analysis, causal decision trees, emergent behavior detection
>
> The two modules work together to form a complete security loop: "detect → report → analyze → block".

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Quick Start — One-Click Launch](#2-quick-start)
3. [Gateway Security Gateway](#3-gateway-security-gateway)
4. [Analyst Intelligence Platform](#4-analyst-intelligence-platform)
5. [CMS Agent Demo](#5-cms-agent-demo)
6. [Configuration (Environment Variables)](#6-configuration-environment-variables)
7. [API Reference](#7-api-reference)
8. [Integration Tests](#8-integration-tests)
9. [Project Structure](#9-project-structure)

---

## 1. System Architecture

```
                           ┌──────────────────────────┐
       User Input  ──────▶ │  AI Sentinel Gateway      │
                           │  (FastAPI :3001)          │
                           │  ├─ /chat     input guard │
                           │  ├─ /confirm-action       │
                           │  ├─ /scan     skill scan  │
                           │  ├─ /v1/chat/completions  │
                           │  ├─ /bans     IP bans     │
                           │  ├─ /rules    rule mgmt   │
                           │  └─ /policy   policy cfg  │
                           └──────────┬───────────────┘
                                      │ SecurityEvent JSON
                                      ▼
                           ┌──────────────────────────┐
                           │  Splunk HEC / sim store   │
                           │  (:8088 or :8000)         │
                           └──────────┬───────────────┘
                                      │ query events
                                      ▼
                           ┌──────────────────────────┐
                           │  AI Sentinel Analyst      │
                           │  (Flask :5000)            │
                           │  ├─ SecurityAgent         │
                           │  ├─ Splunk Query MCP      │
                           │  ├─ Rule Engine MCP       │
                           │  ├─ Gateway Control MCP   │
                           │  ├─ Decision Tree Engine  │
                           │  └─ Web UI Dashboard      │
                           └──────────┬───────────────┘
                                      │ block command
                                      ▼
                           ┌──────────────────────────┐
                           │  Gateway /bans API        │
                           │  (ban IP / target)        │
                           └──────────────────────────┘
```

**Data flow**: Gateway detects malicious input → reports SecurityEvent → Splunk stores it → Analyst pulls events → rule matching → auto/manual block → generates decision-tree report

---

## 2. Quick Start

### 2.1 Install Dependencies

```bash
cd d:\Programs\AI_Sentinel
pip install -r requirements.txt
```

Main dependencies: `fastapi` `uvicorn` `httpx` `flask` `mcp` `pyyaml` `pydantic` (Presidio and splunk-sdk are optional).

### 2.2 One-Click Launch (recommended)

```powershell
# PowerShell — start Gateway + Analyst UI + CMS Agent (web mode)
.\start_all.ps1

# Or start individually:
.\start_all.ps1 -Gateway       # start only the Gateway :3001
.\start_all.ps1 -Analyst       # start only the Analyst UI :5000
.\start_all.ps1 -CmsAgent      # start only the CMS Agent :6001
.\start_all.ps1 -Web           # CMS Agent web mode
```

```cmd
:: CMD — double-click to run
start_all.bat
```

### 2.3 Manual Individual Launch

**Terminal 1 — Gateway (port 3001)**:
```bash
python -m gateway.main
```

**Terminal 2 — Analyst UI (port 5000)**:
```bash
python -m analyst.ui.app
```

### 2.4 Configure the Splunk Connection

Copy `.env.example` to `.env` and fill in real values:

```bash
cp .env.example .env
```

Key variables (simulated data is used by default, so it runs without Splunk):
- `SPLUNK_HEC_URL` / `SPLUNK_HEC_TOKEN` — Gateway reports events to Splunk
- `SPLUNK_HOST` / `SPLUNK_PORT` — Analyst queries events from Splunk
- `SPLUNK_USE_REAL=false` — set to `true` to connect to real Splunk

### 2.5 Verify

```bash
# Gateway health check
curl http://localhost:3001/health
# → {"status":"ok","detector_count":5}

# Analyst stats
curl http://localhost:5000/api/stats
# → {"mode":"observe","total_alerts":...,"total_events":...}

# Analyst command center UI
# Open http://localhost:5000 in a browser
```

---

## 3. Gateway Security Gateway

A **FastAPI**-based security gateway, deployed "in front of" agent / LLM applications.

**Core capabilities**:
- Pluggable detectors (auto-scans `gateway/middlewares/`)
- Block on hit (403 + hit details)
- Hard block on high-risk keywords (delete / drop / rm -rf, etc.)
- Structured JSON logging + async Splunk HEC reporting
- Automatic IP bans (sliding-window threshold exceeded)
- OpenAI-compatible proxy (`/v1/chat/completions`)
- Rule management API (`/rules`), policy API (`/policy`)

**Built-in detectors**:
| Module | Capability |
|------|------|
| `rule_engine.py` | Data-driven multi-engine (regex/sensitive/keyword/entropy) |
| `injection.py` | Prompt injection/jailbreak (10 major categories) |
| `prompt_injection.py` | Injection/jailbreak (keyword regex, incl. Chinese) |
| `sensitive.py` | Sensitive information (regex + Presidio) |
| `pii_leak.py` | PII (Presidio preferred) |
| `command_exec.py` | Command execution detection |
| `entropy.py` | High-entropy obfuscation detection |

**API entry points**: `POST /chat`, `POST /confirm-action`, `POST /scan`, `POST /v1/chat/completions`, `GET/POST /bans`, `GET/POST /rules`, `GET/PUT /policy`

---

## 4. Analyst Intelligence Platform

A **Flask**-based Web UI + SecurityAgent providing multi-alert security analysis.

**Core capabilities**:
- Dual mode: AUTO (automatic blocking) / OBSERVE (manual confirmation)
- NL command parsing (natural-language queries/actions/rule configuration)
- 3 MCP servers (Splunk Query / Gateway Control / Rule Engine)
- Causal decision-tree construction and visualization
- Emergent behavior detection (collusion / privilege escalation / reasoning errors, etc.)
- Disposition record tracking (auto block / admin confirmation)

**API endpoints**:
| Method | Path | Description |
|------|------|------|
| GET | `/` | Command center dashboard |
| GET | `/api/stats` | Stats overview |
| GET | `/api/alerts` | Alert list |
| POST | `/api/query` | NL query/command |
| POST | `/api/block/:id` | Confirm block (OBSERVE) |
| GET/POST | `/api/mode` | Mode switch |
| GET | `/api/rules` | Rule list |
| GET | `/api/dispositions` | Disposition records |

---

## 5. CMS Agent Demo

`cms_agent/` contains a lightweight CRM Agent and its security-guard wrapper:

| File | Purpose |
|------|------|
| `crm_agent.py` | Original CRM Agent (SQLite data, natural-language interaction) |
| `crm_secure.py` | Security-guard wrapper (monkey-patches into the Gateway) |
| `start_secure_crm.bat` | CMD launch script |
| `start_secure_crm.ps1` | One-click PowerShell launch (includes the Gateway) |

**Usage**:
```bash
cd cms_agent

# Original CRM (does not go through the security gateway)
python crm_agent.py

# Secure CRM (goes through Gateway detection)
python crm_secure.py          # command-line mode
python crm_secure.py web 6001 # web mode (http://127.0.0.1:6001)
```

**Guard policy**:
- Input guard: only intercepts "prompt injection/jailbreak" types (PII/sensitive types are allowed through, since CRM legitimately enters such fields)
- Action guard: delete operations are reported with the neutral action name `remove_record` to avoid English hard-block keywords

---

## 6. Configuration (Environment Variables)

See [.env.example](.env.example) for the full configuration. Key variables:

### Gateway
| Variable | Default | Description |
|------|--------|------|
| `GATEWAY_ID` | `gateway-01` | Gateway instance identifier |
| `LLM_PROVIDER` | `anthropic` | Downstream LLM provider |
| `SPLUNK_HEC_URL` | - | Splunk HEC endpoint |
| `SPLUNK_HEC_TOKEN` | - | Splunk HEC token |

### Analyst
| Variable | Default | Description |
|------|--------|------|
| `SPLUNK_HOST` | `splunk.example.com` | Splunk search host |
| `SPLUNK_PORT` | `8089` | Splunk management port |
| `SPLUNK_USE_REAL` | `false` | Connect to real Splunk |
| `GATEWAY_HOST` | `gateway.example.com` | Gateway host |
| `GATEWAY_PORT` | `8443` | Gateway port |
| `RULES_PATH` | - | Path to rules.yaml |

---

## 7. API Reference

### Gateway API (`localhost:3001`)

See the original README §3-4 for details. Core endpoints:
- `POST /chat` — user input detection (200 allow / 403 block)
- `POST /confirm-action` — high-risk action confirmation (`allowed` field)
- `POST /scan` — skill content scan (returns multiple findings)
- `GET /health` — health check
- `GET/POST /bans` — IP ban management
- `GET/POST /rules` — rule CRUD
- `GET/PUT /policy` — policy configuration

### Analyst API (`localhost:5000`)

| Method | Path | Description |
|------|------|------|
| GET | `/api/stats` | Stats overview |
| GET | `/api/alerts` | Alert list |
| GET | `/api/alerts/<id>` | Alert detail |
| POST | `/api/query` | NL query |
| POST | `/api/block/<id>` | Confirm block |
| GET/POST | `/api/mode` | Mode query/switch |
| GET | `/api/rules` | Rule list |
| POST | `/api/rules/search` | Rule search |
| GET | `/api/dispositions` | Disposition records |
| GET | `/api/mcp/status` | MCP status |

---

## 8. Integration Tests

```bash
# Full test (start the Gateway first)
python tests/integration_test.py

# Quick test (no subprocess; Gateway already running)
python tests/integration_test.py --quick
```

Test coverage:
1. Gateway detection logic (injection / normal / high-risk command / masking)
2. Data format alignment (Gateway → Analyst)
3. Rule Engine rule matching
4. Causal decision-tree construction
5. MCP Bridge three-server connection
6. Full Agent cycle (event → rule → block → record)
7. CSV data pipeline
8. rules.yaml validation

---

## 9. Project Structure

```
AI_Sentinel/
├── gateway/                       # Module A: security gateway
│   ├── main.py                    # FastAPI entry, routes, detector loading
│   ├── mcp_sender.py              # Splunk HEC async sender + reliable delivery pipeline
│   ├── disposition.py             # IP ban/policy management (SQLite)
│   ├── llm_proxy.py               # OpenAI-compatible proxy
│   ├── preprocess.py              # Input preprocessor (de-obfuscation)
│   ├── rule_store.py              # Rule store (SQLite + version history)
│   ├── rules_api.py               # Rule management REST API
│   └── middlewares/               # Pluggable detectors (auto-registered)
├── analyst/                       # Module B: intelligence analysis platform
│   ├── agent.py                   # SecurityAgent (dual mode, NL commands)
│   ├── config.py                  # Unified config (env vars > defaults)
│   ├── mcp_client.py              # MCP Bridge (subprocess stdio connection)
│   ├── models.py                  # Data models (Span/CausalNode/GatewayEvent/...)
│   ├── rule_engine.py             # Rule engine (matches events to rules)
│   ├── causal_analyzer.py         # Causal decision-tree construction and analysis
│   ├── nl_engine.py               # NL intent classification / command parsing / rule search
│   ├── report_engine.py           # Report generation (Mermaid.js + emergence detection)
│   ├── servers/                   # MCP servers (run as subprocesses)
│   │   ├── splunk_mcp.py          # Splunk query (real/simulated)
│   │   ├── gateway_mcp.py         # Gateway control (real API / simulated)
│   │   └── rule_mcp.py            # Rule engine (YAML hot-reload)
│   └── ui/                        # Web UI
│       ├── app.py                 # Flask app (API + dashboard)
│       └── templates/dashboard.html
├── cms_agent/                     # Demo: CRM Agent + security guard
│   ├── crm_agent.py               # Original CRM Agent
│   ├── crm_secure.py              # Security-guard wrapper
│   └── start_secure_crm.ps1       # One-click launch script
├── data/                          # Gateway event CSV data
├── tests/                         # Integration tests
│   └── integration_test.py
├── legacy/                        # Old files (deprecated)
├── rules.yaml                     # Shared rules file
├── .env.example                   # Environment variable template
├── requirements.txt               # Unified dependencies
├── start_all.ps1                  # One-click launch script
├── start_all.bat                  # CMD one-click launch
├── README.md                      # This file
└── CLAUDE.md                      # Claude Code instructions
```

Quick lookup of key entry points:
| If you want to… | Look here |
|--------|--------|
| Change Gateway routes/responses | [gateway/main.py](gateway/main.py) |
| Change the high-risk keyword list | [gateway/main.py](gateway/main.py) `HIGH_RISK_KEYWORDS` |
| Add/change detection rules | [gateway/middlewares/](gateway/middlewares/) |
| Change Analyst mode logic | [analyst/agent.py](analyst/agent.py) |
| Change natural-language parsing | [analyst/nl_engine.py](analyst/nl_engine.py) |
| Change MCP tool definitions | [analyst/servers/](analyst/servers/) |
| Change the dashboard UI | [analyst/ui/templates/dashboard.html](analyst/ui/templates/dashboard.html) |
| Change shared rules | [rules.yaml](rules.yaml) |
```
