# AI Sentinel Project Integration Plan

## Current State Analysis

**Member A (Defense Architect)** — `gateway/` module:
- FastAPI security gateway on port 3001
- Middleware detectors (injection, sensitive, PII, rule_engine, command_exec, entropy, prompt_injection)
- Splunk HEC async sender with spooling sink
- Disposition module (IP ban/policy management with SQLite)
- Rule store (SQLite-backed, data-driven rule engine)
- LLM proxy (OpenAI-compatible /v1/chat/completions)
- Rules API and Policy API endpoints

**Member B (Intelligence Analyst)** — `analyst/` module:
- SecurityAgent with dual-mode (AUTO/OBSERVE)
- MCP Bridge connecting to 3 MCP servers (Splunk Query, Gateway Control, Rule Engine)
- Rule engine matching events to security rules
- Causal decision tree analyzer for multi-agent spans
- NL engine for intent classification and command processing
- Report engine (Mermaid.js tree + emergent behavior detection)
- Flask UI with dashboard and API endpoints

**Legacy files** at root:
- `app.py` — Old Flask dashboard (SimulatedSplunk-based, not integrated)
- `security_agent.py` — Old CLI agent
- `simulated_splunk.py` — Old mock Splunk
- `templates/dashboard.html` — Old dashboard template

## Integration Tasks

### 1. Directory Structure Cleanup

Current structure is largely correct. Issues to fix:
- **Remove legacy root files**: `app.py`, `security_agent.py`, `simulated_splunk.py`, `templates/dashboard.html` — superseded by `analyst/` module
- **Keep**: `gateway/`, `analyst/`, `data/`, `docs/`, `skillscan/` (utility)
- **Add**: `rules.yaml` (shared rule file), `.env.example`, `tests/integration_test.py`

Target layout:
```
ai-sentinel/
├── gateway/          # A module
│   ├── main.py
│   ├── mcp_sender.py
│   ├── disposition.py
│   ├── llm_proxy.py
│   ├── preprocess.py
│   ├── rule_store.py
│   ├── rules_api.py
│   ├── middlewares/
│   └── requirements.txt (gateway-specific)
├── analyst/          # B module
│   ├── agent.py
│   ├── report_engine.py
│   ├── rule_engine.py
│   ├── causal_analyzer.py
│   ├── nl_engine.py
│   ├── models.py
│   ├── config.py
│   ├── mcp_client.py
│   ├── servers/
│   │   ├── splunk_mcp.py
│   │   ├── gateway_mcp.py
│   │   └── rule_mcp.py
│   └── ui/
│       ├── app.py
│       └── templates/dashboard.html
├── data/             # Gateway event CSV data
├── docs/             # Documentation
├── tests/            # Integration tests
├── rules.yaml        # Shared rule definitions
├── .env.example      # Environment variable template
├── requirements.txt  # Unified dependencies
├── README.md         # Updated project documentation
└── CLAUDE.md         # Claude Code instructions
```

### 2. Environment Variable Unification

**Current conflicts/duplicates**:
- Gateway uses: `GATEWAY_ID`, `LLM_PROVIDER`, `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `SPLUNK_HEC_VERIFY`, `SPLUNK_HEC_CHANNEL`, `OPENAI_UPSTREAM_URL`, `OPENAI_UPSTREAM_KEY`
- Analyst uses: `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_TOKEN`, `SPLUNK_USE_SSL`, `SPLUNK_VERIFY_SSL`, `SPLUNK_USE_REAL`, `GATEWAY_HOST`, `GATEWAY_PORT`, `GATEWAY_API_KEY`, `GATEWAY_USE_REAL`, `RULES_PATH`

**Resolution**:
- `SPLUNK_TOKEN` is used by both but for different purposes (Gateway=HEC token, Analyst=search token). Rename gateway's to `SPLUNK_HEC_TOKEN` (already done) and keep analyst's `SPLUNK_TOKEN` for search auth.
- Create `.env.example` with all variables grouped by module.

### 3. Data Format Alignment

**Gateway SecurityEvent fields** (from `mcp_sender.py`):
```
event_id, timestamp, module, blocked, handler, risk_score,
user_input, subject_name, agent_id, findings[], gateway_id, llm_provider
```

**Analyst GatewayEvent fields** (from `models.py`):
```
event_id, timestamp, module, blocked, handler, risk_score,
user_input, subject_name, agent_id, findings[], gateway_id, llm_provider
```

✅ **Already aligned!** Both use the same field names. The CSV data confirms this.

**Finding format alignment**:
- Gateway `_finding_from_hit()`: `detector, rule_hit, owasp_ast, severity, matched, description`
- Analyst `Finding`: `detector, rule_hit, owasp_ast, severity, matched, description`

✅ **Already aligned!**

### 4. API Interface Alignment — Gateway Control MCP → Gateway

**Current gap**: `gateway_mcp.py` is purely simulated (in-memory blocks). It needs to call the real gateway's `/bans` API when `GATEWAY_USE_REAL=true`.

**Gateway exposes**:
- `POST /bans` — Ban an IP (`{ip, type, ttl_seconds, reason}`)
- `DELETE /bans/{ip}` — Unban
- `GET /bans` — List active bans
- `GET /bans/{ip}` — Check ban status
- `GET /policy` / `PUT /policy` — Policy management

**MCP gateway_mcp.py tools**:
- `send_block_command(gateway_id, target, reason)` → should map to `POST /bans`
- `unblock_target(target)` → should map to `DELETE /bans/{ip}`
- `list_blocks(target)` → should map to `GET /bans`
- `gateway_status()` → should map to `GET /health`

**Fix**: Update `gateway_mcp.py` to call real gateway API when `GATEWAY_USE_REAL=true`, falling back to simulated.

### 5. Shared Rules File (`rules.yaml`)

**Current state**:
- Gateway has a SQLite `RuleStore` with `seed_from_legacy()` — rules are in a DB
- Analyst MCP Rule Engine has `DEFAULT_RULES` hardcoded + YAML hot-reload support
- Both have similar rules but different formats

**Fix**: Create `rules.yaml` that:
- Contains the analyst's default rules in YAML format (already supported by `rule_mcp.py`)
- Gateway's `seed_from_legacy()` should also seed from this YAML (or at least reference it)
- The YAML becomes the single source of truth for both modules

### 6. Integration Test

Create `tests/integration_test.py` that:
1. Starts gateway on port 3001
2. Sends a malicious request → gateway detects & blocks → emits event to mock Splunk (CSV)
3. Starts analyst agent in AUTO mode → loads events from CSV
4. Agent matches rules → auto-blocks → records disposition
5. Verifies alert records contain correct data
6. Verifies decision tree can be built from span data
7. Verifies emergent behavior detection works

### 7. UI Integration Check

The analyst UI (`analyst/ui/app.py`) is already integrated with the agent. It displays:
- Alerts from gateway events (loaded via CSV/MCP)
- Mode switching
- Block confirmation
- NL query processing
- Rule management
- Disposition records

**No changes needed** — the UI already works with real gateway event data format.

### 8. Dependency Consolidation

Current `requirements.txt` only has gateway deps. Need to add:
- `flask` (analyst UI)
- `mcp` (analyst MCP client/servers)
- `pyyaml` (rule engine YAML support)
- `splunk-sdk` (optional, real Splunk connection)

### 9. README Update

Rewrite README to cover:
- Full project overview (gateway + analyst)
- How to start each module
- How to configure environment
- How to run integration test
- Architecture diagram showing data flow

### 10. Legacy File Cleanup

Remove or move to archive:
- `app.py` (root) — superseded by `analyst/ui/app.py`
- `security_agent.py` (root) — superseded by `analyst/agent.py`
- `simulated_splunk.py` (root) — superseded by `analyst/servers/splunk_mcp.py`
- `templates/dashboard.html` (root) — superseded by `analyst/ui/templates/dashboard.html`
