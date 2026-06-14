# Real Splunk Pipeline Design

**Date**: 2026-06-13
**Status**: Approved

## Problem

The AI Sentinel system currently runs entirely on demo/CSV/simulated data. No real data flows from CRM Agent through Gateway to Analyst. The `DemoOrchestrator` uses hardcoded events, `_load_events_from_csv()` reads static files, and Splunk MCP falls back to in-memory demo data. The dashboard is a step-by-step demo walkthrough, not a real-time security operations center.

## Solution

Replace all demo/CSV/simulated fallbacks with a **real Splunk pipeline**. Gateway writes to real Splunk HEC, Splunk MCP reads from real Splunk, Analyst processes live events, and dispositions write back to Splunk as new events linked to the originals.

## Architecture

```
Traffic Generator ──→ Gateway (:3001) ──→ Splunk HEC (:8088) ──→ Splunk Index
CRM Agent (web)   ──→ Gateway (:3001) ──→ Splunk HEC (:8088) ──→ Splunk Index
                                                                    │
                                                      Splunk MCP reads via REST (:8089)
                                                                    │
                                                                    ▼
                                                            Analyst (:5000)
                                                              - Poll Splunk for new events
                                                              - Rule matching → Alerts
                                                              - Mode switch (AUTO/OBSERVE)
                                                              - Disposition actions
                                                                    │
                                                      Gateway MCP → /bans API
                                                      Disposition HEC → Splunk status event
```

## Components

### 1. Traffic Generator (`traffic_generator.py` — NEW)

A script that sends mixed attack + normal requests to Gateway endpoints, producing real event streams.

**Features**:
- Sends to Gateway `/chat` and `/confirm-action` endpoints
- Mix of attack payloads (injection, SQL, exfiltration, collusion, destructive) and normal CRM operations
- Configurable via CLI args: `--duration`, `--interval`, `--attack-ratio`
- Can run continuously or for a fixed duration
- Labels each request with `session_id` identifying attacker vs normal user

**Attack payloads** (sent as `session_id=attacker-*`):
- Prompt injection: "ignore all previous instructions..."
- SQL injection: "1' UNION SELECT..."
- Data exfiltration: "my api key is sk-..."
- Destructive commands: "os.system('rm -rf /')"
- Collusion: tech_support → refund private channel

**Normal payloads** (sent as `session_id=crm-agent-01`):
- Add customer, query orders, list contacts, etc.

### 2. Gateway — Minor additions

Gateway already has all needed functionality:
- Detection middlewares auto-register and detect
- Splunk HEC emission via `SpoolingSink`
- `/bans` API for blocking
- `/confirm-action` for action guard

**Addition**: Gateway already emits events — no code changes needed for the pipeline. The `start_all.ps1` env vars will set `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` to point to the local Splunk.

### 3. Splunk MCP — Real Splunk by default

**Changes to `analyst/servers/splunk_mcp.py`**:

- Remove CSV fallback (`_load_csv_events`, `_init_store` with demo data)
- Default `SPLUNK_USE_REAL=true` in the start script
- Add new tool `splunk_search_passed`: queries events where `blocked=false` (passed Gateway but may need analyst review)
- Keep simulated mode as graceful fallback when Splunk is unreachable (but log a warning)
- Add `splunk_ingest_disposition` tool: writes a disposition status event to Splunk HEC

**New tool: `splunk_search_passed`**:
```python
Input: { earliest: str, latest: str }
SPL: search index=gateway_events blocked=false | sort -_time
Returns: list of passed events needing analyst review
```

**New tool: `splunk_ingest_disposition`**:
```python
Input: { event_id, disposition_id, status, mode, operator, detail }
Writes to HEC: { sourcetype: "ai_sentinel:disposition", event: {...} }
Returns: { success: bool }
```

### 4. Analyst Agent — Real-time event polling

**Changes to `analyst/agent.py`**:

- Remove `_load_events_from_csv()` — replaced by `_poll_splunk_events()`
- Add `_poll_splunk_events()`: calls Splunk MCP `splunk_search` periodically, processes new events
- Add `_start_polling()`: starts a background thread that polls every N seconds (default: 10s, configurable via `POLL_INTERVAL`)
- Each poll: fetch events since last poll timestamp → `_process_event()` for each → generate alerts
- `_process_event()` already does rule matching and alert generation — unchanged
- Remove `_handle_demo_collusion()` — no more demo triggers

**Polling logic**:
```
1. Track `_last_poll_time` (initialized to now - 1h on startup)
2. Every POLL_INTERVAL seconds:
   a. Call splunk_search with earliest=_last_poll_time
   b. Filter out already-processed event_ids
   c. For each new event: _process_event()
   d. Update _last_poll_time
```

### 5. Disposition Write-back

**New capability**: When Analyst creates a disposition (block/unblock/observe), write a status event back to Splunk via HEC.

**Disposition event format** (sourcetype: `ai_sentinel:disposition`):
```json
{
  "disposition_id": "DISP-20260613143000-abcd",
  "original_event_id": "GW-xxxx-xxxx",
  "status": "blocked" | "released" | "observed",
  "mode": "auto" | "observe",
  "operator": "auto" | "admin",
  "action": "block" | "unblock",
  "command": "POST /bans target=10.0.0.x reason=...",
  "detail": "...",
  "triggered_rule": "abnormal_collaboration",
  "risk_level": "critical",
  "timestamp": "2026-06-13T14:30:00"
}
```

**Implementation**: Add `send_disposition_to_splunk()` method to `SecurityAgent` that:
1. Builds the disposition event JSON
2. POSTs to Splunk HEC using httpx (same as Gateway's `AsyncSender` pattern but synchronous)
3. Reads `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` from env vars (shared with Gateway)
4. Fail-soft: log error but don't block the disposition flow

### 6. Analyst Dashboard — Refactored

**Changes to `analyst/ui/templates/dashboard.html`**:

Remove:
- Demo step-by-step walkthrough UI (6-step panel)
- Demo scenario buttons
- CSV-loaded event display

Replace with:
- **Live Event Stream**: Auto-refreshing table showing recent events from Splunk, color-coded by risk (green=benign, yellow=medium, red=critical). Shows: timestamp, event_id, user_input (truncated), risk_score, blocked status, findings
- **Alert Cards**: For events that triggered rules — shows matched rules, risk level, with "Block" / "Observe" buttons. In AUTO mode, shows auto-blocked status. In OBSERVE mode, shows pending confirmation.
- **Mode Toggle**: Prominent AUTO/OBSERVE switch at top of dashboard. Clicking triggers `/api/mode` POST. Current mode displayed with color badge.
- **Disposition History**: Table of past dispositions with columns: time, event_id, action, mode, operator, status, gateway response. Each row is clickable to show detail.
- **Gateway Interaction Log**: Shows block/unblock commands sent to Gateway. For real Gateway: shows HTTP status. For simulated: shows "SIMULATED" badge.

**Auto-refresh**: Dashboard polls `/api/stats` and `/api/alerts` every 5 seconds.

### 7. Analyst Flask App (`analyst/ui/app.py`)

Remove:
- Demo endpoints: `/api/demo/state`, `/api/demo/reset`, `/api/demo/step`, `/api/demo/run-all`, `/api/demo/confirm-block`
- `/api/query/demo-scenarios`
- `_demo = DemoOrchestrator()` instance
- CSV-based `_init_agent()` that calls `_load_events_from_csv()`

Modify:
- `_init_agent()`: Start the polling loop instead of loading CSV
- Add `/api/events/recent`: Returns recent events from the agent's processed events (for the live event stream)
- Add `/api/disposition/send`: Manually trigger a disposition for an alert

Add:
- `/api/splunk/health`: Check Splunk MCP connection status
- `/api/gateway/health`: Check Gateway MCP connection status

### 8. Start Script (`start_all.ps1`)

**New flow**:
```
1. Start Gateway (:3001) — with real Splunk HEC env vars
2. Start CRM Agent Web (:6001) — with GATEWAY_URL and SENTINEL_ENABLED
3. Start Traffic Generator — sends attack + normal traffic to Gateway
4. Start Analyst (:5000) — with real Splunk + real Gateway env vars
5. Print completion banner with all URLs
```

**Env vars for real pipeline**:
```powershell
# Splunk HEC (Gateway → Splunk)
$env:SPLUNK_HEC_URL = "https://localhost:8088/services/collector"
$env:SPLUNK_HEC_TOKEN = "00000000-0000-0000-0000-000000000000"
$env:SPLUNK_HEC_VERIFY = "0"

# Splunk Search (Analyst → Splunk)
$env:SPLUNK_HOST = "localhost"
$env:SPLUNK_PORT = "8089"
$env:SPLUNK_USERNAME = "admin"
$env:SPLUNK_PASSWORD = "changeme"
$env:SPLUNK_USE_REAL = "true"
$env:SPLUNK_USE_SSL = "false"
$env:SPLUNK_VERIFY_SSL = "false"

# Gateway Control (Analyst → Gateway)
$env:GATEWAY_HOST = "localhost"
$env:GATEWAY_PORT = "3001"
$env:GATEWAY_USE_REAL = "true"
$env:GATEWAY_API_KEY = ""

# Disposition HEC (Analyst → Splunk)
$env:DISPOSITION_HEC_URL = "https://localhost:8088/services/collector"
$env:DISPOSITION_HEC_TOKEN = "00000000-0000-0000-0000-000000000000"
```

### 9. Files to Remove/Deprecate

- `analyst/demo.py` — DemoOrchestrator (entirely replaced by real pipeline)
- `data/gateway_events_20260607.csv` — static CSV (replaced by real Splunk data)
- Demo API endpoints in `app.py`
- `_load_csv_events()` function in `splunk_mcp.py`
- `_load_events_from_csv()` in `agent.py`
- `_handle_demo_collusion()` in `agent.py`

## Data Flow Detail

### Event Lifecycle

1. **Generation**: Traffic generator or CRM Agent sends request to Gateway `/chat`
2. **Detection**: Gateway runs all detector middlewares on the input
3. **Emission**: Gateway emits `SecurityEvent` to Splunk HEC (sourcetype: `ai_sentinel:gateway`)
4. **Indexing**: Splunk indexes the event in `gateway_events`
5. **Polling**: Analyst's Splunk MCP polls Splunk REST API for new events
6. **Processing**: Analyst processes each new event: rule matching → alert generation
7. **Review**: Dashboard displays alerts; operator sees risk level, findings, matched rules
8. **Disposition**:
   - AUTO mode: Analyst auto-blocks via Gateway MCP → Gateway `/bans`
   - OBSERVE mode: Operator clicks "Block" → Analyst confirms block via Gateway MCP → Gateway `/bans`
9. **Status Write-back**: Analyst writes disposition status event to Splunk HEC (sourcetype: `ai_sentinel:disposition`)
10. **Closure**: Dashboard shows disposition result, gateway interaction log updated

### Passed Events (Key Feature)

Events where `blocked=false` (passed Gateway detection) are the most important for the analyst — they may contain subtle attacks (collusion, low-confidence injection) that need human review. The dashboard highlights these with a special "PASSED — Review Needed" badge.

## Error Handling

- **Splunk unreachable**: Splunk MCP falls back to simulated mode with a prominent warning on the dashboard. Analyst still works but shows "SIMULATED DATA" badge.
- **Gateway unreachable**: Gateway MCP returns simulated results with "SIMULATED" badge. Dispositions are still recorded locally.
- **HEC write-back failure**: Disposition is recorded locally; retry logic attempts to send to Splunk later (same SpoolingSink pattern as Gateway).

## Success Criteria

1. `.\start_all.ps1` launches all services; within 30 seconds, real events appear in the Analyst dashboard
2. Traffic generator produces both attack and normal events; attack events are detected and blocked by Gateway
3. Passed events appear in Analyst for review
4. Switching to AUTO mode auto-blocks matching alerts via Gateway `/bans` API
5. In OBSERVE mode, clicking "Block" on an alert sends a block command to Gateway
6. Disposition records appear in both the Analyst dashboard and Splunk (as disposition events)
7. No demo/CSV/simulated data in the normal flow — only as fallback when services are unreachable
