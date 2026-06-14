# AI_Sentinel Gateway — Overview

A security gateway for AI agents: it blocks malicious input, scans malicious skills, guards
high-risk actions, and provides a queryable/editable detection rule store plus a risk
disposition API. All events are normalized and reported to Splunk.

## Capability Map

| Capability | Entry point | Description |
|---|---|---|
| Input guard | `POST /chat` | User input runs through the detectors; blocked when the threshold is exceeded |
| Action guard | `POST /confirm-action` | Confirm high-risk actions (delete, etc.) before execution |
| Skill scan | `POST /scan` | Static multi-engine detection of uploaded skills |
| LLM-compatible proxy | `POST /v1/chat/completions` | Any-language agent integrates by just changing `base_url` |
| IP ban | `/bans` | Temporary/permanent bans + auto-ban |
| Policy / threshold | `/policy` | Block threshold, presets, batch optimization, hit telemetry |
| Rule store | `/rules` | Query/create/update/enable/disable/version/rollback detection rules |

See [api-reference.md](api-reference.md) for details; Splunk fields are in [splunk-events.md](splunk-events.md).

## Detection Engines (rules as data)

All detection rules live in a single SQLite rule store (`rules.db`), executed by the
multi-engine `middlewares/rule_engine.py`. They can be queried/edited externally via `/rules`
and hot-reload takes effect immediately. Engine types:

| engine | Coverage | Example rules |
|---|---|---|
| `regex` | Prompt injection, command execution | system_instruction_override, destructive_command |
| `keyword` | Destructive high-risk keywords | high_risk_action_keyword |
| `entropy` | High-entropy encoded/obfuscated strings | high_entropy_blob |
| `sensitive` | Sensitive information (with declarative masking) | api_key, jwt, email, phone… |

Decision: the highest-scoring hit wins; blocking occurs only when `risk_score >= policy.block_threshold`
(below the threshold = detected but allowed).
Severity: `critical≥90 / high≥70 / medium≥40 / low<40`.
OWASP mapping: `LLM01: Prompt Injection` / `LLM05: Improper Output Handling` / `LLM06: Sensitive Information Disclosure`.

## Agent Integration (standardized, foolproof)

What is standardized is the "interception point", not the agent's functionality. Three integration modes:

| Mode | Operation | Language-agnostic |
|---|---|---|
| **LLM-compatible proxy (recommended, zero-code)** | Set `OPENAI_BASE_URL=http://gateway:3001/v1` | ✅ Any language |
| SDK / decorator (in-process) | Call `guard_input/guard_action/scan_skill` | Python, etc. |
| Non-invasive patch / launcher wrapper | Monkey-patch the chokepoint methods (see `CMS_Agent/crm_secure.py`) | No change to business code |

Channel → detection-module mapping: `user_input/retrieved_content → injection/sensitive`,
`tool_call → action guard/command execution`, `skill_load → /scan`, `output → output guard`.

## Running

```bash
# Required (otherwise logs do not reach Splunk; the sender silently skips)
export SPLUNK_HEC_URL="http://localhost:8088/services/collector"
export SPLUNK_HEC_TOKEN="<HEC token>"
export NO_PROXY="localhost,127.0.0.1"
# Optional
export GATEWAY_ID="gateway-01"        # default gateway-01
export LLM_PROVIDER="anthropic"       # default anthropic
export OPENAI_UPSTREAM_URL=...        # real upstream for the LLM proxy (if unset, requests are simulated/allowed)
export OPENAI_UPSTREAM_KEY=...

python -m gateway.main                # default http://0.0.0.0:3001
```

On startup: an empty rule store is auto-seeded (~32 rules), the data-driven engines are loaded,
and the reliable-delivery worker starts.

## Reliable Delivery

Events pass through `SpoolingSink`: in-memory queue → batching → retry with backoff →
spilled to disk `splunk_spool.jsonl` on failure → replayed once Splunk recovers
(at-least-once, deduplicated by `event_id`) → graceful flush on shutdown.
In short: "as long as it was inspected, the event is not lost".

## Key Files

| File | Responsibility |
|---|---|
| `gateway/main.py` | Entry point, routing, detection flow, lifecycle |
| `gateway/mcp_sender.py` | Event model `SecurityEvent` + reliable delivery `SpoolingSink` |
| `gateway/rule_store.py` | SQLite rule store (schema/CRUD/version/validation/seed) |
| `gateway/middlewares/rule_engine.py` | Multi-engine data-driven detector |
| `gateway/rules_api.py` | `/rules` rule management API |
| `gateway/disposition.py` | `/bans` + `/policy` (incl. optimize/stats) + pre-detection ban middleware |
| `gateway/llm_proxy.py` | `/v1/chat/completions` OpenAI-compatible proxy |
| `gateway/preprocess.py` | Sanitization/decoding preprocessing (strip zero-width/full-width/split chars + recursive base64/url/html decode) |
