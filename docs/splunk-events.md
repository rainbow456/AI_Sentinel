# Splunk Event Field Dictionary

The outer HEC envelope is fixed at `sourcetype = "ai_sentinel:gateway"`, and `event` holds the normalized `SecurityEvent`.
Field paths use dots for nesting and `[]` for array elements. All events are delivered through the reliable-delivery pipeline (queue + retry + disk spool).

## Field Reference

| Field path | Meaning | Enum / fixed value | Writing module |
|---|---|---|---|
| `sourcetype` | Splunk source type | **fixed** `ai_sentinel:gateway` | all |
| `event.event_id` | Unique event ID (dedup for at-least-once delivery) | uuid hex | all |
| `event.timestamp` | Event time | ISO-8601 UTC, automatic | all |
| `event.module` | Which module produced the log | **enum** `input_guard`/`action_guard`/`skill_scanner`/`rule_admin`/`disposition` | see below |
| `event.blocked` | Whether it was blocked | `true`/`false` | all |
| `event.handler` | Who dispositioned it | **enum** `gateway` (self-handled/automatic) / `external` (commanded externally) | all |
| `event.risk_score` | Highest risk score | 0–100; 0 if allowed | all |
| `event.user_input` | Masked inspected content / action description | `sk-***`, `***EMAIL***`, truncated if too long | all |
| `event.subject_name` | Subject judged | action name / skill name / IP / `-` / null | see below |
| `event.agent_id` | Caller identifier | null by default; e.g. `crm-agent-01` | all |
| `event.findings` | Hit list (merged hit + findings) | `[]` if allowed/no hit | mainly detection types |
| `event.findings[].detector` | Detector module name | e.g. `injection`; empty string for engine/scan | detection types |
| `event.findings[].rule_hit` | Name of the rule hit | system_instruction_override / api_key / high_risk_action_keyword / high_entropy_blob… | detection types |
| `event.findings[].owasp_ast` | OWASP category | **enum** `LLM01: Prompt Injection`/`LLM05: Improper Output Handling`/`LLM06: Sensitive Information Disclosure` | detection types |
| `event.findings[].severity` | Severity level | **enum** `critical` (≥90) / `high` (≥70) / `medium` (≥40) / `low` (<40) | detection types |
| `event.findings[].matched` | Masked matched fragment | e.g. `sk-***mnop`, `*@b.com` | detection types |
| `event.findings[].description` | Rule description | — | detection types |
| `event.gateway_id` | Gateway instance identifier | `gateway-01` by default | all |
| `event.llm_provider` | Downstream LLM provider | `anthropic` by default, may be null | all |

## Module → Endpoint + Typical Values

| `module` | Writing endpoint | `blocked` | `handler` | subject_name |
|---|---|---|---|---|
| `input_guard` | `/chat`, `/v1/chat/completions` | hit and ≥ threshold | `gateway` | model name / null |
| `action_guard` | `/confirm-action` | `not allowed` | `gateway` | action name |
| `skill_scanner` | `/scan` | `is_malicious` | `external` | skill name |
| `rule_admin` | `/rules*`, `/policy/optimize` | `false` | `external` | rule id / `-` |
| `disposition` | `/bans*`, `/policy*`, auto-ban, ban interception | ban/interception = true, unban/tuning = false | manual = `external`, auto/interception = `gateway` | IP / `-` |

## Examples

```json
{"sourcetype":"ai_sentinel:gateway","event":{"event_id":"a1..","module":"input_guard","blocked":true,"handler":"gateway","risk_score":90,"user_input":"ignore all previous...","subject_name":"gpt-4o","agent_id":"go-agent-01","findings":[{"detector":"","rule_hit":"system_instruction_override","owasp_ast":"LLM01: Prompt Injection","severity":"critical","matched":"ignore all previous instructions","description":"Override system instructions"}],"gateway_id":"gateway-01","llm_provider":"anthropic"}}
{"event":{"module":"disposition","blocked":true,"handler":"gateway","risk_score":0,"user_input":"auto-ban 8.8.8.8 block threshold exceeded","subject_name":"8.8.8.8","agent_id":"auto-ban","findings":[]}}
{"event":{"module":"rule_admin","blocked":false,"handler":"external","user_input":"disable sensitive-email","subject_name":"sensitive-email","agent_id":"external-agent","findings":[]}}
```

## Common SPL

```spl
# Basic
sourcetype="ai_sentinel:gateway"

# Blocked (use blocked uniformly across modules)
sourcetype="ai_sentinel:gateway" blocked=true
| table _time, module, subject_name, agent_id, risk_score, findings{}.rule_hit

# Block rate (input guard)
sourcetype="ai_sentinel:gateway" module="input_guard" | stats count by blocked

# Top rule hits / OWASP distribution
sourcetype="ai_sentinel:gateway" blocked=true | top limit=10 findings{}.rule_hit
sourcetype="ai_sentinel:gateway" | stats count by findings{}.owasp_ast

# Malicious skill scans
sourcetype="ai_sentinel:gateway" module="skill_scanner" blocked=true
| table _time, subject_name, risk_score, findings{}.rule_hit

# Disposition audit (ban/unban/rule changes)
sourcetype="ai_sentinel:gateway" module IN ("disposition","rule_admin")
| table _time, module, handler, subject_name, agent_id, user_input

# Split by Agent / handler
sourcetype="ai_sentinel:gateway" | stats count by agent_id, module, blocked
sourcetype="ai_sentinel:gateway" | stats count by handler, module
```

## Troubleshooting: logs not reaching Splunk?

1. **Is the gateway process configured with** `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN`? If not, `sender.enabled=False` and it **silently skips** (no error, no log).
2. Does the gateway window show `Failed to send event to Splunk HEC`? If so, it's an address/token/network issue (check that HEC is reachable, the token is valid, and `NO_PROXY=localhost`).
3. Everything looks fine but still no data: widen the time range; use `index=*` to find which index the token lands in.
4. Temporary unreachability won't lose data: events spill to `gateway/splunk_spool.jsonl` and replay automatically once Splunk recovers.
