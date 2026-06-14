# API Reference

Base URL defaults to `http://localhost:3001`. For write operations, the `actor` query parameter identifies the caller (default `external-agent`).

---

## 1. Detection / Integration Endpoints

### POST /chat — Input Guard
Request: `{"prompt": "...", "session_id": "optional"}`
- Pass: `200 {"request_id","blocked":false,"reply","cost_ms"}`
- Block: `403 {"request_id","blocked":true,"reason","detail":{...hit},"auto_banned","cost_ms"}`
- Blocks only when `risk_score >= policy.block_threshold`; each block hit counts toward auto-ban.

### POST /confirm-action — Action Guard
Request: `{"action_name","action_params":{},"agent_id","user_input":"","context":null}`
Response: `200 {"request_id","allowed","reason","rule_hit","risk_score"}`
- Destructive-keyword hard block takes priority; otherwise runs through the detector chain.

### POST /scan — Skill Scan
Request: `{"skill_name","skill_content"}`
Response: `200 {"is_malicious","risk_score","findings":[{"rule_hit","owasp_ast","severity","description","matched_content"}],"scan_duration_ms"}`
- Multi-engine, rule-by-rule matching (multiple findings); sensitive info is already masked in `matched_content`.

### POST /v1/chat/completions — OpenAI-compatible Detection Proxy
Request: OpenAI ChatCompletion format `{"model","messages":[{"role","content"}], ...}`; may include the `X-Agent-Id` header.
Response: standard ChatCompletion + an extra `x_sentinel:{blocked,risk_score,...}`
- If the input is detected as a hit and exceeds the threshold → returns a refusal (`x_sentinel.blocked=true`); otherwise forwards to the upstream (simulated/allowed if no upstream is configured).
- Integration: any-language OpenAI SDK just sets `base_url=<gateway>/v1`, no code changes.

### GET /health
`200 {"status":"ok","detector_count":N}`

---

## 2. Risk Disposition API (external agents can integrate)

### IP Bans `/bans`

| Method | Path | Params | Description |
|---|---|---|---|
| GET | `/bans` | — | List of active bans (incl. `remaining_seconds`) |
| GET | `/bans/{ip}` | — | `{ip,banned,record}` |
| POST | `/bans` | `{ip,type:"temp"\|"permanent",ttl_seconds?,reason}` | temp defaults to 3600s |
| DELETE | `/bans/{ip}` | — | Unban |

Requests from banned IPs are blocked with 403 by the middleware **before detection** (the management plane `/bans /rules /policy /health` is exempt).

### Policy / Threshold `/policy`

| Method | Path | Params | Description |
|---|---|---|---|
| GET | `/policy` | — | Current thresholds + auto-ban parameters |
| PUT | `/policy` | `{block_threshold,suspicious_threshold,auto_ban_enabled,auto_ban_max_blocks,auto_ban_window_s,auto_ban_ttl_s}` | Partial update, thresholds 0–100 |
| POST | `/policy/preset/{name}` | `name∈strict\|balanced\|lenient` | One-click preset |
| POST | `/policy/optimize` | `{rules:[...],enable:[],disable:[],policy:{},dry_run:false}` | **Atomic batch adjustment**: full pre-validation, whole batch returns 400 if any item fails; `dry_run` only previews |
| GET | `/policy/stats` | — | Hit count per rule (incl. enabled rules that never matched) |
| POST | `/policy/optimize/suggest` | — | Heuristic optimization suggestions (never-hit / top hits) |

Preset values: `strict` (threshold 50 + auto-ban on) / `balanced` (70) / `lenient` (90).

### Detection Rules `/rules`

| Method | Path | Description |
|---|---|---|
| GET | `/rules?category=&enabled=&tag=&q=` | Query/search |
| GET | `/rules/{id}` | Fetch one |
| POST | `/rules/validate` | Dry-run validation (regex compile + ReDoS + built-in test cases), does not write to the store |
| POST | `/rules` | Create (validate + test gate → store → hot-reload) |
| PUT | `/rules/{id}` | Update |
| PATCH | `/rules/{id}/enable` · `/disable` | Enable/disable (takes effect immediately) |
| DELETE | `/rules/{id}` | Delete |
| POST | `/rules/{id}/test` | `{samples:[...]}` test-run against this rule |
| GET | `/rules/{id}/versions` | Version history |
| POST | `/rules/{id}/rollback/{version}` | Rollback |
| POST | `/rules/reload` | Manual hot-reload |

**Rule body fields**:
```json
{
  "id": "unique id", "name": "rule name", "category": "group",
  "owasp_ast": "LLM01: Prompt Injection",
  "severity_score": 90,
  "engine": "regex | sensitive | keyword | entropy",
  "patterns": ["regex..."],
  "flags": ["IGNORECASE"],
  "params": { "keywords": ["..."], "min_entropy": 4.5, "mask": "keep:3,4" },
  "enabled": true, "tags": ["..."], "description_zh": "description",
  "test_cases": { "should_match": ["..."], "should_not_match": ["..."] }
}
```
- Tune thresholds = change `severity_score`, or the entropy engine's `params.min_entropy`.
- Mask descriptor (sensitive engine `params.mask`): `keep:H,T` / `email` / `ip_last_octet` / `cc_last4`.
- Write validation: regex must compile, length is capped, basic ReDoS is rejected; if `test_cases` are present they must pass before storing.

---

## 3. Integration Closed-Loop Example

```
Read Splunk to find false positives / attacks
  → GET /policy/stats to see hits  → POST /policy/optimize/suggest to get suggestions
  → POST /policy/optimize {dry_run:true} to preview
  → POST /policy/optimize to apply for real (change rules + thresholds, atomic)
  → POST /bans to ban malicious sources (or PUT /policy to enable auto-ban)
  → changes hot-reload immediately; rule_admin / disposition audit flows back to Splunk
```
