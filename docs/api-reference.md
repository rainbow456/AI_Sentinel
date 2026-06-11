# API 参考

Base URL 默认 `http://localhost:3001`。写操作 `actor` 查询参数标识调用方(默认 `external-agent`)。

---

## 一、检测 / 接入端点

### POST /chat — 输入守卫
请求:`{"prompt": "...", "session_id": "可选"}`
- 通过:`200 {"request_id","blocked":false,"reply","cost_ms"}`
- 拦截:`403 {"request_id","blocked":true,"reason","detail":{...hit},"auto_banned","cost_ms"}`
- 仅当 `risk_score >= policy.block_threshold` 才拦;命中拦截会累计自动封禁。

### POST /confirm-action — 动作守卫
请求:`{"action_name","action_params":{},"agent_id","user_input":"","context":null}`
响应:`200 {"request_id","allowed","reason","rule_hit","risk_score"}`
- 破坏性关键词硬阻断优先;否则过检测器链。

### POST /scan — Skill 扫描
请求:`{"skill_name","skill_content"}`
响应:`200 {"is_malicious","risk_score","findings":[{"rule_hit","owasp_ast","severity","description","matched_content"}],"scan_duration_ms"}`
- 多引擎逐规则命中(多 finding),敏感信息在 `matched_content` 已脱敏。

### POST /v1/chat/completions — OpenAI 兼容检测代理
请求:OpenAI ChatCompletion 格式 `{"model","messages":[{"role","content"}], ...}`;可带头 `X-Agent-Id`。
响应:标准 ChatCompletion + 附加 `x_sentinel:{blocked,risk_score,...}`
- 入参检测命中且超阈值 → 返回拒答(`x_sentinel.blocked=true`);否则转发上游(未配置上游则模拟放行)。
- 接入:任意语言 OpenAI SDK 设 `base_url=<gateway>/v1` 即可,零改动。

### GET /health
`200 {"status":"ok","detector_count":N}`

---

## 二、风险处置 API(外部 agent 可联调)

### IP 封禁 `/bans`

| 方法 | 路径 | 入参 | 说明 |
|---|---|---|---|
| GET | `/bans` | — | 生效封禁列表(含 `remaining_seconds`) |
| GET | `/bans/{ip}` | — | `{ip,banned,record}` |
| POST | `/bans` | `{ip,type:"temp"\|"permanent",ttl_seconds?,reason}` | temp 默认 3600s |
| DELETE | `/bans/{ip}` | — | 解封 |

被封 IP 的请求在**进入检测前**由中间件 403 拦下(管理面 `/bans /rules /policy /health` 豁免)。

### 策略 / 阈值 `/policy`

| 方法 | 路径 | 入参 | 说明 |
|---|---|---|---|
| GET | `/policy` | — | 当前阈值 + 自动封禁参数 |
| PUT | `/policy` | `{block_threshold,suspicious_threshold,auto_ban_enabled,auto_ban_max_blocks,auto_ban_window_s,auto_ban_ttl_s}` | 部分更新,阈值 0–100 |
| POST | `/policy/preset/{name}` | `name∈strict\|balanced\|lenient` | 一键预设 |
| POST | `/policy/optimize` | `{rules:[...],enable:[],disable:[],policy:{},dry_run:false}` | **批量原子调整**:全量预校验,任一失败整批 400;`dry_run` 仅预览 |
| GET | `/policy/stats` | — | 各规则命中次数(含从未命中的启用规则) |
| POST | `/policy/optimize/suggest` | — | 启发式优化建议(从未命中/Top 命中) |

预设值:`strict`(阈值50+自动封禁开)/`balanced`(70)/`lenient`(90)。

### 检测规则 `/rules`

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/rules?category=&enabled=&tag=&q=` | 查询/搜索 |
| GET | `/rules/{id}` | 取单条 |
| POST | `/rules/validate` | 干跑校验(regex 编译+ReDoS+自带用例),不写库 |
| POST | `/rules` | 新增(校验+测试门禁→入库→热加载) |
| PUT | `/rules/{id}` | 修改 |
| PATCH | `/rules/{id}/enable` · `/disable` | 启停(即时生效) |
| DELETE | `/rules/{id}` | 删除 |
| POST | `/rules/{id}/test` | `{samples:[...]}` 对该规则试跑 |
| GET | `/rules/{id}/versions` | 版本历史 |
| POST | `/rules/{id}/rollback/{version}` | 回滚 |
| POST | `/rules/reload` | 手动热加载 |

**规则体字段**:
```json
{
  "id": "唯一id", "name": "规则名", "category": "分组",
  "owasp_ast": "LLM01: Prompt Injection",
  "severity_score": 90,
  "engine": "regex | sensitive | keyword | entropy",
  "patterns": ["正则..."],
  "flags": ["IGNORECASE"],
  "params": { "keywords": ["..."], "min_entropy": 4.5, "mask": "keep:3,4" },
  "enabled": true, "tags": ["..."], "description_zh": "中文说明",
  "test_cases": { "should_match": ["..."], "should_not_match": ["..."] }
}
```
- 调阈值 = 改 `severity_score` 或 entropy 的 `params.min_entropy`。
- 掩码描述符(sensitive 引擎 `params.mask`):`keep:H,T` / `email` / `ip_last_octet` / `cc_last4`。
- 写入校验:regex 必须可编译、长度上限、基础 ReDoS 拒绝;带 `test_cases` 则必须通过才入库。

---

## 三、联调闭环示例

```
读 Splunk 找误报/攻击
  → GET /policy/stats 看命中  → POST /policy/optimize/suggest 拿建议
  → POST /policy/optimize {dry_run:true} 预览
  → POST /policy/optimize 正式应用(改规则+阈值，原子)
  → POST /bans 封禁恶意来源（或 PUT /policy 开自动封禁）
  → 改动即时热加载，rule_admin / disposition 审计回 Splunk
```
