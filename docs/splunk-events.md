# Splunk 事件字段字典

外层 HEC 信封固定 `sourcetype = "ai_sentinel:gateway"`,`event` 为标准化 `SecurityEvent`。
字段路径用点号表示嵌套,`[]` 表示数组元素。所有事件经可靠投递管线(队列+重试+磁盘 spool)送达。

## 字段总表

| 字段路径 | 含义 | 枚举 / 固定值 | 写入模块 |
|---|---|---|---|
| `sourcetype` | Splunk 源类型 | **固定** `ai_sentinel:gateway` | 全部 |
| `event.event_id` | 事件唯一 ID(至少一次投递去重) | uuid hex | 全部 |
| `event.timestamp` | 事件时间 | ISO-8601 UTC,自动 | 全部 |
| `event.module` | 哪个模块的日志 | **枚举** `input_guard`/`action_guard`/`skill_scanner`/`rule_admin`/`disposition` | 见下 |
| `event.blocked` | 是否已拦截 | `true`/`false` | 全部 |
| `event.handler` | 处置者 | **枚举** `gateway`(自处理/自动)/`external`(外部下令) | 全部 |
| `event.risk_score` | 最高风险分 | 0–100;放行为 0 | 全部 |
| `event.user_input` | 脱敏后被检内容 / 动作描述 | `sk-***`、`***EMAIL***`、超长截断 | 全部 |
| `event.subject_name` | 被判对象 | 动作名 / skill 名 / IP / `-` / null | 见下 |
| `event.agent_id` | 调用方标识 | 默认 null;如 `crm-agent-01` | 全部 |
| `event.findings` | 命中列表(合并 hit+findings) | 放行/无命中为 `[]` | 检测类为主 |
| `event.findings[].detector` | 检测器模块名 | 如 `injection`;引擎/扫描为空串 | 检测类 |
| `event.findings[].rule_hit` | 命中规则名 | system_instruction_override / api_key / high_risk_action_keyword / high_entropy_blob… | 检测类 |
| `event.findings[].owasp_ast` | OWASP 分类 | **枚举** `LLM01: Prompt Injection`/`LLM05: Improper Output Handling`/`LLM06: Sensitive Information Disclosure` | 检测类 |
| `event.findings[].severity` | 严重等级 | **枚举** `critical`(≥90)/`high`(≥70)/`medium`(≥40)/`low`(<40) | 检测类 |
| `event.findings[].matched` | 脱敏命中片段 | 如 `sk-***mnop`、`*@b.com` | 检测类 |
| `event.findings[].description` | 规则中文说明 | — | 检测类 |
| `event.gateway_id` | 网关实例标识 | 默认 `gateway-01` | 全部 |
| `event.llm_provider` | 下游 LLM 提供方 | 默认 `anthropic`,可 null | 全部 |

## 模块 → 接口 + 典型取值

| `module` | 写入接口 | `blocked` | `handler` | subject_name |
|---|---|---|---|---|
| `input_guard` | `/chat`、`/v1/chat/completions` | 命中且≥阈值 | `gateway` | model 名 / null |
| `action_guard` | `/confirm-action` | `not allowed` | `gateway` | 动作名 |
| `skill_scanner` | `/scan` | `is_malicious` | `external` | skill 名 |
| `rule_admin` | `/rules*`、`/policy/optimize` | `false` | `external` | 规则 id / `-` |
| `disposition` | `/bans*`、`/policy*`、自动封禁、封禁拦截 | 封禁/拦截=true,解封/调参=false | 人工=`external`,自动/拦截=`gateway` | IP / `-` |

## 样例

```json
{"sourcetype":"ai_sentinel:gateway","event":{"event_id":"a1..","module":"input_guard","blocked":true,"handler":"gateway","risk_score":90,"user_input":"ignore all previous...","subject_name":"gpt-4o","agent_id":"go-agent-01","findings":[{"detector":"","rule_hit":"system_instruction_override","owasp_ast":"LLM01: Prompt Injection","severity":"critical","matched":"ignore all previous instructions","description":"覆盖系统指令"}],"gateway_id":"gateway-01","llm_provider":"anthropic"}}
{"event":{"module":"disposition","blocked":true,"handler":"gateway","risk_score":0,"user_input":"auto-ban 8.8.8.8 block threshold exceeded","subject_name":"8.8.8.8","agent_id":"auto-ban","findings":[]}}
{"event":{"module":"rule_admin","blocked":false,"handler":"external","user_input":"disable sensitive-email","subject_name":"sensitive-email","agent_id":"external-agent","findings":[]}}
```

## 常用 SPL

```spl
# 基础
sourcetype="ai_sentinel:gateway"

# 被拦截的（跨模块统一用 blocked）
sourcetype="ai_sentinel:gateway" blocked=true
| table _time, module, subject_name, agent_id, risk_score, findings{}.rule_hit

# 拦截率（输入守卫）
sourcetype="ai_sentinel:gateway" module="input_guard" | stats count by blocked

# Top 命中规则 / OWASP 分布
sourcetype="ai_sentinel:gateway" blocked=true | top limit=10 findings{}.rule_hit
sourcetype="ai_sentinel:gateway" | stats count by findings{}.owasp_ast

# 恶意 skill 扫描
sourcetype="ai_sentinel:gateway" module="skill_scanner" blocked=true
| table _time, subject_name, risk_score, findings{}.rule_hit

# 处置审计（封禁/解封/规则改动）
sourcetype="ai_sentinel:gateway" module IN ("disposition","rule_admin")
| table _time, module, handler, subject_name, agent_id, user_input

# 按 Agent / 处置者拆分
sourcetype="ai_sentinel:gateway" | stats count by agent_id, module, blocked
sourcetype="ai_sentinel:gateway" | stats count by handler, module
```

## 排查:日志没进 Splunk?

1. **网关进程是否配了** `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN`——未配则 `sender.enabled=False`,**静默跳过**(无错误、无日志)。
2. 网关窗口是否刷 `Failed to send event to Splunk HEC`——有则地址/ token/网络问题(检查 HEC 可达、token 有效、`NO_PROXY=localhost`)。
3. 都正常仍无数据:放宽时间范围;`index=*` 排查 token 落到的 index。
4. 临时不可达不会丢:事件落 `gateway/splunk_spool.jsonl`,恢复后自动回放。
