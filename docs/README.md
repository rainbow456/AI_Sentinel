# AI_Sentinel 网关 — 总览

面向 AI Agent 的安全网关:拦截恶意输入、扫描恶意 skill、守卫高危动作,并提供
可查询/可修改的检测规则库与风险处置 API,所有事件标准化上报 Splunk。

## 能力地图

| 能力 | 入口 | 说明 |
|---|---|---|
| 输入守卫 | `POST /chat` | 用户输入过检测器,命中按阈值拦截 |
| 动作守卫 | `POST /confirm-action` | 高危动作(删除等)执行前确认 |
| Skill 扫描 | `POST /scan` | 上传的 skill 静态多引擎检测 |
| LLM 兼容代理 | `POST /v1/chat/completions` | 任意语言 agent 改 `base_url` 即接入 |
| IP 封禁 | `/bans` | 临时/永久封禁 + 自动封禁 |
| 策略/阈值 | `/policy` | 拦截阈值、预设、批量优化、命中遥测 |
| 规则库 | `/rules` | 检测规则查询/增改/启停/版本/回滚 |

详见 [api-reference.md](api-reference.md);Splunk 字段见 [splunk-events.md](splunk-events.md)。

## 检测引擎(规则即数据)

所有检测规则统一存于 SQLite 规则库(`rules.db`),由 `middlewares/rule_engine.py`
多引擎执行,外部可经 `/rules` 查改、热加载即时生效。引擎类型:

| engine | 覆盖 | 示例规则 |
|---|---|---|
| `regex` | 提示词注入、命令执行 | system_instruction_override、destructive_command |
| `keyword` | 破坏性高危词 | high_risk_action_keyword |
| `entropy` | 高熵编码/混淆串 | high_entropy_blob |
| `sensitive` | 敏感信息(带声明式掩码) | api_key、jwt、email、phone… |

判定:命中取最高分;`risk_score >= policy.block_threshold` 才拦截(低于阈值=检出但放行)。
严重度:`critical≥90 / high≥70 / medium≥40 / low<40`。
OWASP 映射:`LLM01: Prompt Injection` / `LLM05: Improper Output Handling` / `LLM06: Sensitive Information Disclosure`。

## Agent 接入(标准化、可傻瓜化)

标准化的是「拦截点」而非 agent 功能。三种接入模式:

| 模式 | 操作 | 语言无关 |
|---|---|---|
| **LLM 兼容代理(推荐零代码)** | 设 `OPENAI_BASE_URL=http://gateway:3001/v1` | ✅ 任意语言 |
| SDK / 装饰器(进程内) | 调 `guard_input/guard_action/scan_skill` | Python 等 |
| 非侵入 patch / 启动器包装 | monkey-patch 汇聚方法(见 `CMS_Agent/crm_secure.py`) | 不改业务码 |

通道(channel)→ 检测模块映射:`user_input/retrieved_content → 注入/敏感`,
`tool_call → 动作守卫/命令执行`,`skill_load → /scan`,`output → 输出守卫`。

## 运行

```bash
# 必配(否则日志不进 Splunk，sender 静默跳过)
export SPLUNK_HEC_URL="http://localhost:8088/services/collector"
export SPLUNK_HEC_TOKEN="<HEC token>"
export NO_PROXY="localhost,127.0.0.1"
# 可选
export GATEWAY_ID="gateway-01"        # 默认 gateway-01
export LLM_PROVIDER="anthropic"       # 默认 anthropic
export OPENAI_UPSTREAM_URL=...        # LLM 代理真实上游(不配则模拟放行)
export OPENAI_UPSTREAM_KEY=...

python -m gateway.main                # 默认 http://0.0.0.0:3001
```

启动时:空规则库自动 seed(约 32 条)、加载数据驱动引擎、启动可靠投递 worker。

## 可靠投递

事件经 `SpoolingSink`:内存队列 → 批量 → 重试退避 → 失败落盘 `splunk_spool.jsonl` →
Splunk 恢复后回放(至少一次,`event_id` 去重) → 关机优雅 flush。
即「只要经过检测,事件不丢」。

## 关键文件

| 文件 | 职责 |
|---|---|
| `gateway/main.py` | 入口、路由、检测流、生命周期 |
| `gateway/mcp_sender.py` | 事件模型 `SecurityEvent` + 可靠投递 `SpoolingSink` |
| `gateway/rule_store.py` | SQLite 规则库(schema/CRUD/版本/校验/seed) |
| `gateway/middlewares/rule_engine.py` | 多引擎数据驱动检测器 |
| `gateway/rules_api.py` | `/rules` 规则管理 API |
| `gateway/disposition.py` | `/bans` + `/policy`(含 optimize/stats)+ 前置封禁中间件 |
| `gateway/llm_proxy.py` | `/v1/chat/completions` OpenAI 兼容代理 |
| `gateway/preprocess.py` | 洗白/解码预处理(去零宽/全角/拆字 + 递归 base64/url/html) |
