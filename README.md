# AI Sentinel — AI 安全网关与智能分析平台

> **AI Sentinel** 由两个独立模块组成：
> - **Gateway**（安全网关）：在用户输入与 Agent 高危操作之间拦截恶意流量
> - **Analyst**（智能分析师）：多告警安全分析、因果决策树、涌现行为检测
>
> 两个模块协同工作，形成「检测 → 上报 → 分析 → 阻断」的完整安全闭环。

## 目录

1. [系统架构](#1-系统架构)
2. [快速开始 — 一键启动](#2-快速开始)
3. [Gateway 安全网关](#3-gateway-安全网关)
4. [Analyst 智能分析平台](#4-analyst-智能分析平台)
5. [CMS Agent 演示](#5-cms-agent-演示)
6. [配置（环境变量）](#6-配置环境变量)
7. [API 参考](#7-api-参考)
8. [集成测试](#8-集成测试)
9. [项目结构](#9-项目结构)

---

## 1. 系统架构

```
                           ┌──────────────────────────┐
         用户输入  ──────▶ │  AI Sentinel Gateway      │
                           │  (FastAPI :3001)          │
                           │  ├─ /chat     输入守卫    │
                           │  ├─ /confirm-action       │
                           │  ├─ /scan     技能扫描    │
                           │  ├─ /v1/chat/completions  │
                           │  ├─ /bans     IP 封禁     │
                           │  ├─ /rules    规则管理    │
                           │  └─ /policy   策略配置    │
                           └──────────┬───────────────┘
                                      │ SecurityEvent JSON
                                      ▼
                           ┌──────────────────────────┐
                           │  Splunk HEC / 模拟存储    │
                           │  (:8088 或 :8000)         │
                           └──────────┬───────────────┘
                                      │ 查询事件
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
                                      │ 阻断指令
                                      ▼
                           ┌──────────────────────────┐
                           │  Gateway /bans API        │
                           │  (封禁 IP / 目标)          │
                           └──────────────────────────┘
```

**数据流**：Gateway 检测恶意输入 → 上报 SecurityEvent → Splunk 存储 → Analyst 拉取事件 → 规则匹配 → 自动/人工阻断 → 生成决策树报告

---

## 2. 快速开始

### 2.1 安装依赖

```bash
cd d:\Programs\AI_Sentinel
pip install -r requirements.txt
```

主要依赖：`fastapi` `uvicorn` `httpx` `flask` `mcp` `pyyaml` `pydantic`（Presidio 和 splunk-sdk 为可选依赖）

### 2.2 一键启动（推荐）

```powershell
# PowerShell — 启动网关 + Analyst UI + CMS Agent（网页模式）
.\start_all.ps1

# 或分别启动：
.\start_all.ps1 -Gateway       # 仅启动网关 :3001
.\start_all.ps1 -Analyst       # 仅启动 Analyst UI :5000
.\start_all.ps1 -CmsAgent      # 仅启动 CMS Agent :6001
.\start_all.ps1 -Web           # CMS Agent 网页模式
```

```cmd
:: CMD — 双击运行
start_all.bat
```

### 2.3 手动分别启动

**终端 1 — Gateway（端口 3001）**：
```bash
python -m gateway.main
```

**终端 2 — Analyst UI（端口 5000）**：
```bash
python -m analyst.ui.app
```

### 2.4 配置 Splunk 连接

复制 `.env.example` 为 `.env` 并填入实际值：

```bash
cp .env.example .env
```

关键变量（默认使用模拟数据，无需 Splunk 也可运行）：
- `SPLUNK_HEC_URL` / `SPLUNK_HEC_TOKEN` — Gateway 上报事件到 Splunk
- `SPLUNK_HOST` / `SPLUNK_PORT` — Analyst 从 Splunk 查询事件
- `SPLUNK_USE_REAL=false` — 设为 `true` 连接真实 Splunk

### 2.5 验证

```bash
# Gateway 健康检查
curl http://localhost:3001/health
# → {"status":"ok","detector_count":5}

# Analyst 统计
curl http://localhost:5000/api/stats
# → {"mode":"observe","total_alerts":...,"total_events":...}

# Analyst 指挥中心 UI
# 浏览器打开 http://localhost:5000
```

---

## 3. Gateway 安全网关

基于 **FastAPI** 的安全网关，部署在 Agent / LLM 应用「前面」。

**核心能力**：
- 可插拔检测器（自动扫描 `gateway/middlewares/`）
- 命中即阻断（403 + 命中详情）
- 高危关键词硬阻断（delete / drop / rm -rf 等）
- 结构化 JSON 日志 + Splunk HEC 异步上报
- IP 自动封禁（滑动窗口超阈值）
- OpenAI 兼容代理（`/v1/chat/completions`）
- 规则管理 API（`/rules`）、策略 API（`/policy`）

**内置检测器**：
| 模块 | 能力 |
|------|------|
| `rule_engine.py` | 数据驱动多引擎（regex/sensitive/keyword/entropy） |
| `injection.py` | 提示词注入/越狱（10 大类） |
| `prompt_injection.py` | 注入/越狱（关键词正则，含中文） |
| `sensitive.py` | 敏感信息（正则 + Presidio） |
| `pii_leak.py` | PII（Presidio 优先） |
| `command_exec.py` | 命令执行检测 |
| `entropy.py` | 高熵混淆检测 |

**API 入口**：`POST /chat`、`POST /confirm-action`、`POST /scan`、`POST /v1/chat/completions`、`GET/POST /bans`、`GET/POST /rules`、`GET/PUT /policy`

---

## 4. Analyst 智能分析平台

基于 **Flask** 的 Web UI + SecurityAgent，提供多告警安全分析能力。

**核心能力**：
- 双模式：AUTO（自动阻断）/ OBSERVE（人工确认）
- NL 命令解析（自然语言查询/操作/规则配置）
- 3 个 MCP Server（Splunk Query / Gateway Control / Rule Engine）
- 因果决策树构建与可视化
- 涌现行为检测（共谋/越权/推理错误等）
- 处置记录追踪（auto 阻断 / admin 确认）

**API 端点**：
| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/` | 指挥中心仪表盘 |
| GET | `/api/stats` | 统计概览 |
| GET | `/api/alerts` | 告警列表 |
| POST | `/api/query` | NL 查询/命令 |
| POST | `/api/block/:id` | 确认阻断（OBSERVE） |
| GET/POST | `/api/mode` | 模式切换 |
| GET | `/api/rules` | 规则列表 |
| GET | `/api/dispositions` | 处置记录 |

---

## 5. CMS Agent 演示

`cms_agent/` 包含一个轻量级 CRM Agent 及其安全守卫包装器：

| 文件 | 用途 |
|------|------|
| `crm_agent.py` | 原始 CRM Agent（SQLite 数据，自然语言交互） |
| `crm_secure.py` | 安全守卫包装器（monkey-patch 接入 Gateway） |
| `start_secure_crm.bat` | CMD 启动脚本 |
| `start_secure_crm.ps1` | PowerShell 一键启动（含 Gateway） |

**用法**：
```bash
cd cms_agent

# 原版 CRM（不经过安全网关）
python crm_agent.py

# 安全版 CRM（经过 Gateway 检测）
python crm_secure.py          # 命令行模式
python crm_secure.py web 6001 # 网页模式 (http://127.0.0.1:6001)
```

**守卫策略**：
- 输入守卫：仅拦截「提示词注入/越狱」类（PII/敏感类放行，CRM 录入合法字段）
- 动作守卫：删除操作使用中性动作名 `remove_record` 上报，避开英文硬阻断词

---

## 6. 配置（环境变量）

完整配置见 [.env.example](.env.example)。关键变量：

### Gateway
| 变量 | 默认值 | 说明 |
|------|--------|------|
| `GATEWAY_ID` | `gateway-01` | 网关实例标识 |
| `LLM_PROVIDER` | `anthropic` | 下游 LLM 提供方 |
| `SPLUNK_HEC_URL` | - | Splunk HEC 端点 |
| `SPLUNK_HEC_TOKEN` | - | Splunk HEC token |

### Analyst
| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SPLUNK_HOST` | `splunk.example.com` | Splunk 搜索主机 |
| `SPLUNK_PORT` | `8089` | Splunk 管理端口 |
| `SPLUNK_USE_REAL` | `false` | 连接真实 Splunk |
| `GATEWAY_HOST` | `gateway.example.com` | Gateway 主机 |
| `GATEWAY_PORT` | `8443` | Gateway 端口 |
| `RULES_PATH` | - | rules.yaml 路径 |

---

## 7. API 参考

### Gateway API (`localhost:3001`)

详见原 README §3-4，核心端点：
- `POST /chat` — 用户输入检测（200 放行 / 403 阻断）
- `POST /confirm-action` — 高危操作确认（`allowed` 字段）
- `POST /scan` — 技能内容扫描（多 finding 返回）
- `GET /health` — 健康检查
- `GET/POST /bans` — IP 封禁管理
- `GET/POST /rules` — 规则 CRUD
- `GET/PUT /policy` — 策略配置

### Analyst API (`localhost:5000`)

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/stats` | 统计概览 |
| GET | `/api/alerts` | 告警列表 |
| GET | `/api/alerts/<id>` | 告警详情 |
| POST | `/api/query` | NL 查询 |
| POST | `/api/block/<id>` | 确认阻断 |
| GET/POST | `/api/mode` | 模式查询/切换 |
| GET | `/api/rules` | 规则列表 |
| POST | `/api/rules/search` | 规则搜索 |
| GET | `/api/dispositions` | 处置记录 |
| GET | `/api/mcp/status` | MCP 状态 |

---

## 8. 集成测试

```bash
# 完整测试（需先启动 Gateway）
python tests/integration_test.py

# 快速测试（无需子进程，Gateway 已运行）
python tests/integration_test.py --quick
```

测试覆盖：
1. Gateway 检测逻辑（注入/正常/高危命令/脱敏）
2. 数据格式对齐（Gateway → Analyst）
3. Rule Engine 规则匹配
4. 因果决策树构建
5. MCP Bridge 三服务器连接
6. 完整 Agent 周期（事件→规则→阻断→记录）
7. CSV 数据管道
8. rules.yaml 校验

---

## 9. 项目结构

```
AI_Sentinel/
├── gateway/                       # A 模块：安全网关
│   ├── main.py                    # FastAPI 入口，路由，检测器加载
│   ├── mcp_sender.py              # Splunk HEC 异步发送器 + 可靠投递管线
│   ├── disposition.py             # IP 封禁/策略管理（SQLite）
│   ├── llm_proxy.py               # OpenAI 兼容代理
│   ├── preprocess.py              # 输入预处理器（混淆还原）
│   ├── rule_store.py              # 规则存储（SQLite + 版本历史）
│   ├── rules_api.py               # 规则管理 REST API
│   └── middlewares/               # 可插拔检测器（自动注册）
├── analyst/                       # B 模块：智能分析平台
│   ├── agent.py                   # SecurityAgent（双模式，NL命令）
│   ├── config.py                  # 统一配置（环境变量 > 默认值）
│   ├── mcp_client.py              # MCP Bridge（子进程 stdio 连接）
│   ├── models.py                  # 数据模型（Span/CausalNode/GatewayEvent/...）
│   ├── rule_engine.py             # 规则引擎（匹配事件到规则）
│   ├── causal_analyzer.py         # 因果决策树构建与分析
│   ├── nl_engine.py               # NL 意图分类/命令解析/规则搜索
│   ├── report_engine.py           # 报告生成（Mermaid.js + 涌现检测）
│   ├── servers/                   # MCP 服务器（作为子进程运行）
│   │   ├── splunk_mcp.py          # Splunk 查询（真实/模拟）
│   │   ├── gateway_mcp.py         # Gateway 控制（真实 API / 模拟）
│   │   └── rule_mcp.py            # 规则引擎（YAML 热加载）
│   └── ui/                        # Web UI
│       ├── app.py                 # Flask 应用（API + 仪表盘）
│       └── templates/dashboard.html
├── cms_agent/                     # 演示：CRM Agent + 安全守卫
│   ├── crm_agent.py               # 原始 CRM Agent
│   ├── crm_secure.py              # 安全守卫包装器
│   └── start_secure_crm.ps1       # 一键启动脚本
├── data/                          # Gateway 事件 CSV 数据
├── tests/                         # 集成测试
│   └── integration_test.py
├── legacy/                        # 旧版文件（已弃用）
├── rules.yaml                     # 共享规则文件
├── .env.example                   # 环境变量模板
├── requirements.txt               # 统一依赖
├── start_all.ps1                  # 一键启动脚本
├── start_all.bat                  # CMD 一键启动
├── README.md                      # 本文件
└── CLAUDE.md                      # Claude Code 指令
```

关键入口速查：
| 你想… | 看这里 |
|--------|--------|
| 改 Gateway 路由/响应 | [gateway/main.py](gateway/main.py) |
| 改高危关键词清单 | [gateway/main.py](gateway/main.py) `HIGH_RISK_KEYWORDS` |
| 加/改检测规则 | [gateway/middlewares/](gateway/middlewares/) |
| 改 Analyst 模式逻辑 | [analyst/agent.py](analyst/agent.py) |
| 改自然语言解析 | [analyst/nl_engine.py](analyst/nl_engine.py) |
| 改 MCP 工具定义 | [analyst/servers/](analyst/servers/) |
| 改仪表盘 UI | [analyst/ui/templates/dashboard.html](analyst/ui/templates/dashboard.html) |
| 改共享规则 | [rules.yaml](rules.yaml) |
