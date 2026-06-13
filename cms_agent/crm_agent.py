# -*- coding: utf-8 -*-
"""
================================================================================
 CRM-Agent —— 轻量级自然语言客户关系管理助手
================================================================================

参考 Salesforce Agentforce 的核心交互模式：完全基于自然语言对话。
用户在命令行输入中文指令，Agent 解析意图并操作本地数据。

【运行方式】
    命令行模式：python crm_agent.py
    网页模式：  python crm_agent.py web        （默认 http://127.0.0.1:6001）
                python crm_agent.py web 8080   （自定义端口）

两种模式共用同一套数据与业务逻辑。启动后会在脚本所在目录自动创建
SQLite 数据库文件 crm.db（已存在则复用）。

【依赖】
    仅标准库（sqlite3 / re / datetime 等）。
    可选：prettytable（pip install prettytable）——用于美化表格；
          未安装时自动降级为内置字符串对齐输出，功能不受影响。

【支持的命令示例】（输入 help 可随时查看）
    客户：  添加客户 张三 北京XX科技 13800000000 zhang@x.com 北京朝阳
            显示所有客户 / 查找客户 张三 / 修改客户3的电话为139xxxx / 删除客户 3
    联系人：添加联系人 李四 客户ID=1 职位销售经理 电话138xxxx 邮箱li@x.com
            显示所有联系人 / 客户1的联系人 / 删除联系人 2
    机会：  创建机会 年度采购 客户ID=1 金额50000
            将机会3推进到谈判 / 修改机会5金额为80000 / 关闭机会2 赢单 价格合适
            显示所有机会
    任务：  添加任务 客户1 回访客户 截止2026-06-10
            显示未完成任务 / 完成任务8 / 机会3的任务
    其他：  显示概览 / help / exit

【代码组织】
    DatabaseManager —— 所有 SQLite 读写
    CommandParser   —— 自然语言意图解析（正则 + 关键词）
    CRMAgent        —— 主循环、命令分发、业务逻辑、交互反馈
================================================================================
"""

# Load .env before reading any env vars
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import os
import re
import sys
import json
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime

# Windows 控制台默认 GBK 编码，无法输出 emoji / 部分中文，统一切到 UTF-8。
# Python 3.7+ 的标准流支持 reconfigure；失败则静默跳过（不影响核心功能）。
for _stream in (sys.stdout, sys.stdin, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# ------------------------------------------------------------------------------
# 可选依赖 prettytable：有则用，无则降级到内置对齐输出
# ------------------------------------------------------------------------------
try:
    from prettytable import PrettyTable  # type: ignore

    _HAS_PRETTYTABLE = True
except ImportError:  # 未安装时优雅降级，不影响功能
    _HAS_PRETTYTABLE = False


DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crm.db")

# 帮助文本（CLI 与 Web 共用）
HELP_TEXT = """可用命令示例（支持同义词，自然语言即可）：

【客户】
  添加客户 张三 北京XX科技 13800000000 zhang@x.com 北京朝阳区
  显示所有客户
  查找客户 张三            （也可按电话：查找客户 13800000000）
  修改客户3的电话为13911112222
  删除客户 3               （需二次确认）

【联系人】
  添加联系人 李四 客户ID=1 职位销售经理 电话13800000000 邮箱li@x.com
  显示所有联系人
  客户1的联系人
  修改联系人2的邮箱为new@x.com
  删除联系人 2

【销售机会】
  创建机会 年度采购项目 客户ID=1 金额50000
  将机会3推进到谈判        （阶段：初步接触/需求分析/方案报价/谈判/赢单/输单）
  修改机会5金额为80000
  修改机会3的关闭日期为2026-07-01
  显示所有机会            （按阶段分组）
  关闭机会2 赢单 价格合适

【任务/跟进】
  添加任务 客户1 回访客户确认需求 截止2026-06-10
  添加任务 机会3 准备投标方案 2026-06-01
  显示未完成任务
  完成任务8
  机会3的任务

【其他】
  显示概览 / 帮助(help) / 退出(exit)"""

# 机会阶段：内部存储值 -> 中文展示名
STAGE_LABELS = {
    "initial_contact": "初步接触",
    "needs_analysis": "需求分析",
    "proposal": "方案报价",
    "negotiation": "谈判",
    "won": "赢单",
    "lost": "输单",
}
# 中文 -> 内部值（用于解析用户输入的阶段名）
STAGE_FROM_LABEL = {v: k for k, v in STAGE_LABELS.items()}
# 阶段同义词，便于自然语言匹配
STAGE_ALIASES = {
    "初步接触": "initial_contact",
    "接触": "initial_contact",
    "需求分析": "needs_analysis",
    "需求": "needs_analysis",
    "方案报价": "proposal",
    "报价": "proposal",
    "方案": "proposal",
    "谈判": "negotiation",
    "赢单": "won",
    "成交": "won",
    "输单": "lost",
    "丢单": "lost",
    "失败": "lost",
}


# ==============================================================================
# AI_Sentinel 安全网关接入（内置守卫）
# ==============================================================================
# 每条命令先经网关检测，再进业务逻辑；网关因此能记录到每次输入。
# 全部可用环境变量控制，不配也能跑（网关不可达时 fail-open 放行 + 告警）。
SENTINEL_ENABLED = os.getenv("SENTINEL_ENABLED", "1") not in ("0", "false", "False", "")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:3001").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "crm-agent-01")

# 高危 intent → 实体类型；用中性动作名 remove_record 上报，避开网关英文硬阻断词。
HIGH_RISK_ACTIONS = {
    "delete_customer": "customer",
    "delete_contact": "contact",
    "delete_opportunity": "opportunity",
    "delete_task": "task",
}

# 输入守卫的「真正拦截类别」：只有这些检测器命中才拒绝。
# 网关的 sensitive/pii_leak 会把电话、邮箱当敏感信息，而 CRM 录入这些是合法操作，
# 故默认只拦「提示词注入/越狱」类；PII/敏感类在输入方向放行（留痕提示）。
# 可用 SENTINEL_BLOCK_DETECTORS="injection,prompt_injection,sensitive,pii_leak" 收紧。
BLOCK_DETECTORS = set(
    d.strip() for d in
    os.getenv("SENTINEL_BLOCK_DETECTORS", "injection,prompt_injection").split(",")
    if d.strip()
)

# ------------------------------------------------------------------------------
# Skill 扩展：工作人员上传「声明式 skill」优化 agent
# ------------------------------------------------------------------------------
# skill = 一个 manifest JSON，声明新的自然语言触发词 -> 知识问答 / 映射到现有安全动作。
# 不执行上传的任何代码；上传时强制经 AI_Sentinel /scan 扫描，benign 才装载。
SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
# 允许 skill 映射到的动作白名单：只放无参的只读/展示类，杜绝映射到增删改高危动作。
SKILL_SAFE_ACTIONS = {
    "list_customers", "list_contacts", "list_opportunities",
    "list_tasks", "dashboard", "help",
}


class SentinelClient:
    """AI_Sentinel 网关客户端：纯标准库 urllib，超时 5s，网关不可达时 fail-open。"""

    def __init__(self, base_url=GATEWAY_URL, agent_id=AGENT_ID, timeout=5.0):
        """记录网关地址、Agent 标识与超时。"""
        self.base_url = base_url
        self.agent_id = agent_id
        self.timeout = timeout

    def _post(self, path, payload):
        """POST JSON，返回 (status_code, dict)；网络异常返回 (None, {error})。"""
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # 403 等带响应体的错误，读出 body 供判定
            try:
                return e.code, json.loads(e.read().decode("utf-8"))
            except Exception:
                return e.code, {}
        except Exception as e:
            return None, {"error": str(e)}

    def check_input(self, prompt):
        """
        输入守卫（/chat）。
        返回 (ok, info)：ok=True 放行；ok=False 表示网关 403 命中（info 含命中详情）。
        网关不可达 → fail-open，ok=True 且 info={"warn": ...}。
        """
        status, body = self._post("/chat", {"prompt": prompt, "session_id": self.agent_id})
        if status == 200:
            return True, {}
        if status == 403:
            return False, body.get("detail", {})
        # 不可达或异常 → fail-open
        return True, {"warn": f"安全网关不可达，已放行（fail-open）：{body.get('error', status)}"}

    def confirm_action(self, action_name, action_params, user_input=""):
        """
        动作守卫（/confirm-action）。返回 (allowed, reason)。
        网关不可达 → fail-open，allowed=True。
        """
        status, body = self._post("/confirm-action", {
            "action_name": action_name,
            "action_params": action_params or {},
            "agent_id": self.agent_id,
            "user_input": user_input,
        })
        if status == 200:
            return body.get("allowed", False), body.get("reason", "")
        return True, f"安全网关不可达，已放行（fail-open）：{body.get('error', status)}"

    def scan(self, skill_name, skill_content):
        """
        Skill 安全扫描（/scan）。返回 (verdict, info)。
        verdict ∈ benign / suspicious / malicious / unverified。
        与输入守卫不同，skill 上传走 **fail-closed**：网关不可达 → unverified（不装载）。
        """
        status, body = self._post("/scan", {
            "skill_name": skill_name, "skill_content": skill_content,
        })
        if status != 200:
            return "unverified", {"reason": f"安全网关不可达（{body.get('error', status)}）"}
        risk = int(body.get("risk_score", 0))
        evidence = ""
        findings = body.get("findings") or []
        if findings:
            top = findings[0]
            evidence = top.get("description") or top.get("rule_hit") or ""
            if top.get("matched_content"):
                evidence += f"（{top['matched_content']}）"
        if not body.get("is_malicious"):
            return "benign", {"risk_score": risk, "evidence": ""}
        verdict = "malicious" if risk >= 80 else "suspicious"
        return verdict, {"risk_score": risk, "evidence": evidence}


# ==============================================================================
# Skill 管理：上传 -> 安全扫描 -> benign 装载 / 恶意可疑隔离
# ==============================================================================
class SkillManager:
    """
    声明式 skill 的装载与管理。

    一个 skill 是一份 manifest JSON：
        {"name": "退款助手", "version": "1.0", "description": "...",
         "rules": [
            {"triggers": ["退款", "怎么退款"], "respond": "退款流程：……"},
            {"triggers": ["大客户", "vip"], "action": "list_customers"}
         ]}

    triggers 命中后，要么回一段知识文本（respond），要么映射到现有安全动作（action，
    仅限 SKILL_SAFE_ACTIONS 白名单）。上传时先过网关 /scan，benign 才落盘装载。
    """

    def __init__(self, sentinel, skills_dir=SKILLS_DIR):
        """准备目录，加载已装载的 skill。"""
        self.sentinel = sentinel
        self.dir = skills_dir
        self.quarantine = os.path.join(skills_dir, "_quarantine")
        os.makedirs(self.dir, exist_ok=True)
        os.makedirs(self.quarantine, exist_ok=True)
        self.rules = []   # 扁平化后的触发规则
        self.loaded = []  # 已装载 skill 概要
        self.reload()

    def reload(self):
        """重新扫描 skills 目录，重建触发规则表。"""
        self.rules = []
        self.loaded = []
        for fn in sorted(os.listdir(self.dir)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, fn), encoding="utf-8") as f:
                    self._register(json.load(f), fn)
            except Exception:
                continue

    def _register(self, data, fn):
        """把一份 manifest 拆成触发规则，登记进表。返回登记的规则数。"""
        name = data.get("name") or fn[:-5]
        n = 0
        for r in (data.get("rules") or []):
            triggers = [str(x).lower() for x in (r.get("triggers") or []) if str(x).strip()]
            if not triggers:
                continue
            respond = r.get("respond")
            action = r.get("action")
            if action and action not in SKILL_SAFE_ACTIONS:
                action = None  # 不允许映射到高危/带参动作
            if not respond and not action:
                continue
            self.rules.append({"skill": name, "triggers": triggers,
                               "respond": respond, "action": action})
            n += 1
        self.loaded.append({"name": name, "file": fn, "rules": n,
                            "desc": data.get("description", "")})
        return n

    @staticmethod
    def _validate(content):
        """校验 manifest 结构，返回 (data, err)。"""
        try:
            data = json.loads(content)
        except Exception as e:
            return None, f"不是合法 JSON：{e}"
        if not isinstance(data, dict):
            return None, "manifest 顶层应为对象"
        if not str(data.get("name", "")).strip():
            return None, "缺少 name 字段"
        rules = data.get("rules")
        if not isinstance(rules, list) or not rules:
            return None, "缺少非空的 rules 列表"
        return data, None

    def submit(self, name, content):
        """
        上传一个 skill。流程：扫描 -> 判定 -> benign 落盘装载 / 其余隔离。
        返回 {ok, verdict, risk_score, evidence, message}。
        """
        safe = re.sub(r"[^\w\-]", "_", (name or "skill")).strip("_")[:40] or "skill"

        # ① 安全闸门（fail-closed：网关不可达不装载）
        if self.sentinel:
            verdict, info = self.sentinel.scan(safe, content)
        else:
            verdict, info = "unverified", {"reason": "安全网关未启用（SENTINEL_ENABLED=0）"}
        risk = info.get("risk_score", 0)
        evidence = info.get("evidence", "") or info.get("reason", "")

        if verdict != "benign":
            self._quarantine(safe, content, verdict, evidence)
            tip = {"unverified": "安全网关不可达，已挂起待复核",
                   "suspicious": "扫描判定可疑，已隔离",
                   "malicious": "扫描判定恶意，已拦截隔离"}.get(verdict, "未通过")
            return {"ok": False, "verdict": verdict, "risk_score": risk,
                    "evidence": evidence, "message": f"{tip}，未装载。"}

        # ② benign：结构校验后落盘装载
        data, err = self._validate(content)
        if err:
            return {"ok": False, "verdict": "benign", "risk_score": risk,
                    "evidence": "", "message": f"扫描通过但 manifest 无效：{err}"}
        fn = safe + ".json"
        with open(os.path.join(self.dir, fn), "w", encoding="utf-8") as f:
            f.write(content)
        self.reload()
        active = next((s["rules"] for s in self.loaded if s["file"] == fn), 0)
        return {"ok": True, "verdict": "benign", "risk_score": risk, "evidence": "",
                "message": f"扫描通过，已装载 skill「{data.get('name')}」（生效 {active} 条规则）。"}

    def _quarantine(self, name, content, verdict, evidence):
        """把未通过的 skill 连同判定写入隔离区。"""
        try:
            with open(os.path.join(self.quarantine, name + ".json"), "w", encoding="utf-8") as f:
                f.write(content)
            with open(os.path.join(self.quarantine, name + ".meta.json"), "w", encoding="utf-8") as f:
                json.dump({"name": name, "verdict": verdict, "evidence": evidence},
                          f, ensure_ascii=False)
        except Exception:
            pass

    def match(self, text):
        """对未识别输入做触发匹配；命中返回规则，否则 None。"""
        low = (text or "").lower()
        for r in self.rules:
            if any(t in low for t in r["triggers"]):
                return r
        return None

    def listing(self):
        """返回 (已装载, 已隔离) 两个列表。"""
        q = []
        for fn in sorted(os.listdir(self.quarantine)):
            if fn.endswith(".meta.json"):
                try:
                    with open(os.path.join(self.quarantine, fn), encoding="utf-8") as f:
                        q.append(json.load(f))
                except Exception:
                    pass
        return self.loaded, q


# ==============================================================================
# 表格渲染工具：统一处理 prettytable / 降级两种情况
# ==============================================================================
def render_table(headers, rows):
    """
    将表头与数据行渲染为对齐的表格字符串。

    headers: list[str] 列标题
    rows:    list[list] 每行的单元格值（任意类型，内部转为 str）
    返回:    多行字符串；rows 为空时返回提示语。
    """
    if not rows:
        return "（没有匹配的记录）"

    str_rows = [[("" if c is None else str(c)) for c in row] for row in rows]

    if _HAS_PRETTYTABLE:
        table = PrettyTable()
        table.field_names = headers
        table.align = "l"  # 左对齐，中文更易读
        for row in str_rows:
            table.add_row(row)
        return table.get_string()

    # ---- 降级：手工计算列宽并对齐 ----
    widths = [_disp_width(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _disp_width(cell))

    def fmt_row(cells):
        parts = [_pad(cell, widths[i]) for i, cell in enumerate(cells)]
        return "| " + " | ".join(parts) + " |"

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, fmt_row(headers), sep]
    lines += [fmt_row(row) for row in str_rows]
    lines.append(sep)
    return "\n".join(lines)


def _disp_width(text):
    """计算字符串显示宽度：中文/全角字符按 2 计，其余按 1 计。"""
    width = 0
    for ch in text:
        # CJK 统一表意文字、全角符号等占两个终端列宽
        width += 2 if ord(ch) > 0x2E7F else 1
    return width


def _pad(text, width):
    """按显示宽度右侧补空格，使中英文混排也能对齐。"""
    return text + " " * (width - _disp_width(text))


# ==============================================================================
# 数据库管理
# ==============================================================================
class DatabaseManager:
    """封装所有 SQLite 操作；负责建表、增删改查。"""

    def __init__(self, db_path=DB_FILE):
        """连接（或创建）数据库文件，并确保所有表存在。"""
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # 查询结果可按列名访问
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self):
        """创建四张业务表（IF NOT EXISTS，可重复安全调用）。"""
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                company    TEXT,
                phone      TEXT,
                email      TEXT,
                address    TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS contacts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER,
                name        TEXT NOT NULL,
                title       TEXT,
                phone       TEXT,
                email       TEXT
            );
            CREATE TABLE IF NOT EXISTS opportunities (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id   INTEGER,
                name          TEXT NOT NULL,
                amount        REAL DEFAULT 0,
                stage         TEXT DEFAULT 'initial_contact',
                close_date    TEXT,
                closed_reason TEXT,
                created_at    TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                related_type TEXT,
                related_id   INTEGER,
                description  TEXT NOT NULL,
                due_date     TEXT,
                status       TEXT DEFAULT '待办'
            );
            """
        )
        self.conn.commit()

    # ---- 通用执行辅助 ----
    def execute(self, sql, params=()):
        """执行写操作（INSERT/UPDATE/DELETE），返回游标。"""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        self.conn.commit()
        return cur

    def query(self, sql, params=()):
        """执行查询，返回 sqlite3.Row 列表。"""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()

    def query_one(self, sql, params=()):
        """执行查询，返回单行（无结果则 None）。"""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchone()

    def close(self):
        """关闭数据库连接。"""
        self.conn.close()


# ==============================================================================
# 意图解析
# ==============================================================================
class CommandParser:
    """
    将自然语言文本解析为结构化意图。

    解析结果统一为 dict：{"action": <动作名>, ...其余字段}
    无法识别时返回 {"action": "unknown"}。
    采用「关键词定位模块 + 正则抽取字段」的策略，足够覆盖典型句式。
    """

    def parse(self, text):
        """解析一条用户输入，返回意图字典。"""
        t = text.strip()
        low = t.lower()

        # ---- 全局命令 ----
        if low in ("help", "帮助", "?", "？"):
            return {"action": "help"}
        if low in ("exit", "quit", "退出", "再见"):
            return {"action": "exit"}
        if ("概览" in t or "摘要" in t or "仪表" in t
                or "dashboard" in low or "总览" in t):
            return {"action": "dashboard"}
        if low in ("skill", "skills", "技能列表", "skill列表", "显示skill", "显示技能"):
            return {"action": "list_skills"}

        # ---- 按「动作 + 实体」分发 ----
        # 查询/列表类放最前：查询动词（显示/查看/列出…）与增删改前缀互不冲突，
        # 且可避免“显示未完成任务”里的“完成任务”子串被误判为完成任务命令。
        if re.match(r"^(显示|查看|列出|查找|搜索|查|展示|列)", t):
            return self._parse_query(t)
        # 删除类
        if t.startswith("删除") or t.startswith("移除"):
            return self._parse_delete(t)
        # 完成任务
        if "完成任务" in t or re.search(r"任务.*完成", t):
            return self._parse_complete_task(t)
        # 添加 / 新增 / 创建类
        if re.match(r"^(添加|新增|创建|新建|加)", t):
            return self._parse_add(t)
        # 更新 / 修改类
        if re.match(r"^(修改|更新|更改|推进|将|把)", t):
            return self._parse_update(t)
        # 关闭机会
        if "关闭机会" in t or re.search(r"机会.*(赢单|输单|关闭)", t):
            return self._parse_close_opportunity(t)

        # 无动词前缀的查询兜底：如“客户1的联系人”“机会3的任务”“客户2的任务”
        if "的联系人" in t or "的任务" in t:
            return self._parse_query(t)

        return {"action": "unknown"}

    # --------------------------------------------------------------------------
    # 字段抽取辅助
    # --------------------------------------------------------------------------
    @staticmethod
    def _extract_phone(text):
        """抽取手机号（11 位数字，可能带 +86 等，取连续 11 位数字）。"""
        m = re.search(r"\b(1\d{10})\b", text)
        return m.group(1) if m else None

    @staticmethod
    def _extract_email(text):
        """抽取邮箱地址。用 ASCII 字符集，避免 \\w 把前面的中文（如“邮箱”）一起吞掉。"""
        m = re.search(r"[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]+", text)
        return m.group(0) if m else None

    @staticmethod
    def _extract_customer_id(text):
        """抽取客户ID：支持 客户ID=1 / 客户1 / 客户 1 等写法。"""
        m = re.search(r"客户\s*(?:id|ID)?\s*[=＝:：]?\s*(\d+)", text)
        return int(m.group(1)) if m else None

    @staticmethod
    def _extract_amount(text):
        """抽取金额：匹配“金额50000 / 金额=5万 / 5万元 / 50000元”。"""
        # 先找“金额”后面的数值（兼容“金额为/改为/=”等分隔写法）
        m = re.search(r"金额\s*(?:改?为|[=＝:：])?\s*([\d.]+)\s*(万|w|W)?", text)
        if not m:
            # 退而找带“元/万”的数字
            m = re.search(r"([\d.]+)\s*(万|w|W|元)", text)
        if not m:
            return None
        value = float(m.group(1))
        unit = m.group(2) if m.lastindex and m.lastindex >= 2 else None
        if unit in ("万", "w", "W"):
            value *= 10000
        return value

    @staticmethod
    def _extract_date(text):
        """抽取日期 YYYY-MM-DD（也兼容 YYYY/MM/DD）。"""
        m = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
        if not m:
            return None
        y, mo, d = m.group(1), int(m.group(2)), int(m.group(3))
        return f"{y}-{mo:02d}-{d:02d}"

    @staticmethod
    def _match_stage(text):
        """从文本中识别机会阶段，返回内部值或 None。"""
        for label, value in STAGE_ALIASES.items():
            if label in text:
                return value
        return None

    # --------------------------------------------------------------------------
    # 添加类
    # --------------------------------------------------------------------------
    def _parse_add(self, t):
        """
        解析“添加客户/联系人/机会/任务”。
        操作对象 = 紧跟“添加/创建”动词后、出现位置最靠前的实体词。
        （例如“添加任务 机会1…”里“任务”比“机会”靠前，应判定为加任务，
          “机会1”只是它的关联参数。）
        """
        candidates = {
            "联系人": self._parse_add_contact,
            "任务": self._parse_add_task,
            "跟进": self._parse_add_task,
            "机会": self._parse_add_opportunity,
            "客户": self._parse_add_customer,
        }
        best_word, best_pos = None, len(t) + 1
        for word in candidates:
            pos = t.find(word)
            if pos != -1 and pos < best_pos:
                best_word, best_pos = word, pos
        if best_word:
            return candidates[best_word](t)
        return {"action": "unknown"}

    def _parse_add_customer(self, t):
        """
        添加客户。示例：
            添加客户 张三 北京XX科技 13800000000 zhang@x.com 北京朝阳
        策略：先抽出电话/邮箱，剩余 token 里第一个作姓名，第二个作公司，末尾作地址。
        """
        phone = self._extract_phone(t)
        email = self._extract_email(t)

        # 去掉命令词与已识别的电话/邮箱，剩下的按空白切分
        body = re.sub(r"^(添加|新增|创建|新建|加)\s*客户", "", t).strip()
        if phone:
            body = body.replace(phone, " ")
        if email:
            body = body.replace(email, " ")
        tokens = [x for x in re.split(r"\s+", body) if x]

        name = tokens[0] if len(tokens) >= 1 else None
        company = tokens[1] if len(tokens) >= 2 else None
        address = " ".join(tokens[2:]) if len(tokens) >= 3 else None
        return {
            "action": "add_customer",
            "name": name,
            "company": company,
            "phone": phone,
            "email": email,
            "address": address,
        }

    def _parse_add_contact(self, t):
        """
        添加联系人。示例：
            添加联系人 李四 客户ID=1 职位销售经理 电话138xxxx 邮箱li@x.com
        """
        customer_id = self._extract_customer_id(t)
        phone = self._extract_phone(t)
        email = self._extract_email(t)

        title = None
        m = re.search(r"职位\s*[=＝:：]?\s*([^\s]+)", t)
        if m:
            title = m.group(1)

        # 姓名：紧跟“联系人”之后的第一个 token
        body = re.sub(r"^(添加|新增|创建|新建|加)\s*联系人", "", t).strip()
        # 去除已识别字段，避免把它们当姓名
        for chunk in (phone, email):
            if chunk:
                body = body.replace(chunk, " ")
        body = re.sub(r"客户\s*(?:id|ID)?\s*[=＝:：]?\s*\d+", " ", body)
        body = re.sub(r"职位\s*[=＝:：]?\s*[^\s]+", " ", body)
        body = re.sub(r"(电话|邮箱)\s*[=＝:：]?", " ", body)
        tokens = [x for x in re.split(r"\s+", body) if x]
        name = tokens[0] if tokens else None

        return {
            "action": "add_contact",
            "name": name,
            "customer_id": customer_id,
            "title": title,
            "phone": phone,
            "email": email,
        }

    def _parse_add_opportunity(self, t):
        """
        创建机会。示例：
            创建机会 年度采购 客户ID=1 金额50000
        """
        customer_id = self._extract_customer_id(t)
        amount = self._extract_amount(t)
        close_date = self._extract_date(t)

        body = re.sub(r"^(添加|新增|创建|新建|加)\s*机会", "", t).strip()
        body = re.sub(r"客户\s*(?:id|ID)?\s*[=＝:：]?\s*\d+", " ", body)
        body = re.sub(r"金额\s*[=＝:：]?\s*[\d.]+\s*(万|w|W|元)?", " ", body)
        body = re.sub(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", " ", body)
        tokens = [x for x in re.split(r"\s+", body) if x]
        name = tokens[0] if tokens else None

        return {
            "action": "add_opportunity",
            "name": name,
            "customer_id": customer_id,
            "amount": amount,
            "close_date": close_date,
        }

    def _parse_add_task(self, t):
        """
        添加任务。示例：
            添加任务 客户1 回访客户 截止2026-06-10
            添加任务 机会3 准备方案 2026-06-01
        关联对象：出现“机会”关联机会，否则默认关联客户。
        """
        due_date = self._extract_date(t)
        if "机会" in t:
            related_type = "opportunity"
            m = re.search(r"机会\s*(?:id|ID)?\s*[=＝:：]?\s*(\d+)", t)
        else:
            related_type = "customer"
            m = re.search(r"客户\s*(?:id|ID)?\s*[=＝:：]?\s*(\d+)", t)
        related_id = int(m.group(1)) if m else None

        body = re.sub(r"^(添加|新增|创建|新建|加)\s*(任务|跟进)", "", t).strip()
        body = re.sub(r"(客户|机会)\s*(?:id|ID)?\s*[=＝:：]?\s*\d+", " ", body)
        body = re.sub(r"截止\s*[=＝:：]?", " ", body)
        body = re.sub(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", " ", body)
        description = " ".join(x for x in re.split(r"\s+", body) if x).strip()

        return {
            "action": "add_task",
            "related_type": related_type,
            "related_id": related_id,
            "description": description or None,
            "due_date": due_date,
        }

    # --------------------------------------------------------------------------
    # 查询类
    # --------------------------------------------------------------------------
    def _parse_query(self, t):
        """解析各类查询/列表命令。"""
        # 按客户筛选联系人：客户1的联系人 / 客户ID=1 联系人
        if "联系人" in t:
            cid = self._extract_customer_id(t)
            if cid is not None:
                return {"action": "list_contacts", "customer_id": cid}
            return {"action": "list_contacts", "customer_id": None}

        # 机会列表
        if "机会" in t:
            return {"action": "list_opportunities"}

        # 任务：未完成 / 全部 / 按对象
        if "任务" in t:
            if "未完成" in t or "待办" in t or "进行中" in t:
                status = "待办"
            else:
                status = None
            cid = None
            oid = None
            mo = re.search(r"机会\s*(?:id|ID)?\s*[=＝:：]?\s*(\d+)", t)
            mc = re.search(r"客户\s*(?:id|ID)?\s*[=＝:：]?\s*(\d+)", t)
            if mo:
                oid = int(mo.group(1))
            elif mc:
                cid = int(mc.group(1))
            return {
                "action": "list_tasks",
                "status": status,
                "customer_id": cid,
                "opportunity_id": oid,
            }

        # 客户：查找/搜索 客户 关键词
        if "客户" in t:
            m = re.search(r"(?:查找|搜索|查)\s*客户\s*(.+)$", t)
            if m and m.group(1).strip():
                return {"action": "search_customer", "keyword": m.group(1).strip()}
            return {"action": "list_customers"}

        return {"action": "unknown"}

    # --------------------------------------------------------------------------
    # 更新类
    # --------------------------------------------------------------------------
    def _parse_update(self, t):
        """解析更新命令：客户字段 / 机会阶段 / 机会金额、日期。"""
        # 机会阶段推进：将机会3推进到谈判 / 更新机会5的阶段为赢单
        if "机会" in t and ("阶段" in t or "推进" in t or self._match_stage(t)):
            m = re.search(r"机会\s*(?:#|id|ID)?\s*(\d+)", t)
            stage = self._match_stage(t)
            if m and stage:
                return {
                    "action": "update_opp_stage",
                    "id": int(m.group(1)),
                    "stage": stage,
                }

        # 机会金额修改：修改机会5金额为80000
        if "机会" in t and ("金额" in t or "元" in t or "万" in t):
            m = re.search(r"机会\s*(?:#|id|ID)?\s*(\d+)", t)
            amount = self._extract_amount(t)
            if m and amount is not None:
                return {
                    "action": "update_opp_amount",
                    "id": int(m.group(1)),
                    "amount": amount,
                }

        # 机会预计关闭日期：修改机会3的关闭日期为2026-07-01
        if "机会" in t and "日期" in t:
            m = re.search(r"机会\s*(?:#|id|ID)?\s*(\d+)", t)
            date = self._extract_date(t)
            if m and date:
                return {
                    "action": "update_opp_date",
                    "id": int(m.group(1)),
                    "close_date": date,
                }

        # 客户字段更新：修改客户3的电话为139xxxx / 更新客户2的邮箱为a@b.com
        if "客户" in t:
            m = re.search(r"客户\s*(?:#|id|ID)?\s*(\d+)", t)
            if m:
                cid = int(m.group(1))
                field, value = self._parse_field_value(t)
                if field:
                    return {
                        "action": "update_customer",
                        "id": cid,
                        "field": field,
                        "value": value,
                    }

        # 联系人字段更新：修改联系人2的电话为139xxxx
        if "联系人" in t:
            m = re.search(r"联系人\s*(?:#|id|ID)?\s*(\d+)", t)
            if m:
                field, value = self._parse_field_value(t)
                if field:
                    return {
                        "action": "update_contact",
                        "id": int(m.group(1)),
                        "field": field,
                        "value": value,
                    }

        return {"action": "unknown"}

    def _parse_field_value(self, t):
        """
        从“…的<字段>为<值>”中抽取字段名与值。
        返回 (db_field, value)；无法识别返回 (None, None)。
        """
        field_map = {
            "电话": "phone",
            "手机": "phone",
            "邮箱": "email",
            "邮件": "email",
            "名称": "name",
            "姓名": "name",
            "名字": "name",
            "公司": "company",
            "地址": "address",
            "职位": "title",
        }
        m = re.search(r"的?\s*(电话|手机|邮箱|邮件|名称|姓名|名字|公司|地址|职位)\s*"
                      r"(?:改?为|=|＝|:|：)\s*(.+)$", t)
        if not m:
            return None, None
        field = field_map[m.group(1)]
        value = m.group(2).strip()
        return field, value

    # --------------------------------------------------------------------------
    # 删除类
    # --------------------------------------------------------------------------
    def _parse_delete(self, t):
        """解析删除命令：客户 / 联系人 / 机会 / 任务。"""
        if "客户" in t:
            m = re.search(r"客户\s*(?:#|id|ID)?\s*(\d+)", t)
            if m:
                return {"action": "delete_customer", "id": int(m.group(1))}
        if "联系人" in t:
            m = re.search(r"联系人\s*(?:#|id|ID)?\s*(\d+)", t)
            if m:
                return {"action": "delete_contact", "id": int(m.group(1))}
        if "机会" in t:
            m = re.search(r"机会\s*(?:#|id|ID)?\s*(\d+)", t)
            if m:
                return {"action": "delete_opportunity", "id": int(m.group(1))}
        if "任务" in t:
            m = re.search(r"任务\s*(?:#|id|ID)?\s*(\d+)", t)
            if m:
                return {"action": "delete_task", "id": int(m.group(1))}
        return {"action": "unknown"}

    # --------------------------------------------------------------------------
    # 完成任务 / 关闭机会
    # --------------------------------------------------------------------------
    def _parse_complete_task(self, t):
        """解析“完成任务ID 8 / 完成任务8”。"""
        m = re.search(r"任务\s*(?:#|id|ID)?\s*(\d+)", t)
        if m:
            return {"action": "complete_task", "id": int(m.group(1))}
        return {"action": "unknown"}

    def _parse_close_opportunity(self, t):
        """
        解析关闭机会：关闭机会2 赢单 价格合适 / 机会3输单 预算不足
        result: won / lost；reason 为剩余描述。
        """
        m = re.search(r"机会\s*(?:#|id|ID)?\s*(\d+)", t)
        if not m:
            return {"action": "unknown"}
        oid = int(m.group(1))
        if "赢单" in t or "成交" in t:
            result = "won"
        elif "输单" in t or "丢单" in t or "失败" in t:
            result = "lost"
        else:
            result = None  # 由业务层追问

        # 关闭原因：去掉命令词与关键字后剩余文本
        reason = re.sub(r"(关闭|机会|赢单|成交|输单|丢单|失败)", " ", t)
        reason = re.sub(r"(?:#|id|ID)?\s*\d+", " ", reason)
        reason = " ".join(x for x in re.split(r"\s+", reason) if x).strip()
        return {
            "action": "close_opportunity",
            "id": oid,
            "result": result,
            "reason": reason or None,
        }


# ==============================================================================
# 主 Agent：分发命令、执行业务逻辑、产出结构化结果
# ==============================================================================
#
# 业务方法不再直接 print，而是返回「结果块」列表，块的形式：
#   {"kind": "text",  "text": "...", "tone": "ok|err|info|warn"}
#   {"kind": "table", "title": "...", "headers": [...], "rows": [[...]]}
#   {"kind": "stats", "title": "...", "items": [{"label":..,"value":..}, ...]}
# 这样 CLI（_render_cli 打印）与 Web（转 JSON 给前端）可以共用同一套逻辑。
# ==============================================================================
class CRMAgent:
    """CRM 智能体：解析意图 -> 执行 -> 返回结构化结果块。"""

    def __init__(self, interactive=True):
        """
        初始化数据库与解析器。
        interactive=True ：CLI 模式，缺字段时通过 input() 追问、删除二次确认。
        interactive=False：Web 模式，缺字段直接返回提示块；删除由前端弹窗确认后放行。
        """
        self.interactive = interactive
        self.db = DatabaseManager()
        self.parser = CommandParser()
        # 安全网关客户端（可用 SENTINEL_ENABLED=0 关闭）
        self.sentinel = SentinelClient() if SENTINEL_ENABLED else None
        # 工作人员上传的声明式 skill（上传时过网关扫描，benign 才装载）
        self.skills = SkillManager(self.sentinel)
        # 动作 -> 处理方法 的分发表
        self.handlers = {
            "help": self.show_help,
            "dashboard": self.show_dashboard,
            "add_customer": self.add_customer,
            "list_customers": self.list_customers,
            "search_customer": self.search_customer,
            "update_customer": self.update_customer,
            "delete_customer": self.delete_customer,
            "add_contact": self.add_contact,
            "list_contacts": self.list_contacts,
            "update_contact": self.update_contact,
            "delete_contact": self.delete_contact,
            "add_opportunity": self.add_opportunity,
            "list_opportunities": self.list_opportunities,
            "update_opp_stage": self.update_opp_stage,
            "update_opp_amount": self.update_opp_amount,
            "update_opp_date": self.update_opp_date,
            "close_opportunity": self.close_opportunity,
            "delete_opportunity": self.delete_opportunity,
            "add_task": self.add_task,
            "list_tasks": self.list_tasks,
            "complete_task": self.complete_task,
            "delete_task": self.delete_task,
            "list_skills": self.list_skills,
        }

    # --------------------------------------------------------------------------
    # CLI 主循环
    # --------------------------------------------------------------------------
    def run(self):
        """启动命令行交互循环，直到用户输入 exit/quit。"""
        print("=" * 60)
        print(" 🤝  CRM-Agent 已启动 —— 用自然语言管理你的客户与商机")
        print("     输入 help 查看命令示例，输入 exit 退出")
        if self.sentinel:
            print(f" 🛡️  已接入 AI_Sentinel 安全网关：{GATEWAY_URL}")
        else:
            print(" 🛡️  安全网关已关闭（SENTINEL_ENABLED=0）")
        print("=" * 60)
        while True:
            try:
                raw = input("\nCRM-Agent > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n再见！")
                break
            if not raw:
                continue
            if self.parser.parse(raw).get("action") == "exit":
                print("再见！数据已保存。")
                break
            self._render_cli(self.process(raw))
        self.db.close()

    def process(self, raw):
        """解析并执行一条命令，返回结果块列表（CLI 与 Web 共用此入口）。"""
        prefix = []  # 守卫产生的提示块，拼在业务结果前面

        # ── 第 1 层：输入守卫（每条命令都会请求网关，网关因此能记录日志）──
        if self.sentinel:
            ok, info = self.sentinel.check_input(raw)
            if not ok:
                detector = info.get("detector") or ""
                rule = info.get("rule_hit") or detector or "unknown"
                desc = (info.get("details") or {}).get("rule_description") \
                    or info.get("reason") or ""
                if detector in BLOCK_DETECTORS:
                    return [self._err(f"⛔ 输入被安全网关拦截：{rule}"
                                      + (f" — {desc}" if desc else ""))]
                # PII/敏感类：CRM 录入合法字段，放行但留痕
                prefix.append(self._info(
                    f"🔐 网关提示：输入含敏感字段（{rule}），按 CRM 策略放行。"))
            elif info.get("warn"):
                prefix.append(self._text("⚠️ " + info["warn"], "warn"))

        intent = self.parser.parse(raw)
        action = intent.get("action")
        if action == "exit":
            return prefix + [self._info("Web 模式下直接关闭页面即可，无需退出命令。")]
        if action == "unknown":
            # 兜底：交给已装载的 skill 触发匹配
            hit = self.skills.match(raw) if self.skills else None
            if hit and hit.get("action") in self.handlers:
                action = hit["action"]
                intent = {"action": action}
            elif hit and hit.get("respond"):
                return prefix + [self._info(f"💡 {hit['respond']}")]
            else:
                return prefix + [self._err("🤔 没理解这条指令。点上方示例或输入 help 查看用法。")]
        handler = self.handlers.get(action)
        if not handler:
            return prefix + [self._err("该功能暂未实现。")]

        # ── 第 2 层：动作守卫（仅删除类高危操作，会发 /confirm-action 上报）──
        if self.sentinel and action in HIGH_RISK_ACTIONS:
            params = {"entity": HIGH_RISK_ACTIONS[action], "id": intent.get("id")}
            allowed, reason = self.sentinel.confirm_action("remove_record", params, raw)
            if not allowed:
                return prefix + [self._err(f"⛔ 操作被安全网关阻断：{reason}")]

        try:
            result = handler(intent)
            result = result if isinstance(result, list) else [result]
            return prefix + result
        except Exception as e:  # 异常优雅降级，不让程序崩溃
            return prefix + [self._err(f"⚠️ 操作出错：{e}")]

    @staticmethod
    def _render_cli(blocks):
        """把结果块渲染到命令行。"""
        for b in blocks:
            kind = b.get("kind")
            if kind == "text":
                print(b["text"])
            elif kind == "table":
                if b.get("title"):
                    print("\n" + b["title"])
                print(render_table(b["headers"], b["rows"]))
            elif kind == "stats":
                if b.get("title"):
                    print("\n" + b["title"])
                print(render_table(
                    ["指标", "数值"],
                    [[i["label"], i["value"]] for i in b["items"]],
                ))

    # --------------------------------------------------------------------------
    # 结果块构造 & 交互辅助
    # --------------------------------------------------------------------------
    @staticmethod
    def _text(s, tone="info"):
        """构造一个文本块。tone 控制前端配色：ok/err/info/warn。"""
        return {"kind": "text", "text": s, "tone": tone}

    def _ok(self, s):
        """成功提示块。"""
        return self._text(s, "ok")

    def _err(self, s):
        """错误提示块。"""
        return self._text(s, "err")

    def _info(self, s):
        """普通信息块。"""
        return self._text(s, "info")

    @staticmethod
    def _table(title, headers, rows):
        """构造一个表格块。"""
        return {"kind": "table", "title": title, "headers": headers, "rows": rows}

    def _ask(self, prompt):
        """
        追问一个字段。CLI 模式走 input()；Web 模式返回空串
        （Web 端要求一次性把信息写在命令里，缺失时由调用方给出补充提示）。
        """
        if not self.interactive:
            return ""
        try:
            return input(f"   ↳ {prompt}").strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    def _confirm(self, prompt):
        """
        二次确认。CLI 模式走 input()；Web 模式默认放行
        （前端已用弹窗确认过删除操作）。
        """
        if not self.interactive:
            return True
        try:
            ans = input(f"   ⚠️  {prompt}（y/n）").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes", "是", "确认")

    def _get_customer(self, cid):
        """按 ID 取客户行，不存在返回 None。"""
        return self.db.query_one("SELECT * FROM customers WHERE id=?", (cid,))

    # ==========================================================================
    # 帮助 & 仪表板
    # ==========================================================================
    def list_skills(self, _intent):
        """展示已装载与被隔离的 skill。"""
        installed, quarantined = self.skills.listing()
        blocks = []
        if installed:
            blocks.append(self._table(
                "📦 已装载 Skill", ["名称", "规则数", "说明"],
                [[s["name"], s["rules"], s.get("desc", "")] for s in installed]))
        else:
            blocks.append(self._info("还没有已装载的 skill。工作人员可在 Web 端「Skill 管理」上传。"))
        if quarantined:
            blocks.append(self._table(
                "🚫 已隔离 Skill（未通过安全扫描）", ["名称", "判定", "证据"],
                [[s.get("name", ""), s.get("verdict", ""), s.get("evidence", "")] for s in quarantined]))
        return blocks

    def show_help(self, _intent):
        """返回所有可用命令示例。"""
        return [self._text(HELP_TEXT)]

    def show_dashboard(self, _intent):
        """返回业务概览统计（stats 块）。"""
        cust = self.db.query_one("SELECT COUNT(*) c FROM customers")["c"]
        open_opp = self.db.query_one(
            "SELECT COUNT(*) c FROM opportunities WHERE stage NOT IN ('won','lost')"
        )["c"]
        total_amt = self.db.query_one(
            "SELECT COALESCE(SUM(amount),0) s FROM opportunities "
            "WHERE stage NOT IN ('won','lost')"
        )["s"]
        won_amt = self.db.query_one(
            "SELECT COALESCE(SUM(amount),0) s FROM opportunities WHERE stage='won'"
        )["s"]
        todo = self.db.query_one(
            "SELECT COUNT(*) c FROM tasks WHERE status='待办'"
        )["c"]
        return [{
            "kind": "stats",
            "title": "📊 业务概览",
            "items": [
                {"label": "客户总数", "value": cust},
                {"label": "进行中机会", "value": open_opp},
                {"label": "进行中金额", "value": f"{total_amt:,.0f}"},
                {"label": "已赢单金额", "value": f"{won_amt:,.0f}"},
                {"label": "未完成任务", "value": todo},
            ],
        }]

    # ==========================================================================
    # 客户管理
    # ==========================================================================
    def add_customer(self, intent):
        """添加客户；姓名为必填（缺失则追问/提示），电话建议填写。"""
        name = intent.get("name")
        phone = intent.get("phone")
        company = intent.get("company")
        email = intent.get("email")
        address = intent.get("address")

        if not name:
            name = self._ask("请输入客户名称：") or None
            if not name:
                return [self._err("❌ 缺少客户名称，已取消。示例：添加客户 张三 公司名 138...")]
        if not phone:
            phone = self._ask("请输入客户电话（可回车跳过）：") or None

        self.db.execute(
            "INSERT INTO customers (name, company, phone, email, address, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (name, company, phone, email, address,
             datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        cid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        return [self._ok(f"✅ 已添加客户 #{cid}：{name}"
                         + (f"（{company}）" if company else ""))]

    def list_customers(self, _intent):
        """列出所有客户。"""
        rows = self.db.query(
            "SELECT id, name, company, phone, email, address FROM customers ORDER BY id"
        )
        return [self._table(
            "👥 客户列表",
            ["ID", "名称", "公司", "电话", "邮箱", "地址"],
            [[r["id"], r["name"], r["company"], r["phone"], r["email"], r["address"]]
             for r in rows],
        )]

    def search_customer(self, intent):
        """按名称或电话模糊搜索客户。"""
        kw = intent["keyword"]
        rows = self.db.query(
            "SELECT id, name, company, phone, email, address FROM customers "
            "WHERE name LIKE ? OR phone LIKE ? ORDER BY id",
            (f"%{kw}%", f"%{kw}%"),
        )
        return [self._table(
            f"🔍 搜索“{kw}”的结果",
            ["ID", "名称", "公司", "电话", "邮箱", "地址"],
            [[r["id"], r["name"], r["company"], r["phone"], r["email"], r["address"]]
             for r in rows],
        )]

    def update_customer(self, intent):
        """更新客户的某个字段。"""
        cid, field, value = intent["id"], intent["field"], intent["value"]
        if not self._get_customer(cid):
            return [self._err(f"❌ 客户 #{cid} 不存在。")]
        self.db.execute(
            f"UPDATE customers SET {field}=? WHERE id=?", (value, cid)
        )
        return [self._ok(f"✅ 已更新客户 #{cid} 的 {field} 为「{value}」。")]

    def delete_customer(self, intent):
        """删除客户（二次确认；同时清理其联系人）。"""
        cid = intent["id"]
        cust = self._get_customer(cid)
        if not cust:
            return [self._err(f"❌ 客户 #{cid} 不存在。")]
        if not self._confirm(f"确认删除客户 #{cid}「{cust['name']}」？此操作不可撤销"):
            return [self._info("已取消删除。")]
        self.db.execute("DELETE FROM customers WHERE id=?", (cid,))
        self.db.execute("DELETE FROM contacts WHERE customer_id=?", (cid,))
        return [self._ok(f"🗑️ 已删除客户 #{cid}「{cust['name']}」及其联系人。")]

    # ==========================================================================
    # 联系人管理
    # ==========================================================================
    def add_contact(self, intent):
        """添加联系人；姓名与所属客户为必填。"""
        name = intent.get("name")
        customer_id = intent.get("customer_id")
        title = intent.get("title")
        phone = intent.get("phone")
        email = intent.get("email")

        if not name:
            name = self._ask("请输入联系人姓名：") or None
            if not name:
                return [self._err("❌ 缺少联系人姓名，已取消。")]
        if customer_id is None:
            ans = self._ask("请输入所属客户ID：")
            customer_id = int(ans) if ans.isdigit() else None
        if customer_id is None or not self._get_customer(customer_id):
            return [self._err(f"❌ 客户 #{customer_id} 不存在，无法添加联系人。")]

        self.db.execute(
            "INSERT INTO contacts (customer_id, name, title, phone, email)"
            " VALUES (?,?,?,?,?)",
            (customer_id, name, title, phone, email),
        )
        cid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        return [self._ok(f"✅ 已添加联系人 #{cid}：{name}"
                         + (f"（{title}）" if title else "")
                         + f"，所属客户 #{customer_id}")]

    def list_contacts(self, intent):
        """列出联系人，展示所属客户名；可按客户筛选。"""
        customer_id = intent.get("customer_id")
        if customer_id is not None:
            rows = self.db.query(
                "SELECT ct.id, ct.name, ct.title, ct.phone, ct.email, "
                "c.name AS cust FROM contacts ct "
                "LEFT JOIN customers c ON ct.customer_id=c.id "
                "WHERE ct.customer_id=? ORDER BY ct.id",
                (customer_id,),
            )
            title = f"📇 客户 #{customer_id} 的联系人"
        else:
            rows = self.db.query(
                "SELECT ct.id, ct.name, ct.title, ct.phone, ct.email, "
                "c.name AS cust FROM contacts ct "
                "LEFT JOIN customers c ON ct.customer_id=c.id ORDER BY ct.id"
            )
            title = "📇 联系人列表"
        return [self._table(
            title,
            ["ID", "姓名", "职位", "电话", "邮箱", "所属客户"],
            [[r["id"], r["name"], r["title"], r["phone"], r["email"], r["cust"]]
             for r in rows],
        )]

    def update_contact(self, intent):
        """更新联系人字段。"""
        cid, field, value = intent["id"], intent["field"], intent["value"]
        if not self.db.query_one("SELECT id FROM contacts WHERE id=?", (cid,)):
            return [self._err(f"❌ 联系人 #{cid} 不存在。")]
        self.db.execute(f"UPDATE contacts SET {field}=? WHERE id=?", (value, cid))
        return [self._ok(f"✅ 已更新联系人 #{cid} 的 {field} 为「{value}」。")]

    def delete_contact(self, intent):
        """删除联系人（二次确认）。"""
        cid = intent["id"]
        row = self.db.query_one("SELECT name FROM contacts WHERE id=?", (cid,))
        if not row:
            return [self._err(f"❌ 联系人 #{cid} 不存在。")]
        if not self._confirm(f"确认删除联系人 #{cid}「{row['name']}」？"):
            return [self._info("已取消删除。")]
        self.db.execute("DELETE FROM contacts WHERE id=?", (cid,))
        return [self._ok(f"🗑️ 已删除联系人 #{cid}「{row['name']}」。")]

    # ==========================================================================
    # 销售机会管理
    # ==========================================================================
    def add_opportunity(self, intent):
        """创建机会；名称与所属客户为必填，初始阶段为初步接触。"""
        name = intent.get("name")
        customer_id = intent.get("customer_id")
        amount = intent.get("amount") or 0
        close_date = intent.get("close_date")

        if not name:
            name = self._ask("请输入机会名称：") or None
            if not name:
                return [self._err("❌ 缺少机会名称，已取消。")]
        if customer_id is None:
            ans = self._ask("请输入关联客户ID：")
            customer_id = int(ans) if ans.isdigit() else None
        if customer_id is None or not self._get_customer(customer_id):
            return [self._err(f"❌ 客户 #{customer_id} 不存在，无法创建机会。")]

        self.db.execute(
            "INSERT INTO opportunities (customer_id, name, amount, stage, "
            "close_date, created_at) VALUES (?,?,?,?,?,?)",
            (customer_id, name, amount, "initial_contact", close_date,
             datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        oid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        return [self._ok(f"✅ 已创建机会 #{oid}：{name}，金额 {amount:,.0f}，"
                         f"阶段「初步接触」，关联客户 #{customer_id}")]

    def list_opportunities(self, _intent):
        """查看所有机会，按阶段分组展示（每个阶段一个表格块）。"""
        order = ["initial_contact", "needs_analysis", "proposal",
                 "negotiation", "won", "lost"]
        blocks = []
        for stage in order:
            rows = self.db.query(
                "SELECT o.id, o.name, o.amount, o.close_date, o.closed_reason, "
                "c.name AS cust FROM opportunities o "
                "LEFT JOIN customers c ON o.customer_id=c.id "
                "WHERE o.stage=? ORDER BY o.id",
                (stage,),
            )
            if not rows:
                continue
            subtotal = sum(r["amount"] or 0 for r in rows)
            blocks.append(self._table(
                f"💼 {STAGE_LABELS[stage]}（{len(rows)} 个，合计 {subtotal:,.0f}）",
                ["ID", "机会名称", "客户", "金额", "预计关闭", "关闭原因"],
                [[r["id"], r["name"], r["cust"], f"{r['amount'] or 0:,.0f}",
                  r["close_date"], r["closed_reason"]] for r in rows],
            ))
        if not blocks:
            return [self._info("（暂无机会记录）")]
        return blocks

    def _get_opp(self, oid):
        """按 ID 取机会行。"""
        return self.db.query_one("SELECT * FROM opportunities WHERE id=?", (oid,))

    def update_opp_stage(self, intent):
        """推进/更新机会阶段。"""
        oid, stage = intent["id"], intent["stage"]
        if not self._get_opp(oid):
            return [self._err(f"❌ 机会 #{oid} 不存在。")]
        self.db.execute(
            "UPDATE opportunities SET stage=? WHERE id=?", (stage, oid)
        )
        return [self._ok(f"✅ 机会 #{oid} 阶段已更新为「{STAGE_LABELS[stage]}」。")]

    def update_opp_amount(self, intent):
        """修改机会金额。"""
        oid, amount = intent["id"], intent["amount"]
        if not self._get_opp(oid):
            return [self._err(f"❌ 机会 #{oid} 不存在。")]
        self.db.execute(
            "UPDATE opportunities SET amount=? WHERE id=?", (amount, oid)
        )
        return [self._ok(f"✅ 机会 #{oid} 金额已更新为 {amount:,.0f}。")]

    def update_opp_date(self, intent):
        """修改机会预计关闭日期。"""
        oid, date = intent["id"], intent["close_date"]
        if not self._get_opp(oid):
            return [self._err(f"❌ 机会 #{oid} 不存在。")]
        self.db.execute(
            "UPDATE opportunities SET close_date=? WHERE id=?", (date, oid)
        )
        return [self._ok(f"✅ 机会 #{oid} 预计关闭日期已更新为 {date}。")]

    def close_opportunity(self, intent):
        """关闭机会（赢单/输单），记录关闭原因。"""
        oid = intent["id"]
        result = intent.get("result")
        reason = intent.get("reason")
        if not self._get_opp(oid):
            return [self._err(f"❌ 机会 #{oid} 不存在。")]
        if result not in ("won", "lost"):
            ans = self._ask("赢单还是输单？（赢单/输单）")
            if "赢" in ans or "成交" in ans:
                result = "won"
            elif "输" in ans or "丢" in ans or "失败" in ans:
                result = "lost"
            else:
                return [self._err("❌ 未指明赢单/输单。示例：关闭机会2 赢单 价格合适")]
        if not reason:
            reason = self._ask("请输入关闭原因（可回车跳过）：") or None
        self.db.execute(
            "UPDATE opportunities SET stage=?, closed_reason=?, close_date=? "
            "WHERE id=?",
            (result, reason, datetime.now().strftime("%Y-%m-%d"), oid),
        )
        return [self._ok(f"✅ 机会 #{oid} 已关闭为「{STAGE_LABELS[result]}」"
                         + (f"，原因：{reason}" if reason else "") + "。")]

    def delete_opportunity(self, intent):
        """删除机会（二次确认）。"""
        oid = intent["id"]
        opp = self._get_opp(oid)
        if not opp:
            return [self._err(f"❌ 机会 #{oid} 不存在。")]
        if not self._confirm(f"确认删除机会 #{oid}「{opp['name']}」？"):
            return [self._info("已取消删除。")]
        self.db.execute("DELETE FROM opportunities WHERE id=?", (oid,))
        return [self._ok(f"🗑️ 已删除机会 #{oid}「{opp['name']}」。")]

    # ==========================================================================
    # 任务 / 跟进管理
    # ==========================================================================
    def add_task(self, intent):
        """创建任务，关联客户或机会。"""
        related_type = intent.get("related_type")
        related_id = intent.get("related_id")
        description = intent.get("description")
        due_date = intent.get("due_date")

        if not description:
            description = self._ask("请输入任务内容：") or None
            if not description:
                return [self._err("❌ 缺少任务内容，已取消。")]
        if related_id is None:
            ans = self._ask("请输入关联对象ID（客户或机会）：")
            related_id = int(ans) if ans.isdigit() else None

        # 校验关联对象存在
        if related_type == "customer" and related_id is not None:
            if not self._get_customer(related_id):
                return [self._err(f"❌ 客户 #{related_id} 不存在。")]
        if related_type == "opportunity" and related_id is not None:
            if not self._get_opp(related_id):
                return [self._err(f"❌ 机会 #{related_id} 不存在。")]

        self.db.execute(
            "INSERT INTO tasks (related_type, related_id, description, due_date, status)"
            " VALUES (?,?,?,?,?)",
            (related_type, related_id, description, due_date, "待办"),
        )
        tid = self.db.query_one("SELECT last_insert_rowid() id")["id"]
        rel_label = "客户" if related_type == "customer" else "机会"
        return [self._ok(f"✅ 已创建任务 #{tid}：{description}"
                         + (f"（截止 {due_date}）" if due_date else "")
                         + f"，关联{rel_label} #{related_id}")]

    def list_tasks(self, intent):
        """列出任务；可按状态、关联客户/机会筛选。"""
        status = intent.get("status")
        cid = intent.get("customer_id")
        oid = intent.get("opportunity_id")

        sql = (
            "SELECT id, related_type, related_id, description, due_date, status "
            "FROM tasks WHERE 1=1"
        )
        params = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if cid is not None:
            sql += " AND related_type='customer' AND related_id=?"
            params.append(cid)
        if oid is not None:
            sql += " AND related_type='opportunity' AND related_id=?"
            params.append(oid)
        sql += " ORDER BY status DESC, due_date"
        rows = self.db.query(sql, tuple(params))

        title = "📌 未完成任务" if status == "待办" else "📌 任务列表"
        return [self._table(
            title,
            ["ID", "关联", "内容", "截止日期", "状态"],
            [[r["id"],
              ("客户#" if r["related_type"] == "customer" else "机会#")
              + str(r["related_id"]),
              r["description"], r["due_date"], r["status"]] for r in rows],
        )]

    def complete_task(self, intent):
        """标记任务完成。"""
        tid = intent["id"]
        row = self.db.query_one("SELECT description, status FROM tasks WHERE id=?", (tid,))
        if not row:
            return [self._err(f"❌ 任务 #{tid} 不存在。")]
        if row["status"] == "已完成":
            return [self._info(f"ℹ️ 任务 #{tid} 已是完成状态。")]
        self.db.execute("UPDATE tasks SET status='已完成' WHERE id=?", (tid,))
        return [self._ok(f"✅ 任务 #{tid}「{row['description']}」已标记为完成。")]

    def delete_task(self, intent):
        """删除任务（二次确认）。"""
        tid = intent["id"]
        row = self.db.query_one("SELECT description FROM tasks WHERE id=?", (tid,))
        if not row:
            return [self._err(f"❌ 任务 #{tid} 不存在。")]
        if not self._confirm(f"确认删除任务 #{tid}「{row['description']}」？"):
            return [self._info("已取消删除。")]
        self.db.execute("DELETE FROM tasks WHERE id=?", (tid,))
        return [self._ok(f"🗑️ 已删除任务 #{tid}。")]


# ==============================================================================
# Web 前端：标准库 http.server，提供聊天式交互界面 + /api/command 接口
# ==============================================================================
def run_web(host="127.0.0.1", port=6001):
    """
    启动本地 Web 服务：GET / 返回聊天页面，POST /api/command 执行命令。
    复用 CRMAgent（interactive=False）的全部业务逻辑，结果以 JSON 块返回。
    采用单线程 HTTPServer，避免 SQLite 跨线程问题。
    """
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    agent = CRMAgent(interactive=False)  # Web 模式：不走 input() 追问

    class Handler(BaseHTTPRequestHandler):
        """处理页面与 API 请求。"""

        def _send(self, code, body, content_type="application/json; charset=utf-8"):
            """统一发送响应。"""
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            """返回前端页面 / skill 列表。"""
            if self.path in ("/", "/index.html"):
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
            elif self.path == "/api/skill/list":
                installed, quarantined = agent.skills.listing()
                self._send(200, json.dumps(
                    {"installed": installed, "quarantined": quarantined},
                    ensure_ascii=False))
            else:
                self._send(404, "Not Found", "text/plain; charset=utf-8")

        def _body(self):
            """读取并解码请求体为 dict。"""
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length) if length else b"{}"
            for enc in ("utf-8", "gbk"):
                try:
                    raw = data.decode(enc)
                    break
                except UnicodeDecodeError:
                    raw = data.decode("utf-8", errors="replace")
            try:
                return json.loads(raw) or {}
            except Exception:
                return {}

        def do_POST(self):
            """执行命令 / 上传 skill。"""
            if self.path == "/api/skill/upload":
                payload = self._body()
                res = agent.skills.submit(
                    payload.get("name", ""), payload.get("content", ""))
                self._send(200, json.dumps(res, ensure_ascii=False))
                return
            if self.path != "/api/command":
                self._send(404, json.dumps({"error": "not found"}))
                return
            command = (self._body().get("command", "") or "").strip()
            if not command:
                self._send(200, json.dumps({"blocks": []}, ensure_ascii=False))
                return
            blocks = agent.process(command)
            self._send(200, json.dumps({"blocks": blocks}, ensure_ascii=False))

        def log_message(self, *_args):
            """静默访问日志，保持控制台干净。"""
            return

    server = HTTPServer((host, port), Handler)
    print("=" * 60)
    print(f" 🌐  CRM-Agent Web 已启动 -> http://{host}:{port}")
    print("     在浏览器打开上面的地址即可对话，Ctrl+C 停止")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止 Web 服务。")
    finally:
        server.server_close()
        agent.db.close()


# ------------------------------------------------------------------------------
# 前端页面（单页 HTML，内联 CSS/JS，零外部依赖）
# ------------------------------------------------------------------------------
INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRM-Agent · 自然语言客户管理</title>
<style>
  :root {
    --bg: #0f172a; --panel: #1e293b; --panel2: #273449;
    --line: #334155; --txt: #e2e8f0; --muted: #94a3b8;
    --brand: #6366f1; --brand2: #8b5cf6; --ok: #22c55e; --err: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; height: 100vh; display: flex; color: var(--txt);
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    background: radial-gradient(1200px 600px at 80% -10%, #1e1b4b 0%, var(--bg) 55%);
  }
  /* 侧栏：命令示例 */
  #side {
    width: 290px; flex-shrink: 0; background: rgba(15,23,42,.6);
    border-right: 1px solid var(--line); padding: 20px 16px; overflow-y: auto;
  }
  #side h2 { font-size: 14px; color: var(--muted); margin: 18px 0 8px; letter-spacing: .05em; }
  .brand { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 700; }
  .brand .dot { width: 28px; height: 28px; border-radius: 8px;
    background: linear-gradient(135deg, var(--brand), var(--brand2));
    display: grid; place-items: center; }
  .chip {
    display: block; width: 100%; text-align: left; cursor: pointer;
    background: var(--panel); border: 1px solid var(--line); color: var(--txt);
    border-radius: 10px; padding: 8px 10px; margin: 6px 0; font-size: 12.5px;
    transition: .15s; line-height: 1.4;
  }
  .chip:hover { border-color: var(--brand); background: var(--panel2); transform: translateX(2px); }
  /* 主区 */
  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #top { padding: 16px 24px; border-bottom: 1px solid var(--line);
    display: flex; align-items: center; justify-content: space-between; }
  #top .sub { color: var(--muted); font-size: 13px; }
  #log { flex: 1; overflow-y: auto; padding: 24px; display: flex; flex-direction: column; gap: 14px; }
  .row { display: flex; }
  .row.user { justify-content: flex-end; }
  .bubble { max-width: 78%; padding: 11px 15px; border-radius: 14px; line-height: 1.55;
    white-space: pre-wrap; word-break: break-word; font-size: 14px; }
  .user .bubble { background: linear-gradient(135deg, var(--brand), var(--brand2)); color: #fff;
    border-bottom-right-radius: 4px; }
  .bot .bubble { background: var(--panel); border: 1px solid var(--line);
    border-bottom-left-radius: 4px; }
  .bot .bubble.ok { border-left: 3px solid var(--ok); }
  .bot .bubble.err { border-left: 3px solid var(--err); }
  /* 表格 */
  .tbl-title { font-weight: 600; margin: 2px 0 8px; font-size: 13.5px; color: var(--txt); }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { border: 1px solid var(--line); padding: 6px 10px; text-align: left; }
  th { background: var(--panel2); color: var(--muted); font-weight: 600; }
  tr:nth-child(even) td { background: rgba(255,255,255,.02); }
  /* 概览卡片 */
  .stats { display: flex; flex-wrap: wrap; gap: 10px; }
  .stat { flex: 1; min-width: 110px; background: var(--panel2); border: 1px solid var(--line);
    border-radius: 12px; padding: 12px 14px; }
  .stat .v { font-size: 22px; font-weight: 700;
    background: linear-gradient(135deg, #a5b4fc, #c4b5fd); -webkit-background-clip: text;
    -webkit-text-fill-color: transparent; }
  .stat .l { color: var(--muted); font-size: 12px; margin-top: 2px; }
  /* 输入区 */
  #bar { padding: 16px 24px; border-top: 1px solid var(--line); display: flex; gap: 10px; }
  #inp { flex: 1; background: var(--panel); border: 1px solid var(--line); color: var(--txt);
    border-radius: 12px; padding: 12px 14px; font-size: 14px; outline: none; }
  #inp:focus { border-color: var(--brand); }
  #send { border: 0; border-radius: 12px; padding: 0 22px; cursor: pointer; color: #fff;
    font-size: 14px; font-weight: 600;
    background: linear-gradient(135deg, var(--brand), var(--brand2)); }
  #send:disabled { opacity: .5; cursor: default; }
  /* Skill 管理弹窗 */
  #mask { position: fixed; inset: 0; background: rgba(2,6,23,.66); display: none;
    align-items: center; justify-content: center; z-index: 50; }
  #mask.show { display: flex; }
  #skillbox { width: 560px; max-width: 92vw; max-height: 86vh; overflow: hidden;
    background: var(--panel); border: 1px solid var(--line); border-radius: 16px;
    display: flex; flex-direction: column; }
  .sk-head { padding: 16px 18px; border-bottom: 1px solid var(--line); position: relative; }
  .sk-head .sub { display: block; margin-top: 4px; }
  .sk-x { position: absolute; top: 14px; right: 16px; background: none; border: 0;
    color: var(--muted); font-size: 16px; cursor: pointer; }
  .sk-body { padding: 16px 18px; overflow-y: auto; }
  .sk-body label { display: block; font-size: 12.5px; color: var(--muted);
    margin: 12px 0 6px; }
  .sk-body input, .sk-body textarea { width: 100%; background: var(--panel2);
    border: 1px solid var(--line); color: var(--txt); border-radius: 10px;
    padding: 9px 11px; font-size: 13px; outline: none; font-family: inherit; }
  .sk-body textarea { height: 130px; resize: vertical;
    font-family: ui-monospace, Consolas, monospace; }
  .sk-mini { float: right; background: none; border: 0; color: var(--brand);
    cursor: pointer; font-size: 12px; }
  #sk-up { margin-top: 12px; width: 100%; border: 0; border-radius: 10px; padding: 10px;
    cursor: pointer; color: #fff; font-weight: 600;
    background: linear-gradient(135deg, var(--brand), var(--brand2)); }
  #sk-up:disabled { opacity: .5; cursor: default; }
  #sk-msg { margin-top: 12px; font-size: 13px; line-height: 1.5; }
  #sk-msg .ok { color: var(--ok); }
  #sk-msg .bad { color: var(--err); }
  #sk-list { margin-top: 14px; font-size: 12.5px; }
  #sk-list .item { border: 1px solid var(--line); border-radius: 10px; padding: 8px 10px;
    margin: 6px 0; display: flex; justify-content: space-between; gap: 8px; }
  .badge { font-size: 11px; padding: 1px 8px; border-radius: 999px; white-space: nowrap; }
  .b-ok { background: rgba(34,197,94,.15); color: #4ade80; }
  .b-bad { background: rgba(239,68,68,.15); color: #f87171; }
  .b-warn { background: rgba(234,179,8,.15); color: #facc15; }
</style>
</head>
<body>
  <aside id="side">
    <div class="brand"><span class="dot">🤝</span> CRM-Agent</div>
    <h2>客户</h2>
    <button class="chip">添加客户 张三 北京XX科技 13800000000 zhang@x.com 北京朝阳</button>
    <button class="chip">显示所有客户</button>
    <button class="chip">查找客户 张三</button>
    <h2>联系人</h2>
    <button class="chip">添加联系人 李四 客户ID=1 职位销售经理 电话13900000000</button>
    <button class="chip">客户1的联系人</button>
    <h2>销售机会</h2>
    <button class="chip">创建机会 年度采购项目 客户ID=1 金额50000</button>
    <button class="chip">将机会1推进到谈判</button>
    <button class="chip">显示所有机会</button>
    <button class="chip">关闭机会1 赢单 价格合适</button>
    <h2>任务</h2>
    <button class="chip">添加任务 客户1 回访客户确认需求 截止2026-06-10</button>
    <button class="chip">显示未完成任务</button>
    <button class="chip">完成任务1</button>
    <h2>其他</h2>
    <button class="chip">显示概览</button>
    <button class="chip">help</button>
    <h2>Skill 扩展</h2>
    <button class="chip" onclick="openSkill()">🧩 管理 / 上传 Skill</button>
    <button class="chip">显示skill</button>
  </aside>

  <main id="main">
    <div id="top">
      <div><strong>自然语言 CRM 助手</strong>
        <span class="sub">· 输入指令即可管理客户 / 联系人 / 机会 / 任务</span></div>
      <div class="sub">SQLite 本地存储</div>
    </div>
    <div id="log"></div>
    <div id="bar">
      <input id="inp" placeholder="例如：添加客户 王五 上海ABC 13700000000 / 显示概览" autofocus>
      <button id="send" onclick="send()">发送</button>
    </div>
  </main>

  <div id="mask" onclick="if(event.target===this)closeSkill()">
    <div id="skillbox">
      <div class="sk-head">
        <strong>🧩 Skill 管理</strong>
        <span class="sub">上传声明式 skill 优化 Agent · 先过安全扫描，benign 才装载</span>
        <button class="sk-x" onclick="closeSkill()">✕</button>
      </div>
      <div class="sk-body">
        <label>名称</label>
        <input id="sk-name" placeholder="例如 退款助手">
        <label>Manifest（JSON）<button class="sk-mini" onclick="fillSample()">填入示例</button></label>
        <textarea id="sk-content" spellcheck="false"
          placeholder='{"name":"退款助手","rules":[{"triggers":["退款"],"respond":"退款流程：……"}]}'></textarea>
        <button id="sk-up" onclick="uploadSkill()">上传并扫描</button>
        <div id="sk-msg"></div>
        <div id="sk-list"></div>
      </div>
    </div>
  </div>

<script>
const log = document.getElementById('log');
const inp = document.getElementById('inp');
const btn = document.getElementById('send');

// HTML 转义，避免数据里的尖括号破坏页面
function esc(s){ return String(s==null?'':s).replace(/[&<>]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function addUser(text){
  const row = document.createElement('div'); row.className = 'row user';
  row.innerHTML = '<div class="bubble">'+esc(text)+'</div>';
  log.appendChild(row); log.scrollTop = log.scrollHeight;
}

// 把后端返回的结果块渲染成气泡
function addBlocks(blocks){
  if(!blocks || !blocks.length){
    blocks = [{kind:'text', text:'（无输出）', tone:'info'}];
  }
  blocks.forEach(b => {
    const row = document.createElement('div'); row.className = 'row bot';
    const bub = document.createElement('div'); bub.className = 'bubble';
    if(b.kind === 'text'){
      if(b.tone) bub.classList.add(b.tone);
      bub.textContent = b.text;
    } else if(b.kind === 'table'){
      bub.innerHTML = renderTable(b);
    } else if(b.kind === 'stats'){
      bub.innerHTML = renderStats(b);
    }
    row.appendChild(bub); log.appendChild(row);
  });
  log.scrollTop = log.scrollHeight;
}

function renderTable(b){
  let h = '<div class="tbl-title">'+esc(b.title||'')+'</div>';
  if(!b.rows || !b.rows.length) return h + '<div style="color:#94a3b8">（没有匹配的记录）</div>';
  h += '<table><thead><tr>';
  b.headers.forEach(x => h += '<th>'+esc(x)+'</th>');
  h += '</tr></thead><tbody>';
  b.rows.forEach(r => { h += '<tr>'; r.forEach(c => h += '<td>'+esc(c)+'</td>'); h += '</tr>'; });
  return h + '</tbody></table>';
}

function renderStats(b){
  let h = '<div class="tbl-title">'+esc(b.title||'')+'</div><div class="stats">';
  b.items.forEach(i => h += '<div class="stat"><div class="v">'+esc(i.value)
    +'</div><div class="l">'+esc(i.label)+'</div></div>');
  return h + '</div>';
}

async function send(){
  const text = inp.value.trim();
  if(!text) return;
  addUser(text); inp.value = ''; btn.disabled = true;
  // 删除类操作前端先确认一次（后端在 Web 模式下默认放行）
  if(/^(删除|移除)/.test(text) && !confirm('确认执行：「'+text+'」？此操作不可撤销')){
    addBlocks([{kind:'text', text:'已取消删除。', tone:'info'}]);
    btn.disabled = false; inp.focus(); return;
  }
  try{
    const resp = await fetch('/api/command', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({command: text})
    });
    const data = await resp.json();
    addBlocks(data.blocks);
  }catch(e){
    addBlocks([{kind:'text', text:'请求失败：'+e, tone:'err'}]);
  }finally{
    btn.disabled = false; inp.focus();
  }
}

// 侧栏示例：点击即填入输入框
document.querySelectorAll('.chip').forEach(c =>
  c.addEventListener('click', () => { inp.value = c.textContent; inp.focus(); }));
inp.addEventListener('keydown', e => { if(e.key === 'Enter') send(); });

// 开场白
addBlocks([{kind:'text', tone:'info',
  text:'👋 你好！我是 CRM-Agent。用自然语言告诉我要做什么，'
       +'或点击左侧示例快速开始。输入 help 查看全部用法。'}]);

// ---- Skill 管理弹窗 ----
const mask = document.getElementById('mask');
function openSkill(){ mask.classList.add('show'); loadSkills(); }
function closeSkill(){ mask.classList.remove('show'); }
function fillSample(){
  document.getElementById('sk-name').value = '退款助手';
  document.getElementById('sk-content').value = JSON.stringify({
    name:'退款助手', version:'1.0', description:'认识退款相关说法并答复',
    rules:[
      {triggers:['退款','怎么退款','退货流程'], respond:'退款流程：1) 在机会中标记输单原因；2) 联系财务发起退款；3) 同步更新客户备注。'},
      {triggers:['大客户','vip客户'], action:'list_customers'}
    ]
  }, null, 2);
}
async function loadSkills(){
  try{
    const r = await fetch('/api/skill/list'); const d = await r.json();
    let h = '';
    (d.installed||[]).forEach(s => h += '<div class="item"><span>📦 '+esc(s.name)
      +' <span style="color:#94a3b8">· '+s.rules+' 规则</span></span>'
      +'<span class="badge b-ok">已装载</span></div>');
    (d.quarantined||[]).forEach(s => h += '<div class="item"><span>🚫 '+esc(s.name)
      +' <span style="color:#94a3b8">· '+esc(s.evidence||'')+'</span></span>'
      +'<span class="badge '+(s.verdict==='malicious'?'b-bad':'b-warn')+'">'+esc(s.verdict)+'</span></div>');
    document.getElementById('sk-list').innerHTML = h || '<span style="color:#94a3b8">暂无 skill</span>';
  }catch(e){ document.getElementById('sk-list').textContent = '加载列表失败：'+e; }
}
async function uploadSkill(){
  const name = document.getElementById('sk-name').value.trim();
  const content = document.getElementById('sk-content').value.trim();
  const msg = document.getElementById('sk-msg'); const up = document.getElementById('sk-up');
  if(!content){ msg.innerHTML = '<span class="bad">请先填写 manifest。</span>'; return; }
  up.disabled = true; msg.textContent = '扫描中…';
  try{
    const r = await fetch('/api/skill/upload', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, content})
    });
    const d = await r.json();
    const cls = d.ok ? 'ok' : 'bad';
    let line = '<span class="'+cls+'">'+esc(d.message)+'</span>';
    if(d.evidence) line += '<br><span style="color:#94a3b8">证据：'+esc(d.evidence)+'</span>';
    if(typeof d.risk_score==='number') line += '<br><span style="color:#94a3b8">判定：'
      +esc(d.verdict)+' · 风险分 '+d.risk_score+'</span>';
    msg.innerHTML = line;
    loadSkills();
  }catch(e){ msg.innerHTML = '<span class="bad">上传失败：'+e+'</span>'; }
  finally{ up.disabled = false; }
}
</script>
</body>
</html>"""


# ==============================================================================
# 程序入口： python crm_agent.py [web]
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("web", "server", "ui"):
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6001
        run_web(port=port)
    else:
        CRMAgent().run()
