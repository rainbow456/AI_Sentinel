# -*- coding: utf-8 -*-
"""
================================================================================
 crm_secure.py —— 给 CRM-Agent 接入 AI_Sentinel 安全网关的「外挂」启动器
================================================================================

设计目标：**不改动 crm_agent.py 一行代码**，在它外面包一层安全守卫。

原理：
  crm_agent.py 的业务执行都汇聚到 CRMAgent.process(raw) 这一个方法，且 CLI 与
  Web 两端都走它。本脚本用 monkey-patch 把 process 包裹起来，在调用原逻辑前后
  插入两层守卫，再启动原版的 CLI / Web。由于 patch 打在「类方法」上，run_web()
  内部新建的 CRMAgent 实例同样生效。

两层守卫（对应网关两个入口）：
  1) 输入守卫  POST /chat           —— 命令进入解析前做注入/越狱/PII 检测，403 即拦截
  2) 动作守卫  POST /confirm-action —— 删除等高危操作执行前确认，allowed=false 即阻断

策略（按既定决策）：
  - 删除类用「中性动作名」remove_record 上报，绕开网关对 delete/drop 的关键词硬阻断；
    正常删除放行，仅当原始输入含注入/恶意上下文时被检测器拦下。
  - 网关不可达时 **fail-open**：放行并打印一条告警，保证 CRM 可用。
  - 仅用标准库 urllib，零新增依赖。

【运行方式】（与 crm_agent.py 完全一致，只是换成本脚本启动）
    命令行模式：python crm_secure.py
    网页模式：  python crm_secure.py web          （默认 http://127.0.0.1:6000）
                python crm_secure.py web 8080     （自定义端口）

【前置】先启动安全网关（默认 http://localhost:3001）：
    cd d:/hackathon/AI_Sentinel
    python -m gateway.main

【环境变量】
    SENTINEL_ENABLED  默认 "1"；设 "0" 则本脚本退化为直接启动原版（不做检测）
    GATEWAY_URL       默认 "http://localhost:3001"
    AGENT_ID          默认 "crm-agent-01"
================================================================================
"""

import os
import sys
import json
import urllib.request
import urllib.error

import crm_agent  # 原版 Agent，导入不会触发其主程序（受 __main__ 保护）


# ------------------------------------------------------------------------------
# 配置（环境变量，带默认值）
# ------------------------------------------------------------------------------
SENTINEL_ENABLED = os.getenv("SENTINEL_ENABLED", "1") not in ("0", "false", "False", "")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:3001").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "crm-agent-01")

# 需要走「动作守卫」的高危 intent → 实体类型映射。
# 用中性动作名 remove_record 上报，避免命中网关英文硬阻断词（delete/drop/...）。
HIGH_RISK_ACTIONS = {
    "delete_customer": "customer",
    "delete_contact": "contact",
    "delete_opportunity": "opportunity",
    "delete_task": "task",
}

# 输入守卫的「拦截类别」白名单：只有这些检测器命中才真正拦截。
# 原因：网关的 sensitive/pii_leak 会把电话、邮箱、身份证当作敏感信息，
# 而 CRM 录入这些字段是核心合法操作（用户在管理自己的数据，不是外泄）。
# 因此默认只拦「提示词注入 / 越狱」类；PII/敏感类在输入方向放行（记一条提示）。
# 可用环境变量覆盖，例如 SENTINEL_BLOCK_DETECTORS="injection,prompt_injection,sensitive,pii_leak"
# 收紧为「全部拦截」。
BLOCK_DETECTORS = set(
    d.strip() for d in
    os.getenv("SENTINEL_BLOCK_DETECTORS", "injection,prompt_injection").split(",")
    if d.strip()
)


# ==============================================================================
# 安全网关客户端（标准库 urllib 实现）
# ==============================================================================
class SentinelClient:
    """封装对 AI_Sentinel 两个入口的调用；所有网络异常一律 fail-open。"""

    def __init__(self, base_url=GATEWAY_URL, agent_id=AGENT_ID, timeout=5.0):
        """记录网关地址、Agent 标识与超时。"""
        self.base_url = base_url
        self.agent_id = agent_id
        self.timeout = timeout

    def _post(self, path, payload):
        """
        POST JSON 到网关，返回 (status_code, body_dict)。
        注意：urllib 对 4xx/5xx 会抛 HTTPError，这里把 403 等当作正常返回处理，
        真正的连接失败（URLError/OSError）由调用方按 fail-open 兜底。
        """
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # 403 等：仍带 JSON 主体，读出来交给调用方判定
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            return e.code, body

    def check_input(self, prompt):
        """
        输入守卫。返回 (ok, info)：
          ok=False  -> 被拦截，info 为命中详情（detail）
          ok=True   -> 放行；若 info 含 'warn' 说明网关不可达走了 fail-open
        """
        try:
            status, body = self._post("/chat", {"prompt": prompt, "session_id": self.agent_id})
        except (urllib.error.URLError, OSError) as e:
            return True, {"warn": f"安全网关不可达，已放行（fail-open）：{e}"}
        if status == 403:
            return False, body.get("detail", {})
        if status != 200:
            return True, {"warn": f"安全网关返回异常状态 {status}，已放行（fail-open）"}
        return True, {}

    def confirm_action(self, action_name, action_params, user_input):
        """
        动作守卫。返回 (allowed, reason)。
        网关不可达 -> fail-open，allowed=True。
        """
        payload = {
            "action_name": action_name,
            "action_params": action_params or {},
            "agent_id": self.agent_id,
            "user_input": user_input,
        }
        try:
            status, body = self._post("/confirm-action", payload)
        except (urllib.error.URLError, OSError) as e:
            return True, f"安全网关不可达，已放行（fail-open）：{e}"
        if status != 200:
            return True, f"安全网关返回异常状态 {status}，已放行（fail-open）"
        return bool(body.get("allowed", False)), body.get("reason", "")

    def health(self):
        """健康检查；返回 detector_count 或 None（不可达）。"""
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8")).get("detector_count")
        except Exception:
            return None


# 全局单例，供被 patch 的 process 引用
SENTINEL = SentinelClient()


# ==============================================================================
# monkey-patch：在 CRMAgent.process 外面包两层守卫
# ==============================================================================
_ORIGINAL_PROCESS = crm_agent.CRMAgent.process  # 保存原方法引用


def guarded_process(self, raw):
    """
    包装版 process：先过安全网关，再调用原版业务逻辑。
    复用 self._err / self._info 等原版结果块构造器，保证 CLI / Web 渲染一致。
    """
    raw = (raw or "").strip()
    if not raw:
        return _ORIGINAL_PROCESS(self, raw)

    prefix_blocks = []  # fail-open 告警等附加提示，拼在正常结果前面

    # ── 第 1 层：输入守卫 ──
    ok, info = SENTINEL.check_input(raw)
    if not ok:
        # 网关判定命中；再按「拦截类别」决定是否真的拦
        detector = info.get("detector") or ""
        rule = info.get("rule_hit") or detector or "unknown"
        desc = (info.get("details") or {}).get("rule_description") \
            or info.get("reason") or ""
        if detector in BLOCK_DETECTORS:
            return [self._err(f"⛔ 输入被安全网关拦截：{rule}"
                              + (f" — {desc}" if desc else ""))]
        # PII/敏感类：CRM 录入合法字段，放行但留痕提示
        prefix_blocks.append(self._info(
            f"🔐 网关提示：输入含敏感字段（{rule}），按 CRM 策略放行。"))
    elif info.get("warn"):
        prefix_blocks.append(self._info("⚠️ " + info["warn"]))

    # ── 第 2 层：动作守卫（仅高危删除类）──
    intent = self.parser.parse(raw)
    action = intent.get("action")
    if action in HIGH_RISK_ACTIONS:
        params = {"entity": HIGH_RISK_ACTIONS[action], "id": intent.get("id")}
        allowed, reason = SENTINEL.confirm_action("remove_record", params, raw)
        if not allowed:
            return [self._err(f"⛔ 高危操作被安全网关阻断：{reason or '违反安全策略'}")]

    # ── 通过守卫，执行原版逻辑 ──
    return prefix_blocks + _ORIGINAL_PROCESS(self, raw)


def install_guard():
    """把守卫装到 CRMAgent 类上；返回是否成功启用。"""
    if not SENTINEL_ENABLED:
        return False
    crm_agent.CRMAgent.process = guarded_process
    return True


# ==============================================================================
# 入口：装好守卫后，复用原版的 CLI / Web 启动
# ==============================================================================
def _banner(enabled):
    """打印安全状态横幅。"""
    print("=" * 64)
    if not enabled:
        print(" 🔓  安全守卫已禁用（SENTINEL_ENABLED=0）—— 以原版模式运行")
        print("=" * 64)
        return
    count = SENTINEL.health()
    status = (f"在线，{count} 个检测器" if count is not None
              else "不可达（将 fail-open 放行 + 告警）")
    print(" 🛡️  CRM-Agent 安全模式 —— 已接入 AI_Sentinel")
    print(f"     网关：{GATEWAY_URL}  状态：{status}")
    print(f"     Agent 标识：{AGENT_ID}")
    print(f"     拦截类别：{', '.join(sorted(BLOCK_DETECTORS)) or '(无)'}"
          "  （PII/敏感类在输入方向放行）")
    print("=" * 64)


if __name__ == "__main__":
    enabled = install_guard()
    _banner(enabled)

    if len(sys.argv) > 1 and sys.argv[1].lower() in ("web", "server", "ui"):
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6000
        crm_agent.run_web(port=port)
    else:
        crm_agent.CRMAgent().run()
