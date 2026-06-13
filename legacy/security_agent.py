"""
[DEPRECATED] — Superseded by analyst/agent.py (SecurityAgent with MCP, dual-mode, NL commands).
Legacy Security Monitoring Agent — polls simulated Splunk for high-priority alerts.
"""

import re
import signal
import sys
import time
from collections import Counter
from datetime import datetime, timedelta

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

from simulated_splunk import SecurityEvent, SimulatedSplunk

# ── Display helpers ───────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

SEVERITY_COLORS = {
    "critical": RED + BOLD,
    "high": RED,
    "medium": YELLOW,
    "low": DIM,
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def timestamp() -> str:
    """Return current time as [HH:MM:SS] string."""
    return f"{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RESET}"


def think(msg: str):
    """Print a 'thinking' message — the agent's internal monologue."""
    print(f"{timestamp()} {CYAN}🧠 思考{RESET} {msg}")


def step(emoji: str, msg: str):
    """Print a high-level action step."""
    print(f"{timestamp()} {emoji} {BOLD}{msg}{RESET}")


def divider(char: str = "─", width: int = 60):
    """Print a horizontal divider."""
    print(f"{DIM}{char * width}{RESET}")


# ── Security Agent ────────────────────────────────────────────────────────

class SecurityAgent:
    """
    Autonomous security monitoring agent.

    Polls a simulated Splunk instance every 30 seconds for new high-priority
    alerts, extracts threat information, investigates correlated activity,
    and produces natural language analysis reports.
    """

    def __init__(self):
        self.splunk = SimulatedSplunk(seed_events=40)
        self.last_check_time = datetime.now()
        self.cycle_count = 0
        self.alerts_processed = 0
        self._running = True

        # Track seen alerts to avoid re-processing
        self._seen_alert_ids: set[str] = set()

    # ── Main loop ─────────────────────────────────────────────────────

    def run(self):
        """Main agent loop. Runs until interrupted with Ctrl+C."""
        self._setup_signal_handlers()

        print()
        divider("═", 62)
        print(f"  {BOLD}{CYAN}🛡️  安全监控 Agent 已启动{RESET}")
        print(f"  {DIM}轮询间隔: 30秒 | 告警源: 模拟 Splunk{RESET}")
        print(f"  {DIM}按 Ctrl+C 停止{RESET}")
        divider("═", 62)
        print()

        # Do an immediate first check so the user sees results quickly
        self._run_cycle()

        while self._running:
            try:
                think(f"等待 30 秒后进行下一轮检查...")
                # Sleep in small chunks so Ctrl+C is responsive
                for _ in range(30):
                    if not self._running:
                        break
                    time.sleep(1)
                if self._running:
                    self._run_cycle()
            except KeyboardInterrupt:
                break

        self._shutdown()

    def _run_cycle(self):
        """Execute one full monitoring cycle."""
        self.cycle_count += 1

        print()
        divider("─", 58)
        print(
            f"{timestamp()} 🔍 {BOLD}检查轮次 #{self.cycle_count}{RESET}"
            f"  {DIM}│  已处理 {self.alerts_processed} 条告警{RESET}"
        )
        divider("─", 58)

        # ── Step 1: Check for new high-priority alerts ──────────────────
        step("📡", "查询 Splunk: 检查新的高危/严重告警...")
        time.sleep(0.4)  # Small delay so user can follow the thinking

        new_alerts = self.splunk.get_new_high_alerts(self.last_check_time)
        check_time = datetime.now()

        if not new_alerts:
            step("✅", "没有发现新的高危告警")
            self.last_check_time = check_time
            return

        step(
            "🚨",
            f"发现 {len(new_alerts)} 条新高危告警!",
        )

        # ── Step 2: Process each alert ──────────────────────────────────
        for i, alert in enumerate(new_alerts, 1):
            # Skip already-seen alerts
            alert_id = f"{alert.source_ip}|{alert.attack_type}|{alert.timestamp.isoformat()}"
            if alert_id in self._seen_alert_ids:
                continue
            self._seen_alert_ids.add(alert_id)

            print()
            think(f"开始分析告警 #{i}/{len(new_alerts)}...")
            time.sleep(0.3)

            # ── Step 2a: Extract threat info ───────────────────────
            self._analyze_alert(alert)
            self.alerts_processed += 1

        self.last_check_time = check_time

    def _analyze_alert(self, alert: SecurityEvent):
        """Fully analyze a single alert: extract, investigate, summarize."""
        sev_color = SEVERITY_COLORS.get(alert.severity, RESET)

        # Show the alert
        print()
        print(
            f"  {SEVERITY_EMOJI.get(alert.severity, '•')} "
            f"{sev_color}[{alert.severity.upper()}]{RESET} "
            f"{BOLD}{alert.attack_type}{RESET}"
        )
        print(f"  {DIM}描述:{RESET} {alert.description}")
        print(f"  {DIM}源 IP:{RESET} {BOLD}{alert.source_ip}{RESET}")
        print(f"  {DIM}时间:{RESET} {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

        # Extract attack type
        think(
            f"识别攻击类型: {BOLD}{alert.attack_type}{RESET}"
            f"  {DIM}(来源: {alert.source_ip}){RESET}"
        )
        time.sleep(0.3)

        # ── Step 3: Investigate the source IP ──────────────────────────
        think(
            f"在 Splunk 中搜索 IP {BOLD}{alert.source_ip}{RESET} "
            f"过去 1 小时的所有相关日志..."
        )
        time.sleep(0.5)

        related_logs = self.splunk.get_events_by_ip(
            alert.source_ip, time_range=timedelta(hours=1)
        )

        think(
            f"搜索完成 — 找到 {BOLD}{len(related_logs)} 条{RESET} "
            f"与 {alert.source_ip} 相关的日志"
        )
        time.sleep(0.3)

        if len(related_logs) <= 1:
            think("只有当前告警 — 这可能是首次探测活动")
        else:
            # Analyze the related logs to build context
            self._correlate_logs(related_logs, alert)

        # ── Step 4: Generate summary ───────────────────────────────────
        self._print_summary(alert, related_logs)

    def _correlate_logs(self, logs: list[SecurityEvent], alert: SecurityEvent):
        """Analyze related logs to build attack context."""
        # Count attack types
        type_counts = Counter(log.attack_type for log in logs)
        sev_counts = Counter(log.severity for log in logs)

        think("关联分析: 识别相关日志中的攻击模式...")
        time.sleep(0.3)

        # Show what we found
        print(f"\n  {DIM}📊 关联日志分析:{RESET}")
        print(f"  {DIM}攻击类型分布:{RESET}")
        for atype, count in type_counts.most_common():
            marker = " ← 当前" if atype == alert.attack_type else ""
            print(f"    • {atype}: {count} 条{marker}")

        print(f"  {DIM}严重级别分布:{RESET}")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in sev_counts:
                print(
                    f"    • {SEVERITY_EMOJI.get(sev, '•')} {sev}: {sev_counts[sev]} 条"
                )

        # Timeline analysis
        if len(logs) >= 3:
            first = logs[-1]  # oldest
            last = logs[0]  # newest
            duration = (last.timestamp - first.timestamp).total_seconds()
            think(
                f"时间跨度分析: 从 {first.timestamp.strftime('%H:%M:%S')} 到 "
                f"{last.timestamp.strftime('%H:%M:%S')} "
                f"({duration:.0f} 秒内 {len(logs)} 条日志)"
            )

        # Risk escalation check
        has_critical = any(log.severity == "critical" for log in logs)
        multi_type = len(type_counts) >= 2
        if has_critical and multi_type:
            think(
                f"{RED}⚠ 警告: 检测到多种攻击类型 + 严重级别告警 — 可能是协同攻击{RESET}"
            )
        elif has_critical:
            think(f"{RED}⚠ 注意: 此 IP 触发了严重级别告警{RESET}")

    def _print_summary(self, alert: SecurityEvent, related_logs: list[SecurityEvent]):
        """Print a structured natural language summary."""
        type_counts = Counter(log.attack_type for log in related_logs)
        sev_counts = Counter(log.severity for log in related_logs)

        # Determine risk level
        if sev_counts.get("critical", 0) >= 2 or (
            sev_counts.get("critical", 0) >= 1 and len(type_counts) >= 3
        ):
            risk_level = "🔴 严重威胁"
            risk_detail = "该 IP 表现出多种攻击行为并触发了严重级别告警，威胁可信度极高"
            action = "立即封锁该 IP，启动应急响应流程，通知安全团队"
        elif sev_counts.get("critical", 0) >= 1 or sev_counts.get("high", 0) >= 3:
            risk_level = "🟠 高度可疑"
            risk_detail = "该 IP 存在明确的恶意行为，已触发高危告警，需要立即关注"
            action = "建议封锁该 IP，并在 WAF 中添加相应规则"
        elif sev_counts.get("high", 0) >= 1 or len(related_logs) >= 5:
            risk_level = "🟡 中等风险"
            risk_detail = "该 IP 表现出可疑活动模式，虽然严重程度不高但活跃度较大"
            action = "持续监控该 IP，如活动升级则立即封锁"
        else:
            risk_level = "🟢 低风险"
            risk_detail = "该 IP 仅触发少量低危告警，可能是自动化扫描或误报"
            action = "记录并继续观察，无需立即行动"

        print()
        divider("═", 58)
        print(f"  {BOLD}📋 安全事件分析报告{RESET}")
        divider("═", 58)

        # Report header
        print(f"""
  {BOLD}威胁等级:{RESET} {risk_level}
  {BOLD}攻击源 IP:{RESET} {alert.source_ip}
  {BOLD}主要攻击类型:{RESET} {alert.attack_type}
  {BOLD}相关日志数:{RESET} {len(related_logs)} 条 (过去 1 小时)
  {BOLD}首次发现:{RESET} {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
""")

        # Threat analysis
        print(f"  {BOLD}🧠 分析结论:{RESET}")
        print(f"  {risk_detail}。")

        # Activity breakdown
        if len(related_logs) > 1:
            print(f"\n  {BOLD}📊 活动统计:{RESET}")
            for atype, count in type_counts.most_common():
                pct = count / len(related_logs) * 100
                bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
                print(f"  {bar} {atype}: {count} 条")

        # Timeline
        if len(related_logs) >= 2:
            print(f"\n  {BOLD}⏱ 时间线:{RESET}")
            for log in related_logs[:8]:  # Show at most 8 entries
                sev_emoji = SEVERITY_EMOJI.get(log.severity, "•")
                print(
                    f"  {sev_emoji} [{log.timestamp.strftime('%H:%M:%S')}] "
                    f"{log.attack_type} — {log.description[:60]}"
                )
            if len(related_logs) > 8:
                print(f"  {DIM}... 还有 {len(related_logs) - 8} 条日志{RESET}")

        # Recommended actions
        print(f"\n  {BOLD}💡 建议措施:{RESET}")
        print(f"  1. {action}")
        if alert.attack_type == "SQL Injection":
            print(f"  2. 检查 Web 应用 WAF 规则，验证 SQL 注入防护是否生效")
            print(f"  3. 审计数据库访问日志，确认是否有数据泄露")
        elif alert.attack_type == "Brute Force SSH":
            print(f"  2. 检查 SSH 配置，确保禁用密码登录，仅允许密钥认证")
            print(f"  3. 审计系统日志，确认是否有成功登录记录")
        elif alert.attack_type == "Malware C2 Callback":
            print(f"  2. 立即隔离受感染主机，进行取证分析")
            print(f"  3. 检查该主机最近的进程、网络连接和文件变更")
        elif alert.attack_type == "DDoS":
            print(f"  2. 启用 DDoS 缓解措施，联系上游 ISP 进行流量清洗")
            print(f"  3. 检查业务可用性，确认是否有服务降级")
        elif alert.attack_type == "Port Scan":
            print(f"  2. 检查防火墙规则，确认不必要的端口已关闭")
            print(f"  3. 评估扫描结果 — 攻击者可能在为后续攻击做准备")
        elif alert.attack_type == "Credential Stuffing":
            print(f"  2. 检查受影响账户的登录历史，强制可疑用户重置密码")
            print(f"  3. 考虑启用 MFA 和登录速率限制")
        elif alert.attack_type == "XSS":
            print(f"  2. 审查 Content-Security-Policy 配置")
            print(f"  3. 检查输出编码和输入验证机制")
        elif alert.attack_type == "Path Traversal":
            print(f"  2. 检查 Web 服务器配置，确认路径访问限制")
            print(f"  3. 审计文件系统访问日志，确认是否有敏感文件被读取")

        # Raw log snippet
        print(f"\n  {BOLD}📄 原始日志 (摘录):{RESET}")
        print(f"  {DIM}{alert.raw_log[:120]}...{RESET}")

        divider("═", 58)
        print()

    # ── Lifecycle ──────────────────────────────────────────────────────

    def _setup_signal_handlers(self):
        """Set up graceful shutdown on Ctrl+C."""

        def handler(sig, frame):
            print()
            think("收到停止信号，正在优雅退出...")
            self._running = False

        signal.signal(signal.SIGINT, handler)

    def _shutdown(self):
        """Clean shutdown."""
        self.splunk.stop()
        print()
        divider("═", 58)
        print(
            f"  {BOLD}🛡️  Agent 已停止{RESET}"
            f"  {DIM}| 共 {self.cycle_count} 轮检查, "
            f"处理 {self.alerts_processed} 条告警{RESET}"
        )
        divider("═", 58)
        print()


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    agent = SecurityAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        pass  # Already handled by signal handler


if __name__ == "__main__":
    main()
