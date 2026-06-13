"""
[DEPRECATED] — This file has been superseded by analyst/ui/app.py.
The new Flask dashboard integrates with the SecurityAgent, MCP servers,
and real gateway event data. Use `python -m analyst.ui.app` instead.

Legacy Flask web dashboard for the Security Event Command center.
Serves a cyberpunk-themed real-time alert monitoring page backed by
the simulated Splunk data source.
"""

import json
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template, request

from simulated_splunk import SecurityEvent, SimulatedSplunk

app = Flask(__name__)

# ── In-memory alert store ─────────────────────────────────────────────────

_analyzed_alerts: list[dict] = []  # Fully analyzed alerts with reports
_lock = threading.Lock()
_splunk: SimulatedSplunk | None = None
_last_check: datetime | None = None
_running = True

# ── Risk assessment helpers ───────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#ff0040",
    "high": "#ff5500",
    "medium": "#ffcc00",
    "low": "#00ff41",
}

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}


def _assess_risk(alert: SecurityEvent, related_logs: list[SecurityEvent]) -> dict:
    """Determine risk level and generate assessment text."""
    type_counts = Counter(log.attack_type for log in related_logs)
    sev_counts = Counter(log.severity for log in related_logs)

    if sev_counts.get("critical", 0) >= 2 or (
        sev_counts.get("critical", 0) >= 1 and len(type_counts) >= 3
    ):
        return {
            "level": "🔴 严重威胁",
            "color": "#ff0040",
            "detail": "该 IP 表现出多种攻击行为并触发了严重级别告警，威胁可信度极高。建议立即启动应急响应流程。",
            "action": "立即封锁该 IP，启动应急响应流程，通知安全团队",
        }
    elif sev_counts.get("critical", 0) >= 1 or sev_counts.get("high", 0) >= 3:
        return {
            "level": "🟠 高度可疑",
            "color": "#ff5500",
            "detail": "该 IP 存在明确的恶意行为，已触发高危告警，需要立即关注。",
            "action": "建议封锁该 IP，并在 WAF 中添加相应规则",
        }
    elif sev_counts.get("high", 0) >= 1 or len(related_logs) >= 5:
        return {
            "level": "🟡 中等风险",
            "color": "#ffcc00",
            "detail": "该 IP 表现出可疑活动模式，虽然严重程度不高但活跃度较大，需要持续关注。",
            "action": "持续监控该 IP，如活动升级则立即封锁",
        }
    else:
        return {
            "level": "🟢 低风险",
            "color": "#00ff41",
            "detail": "该 IP 仅触发少量低危告警，可能是自动化扫描或误报。",
            "action": "记录并继续观察，无需立即行动",
        }


def _get_recommendations(attack_type: str) -> list[str]:
    """Return type-specific recommended actions."""
    actions = {
        "SQL Injection": [
            "检查 Web 应用 WAF 规则，验证 SQL 注入防护是否生效",
            "审计数据库访问日志，确认是否有数据泄露",
            "对受影响的 Web 应用进行代码审计",
        ],
        "Brute Force SSH": [
            "检查 SSH 配置，确保禁用密码登录，仅允许密钥认证",
            "审计系统认证日志，确认是否有成功登录记录",
            "考虑部署 fail2ban 或类似防护工具",
        ],
        "Malware C2 Callback": [
            "立即隔离受感染主机，进行取证分析",
            "检查该主机最近的进程、网络连接和文件变更",
            "扫描内网其他主机，确认影响范围",
        ],
        "DDoS": [
            "启用 DDoS 缓解措施，联系上游 ISP 进行流量清洗",
            "检查业务可用性，确认是否有服务降级",
            "评估是否需要扩容或启用 CDN 防护",
        ],
        "Port Scan": [
            "检查防火墙规则，确认不必要的端口已关闭",
            "评估扫描结果 — 攻击者可能在为后续攻击做准备",
            "加强网络入侵检测规则",
        ],
        "Credential Stuffing": [
            "检查受影响账户的登录历史，强制可疑用户重置密码",
            "考虑启用 MFA 和登录速率限制",
            "审计账户活动日志，确认是否有未授权访问",
        ],
        "XSS": [
            "审查 Content-Security-Policy 配置",
            "检查输出编码和输入验证机制",
            "对受影响页面进行安全扫描",
        ],
        "Path Traversal": [
            "检查 Web 服务器配置，确认路径访问限制",
            "审计文件系统访问日志，确认是否有敏感文件被读取",
            "修复文件下载/读取功能的路径验证逻辑",
        ],
    }
    return actions.get(attack_type, ["评估告警并采取相应安全措施"])


def _analyze_alert(alert: SecurityEvent, splunk: SimulatedSplunk) -> dict:
    """Run full analysis pipeline on a single alert, return structured report."""
    # Investigate the source IP in the past hour
    related_logs = splunk.get_events_by_ip(alert.source_ip, timedelta(hours=1))

    # Correlation analysis
    type_counts = Counter(log.attack_type for log in related_logs)
    sev_counts = Counter(log.severity for log in related_logs)

    # Time span
    if len(related_logs) >= 2:
        first = related_logs[-1]
        last = related_logs[0]
        time_span = (last.timestamp - first.timestamp).total_seconds()
    else:
        time_span = 0

    coordinated = (
        sev_counts.get("critical", 0) >= 1 and len(type_counts) >= 2
    )

    # Risk assessment
    risk = _assess_risk(alert, related_logs)
    recommendations = _get_recommendations(alert.attack_type)

    # Build timeline
    timeline = []
    for log in related_logs[:10]:
        timeline.append({
            "time": log.timestamp.strftime("%H:%M:%S"),
            "severity": log.severity,
            "attack_type": log.attack_type,
            "description": log.description,
        })

    # Build the report
    return {
        "id": str(uuid.uuid4())[:8],
        "severity": alert.severity,
        "severity_label": SEVERITY_LABEL.get(alert.severity, alert.severity),
        "severity_color": SEVERITY_COLORS.get(alert.severity, "#888"),
        "attack_type": alert.attack_type,
        "source_ip": alert.source_ip,
        "description": alert.description,
        "timestamp": alert.timestamp.isoformat(),
        "timestamp_display": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "risk_level": risk["level"],
        "risk_color": risk["color"],
        "related_count": len(related_logs),
        "technical_report": {
            "raw_log": alert.raw_log,
            "timeline": timeline,
            "correlation": {
                "attack_types": dict(type_counts),
                "severities": dict(sev_counts),
                "time_span_seconds": round(time_span, 1),
                "coordinated_attack": coordinated,
            },
        },
        "executive_summary": {
            "risk_assessment": risk["level"],
            "analysis_conclusion": risk["detail"],
            "primary_action": risk["action"],
            "recommended_actions": [risk["action"]] + recommendations,
            "activity_summary": (
                f"在过去 1 小时内，IP {alert.source_ip} 共触发 {len(related_logs)} 条安全告警，"
                f"涉及 {len(type_counts)} 种攻击类型。"
                f"主要威胁类型为 {alert.attack_type}，"
                f"{'同时存在协同攻击迹象，' if coordinated else ''}"
                f"威胁等级评定为{risk['level']}。"
            ),
        },
    }


# ── Background alert processor ────────────────────────────────────────────

def _background_processor():
    """Continuously check for new alerts and analyze them."""
    global _splunk, _last_check, _running

    _splunk = SimulatedSplunk(seed_events=20)
    _last_check = datetime.now()

    # Wait a moment for the background generator to produce events
    time.sleep(3)

    while _running:
        try:
            new_alerts = _splunk.get_new_high_alerts(_last_check)
            check_time = datetime.now()

            if new_alerts:
                analyzed = []
                for alert in new_alerts:
                    report = _analyze_alert(alert, _splunk)
                    analyzed.append(report)

                with _lock:
                    # Prepend new alerts (newest first)
                    for report in reversed(analyzed):
                        _analyzed_alerts.insert(0, report)

            _last_check = check_time

        except Exception as e:
            print(f"[Background processor error] {e}")

        # Sleep 10 seconds between checks
        for _ in range(10):
            if not _running:
                break
            time.sleep(1)


def _seed_demo_data():
    """Pre-generate analyzed alerts so the dashboard isn't empty on load."""
    global _splunk

    if _splunk is None:
        _splunk = SimulatedSplunk(seed_events=20)
        _last_check = datetime.now()
        time.sleep(2)

    # Force-generate a batch of recent high-severity events
    now = datetime.now()
    demo_events = []
    attack_types = [
        ("SQL Injection", "critical"),
        ("Brute Force SSH", "high"),
        ("Malware C2 Callback", "critical"),
        ("DDoS", "high"),
        ("Port Scan", "high"),
        ("Credential Stuffing", "high"),
        ("XSS", "medium"),
        ("Path Traversal", "high"),
        ("SQL Injection", "critical"),
        ("Brute Force SSH", "high"),
        ("Port Scan", "medium"),
        ("DDoS", "critical"),
    ]

    import random
    attacker_ips = [
        "203.0.113.42", "198.51.100.73", "45.33.32.100",
        "107.170.40.89", "185.220.101.34", "91.121.87.55",
        "62.210.16.120", "5.188.62.21", "141.98.10.65",
        "194.26.29.113", "37.49.230.83", "116.31.116.15",
    ]

    descriptions = {
        "SQL Injection": [
            "UNION-based SQL injection in product API",
            "Blind SQL injection via search parameter",
            "Error-based SQL injection in login form",
        ],
        "Brute Force SSH": [
            "SSH brute force on root account",
            "Dictionary attack against SSH service",
            "Rapid SSH connection attempts detected",
        ],
        "Malware C2 Callback": [
            "Beaconing to known C2 server detected",
            "Outbound connection to malicious domain",
            "CobaltStrike beacon pattern identified",
        ],
        "DDoS": [
            "HTTP flood from single source IP",
            "SYN flood causing connection exhaustion",
            "Layer 7 GET flood on API endpoint",
        ],
        "Port Scan": [
            "Aggressive SYN scan on common ports",
            "Service discovery scan detected",
            "Horizontal port scan across subnet",
        ],
        "Credential Stuffing": [
            "Automated login attempts detected",
            "Credential stuffing on auth endpoint",
            "Bulk account takeover attempts",
        ],
        "XSS": [
            "Reflected XSS in search parameter",
            "Stored XSS payload in comment field",
            "DOM-based XSS probe detected",
        ],
        "Path Traversal": [
            "Directory traversal to /etc/passwd",
            "Path traversal in file download",
            "LFI attempt via PHP filter wrapper",
        ],
    }

    raw_logs = {
        "SQL Injection": '192.168.1.100 - - [{ts}] "GET /api/products?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" 500 1234 "-" "sqlmap/1.6"',
        "Brute Force SSH": '{ts} sshd[2341]: Failed password for root from {ip} port 54321 ssh2',
        "Malware C2 Callback": '{ts} suricata[234]: [1:2012345:3] "ET TROJAN CobaltStrike Beacon Detected" {ip}:443 -> 10.0.1.50:49152',
        "DDoS": '{ts} kernel: [IPTABLES] SYN flood detected: 15000 SYN/sec from {ip} to 10.0.1.10:80',
        "Port Scan": '{ts} kernel: [IPTABLES] IN=eth0 SRC={ip} DST=10.0.1.10 PROTO=TCP SPT=45678 DPT=22',
        "Credential Stuffing": '{ts} app[web.1]: WARN  Failed login for user "admin@company.com" from {ip} - account locked after 5 attempts',
        "XSS": '{ts} nginx[123]: {ip} - - [{ts}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 234',
        "Path Traversal": '{ts} nginx[123]: {ip} - - [{ts}] "GET /download?file=../../etc/passwd HTTP/1.1" 403 123',
    }

    for i, (attack_type, severity) in enumerate(attack_types):
        event_time = now - timedelta(seconds=random.randint(5, 300))
        ip = random.choice(attacker_ips)
        desc = random.choice(descriptions.get(attack_type, ["Security alert"]))
        ts_apache = event_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ts_syslog = event_time.strftime("%b %d %H:%M:%S")

        raw = raw_logs.get(attack_type, "Alert from {ip}").format(
            ip=ip, ts=ts_apache
        )

        # Create related events for the same IP to make investigation interesting
        related_events = []
        for j in range(random.randint(1, 4)):
            rel_time = event_time + timedelta(seconds=random.randint(10, 600))
            rel_type = random.choice(attack_types)[0]
            rel_sev = random.choice(["low", "medium", "high", "critical"])
            rel_ts = rel_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            rel_desc = random.choice(descriptions.get(rel_type, ["Related activity"]))
            rel_raw = raw_logs.get(rel_type, "Related log from {ip}").format(
                ip=ip, ts=rel_ts
            )
            related_events.append(SecurityEvent(
                timestamp=rel_time,
                severity=rel_sev,
                source_ip=ip,
                attack_type=rel_type,
                description=rel_desc,
                raw_log=rel_raw,
            ))

        # Add events to splunk store
        alert_event = SecurityEvent(
            timestamp=event_time,
            severity=severity,
            source_ip=ip,
            attack_type=attack_type,
            description=desc,
            raw_log=raw,
        )
        with _splunk._lock:
            _splunk._events.append(alert_event)
            for re in related_events:
                _splunk._events.append(re)

        # Analyze
        all_related = [alert_event] + related_events
        # We need get_events_by_ip to work — use the splunk's method
        # Reconstruct related logs via the splunk API
        full_related = _splunk.get_events_by_ip(ip, timedelta(hours=1))
        if not full_related:
            full_related = all_related

        report = {
            "id": f"demo-{i:03d}",
            "severity": severity,
            "severity_label": SEVERITY_LABEL.get(severity, severity),
            "severity_color": SEVERITY_COLORS.get(severity, "#888"),
            "attack_type": attack_type,
            "source_ip": ip,
            "description": desc,
            "timestamp": event_time.isoformat(),
            "timestamp_display": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": _assess_risk(alert_event, full_related)["level"],
            "risk_color": _assess_risk(alert_event, full_related)["color"],
            "related_count": len(full_related),
            "technical_report": {
                "raw_log": raw,
                "timeline": [
                    {
                        "time": e.timestamp.strftime("%H:%M:%S"),
                        "severity": e.severity,
                        "attack_type": e.attack_type,
                        "description": e.description,
                    }
                    for e in sorted(full_related, key=lambda x: x.timestamp, reverse=True)[:8]
                ],
                "correlation": {
                    "attack_types": dict(Counter(e.attack_type for e in full_related)),
                    "severities": dict(Counter(e.severity for e in full_related)),
                    "time_span_seconds": round(
                        (full_related[0].timestamp - full_related[-1].timestamp).total_seconds(), 1
                    ) if len(full_related) >= 2 else 0,
                    "coordinated_attack": any(
                        e.severity == "critical" for e in full_related
                    ) and len(set(e.attack_type for e in full_related)) >= 2,
                },
            },
            "executive_summary": _build_exec_summary(alert_event, full_related),
        }
        _analyzed_alerts.append(report)


def _build_exec_summary(alert: SecurityEvent, related_logs: list[SecurityEvent]) -> dict:
    """Build the executive summary for a pre-seeded demo alert."""
    risk = _assess_risk(alert, related_logs)
    recommendations = _get_recommendations(alert.attack_type)
    type_counts = Counter(log.attack_type for log in related_logs)
    coordinated = (
        any(e.severity == "critical" for e in related_logs)
        and len(type_counts) >= 2
    )

    return {
        "risk_assessment": risk["level"],
        "analysis_conclusion": risk["detail"],
        "primary_action": risk["action"],
        "recommended_actions": [risk["action"]] + recommendations,
        "activity_summary": (
            f"在过去 1 小时内，IP {alert.source_ip} 共触发 {len(related_logs)} 条安全告警，"
            f"涉及 {len(type_counts)} 种攻击类型。"
            f"主要威胁类型为 {alert.attack_type}，"
            f"{'同时存在协同攻击迹象，' if coordinated else ''}"
            f"威胁等级评定为{risk['level']}。"
        ),
    }


# ── Flask routes ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/alerts")
def get_alerts():
    """Return all analyzed alerts (summary fields only)."""
    with _lock:
        alerts = []
        for a in _analyzed_alerts:
            alerts.append({
                "id": a["id"],
                "severity": a["severity"],
                "severity_label": a["severity_label"],
                "severity_color": a["severity_color"],
                "attack_type": a["attack_type"],
                "source_ip": a["source_ip"],
                "description": a["description"],
                "timestamp_display": a["timestamp_display"],
                "risk_level": a["risk_level"],
                "risk_color": a["risk_color"],
                "related_count": a["related_count"],
            })
        return jsonify(alerts)


@app.route("/api/alerts/<alert_id>")
def get_alert_detail(alert_id):
    """Return full analysis report for a specific alert."""
    with _lock:
        for a in _analyzed_alerts:
            if a["id"] == alert_id:
                return jsonify(a)
    return jsonify({"error": "Alert not found"}), 404


@app.route("/api/stats")
def get_stats():
    """Return aggregate statistics."""
    with _lock:
        sev_counts = Counter(a["severity"] for a in _analyzed_alerts)
        return jsonify({
            "total": len(_analyzed_alerts),
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
        })


@app.route("/api/events/stream")
def event_stream():
    """SSE endpoint for real-time event streaming (optional)."""
    def generate():
        last_id = 0
        while True:
            with _lock:
                if len(_analyzed_alerts) > last_id:
                    new_alerts = _analyzed_alerts[:len(_analyzed_alerts) - last_id]
                    last_id = len(_analyzed_alerts)
                    for alert in new_alerts:
                        yield f"data: {json.dumps(alert)}\n\n"
            time.sleep(3)

    return app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Startup & shutdown ────────────────────────────────────────────────────

def _startup():
    """Initialize the background processor and seed demo data."""
    global _analyzed_alerts

    print("[STARTUP] Seeding demo data...")
    _seed_demo_data()
    print(f"[STARTUP] Seeded {len(_analyzed_alerts)} demo alerts")

    print("[STARTUP] Starting background processor...")
    processor = threading.Thread(target=_background_processor, daemon=True)
    processor.start()


def _shutdown():
    """Stop the background processor."""
    global _running, _splunk
    _running = False
    if _splunk:
        _splunk.stop()


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    _startup()
    try:
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    finally:
        _shutdown()
