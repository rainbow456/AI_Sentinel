"""
Centralized configuration for the Multi-Alert Security Analyzer.

All service connections (Splunk, Gateway, Rule Engine) are configured here.
Environment variables override defaults — sensitive values should never be
hardcoded.

Usage:
    from analyst.config import get_config
    cfg = get_config()
    print(cfg.splunk_host)  # → "splunk.example.com" (or env SPLUNK_HOST)

Quick start (simulated mode, no external services):
    All backends default to simulated mode. Just run the app — no config needed.

Connect to real Splunk:
    export SPLUNK_HOST=splunk.internal.example.com
    export SPLUNK_PORT=8089
    export SPLUNK_USERNAME=admin
    export SPLUNK_PASSWORD=changeme
    export SPLUNK_USE_REAL=true

Connect to real Gateway:
    export GATEWAY_HOST=gateway.internal.example.com
    export GATEWAY_PORT=8443
    export GATEWAY_API_KEY=sk-gw-xxxxx

Custom rules path:
    export RULES_PATH=/path/to/custom/rules.yaml
"""

import os
from dataclasses import dataclass, field


@dataclass
class SplunkConfig:
    """Splunk connection settings."""

    # ── Connection ──────────────────────────────────────────────────────
    host: str = "pdas-snap-dad-controlled.trycloudflare.com"
    port: int = 443
    username: str = "admin"
    password: str = "hero54110"                # Set via SPLUNK_PASSWORD env var — NEVER hardcode
    token: str = ""                   # HTTP Event Collector token (alternative to user/pass)

    # ── SSL / TLS ───────────────────────────────────────────────────────
    use_ssl: bool = True
    verify_ssl: bool = True

    # ── Mode ────────────────────────────────────────────────────────────
    use_real: bool = False    # True = connect to real Splunk; False = simulated backend

    # ── Query defaults ──────────────────────────────────────────────────
    default_index: str = "gateway_events"
    default_earliest: str = "-1h"
    max_results: int = 1000

    def is_configured(self) -> bool:
        """Check if enough config is present to attempt a real connection."""
        return self.use_real and bool(self.host) and (bool(self.token) or bool(self.password))


@dataclass
class GatewayConfig:
    """Gateway Control connection settings."""

    host: str = "gateway.example.com"
    port: int = 8443
    api_key: str = ""         # Set via GATEWAY_API_KEY env var
    use_real: bool = False    # True = connect to real gateway; False = simulated

    def is_configured(self) -> bool:
        return self.use_real and bool(self.host) and bool(self.api_key)


@dataclass
class RuleEngineConfig:
    """Rule Engine settings."""

    rules_path: str = ""      # Path to rules.yaml (auto-computed if empty)
    auto_reload: bool = True  # Hot-reload rules on every get_rules() call


@dataclass
class AppConfig:
    """Top-level application configuration."""

    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    rules: RuleEngineConfig = field(default_factory=RuleEngineConfig)


# ═══════════════════════════════════════════════════════════════════════════
# Config loader — env vars override defaults
# ═══════════════════════════════════════════════════════════════════════════

def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name, str(default)).lower()
    return val in ("true", "1", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def get_config() -> AppConfig:
    """
    Build the application config from environment variables.

    Priority: environment variable > default value.

    Returns:
        AppConfig with all settings resolved.
    """
    # ── Splunk ──────────────────────────────────────────────────────────
    splunk = SplunkConfig(
        host=_env("SPLUNK_HOST", "splunk.example.com"),
        port=_env_int("SPLUNK_PORT", 8089),
        username=_env("SPLUNK_USERNAME", "admin"),
        password=_env("SPLUNK_PASSWORD", ""),
        token=_env("SPLUNK_TOKEN", ""),
        use_ssl=_env_bool("SPLUNK_USE_SSL", True),
        verify_ssl=_env_bool("SPLUNK_VERIFY_SSL", True),
        use_real=_env_bool("SPLUNK_USE_REAL", False),
        default_index=_env("SPLUNK_DEFAULT_INDEX", "gateway_events"),
        default_earliest=_env("SPLUNK_DEFAULT_EARLIEST", "-1h"),
        max_results=_env_int("SPLUNK_MAX_RESULTS", 1000),
    )

    # ── Gateway ─────────────────────────────────────────────────────────
    gateway = GatewayConfig(
        host=_env("GATEWAY_HOST", "gateway.example.com"),
        port=_env_int("GATEWAY_PORT", 8443),
        api_key=_env("GATEWAY_API_KEY", ""),
        use_real=_env_bool("GATEWAY_USE_REAL", False),
    )

    # ── Rule Engine ─────────────────────────────────────────────────────
    rules = RuleEngineConfig(
        rules_path=_env("RULES_PATH", ""),
        auto_reload=_env_bool("RULES_AUTO_RELOAD", True),
    )

    return AppConfig(splunk=splunk, gateway=gateway, rules=rules)


# ── Convenience: module-level access (loaded once at import) ──────────────

_config: AppConfig | None = None


def reload_config() -> AppConfig:
    """Force reload config from environment (useful for testing)."""
    global _config
    _config = get_config()
    return _config


# Auto-load on first access
def _get_cached() -> AppConfig:
    global _config
    if _config is None:
        _config = get_config()
    return _config


# Public shortcut
@property
def config() -> AppConfig:  # type: ignore
    return _get_cached()


# Make `config` accessible as a module attribute via __getattr__
def __getattr__(name: str):
    if name == "config":
        return _get_cached()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ── Print current config ──────────────────────────────────────────────────

def print_config():
    """Print current configuration (masks passwords)."""
    c = _get_cached()
    print("═" * 60)
    print("  Current Configuration")
    print("═" * 60)
    print(f"  Splunk:")
    print(f"    host      = {c.splunk.host}:{c.splunk.port}")
    print(f"    username  = {c.splunk.username}")
    print(f"    password  = {'***' if c.splunk.password else '(not set)'}")
    print(f"    token     = {c.splunk.token[:8]}...{'***' if c.splunk.token else '(not set)'}")
    print(f"    use_real  = {c.splunk.use_real}")
    print(f"    simulated = {not c.splunk.use_real}")
    print(f"  Gateway:")
    print(f"    host      = {c.gateway.host}:{c.gateway.port}")
    print(f"    api_key   = {'***' if c.gateway.api_key else '(not set)'}")
    print(f"    use_real  = {c.gateway.use_real}")
    print(f"  Rules:")
    print(f"    path      = {c.rules.rules_path or '(auto)'}")
    print(f"    auto_reload = {c.rules.auto_reload}")
    print("═" * 60)


# ── CLI entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print_config()
