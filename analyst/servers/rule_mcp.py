"""
Rule Engine MCP Server — YAML-backed rule management with hot-reload.

Tools:
  - get_rules(enabled_only) → rule list
  - toggle_rule(rule_id, enabled) → updated rule
  - upsert_rule(rule_dict) → success
  - reload_rules() → reloads from YAML file

Data source: configured rules.yaml path (from analyst/config.py, default: project_root/rules.yaml).
Falls back to hardcoded defaults if YAML is unavailable.
Hot-reload: reads file on every get_rules call when auto_reload is enabled.
"""

import asyncio
import json
import os
import sys
from datetime import datetime

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from analyst.config import get_config

_rules_cfg = get_config().rules

server = Server("rule-engine-server")

# ── Default rules (fallback when YAML is unavailable) ─────────────────────

# 与 rules.yaml / analyst/rule_engine.py:DEFAULT_RULES 对齐（实测网关 rule_hit taxonomy）。
DEFAULT_RULES = [
    {"rule_id": "R001", "name": "prompt_injection", "description": "提示词注入：试图用指令覆盖/越权系统提示",
     "action": "block", "severity": "high", "enabled": True,
     "patterns": ["prompt_injection", "ignore previous", "ignore all previous", "system prompt", "forget all", "jailbreak", "you are now"]},
    {"rule_id": "R002", "name": "system_instruction_override", "description": "系统指令覆盖：诱导泄露/改写系统指令",
     "action": "block", "severity": "high", "enabled": True,
     "patterns": ["system_instruction_override", "system instruction", "override instructions", "new instructions", "disregard", "reveal the system"]},
    {"rule_id": "R003", "name": "role_play", "description": "角色扮演越狱（DAN / act as / 假装你是）",
     "action": "block", "severity": "high", "enabled": True,
     "patterns": ["role_play", "pretend you are", "act as", "roleplay", "dan mode"]},
    {"rule_id": "R004", "name": "abnormal_collaboration", "description": "Agent间异常协作（共谋）—— 由 disposition 信号触发",
     "action": "block", "severity": "critical", "enabled": True,
     "patterns": ["abnormal_collaboration", "action_confirmation"],
     "forbidden_pairs": [["tech_support", "refund"]]},
    {"rule_id": "R005", "name": "high_risk_action_keyword", "description": "高危动作关键词（删除/转账/授权/降级等）",
     "action": "block", "severity": "high", "enabled": True,
     "patterns": ["high_risk_action_keyword", "delete", "drop", "transfer", "grant", "disable", "revoke", "escalate"]},
    {"rule_id": "R006", "name": "destructive_command", "description": "破坏性命令（drop table / delete from / rm -rf / truncate）",
     "action": "block", "severity": "critical", "enabled": True,
     "patterns": ["destructive_command", "rm -rf", "drop table", "delete from", "truncate", "format", "shutdown"]},
    {"rule_id": "R007", "name": "shell_process_exec", "description": "Shell / 进程执行（os.system / subprocess / bash -c）",
     "action": "block", "severity": "critical", "enabled": True,
     "patterns": ["shell_process_exec", "/bin/sh", "subprocess", "os.system", "exec(", "powershell", "cmd.exe", "bash -c"]},
    {"rule_id": "R008", "name": "api_key", "description": "密钥/凭据泄露（API key / token / 私钥）",
     "action": "block", "severity": "critical", "enabled": True,
     "patterns": ["api_key", "secret", "token", "password", "-----begin", "access_key", "credential", "private key"]},
    {"rule_id": "R009", "name": "high_entropy_blob", "description": "高熵串：疑似密钥/Token/编码载荷",
     "action": "alert", "severity": "high", "enabled": True,
     "patterns": ["high_entropy_blob", "base64", "entropy"]},
    {"rule_id": "R010", "name": "pii_email", "description": "PII：邮箱地址",
     "action": "alert", "severity": "medium", "enabled": True,
     "patterns": ["email"]},
    {"rule_id": "R011", "name": "pii_phone", "description": "PII：电话号码",
     "action": "alert", "severity": "medium", "enabled": True,
     "patterns": ["phone"]},
    {"rule_id": "R012", "name": "pii_url", "description": "PII：URL（presidio 识别）",
     "action": "alert", "severity": "low", "enabled": True,
     "patterns": ["presidio:url"]},
    {"rule_id": "R013", "name": "multilingual_evasion", "description": "多语种混写规避检测",
     "action": "alert", "severity": "medium", "enabled": True,
     "patterns": ["multilingual"]},
]

# ── Rules file path ───────────────────────────────────────────────────────

def _rules_file_path() -> str:
    """Get the path to rules.yaml from config, with auto-computed fallback."""
    if _rules_cfg.rules_path:
        return _rules_cfg.rules_path
    # Default: project_root/rules.yaml
    # analyst/servers/rule_mcp.py → analyst/ → project root
    analyst_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root = os.path.dirname(analyst_dir)
    return os.path.join(root, "rules.yaml")


# ── YAML helpers ──────────────────────────────────────────────────────────

def _load_yaml_rules() -> list[dict] | None:
    """Try loading rules from YAML. Returns None if unavailable."""
    path = _rules_file_path()
    if not os.path.exists(path):
        return None
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, list):
            return data
    except (ImportError, Exception) as e:
        print(f"[Rule MCP] YAML load warning: {e}", file=sys.stderr)
    return None


_yaml_warned = False  # Only warn once about missing PyYAML


def _save_yaml_rules(rules: list[dict]) -> bool:
    """Persist rules to YAML. Returns True on success."""
    global _yaml_warned
    path = _rules_file_path()
    try:
        import yaml
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(rules, f, allow_unicode=True, default_flow_style=False)
        return True
    except ImportError:
        if not _yaml_warned:
            print("[Rule MCP] PyYAML not installed — rules will be in-memory only", file=sys.stderr)
            _yaml_warned = True
        return False
    except Exception as e:
        print(f"[Rule MCP] YAML save error: {e}", file=sys.stderr)
        return False


# ── In-memory rule store (loaded from YAML or defaults) ───────────────────

_rules: list[dict] = []
_rules_loaded_at: str = ""


def _ensure_rules():
    """Load rules from YAML or defaults (hot-reload on every call)."""
    global _rules, _rules_loaded_at
    yaml_rules = _load_yaml_rules()
    if yaml_rules:
        _rules = yaml_rules
    elif not _rules:
        _rules = [dict(r) for r in DEFAULT_RULES]
    _rules_loaded_at = datetime.now().isoformat()

    # Initialize rules.yaml from defaults if it doesn't exist (one-time attempt)
    path = _rules_file_path()
    if not os.path.exists(path):
        if not hasattr(_ensure_rules, '_init_attempted'):
            _ensure_rules._init_attempted = True  # type: ignore[attr-defined]
            _save_yaml_rules(_rules)


# ── Tool implementations ──────────────────────────────────────────────────

async def _do_get_rules(enabled_only: bool) -> str:
    _ensure_rules()
    rules = [r for r in _rules if not enabled_only or r.get("enabled", True)]
    return json.dumps({
        "total": len(rules),
        "enabled_count": sum(1 for r in rules if r.get("enabled", True)),
        "loaded_at": _rules_loaded_at,
        "source": "yaml" if os.path.exists(_rules_file_path()) else "defaults",
        "rules": rules,
    }, ensure_ascii=False)


async def _do_toggle_rule(rule_id: str, enabled: bool) -> str:
    _ensure_rules()
    for r in _rules:
        if r.get("rule_id") == rule_id:
            r["enabled"] = enabled
            _save_yaml_rules(_rules)
            return json.dumps({
                "success": True,
                "rule_id": rule_id,
                "enabled": enabled,
                "updated_at": datetime.now().isoformat(),
            }, ensure_ascii=False)
    return json.dumps({"error": f"Rule not found: {rule_id}"})


async def _do_upsert_rule(rule_data: dict) -> str:
    _ensure_rules()
    rid = rule_data.get("rule_id", f"R{len(_rules)+1:03d}")
    # Update existing or append
    for i, r in enumerate(_rules):
        if r.get("rule_id") == rid:
            _rules[i] = {**r, **rule_data}
            _save_yaml_rules(_rules)
            return json.dumps({"success": True, "rule_id": rid, "action": "updated"}, ensure_ascii=False)
    # New rule
    rule_data["rule_id"] = rid
    _rules.append(rule_data)
    _save_yaml_rules(_rules)
    return json.dumps({"success": True, "rule_id": rid, "action": "created"}, ensure_ascii=False)


async def _do_reload_rules() -> str:
    """Force reload from YAML."""
    global _rules
    yaml_rules = _load_yaml_rules()
    if yaml_rules:
        _rules = yaml_rules
        return json.dumps({"success": True, "source": "yaml", "count": len(_rules)}, ensure_ascii=False)
    return json.dumps({"success": False, "error": "YAML file not found or invalid"}, ensure_ascii=False)


async def _do_delete_rule(rule_id: str) -> str:
    _ensure_rules()
    global _rules
    new_rules = [r for r in _rules if r.get("rule_id") != rule_id]
    if len(new_rules) < len(_rules):
        _rules = new_rules
        _save_yaml_rules(_rules)
        return json.dumps({"success": True, "rule_id": rule_id, "action": "deleted"}, ensure_ascii=False)
    return json.dumps({"error": f"Rule not found: {rule_id}"})


# ── MCP Tool definitions & handler ────────────────────────────────────────

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_rules",
            description="Get all rules, optionally filtering to enabled only. Hot-reloads from YAML.",
            inputSchema={
                "type": "object",
                "properties": {
                    "enabled_only": {"type": "boolean", "description": "If true, return only enabled rules", "default": False},
                },
            },
        ),
        Tool(
            name="toggle_rule",
            description="Enable or disable a rule by ID. Persists to YAML.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule ID to toggle"},
                    "enabled": {"type": "boolean", "description": "New enabled state"},
                },
                "required": ["rule_id", "enabled"],
            },
        ),
        Tool(
            name="upsert_rule",
            description="Create or update a rule. Persists to YAML.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_data": {"type": "object", "description": "Rule definition dict"},
                },
                "required": ["rule_data"],
            },
        ),
        Tool(
            name="reload_rules",
            description="Force reload rules from YAML file.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="delete_rule",
            description="Delete a rule by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule ID to delete"},
                },
                "required": ["rule_id"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "get_rules":
        result = await _do_get_rules(arguments.get("enabled_only", False))
    elif name == "toggle_rule":
        result = await _do_toggle_rule(
            arguments.get("rule_id", ""),
            arguments.get("enabled", True),
        )
    elif name == "upsert_rule":
        result = await _do_upsert_rule(arguments.get("rule_data", {}))
    elif name == "reload_rules":
        result = await _do_reload_rules()
    elif name == "delete_rule":
        result = await _do_delete_rule(arguments.get("rule_id", ""))
    else:
        result = json.dumps({"error": f"Unknown tool: {name}"})

    return [TextContent(type="text", text=result)]


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream,
                server.create_initialization_options(),
            )
    asyncio.run(_run())


if __name__ == "__main__":
    main()
