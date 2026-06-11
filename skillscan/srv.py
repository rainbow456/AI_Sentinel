import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from rules import scan

notes = {
    "system_instruction_override": "试图覆盖或忽略先前的系统指令",
    "jailbreak": "检测到越狱触发词（DAN / 无限制人格）",
    "role_play": "强制模型扮演新角色以绕过策略",
    "prompt_leak": "试图套取系统提示词",
    "token_smuggling": "通过编码 / 零宽字符走私隐藏指令",
    "context_manipulation": "注入伪造角色或对话模板标记",
    "api_manipulation": "篡改模型参数、工具或函数调用",
    "indirect_injection": "面向读取外部内容的 AI 的隐藏指令",
    "multilingual": "非英文（中文 / 西 / 法等）注入攻击",
    "output_hijacking": "强制逐字 / 受限输出以绕过安全措辞",
    "shell_process_exec": "检测到进程 / shell 执行调用",
    "dynamic_code_eval": "检测到动态代码执行或不安全反序列化",
    "destructive_command": "检测到破坏性系统命令",
    "remote_payload_exec": "检测到远程载荷下载并执行",
    "reverse_shell": "检测到反弹 / 绑定 shell 特征",
    "credential_file_access": "检测到读取凭据或敏感系统文件",
    "privilege_persistence": "检测到提权或持久化操作",
    "api_key": "检测到 API 密钥（sk-...）",
    "jwt": "检测到 JWT 令牌",
    "credit_card": "检测到信用卡号",
    "id_card": "检测到身份证号",
    "phone": "检测到手机号",
    "intranet_ip": "检测到内网 IP 地址",
    "email": "检测到电子邮箱地址",
    "high_entropy_blob": "检测到高熵的疑似编码 / 加密混淆串",
}


def level(n):
    if n >= 90:
        return "critical"
    if n >= 70:
        return "high"
    if n >= 40:
        return "medium"
    return "low"


def review(text):
    clock = time.perf_counter()
    rows = []
    peak = 0
    for sc, tag, owasp, frag in scan(text):
        peak = max(peak, sc)
        rows.append({
            "rule_hit": tag,
            "owasp_ast": owasp,
            "severity": level(sc),
            "description": notes.get(tag, "可疑内容"),
            "matched_content": frag,
        })
    return {
        "is_malicious": bool(rows),
        "risk_score": peak,
        "findings": rows,
        "scan_duration_ms": int((time.perf_counter() - clock) * 1000),
    }


class H(BaseHTTPRequestHandler):
    def reply(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.reply({"status": "ok"})
        else:
            self.reply({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/scan":
            self.reply({"error": "not found"}, 404)
            return
        size = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(size) or b"{}")
        except Exception:
            self.reply({"error": "bad json"}, 400)
            return
        self.reply(review(payload.get("skill_content", "")))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
