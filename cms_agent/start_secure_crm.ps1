# ============================================================================
#  一键启动：AI_Sentinel 安全网关 + CRM Agent
#  用法：
#    .\start_secure_crm.ps1          # 启动网关 + CRM 命令行
#    .\start_secure_crm.ps1 -Web     # 启动网关 + CRM 网页(http://127.0.0.1:6001)
#  说明：
#    - 网关在“新窗口”运行（可看实时日志），CRM 在“当前窗口”运行。
#    - 关闭 CRM 后，网关窗口仍开着；不需要时手动关闭那个窗口即可。
# ============================================================================
param([switch]$Web)

# ---------------------------------------------------------------------------
# 配置（按需修改）
# ---------------------------------------------------------------------------
$SPLUNK_HEC_URL   = "http://localhost:8088/services/collector"   # 注意是 8088，不是 8000
$SPLUNK_HEC_TOKEN = "b122039b-c1bd-40ca-a16e-9873126b70a3"
$SPLUNK_HEC_VERIFY = ""        # HEC 是 https 自签证书时填 "0"；http 留空
$GATEWAY_URL      = "http://localhost:3001"
$SENTINEL_ENABLED = "1"        # 设 "0" 可关闭守卫
$CRM_WEB_PORT     = "6001"     # 网页模式(-Web)监听端口

$GatewayDir = Split-Path $PSScriptRoot -Parent
$AgentDir   = $PSScriptRoot

# ---------------------------------------------------------------------------
# 1) 启动网关（新窗口，便于看日志）
# ---------------------------------------------------------------------------
Write-Host "==> 启动 AI_Sentinel 网关 ..." -ForegroundColor Cyan

# 拼接子窗口要执行的命令：设环境变量 + 启动网关
$gwCmd = "`$env:NO_PROXY='localhost,127.0.0.1';" +
         "`$env:SPLUNK_HEC_URL='$SPLUNK_HEC_URL';" +
         "`$env:SPLUNK_HEC_TOKEN='$SPLUNK_HEC_TOKEN';" +
         "`$env:GATEWAY_ID='gateway-01';"
if ($SPLUNK_HEC_VERIFY -ne "") { $gwCmd += "`$env:SPLUNK_HEC_VERIFY='$SPLUNK_HEC_VERIFY';" }
$gwCmd += "Set-Location '$GatewayDir'; python -u -m gateway.main"

Start-Process powershell -ArgumentList @("-NoExit", "-Command", $gwCmd) | Out-Null

# ---------------------------------------------------------------------------
# 2) 等网关就绪
# ---------------------------------------------------------------------------
Write-Host "==> 等待网关就绪 ($GATEWAY_URL/health) ..." -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-RestMethod -Uri "$GATEWAY_URL/health" -TimeoutSec 3
        if ($r.status -eq "ok") { $ready = $true; break }
    } catch { }
}
if ($ready) {
    Write-Host "==> 网关已就绪 (检测器 $($r.detector_count) 个) ✅" -ForegroundColor Green
} else {
    Write-Host "==> 网关未在 80s 内就绪，请查看新开的网关窗口日志。" -ForegroundColor Yellow
    Write-Host "    （首次启动会下载 spaCy 模型，可能较慢；可稍候再启动 CRM。）" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 3) 启动 CRM Agent（当前窗口，交互）
# ---------------------------------------------------------------------------
$env:GATEWAY_URL = $GATEWAY_URL
$env:SENTINEL_ENABLED = $SENTINEL_ENABLED
$env:NO_PROXY = "localhost,127.0.0.1"
Set-Location $AgentDir

if ($Web) {
    Write-Host "==> 启动 CRM Agent（网页模式 http://127.0.0.1:$CRM_WEB_PORT）..." -ForegroundColor Cyan
    python crm_agent.py web $CRM_WEB_PORT
} else {
    Write-Host "==> 启动 CRM Agent（命令行模式）..." -ForegroundColor Cyan
    python crm_agent.py
}
