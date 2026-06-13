# ============================================================================
#  AI Sentinel — One-Click Real Splunk Pipeline
#
#  Flow:
#    1. Gateway (:3001) — Detection + Splunk HEC emission
#    2. CRM Agent Web (:6001) — Monitored "victim" agent (routes to Gateway internally)
#    3. Traffic Generator — CRM-format commands → CRM Agent → Gateway → Splunk
#    4. Analyst (:5000) — Polls Splunk, generates alerts, mode/block
#
#  Prerequisites:
#    - Splunk Enterprise running on localhost:8089 (REST) + :8088 (HEC)
#    - Python 3.12+ with dependencies installed
#
#  Usage:
#    .\start_all.ps1                  # Full pipeline (all services)
#    .\start_all.ps1 -Gateway         # Gateway only
#    .\start_all.ps1 -Analyst         # Analyst only
#    .\start_all.ps1 -CrmAgent        # CRM Agent only
#    .\start_all.ps1 -Traffic         # Traffic Generator only
#    .\start_all.ps1 -Web             # CRM Agent in web mode
# ============================================================================
param(
    [switch]$Gateway,
    [switch]$Analyst,
    [switch]$CrmAgent,
    [switch]$Traffic,
    [switch]$All,
    [switch]$Web
)

# Default: start everything
if (-not $Gateway -and -not $Analyst -and -not $CrmAgent -and -not $Traffic) { $All = $true }
if ($All) { $Gateway = $true; $Analyst = $true; $CrmAgent = $true; $Traffic = $true }

$ProjectRoot  = $PSScriptRoot
$CmsAgentDir  = Join-Path $ProjectRoot "cms_agent"

# ═══════════════════════════════════════════════════════════════════════════
# Environment Variables — Real Splunk Pipeline
# ═══════════════════════════════════════════════════════════════════════════

# --- Splunk HEC (Gateway writes events here) ---
$env:SPLUNK_HEC_URL    = "https://localhost:8088/services/collector"
$env:SPLUNK_HEC_TOKEN  = "47242114-7008-4bfe-a358-41d4b4d1838e"
$env:SPLUNK_HEC_VERIFY = "0"

# --- Splunk REST API (Analyst reads from here) ---
$env:SPLUNK_HOST       = "localhost"
$env:SPLUNK_PORT       = "8089"
$env:SPLUNK_USERNAME   = "admin"
$env:SPLUNK_PASSWORD   = "hero54110"
$env:SPLUNK_USE_REAL   = "true"
$env:SPLUNK_USE_SSL    = "false"
$env:SPLUNK_VERIFY_SSL = "false"
$env:SPLUNK_DEFAULT_EARLIEST = "-30d"

# --- Gateway Control (Analyst → Gateway /bans) ---
$env:GATEWAY_HOST      = "localhost"
$env:GATEWAY_PORT      = "3001"
$env:GATEWAY_USE_REAL  = "true"
$env:GATEWAY_API_KEY   = ""

# --- Generic ---
$env:GATEWAY_ID         = "gateway-01"
$env:LLM_PROVIDER       = "anthropic"
$env:NO_PROXY           = "localhost,127.0.0.1"
$env:PYTHONUNBUFFERED   = "1"

# --- Additional defaults (matches .env.example) ---
$env:SPLUNK_TOKEN              = ""
$env:SPLUNK_DEFAULT_INDEX      = "gateway_events"
$env:SPLUNK_MAX_RESULTS        = "1000"
$env:SPLUNK_HEC_CHANNEL        = ""
$env:OPENAI_UPSTREAM_URL       = ""
$env:OPENAI_UPSTREAM_KEY       = ""
$env:RULES_PATH                = ""
$env:RULES_AUTO_RELOAD         = "true"
$env:POLL_INTERVAL             = "10"
$env:SENTINEL_BLOCK_DETECTORS  = "injection,prompt_injection"

# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════
function Write-Banner($title) {
    Write-Host ""
    Write-Host ("=" * 64) -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor White
    Write-Host ("=" * 64) -ForegroundColor Cyan
}

function Start-InNewWindow($title, $dir, $command) {
    $fullCmd = "Set-Location '$dir'; Write-Host '[$title] Starting...' -ForegroundColor Yellow; $command"
    Start-Process powershell -ArgumentList @("-NoExit", "-Command", $fullCmd) | Out-Null
    Write-Host "  [$title] 已在新窗口启动" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════════════
# 1) Gateway (:3001)
# ═══════════════════════════════════════════════════════════════════════════
if ($Gateway) {
    Write-Banner "1/4 AI Sentinel Gateway (http://localhost:3001)"
    Start-InNewWindow "Gateway" $ProjectRoot "python -u -m gateway.main"
    Start-Sleep -Seconds 3
}

# ═══════════════════════════════════════════════════════════════════════════
# 2) CRM Agent Web (:6001)
# ═══════════════════════════════════════════════════════════════════════════
if ($CrmAgent) {
    Write-Banner "2/4 CRM Agent — Security Guard Mode (http://127.0.0.1:6001)"
    $env:GATEWAY_URL     = "http://localhost:3001"
    $env:SENTINEL_ENABLED = "1"
    $port = if ($Web) { 6001 } else { 6001 }
    Write-Host "  [CRM Agent] 网页模式运行在 http://127.0.0.1:${port}" -ForegroundColor Yellow
    Start-InNewWindow "CRM-Agent" $CmsAgentDir "python crm_secure.py web $port"
    Start-Sleep -Seconds 2
}

# ═══════════════════════════════════════════════════════════════════════════
# 3) Traffic Generator
# ═══════════════════════════════════════════════════════════════════════════
if ($Traffic) {
    Write-Banner "3/4 Traffic Generator (CRM-format → CRM Agent → Gateway)"
    Write-Host "  [Traffic] 每 2s 发送一次 CRM 命令（35% 含攻击载荷）" -ForegroundColor Yellow
    Write-Host "  [Traffic] 流量路径: 流量生成器 → CRM Agent(:6001) → Gateway(:3001) → Splunk HEC" -ForegroundColor DarkGray
    Write-Host "  [Traffic] 若需更长时间，Ctrl+C 后运行: python traffic_generator.py --loop" -ForegroundColor DarkGray
    Start-InNewWindow "Traffic-Gen" $ProjectRoot "python traffic_generator.py --duration 120 --interval 2.0 --attack-ratio 0.35"
    Start-Sleep -Seconds 1
}

# ═══════════════════════════════════════════════════════════════════════════
# 4) Analyst UI (:5000)
# ═══════════════════════════════════════════════════════════════════════════
if ($Analyst) {
    Write-Banner "4/4 Analyst Command Center (http://localhost:5000)"
    Start-InNewWindow "Analyst" $ProjectRoot "python -u -m analyst.ui.app"
    Start-Sleep -Seconds 3
}

# ═══════════════════════════════════════════════════════════════════════════
# Done
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ("=" * 64) -ForegroundColor Cyan
Write-Host "  ✅ 所有服务已启动！" -ForegroundColor Green
Write-Host ("=" * 64) -ForegroundColor Cyan
Write-Host "  Gateway:     http://localhost:3001/health" -ForegroundColor White
Write-Host "  Gateway API: http://localhost:3001/docs" -ForegroundColor White
Write-Host "  CRM Agent:   http://127.0.0.1:6001" -ForegroundColor White
Write-Host "  Analyst:     http://localhost:5000" -ForegroundColor White
Write-Host ""
Write-Host "  Splunk HEC:  https://localhost:8088/services/collector" -ForegroundColor DarkGray
Write-Host "  Splunk REST: https://localhost:8089" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Flow: CRM Agent / Traffic Gen → Gateway → Splunk HEC → Analyst" -ForegroundColor DarkGray
Write-Host "  Traffic Gen sends CRM-format commands → CRM Agent(:6001) routes to Gateway(:3001)" -ForegroundColor DarkGray
Write-Host "  Each service runs in its own window. Close windows to stop." -ForegroundColor DarkGray
Write-Host ""
