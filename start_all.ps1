# ============================================================================
#  AI Sentinel — 一键启动全部服务
#  用法：
#    .\start_all.ps1                  # 启动 Gateway + Analyst UI + CMS Agent(网页)
#    .\start_all.ps1 -Gateway         # 仅启动 Gateway (:3001)
#    .\start_all.ps1 -Analyst         # 仅启动 Analyst UI (:5000)
#    .\start_all.ps1 -CmsAgent        # 仅启动 CMS Agent 命令行 (:6000)
#    .\start_all.ps1 -CmsAgent -Web   # CMS Agent 网页模式 (:6001)
#    .\start_all.ps1 -All             # 全部服务（默认行为）
# ============================================================================
param(
    [switch]$Gateway,
    [switch]$Analyst,
    [switch]$CmsAgent,
    [switch]$Web,
    [switch]$All
)

# 如果没指定任何开关，默认启动全部
if (-not $Gateway -and -not $Analyst -and -not $CmsAgent) { $All = $true }
if ($All) { $Gateway = $true; $Analyst = $true; $CmsAgent = $true }

$ProjectRoot = $PSScriptRoot
$GateWayDir  = $ProjectRoot
$AnalystDir  = $ProjectRoot
$CmsAgentDir = Join-Path $ProjectRoot "cms_agent"

# ── Splunk / HEC 配置 ───────────────────────────────────────────────────
$env:SPLUNK_HEC_URL   = "http://localhost:8088/services/collector"
$env:SPLUNK_HEC_TOKEN = "b122039b-c1bd-40ca-a16e-9873126b70a3"
$env:SPLUNK_HEC_VERIFY = "0"
$env:GATEWAY_ID = "gateway-01"
$env:LLM_PROVIDER = "anthropic"
$env:NO_PROXY = "localhost,127.0.0.1"

# Analyst Splunk 搜索配置 (localhost:8000, admin/hero54110)
$env:SPLUNK_HOST = "localhost"
$env:SPLUNK_PORT = "8000"
$env:SPLUNK_USERNAME = "admin"
$env:SPLUNK_PASSWORD = "hero54110"
$env:SPLUNK_USE_REAL = "false"
$env:SPLUNK_USE_SSL = "false"
$env:SPLUNK_VERIFY_SSL = "false"

# ── 辅助函数 ─────────────────────────────────────────────────────────────
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

# ── 1) Gateway (:3001) ───────────────────────────────────────────────────
if ($Gateway) {
    Write-Banner "1/3 AI Sentinel Gateway (http://localhost:3001)"
    Start-InNewWindow "Gateway" $GatewayDir "python -u -m gateway.main"
    Start-Sleep -Seconds 3
}

# ── 2) Analyst UI (:5000) ───────────────────────────────────────────────
if ($Analyst) {
    Write-Banner "2/3 Analyst Command Center (http://localhost:5000)"
    Start-InNewWindow "Analyst" $AnalystDir "python -u -m analyst.ui.app"
    Start-Sleep -Seconds 3
}

# ── 3) CMS Agent ────────────────────────────────────────────────────────
if ($CmsAgent) {
    if ($Web) {
        $port = 6001
        Write-Banner "3/3 CMS Agent Web (http://127.0.0.1:${port})"
        Set-Location $CmsAgentDir
        Write-Host "  [CMS Agent] 当前窗口启动网页模式 (Ctrl+C 停止)..." -ForegroundColor Yellow
        $env:GATEWAY_URL = "http://localhost:3001"
        $env:SENTINEL_ENABLED = "1"
        python crm_secure.py web $port
    } else {
        Write-Banner "3/3 CMS Agent CLI (命令行模式)"
        Set-Location $CmsAgentDir
        Write-Host "  [CMS Agent] 当前窗口启动命令行模式 (Ctrl+C 停止)..." -ForegroundColor Yellow
        $env:GATEWAY_URL = "http://localhost:3001"
        $env:SENTINEL_ENABLED = "1"
        python crm_secure.py
    }
}

# ── 完成提示 ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 64) -ForegroundColor Cyan
Write-Host "  所有服务已启动！" -ForegroundColor Green
Write-Host ("=" * 64) -ForegroundColor Cyan
Write-Host "  Gateway:    http://localhost:3001/health" -ForegroundColor White
Write-Host "  Gateway:    http://localhost:3001/docs" -ForegroundColor White
Write-Host "  Analyst UI: http://localhost:5000" -ForegroundColor White
if ($CmsAgent -and $Web) {
    Write-Host "  CMS Agent:  http://127.0.0.1:6001" -ForegroundColor White
}
Write-Host ""
Write-Host "  Gateway 和 Analyst 在各自的新窗口中运行。" -ForegroundColor DarkGray
Write-Host "  关闭那些窗口即可停止对应服务。" -ForegroundColor DarkGray
Write-Host ""
