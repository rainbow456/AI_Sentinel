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
# Environment Variables — fallback defaults only
#   配置优先级：.env  >  下面的默认值。
#   python 侧用 load_dotenv(override=True)，.env 里有的项永远生效；
#   Set-Default 只在该变量当前未设置（且 .env 缺该项时）兜底。
#   => 日常只需维护 .env 一处；除非要改默认兜底值，否则不用动本文件。
# ═══════════════════════════════════════════════════════════════════════════

# 仅当环境变量当前为空时才设默认值（不覆盖已有的 / .env 后续会再覆盖）。
function Set-Default($name, $value) {
    if (-not [System.Environment]::GetEnvironmentVariable($name, 'Process')) {
        Set-Item -Path "env:$name" -Value $value
    }
}

# --- Splunk HEC (Gateway writes events here) ---
# HEC on :8088 is plain HTTP here (no TLS listener), so use http://.
Set-Default 'SPLUNK_HEC_URL'    'http://localhost:8088/services/collector'
Set-Default 'SPLUNK_HEC_TOKEN'  '00000000-0000-0000-0000-000000000000'
Set-Default 'SPLUNK_HEC_VERIFY' '0'

# --- Splunk REST API (Analyst reads from here) ---
Set-Default 'SPLUNK_HOST'       'localhost'
Set-Default 'SPLUNK_PORT'       '8089'
Set-Default 'SPLUNK_USERNAME'   'admin'
Set-Default 'SPLUNK_PASSWORD'   'changeme'
Set-Default 'SPLUNK_USE_REAL'   'true'
# Management port :8089 is HTTPS (self-signed) -> use SSL + skip verify.
Set-Default 'SPLUNK_USE_SSL'    'true'
Set-Default 'SPLUNK_VERIFY_SSL' 'false'
Set-Default 'SPLUNK_DEFAULT_EARLIEST' '-30d'

# --- Gateway Control (Analyst → Gateway /bans) ---
Set-Default 'GATEWAY_HOST'      'localhost'
Set-Default 'GATEWAY_PORT'      '3001'
Set-Default 'GATEWAY_USE_REAL'  'true'

# --- Generic ---
Set-Default 'GATEWAY_ID'        'gateway-01'
Set-Default 'LLM_PROVIDER'      'anthropic'
Set-Default 'NO_PROXY'          'localhost,127.0.0.1'
Set-Default 'PYTHONUNBUFFERED'  '1'

# --- Additional defaults (matches .env.example) ---
Set-Default 'SPLUNK_HEC_INDEX'         'main'   # 网关写入索引；须与 SPLUNK_DEFAULT_INDEX 一致
Set-Default 'SPLUNK_DEFAULT_INDEX'     'main'   # Analyst 查询索引
Set-Default 'SPLUNK_MAX_RESULTS'       '1000'
Set-Default 'RULES_AUTO_RELOAD'        'true'
Set-Default 'POLL_INTERVAL'            '10'
Set-Default 'SENTINEL_BLOCK_DETECTORS' 'injection,prompt_injection'

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
    # chcp 65001 -> UTF-8 console so emoji/Chinese banners render (python side
    # also won't crash on a GBK console — stdout reconfigured with errors=replace).
    $fullCmd = "chcp 65001 > `$null; Set-Location '$dir'; Write-Host '[$title] Starting...' -ForegroundColor Yellow; $command"
    Start-Process powershell -ArgumentList @("-NoExit", "-Command", $fullCmd) | Out-Null
    Write-Host "  [$title] 已在新窗口启动" -ForegroundColor Green
}

# Restart helper: stop any previous AI Sentinel processes before starting new ones.
# Launcher-independent — matches the python command line, so it cleans up whether
# the last run was started via start_all.ps1 or start_all.bat. Mirrors the [0/4]
# step in start_all.bat (Get-CimInstance/Get-NetTCPConnection vs wmic/netstat).
function Stop-Previous {
    Write-Banner "0/4 Stopping previous AI Sentinel processes (restart)"

    # 1) Kill Gateway / Analyst / CRM / Traffic / MCP servers by command-line match.
    #    Also catches the launcher wrapper windows and the Analyst MCP subprocesses.
    $patterns = 'gateway\.main', 'analyst\.ui\.app', 'analyst\.servers', 'crm_secure\.py', 'traffic_generator\.py'
    $myPid = $PID
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $cl = $_.CommandLine
        $cl -and $_.ProcessId -ne $myPid -and ($patterns | Where-Object { $cl -match $_ })
    } | ForEach-Object {
        try {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
            Write-Host "  已结束 PID $($_.ProcessId)" -ForegroundColor DarkGray
        } catch {}
    }

    # 2) Backstop: free our listening ports (3001 Gateway, 5000 Analyst, 6001 CRM Agent).
    foreach ($p in 3001, 5000, 6001) {
        Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique |
            ForEach-Object {
                if ($_ -and $_ -ne $myPid) { try { Stop-Process -Id $_ -Force -ErrorAction Stop } catch {} }
            }
    }

    Start-Sleep -Seconds 2
    Write-Host "  上一轮进程已清理。" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════════════
# 0) Restart — stop any previous AI Sentinel processes before starting new ones
# ═══════════════════════════════════════════════════════════════════════════
Stop-Previous

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
Write-Host "  Splunk HEC:  http://localhost:8088/services/collector" -ForegroundColor DarkGray
Write-Host "  Splunk REST: https://localhost:8089" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Flow: CRM Agent / Traffic Gen → Gateway → Splunk HEC → Analyst" -ForegroundColor DarkGray
Write-Host "  Traffic Gen sends CRM-format commands → CRM Agent(:6001) routes to Gateway(:3001)" -ForegroundColor DarkGray
Write-Host "  Each service runs in its own window. Close windows to stop." -ForegroundColor DarkGray
Write-Host ""
