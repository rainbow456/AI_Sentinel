@echo off
REM One-click real Splunk pipeline launcher
REM Usage: start_all.bat
REM NOTE: keep this file ASCII-only. cmd.exe reads .bat lines in the console
REM OEM codepage (cp936 on zh-CN), so UTF-8 Chinese/em-dashes corrupt parsing.

setlocal
set "PROJECT_ROOT=%~dp0"

REM ================================================================
REM  Config precedence: .env  >  the defaults below.
REM  The python side uses load_dotenv(override=True), so whatever is in
REM  .env always wins; the "if not defined" lines below only fill in a
REM  default when .env is missing that key (or there is no .env at all).
REM  => Day to day, only maintain .env. No need to edit this file unless
REM     you want to change the fallback defaults.
REM ================================================================

REM --- Splunk HEC (Gateway writes events here) ---
REM HEC on :8088 is plain HTTP here (no TLS listener), so use http://.
if not defined SPLUNK_HEC_URL    set "SPLUNK_HEC_URL=http://localhost:8088/services/collector"
if not defined SPLUNK_HEC_TOKEN  set "SPLUNK_HEC_TOKEN=00000000-0000-0000-0000-000000000000"
if not defined SPLUNK_HEC_VERIFY set "SPLUNK_HEC_VERIFY=0"

REM --- Splunk REST API (Analyst reads from here) ---
if not defined SPLUNK_HOST       set "SPLUNK_HOST=localhost"
if not defined SPLUNK_PORT       set "SPLUNK_PORT=8089"
if not defined SPLUNK_USERNAME   set "SPLUNK_USERNAME=admin"
if not defined SPLUNK_PASSWORD   set "SPLUNK_PASSWORD=changeme"
if not defined SPLUNK_USE_REAL   set "SPLUNK_USE_REAL=true"
REM Management port :8089 is HTTPS (self-signed) -> use SSL + skip verify.
if not defined SPLUNK_USE_SSL    set "SPLUNK_USE_SSL=true"
if not defined SPLUNK_VERIFY_SSL set "SPLUNK_VERIFY_SSL=false"
if not defined SPLUNK_DEFAULT_EARLIEST set "SPLUNK_DEFAULT_EARLIEST=-30d"

REM --- Gateway Control (Analyst -> Gateway /bans) ---
if not defined GATEWAY_HOST      set "GATEWAY_HOST=localhost"
if not defined GATEWAY_PORT      set "GATEWAY_PORT=3001"
if not defined GATEWAY_USE_REAL  set "GATEWAY_USE_REAL=true"

REM --- Generic ---
if not defined GATEWAY_ID        set "GATEWAY_ID=gateway-01"
if not defined LLM_PROVIDER      set "LLM_PROVIDER=anthropic"
if not defined NO_PROXY          set "NO_PROXY=localhost,127.0.0.1"
if not defined PYTHONUNBUFFERED  set "PYTHONUNBUFFERED=1"

REM --- Additional config (matches .env.example) ---
if not defined SPLUNK_HEC_INDEX     set "SPLUNK_HEC_INDEX=main"
if not defined SPLUNK_DEFAULT_INDEX set "SPLUNK_DEFAULT_INDEX=main"
if not defined SPLUNK_MAX_RESULTS   set "SPLUNK_MAX_RESULTS=1000"
if not defined RULES_AUTO_RELOAD    set "RULES_AUTO_RELOAD=true"
if not defined POLL_INTERVAL        set "POLL_INTERVAL=10"
if not defined SENTINEL_BLOCK_DETECTORS set "SENTINEL_BLOCK_DETECTORS=injection,prompt_injection"

echo ================================================================
echo   AI Sentinel -- Real Splunk Pipeline
echo ================================================================
echo.

REM ================================================================
REM  [0/4] Restart: stop any previous AI Sentinel processes first
REM  Launcher-independent: matches the python command line, so it
REM  cleans up regardless of whether the last run used .bat or .ps1.
REM ================================================================
echo [0/4] Stopping any previous AI Sentinel processes (restart) ...
REM Close previous service windows opened by this script. /T also kills the
REM python child running inside each window.
for %%T in (Gateway CRM-Agent Traffic-Gen Analyst) do taskkill /FI "WINDOWTITLE eq %%T*" /T /F >nul 2>&1
REM Kill any remaining Gateway / Analyst / CRM / Traffic / MCP python servers by
REM command-line match (covers runs started another way, e.g. start_all.ps1, and
REM the Analyst's MCP subprocesses). Restricted to name='python.exe' so the wmic
REM query process can never match (and terminate) itself.
for %%M in ("gateway.main" "analyst.ui.app" "analyst.servers" "crm_secure.py" "traffic_generator.py") do (
    wmic process where "name='python.exe' and commandline like '%%%%~M%%'" call terminate >nul 2>&1
)
REM Backstop: free our listening ports (3001 Gateway, 5000 Analyst, 6001 CRM Agent).
for %%P in (3001 5000 6001) do (
    for /f "tokens=5" %%I in ('netstat -ano ^| findstr ":%%P " ^| findstr LISTENING') do taskkill /F /PID %%I >nul 2>&1
)
timeout /t 2 /nobreak >nul
echo       previous processes stopped.
echo.

REM Each child window runs `chcp 65001` first so the console is UTF-8 and the
REM emoji/Chinese banners render correctly (the python side also won't crash on
REM a GBK console -- stdout is reconfigured with errors=replace).
echo [1/4] Starting Gateway (http://localhost:3001) ...
start "Gateway" /D "%PROJECT_ROOT%" cmd /k "chcp 65001>nul && python -u -m gateway.main"
timeout /t 3 /nobreak >nul

echo [2/4] Starting CRM Agent Web (http://127.0.0.1:6001) ...
start "CRM-Agent" /D "%PROJECT_ROOT%cms_agent" cmd /k "chcp 65001>nul && set GATEWAY_URL=http://localhost:3001 && set SENTINEL_ENABLED=1 && python crm_secure.py web 6001"
timeout /t 2 /nobreak >nul

echo [3/4] Starting Traffic Generator (CRM-format via CRM Agent -^> Gateway) ...
start "Traffic-Gen" /D "%PROJECT_ROOT%" cmd /k "chcp 65001>nul && python traffic_generator.py --duration 120 --interval 2.0 --attack-ratio 0.35"
timeout /t 1 /nobreak >nul

echo [4/4] Starting Analyst UI (http://localhost:5000) ...
start "Analyst" /D "%PROJECT_ROOT%" cmd /k "chcp 65001>nul && python -u -m analyst.ui.app"
timeout /t 3 /nobreak >nul

echo.
echo ================================================================
echo   All services started!
echo ================================================================
echo   Gateway:     http://localhost:3001/health
echo   Gateway API: http://localhost:3001/docs
echo   CRM Agent:   http://127.0.0.1:6001
echo   Analyst:     http://localhost:5000
echo.
echo   Splunk HEC:  http://localhost:8088/services/collector
echo   Splunk REST: https://localhost:8089
echo.
echo   Flow: CRM Agent / Traffic Gen -^> Gateway -^> Splunk HEC -^> Analyst
echo   Traffic Gen sends CRM-format commands to CRM Agent (port 6001)
echo   Each service runs in its own window. Close windows to stop.
echo.
pause
