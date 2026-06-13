@echo off
REM One-click real Splunk pipeline launcher
REM Usage: start_all.bat

setlocal
set "PROJECT_ROOT=%~dp0"

REM --- Splunk HEC (Gateway writes events here) ---
set "SPLUNK_HEC_URL=https://localhost:8088/services/collector"
set "SPLUNK_HEC_TOKEN=47242114-7008-4bfe-a358-41d4b4d1838e"
set "SPLUNK_HEC_VERIFY=0"

REM --- Splunk REST API (Analyst reads from here) ---
set "SPLUNK_HOST=localhost"
set "SPLUNK_PORT=8089"
set "SPLUNK_USERNAME=admin"
set "SPLUNK_PASSWORD=hero54110"
set "SPLUNK_USE_REAL=true"
set "SPLUNK_USE_SSL=false"
set "SPLUNK_VERIFY_SSL=false"
set "SPLUNK_DEFAULT_EARLIEST=-30d"

REM --- Gateway Control (Analyst -> Gateway /bans) ---
set "GATEWAY_HOST=localhost"
set "GATEWAY_PORT=3001"
set "GATEWAY_USE_REAL=true"
set "GATEWAY_API_KEY="

REM --- Generic ---
set "GATEWAY_ID=gateway-01"
set "LLM_PROVIDER=anthropic"
set "NO_PROXY=localhost,127.0.0.1"
set "PYTHONUNBUFFERED=1"

REM --- Additional config (matches .env.example) ---
set "SPLUNK_TOKEN="
set "SPLUNK_DEFAULT_INDEX=gateway_events"
set "SPLUNK_MAX_RESULTS=1000"
set "RULES_PATH="
set "RULES_AUTO_RELOAD=true"
set "SPLUNK_HEC_CHANNEL="
set "OPENAI_UPSTREAM_URL="
set "OPENAI_UPSTREAM_KEY="
set "POLL_INTERVAL=10"
set "SENTINEL_BLOCK_DETECTORS=injection,prompt_injection"

echo ================================================================
echo   AI Sentinel -- Real Splunk Pipeline
echo ================================================================
echo.

echo [1/4] Starting Gateway (http://localhost:3001) ...
start "Gateway" /D "%PROJECT_ROOT%" cmd /k "python -u -m gateway.main"
timeout /t 3 /nobreak >nul

echo [2/4] Starting CRM Agent Web (http://127.0.0.1:6001) ...
start "CRM-Agent" /D "%PROJECT_ROOT%cms_agent" cmd /k "set GATEWAY_URL=http://localhost:3001 && set SENTINEL_ENABLED=1 && python crm_secure.py web 6001"
timeout /t 2 /nobreak >nul

echo [3/4] Starting Traffic Generator (CRM-format via CRM Agent -^> Gateway) ...
start "Traffic-Gen" /D "%PROJECT_ROOT%" cmd /k "python traffic_generator.py --duration 120 --interval 2.0 --attack-ratio 0.35"
timeout /t 1 /nobreak >nul

echo [4/4] Starting Analyst UI (http://localhost:5000) ...
start "Analyst" /D "%PROJECT_ROOT%" cmd /k "python -u -m analyst.ui.app"
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
echo   Splunk HEC:  https://localhost:8088/services/collector
echo   Splunk REST: https://localhost:8089
echo.
echo   Flow: CRM Agent / Traffic Gen -^> Gateway -^> Splunk HEC -^> Analyst
echo   Traffic Gen sends CRM-format commands to CRM Agent (port 6001)
echo   Each service runs in its own window. Close windows to stop.
echo.
pause
