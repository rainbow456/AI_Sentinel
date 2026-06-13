@echo off

REM One-click launcher: Gateway + Analyst UI + CMS Agent

REM Usage: start_all.bat [-Web] (for CMS Agent web mode)

setlocal

set "PROJECT_ROOT=%~dp0"



set "SPLUNK_HEC_URL=http://localhost:8088/services/collector"

set "SPLUNK_HEC_TOKEN=b122039b-c1bd-40ca-a16e-9873126b70a3"

set "SPLUNK_HEC_VERIFY=0"

set "GATEWAY_ID=gateway-01"

set "LLM_PROVIDER=anthropic"

set "NO_PROXY=localhost,127.0.0.1"

set "SPLUNK_HOST=localhost"

set "SPLUNK_PORT=8089"

set "SPLUNK_USERNAME=admin"

set "SPLUNK_PASSWORD=hero54110"



set "CMS_WEB=0"

if /i "%1"=="-Web" set "CMS_WEB=1"

if /i "%1"=="web"  set "CMS_WEB=1"



echo ================================================================

echo   AI Sentinel - One-Click Start

echo ================================================================

echo.



echo [1/3] Starting Gateway (http://localhost:3001) ...

start "Gateway" /D "%PROJECT_ROOT%" cmd /k "python -u -m gateway.main"

timeout /t 3 /nobreak >nul



echo [2/3] Starting Analyst UI (http://localhost:5000) ...

start "Analyst" /D "%PROJECT_ROOT%" cmd /k "python -u -m analyst.ui.app"

timeout /t 3 /nobreak >nul



if "%CMS_WEB%"=="1" (

    echo [3/3] Starting CMS Agent Web (http://127.0.0.1:6001) ...

    cd /d "%PROJECT_ROOT%cms_agent"

    set "GATEWAY_URL=http://localhost:3001"

    set "SENTINEL_ENABLED=1"

    python crm_secure.py web 6001

) else (

    echo [3/3] Starting CMS Agent CLI ...

    cd /d "%PROJECT_ROOT%cms_agent"

    set "GATEWAY_URL=http://localhost:3001"

    set "SENTINEL_ENABLED=1"

    python crm_secure.py

)



echo.

echo Gateway and Analyst are running in separate windows.

echo Close those windows to stop the services.

pause

