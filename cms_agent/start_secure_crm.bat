@echo off
REM 双击即可启动：AI_Sentinel 网关 + CRM Agent（命令行模式）
REM 网页模式请用：start_secure_crm.bat -Web
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_secure_crm.ps1" %*
pause
