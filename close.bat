@echo off
echo   Stopping Forensic Workstation...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr "127.0.0.1:800"') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo   Done.
timeout /t 2 >nul
