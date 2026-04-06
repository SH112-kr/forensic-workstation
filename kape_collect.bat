@echo off
chcp 949 >nul
title Forensic Workstation - KAPE Collection
setlocal

set SOURCE=%~1
set CASE_NAME=%~2

if "%SOURCE%"=="" goto usage
if "%CASE_NAME%"=="" set CASE_NAME=case

set YY=%date:~0,4%
set MM=%date:~5,2%
set DD=%date:~8,2%
set DATESTAMP=%YY%%MM%%DD%

net session >/dev/null 2>&1
if not %errorlevel%==0 (
    echo.
    echo   ERROR: Run as Administrator
    echo.
    pause
    exit /b 1
)

set OUT_DIR=%CD%\export\%DATESTAMP%_%CASE_NAME%

echo.
echo   ==========================================
echo   Forensic Workstation - KAPE Collection
echo   ==========================================
echo.
echo   Source:  %SOURCE%\
echo   Output:  %OUT_DIR%
echo.

if defined FORENSIC_KAPE_PATH (
    set KAPE_EXE=%FORENSIC_KAPE_PATH%
) else (
    where kape.exe >nul 2>&1
    if %errorlevel%==0 (
        for /f "delims=" %%i in ('where kape.exe') do set KAPE_EXE=%%i
    ) else (
        echo.
        echo   ERROR: kape.exe not found.
        echo   Set FORENSIC_KAPE_PATH or add KAPE to PATH.
        echo.
        pause
        exit /b 1
    )
)

"%KAPE_EXE%" --tsource %SOURCE%\ --tdest "%OUT_DIR%\collected" --target ForensicWorkstation --mdest "%OUT_DIR%\parsed" --module ForensicWorkstation --msource "%OUT_DIR%\collected" --vss --vd

echo.
echo   Complete: %OUT_DIR%
echo.
pause
goto :eof

:usage
echo.
echo   Usage: kape_collect.bat [drive] [case_name]
echo   Example: kape_collect.bat G: case01
echo.
pause