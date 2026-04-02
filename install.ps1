# Forensic Workstation — Windows Installer
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

param(
    [switch]$Full,
    [switch]$Memory,
    [switch]$Ghidra,
    [switch]$Network,
    [switch]$BuildFrontend
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Forensic Workstation Installer" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Python Check ──
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
try {
    $pyVersion = python --version 2>&1
    Write-Host "  Found: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Python not found" -ForegroundColor Red
    exit 1
}

# ── 2. Backend Dependencies ──
Write-Host "[2/5] Installing backend dependencies..." -ForegroundColor Yellow
pip install fastapi uvicorn "mcp[cli]>=1.2.0" "pydantic>=2.0" "pydantic-settings>=2.0" websockets 2>&1 | Out-Null
Write-Host "  Core: FastAPI, uvicorn, mcp, pydantic" -ForegroundColor Green

if ($Full -or $Memory) {
    pip install volatility3 yara-python regipy 2>&1 | Out-Null
    Write-Host "  Memory: volatility3, yara-python, regipy" -ForegroundColor Green
}
if ($Full -or $Ghidra) {
    pip install pyhidra 2>&1 | Out-Null
    Write-Host "  Ghidra: pyhidra (JDK 21+ and Ghidra required separately)" -ForegroundColor Green
}
if ($Full -or $Network) {
    pip install pyshark 2>&1 | Out-Null
    Write-Host "  Network: pyshark (Wireshark required separately)" -ForegroundColor Green
}

# ── 3. Frontend ──
Write-Host "[3/5] Checking frontend..." -ForegroundColor Yellow
$distDir = Join-Path $ProjectDir "frontend\dist"
if (Test-Path $distDir) {
    Write-Host "  Pre-built frontend found" -ForegroundColor Green
} elseif ($BuildFrontend) {
    Write-Host "  Building frontend (requires Node.js)..." -ForegroundColor Gray
    Push-Location (Join-Path $ProjectDir "frontend")
    npm install 2>&1 | Out-Null
    npm run build 2>&1 | Out-Null
    Pop-Location
    Write-Host "  Frontend built" -ForegroundColor Green
} else {
    Write-Host "  No pre-built frontend. Use -BuildFrontend flag or build manually." -ForegroundColor Yellow
}

# ── 4. Create start script ──
Write-Host "[4/5] Creating start script..." -ForegroundColor Yellow
$startScript = @"
@echo off
title Forensic Workstation
echo.
echo   Forensic Workstation starting...
echo.
cd /d "%~dp0"
python backend\main.py
pause
"@
Set-Content (Join-Path $ProjectDir "start.bat") -Value $startScript -Encoding ASCII
Write-Host "  Created start.bat" -ForegroundColor Green

# ── 5. Register MCP for Claude Code ──
Write-Host "[5/6] Registering MCP server for Claude Code..." -ForegroundColor Yellow
$claudeSettingsPath = Join-Path $env:USERPROFILE ".claude\settings.json"
$mcpBridgePath = (Join-Path $ProjectDir "backend\mcp_bridge.py") -replace '\\', '\\\\'

$claudeDir = Split-Path $claudeSettingsPath -Parent
if (-not (Test-Path $claudeDir)) {
    New-Item -ItemType Directory -Path $claudeDir -Force | Out-Null
}

if (Test-Path $claudeSettingsPath) {
    try {
        $settings = Get-Content $claudeSettingsPath -Raw | ConvertFrom-Json
        if (-not $settings.mcpServers) {
            $settings | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue @{} -Force
        }
        $settings.mcpServers | Add-Member -NotePropertyName "forensic-workstation" -NotePropertyValue @{
            command = "python"
            args = @($mcpBridgePath -replace '\\\\', '\')
            env = @{}
        } -Force
        $settings | ConvertTo-Json -Depth 10 | Set-Content $claudeSettingsPath -Encoding UTF8
        Write-Host "  MCP registered in existing settings.json" -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: Could not update settings.json: $_" -ForegroundColor Yellow
    }
} else {
    $newSettings = @"
{
  "mcpServers": {
    "forensic-workstation": {
      "command": "python",
      "args": ["$mcpBridgePath"],
      "env": {}
    }
  }
}
"@
    Set-Content $claudeSettingsPath -Value $newSettings -Encoding UTF8
    Write-Host "  MCP registered (new settings.json created)" -ForegroundColor Green
}
Write-Host "  Path: $claudeSettingsPath" -ForegroundColor Gray
Write-Host "  Restart Claude Code to activate MCP" -ForegroundColor Gray

# ── 6. Verify ──
Write-Host "[6/6] Verifying..." -ForegroundColor Yellow
$testResult = python -c "
import sys
sys.path.insert(0, '$($ProjectDir -replace '\\', '/')/backend')
import core
from main import app
print('OK')
" 2>&1
if ($testResult -match "OK") {
    Write-Host "  Backend: OK" -ForegroundColor Green
} else {
    Write-Host "  Backend: FAILED ($testResult)" -ForegroundColor Red
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage:" -ForegroundColor White
Write-Host "  1. Double-click start.bat (or: python backend\main.py)" -ForegroundColor Gray
Write-Host "  2. Open http://localhost:8001 in browser" -ForegroundColor Gray
Write-Host "  3. Restart Claude Code for MCP tools (15 tools available)" -ForegroundColor Gray
Write-Host ""
