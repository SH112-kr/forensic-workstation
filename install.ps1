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
    # Check minimum version (3.10+)
    $ver = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
    $major, $minor = $ver -split '\.'
    if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 10)) {
        Write-Host "  ERROR: Python 3.10+ required (found $ver)" -ForegroundColor Red
        Write-Host "  Install: winget install Python.Python.3.12" -ForegroundColor Gray
        exit 1
    }
} catch {
    Write-Host "  ERROR: Python not found. Install: winget install Python.Python.3.12" -ForegroundColor Red
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

# ── 4. External Forensic Tools (auto-download) ──
Write-Host "[4/7] Setting up forensic tools..." -ForegroundColor Yellow

$ToolsDir = Join-Path $ProjectDir "tools"
if (-not (Test-Path $ToolsDir)) { New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null }

# .env file for tool paths
$envFile = Join-Path $ProjectDir "backend\.env"

# ── KAPE ──
$kapePath = Get-ChildItem -Path $ToolsDir -Recurse -Filter "kape.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($kapePath) {
    Write-Host "  KAPE: Found $($kapePath.FullName)" -ForegroundColor Green
} else {
    Write-Host "  KAPE: Not found. Download manually from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape" -ForegroundColor Yellow
    Write-Host "         Extract to: $ToolsDir\KAPE\" -ForegroundColor Gray
}

# ── EZ Tools (Eric Zimmerman) ──
$ezToolsUrl = "https://download.ericzimmermanstools.com/net6/All_6.zip"
$ezDir = Join-Path $ToolsDir "EZTools"
if (-not (Test-Path (Join-Path $ezDir "PECmd.exe")) -and -not $kapePath) {
    Write-Host "  EZ Tools: Downloading..." -ForegroundColor Gray
    try {
        $ezZip = Join-Path $env:TEMP "EZTools.zip"
        Invoke-WebRequest -Uri $ezToolsUrl -OutFile $ezZip -UseBasicParsing
        Expand-Archive -Path $ezZip -DestinationPath $ezDir -Force
        Remove-Item $ezZip -Force
        Write-Host "  EZ Tools: Downloaded to $ezDir" -ForegroundColor Green
    } catch {
        Write-Host "  EZ Tools: Download failed. Get manually from https://ericzimmerman.github.io/" -ForegroundColor Yellow
    }
} else {
    Write-Host "  EZ Tools: Available" -ForegroundColor Green
}

# ── Ghidra ──
if ($Full -or $Ghidra) {
    $ghidraDir = Get-ChildItem -Path $ToolsDir -Directory -Filter "ghidra_*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ghidraDir) {
        $ghidraDir = Get-ChildItem -Path "C:\Tools","D:\Tools","$env:USERPROFILE\Desktop" -Directory -Filter "ghidra_*" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($ghidraDir) {
        Write-Host "  Ghidra: Found $($ghidraDir.FullName)" -ForegroundColor Green
        Add-Content $envFile "FORENSIC_GHIDRA_INSTALL_DIR=$($ghidraDir.FullName)"
    } else {
        Write-Host "  Ghidra: Not found. Download from https://ghidra-sre.org/" -ForegroundColor Yellow
        Write-Host "         Requires JDK 21+: winget install Microsoft.OpenJDK.21" -ForegroundColor Gray
    }
}

# ── Hayabusa ──
$hayabusaPath = Get-ChildItem -Path $ToolsDir -Recurse -Filter "hayabusa*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $hayabusaPath) {
    $hayabusaPath = Get-Command hayabusa -ErrorAction SilentlyContinue
}
if ($hayabusaPath) {
    Write-Host "  Hayabusa: Found" -ForegroundColor Green
} else {
    Write-Host "  Hayabusa: Downloading latest release..." -ForegroundColor Gray
    try {
        $hayaDir = Join-Path $ToolsDir "hayabusa"
        New-Item -ItemType Directory -Path $hayaDir -Force | Out-Null
        $hayaRelease = Invoke-RestMethod "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
        $hayaAsset = $hayaRelease.assets | Where-Object { $_.name -match "win-x64.*zip$" } | Select-Object -First 1
        if ($hayaAsset) {
            $hayaZip = Join-Path $env:TEMP "hayabusa.zip"
            Invoke-WebRequest -Uri $hayaAsset.browser_download_url -OutFile $hayaZip -UseBasicParsing
            Expand-Archive -Path $hayaZip -DestinationPath $hayaDir -Force
            Remove-Item $hayaZip -Force
            Write-Host "  Hayabusa: Downloaded to $hayaDir" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Hayabusa: Download failed. Get from https://github.com/Yamato-Security/hayabusa/releases" -ForegroundColor Yellow
    }
}

# ── Write .env with detected paths ──
Write-Host "  Scanning for tool paths..." -ForegroundColor Gray
$scanDirs = @($ToolsDir, "C:\Tools", "D:\Tools", "E:\kape")
foreach ($scanDir in $scanDirs) {
    if (-not (Test-Path $scanDir)) { continue }
    $kape = Get-ChildItem -Path $scanDir -Recurse -Filter "kape.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($kape) {
        $existing = Get-Content $envFile -ErrorAction SilentlyContinue
        if ($existing -notmatch "FORENSIC_KAPE_PATH") {
            Add-Content $envFile "FORENSIC_KAPE_PATH=$($kape.FullName)"
            Write-Host "  .env: KAPE=$($kape.FullName)" -ForegroundColor Gray
        }
    }
    $hayabusa = Get-ChildItem -Path $scanDir -Recurse -Filter "hayabusa.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hayabusa) {
        $existing = Get-Content $envFile -ErrorAction SilentlyContinue
        if ($existing -notmatch "FORENSIC_HAYABUSA_PATH") {
            Add-Content $envFile "FORENSIC_HAYABUSA_PATH=$($hayabusa.FullName)"
            Write-Host "  .env: Hayabusa=$($hayabusa.FullName)" -ForegroundColor Gray
        }
    }
}

# ── 5. Create start script ──
Write-Host "[5/7] Creating start script..." -ForegroundColor Yellow
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

# ── 6. Register MCP for Claude Code ──
Write-Host "[6/7] Registering MCP server for Claude Code..." -ForegroundColor Yellow
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

# ── 7. Verify ──
Write-Host "[7/7] Verifying..." -ForegroundColor Yellow
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
