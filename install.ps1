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
Write-Host "[2/7] Installing backend dependencies..." -ForegroundColor Yellow
$reqFile = Join-Path $ProjectDir "backend\requirements.txt"
pip install -r $reqFile 2>&1 | Out-Null
Write-Host "  Core: FastAPI, uvicorn, mcp, pydantic" -ForegroundColor Green

if ($Full -or $Memory) {
    pip install volatility3 yara-python regipy 2>&1 | Out-Null
    Write-Host "  Memory: volatility3, yara-python, regipy" -ForegroundColor Green
}
if ($Full -or $Ghidra) {
    pip install pyhidra 2>&1 | Out-Null
    Write-Host "  Ghidra: pyhidra" -ForegroundColor Green
}
if ($Full -or $Network) {
    pip install pyshark 2>&1 | Out-Null
    Write-Host "  Network: pyshark" -ForegroundColor Green
}
if ($Full) {
    pip install volatility3 yara-python regipy pyhidra pyshark 2>&1 | Out-Null
    Write-Host "  Full: All optional packages installed" -ForegroundColor Green
}

# ── 3. Frontend ──
Write-Host "[3/7] Building frontend..." -ForegroundColor Yellow
$distDir = Join-Path $ProjectDir "frontend\dist"
if (Test-Path $distDir) {
    Write-Host "  Pre-built frontend found" -ForegroundColor Green
} else {
    # Check Node.js
    try {
        $nodeVer = node --version 2>&1
        Write-Host "  Node.js: $nodeVer" -ForegroundColor Gray
        Push-Location (Join-Path $ProjectDir "frontend")
        Write-Host "  Installing npm packages..." -ForegroundColor Gray
        npm install 2>&1 | Out-Null
        Write-Host "  Building..." -ForegroundColor Gray
        npm run build 2>&1 | Out-Null
        Pop-Location
        Write-Host "  Frontend built" -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: Node.js not found. Install from https://nodejs.org/" -ForegroundColor Yellow
        Write-Host "  Web UI will not be available until frontend is built." -ForegroundColor Gray
    }
}

# ── 4. External Forensic Tools (auto-download) ──
Write-Host "[4/7] Setting up forensic tools..." -ForegroundColor Yellow

$ToolsDir = Join-Path $ProjectDir "tools"
if (-not (Test-Path $ToolsDir)) { New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null }

# .env file for tool paths
$envFile = Join-Path $ProjectDir "backend\.env"

# ── KAPE ──
$kapePath = Get-ChildItem -Path $ToolsDir -Recurse -Filter "kape.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $kapePath) {
    # Also scan common locations
    foreach ($scanPath in @("C:\Tools", "D:\Tools", "E:\kape", "$env:USERPROFILE\Desktop")) {
        $kapePath = Get-ChildItem -Path $scanPath -Recurse -Filter "kape.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($kapePath) { break }
    }
}
if ($kapePath) {
    $kapeDir = Split-Path (Split-Path $kapePath.FullName -Parent) -Parent
    if ($kapePath.Directory.Name -eq "KAPE") { $kapeDir = $kapePath.Directory.FullName }
    else { $kapeDir = $kapePath.Directory.FullName }
    Write-Host "  KAPE: Found $($kapePath.FullName)" -ForegroundColor Green

    # Deploy custom Targets & Modules
    $customDir = Join-Path $ProjectDir "kape_custom"
    if (Test-Path $customDir) {
        Write-Host "  KAPE: Deploying custom Targets & Modules..." -ForegroundColor Gray
        # Copy custom targets
        $customTargets = Join-Path $customDir "Targets"
        if (Test-Path $customTargets) {
            Copy-Item -Path "$customTargets\*" -Destination (Join-Path $kapeDir "Targets") -Recurse -Force
            Write-Host "    Targets: ForensicWorkstation.tkape, OpenSSHServer.tkape" -ForegroundColor Green
        }
        # Copy custom modules
        $customModules = Join-Path $customDir "Modules"
        if (Test-Path $customModules) {
            Copy-Item -Path "$customModules\*" -Destination (Join-Path $kapeDir "Modules") -Recurse -Force
            Write-Host "    Modules: RECmd_Kroll.mkape" -ForegroundColor Green
        }
    }
} else {
    Write-Host "  KAPE: Not found. Download from https://www.kroll.com/kape" -ForegroundColor Yellow
    Write-Host "         Extract to: $ToolsDir\KAPE\ then re-run install.ps1" -ForegroundColor Gray
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

# ── JDK (required for Ghidra) ──
if ($Full -or $Ghidra) {
    $javaVer = java -version 2>&1 | Select-String "version" | Select-Object -First 1
    if ($javaVer) {
        Write-Host "  JDK: $javaVer" -ForegroundColor Green
    } else {
        Write-Host "  JDK: Not found. Installing OpenJDK 21..." -ForegroundColor Gray
        try {
            winget install Microsoft.OpenJDK.21 --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
            Write-Host "  JDK 21: Installed via winget" -ForegroundColor Green
        } catch {
            Write-Host "  JDK: winget install failed. Download from https://adoptium.net/" -ForegroundColor Yellow
        }
    }
}

# ── Ghidra ──
if ($Full -or $Ghidra) {
    $ghidraDir = Get-ChildItem -Path $ToolsDir -Directory -Filter "ghidra_*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ghidraDir) {
        $ghidraDir = Get-ChildItem -Path "C:\Tools","D:\Tools","$env:USERPROFILE\Desktop" -Directory -Filter "ghidra_*" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($ghidraDir) {
        Write-Host "  Ghidra: Found $($ghidraDir.FullName)" -ForegroundColor Green
    } else {
        Write-Host "  Ghidra: Downloading latest release..." -ForegroundColor Gray
        try {
            $ghidraRelease = Invoke-RestMethod "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
            $ghidraAsset = $ghidraRelease.assets | Where-Object { $_.name -match "ghidra.*\.zip$" -and $_.name -notmatch "src" } | Select-Object -First 1
            if ($ghidraAsset) {
                $ghidraZip = Join-Path $env:TEMP "ghidra.zip"
                Write-Host "  Ghidra: Downloading $($ghidraAsset.name) ..." -ForegroundColor Gray
                Invoke-WebRequest -Uri $ghidraAsset.browser_download_url -OutFile $ghidraZip -UseBasicParsing
                Expand-Archive -Path $ghidraZip -DestinationPath $ToolsDir -Force
                Remove-Item $ghidraZip -Force
                $ghidraDir = Get-ChildItem -Path $ToolsDir -Directory -Filter "ghidra_*" | Select-Object -First 1
                Write-Host "  Ghidra: Downloaded to $($ghidraDir.FullName)" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Ghidra: Download failed. Get from https://github.com/NationalSecurityAgency/ghidra/releases" -ForegroundColor Yellow
        }
    }
    if ($ghidraDir) {
        $existing = Get-Content $envFile -ErrorAction SilentlyContinue
        if ($existing -notmatch "FORENSIC_GHIDRA_INSTALL_DIR") {
            Add-Content $envFile "FORENSIC_GHIDRA_INSTALL_DIR=$($ghidraDir.FullName)"
        }
    }
}

# ── Wireshark (required for pyshark/Network analysis) ──
if ($Full -or $Network) {
    $wsPath = Get-Command tshark -ErrorAction SilentlyContinue
    if ($wsPath) {
        Write-Host "  Wireshark: Found (tshark)" -ForegroundColor Green
    } else {
        Write-Host "  Wireshark: Installing..." -ForegroundColor Gray
        try {
            winget install WiresharkFoundation.Wireshark --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
            Write-Host "  Wireshark: Installed via winget" -ForegroundColor Green
        } catch {
            Write-Host "  Wireshark: winget failed. Download from https://www.wireshark.org/" -ForegroundColor Yellow
        }
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

# ── KAPE Health Check: runtimeconfig.json + broken smaps ──
if ($kapePath) {
    $binDir = Join-Path $kapeDir "Modules\bin"
    if (Test-Path $binDir) {
        # Fix missing runtimeconfig.json (EZ tools fail without it)
        $ezTools = @("PECmd","LECmd","JLECmd","SBECmd","RBCmd","WxTCmd","SrumECmd","SumECmd","AmcacheParser","AppCompatCacheParser","MFTECmd","RECmd")
        $fixed = 0
        foreach ($tool in $ezTools) {
            $rootRc = Join-Path $binDir "$tool.runtimeconfig.json"
            $subRc = Join-Path $binDir "$tool\$tool.runtimeconfig.json"
            if ((Test-Path (Join-Path $binDir "$tool.dll")) -and -not (Test-Path $rootRc) -and (Test-Path $subRc)) {
                Copy-Item $subRc $rootRc
                $fixed++
            }
        }
        if ($fixed -gt 0) {
            Write-Host "  KAPE Health: Fixed $fixed missing runtimeconfig.json files" -ForegroundColor Green
        } else {
            Write-Host "  KAPE Health: All EZ tools OK" -ForegroundColor Green
        }

        # Fix broken SQLECmd smap files (BlobColumns property error)
        $smapDir = Join-Path $binDir "SQLECmd\Maps"
        if (Test-Path $smapDir) {
            $brokenSmaps = @("TestFiles_BlobTest.smap","TestFiles_BlobTest_Three.smap","TestFiles_BlobTest_Two.smap","Windows_EdgeBrowser_HistoryScreenshots.smap")
            $disabledDir = Join-Path $smapDir "_disabled"
            $smapFixed = 0
            foreach ($smap in $brokenSmaps) {
                $smapPath = Join-Path $smapDir $smap
                if (Test-Path $smapPath) {
                    if (-not (Test-Path $disabledDir)) { New-Item -ItemType Directory -Path $disabledDir -Force | Out-Null }
                    Move-Item $smapPath (Join-Path $disabledDir $smap) -Force
                    $smapFixed++
                }
            }
            if ($smapFixed -gt 0) {
                Write-Host "  KAPE Health: Disabled $smapFixed broken SQLECmd smap files" -ForegroundColor Green
            }
        }
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
