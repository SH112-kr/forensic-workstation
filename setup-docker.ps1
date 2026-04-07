# Forensic Workstation — Docker Setup
# Builds container, starts it, and registers MCP for Claude Code
#
# Usage: powershell -ExecutionPolicy Bypass -File setup-docker.ps1

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Forensic Workstation (Docker)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Check Docker ──
Write-Host "[1/4] Checking Docker..." -ForegroundColor Yellow
try {
    $dockerVer = docker --version 2>&1
    Write-Host "  $dockerVer" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Docker not found. Install from https://docker.com/get-started" -ForegroundColor Red
    exit 1
}

# ── 2. Build & Start ──
Write-Host "[2/4] Building and starting container..." -ForegroundColor Yellow
Write-Host "  This may take 3-5 minutes on first run." -ForegroundColor Gray
Push-Location $ProjectDir
docker compose up --build -d 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
Pop-Location

# Wait for container to be healthy
Write-Host "  Waiting for server..." -ForegroundColor Gray
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $health = Invoke-RestMethod "http://localhost:8001/api/health" -TimeoutSec 2
        if ($health.status -eq "ok") { $ready = $true; break }
    } catch {}
}
if ($ready) {
    Write-Host "  Server ready at http://localhost:8001" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Server may still be starting. Check: docker logs forensic-workstation" -ForegroundColor Yellow
}

# ── 3. Register MCP for Claude Code ──
Write-Host "[3/4] Registering MCP server for Claude Code..." -ForegroundColor Yellow
$claudeSettingsPath = Join-Path $env:USERPROFILE ".claude\settings.json"
$claudeDir = Split-Path $claudeSettingsPath -Parent

if (-not (Test-Path $claudeDir)) {
    New-Item -ItemType Directory -Path $claudeDir -Force | Out-Null
}

$mcpConfig = @{
    command = "docker"
    args = @("exec", "-i", "forensic-workstation", "python", "backend/mcp_bridge.py")
    env = @{}
}

if (Test-Path $claudeSettingsPath) {
    try {
        $settings = Get-Content $claudeSettingsPath -Raw | ConvertFrom-Json
        if (-not $settings.mcpServers) {
            $settings | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue @{} -Force
        }
        $settings.mcpServers | Add-Member -NotePropertyName "forensic-workstation" -NotePropertyValue $mcpConfig -Force
        $settings | ConvertTo-Json -Depth 10 | Set-Content $claudeSettingsPath -Encoding UTF8
        Write-Host "  MCP registered in existing settings.json" -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: Could not update settings.json: $_" -ForegroundColor Yellow
    }
} else {
    $newSettings = @{ mcpServers = @{ "forensic-workstation" = $mcpConfig } }
    $newSettings | ConvertTo-Json -Depth 10 | Set-Content $claudeSettingsPath -Encoding UTF8
    Write-Host "  MCP registered (new settings.json created)" -ForegroundColor Green
}

# ── 4. KAPE check ──
Write-Host "[4/4] Checking KAPE..." -ForegroundColor Yellow
$kapePath = $null
Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object {
    if (-not $kapePath) {
        $kapePath = Get-ChildItem -Path (Join-Path $_.Root "Tools"), (Join-Path $_.Root "KAPE"), (Join-Path $_.Root "kape") -Recurse -Filter "kape.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
}
if (-not $kapePath) {
    $kapePath = Get-ChildItem -Path "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads" -Recurse -Filter "kape.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
}

if ($kapePath) {
    $kapeDir = $kapePath.Directory.FullName
    Write-Host "  KAPE found: $($kapePath.FullName)" -ForegroundColor Green

    # Deploy custom Targets & Modules
    $customDir = Join-Path $ProjectDir "kape_custom"
    if (Test-Path $customDir) {
        Copy-Item -Path (Join-Path $customDir "Targets\*") -Destination (Join-Path $kapeDir "Targets") -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -Path (Join-Path $customDir "Modules\*") -Destination (Join-Path $kapeDir "Modules") -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Custom Targets/Modules deployed" -ForegroundColor Green
    }

    # Fix runtimeconfig.json
    $binDir = Join-Path $kapeDir "Modules\bin"
    if (Test-Path $binDir) {
        $fixed = 0
        foreach ($tool in @("PECmd","LECmd","JLECmd","SBECmd","RBCmd","WxTCmd","SrumECmd","SumECmd","AmcacheParser","AppCompatCacheParser","MFTECmd","RECmd")) {
            $rootRc = Join-Path $binDir "$tool.runtimeconfig.json"
            $subRc = Join-Path $binDir "$tool\$tool.runtimeconfig.json"
            if ((Test-Path (Join-Path $binDir "$tool.dll")) -and -not (Test-Path $rootRc) -and (Test-Path $subRc)) {
                Copy-Item $subRc $rootRc
                $fixed++
            }
        }
        if ($fixed -gt 0) { Write-Host "  Fixed $fixed runtimeconfig.json files" -ForegroundColor Green }
    }
} else {
    Write-Host "  KAPE not found (optional — only needed for artifact collection)" -ForegroundColor Yellow
    Write-Host "  Download: https://www.kroll.com/kape" -ForegroundColor Gray
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Web UI:      http://localhost:8001" -ForegroundColor White
Write-Host "  Claude Code: Restart to activate MCP tools" -ForegroundColor White
Write-Host "  KAPE:        $(if ($kapePath) { 'Ready' } else { 'Not installed (optional)' })" -ForegroundColor White
Write-Host ""
Write-Host "  Stop:    docker compose down" -ForegroundColor Gray
Write-Host "  Restart: docker compose up -d" -ForegroundColor Gray
Write-Host "  Logs:    docker logs forensic-workstation" -ForegroundColor Gray
Write-Host ""
