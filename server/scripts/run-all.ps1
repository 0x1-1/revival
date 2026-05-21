# run-all.ps1 -- starts all three servers in background jobs
# Patch + launcher-web on port 80 each cannot coexist; we run patch on :80 and
# launcher-web on :8080 by default. Adjust if you proxy through a reverse-proxy.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
Set-Location $root

# Build first
Write-Host "Building..." -ForegroundColor Cyan
go build -o bin/patch-server.exe ./cmd/patch-server
go build -o bin/launcher-web.exe ./cmd/launcher-web
go build -o bin/login-server.exe ./cmd/login-server
Write-Host "Build OK" -ForegroundColor Green

# Kill any prior instances
Get-Process -Name 'patch-server','launcher-web','login-server' -ErrorAction SilentlyContinue | Stop-Process -Force

# Start each in background
$patch    = Start-Process -FilePath ".\bin\patch-server.exe"    -ArgumentList '-addr',':80' -PassThru -WindowStyle Minimized
$launcher = Start-Process -FilePath ".\bin\launcher-web.exe"    -ArgumentList '-addr',':8080','-root','web/launcher' -PassThru -WindowStyle Minimized
$login    = Start-Process -FilePath ".\bin\login-server.exe"    -PassThru -WindowStyle Minimized

Start-Sleep 2
Write-Host ""
Write-Host "=== STARTED ===" -ForegroundColor Green
Write-Host "patch-server    PID=$($patch.Id)"
Write-Host "launcher-web    PID=$($launcher.Id)"
Write-Host "login-server    PID=$($login.Id)"
Write-Host ""
Write-Host "Logs: $root\logs\"
Write-Host "Tail any log live: Get-Content logs\login-server.log -Wait"
