# Quick Test Script for KernelEye
# Run as Administrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  KernelEye Quick Test Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

# Check test signing
Write-Host "[CHECK] Verifying test signing mode..." -ForegroundColor Yellow
$testSigning = bcdedit /enum "{current}" | Select-String "testsigning"
if ($testSigning -match "Yes") {
    Write-Host "[PASS] Test signing is enabled" -ForegroundColor Green
} else {
    Write-Host "[WARN] Test signing is NOT enabled!" -ForegroundColor Red
    Write-Host "Run: bcdedit /set testsigning on" -ForegroundColor Yellow
    Write-Host "Then reboot your system" -ForegroundColor Yellow
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne "y") { exit 1 }
}

Write-Host ""

# Navigate to bin directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$binPath = Join-Path $scriptPath "bin\x64\Debug"

if (-not (Test-Path $binPath)) {
    Write-Host "[ERROR] Build output not found: $binPath" -ForegroundColor Red
    Write-Host "Please build the solution first (Debug|x64)" -ForegroundColor Yellow
    pause
    exit 1
}

Set-Location $binPath
Write-Host "[INFO] Working directory: $binPath" -ForegroundColor Cyan
Write-Host ""

# Check if driver file exists
if (-not (Test-Path "KernelEye.sys")) {
    Write-Host "[ERROR] KernelEye.sys not found!" -ForegroundColor Red
    Write-Host "Build the solution first" -ForegroundColor Yellow
    pause
    exit 1
}

# Check if service is already running
$service = Get-Service -Name "KernelEye" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "[INFO] Service already exists. Status: $($service.Status)" -ForegroundColor Yellow
    if ($service.Status -eq "Running") {
        Write-Host "[INFO] Stopping existing service..." -ForegroundColor Yellow
        sc.exe stop KernelEye | Out-Null
        Start-Sleep -Seconds 2
    }
    Write-Host "[INFO] Removing existing service..." -ForegroundColor Yellow
    sc.exe delete KernelEye | Out-Null
    Start-Sleep -Seconds 1
}

# Create service
Write-Host "[STEP] Creating driver service..." -ForegroundColor Cyan
$driverPath = Join-Path $binPath "KernelEye.sys"
$result = sc.exe create KernelEye type= kernel binPath= $driverPath 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to create service!" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
    pause
    exit 1
}
Write-Host "[PASS] Service created successfully" -ForegroundColor Green
Write-Host ""

# Start service
Write-Host "[STEP] Starting driver..." -ForegroundColor Cyan
$result = sc.exe start KernelEye 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to start driver!" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
    Write-Host ""
    Write-Host "Common causes:" -ForegroundColor Yellow
    Write-Host "  - Test signing not enabled (bcdedit /set testsigning on)" -ForegroundColor Yellow
    Write-Host "  - Driver incompatible with Windows version" -ForegroundColor Yellow
    Write-Host "  - Driver already loaded" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[PASS] Driver started successfully" -ForegroundColor Green
Start-Sleep -Seconds 1
Write-Host ""

# Run test utility if available
if (Test-Path "MemoryScanTest.exe") {
    Write-Host "[STEP] Running memory scan test..." -ForegroundColor Cyan
    Write-Host ""
    & ".\MemoryScanTest.exe"
} else {
    Write-Host "[WARN] MemoryScanTest.exe not found" -ForegroundColor Yellow
    Write-Host "[INFO] Starting service instead..." -ForegroundColor Cyan
    Write-Host ""
    
    if (Test-Path "KernelEyeService.exe") {
        Write-Host "Press Ctrl+C to stop the service" -ForegroundColor Yellow
        Write-Host ""
        & ".\KernelEyeService.exe"
    } else {
        Write-Host "[ERROR] KernelEyeService.exe not found!" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[INFO] Cleaning up..." -ForegroundColor Cyan

# Stop and remove driver
sc.exe stop KernelEye | Out-Null
Start-Sleep -Seconds 1
sc.exe delete KernelEye | Out-Null

Write-Host "[DONE] Test complete" -ForegroundColor Green
Write-Host ""
