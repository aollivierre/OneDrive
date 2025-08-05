#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Final working SYSTEM test for OneDrive RMM scripts
.DESCRIPTION
    Runs detection and remediation scripts as SYSTEM with windows that stay open
#>

param(
    [switch]$SkipRemediation,
    [switch]$ForceRemediation
)

Write-Host "`nOneDrive RMM Scripts - SYSTEM Context Test" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "This script must be run as Administrator"
}

# Check/Download PSExec
$psExecPath = "C:\Temp\PSExec64.exe"
if (-not (Test-Path $psExecPath)) {
    Write-Host "`nDownloading PSExec..." -ForegroundColor Yellow
    New-Item -Path "C:\Temp" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Invoke-WebRequest 'https://live.sysinternals.com/PsExec64.exe' -OutFile $psExecPath -UseBasicParsing
    Write-Host "PSExec downloaded successfully" -ForegroundColor Green
}

# Paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM-v3.ps1"
$remediationScript = Join-Path $scriptPath "Remediate-OneDriveConfiguration-RMM-v2.ps1"

# Use v4 if available
$v4Detection = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM-v4-SystemAware.ps1"
if (Test-Path $v4Detection) {
    Write-Host "Using v4 SYSTEM-aware detection script" -ForegroundColor Yellow
    $detectionScript = $v4Detection
}

# Verify scripts exist
if (!(Test-Path $detectionScript)) {
    throw "Detection script not found: $detectionScript"
}
if (!(Test-Path $remediationScript)) {
    throw "Remediation script not found: $remediationScript"
}

Write-Host "`nScript paths:" -ForegroundColor Yellow
Write-Host "  Detection:   $(Split-Path -Leaf $detectionScript)" -ForegroundColor Gray
Write-Host "  Remediation: $(Split-Path -Leaf $remediationScript)" -ForegroundColor Gray

# Function to run script as SYSTEM with interactive window
function Invoke-AsSystemInteractive {
    param(
        [string]$ScriptPath,
        [string]$Description,
        [string]$TaskType
    )
    
    Write-Host "`n$Description" -ForegroundColor Green
    Write-Host ("-" * 70) -ForegroundColor DarkGray
    
    # Create wrapper that shows context and pauses
    $wrapper = @"
@echo off
cls
echo ===============================================
echo Running as SYSTEM - $TaskType
echo ===============================================
echo.
echo Current User: %USERNAME%
echo Computer: %COMPUTERNAME%
echo Time: %DATE% %TIME%
echo ===============================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'Starting PowerShell...' -ForegroundColor Yellow; & '$ScriptPath'; Write-Host '`nExit Code:' `$LASTEXITCODE -ForegroundColor Cyan; pause"
"@
    
    $wrapperPath = "C:\Temp\$TaskType-wrapper.bat"
    $wrapper | Out-File -FilePath $wrapperPath -Encoding ASCII -Force
    
    Write-Host "Launching SYSTEM window..." -ForegroundColor Yellow
    Write-Host "Look for new command window!" -ForegroundColor Magenta
    
    # Run with PSExec in new window
    Start-Process -FilePath $psExecPath -ArgumentList @(
        "-accepteula",
        "-s",               # Run as SYSTEM
        "-i",               # Interactive
        "-d",               # Don't wait
        "cmd.exe",
        "/k",               # Keep window open
        $wrapperPath
    )
    
    # Give user time to see the window
    Write-Host "`nA new window should have opened running as SYSTEM." -ForegroundColor Green
    Write-Host "Check that window for output. The window will stay open." -ForegroundColor Yellow
    
    # Wait for user to check results
    Write-Host "`nAfter checking the results in the SYSTEM window, press Enter to continue..." -ForegroundColor Cyan
    Read-Host
    
    # Ask for exit code
    $exitCode = Read-Host "What was the exit code shown in the SYSTEM window? (0=success, 1=needs remediation)"
    
    return [int]$exitCode
}

try {
    # Run detection
    $detectionExitCode = Invoke-AsSystemInteractive `
        -ScriptPath $detectionScript `
        -Description "STEP 1: RUNNING DETECTION SCRIPT" `
        -TaskType "Detection"
    
    # Check if remediation is needed
    if ($detectionExitCode -eq 0) {
        Write-Host "`nDetection shows NO REMEDIATION NEEDED!" -ForegroundColor Green
        $needsRemediation = $false
    } else {
        Write-Host "`nDetection shows REMEDIATION IS NEEDED!" -ForegroundColor Yellow
        $needsRemediation = $true
    }
    
    # Run remediation if needed
    if (($needsRemediation -or $ForceRemediation) -and -not $SkipRemediation) {
        
        Write-Host "`nPress Enter to continue with remediation..." -ForegroundColor Yellow
        Read-Host
        
        $remediationExitCode = Invoke-AsSystemInteractive `
            -ScriptPath $remediationScript `
            -Description "STEP 2: RUNNING REMEDIATION SCRIPT" `
            -TaskType "Remediation"
        
        Write-Host "`nPress Enter to run verification..." -ForegroundColor Yellow
        Read-Host
        
        # Run detection again to verify
        $verifyExitCode = Invoke-AsSystemInteractive `
            -ScriptPath $detectionScript `
            -Description "STEP 3: RUNNING DETECTION AGAIN TO VERIFY" `
            -TaskType "Verification"
        
        if ($verifyExitCode -eq 0) {
            Write-Host "`nVERIFICATION: Remediation was SUCCESSFUL!" -ForegroundColor Green
        } else {
            Write-Host "`nVERIFICATION: Remediation may require user login or additional steps" -ForegroundColor Yellow
        }
    } elseif ($SkipRemediation) {
        Write-Host "`nSkipping remediation as requested" -ForegroundColor Gray
    }
}
catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

# Show logs
Write-Host "`n=== LOG FILES ===" -ForegroundColor Cyan
$recentLogs = Get-ChildItem -Path $env:TEMP -Filter "OneDrive-*.log" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 3

if ($recentLogs) {
    Write-Host "Recent OneDrive logs:" -ForegroundColor Gray
    foreach ($log in $recentLogs) {
        Write-Host "  $($log.Name) - $($log.LastWriteTime)" -ForegroundColor Gray
    }
}

Write-Host "`nTest completed!" -ForegroundColor Green
Write-Host "The SYSTEM windows should still be open for review." -ForegroundColor Yellow