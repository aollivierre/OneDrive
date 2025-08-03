#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Simple SYSTEM test for OneDrive RMM scripts using psexec
.DESCRIPTION
    Runs detection and remediation scripts as SYSTEM with real-time output
.EXAMPLE
    .\Test-OneDriveRMM-AsSystem-Simple.ps1
#>

param(
    [switch]$SkipRemediation,
    [switch]$ForceRemediation
)

Write-Host "OneDrive RMM Scripts - SYSTEM Context Test" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "This script must be run as Administrator"
}

# Check if psexec exists
$psexec = Get-Command psexec.exe -ErrorAction SilentlyContinue
if (-not $psexec) {
    Write-Host "`nERROR: psexec.exe not found in PATH" -ForegroundColor Red
    Write-Host "Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/psexec" -ForegroundColor Yellow
    return
}

# Paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM-v3.ps1"
$remediationScript = Join-Path $scriptPath "Remediate-OneDriveConfiguration-RMM-v2.ps1"

# Verify scripts exist
if (!(Test-Path $detectionScript)) {
    throw "Detection script not found: $detectionScript"
}
if (!(Test-Path $remediationScript)) {
    throw "Remediation script not found: $remediationScript"
}

Write-Host "`nScript paths:" -ForegroundColor Yellow
Write-Host "Detection:    $detectionScript"
Write-Host "Remediation:  $remediationScript"

# Function to run script as SYSTEM
function Invoke-AsSystem {
    param(
        [string]$ScriptPath,
        [string]$Description
    )
    
    Write-Host "`n$Description" -ForegroundColor Green
    Write-Host ("-" * 50)
    Write-Host "Running as SYSTEM..." -ForegroundColor Yellow
    
    # Run with psexec and capture exit code
    & psexec.exe -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ScriptPath"
    $exitCode = $LASTEXITCODE
    
    Write-Host "`nExit Code: $exitCode" -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })
    
    return $exitCode
}

# Run detection
$detectionExitCode = Invoke-AsSystem -ScriptPath $detectionScript -Description "RUNNING DETECTION SCRIPT"

# Check if remediation is needed
$needsRemediation = $detectionExitCode -ne 0

if ($needsRemediation) {
    Write-Host "`nDetection indicates REMEDIATION NEEDED" -ForegroundColor Yellow
} else {
    Write-Host "`nDetection indicates NO REMEDIATION NEEDED" -ForegroundColor Green
}

# Run remediation if needed or forced
if (($needsRemediation -or $ForceRemediation) -and -not $SkipRemediation) {
    $remediationExitCode = Invoke-AsSystem -ScriptPath $remediationScript -Description "RUNNING REMEDIATION SCRIPT"
    
    # Run detection again to verify
    $verifyExitCode = Invoke-AsSystem -ScriptPath $detectionScript -Description "RUNNING DETECTION AGAIN TO VERIFY"
    
    if ($verifyExitCode -eq 0) {
        Write-Host "`nVERIFICATION: Remediation was SUCCESSFUL" -ForegroundColor Green
    } else {
        Write-Host "`nVERIFICATION: Remediation may require user login or additional steps" -ForegroundColor Yellow
    }
} elseif ($SkipRemediation) {
    Write-Host "`nSkipping remediation as requested" -ForegroundColor Yellow
}

# Display log locations
Write-Host "`n=== LOG FILE LOCATIONS ===" -ForegroundColor Cyan
$tempLogs = Get-ChildItem -Path $env:TEMP -Filter "OneDrive-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
if ($tempLogs) {
    Write-Host "Recent log files:"
    foreach ($log in $tempLogs) {
        Write-Host "  $($log.FullName)"
    }
} else {
    Write-Host "No log files found in: $env:TEMP"
}

Write-Host "`nTest completed!" -ForegroundColor Green