#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Tests OneDrive detection and remediation scripts under SYSTEM context
.DESCRIPTION
    Wrapper script that runs detection and remediation scripts as SYSTEM
    to mimic RMM behavior for testing purposes
.EXAMPLE
    .\Test-OneDriveRMM-AsSystem.ps1
    .\Test-OneDriveRMM-AsSystem.ps1 -SkipRemediation
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
    
    # Create temporary directory
    $tempDir = "C:\Temp\OneDriveRMM-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    # Copy script to temp location (psexec sometimes has path issues)
    $tempScript = Join-Path $tempDir (Split-Path -Leaf $ScriptPath)
    Copy-Item -Path $ScriptPath -Destination $tempScript -Force
    
    # Output file for capturing results
    $outputFile = Join-Path $tempDir "output.txt"
    
    # Run as SYSTEM using psexec
    $psexecArgs = @(
        "-accepteula",
        "-s",           # Run as SYSTEM
        "-i",           # Interactive (allows console output)
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$tempScript`""
    )
    
    Write-Host "Running as SYSTEM..."
    $process = Start-Process -FilePath "psexec.exe" -ArgumentList $psexecArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $outputFile
    
    # Display output
    if (Test-Path $outputFile) {
        $output = Get-Content -Path $outputFile -Raw
        Write-Host $output
    }
    
    # Get exit code
    Write-Host "`nExit Code: $($process.ExitCode)" -ForegroundColor $(if ($process.ExitCode -eq 0) { "Green" } else { "Red" })
    
    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    
    return $process.ExitCode
}

# Run detection
Write-Host "`n" -ForegroundColor White
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
    Write-Host "`n" -ForegroundColor White
    $remediationExitCode = Invoke-AsSystem -ScriptPath $remediationScript -Description "RUNNING REMEDIATION SCRIPT"
    
    # Run detection again to verify
    Write-Host "`n" -ForegroundColor White
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