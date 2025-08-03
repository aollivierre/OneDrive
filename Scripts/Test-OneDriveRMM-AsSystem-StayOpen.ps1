#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Tests OneDrive scripts as SYSTEM with windows that ACTUALLY stay open
.DESCRIPTION
    Based on the Win11 Detection example that works correctly
#>

param(
    [switch]$DetectionOnly,
    [switch]$RemediationOnly,
    [switch]$NoDebug  # Add this switch to test production mode
)

Write-Host "`n=== Testing OneDrive Scripts as SYSTEM (Interactive Windows) ===" -ForegroundColor Cyan
if ($NoDebug) {
    Write-Host "Running in PRODUCTION MODE (No Debug) - Simulates RMM execution" -ForegroundColor Yellow
} else {
    Write-Host "Running in DEBUG MODE - Full verbose output" -ForegroundColor Green
}
Write-Host "This will open new PowerShell windows running as SYSTEM`n" -ForegroundColor Gray

# Download PSExec if not present
$psExecPath = "C:\Temp\PSExec64.exe"
if (-not (Test-Path $psExecPath)) {
    Write-Host "Downloading PSExec..." -ForegroundColor Yellow
    New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
    Invoke-WebRequest 'https://live.sysinternals.com/PsExec64.exe' -OutFile $psExecPath
}

# Script paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Use the SINGLE detection script (no more versions!)
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM.ps1"
$remediationScript = Join-Path $scriptPath "Remediate-OneDriveConfiguration-RMM.ps1"

function Test-ScriptAsSystem {
    param(
        [string]$ScriptToTest,
        [string]$TestType
    )
    
    Write-Host "`n--- Testing $TestType Script ---" -ForegroundColor Yellow
    
    # Create wrapper script that will pause after execution
    $wrapperScript = @"
Write-Host '=== Running as SYSTEM ===' -ForegroundColor Green

# Set debug mode based on parameter
`$global:EnableDebug = $(if ($NoDebug) { '$false' } else { '$true' })

# Use proper user detection
`$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if (`$currentUser.Name -eq "NT AUTHORITY\SYSTEM") {
    Write-Host "Current User: LocalSystem (SYSTEM context)" -ForegroundColor Yellow
} else {
    Write-Host "Current User: `$(`$currentUser.Name)" -ForegroundColor Yellow
}

Write-Host "Computer: `$env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Script Type: $TestType" -ForegroundColor Yellow
Write-Host "Time: `$(Get-Date)" -ForegroundColor Yellow
Write-Host ("-" * 70) -ForegroundColor Gray
Write-Host ""

# Run the actual script
if (`$global:EnableDebug) {
    Write-Host "Running $TestType script WITH DEBUG LOGGING..." -ForegroundColor Cyan
    Write-Host "Debug mode enabled globally: `$(`$global:EnableDebug)" -ForegroundColor Gray
    & '$ScriptToTest' -EnableDebug
} else {
    Write-Host "Running $TestType script in PRODUCTION MODE (No Debug)..." -ForegroundColor Yellow
    Write-Host "Only RMM-formatted output will be shown" -ForegroundColor Gray
    & '$ScriptToTest'
}
try {
    `$exitCode = `$LASTEXITCODE
    if (`$null -eq `$exitCode) { `$exitCode = 0 }
    
    Write-Host "`n`n=== COMPLETED ===" -ForegroundColor Green
    if (`$exitCode -eq 0) {
        Write-Host "Exit Code: `$exitCode" -ForegroundColor Green
    } else {
        Write-Host "Exit Code: `$exitCode" -ForegroundColor Yellow
    }
    
    if (`$exitCode -eq 0) {
        Write-Host "Status: SUCCESS - No remediation needed" -ForegroundColor Green
    } elseif (`$exitCode -eq 1) {
        Write-Host "Status: REMEDIATION REQUIRED" -ForegroundColor Yellow
    } else {
        Write-Host "Status: ERROR" -ForegroundColor Red
    }
} catch {
    Write-Host "`n`nERROR: `$_" -ForegroundColor Red
    Write-Host "Stack Trace:`n`$(`$_.ScriptStackTrace)" -ForegroundColor Red
    `$exitCode = 999
}

Write-Host "`n`nScript completed. Press any key to close this window..." -ForegroundColor Yellow
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@
    
    # Save wrapper script
    $wrapperPath = "C:\Temp\OneDrive-$TestType-SystemWrapper.ps1"
    $wrapperScript | Out-File -FilePath $wrapperPath -Encoding UTF8
    
    # PSExec arguments for interactive SYSTEM execution
    $psexecArgs = @(
        "-accepteula",      # Accept EULA silently
        "-s",               # Run as SYSTEM
        "-i",               # Interactive in current session (shows window)
        "-d",               # Don't wait for process to terminate
        "powershell.exe",   # Run PowerShell
        "-ExecutionPolicy", "Bypass",
        "-File", $wrapperPath
    )
    
    Write-Host "Launching SYSTEM PowerShell window for $TestType..." -ForegroundColor Green
    
    # Execute as SYSTEM in new window
    & $psExecPath @psexecArgs
    
    Write-Host "A new PowerShell window should have opened running as SYSTEM." -ForegroundColor Green
    Write-Host "Check that window for the script output." -ForegroundColor Yellow
}

# Main execution
Write-Host "Current user: $env:USERNAME" -ForegroundColor Yellow

if (-not $RemediationOnly) {
    Test-ScriptAsSystem -ScriptToTest $detectionScript -TestType "Detection"
    
    if (-not $DetectionOnly) {
        Write-Host "`nPress Enter when ready to test Remediation script..." -ForegroundColor Cyan
        Read-Host
    }
}

if (-not $DetectionOnly) {
    Test-ScriptAsSystem -ScriptToTest $remediationScript -TestType "Remediation"
    
    Write-Host "`nPress Enter when ready to run Detection again for verification..." -ForegroundColor Cyan
    Read-Host
    
    Test-ScriptAsSystem -ScriptToTest $detectionScript -TestType "Verification"
}

Write-Host "`n=== All Tests Launched ===" -ForegroundColor Green
Write-Host "Check the SYSTEM windows for results." -ForegroundColor Yellow
Write-Host "Each window will stay open until you press a key in it." -ForegroundColor Gray

# Show log locations
Write-Host "`n=== Log Locations ===" -ForegroundColor Cyan
$tempLogs = Get-ChildItem -Path $env:TEMP -Filter "OneDrive-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
if ($tempLogs) {
    Write-Host "Recent OneDrive logs:"
    foreach ($log in $tempLogs) {
        Write-Host "  $($log.Name) - $('{0:N2} KB' -f ($log.Length/1KB))" -ForegroundColor Gray
    }
}