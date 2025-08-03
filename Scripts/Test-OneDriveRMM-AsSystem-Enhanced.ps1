#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enhanced SYSTEM test for OneDrive RMM scripts with comprehensive logging
.DESCRIPTION
    Runs detection and remediation scripts as SYSTEM with:
    - Interactive windows that stay open
    - Comprehensive debug logging
    - Stack trace on errors
.EXAMPLE
    .\Test-OneDriveRMM-AsSystem-Enhanced.ps1
#>

param(
    [switch]$SkipRemediation,
    [switch]$ForceRemediation,
    [string]$LogPath = "C:\Temp\OneDriveRMM-SystemTest-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

#region Logging Functions
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG', 'SUCCESS')]
        [string]$Level = 'INFO',
        [switch]$Console = $true
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $caller = (Get-PSCallStack)[1]
    $lineNumber = $caller.ScriptLineNumber
    $function = $caller.FunctionName
    if ($function -eq '<ScriptBlock>') { $function = 'Main' }
    
    $logEntry = "$timestamp [$Level] [${function}:${lineNumber}] $Message"
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logEntry -Force
    
    # Write to console with color
    if ($Console) {
        $color = switch ($Level) {
            'INFO'    { 'White' }
            'WARNING' { 'Yellow' }
            'ERROR'   { 'Red' }
            'DEBUG'   { 'Gray' }
            'SUCCESS' { 'Green' }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Write-ErrorLog {
    param($ErrorRecord)
    
    Write-LogMessage "ERROR: $($ErrorRecord.Exception.Message)" -Level ERROR
    Write-LogMessage "Stack Trace: $($ErrorRecord.ScriptStackTrace)" -Level ERROR
    Write-LogMessage "At Line: $($ErrorRecord.InvocationInfo.ScriptLineNumber)" -Level ERROR
    Write-LogMessage "In Script: $($ErrorRecord.InvocationInfo.ScriptName)" -Level ERROR
}
#endregion

Write-Host "`nOneDrive RMM Scripts - Enhanced SYSTEM Context Test" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-LogMessage "Starting enhanced SYSTEM test" -Level INFO

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-LogMessage "This script must be run as Administrator" -Level ERROR
    throw "This script must be run as Administrator"
}

# Check/Download PSExec
$psExecPath = "C:\Temp\PSExec64.exe"
if (-not (Test-Path $psExecPath)) {
    Write-LogMessage "PSExec not found, downloading..." -Level WARNING
    try {
        New-Item -Path "C:\Temp" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Write-LogMessage "Downloading PSExec from Sysinternals..." -Level INFO
        Invoke-WebRequest 'https://live.sysinternals.com/PsExec64.exe' -OutFile $psExecPath -UseBasicParsing
        Write-LogMessage "PSExec downloaded successfully" -Level SUCCESS
    }
    catch {
        Write-ErrorLog $_
        throw "Failed to download PSExec"
    }
}

# Paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM-v3.ps1"
$remediationScript = Join-Path $scriptPath "Remediate-OneDriveConfiguration-RMM-v2.ps1"

# Verify scripts exist
if (!(Test-Path $detectionScript)) {
    Write-LogMessage "Detection script not found: $detectionScript" -Level ERROR
    throw "Detection script not found"
}
if (!(Test-Path $remediationScript)) {
    Write-LogMessage "Remediation script not found: $remediationScript" -Level ERROR
    throw "Remediation script not found"
}

Write-LogMessage "Script paths verified:" -Level INFO
Write-LogMessage "  Detection:   $detectionScript" -Level INFO
Write-LogMessage "  Remediation: $remediationScript" -Level INFO

# Function to run script as SYSTEM with interactive window
function Invoke-AsSystemInteractive {
    param(
        [string]$ScriptPath,
        [string]$Description,
        [string]$TaskType
    )
    
    Write-LogMessage "`n$Description" -Level INFO
    Write-Host ("-" * 70) -ForegroundColor Gray
    
    # Create wrapper script that will:
    # 1. Show system context
    # 2. Run the actual script
    # 3. Pause to keep window open
    $wrapperContent = @"
Write-Host '=== Running as SYSTEM ===' -ForegroundColor Green
Write-Host "Current User: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Yellow
Write-Host "Computer: `$env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Script: $TaskType" -ForegroundColor Yellow
Write-Host "Time: `$(Get-Date)" -ForegroundColor Yellow
Write-Host ("-" * 70) -ForegroundColor Gray
Write-Host ""

# Run the actual script
try {
    & '$ScriptPath'
    `$exitCode = `$LASTEXITCODE
    Write-Host "`n`nScript completed with exit code: `$exitCode" -ForegroundColor Cyan
} catch {
    Write-Host "`n`nERROR: `$_" -ForegroundColor Red
    Write-Host "Stack: `$(`$_.ScriptStackTrace)" -ForegroundColor Red
    `$exitCode = 999
}

# Save exit code for parent process
`$exitCode | Out-File -FilePath "C:\Temp\$TaskType-exitcode.txt" -Force

Write-Host "`n`nPress any key to close this window..." -ForegroundColor Yellow
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@
    
    # Save wrapper script
    $wrapperPath = "C:\Temp\$TaskType-wrapper.ps1"
    $wrapperContent | Out-File -FilePath $wrapperPath -Encoding UTF8 -Force
    Write-LogMessage "Created wrapper script: $wrapperPath" -Level DEBUG
    
    # Run with PSExec in new window
    Write-LogMessage "Launching SYSTEM PowerShell window..." -Level INFO
    
    $psexecArgs = @(
        "-accepteula",
        "-s",               # Run as SYSTEM
        "-i",               # Interactive
        "-d",               # Don't wait (keeps window open)
        "powershell.exe",
        "-NoExit",          # Keep PowerShell open
        "-ExecutionPolicy", "Bypass",
        "-File", $wrapperPath
    )
    
    & $psExecPath @psexecArgs
    
    Write-LogMessage "Waiting for window to open and script to complete..." -Level INFO
    Write-Host "Check the new PowerShell window for output!" -ForegroundColor Yellow
    
    # Wait for exit code file
    $timeout = 60
    $elapsed = 0
    $exitCodeFile = "C:\Temp\$TaskType-exitcode.txt"
    
    while (-not (Test-Path $exitCodeFile) -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 1
        $elapsed++
        if ($elapsed % 5 -eq 0) {
            Write-Host "." -NoNewline
        }
    }
    Write-Host ""
    
    if (Test-Path $exitCodeFile) {
        $exitCode = [int](Get-Content $exitCodeFile -Raw).Trim()
        Remove-Item $exitCodeFile -Force
        Write-LogMessage "Script completed with exit code: $exitCode" -Level $(if ($exitCode -eq 0) { 'SUCCESS' } else { 'WARNING' })
    } else {
        $exitCode = 999
        Write-LogMessage "Timeout waiting for script completion" -Level ERROR
    }
    
    return $exitCode
}

try {
    # Run detection
    $detectionExitCode = Invoke-AsSystemInteractive `
        -ScriptPath $detectionScript `
        -Description "RUNNING DETECTION SCRIPT" `
        -TaskType "Detection"
    
    # Check if remediation is needed
    $needsRemediation = $detectionExitCode -ne 0
    
    if ($needsRemediation) {
        Write-LogMessage "Detection indicates REMEDIATION NEEDED" -Level WARNING
    } else {
        Write-LogMessage "Detection indicates NO REMEDIATION NEEDED" -Level SUCCESS
    }
    
    # Run remediation if needed or forced
    if (($needsRemediation -or $ForceRemediation) -and -not $SkipRemediation) {
        
        Write-Host "`nPress Enter to continue with remediation..." -ForegroundColor Yellow
        Read-Host
        
        $remediationExitCode = Invoke-AsSystemInteractive `
            -ScriptPath $remediationScript `
            -Description "RUNNING REMEDIATION SCRIPT" `
            -TaskType "Remediation"
        
        Write-Host "`nPress Enter to run verification..." -ForegroundColor Yellow
        Read-Host
        
        # Run detection again to verify
        $verifyExitCode = Invoke-AsSystemInteractive `
            -ScriptPath $detectionScript `
            -Description "RUNNING DETECTION AGAIN TO VERIFY" `
            -TaskType "Verification"
        
        if ($verifyExitCode -eq 0) {
            Write-LogMessage "VERIFICATION: Remediation was SUCCESSFUL" -Level SUCCESS
        } else {
            Write-LogMessage "VERIFICATION: Remediation may require user login or additional steps" -Level WARNING
        }
    } elseif ($SkipRemediation) {
        Write-LogMessage "Skipping remediation as requested" -Level INFO
    }
}
catch {
    Write-ErrorLog $_
}

# Display log information
Write-Host "`n=== LOG FILES ===" -ForegroundColor Cyan
Write-LogMessage "Test log saved to: $LogPath" -Level INFO

# Show recent OneDrive logs
$recentLogs = Get-ChildItem -Path $env:TEMP -Filter "OneDrive-*.log" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 5

if ($recentLogs) {
    Write-LogMessage "Recent OneDrive logs:" -Level INFO
    foreach ($log in $recentLogs) {
        Write-LogMessage "  $($log.FullName) ($('{0:N2} KB' -f ($log.Length/1KB)))" -Level INFO
    }
}

Write-Host "`nTest completed! Check the log file for details." -ForegroundColor Green
Write-Host "Log: $LogPath" -ForegroundColor Yellow