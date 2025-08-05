#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Tests OneDrive RMM scripts as SYSTEM using Task Scheduler (no psexec needed)
.DESCRIPTION
    Alternative wrapper that uses Task Scheduler to run as SYSTEM
    Mimics RMM behavior without requiring psexec
.EXAMPLE
    .\Test-OneDriveRMM-AsSystem-TaskScheduler.ps1
#>

param(
    [switch]$SkipRemediation,
    [switch]$ForceRemediation
)

Write-Host "OneDrive RMM Scripts - SYSTEM Context Test (Task Scheduler)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "This script must be run as Administrator"
}

# Paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM-v3.ps1"
$remediationScript = Join-Path $scriptPath "Remediate-OneDriveConfiguration-RMM-v2.ps1"
$tempDir = "C:\Temp\OneDriveRMM-$(Get-Date -Format 'yyyyMMddHHmmss')"

# Verify scripts exist
if (!(Test-Path $detectionScript)) {
    throw "Detection script not found: $detectionScript"
}
if (!(Test-Path $remediationScript)) {
    throw "Remediation script not found: $remediationScript"
}

# Create temp directory
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

Write-Host "`nScript paths:" -ForegroundColor Yellow
Write-Host "Detection:    $detectionScript"
Write-Host "Remediation:  $remediationScript"
Write-Host "Temp Dir:     $tempDir"

function Invoke-AsSystemViaTask {
    param(
        [string]$ScriptPath,
        [string]$Description,
        [string]$TaskName
    )
    
    Write-Host "`n$Description" -ForegroundColor Green
    Write-Host ("-" * 50)
    
    # Output file
    $outputFile = Join-Path $tempDir "$TaskName-output.txt"
    $exitCodeFile = Join-Path $tempDir "$TaskName-exitcode.txt"
    
    # Create wrapper script that captures output and exit code
    $wrapperScript = @"
`$output = & '$ScriptPath' 2>&1
`$output | Out-File -FilePath '$outputFile' -Encoding UTF8
`$LASTEXITCODE | Out-File -FilePath '$exitCodeFile'
exit `$LASTEXITCODE
"@
    
    $wrapperPath = Join-Path $tempDir "$TaskName-wrapper.ps1"
    $wrapperScript | Out-File -FilePath $wrapperPath -Encoding UTF8
    
    # Create scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapperPath`""
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    # Register and run task
    Write-Host "Creating and running scheduled task as SYSTEM..."
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    
    # Wait for completion
    Write-Host "Waiting for task to complete..."
    $timeout = 60
    $elapsed = 0
    while ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running' -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 1
        $elapsed++
        Write-Host "." -NoNewline
    }
    Write-Host ""
    
    # Get results
    $exitCode = 999
    if (Test-Path $exitCodeFile) {
        $exitCode = [int](Get-Content $exitCodeFile -Raw).Trim()
    }
    
    if (Test-Path $outputFile) {
        Write-Host "`nOutput:" -ForegroundColor Yellow
        Get-Content $outputFile | Write-Host
    }
    
    # Cleanup task
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-Host "`nExit Code: $exitCode" -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })
    
    return $exitCode
}

# Run detection
$detectionExitCode = Invoke-AsSystemViaTask -ScriptPath $detectionScript -Description "RUNNING DETECTION SCRIPT" -TaskName "OneDriveDetection_Test"

# Check if remediation is needed
$needsRemediation = $detectionExitCode -ne 0

if ($needsRemediation) {
    Write-Host "`nDetection indicates REMEDIATION NEEDED" -ForegroundColor Yellow
} else {
    Write-Host "`nDetection indicates NO REMEDIATION NEEDED" -ForegroundColor Green
}

# Run remediation if needed or forced
if (($needsRemediation -or $ForceRemediation) -and -not $SkipRemediation) {
    $remediationExitCode = Invoke-AsSystemViaTask -ScriptPath $remediationScript -Description "RUNNING REMEDIATION SCRIPT" -TaskName "OneDriveRemediation_Test"
    
    # Run detection again to verify
    $verifyExitCode = Invoke-AsSystemViaTask -ScriptPath $detectionScript -Description "RUNNING DETECTION AGAIN TO VERIFY" -TaskName "OneDriveVerify_Test"
    
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
Write-Host "Temp Directory: $tempDir"
$logs = Get-ChildItem -Path $env:TEMP -Filter "OneDrive-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
if ($logs) {
    Write-Host "`nRecent OneDrive logs:"
    foreach ($log in $logs) {
        Write-Host "  $($log.FullName)"
    }
}

# Cleanup temp directory
Write-Host "`nCleaning up temp files..." -ForegroundColor Gray
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`nTest completed!" -ForegroundColor Green