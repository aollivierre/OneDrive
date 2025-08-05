#Requires -Version 5.1

<#
.SYNOPSIS
    Simple test harness for OneDrive RMM scripts
.DESCRIPTION
    Tests detection and remediation scripts without SYSTEM context requirement
.EXAMPLE
    .\Test-OneDriveRMM-Simple.ps1
    .\Test-OneDriveRMM-Simple.ps1 -WhatIf
#>

param(
    [switch]$WhatIf
)

Write-Host "OneDrive RMM Scripts - Simple Test" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration-RMM.ps1"
$remediationScript = Join-Path $scriptPath "Remediate-OneDriveConfiguration-RMM.ps1"

# Check current status
Write-Host "`nChecking current OneDrive configuration..." -ForegroundColor Yellow

# Quick manual check
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
if (Test-Path $policyPath) {
    Write-Host "`nCurrent Policy Settings:" -ForegroundColor Green
    Get-ItemProperty -Path $policyPath | Format-List
} else {
    Write-Host "No OneDrive policies configured" -ForegroundColor Red
}

if ($WhatIf) {
    Write-Host "`n[WhatIf Mode] Would run the following:" -ForegroundColor Magenta
    Write-Host "1. Detection script: $detectionScript"
    Write-Host "2. If needed, remediation script: $remediationScript"
    Write-Host "3. Re-run detection to verify"
    return
}

# Run detection
Write-Host "`n=== RUNNING DETECTION ===" -ForegroundColor Green
& $detectionScript
$detectionResult = $LASTEXITCODE

Write-Host "`nDetection Exit Code: $detectionResult" -ForegroundColor $(if ($detectionResult -eq 0) { "Green" } else { "Yellow" })

if ($detectionResult -ne 0) {
    Write-Host "`n=== RUNNING REMEDIATION ===" -ForegroundColor Green
    
    # Show what will be configured
    Write-Host "`nRemediation will configure:" -ForegroundColor Yellow
    Write-Host "- Tenant ID: 336dbee2-bd39-4116-b305-3105539e416f"
    Write-Host "- Files On-Demand: Enabled"
    Write-Host "- KFM for: Desktop, Documents, Pictures, Downloads"
    Write-Host "- Excluded files: *.pst, *.ost"
    
    $confirm = Read-Host "`nProceed with remediation? (Y/N)"
    if ($confirm -eq 'Y') {
        & $remediationScript
        $remediationResult = $LASTEXITCODE
        
        Write-Host "`nRemediation Exit Code: $remediationResult" -ForegroundColor $(if ($remediationResult -eq 0) { "Green" } else { "Red" })
        
        # Verify
        Write-Host "`n=== RUNNING DETECTION AGAIN ===" -ForegroundColor Green
        & $detectionScript
        $verifyResult = $LASTEXITCODE
        
        Write-Host "`nVerification Exit Code: $verifyResult" -ForegroundColor $(if ($verifyResult -eq 0) { "Green" } else { "Yellow" })
    }
} else {
    Write-Host "`nNo remediation needed - OneDrive is properly configured!" -ForegroundColor Green
}

# Show logs
Write-Host "`n=== RECENT LOG FILES ===" -ForegroundColor Cyan
Get-ChildItem -Path $env:TEMP -Filter "OneDrive-*.log" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 3 | 
    Format-Table Name, LastWriteTime, Length -AutoSize