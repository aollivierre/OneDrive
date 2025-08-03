#Requires -Version 5.1

<#
.SYNOPSIS
    Quick test to verify both Detection and Remediation scripts use standardized logging
#>

Write-Host "`n=== Testing Standardized Logging ===" -ForegroundColor Cyan
Write-Host "This will run both scripts in debug mode to verify logging module usage`n" -ForegroundColor Gray

# Test Detection Script
Write-Host "--- Testing Detection Script ---" -ForegroundColor Yellow
& "$PSScriptRoot\Detect-OneDriveConfiguration-RMM.ps1" -EnableDebug | Select-Object -First 20

Write-Host "`n`n--- Testing Remediation Script ---" -ForegroundColor Yellow
& "$PSScriptRoot\Remediate-OneDriveConfiguration-RMM.ps1" -EnableDebug | Select-Object -First 20

Write-Host "`n`n=== Summary ===" -ForegroundColor Green
Write-Host "Both scripts should show:" -ForegroundColor Gray
Write-Host "  - [DEBUG] Found logging module at: ..." -ForegroundColor Gray
Write-Host "  - [DEBUG] Logging module imported successfully" -ForegroundColor Gray
Write-Host "  - [Information/Warning/Error] messages with line numbers" -ForegroundColor Gray
Write-Host "  - Consistent formatting like: [Level] [ScriptName.Function:LineNumber] - Message" -ForegroundColor Gray

Write-Host "`nLog locations:" -ForegroundColor Yellow
Write-Host "  Detection: C:\ProgramData\OneDriveDetection\Logs\" -ForegroundColor Gray
Write-Host "  Remediation: C:\ProgramData\OneDriveRemediation\Logs\" -ForegroundColor Gray