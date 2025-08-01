# Test remediation functionality
$tenantID = "12345678-1234-1234-1234-123456789012"

Write-Host "Testing OneDrive Remediation Script..." -ForegroundColor Cyan
Write-Host "This will make changes to your system registry!" -ForegroundColor Yellow
Write-Host ""

# First, check current state
Write-Host "Current Registry State:" -ForegroundColor Green
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
if (Test-Path $policyPath) {
    Get-ItemProperty -Path $policyPath | Format-List
}
else {
    Write-Host "  Policy path does not exist" -ForegroundColor Gray
}

# Run remediation
Write-Host "`nRunning remediation script..." -ForegroundColor Yellow
$remediationScript = "C:\code\OneDrive\Scripts\Remediate-OneDriveConfiguration.ps1"
& powershell.exe -ExecutionPolicy Bypass -File $remediationScript -TenantID $tenantID

# Check state after remediation
Write-Host "`nRegistry State After Remediation:" -ForegroundColor Green
if (Test-Path $policyPath) {
    $policies = Get-ItemProperty -Path $policyPath
    Write-Host "  KFMSilentOptIn: $($policies.KFMSilentOptIn)" -ForegroundColor Cyan
    Write-Host "  FilesOnDemandEnabled: $($policies.FilesOnDemandEnabled)" -ForegroundColor Cyan
    Write-Host "  SilentAccountConfig: $($policies.SilentAccountConfig)" -ForegroundColor Cyan
    Write-Host "  KFMBlockOptOut: $($policies.KFMBlockOptOut)" -ForegroundColor Cyan
}

# Test detection again
Write-Host "`nRunning detection after remediation..." -ForegroundColor Yellow
$detectionScript = "C:\code\OneDrive\Scripts\Detect-OneDriveConfiguration.ps1"
& powershell.exe -ExecutionPolicy Bypass -File $detectionScript -TenantID $tenantID

Write-Host "`nRemediation test completed!" -ForegroundColor Green