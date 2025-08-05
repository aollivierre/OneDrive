# Script to categorize files for organization

$baseDir = "C:\code\OneDrive\Scripts"

# Key Production Files (for src folder)
$productionFiles = @(
    "Detect-OneDriveConfiguration-RMM.ps1",
    "Remediate-OneDriveConfiguration-RMM.ps1",
    "Test-OneDriveRMM-AsSystem-StayOpen.ps1",  # Main test wrapper
    "README-RMM.md"
)

# Test Files (for tests folder)
$testFiles = @(
    "Test-OneDrive-As-SYSTEM-Interactive.ps1",
    "Test-OneDriveAutomated.ps1",
    "Test-SimpleLogging.ps1",
    "Test-StandardizedLogging.ps1",
    "test-logging-fix.ps1",
    "test-minimal-logging-v2.ps1",
    "test-minimal-logging.ps1",
    "test-module-version.ps1",
    "test-rmm-style-logging.ps1"
)

# Utility/Helper Scripts (for utils folder)
$utilityFiles = @(
    "Get-ActualTenantID.ps1",
    "Get-AutoDetectedTenantID.ps1",
    "Get-OneDriveRealStatus.ps1",
    "Get-OptimalOneDriveLibVersion.ps1",
    "Get-TenantID-Enhanced.ps1",
    "Find-TenantInfo.ps1",
    "Check-StorageSense-Current.ps1",
    "Collect-OneDriveStatus-Adaptive.ps1",
    "Collect-OneDriveStatus-UserContext.ps1"
)

# Archive/Backup files (stay in Archive)
$archiveFiles = @(
    "Archive.ps1",
    "archive-files.ps1",
    "Detect-OneDriveConfiguration-RMM-Production.ps1",
    "Remediate-OneDriveConfiguration-RMM-Production.ps1"
)

# Dev/Debug Scripts (for dev folder)
$devFiles = @(
    "Fix-OneDriveKFM-Properly.ps1",
    "Force-KFMRedirection.ps1",
    "Force-OneDrivePolicyApplication.ps1",
    "Invoke-OneDriveDetectionRemediation.ps1",
    "Invoke-OneDriveDetectionRemediationV2.ps1",
    "Detect-OneDriveConfiguration.ps1"
)

# Maintenance scripts (stay in root)
$maintenanceFiles = @(
    "push-to-github.ps1",
    "sync-logging-docs.ps1",
    "check-unicode.ps1"
)

Write-Host "=== FILE ORGANIZATION PLAN ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Production Files (src/):" -ForegroundColor Green
$productionFiles | ForEach-Object { Write-Host "  $_" }

Write-Host "`nTest Files (tests/):" -ForegroundColor Yellow
$testFiles | ForEach-Object { Write-Host "  $_" }

Write-Host "`nUtility Files (utils/):" -ForegroundColor Magenta
$utilityFiles | ForEach-Object { Write-Host "  $_" }

Write-Host "`nDev/Debug Files (dev/):" -ForegroundColor Blue
$devFiles | ForEach-Object { Write-Host "  $_" }

Write-Host "`nArchive Files (Archive/):" -ForegroundColor Gray
$archiveFiles | ForEach-Object { Write-Host "  $_" }

Write-Host "`nMaintenance Files (root):" -ForegroundColor White
$maintenanceFiles | ForEach-Object { Write-Host "  $_" }

Write-Host "`nSpecial Folders:" -ForegroundColor Cyan
Write-Host "  logging/ - Stays as-is (referenced by production scripts)"