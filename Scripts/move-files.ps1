# Move files to organized structure
$baseDir = "C:\code\OneDrive\Scripts"

# Move production files to src
$productionFiles = @(
    "Detect-OneDriveConfiguration-RMM.ps1",
    "Remediate-OneDriveConfiguration-RMM.ps1",
    "Test-OneDriveRMM-AsSystem-StayOpen.ps1",
    "README-RMM.md"
)

Write-Host "Moving production files to src/..." -ForegroundColor Cyan
foreach ($file in $productionFiles) {
    $source = Join-Path $baseDir $file
    $dest = Join-Path $baseDir "src\$file"
    if (Test-Path $source) {
        Move-Item -Path $source -Destination $dest -Force
        Write-Host "  Moved: $file" -ForegroundColor Green
    }
}

# Move test files to tests
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

Write-Host "`nMoving test files to tests/..." -ForegroundColor Cyan
foreach ($file in $testFiles) {
    $source = Join-Path $baseDir $file
    $dest = Join-Path $baseDir "tests\$file"
    if (Test-Path $source) {
        Move-Item -Path $source -Destination $dest -Force
        Write-Host "  Moved: $file" -ForegroundColor Green
    }
}

# Move utility files to utils
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

Write-Host "`nMoving utility files to utils/..." -ForegroundColor Cyan
foreach ($file in $utilityFiles) {
    $source = Join-Path $baseDir $file
    $dest = Join-Path $baseDir "utils\$file"
    if (Test-Path $source) {
        Move-Item -Path $source -Destination $dest -Force
        Write-Host "  Moved: $file" -ForegroundColor Green
    }
}

# Move dev files to dev
$devFiles = @(
    "Fix-OneDriveKFM-Properly.ps1",
    "Force-KFMRedirection.ps1",
    "Force-OneDrivePolicyApplication.ps1",
    "Invoke-OneDriveDetectionRemediation.ps1",
    "Invoke-OneDriveDetectionRemediationV2.ps1",
    "Detect-OneDriveConfiguration.ps1"
)

Write-Host "`nMoving dev/debug files to dev/..." -ForegroundColor Cyan
foreach ($file in $devFiles) {
    $source = Join-Path $baseDir $file
    $dest = Join-Path $baseDir "dev\$file"
    if (Test-Path $source) {
        Move-Item -Path $source -Destination $dest -Force
        Write-Host "  Moved: $file" -ForegroundColor Green
    }
}

# Move Production versions to Archive
$archiveFiles = @(
    "Detect-OneDriveConfiguration-RMM-Production.ps1",
    "Remediate-OneDriveConfiguration-RMM-Production.ps1"
)

Write-Host "`nMoving -Production versions to Archive/..." -ForegroundColor Cyan
foreach ($file in $archiveFiles) {
    $source = Join-Path $baseDir $file
    $dest = Join-Path $baseDir "Archive\$file"
    if (Test-Path $source) {
        Move-Item -Path $source -Destination $dest -Force
        Write-Host "  Moved: $file" -ForegroundColor Green
    }
}

Write-Host "`nOrganization complete!" -ForegroundColor Green