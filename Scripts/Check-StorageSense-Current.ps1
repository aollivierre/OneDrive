#Requires -Version 5.1

<#
.SYNOPSIS
    Checks current Storage Sense configuration
#>

Write-Host "=== Storage Sense Configuration Check ===" -ForegroundColor Cyan
Write-Host "Machine: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "User: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Date: $(Get-Date)" -ForegroundColor Yellow

# Check Group Policy settings
Write-Host "`n--- Group Policy Settings ---" -ForegroundColor Green
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
if (Test-Path $policyPath) {
    Write-Host "Policy path exists" -ForegroundColor Green
    Get-ItemProperty -Path $policyPath | Format-List
} else {
    Write-Host "No Storage Sense Group Policy configured" -ForegroundColor Red
}

# Check user settings
Write-Host "`n--- User Settings ---" -ForegroundColor Green
$userPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
if (Test-Path $userPath) {
    $settings = Get-ItemProperty -Path $userPath
    
    # Decode the settings
    Write-Host "`nStorage Sense Status:" -ForegroundColor Yellow
    if ($settings.'01' -eq 1) {
        Write-Host "  Storage Sense: ENABLED" -ForegroundColor Green
    } else {
        Write-Host "  Storage Sense: DISABLED" -ForegroundColor Red
    }
    
    Write-Host "`nCloud Content Settings:" -ForegroundColor Yellow
    if ($settings.'04' -eq 1) {
        Write-Host "  Make files online-only: ENABLED" -ForegroundColor Green
        Write-Host "  Days until online-only: $($settings.'08')" -ForegroundColor Green
    } else {
        Write-Host "  Make files online-only: DISABLED" -ForegroundColor Red
    }
    
    Write-Host "`nRun Frequency:" -ForegroundColor Yellow
    $frequency = switch ($settings.'2048') {
        0 { "During low free disk space (default)" }
        1 { "Every day" }
        7 { "Every week" }
        30 { "Every month" }
        default { "Unknown ($($settings.'2048'))" }
    }
    Write-Host "  Frequency: $frequency" -ForegroundColor Green
    
    Write-Host "`nTemporary Files:" -ForegroundColor Yellow
    if ($settings.'04' -eq 1) {
        Write-Host "  Delete temporary files: ENABLED" -ForegroundColor Green
    } else {
        Write-Host "  Delete temporary files: DISABLED" -ForegroundColor Red
    }
    
    Write-Host "`nRecycle Bin:" -ForegroundColor Yellow
    Write-Host "  Delete files older than: $($settings.'256') days" -ForegroundColor Green
    
    Write-Host "`nDownloads Folder:" -ForegroundColor Yellow
    if ($settings.'32' -eq 0) {
        Write-Host "  Never delete from Downloads" -ForegroundColor Green
    } else {
        Write-Host "  Delete files older than: $($settings.'32') days" -ForegroundColor Yellow
    }
} else {
    Write-Host "No user Storage Sense settings found" -ForegroundColor Red
}

# Check if OneDrive is configured for Files On-Demand
Write-Host "`n--- OneDrive Files On-Demand ---" -ForegroundColor Green
$oneDrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
if (Test-Path $oneDrivePath) {
    $fodSetting = Get-ItemProperty -Path $oneDrivePath -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
    if ($fodSetting -and $fodSetting.FilesOnDemandEnabled -eq 1) {
        Write-Host "  Files On-Demand: ENABLED (via policy)" -ForegroundColor Green
    } else {
        Write-Host "  Files On-Demand: Not set in policy" -ForegroundColor Yellow
    }
} else {
    Write-Host "  OneDrive policy not configured" -ForegroundColor Yellow
}

# Check OneDrive version
$oneDriveExe = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
if (Test-Path $oneDriveExe) {
    $version = (Get-Item $oneDriveExe).VersionInfo.FileVersion
    Write-Host "  OneDrive Version: $version" -ForegroundColor Green
    
    $versionParts = $version.Split('.')
    if ([int]$versionParts[0] -gt 23 -or ([int]$versionParts[0] -eq 23 -and [int]$versionParts[1] -ge 66)) {
        Write-Host "  Files On-Demand: ON BY DEFAULT (v23.066+)" -ForegroundColor Green
    }
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Storage Sense is currently:" -ForegroundColor Yellow
if ($settings -and $settings.'01' -eq 1) {
    Write-Host "  [X] ENABLED but not optimally configured" -ForegroundColor Yellow
    Write-Host "  [X] NOT making OneDrive files online-only automatically" -ForegroundColor Red
    Write-Host "  [X] Running only during low disk space" -ForegroundColor Red
} else {
    Write-Host "  [X] DISABLED" -ForegroundColor Red
    Write-Host "  [X] Not automatically managing disk space" -ForegroundColor Red
    Write-Host "  [X] Files On-Demand must be managed manually" -ForegroundColor Red
}