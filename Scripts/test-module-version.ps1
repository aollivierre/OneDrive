# Test script to verify module versioning
Write-Host "Testing logging module with manifest..." -ForegroundColor Cyan

# Test loading with .psd1
Write-Host "`nTest 1: Loading module via manifest (.psd1)" -ForegroundColor Yellow
try {
    Import-Module "C:\code\Win11UpgradeScheduler\Win11Detection\src\logging\logging.psd1" -Force
    $version = Get-LoggingModuleVersion
    Write-Host "Success! Module version: $version" -ForegroundColor Green
    
    $moduleInfo = Get-Module -Name logging
    Write-Host "Module info:" -ForegroundColor Yellow
    Write-Host "  Name: $($moduleInfo.Name)"
    Write-Host "  Version: $($moduleInfo.Version)"
    Write-Host "  Description: $($moduleInfo.Description)"
    Write-Host "  Author: $($moduleInfo.Author)"
} catch {
    Write-Host "Failed to load module: $_" -ForegroundColor Red
}

# Test loading directly with .psm1
Write-Host "`nTest 2: Loading module directly (.psm1)" -ForegroundColor Yellow
try {
    Remove-Module logging -ErrorAction SilentlyContinue
    Import-Module "C:\code\OneDrive\Scripts\logging\logging.psm1" -Force
    $version = Get-LoggingModuleVersion
    Write-Host "Success! Module version: $version" -ForegroundColor Green
} catch {
    Write-Host "Failed to load module: $_" -ForegroundColor Red
}

Write-Host "`nModule testing complete!" -ForegroundColor Cyan