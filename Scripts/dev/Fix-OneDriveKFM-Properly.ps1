#requires -RunAsAdministrator
<#
.SYNOPSIS
    Properly configures OneDrive KFM with the REAL tenant ID
    
.DESCRIPTION
    This script:
    1. Detects the real tenant ID from OneDrive configuration
    2. Sets the correct registry policies
    3. Triggers KFM for Desktop, Documents, and Pictures
    4. Does NOT require user interaction
#>

Write-Host "=== Fixing OneDrive KFM Configuration ===" -ForegroundColor Green

# Get the real tenant ID
$businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
$realTenantID = $null

if (Test-Path $businessPath) {
    $realTenantID = (Get-ItemProperty -Path $businessPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue).ConfiguredTenantId
    
    if ($realTenantID) {
        Write-Host "Found real Tenant ID: $realTenantID" -ForegroundColor Green
        $userEmail = (Get-ItemProperty -Path $businessPath -Name "UserEmail" -ErrorAction SilentlyContinue).UserEmail
        Write-Host "User: $userEmail" -ForegroundColor Cyan
    }
    else {
        Write-Host "ERROR: Could not find tenant ID. Is OneDrive signed in?" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "ERROR: OneDrive Business account not found. Please sign in to OneDrive first." -ForegroundColor Red
    exit 1
}

# Set the correct policies
Write-Host "`nConfiguring registry policies..." -ForegroundColor Yellow
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"

if (!(Test-Path $policyPath)) {
    New-Item -Path $policyPath -Force | Out-Null
}

# Set all required policies
$policies = @{
    "KFMSilentOptIn" = $realTenantID
    "KFMSilentOptInWithNotification" = 0
    "KFMBlockOptOut" = 1
    "FilesOnDemandEnabled" = 1
    "SilentAccountConfig" = 1
}

foreach ($policy in $policies.GetEnumerator()) {
    Set-ItemProperty -Path $policyPath -Name $policy.Key -Value $policy.Value -Force
    Write-Host "  Set $($policy.Key) = $($policy.Value)" -ForegroundColor Gray
}

# Force a policy refresh
Write-Host "`nForcing policy refresh..." -ForegroundColor Yellow
gpupdate /force | Out-Null

# Restart OneDrive to apply settings
Write-Host "`nRestarting OneDrive..." -ForegroundColor Yellow
$oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($oneDriveProcess) {
    Stop-Process -Name "OneDrive" -Force
    Start-Sleep -Seconds 2
}

# Start OneDrive with the correct user
$oneDriveExe = Get-ChildItem -Path @(
    "$env:PROGRAMFILES\Microsoft OneDrive",
    "${env:PROGRAMFILES(x86)}\Microsoft OneDrive",
    "$env:LOCALAPPDATA\Microsoft\OneDrive"
) -Filter "OneDrive.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($oneDriveExe) {
    Start-Process -FilePath $oneDriveExe.FullName
    Write-Host "OneDrive restarted" -ForegroundColor Green
    
    # Wait for OneDrive to start
    Start-Sleep -Seconds 5
}

# Verify the changes
Write-Host "`n=== Verification ===" -ForegroundColor Cyan
& "$PSScriptRoot\Get-OneDriveRealStatus.ps1"

Write-Host "`n=== IMPORTANT ===" -ForegroundColor Yellow
Write-Host "KFM has been configured with the correct tenant ID." -ForegroundColor Green
Write-Host "It may take a few minutes for folders to start redirecting." -ForegroundColor Yellow
Write-Host "You may need to sign out and sign back in for full effect." -ForegroundColor Yellow