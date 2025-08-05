#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Forces OneDrive to apply Group Policy settings immediately
.DESCRIPTION
    Restarts OneDrive for the logged-in user to force it to read and apply
    the Group Policy registry settings we configured.
#>

Write-Host "`n=== Forcing OneDrive Policy Application ===" -ForegroundColor Cyan

# Get logged-in user
$explorer = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
if ($explorer) {
    $owner = $explorer.GetOwner()
    if ($owner.ReturnValue -eq 0) {
        $username = $owner.User
        Write-Host "Found logged-in user: $username" -ForegroundColor Green
    }
}

# Stop OneDrive for the user
Write-Host "`nStopping OneDrive..." -ForegroundColor Yellow
$oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($oneDriveProcess) {
    $oneDriveProcess | Stop-Process -Force
    Write-Host "OneDrive stopped" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "OneDrive was not running" -ForegroundColor Gray
}

# Find OneDrive executable
$oneDrivePaths = @(
    "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
    "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
)

$oneDriveExe = $null
foreach ($path in $oneDrivePaths) {
    if (Test-Path $path) {
        $oneDriveExe = $path
        break
    }
}

if ($oneDriveExe) {
    Write-Host "`nStarting OneDrive..." -ForegroundColor Yellow
    Write-Host "Path: $oneDriveExe" -ForegroundColor Gray
    
    # Start OneDrive with /background switch
    Start-Process -FilePath $oneDriveExe -ArgumentList "/background" -WindowStyle Hidden
    
    Write-Host "OneDrive started" -ForegroundColor Green
    Write-Host "`nOneDrive should now apply the Group Policy settings" -ForegroundColor Cyan
    
    # Wait a moment for OneDrive to initialize
    Start-Sleep -Seconds 5
    
    # Check if tenant ID is now in user registry
    $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path $businessPath) {
        $keys = Get-ItemProperty -Path $businessPath -ErrorAction SilentlyContinue
        if ($keys.ConfiguredTenantId) {
            Write-Host "`nSUCCESS: Tenant ID now configured in user registry: $($keys.ConfiguredTenantId)" -ForegroundColor Green
        } else {
            Write-Host "`nWARNING: Tenant ID not yet in user registry. May need user logoff/logon." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "ERROR: Could not find OneDrive.exe" -ForegroundColor Red
}

Write-Host "`n=== Complete ===" -ForegroundColor Green