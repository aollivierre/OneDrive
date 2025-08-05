#requires -Version 5.1
<#
.SYNOPSIS
    OneDrive for Business detection script for RMM deployment.

.DESCRIPTION
    This script detects OneDrive configuration issues without making changes.
    Exit codes:
    0 = All checks passed, no issues detected
    1 = Issues detected, remediation needed
    
.PARAMETER TenantID
    The Azure AD Tenant ID for OneDrive configuration validation

.PARAMETER CheckDownloadsFolder
    Include Downloads folder in detection checks (default: $true)

.EXAMPLE
    .\Detect-OneDriveConfiguration.ps1 -TenantID "12345678-1234-1234-1234-123456789012"

.NOTES
    Designed for RMM deployment from SYSTEM context
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantID,
    
    [Parameter()]
    [bool]$CheckDownloadsFolder = $true
)

$ErrorActionPreference = 'Stop'

# Detection results
$issues = @()

try {
    # Check 1: OneDrive Installation
    $oneDrivePaths = @(
        "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
        "$env:PROGRAMFILES(x86)\Microsoft OneDrive\OneDrive.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    )
    
    $oneDriveInstalled = $oneDrivePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    
    if (!$oneDriveInstalled) {
        $issues += "OneDrive is not installed"
    }
    else {
        # Check 2: OneDrive Running
        $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
        if (!$oneDriveProcess) {
            $issues += "OneDrive is not running"
        }
        
        # Check 3: KFM Configuration
        $kfmEnabled = $false
        $policyPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive",
            "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
        )
        
        foreach ($path in $policyPaths) {
            if (Test-Path $path) {
                $kfmSetting = Get-ItemProperty -Path $path -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
                if ($kfmSetting -and $kfmSetting.KFMSilentOptIn -eq $TenantID) {
                    $kfmEnabled = $true
                    break
                }
            }
        }
        
        if (!$kfmEnabled) {
            $issues += "Known Folder Move (KFM) is not enabled"
        }
        
        # Check 4: Files On-Demand
        $fodEnabled = $false
        foreach ($path in $policyPaths) {
            if (Test-Path $path) {
                $fodSetting = Get-ItemProperty -Path $path -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
                if ($fodSetting -and $fodSetting.FilesOnDemandEnabled -eq 1) {
                    $fodEnabled = $true
                    break
                }
            }
        }
        
        if (!$fodEnabled) {
            $issues += "Files On-Demand is not enabled"
        }
        
        # Check 5: Downloads Folder (if requested)
        if ($CheckDownloadsFolder) {
            $userShellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            $downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
            
            if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
                # Running as SYSTEM - try to check for logged-in user
                $explorerProcess = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($explorerProcess) {
                    # Note: This is a simplified check. In production, use proper impersonation
                    Write-Host "Running as SYSTEM - Downloads folder check skipped"
                }
            }
            else {
                $downloadsPath = Get-ItemProperty -Path $userShellFolders -Name $downloadsGuid -ErrorAction SilentlyContinue
                if ($downloadsPath) {
                    $currentPath = $downloadsPath.$downloadsGuid
                    $oneDrivePath = $env:OneDrive
                    
                    if (!($oneDrivePath -and $currentPath -like "*$oneDrivePath*")) {
                        $issues += "Downloads folder is not redirected to OneDrive"
                    }
                }
            }
        }
        
        # Check 6: Disk Space
        $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
        $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        
        if ($freeSpaceGB -lt 32) {
            $issues += "Insufficient disk space for Windows 11 upgrade (${freeSpaceGB}GB free, need 32GB)"
        }
    }
    
    # Output results
    if ($issues.Count -eq 0) {
        Write-Output "SUCCESS: All OneDrive checks passed"
        exit 0
    }
    else {
        Write-Output "ISSUES DETECTED:"
        $issues | ForEach-Object { Write-Output "  - $_" }
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}