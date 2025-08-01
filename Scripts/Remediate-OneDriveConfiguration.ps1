#requires -Version 5.1
<#
.SYNOPSIS
    OneDrive for Business remediation script for RMM deployment.

.DESCRIPTION
    This script remediates OneDrive configuration issues detected by the detection script.
    Exit codes:
    0 = Remediation successful
    1 = Remediation failed
    
.PARAMETER TenantID
    The Azure AD Tenant ID for OneDrive configuration

.PARAMETER EnableDownloadsFolder
    Enable Downloads folder redirection (default: $true)

.EXAMPLE
    .\Remediate-OneDriveConfiguration.ps1 -TenantID "12345678-1234-1234-1234-123456789012"

.NOTES
    Designed for RMM deployment from SYSTEM context
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantID,
    
    [Parameter()]
    [bool]$EnableDownloadsFolder = $true
)

$ErrorActionPreference = 'Stop'
$logPath = "C:\ProgramData\OneDriveRemediation"
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile = Join-Path $logPath "Remediation_$timestamp.log"

# Create log directory
if (!(Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param($Message, $Level = 'Info')
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -Force
    Write-Host $entry
}

try {
    Write-Log "Starting OneDrive remediation"
    Write-Log "TenantID: $TenantID"
    
    # Step 1: Ensure registry policy path exists
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    if (!(Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
        Write-Log "Created OneDrive policy registry path"
    }
    
    # Step 2: Configure KFM
    Write-Log "Configuring Known Folder Move (KFM)"
    Set-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -Value $TenantID -Force
    Set-ItemProperty -Path $policyPath -Name "KFMSilentOptInWithNotification" -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name "KFMBlockOptOut" -Value 1 -Force
    Write-Log "KFM configuration completed"
    
    # Step 3: Enable Files On-Demand
    Write-Log "Enabling Files On-Demand"
    Set-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -Value 1 -Force
    Write-Log "Files On-Demand enabled"
    
    # Step 4: Configure Silent Account Configuration
    Write-Log "Configuring silent account setup"
    Set-ItemProperty -Path $policyPath -Name "SilentAccountConfig" -Value 1 -Force
    Write-Log "Silent account configuration enabled"
    
    # Step 5: Start OneDrive if not running
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if (!$oneDriveProcess) {
        Write-Log "OneDrive not running, attempting to start"
        
        $oneDrivePaths = @(
            "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
            "$env:PROGRAMFILES(x86)\Microsoft OneDrive\OneDrive.exe",
            "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
        )
        
        $oneDriveExe = $oneDrivePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        
        if ($oneDriveExe) {
            # If running as SYSTEM, create a scheduled task to run as logged-in user
            if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
                Write-Log "Running as SYSTEM, creating scheduled task"
                
                $activeUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
                if ($activeUser) {
                    $taskName = "StartOneDrive_$timestamp"
                    $action = New-ScheduledTaskAction -Execute $oneDriveExe -Argument "/background"
                    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)
                    $principal = New-ScheduledTaskPrincipal -UserId $activeUser -LogonType Interactive
                    
                    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
                    Start-ScheduledTask -TaskName $taskName
                    
                    Start-Sleep -Seconds 5
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                    
                    Write-Log "OneDrive start task executed"
                }
            }
            else {
                Start-Process -FilePath $oneDriveExe -ArgumentList "/background" -WindowStyle Hidden
                Write-Log "OneDrive started"
            }
        }
    }
    
    # Step 6: Configure Downloads folder (if enabled and not running as SYSTEM)
    if ($EnableDownloadsFolder -and ![Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        Write-Log "Configuring Downloads folder redirection"
        
        $oneDrivePath = $env:OneDrive
        if ($oneDrivePath) {
            $oneDriveDownloads = Join-Path $oneDrivePath "Downloads"
            
            # Create Downloads folder in OneDrive
            if (!(Test-Path $oneDriveDownloads)) {
                New-Item -Path $oneDriveDownloads -ItemType Directory -Force | Out-Null
            }
            
            # Update registry
            $userShellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            $downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
            
            Set-ItemProperty -Path $userShellFolders -Name $downloadsGuid -Value $oneDriveDownloads -Force
            
            Write-Log "Downloads folder configured to: $oneDriveDownloads"
        }
    }
    
    Write-Log "OneDrive remediation completed successfully"
    Write-Output "SUCCESS: OneDrive remediation completed"
    exit 0
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Log "ERROR: $errorMsg" -Level 'Error'
    Write-Output "ERROR: $errorMsg"
    exit 1
}