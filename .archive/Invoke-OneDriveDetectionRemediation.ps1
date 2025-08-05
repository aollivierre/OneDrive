#requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive OneDrive for Business detection and remediation script for RMM deployment.

.DESCRIPTION
    This script performs detection and optional remediation of OneDrive for Business settings:
    - Checks OneDrive installation and running status
    - Verifies sync status using OneDriveLib.dll
    - Detects KFM (Known Folder Move) configuration
    - Detects Files On-Demand status
    - Optionally remediates all settings including Downloads folder redirection
    
    Designed to run from SYSTEM context (RMM) with user impersonation capabilities.

.PARAMETER TenantID
    The Azure AD Tenant ID for OneDrive configuration (required for KFM)

.PARAMETER RemediationMode
    Enable remediation mode to fix detected issues (default: $false for detection only)

.PARAMETER IncludeDownloadsFolder
    Include Downloads folder in KFM redirection (default: $true)

.PARAMETER LogPath
    Path for detailed logging (default: C:\ProgramData\OneDriveRemediation)

.EXAMPLE
    .\Invoke-OneDriveDetectionRemediation.ps1 -TenantID "12345678-1234-1234-1234-123456789012"
    
.EXAMPLE
    .\Invoke-OneDriveDetectionRemediation.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RemediationMode $true

.NOTES
    Author: OneDrive Automation Team
    Version: 1.0.0
    Requires: Windows 10 1709+ or Windows 11
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantID,
    
    [Parameter()]
    [bool]$RemediationMode = $false,
    
    [Parameter()]
    [bool]$IncludeDownloadsFolder = $true,
    
    [Parameter()]
    [string]$LogPath = "C:\ProgramData\OneDriveRemediation"
)

#region Initialization
$ErrorActionPreference = 'Stop'
$script:ExitCode = 0
$script:DetectionResults = @{
    OneDriveInstalled = $false
    OneDriveRunning = $false
    OneDriveVersion = "Not Installed"
    OneDriveArchitecture = "Unknown"
    SyncStatus = "Unknown"
    KFMEnabled = $false
    FilesOnDemandEnabled = $false
    DownloadsFolderRedirected = $false
    RequiredDiskSpace = $false
    UserContext = $env:USERNAME
    RunningAsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
}

# Create log directory
if (!(Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$script:LogFile = Join-Path $LogPath "OneDriveRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
#endregion

#region Logging Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logEntry -Force
    
    # Write to console with color
    switch ($Level) {
        'Info' { Write-Host $logEntry -ForegroundColor Green }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Error' { Write-Host $logEntry -ForegroundColor Red }
    }
}
#endregion

#region User Impersonation for SYSTEM Context
function Get-LoggedOnUserToken {
    <#
    .SYNOPSIS
        Gets the token of the currently logged-on user for impersonation
    #>
    
    Write-Log "Attempting to get logged-on user token"
    
    Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Principal;
    using System.Diagnostics;
    
    public class TokenImpersonation {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            int ImpersonationLevel,
            int TokenType,
            out IntPtr phNewToken);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
        
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint MAXIMUM_ALLOWED = 0x2000000;
        public const int SecurityImpersonation = 2;
        public const int TokenPrimary = 1;
        
        public static IntPtr GetUserToken() {
            IntPtr userToken = IntPtr.Zero;
            Process[] explorerProcesses = Process.GetProcessesByName("explorer");
            
            foreach (Process explorerProcess in explorerProcesses) {
                IntPtr processToken = IntPtr.Zero;
                try {
                    if (OpenProcessToken(explorerProcess.Handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, out processToken)) {
                        if (DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out userToken)) {
                            return userToken;
                        }
                    }
                }
                finally {
                    if (processToken != IntPtr.Zero) {
                        CloseHandle(processToken);
                    }
                }
            }
            
            return IntPtr.Zero;
        }
    }
'@
    
    try {
        $token = [TokenImpersonation]::GetUserToken()
        if ($token -ne [IntPtr]::Zero) {
            Write-Log "Successfully obtained user token"
            return $token
        }
        else {
            Write-Log "Failed to obtain user token" -Level Warning
            return $null
        }
    }
    catch {
        Write-Log "Error getting user token: $_" -Level Error
        return $null
    }
}

function Invoke-AsUser {
    param(
        [scriptblock]$ScriptBlock,
        [hashtable]$ArgumentList = @{}
    )
    
    if (!$script:DetectionResults.RunningAsSystem) {
        Write-Log "Not running as SYSTEM, executing directly"
        return & $ScriptBlock @ArgumentList
    }
    
    Write-Log "Running as SYSTEM, attempting user impersonation"
    
    try {
        # Try to get user token for impersonation
        $userToken = Get-LoggedOnUserToken
        
        if ($userToken -and $userToken -ne [IntPtr]::Zero) {
            # Create a new runspace with user impersonation
            $runspace = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $runspace.Open()
            
            $pipeline = $runspace.CreatePipeline()
            $pipeline.Commands.AddScript($ScriptBlock.ToString())
            
            foreach ($key in $ArgumentList.Keys) {
                $pipeline.Commands[0].Parameters.Add($key, $ArgumentList[$key])
            }
            
            # Impersonate user
            [TokenImpersonation]::ImpersonateLoggedOnUser($userToken) | Out-Null
            
            try {
                $results = $pipeline.Invoke()
                return $results
            }
            finally {
                # Revert impersonation
                [TokenImpersonation]::RevertToSelf() | Out-Null
                [TokenImpersonation]::CloseHandle($userToken) | Out-Null
                $runspace.Close()
            }
        }
        else {
            Write-Log "Could not obtain user token, attempting alternate method" -Level Warning
            
            # Fallback: Try to run in active user session
            $activeUsername = (Get-WmiObject -Class Win32_ComputerSystem).UserName
            if ($activeUsername) {
                $username = $activeUsername.Split('\')[-1]
                Write-Log "Found active user: $username"
                
                # Create scheduled task to run as user
                $taskName = "OneDriveTempTask_$(Get-Random)"
                $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$($ScriptBlock.ToString())`""
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)
                $principal = New-ScheduledTaskPrincipal -UserId $activeUsername -LogonType Interactive
                
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
                Start-ScheduledTask -TaskName $taskName
                
                # Wait for completion
                Start-Sleep -Seconds 3
                
                # Clean up
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                
                return $true
            }
        }
    }
    catch {
        Write-Log "Error during user impersonation: $_" -Level Error
        return $null
    }
}
#endregion

#region OneDrive Detection Functions
function Get-OneDriveInstallInfo {
    Write-Log "Checking OneDrive installation"
    
    try {
        # Check for OneDrive executable
        $oneDrivePaths = @(
            "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
            "$env:PROGRAMFILES(x86)\Microsoft OneDrive\OneDrive.exe",
            "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
        )
        
        $oneDriveExe = $oneDrivePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        
        if ($oneDriveExe) {
            $script:DetectionResults.OneDriveInstalled = $true
            
            # Get version info
            $versionInfo = (Get-Item $oneDriveExe).VersionInfo
            $script:DetectionResults.OneDriveVersion = $versionInfo.FileVersion
            
            # Check architecture
            if ($oneDriveExe -like "*Program Files\Microsoft OneDrive*") {
                $script:DetectionResults.OneDriveArchitecture = "64-bit"
            }
            else {
                $script:DetectionResults.OneDriveArchitecture = "32-bit"
            }
            
            Write-Log "OneDrive found: Version $($versionInfo.FileVersion), Architecture: $($script:DetectionResults.OneDriveArchitecture)"
            
            # Check if running
            $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
            if ($oneDriveProcess) {
                $script:DetectionResults.OneDriveRunning = $true
                Write-Log "OneDrive is running (PID: $($oneDriveProcess.Id))"
            }
            else {
                Write-Log "OneDrive is not running" -Level Warning
            }
        }
        else {
            Write-Log "OneDrive is not installed" -Level Warning
        }
    }
    catch {
        Write-Log "Error checking OneDrive installation: $_" -Level Error
    }
}

function Get-OneDriveSyncStatus {
    Write-Log "Checking OneDrive sync status"
    
    if (!$script:DetectionResults.OneDriveRunning) {
        Write-Log "OneDrive is not running, cannot check sync status" -Level Warning
        return
    }
    
    try {
        # Download OneDriveLib.dll if needed
        $oneDriveLibPath = Join-Path $LogPath "OneDriveLib.dll"
        
        if (!(Test-Path $oneDriveLibPath)) {
            Write-Log "Downloading OneDriveLib.dll"
            
            # Determine Windows version for correct DLL
            $osVersion = [System.Environment]::OSVersion.Version
            $isWindows11 = $osVersion.Major -eq 10 -and $osVersion.Build -ge 22000
            
            $dllUrl = if ($isWindows11) {
                "https://github.com/rodneyviana/ODSyncService/raw/main/Binaries/PowerShell/OneDriveLib.dll"
            }
            else {
                "https://github.com/rodneyviana/ODSyncService/raw/main/Binaries/PowerShell/OneDriveLib.dll"
            }
            
            try {
                Invoke-WebRequest -Uri $dllUrl -OutFile $oneDriveLibPath -UseBasicParsing
                Write-Log "Downloaded OneDriveLib.dll successfully"
            }
            catch {
                Write-Log "Failed to download OneDriveLib.dll: $_" -Level Error
                return
            }
        }
        
        # Load the DLL and check sync status
        try {
            Add-Type -Path $oneDriveLibPath
            
            # Get sync status using user context if running as SYSTEM
            $syncStatus = Invoke-AsUser -ScriptBlock {
                param($dllPath)
                Add-Type -Path $dllPath
                $status = [OneDriveLib.StatusService]::GetStatus()
                return $status
            } -ArgumentList @{dllPath = $oneDriveLibPath}
            
            if ($syncStatus) {
                # Parse sync status
                $statusInfo = $syncStatus | ConvertFrom-Json
                
                switch ($statusInfo.StatusCode) {
                    1 { $script:DetectionResults.SyncStatus = "NotInstalled" }
                    2 { $script:DetectionResults.SyncStatus = "ReadOnly" }
                    3 { $script:DetectionResults.SyncStatus = "Error" }
                    4 { $script:DetectionResults.SyncStatus = "Syncing" }
                    5 { $script:DetectionResults.SyncStatus = "UpToDate" }
                    6 { $script:DetectionResults.SyncStatus = "Paused" }
                    default { $script:DetectionResults.SyncStatus = "Unknown" }
                }
                
                Write-Log "OneDrive sync status: $($script:DetectionResults.SyncStatus)"
            }
        }
        catch {
            Write-Log "Error getting sync status: $_" -Level Error
            
            # Fallback method - check registry
            $syncRootPath = Get-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1" -Name "UserFolder" -ErrorAction SilentlyContinue
            if ($syncRootPath) {
                $script:DetectionResults.SyncStatus = "Configured"
                Write-Log "OneDrive appears to be configured (fallback method)"
            }
        }
    }
    catch {
        Write-Log "Error in Get-OneDriveSyncStatus: $_" -Level Error
    }
}

function Get-KFMStatus {
    Write-Log "Checking Known Folder Move (KFM) status"
    
    try {
        # Check both HKLM and HKCU policies
        $kfmPolicies = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive",
            "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
        )
        
        $kfmEnabled = $false
        
        foreach ($policyPath in $kfmPolicies) {
            if (Test-Path $policyPath) {
                $silentOptIn = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
                if ($silentOptIn -and $silentOptIn.KFMSilentOptIn -eq $TenantID) {
                    $kfmEnabled = $true
                    Write-Log "KFM is enabled via policy at $policyPath"
                    break
                }
            }
        }
        
        $script:DetectionResults.KFMEnabled = $kfmEnabled
        
        # Check which folders are redirected
        if ($kfmEnabled) {
            $userShellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            $desktopPath = (Get-ItemProperty -Path $userShellFolders -Name "Desktop" -ErrorAction SilentlyContinue).Desktop
            $documentsPath = (Get-ItemProperty -Path $userShellFolders -Name "Personal" -ErrorAction SilentlyContinue).Personal
            $picturesPath = (Get-ItemProperty -Path $userShellFolders -Name "My Pictures" -ErrorAction SilentlyContinue)."My Pictures"
            
            $oneDrivePath = $env:OneDrive
            if ($oneDrivePath) {
                if ($desktopPath -like "*$oneDrivePath*") {
                    Write-Log "Desktop folder is redirected to OneDrive"
                }
                if ($documentsPath -like "*$oneDrivePath*") {
                    Write-Log "Documents folder is redirected to OneDrive"
                }
                if ($picturesPath -like "*$oneDrivePath*") {
                    Write-Log "Pictures folder is redirected to OneDrive"
                }
            }
        }
        else {
            Write-Log "KFM is not enabled" -Level Warning
        }
    }
    catch {
        Write-Log "Error checking KFM status: $_" -Level Error
    }
}

function Get-FilesOnDemandStatus {
    Write-Log "Checking Files On-Demand status"
    
    try {
        # Check policy settings
        $fodPolicies = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive",
            "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
        )
        
        $fodEnabled = $false
        
        foreach ($policyPath in $fodPolicies) {
            if (Test-Path $policyPath) {
                $fodSetting = Get-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
                if ($fodSetting -and $fodSetting.FilesOnDemandEnabled -eq 1) {
                    $fodEnabled = $true
                    Write-Log "Files On-Demand is enabled via policy at $policyPath"
                    break
                }
            }
        }
        
        # Also check user settings
        $userSettingsPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1\ScopeIdToMountPointPathCache"
        if (Test-Path $userSettingsPath) {
            $mountPoints = Get-ItemProperty -Path $userSettingsPath -ErrorAction SilentlyContinue
            if ($mountPoints) {
                Write-Log "OneDrive mount points detected - Files On-Demand likely active"
                $fodEnabled = $true
            }
        }
        
        $script:DetectionResults.FilesOnDemandEnabled = $fodEnabled
        
        if (!$fodEnabled) {
            Write-Log "Files On-Demand is not enabled" -Level Warning
        }
    }
    catch {
        Write-Log "Error checking Files On-Demand status: $_" -Level Error
    }
}

function Get-DownloadsFolderStatus {
    Write-Log "Checking Downloads folder redirection status"
    
    try {
        $userShellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
        
        $downloadsPath = Get-ItemProperty -Path $userShellFolders -Name $downloadsGuid -ErrorAction SilentlyContinue
        
        if ($downloadsPath) {
            $currentPath = $downloadsPath.$downloadsGuid
            $oneDrivePath = $env:OneDrive
            
            if ($oneDrivePath -and $currentPath -like "*$oneDrivePath*") {
                $script:DetectionResults.DownloadsFolderRedirected = $true
                Write-Log "Downloads folder is redirected to OneDrive: $currentPath"
            }
            else {
                Write-Log "Downloads folder is not redirected to OneDrive. Current path: $currentPath"
            }
        }
        else {
            Write-Log "Downloads folder registry entry not found"
        }
    }
    catch {
        Write-Log "Error checking Downloads folder status: $_" -Level Error
    }
}

function Get-DiskSpaceStatus {
    Write-Log "Checking disk space for Windows 11 upgrade"
    
    try {
        $systemDrive = $env:SystemDrive
        $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        
        $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)
        $requiredSpaceGB = 32  # Windows 11 requirement
        
        Write-Log "Disk space - Total: ${totalSpaceGB}GB, Free: ${freeSpaceGB}GB, Required: ${requiredSpaceGB}GB"
        
        if ($freeSpaceGB -ge $requiredSpaceGB) {
            $script:DetectionResults.RequiredDiskSpace = $true
            Write-Log "Sufficient disk space available for Windows 11 upgrade"
        }
        else {
            Write-Log "Insufficient disk space for Windows 11 upgrade. Need additional $([math]::Round($requiredSpaceGB - $freeSpaceGB, 2))GB" -Level Warning
        }
    }
    catch {
        Write-Log "Error checking disk space: $_" -Level Error
    }
}
#endregion

#region Remediation Functions
function Enable-KFM {
    Write-Log "Enabling Known Folder Move (KFM)"
    
    try {
        # Create policy key if it doesn't exist
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        if (!(Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
            Write-Log "Created OneDrive policy registry key"
        }
        
        # Set KFM policies
        $policies = @{
            "KFMSilentOptIn" = $TenantID
            "KFMSilentOptInWithNotification" = 0
            "KFMOptInWithWizard" = $TenantID
            "KFMBlockOptOut" = 1
        }
        
        foreach ($policy in $policies.GetEnumerator()) {
            Set-ItemProperty -Path $policyPath -Name $policy.Key -Value $policy.Value -Force
            Write-Log "Set policy: $($policy.Key) = $($policy.Value)"
        }
        
        Write-Log "KFM enabled successfully"
        return $true
    }
    catch {
        Write-Log "Error enabling KFM: $_" -Level Error
        return $false
    }
}

function Enable-FilesOnDemand {
    Write-Log "Enabling Files On-Demand"
    
    try {
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        
        # Enable Files On-Demand
        Set-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -Value 1 -Force
        Write-Log "Set policy: FilesOnDemandEnabled = 1"
        
        # Also set user preference
        $userPath = "HKCU:\Software\Microsoft\OneDrive"
        if (Test-Path $userPath) {
            Set-ItemProperty -Path $userPath -Name "EnableAllOSFilesOnDemand" -Value 1 -Force -ErrorAction SilentlyContinue
            Write-Log "Enabled Files On-Demand in user settings"
        }
        
        Write-Log "Files On-Demand enabled successfully"
        return $true
    }
    catch {
        Write-Log "Error enabling Files On-Demand: $_" -Level Error
        return $false
    }
}

function Enable-DownloadsFolderRedirection {
    Write-Log "Enabling Downloads folder redirection"
    
    if (!$IncludeDownloadsFolder) {
        Write-Log "Downloads folder redirection skipped by parameter"
        return $true
    }
    
    try {
        # Get OneDrive path
        $oneDrivePath = $env:OneDrive
        if (!$oneDrivePath) {
            Write-Log "OneDrive environment variable not found" -Level Warning
            return $false
        }
        
        # Create Downloads folder in OneDrive
        $oneDriveDownloads = Join-Path $oneDrivePath "Downloads"
        if (!(Test-Path $oneDriveDownloads)) {
            New-Item -Path $oneDriveDownloads -ItemType Directory -Force | Out-Null
            Write-Log "Created Downloads folder in OneDrive: $oneDriveDownloads"
        }
        
        # Update registry for folder redirection
        $userShellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
        
        Set-ItemProperty -Path $userShellFolders -Name $downloadsGuid -Value $oneDriveDownloads -Force
        Write-Log "Updated Downloads folder registry to: $oneDriveDownloads"
        
        # Also update the non-expanded version
        $shellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        Set-ItemProperty -Path $shellFolders -Name $downloadsGuid -Value $oneDriveDownloads -Force
        
        # Move existing files if folder exists
        $defaultDownloads = [Environment]::GetFolderPath('UserProfile') + "\Downloads"
        if ((Test-Path $defaultDownloads) -and ($defaultDownloads -ne $oneDriveDownloads)) {
            Write-Log "Moving existing files from $defaultDownloads to $oneDriveDownloads"
            
            try {
                # Use robocopy for reliable file moving
                $robocopyArgs = @(
                    "`"$defaultDownloads`"",
                    "`"$oneDriveDownloads`"",
                    "/E",       # Copy subdirectories including empty ones
                    "/MOVE",    # Move files and directories
                    "/R:3",     # Retry 3 times
                    "/W:1",     # Wait 1 second between retries
                    "/NP",      # No progress
                    "/LOG+:`"$LogPath\Downloads_Migration.log`""
                )
                
                $robocopyCmd = "robocopy.exe $($robocopyArgs -join ' ')"
                $result = Invoke-Expression $robocopyCmd
                
                Write-Log "Downloads folder migration completed"
            }
            catch {
                Write-Log "Error moving Downloads folder contents: $_" -Level Warning
            }
        }
        
        Write-Log "Downloads folder redirection enabled successfully"
        return $true
    }
    catch {
        Write-Log "Error enabling Downloads folder redirection: $_" -Level Error
        return $false
    }
}

function Start-OneDriveIfNotRunning {
    Write-Log "Checking if OneDrive needs to be started"
    
    if ($script:DetectionResults.OneDriveRunning) {
        Write-Log "OneDrive is already running"
        return $true
    }
    
    try {
        # Find OneDrive executable
        $oneDrivePaths = @(
            "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
            "$env:PROGRAMFILES(x86)\Microsoft OneDrive\OneDrive.exe",
            "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
        )
        
        $oneDriveExe = $oneDrivePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        
        if ($oneDriveExe) {
            Write-Log "Starting OneDrive from: $oneDriveExe"
            
            # Start OneDrive in user context
            Invoke-AsUser -ScriptBlock {
                param($exePath)
                Start-Process -FilePath $exePath -ArgumentList "/background" -WindowStyle Hidden
            } -ArgumentList @{exePath = $oneDriveExe}
            
            # Wait for OneDrive to start
            $maxWait = 30
            $waited = 0
            while ($waited -lt $maxWait) {
                Start-Sleep -Seconds 2
                $waited += 2
                
                if (Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue) {
                    Write-Log "OneDrive started successfully"
                    return $true
                }
            }
            
            Write-Log "OneDrive did not start within timeout period" -Level Warning
            return $false
        }
        else {
            Write-Log "OneDrive executable not found" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error starting OneDrive: $_" -Level Error
        return $false
    }
}

function Optimize-DiskSpace {
    Write-Log "Optimizing disk space with Files On-Demand"
    
    if (!$script:DetectionResults.FilesOnDemandEnabled) {
        Write-Log "Files On-Demand is not enabled, skipping optimization" -Level Warning
        return $false
    }
    
    try {
        $oneDrivePath = $env:OneDrive
        if (!$oneDrivePath -or !(Test-Path $oneDrivePath)) {
            Write-Log "OneDrive folder not found" -Level Warning
            return $false
        }
        
        Write-Log "Converting files to online-only in: $oneDrivePath"
        
        # Convert files to online-only using attrib command
        # Note: This is a simplified version. In production, you might want to be more selective
        $attribCmd = "attrib +U -P /s `"$oneDrivePath\*.*`""
        
        Write-Log "Executing: $attribCmd"
        $result = cmd /c $attribCmd 2>&1
        
        # Calculate space saved
        $freeSpaceAfter = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace / 1GB, 2)
        Write-Log "Disk optimization completed. Free space: ${freeSpaceAfter}GB"
        
        return $true
    }
    catch {
        Write-Log "Error optimizing disk space: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Execution
function Main {
    Write-Log "=== OneDrive Detection and Remediation Script Started ==="
    Write-Log "Parameters - TenantID: $TenantID, RemediationMode: $RemediationMode, IncludeDownloadsFolder: $IncludeDownloadsFolder"
    Write-Log "Running as: $($env:USERNAME), IsSystem: $($script:DetectionResults.RunningAsSystem)"
    
    # Phase 1: Detection
    Write-Log "--- Phase 1: Detection ---"
    
    Get-OneDriveInstallInfo
    
    if ($script:DetectionResults.OneDriveInstalled) {
        Get-OneDriveSyncStatus
        Get-KFMStatus
        Get-FilesOnDemandStatus
        Get-DownloadsFolderStatus
    }
    
    Get-DiskSpaceStatus
    
    # Generate detection summary
    Write-Log "--- Detection Summary ---"
    $script:DetectionResults.GetEnumerator() | ForEach-Object {
        Write-Log "$($_.Key): $($_.Value)"
    }
    
    # Determine if remediation is needed
    $remediationNeeded = $false
    
    if (!$script:DetectionResults.OneDriveInstalled) {
        Write-Log "Remediation needed: OneDrive not installed" -Level Warning
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    elseif (!$script:DetectionResults.OneDriveRunning) {
        Write-Log "Remediation needed: OneDrive not running" -Level Warning
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    elseif (!$script:DetectionResults.KFMEnabled) {
        Write-Log "Remediation needed: KFM not enabled" -Level Warning
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    elseif (!$script:DetectionResults.FilesOnDemandEnabled) {
        Write-Log "Remediation needed: Files On-Demand not enabled" -Level Warning
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    elseif ($IncludeDownloadsFolder -and !$script:DetectionResults.DownloadsFolderRedirected) {
        Write-Log "Remediation needed: Downloads folder not redirected" -Level Warning
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    
    if (!$remediationNeeded) {
        Write-Log "No remediation needed - all checks passed!" -Level Info
        $script:ExitCode = 0
    }
    
    # Phase 2: Remediation (if enabled and needed)
    if ($RemediationMode -and $remediationNeeded) {
        Write-Log "--- Phase 2: Remediation ---"
        
        $remediationSuccess = $true
        
        # Start OneDrive if not running
        if ($script:DetectionResults.OneDriveInstalled -and !$script:DetectionResults.OneDriveRunning) {
            if (!(Start-OneDriveIfNotRunning)) {
                $remediationSuccess = $false
            }
        }
        
        # Enable KFM
        if (!$script:DetectionResults.KFMEnabled) {
            if (!(Enable-KFM)) {
                $remediationSuccess = $false
            }
        }
        
        # Enable Files On-Demand
        if (!$script:DetectionResults.FilesOnDemandEnabled) {
            if (!(Enable-FilesOnDemand)) {
                $remediationSuccess = $false
            }
        }
        
        # Enable Downloads folder redirection
        if ($IncludeDownloadsFolder -and !$script:DetectionResults.DownloadsFolderRedirected) {
            if (!(Enable-DownloadsFolderRedirection)) {
                $remediationSuccess = $false
            }
        }
        
        # Optimize disk space if needed
        if (!$script:DetectionResults.RequiredDiskSpace -and $script:DetectionResults.FilesOnDemandEnabled) {
            Write-Log "Attempting to free up disk space"
            Optimize-DiskSpace
        }
        
        if ($remediationSuccess) {
            Write-Log "Remediation completed successfully"
            $script:ExitCode = 0
        }
        else {
            Write-Log "Remediation completed with errors" -Level Warning
            $script:ExitCode = 2
        }
    }
    
    # Final summary
    Write-Log "=== Script Completed ==="
    Write-Log "Exit Code: $script:ExitCode"
    Write-Log "Log file: $script:LogFile"
    
    # Output for RMM console
    if ($script:ExitCode -eq 0) {
        Write-Output "SUCCESS: OneDrive configuration is correct"
    }
    elseif ($script:ExitCode -eq 1) {
        Write-Output "DETECTION: OneDrive configuration issues found"
    }
    else {
        Write-Output "REMEDIATION: OneDrive remediation completed with warnings"
    }
    
    # Return detection results as JSON for RMM parsing
    $script:DetectionResults | ConvertTo-Json -Compress
    
    exit $script:ExitCode
}

# Execute main function
Main