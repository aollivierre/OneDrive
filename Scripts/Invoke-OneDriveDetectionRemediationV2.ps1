#requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive OneDrive for Business detection and remediation script V2 - Enhanced with community best practices.

.DESCRIPTION
    This enhanced version incorporates best practices from:
    - CyberDrain's monitoring approach with process impersonation
    - Jos Lieben's silent configuration and folder redirection
    - Enhanced logging and error handling
    
    Features:
    - Robust user impersonation from SYSTEM context
    - JSON-based inter-process communication
    - VBS wrapper for silent execution
    - x86/x64 architecture handling
    - Downloads folder redirection with content migration

.PARAMETER TenantID
    The Azure AD Tenant ID for OneDrive configuration (required for KFM)

.PARAMETER RemediationMode
    Enable remediation mode to fix detected issues (default: $false for detection only)

.PARAMETER IncludeDownloadsFolder
    Include Downloads folder in KFM redirection (default: $true)

.PARAMETER CopyFolderContents
    Copy existing folder contents during redirection (default: $false - use with caution!)

.PARAMETER CreateVBSWrapper
    Create VBS wrapper for silent execution at logon (default: $false)

.PARAMETER LogPath
    Path for detailed logging (default: C:\ProgramData\OneDriveRemediation)

.EXAMPLE
    .\Invoke-OneDriveDetectionRemediationV2.ps1 -TenantID "12345678-1234-1234-1234-123456789012"
    
.EXAMPLE
    .\Invoke-OneDriveDetectionRemediationV2.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RemediationMode $true -CopyFolderContents $true

.NOTES
    Version: 2.0.0
    Incorporates community best practices from CyberDrain, Jos Lieben, and others
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
    [bool]$CopyFolderContents = $false,
    
    [Parameter()]
    [bool]$CreateVBSWrapper = $false,
    
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
    SyncStatusString = "Unknown"
    KFMEnabled = $false
    FilesOnDemandEnabled = $false
    DownloadsFolderRedirected = $false
    RequiredDiskSpace = $false
    UserContext = $env:USERNAME
    RunningAsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
    OSArchitecture = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }
    PSArchitecture = if ([Environment]::Is64BitProcess) { "64-bit" } else { "32-bit" }
}

# Create log directory
if (!(Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$script:LogFile = Join-Path $LogPath "OneDriveRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:JsonStatusFile = Join-Path $LogPath "OneDriveStatus.json"
#endregion

#region Architecture Handling (from Jos Lieben)
# Ensure we're running in 64-bit PowerShell on 64-bit OS
if (!([Environment]::Is64BitProcess) -and [Environment]::Is64BitOperatingSystem) {
    Write-Host "Running 32-bit PowerShell on 64-bit OS, restarting as 64-bit process..."
    $arguments = "-NoProfile -ExecutionPolicy ByPass -WindowStyle Hidden -File `"" + $MyInvocation.MyCommand.Definition + "`""
    
    # Add all parameters
    foreach ($param in $PSBoundParameters.GetEnumerator()) {
        if ($param.Value -is [bool]) {
            $arguments += " -$($param.Key) `$$($param.Value)"
        }
        else {
            $arguments += " -$($param.Key) `"$($param.Value)`""
        }
    }
    
    $path = Join-Path $Env:SystemRoot -ChildPath "\sysnative\WindowsPowerShell\v1.0\powershell.exe"
    Start-Process $path -ArgumentList $arguments -Verb Open -Wait
    exit $LASTEXITCODE
}
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

#region CyberDrain's Process Impersonation
$ProcessImpersonationSource = @'
using System;  
using System.Runtime.InteropServices;

namespace murrayju.ProcessExtensions  
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;
        private const int CREATE_NEW_CONSOLE = 0x00000010;
        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
            return true;
        }
    }
}
'@
#endregion

#region OneDrive DLL Management
function Get-OneDriveLib {
    Write-Log "Checking for OneDriveLib.dll"
    
    $dllPath = Join-Path $LogPath "OneDriveLib.dll"
    
    if (!(Test-Path $dllPath)) {
        Write-Log "Downloading OneDriveLib.dll from GitHub"
        
        # Use the official GitHub repo URL from CyberDrain
        $dllUrl = "https://raw.githubusercontent.com/rodneyviana/ODSyncService/master/Binaries/PowerShell/OneDriveLib.dll"
        
        try {
            Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing
            Write-Log "Downloaded OneDriveLib.dll successfully"
            
            # Unblock the file
            Unblock-File -Path $dllPath
        }
        catch {
            Write-Log "Failed to download OneDriveLib.dll: $_" -Level Error
            return $null
        }
    }
    
    return $dllPath
}
#endregion

#region OneDrive Detection Functions
function Get-OneDriveInstallInfo {
    Write-Log "Checking OneDrive installation"
    
    try {
        # Check for OneDrive executable in all possible locations
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
            
            return $oneDriveExe
        }
        else {
            Write-Log "OneDrive is not installed" -Level Warning
            return $null
        }
    }
    catch {
        Write-Log "Error checking OneDrive installation: $_" -Level Error
        return $null
    }
}

function Get-OneDriveSyncStatusV2 {
    Write-Log "Checking OneDrive sync status using CyberDrain method"
    
    if (!$script:DetectionResults.OneDriveRunning) {
        Write-Log "OneDrive is not running, cannot check sync status" -Level Warning
        return
    }
    
    try {
        # Get OneDriveLib.dll
        $dllPath = Get-OneDriveLib
        if (!$dllPath) {
            return
        }
        
        # Check if we have a logged-in user
        $activeUser = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName -ErrorAction SilentlyContinue
        
        if (!$activeUser -and $script:DetectionResults.RunningAsSystem) {
            Write-Log "No user logged in and running as SYSTEM" -Level Warning
            $script:DetectionResults.SyncStatus = "NoUserLoggedIn"
            return
        }
        
        # Compile the process impersonation code
        Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $ProcessImpersonationSource -Language CSharp
        
        # Create the script block to run in user context
        $scriptBlock = {
            Unblock-File 'C:\ProgramData\OneDriveRemediation\OneDriveLib.dll'
            Import-Module 'C:\ProgramData\OneDriveRemediation\OneDriveLib.dll'
            $status = Get-ODStatus | ConvertTo-Json
            $status | Out-File 'C:\ProgramData\OneDriveRemediation\OneDriveStatus.json' -Force
        }
        
        # Execute in user context if running as SYSTEM
        if ($script:DetectionResults.RunningAsSystem) {
            Write-Log "Running sync status check in user context"
            
            $psPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe'
            $command = "-NoProfile -ExecutionPolicy Bypass -Command `"$($scriptBlock.ToString())`""
            
            [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($psPath, $command, 'C:\Windows\System32\WindowsPowerShell\v1.0', $false)
            
            # Wait for the process to complete
            Start-Sleep -Seconds 5
        }
        else {
            # Running as user, execute directly
            Write-Log "Running sync status check directly"
            & $scriptBlock
        }
        
        # Read the status file
        if (Test-Path $script:JsonStatusFile) {
            $statusData = Get-Content $script:JsonStatusFile -Raw | ConvertFrom-Json
            
            # Parse status similar to CyberDrain
            $errorList = @('NotInstalled', 'ReadOnly', 'Error', 'OndemandOrUnknown')
            $statusErrors = @()
            
            foreach ($status in $statusData.value) {
                if ($status.StatusString -in $errorList) {
                    $statusErrors += "$($status.LocalPath) is in state $($status.StatusString)"
                }
                
                # Set primary status from first entry
                if (!$script:DetectionResults.SyncStatusString) {
                    $script:DetectionResults.SyncStatusString = $status.StatusString
                    
                    # Map to our status codes
                    switch ($status.StatusString) {
                        'NotInstalled' { $script:DetectionResults.SyncStatus = "NotInstalled" }
                        'ReadOnly' { $script:DetectionResults.SyncStatus = "ReadOnly" }
                        'Error' { $script:DetectionResults.SyncStatus = "Error" }
                        'OndemandOrUnknown' { $script:DetectionResults.SyncStatus = "Unknown" }
                        'UpToDate' { $script:DetectionResults.SyncStatus = "UpToDate" }
                        'Syncing' { $script:DetectionResults.SyncStatus = "Syncing" }
                        'Paused' { $script:DetectionResults.SyncStatus = "Paused" }
                        default { $script:DetectionResults.SyncStatus = "Unknown" }
                    }
                }
            }
            
            if ($statusErrors.Count -eq 0) {
                Write-Log "OneDrive sync status: Healthy"
            }
            else {
                Write-Log "OneDrive sync errors detected:" -Level Warning
                $statusErrors | ForEach-Object { Write-Log "  $_" -Level Warning }
            }
        }
        else {
            Write-Log "Status file not found, OneDrive may not be properly configured" -Level Warning
        }
    }
    catch {
        Write-Log "Error getting sync status: $_" -Level Error
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
        if ($kfmEnabled -or !$script:DetectionResults.RunningAsSystem) {
            $userShellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            $desktopPath = (Get-ItemProperty -Path $userShellFolders -Name "Desktop" -ErrorAction SilentlyContinue).Desktop
            $documentsPath = (Get-ItemProperty -Path $userShellFolders -Name "Personal" -ErrorAction SilentlyContinue).Personal
            $picturesPath = (Get-ItemProperty -Path $userShellFolders -Name "My Pictures" -ErrorAction SilentlyContinue)."My Pictures"
            
            $oneDrivePath = $env:OneDrive
            if ($oneDrivePath) {
                $redirectedFolders = @()
                if ($desktopPath -like "*$oneDrivePath*") {
                    $redirectedFolders += "Desktop"
                }
                if ($documentsPath -like "*$oneDrivePath*") {
                    $redirectedFolders += "Documents"
                }
                if ($picturesPath -like "*$oneDrivePath*") {
                    $redirectedFolders += "Pictures"
                }
                
                if ($redirectedFolders.Count -gt 0) {
                    Write-Log "Folders redirected to OneDrive: $($redirectedFolders -join ', ')"
                }
            }
        }
        
        if (!$kfmEnabled) {
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
        if ($script:DetectionResults.RunningAsSystem) {
            Write-Log "Running as SYSTEM - Downloads folder check requires user context"
            return
        }
        
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
            "SilentAccountConfig" = 1  # Added from Jos Lieben's script
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
    
    if ($script:DetectionResults.RunningAsSystem) {
        Write-Log "Running as SYSTEM - Downloads folder redirection requires user context" -Level Warning
        return $false
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
        $shellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        $downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
        
        Set-ItemProperty -Path $userShellFolders -Name $downloadsGuid -Value $oneDriveDownloads -Force
        Set-ItemProperty -Path $shellFolders -Name $downloadsGuid -Value $oneDriveDownloads -Force
        
        Write-Log "Updated Downloads folder registry to: $oneDriveDownloads"
        
        # Handle content migration if requested
        if ($CopyFolderContents) {
            $defaultDownloads = [Environment]::GetFolderPath('UserProfile') + "\Downloads"
            
            if ((Test-Path $defaultDownloads) -and ($defaultDownloads -ne $oneDriveDownloads)) {
                Write-Log "Copying existing files from $defaultDownloads to $oneDriveDownloads"
                
                try {
                    # Use robocopy for reliable file copying (from Jos Lieben approach)
                    $robocopyArgs = @(
                        "`"$defaultDownloads`"",
                        "`"$oneDriveDownloads`"",
                        "/E",       # Copy subdirectories including empty ones
                        "/Z",       # Restartable mode
                        "/R:3",     # Retry 3 times
                        "/W:1",     # Wait 1 second between retries
                        "/NP",      # No progress
                        "/LOG+:`"$LogPath\Downloads_Copy.log`""
                    )
                    
                    $robocopyCmd = "robocopy.exe $($robocopyArgs -join ' ')"
                    $result = Invoke-Expression $robocopyCmd
                    
                    Write-Log "Downloads folder content copy completed"
                }
                catch {
                    Write-Log "Error copying Downloads folder contents: $_" -Level Warning
                }
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
        # Get OneDrive executable path
        $oneDriveExe = Get-OneDriveInstallInfo
        
        if ($oneDriveExe) {
            Write-Log "Starting OneDrive from: $oneDriveExe"
            
            # Start OneDrive based on context
            if ($script:DetectionResults.RunningAsSystem) {
                # Use process impersonation to start in user context
                $psPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe'
                $command = "-NoProfile -ExecutionPolicy Bypass -Command `"Start-Process -FilePath '$oneDriveExe' -ArgumentList '/background' -WindowStyle Hidden`""
                
                [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($psPath, $command, 'C:\Windows\System32\WindowsPowerShell\v1.0', $false)
            }
            else {
                # Start directly
                Start-Process -FilePath $oneDriveExe -ArgumentList "/background" -WindowStyle Hidden
            }
            
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

function Create-VBSWrapper {
    Write-Log "Creating VBS wrapper for silent execution"
    
    if (!$CreateVBSWrapper) {
        Write-Log "VBS wrapper creation skipped by parameter"
        return
    }
    
    try {
        # From Jos Lieben's script
        $desiredBootScriptFolder = Join-Path $Env:ProgramData -ChildPath "OneDriveRemediation"
        $desiredBootScriptPath = Join-Path $desiredBootScriptFolder -ChildPath "OneDriveAutoConfig.ps1"
        $desiredVBSScriptPath = Join-Path $desiredBootScriptFolder -ChildPath "OneDriveAutoConfig.vbs"
        
        $vbsSilentPSRunner = @"
Dim objShell,objFSO,objFile

Set objShell=CreateObject("WScript.Shell")
Set objFSO=CreateObject("Scripting.FileSystemObject")

strPath=WScript.Arguments.Item(0)

If objFSO.FileExists(strPath) Then
    set objFile=objFSO.GetFile(strPath)
    strCMD="powershell -nologo -executionpolicy ByPass -command " & Chr(34) & "&{" &_
     objFile.ShortPath & "}" & Chr(34) 
    objShell.Run strCMD,0
Else
    WScript.Echo "Failed to find " & strPath
    WScript.Quit
End If
"@
        
        # Create VBS file
        $vbsSilentPSRunner | Out-File $desiredVBSScriptPath -Force -Encoding ASCII
        
        # Copy current script to boot location
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $desiredBootScriptPath -Force
        
        # Register in Run key for current user
        $runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $wscriptPath = Join-Path $env:SystemRoot -ChildPath "System32\wscript.exe"
        $fullRunPath = "`"$wscriptPath`" `"$desiredVBSScriptPath`" `"$desiredBootScriptPath`""
        
        Set-ItemProperty -Path $runPath -Name "OneDriveAutoConfig" -Value $fullRunPath -Force
        
        Write-Log "VBS wrapper created and registered for logon"
    }
    catch {
        Write-Log "Error creating VBS wrapper: $_" -Level Error
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
        
        # Get initial disk space
        $initialFreeSpace = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace / 1GB, 2)
        
        # Convert files to online-only using attrib command
        # +U = Set the 'Unpinned' attribute (online-only)
        # -P = Remove the 'Pinned' attribute (always available offline)
        $attribCmd = "attrib +U -P /s `"$oneDrivePath\*.*`""
        
        Write-Log "Executing: $attribCmd"
        $result = cmd /c $attribCmd 2>&1
        
        # Wait a moment for changes to take effect
        Start-Sleep -Seconds 5
        
        # Calculate space saved
        $freeSpaceAfter = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace / 1GB, 2)
        $spaceSaved = $freeSpaceAfter - $initialFreeSpace
        
        Write-Log "Disk optimization completed. Free space before: ${initialFreeSpace}GB, after: ${freeSpaceAfter}GB, saved: ${spaceSaved}GB"
        
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
    Write-Log "=== OneDrive Detection and Remediation Script V2 Started ==="
    Write-Log "Parameters - TenantID: $TenantID, RemediationMode: $RemediationMode, IncludeDownloadsFolder: $IncludeDownloadsFolder"
    Write-Log "Running as: $($env:USERNAME), IsSystem: $($script:DetectionResults.RunningAsSystem)"
    Write-Log "OS Architecture: $($script:DetectionResults.OSArchitecture), PS Architecture: $($script:DetectionResults.PSArchitecture)"
    
    # Phase 1: Detection
    Write-Log "--- Phase 1: Detection ---"
    
    Get-OneDriveInstallInfo
    
    if ($script:DetectionResults.OneDriveInstalled) {
        Get-OneDriveSyncStatusV2
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
    $remediationReasons = @()
    
    if (!$script:DetectionResults.OneDriveInstalled) {
        $remediationReasons += "OneDrive not installed"
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    elseif (!$script:DetectionResults.OneDriveRunning) {
        $remediationReasons += "OneDrive not running"
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    
    if (!$script:DetectionResults.KFMEnabled) {
        $remediationReasons += "KFM not enabled"
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    
    if (!$script:DetectionResults.FilesOnDemandEnabled) {
        $remediationReasons += "Files On-Demand not enabled"
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    
    if ($IncludeDownloadsFolder -and !$script:DetectionResults.DownloadsFolderRedirected -and !$script:DetectionResults.RunningAsSystem) {
        $remediationReasons += "Downloads folder not redirected"
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    
    # Check sync status
    if ($script:DetectionResults.SyncStatusString -in @('NotInstalled', 'ReadOnly', 'Error')) {
        $remediationReasons += "OneDrive sync status: $($script:DetectionResults.SyncStatusString)"
        $remediationNeeded = $true
        $script:ExitCode = 1
    }
    
    if ($remediationNeeded) {
        Write-Log "Remediation needed for the following reasons:" -Level Warning
        $remediationReasons | ForEach-Object { Write-Log "  - $_" -Level Warning }
    }
    else {
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
        if ($IncludeDownloadsFolder -and !$script:DetectionResults.DownloadsFolderRedirected -and !$script:DetectionResults.RunningAsSystem) {
            if (!(Enable-DownloadsFolderRedirection)) {
                $remediationSuccess = $false
            }
        }
        
        # Create VBS wrapper if requested
        Create-VBSWrapper
        
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
        if ($remediationReasons.Count -gt 0) {
            Write-Output "Issues:"
            $remediationReasons | ForEach-Object { Write-Output "  - $_" }
        }
    }
    else {
        Write-Output "REMEDIATION: OneDrive remediation completed with warnings"
    }
    
    # Return detection results as JSON for RMM parsing
    $script:DetectionResults | ConvertTo-Json -Compress | Out-File (Join-Path $LogPath "DetectionResults.json") -Force
    
    # Clean up old status files
    $oldFiles = Get-ChildItem -Path $LogPath -Filter "*.json" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
    if ($oldFiles) {
        Write-Log "Cleaning up $($oldFiles.Count) old status files"
        $oldFiles | Remove-Item -Force
    }
    
    exit $script:ExitCode
}

# Execute main function
Main