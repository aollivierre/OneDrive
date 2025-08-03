#Requires -Version 5.1

<#
.SYNOPSIS
    SYSTEM-aware OneDrive detection script for RMM
.DESCRIPTION
    v4 - Properly handles SYSTEM context by checking logged-in user paths
.NOTES
    Designed to work correctly when run as SYSTEM via RMM
#>

param(
    [string]$LogPath = "$env:TEMP\OneDrive-Detection-$(Get-Date -Format 'yyyyMMdd-HHmmss').log",
    [switch]$EnableDebug = $false
)

# Initialize
$VerbosePreference = 'SilentlyContinue'
$script:exitCode = 0
$script:remediationNeeded = $false
$script:detectionResults = @{}

#region Enhanced Logging
function Write-DetectionLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG', 'SUCCESS')]
        [string]$Level = 'INFO',
        [switch]$IncludeContext = $false
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    
    # Get caller context
    $caller = (Get-PSCallStack)[1]
    $lineNumber = $caller.ScriptLineNumber
    $function = $caller.FunctionName
    if ($function -eq '<ScriptBlock>') { $function = 'Main' }
    
    # Build log entry
    if ($IncludeContext -or $EnableDebug) {
        $logEntry = "$timestamp [$Level] [${function}:${lineNumber}] $Message"
    } else {
        $logEntry = "$timestamp [$Level] $Message"
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logEntry -Force -ErrorAction SilentlyContinue
    
    # Console output with color
    $color = switch ($Level) {
        'ERROR'   { 'Red' }
        'WARNING' { 'Yellow' }
        'DEBUG'   { 'Gray' }
        'SUCCESS' { 'Green' }
        default   { 'White' }
    }
    
    if ($Level -ne 'DEBUG' -or $EnableDebug) {
        Write-Host $Message -ForegroundColor $color
    }
}

function Write-ErrorDetails {
    param($ErrorRecord)
    Write-DetectionLog "ERROR: $($ErrorRecord.Exception.Message)" -Level ERROR -IncludeContext
    Write-DetectionLog "Stack Trace: $($ErrorRecord.ScriptStackTrace)" -Level ERROR
    Write-DetectionLog "Error Type: $($ErrorRecord.Exception.GetType().FullName)" -Level ERROR
}
#endregion

#region SYSTEM Context Detection
function Get-LoggedInUser {
    Write-DetectionLog "Detecting logged-in user..." -Level DEBUG
    
    # Check if running as SYSTEM
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $currentUser.IsSystem
    
    Write-DetectionLog "Current context: $($currentUser.Name) (IsSystem: $isSystem)" -Level DEBUG
    
    if ($isSystem) {
        # Running as SYSTEM - need to find logged-in user
        try {
            # Method 1: Check explorer.exe owner
            $explorer = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | 
                Select-Object -First 1
            
            if ($explorer) {
                $owner = $explorer.GetOwner()
                if ($owner.ReturnValue -eq 0) {
                    $username = $owner.User
                    Write-DetectionLog "Found logged-in user via explorer.exe: $username" -Level SUCCESS
                    return $username
                }
            }
            
            # Method 2: Check active console session
            $sessions = quser 2>$null | Where-Object { $_ -match '^\s*(\S+)\s+console' }
            if ($sessions) {
                $username = ($sessions -split '\s+')[1]
                Write-DetectionLog "Found logged-in user via console session: $username" -Level SUCCESS
                return $username
            }
        }
        catch {
            Write-ErrorDetails $_
        }
        
        Write-DetectionLog "No logged-in user found while running as SYSTEM" -Level WARNING
        return $null
    }
    else {
        # Not SYSTEM - return current user
        $username = $env:USERNAME
        Write-DetectionLog "Running as user: $username" -Level DEBUG
        return $username
    }
}

function Get-UserProfilePath {
    param([string]$Username)
    
    if (-not $Username) { return $null }
    
    # Try to get user profile path
    $profilePath = $null
    
    # Method 1: Check standard location
    $standardPath = "C:\Users\$Username"
    if (Test-Path $standardPath) {
        $profilePath = $standardPath
    }
    else {
        # Method 2: Query registry
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
            if (Test-Path $regPath) {
                $profilePath = (Get-ItemProperty $regPath).ProfileImagePath
            }
        }
        catch {
            Write-DetectionLog "Failed to get profile path from registry: $_" -Level DEBUG
        }
    }
    
    Write-DetectionLog "User profile path: $profilePath" -Level DEBUG
    return $profilePath
}
#endregion

Write-DetectionLog "=== Starting OneDrive Detection v4 (SYSTEM-Aware) ===" -Level INFO -IncludeContext
Write-DetectionLog "Running as: $env:USERNAME" -Level INFO
Write-DetectionLog "Computer: $env:COMPUTERNAME" -Level INFO
Write-DetectionLog "Debug mode: $EnableDebug" -Level INFO

try {
    # Get the actual user context
    $targetUser = Get-LoggedInUser
    $userProfile = if ($targetUser) { Get-UserProfilePath -Username $targetUser } else { $env:USERPROFILE }
    
    if (-not $userProfile -or -not (Test-Path $userProfile)) {
        Write-DetectionLog "Could not determine user profile path" -Level ERROR
        $script:remediationNeeded = $true
        $script:detectionResults.Error = "No user profile found"
        throw "No valid user profile path found"
    }
    
    Write-DetectionLog "Target user: $targetUser" -Level INFO
    Write-DetectionLog "User profile: $userProfile" -Level INFO
    
    # 1. Check OneDrive Installation
    Write-DetectionLog "Checking OneDrive installation..." -Level INFO
    
    $oneDrivePaths = @(
        "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
        "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
        "$userProfile\AppData\Local\Microsoft\OneDrive\OneDrive.exe"  # User-specific path
    )
    
    $oneDriveInstalled = $false
    foreach ($path in $oneDrivePaths) {
        Write-DetectionLog "Checking: $path" -Level DEBUG
        if (Test-Path $path) {
            $oneDriveInstalled = $true
            $script:detectionResults.OneDrivePath = $path
            
            # Get OneDrive version
            $versionInfo = (Get-Item $path).VersionInfo
            $script:detectionResults.OneDriveVersion = $versionInfo.FileVersion
            
            Write-DetectionLog "OneDrive found at: $path (Version: $($versionInfo.FileVersion))" -Level SUCCESS
            
            # Check if version supports Files On-Demand by default
            $versionParts = $versionInfo.FileVersion.Split('.')
            if ([int]$versionParts[0] -ge 23 -and [int]$versionParts[1] -ge 66) {
                Write-DetectionLog "OneDrive version supports Files On-Demand by default" -Level SUCCESS
                $script:detectionResults.FilesOnDemandDefault = $true
            } else {
                $script:detectionResults.FilesOnDemandDefault = $false
            }
            break
        }
    }
    
    if (-not $oneDriveInstalled) {
        Write-DetectionLog "OneDrive is NOT installed" -Level ERROR
        $script:remediationNeeded = $true
        $script:detectionResults.OneDriveInstalled = $false
    } else {
        $script:detectionResults.OneDriveInstalled = $true
    }
    
    # 2. Check if OneDrive is Running
    Write-DetectionLog "Checking if OneDrive is running..." -Level INFO
    
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($oneDriveProcess) {
        Write-DetectionLog "OneDrive is running (PID: $($oneDriveProcess.Id))" -Level SUCCESS
        $script:detectionResults.OneDriveRunning = $true
    } else {
        Write-DetectionLog "OneDrive is NOT running" -Level WARNING
        $script:remediationNeeded = $true
        $script:detectionResults.OneDriveRunning = $false
    }
    
    # 3. Check Tenant ID (from user's registry)
    Write-DetectionLog "Checking tenant ID configuration..." -Level INFO
    
    # When running as SYSTEM, we need to load user's registry hive
    $detectedTenantId = $null
    
    if ($targetUser -and $currentUser.IsSystem) {
        # Running as SYSTEM - need to access user's registry
        try {
            # Get user SID
            $userSID = (New-Object System.Security.Principal.NTAccount($targetUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            
            # Check if user hive is already loaded
            $userRegPath = "Registry::HKEY_USERS\$userSID\Software\Microsoft\OneDrive\Accounts\Business1"
            
            if (Test-Path $userRegPath) {
                $keys = Get-ItemProperty -Path $userRegPath -ErrorAction SilentlyContinue
                if ($keys.ConfiguredTenantId) {
                    $detectedTenantId = $keys.ConfiguredTenantId
                    Write-DetectionLog "Found tenant ID in user registry: $detectedTenantId" -Level SUCCESS
                }
            }
        }
        catch {
            Write-DetectionLog "Could not access user registry: $_" -Level WARNING
        }
    }
    else {
        # Running as user - use HKCU
        $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
        if (Test-Path $businessPath) {
            $keys = Get-ItemProperty -Path $businessPath -ErrorAction SilentlyContinue
            if ($keys.ConfiguredTenantId) {
                $detectedTenantId = $keys.ConfiguredTenantId
                Write-DetectionLog "Found tenant ID: $detectedTenantId" -Level SUCCESS
            }
        }
    }
    
    if ($detectedTenantId) {
        $script:detectionResults.TenantId = $detectedTenantId
        $script:detectionResults.TenantIdConfigured = $true
        
        # Check if it's also in policy
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        if (Test-Path $policyPath) {
            $kfmValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
            if ($kfmValue -and $kfmValue.KFMSilentOptIn -eq $detectedTenantId) {
                Write-DetectionLog "Tenant ID also configured in policy" -Level SUCCESS
            } else {
                Write-DetectionLog "Tenant ID not in policy (may need remediation for new users)" -Level WARNING
            }
        }
    } else {
        Write-DetectionLog "Tenant ID not found" -Level ERROR
        $script:remediationNeeded = $true
        $script:detectionResults.TenantIdConfigured = $false
    }
    
    # Continue with other checks...
    # [Rest of the detection logic remains the same]
    
    # 4. Check Files On-Demand
    Write-DetectionLog "Checking Files On-Demand configuration..." -Level INFO
    
    $fodEnabled = $false
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    if (Test-Path $policyPath) {
        $fodValue = Get-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
        if ($fodValue -and $fodValue.FilesOnDemandEnabled -eq 1) {
            Write-DetectionLog "Files On-Demand is enabled in policy" -Level SUCCESS
            $fodEnabled = $true
        }
    }
    
    # Check if Files On-Demand is on by default
    if (-not $fodEnabled -and $script:detectionResults.FilesOnDemandDefault) {
        Write-DetectionLog "Files On-Demand is enabled by default (OneDrive version 23.066+)" -Level SUCCESS
        $fodEnabled = $true
    }
    
    $script:detectionResults.FilesOnDemandEnabled = $fodEnabled
    
    # 5. Check Storage Sense
    Write-DetectionLog "Checking Storage Sense configuration..." -Level INFO
    
    $storageSenseConfigured = $false
    $storagePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
    
    if (Test-Path $storagePolicyPath) {
        $storageSenseEnabled = Get-ItemProperty -Path $storagePolicyPath -Name "AllowStorageSenseGlobal" -ErrorAction SilentlyContinue
        if ($storageSenseEnabled -and $storageSenseEnabled.AllowStorageSenseGlobal -eq 1) {
            Write-DetectionLog "Storage Sense is enabled" -Level SUCCESS
            $storageSenseConfigured = $true
            
            $dehydrationThreshold = Get-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -ErrorAction SilentlyContinue
            if ($dehydrationThreshold) {
                $days = $dehydrationThreshold.ConfigStorageSenseCloudContentDehydrationThreshold
                Write-DetectionLog "Files convert to online-only after $days days" -Level SUCCESS
                $script:detectionResults.StorageSenseDays = $days
            }
        }
    }
    
    $script:detectionResults.StorageSenseEnabled = $storageSenseConfigured
    
    # Final Result
    Write-DetectionLog "`n=== DETECTION SUMMARY ===" -Level INFO
    Write-DetectionLog "OneDrive Installed: $($script:detectionResults.OneDriveInstalled)" -Level INFO
    Write-DetectionLog "OneDrive Running: $($script:detectionResults.OneDriveRunning)" -Level INFO
    Write-DetectionLog "Tenant ID Configured: $($script:detectionResults.TenantIdConfigured)" -Level INFO
    Write-DetectionLog "Files On-Demand Enabled: $($script:detectionResults.FilesOnDemandEnabled)" -Level INFO
    Write-DetectionLog "Storage Sense Enabled: $($script:detectionResults.StorageSenseEnabled)" -Level INFO
    
    if ($script:remediationNeeded) {
        Write-DetectionLog "`nREMEDIATION NEEDED" -Level ERROR
        $script:exitCode = 1
    } else {
        Write-DetectionLog "`nCONFIGURATION OK - No remediation needed" -Level SUCCESS
        $script:exitCode = 0
    }
}
catch {
    Write-ErrorDetails $_
    $script:exitCode = 1
}

Write-DetectionLog "Detection completed. Exit code: $script:exitCode" -Level INFO
Write-DetectionLog "Log saved to: $LogPath" -Level INFO

# Return exit code for RMM
exit $script:exitCode