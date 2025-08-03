#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$EnableDebug = $false
)

<#
.SYNOPSIS
    OneDrive Configuration Detection Script for RMM
    
.DESCRIPTION
    Detects OneDrive configuration for disk space optimization.
    Properly handles SYSTEM context by detecting logged-in users.
    
    Exit Codes:
    0 = Properly configured (no remediation needed)
    1 = Remediation required
    
.NOTES
    Version: 1.0
    Author: OneDrive RMM Detection
#>

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Debug output to verify script is running
if ($EnableDebug) {
    Write-Host "[DEBUG] Detection script started with EnableDebug = $EnableDebug" -ForegroundColor Cyan
}

# Initialize variables
$script:exitCode = 1  # Default to remediation required
$script:outputData = @{
    OneDrive_Status = "CHECKING"
    OneDrive_Reason = "Initializing"
    OneDrive_CheckDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    OneDrive_Installed = "NO"
    OneDrive_Running = "NO"
    OneDrive_TenantConfigured = "NO"
    OneDrive_FilesOnDemand = "NO"
    OneDrive_KFMConfigured = "NO"
    OneDrive_StorageSense = "NO"
}

#region Logging Module Configuration
# Import logging module
$LoggingModulePath = Join-Path $PSScriptRoot "..\..\Win11UpgradeScheduler\Win11Detection\src\logging\logging.psm1"
$script:LoggingEnabled = $false
$script:LoggingMode = if ($EnableDebug) { 'EnableDebug' } else { 'SilentMode' }

# Try alternate path if main path doesn't exist
if (-not (Test-Path $LoggingModulePath)) {
    # Try local logging folder
    $LoggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
}

if (Test-Path $LoggingModulePath) {
    try {
        if ($EnableDebug) {
            Write-Host "[DEBUG] Found logging module at: $LoggingModulePath" -ForegroundColor Cyan
        }
        
        Import-Module $LoggingModulePath -Force -WarningAction SilentlyContinue
        $script:LoggingEnabled = $true
        
        if ($EnableDebug) {
            Write-Host "[DEBUG] Logging module imported successfully" -ForegroundColor Cyan
            Write-Host "[DEBUG] LoggingMode: $script:LoggingMode" -ForegroundColor Cyan
        }
        
        # Initialize logging
        Initialize-Logging -BaseLogPath "C:\ProgramData\OneDriveDetection\Logs" `
                          -JobName "OneDriveDetection" `
                          -ParentScriptName "Detect-OneDriveConfiguration-RMM"
        
        # Set global EnableDebug for logging module
        $global:EnableDebug = $EnableDebug
        
        if ($EnableDebug) {
            Write-Host "[DEBUG] Logging initialized. Global EnableDebug = $($global:EnableDebug)" -ForegroundColor Cyan
        }
        
        # Test direct call with debug
        if ($EnableDebug) {
            Write-Host "[DEBUG TEST] About to call Write-AppDeploymentLog with Mode: $script:LoggingMode" -ForegroundColor Yellow
            Write-Host "[DEBUG TEST] Global EnableDebug: $($global:EnableDebug)" -ForegroundColor Yellow
        }
        
        Write-AppDeploymentLog -Message "OneDrive Detection Script Started" -Level "Information" -Mode $script:LoggingMode
        Write-AppDeploymentLog -Message "Computer: $env:COMPUTERNAME" -Level "Information" -Mode $script:LoggingMode
        
        # Get user context
        $userContext = Get-CurrentUser
        Write-AppDeploymentLog -Message "User: $($userContext.UserName) (Type: $($userContext.UserType))" -Level "Information" -Mode $script:LoggingMode
        
        if ($EnableDebug) {
            Write-Host "[DEBUG] First log messages written" -ForegroundColor Cyan
        }
    }
    catch {
        $script:LoggingEnabled = $false
        if ($EnableDebug) {
            Write-Host "[DEBUG ERROR] Logging initialization failed: $_" -ForegroundColor Red
            Write-Host "[DEBUG ERROR] Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
        }
    }
}
else {
    if ($EnableDebug) {
        Write-Host "[DEBUG WARNING] Logging module not found at: $LoggingModulePath" -ForegroundColor Yellow
    }
}
#endregion

#region Helper Functions
function Write-DetectionLog {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Information'
    )
    
    # Get the calling line number
    $callStack = Get-PSCallStack
    $lineNumber = if ($callStack.Count -ge 2) { $callStack[1].ScriptLineNumber } else { 0 }
    
    if ($script:LoggingEnabled) {
        try {
            # Force EnableDebug mode if global debug is set
            $actualMode = if ($global:EnableDebug) { 'EnableDebug' } else { $script:LoggingMode }
            Write-AppDeploymentLog -Message $Message -Level $Level -Mode $actualMode
        }
        catch {
            # Logging failed, continue
        }
    }
    
    # Only write to console if debug enabled (RMM should see clean output only)
    if ($EnableDebug) {
        $color = switch ($Level) {
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Debug' { 'Gray' }
            default { 'White' }
        }
        Write-Host $Message -ForegroundColor $color
    }
}

function Write-DetectionError {
    param(
        [string]$Message,
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    
    $errorMessage = $Message
    if ($ErrorRecord) {
        $errorMessage += " | Error: $($ErrorRecord.Exception.Message)"
        $errorMessage += " | ScriptStackTrace: $($ErrorRecord.ScriptStackTrace)"
    }
    
    Write-DetectionLog -Message $errorMessage -Level 'Error'
}

function Get-LoggedInUser {
    Write-DetectionLog -Message "Detecting logged-in user..." -Level 'Debug'
    
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $currentUser.IsSystem
    
    Write-DetectionLog -Message "Running as: $($currentUser.Name) (IsSystem: $isSystem)" -Level 'Debug'
    
    if ($isSystem) {
        # Running as SYSTEM - find logged-in user
        try {
            # Method 1: Check explorer.exe owner
            $explorer = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
            if ($explorer) {
                $owner = $explorer.GetOwner()
                if ($owner.ReturnValue -eq 0) {
                    Write-DetectionLog -Message "Found user via explorer.exe: $($owner.User)" -Level 'Debug'
                    return $owner.User
                }
            }
            
            # Method 2: Check console session
            $sessions = quser 2>$null | Where-Object { $_ -match '^\s*(\S+)\s+console' }
            if ($sessions) {
                $username = ($sessions -split '\s+')[1]
                Write-DetectionLog -Message "Found user via console: $username" -Level 'Debug'
                return $username
            }
        }
        catch {
            Write-DetectionError -Message "Error detecting logged-in user" -ErrorRecord $_
        }
        
        Write-DetectionLog -Message "No logged-in user found (SYSTEM context)" -Level 'Warning'
        return $null
    }
    else {
        return $env:USERNAME
    }
}

function Get-UserProfilePath {
    param([string]$Username)
    
    if (-not $Username) { return $env:USERPROFILE }
    
    $profilePath = "C:\Users\$Username"
    if (Test-Path $profilePath) {
        return $profilePath
    }
    
    # Try registry if standard path doesn't exist
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        if (Test-Path $regPath) {
            $profilePath = (Get-ItemProperty $regPath).ProfileImagePath
            if (Test-Path $profilePath) { return $profilePath }
        }
    }
    catch {
        Write-DetectionLog -Message "Failed to get profile from registry: $_" -Level 'Debug'
    }
    
    return $null
}

function Get-OneDriveTenantId {
    param([string]$Username)
    
    # Try user registry first
    if ($Username) {
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $userRegPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\OneDrive\Accounts\Business1"
            
            if (Test-Path $userRegPath) {
                $keys = Get-ItemProperty -Path $userRegPath -ErrorAction SilentlyContinue
                if ($keys.ConfiguredTenantId) {
                    return $keys.ConfiguredTenantId
                }
            }
        }
        catch {
            Write-DetectionLog -Message "Could not access user registry: $_" -Level 'Debug'
        }
    }
    
    # Try HKCU if running as user
    $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path $businessPath) {
        $keys = Get-ItemProperty -Path $businessPath -ErrorAction SilentlyContinue
        if ($keys.ConfiguredTenantId) {
            return $keys.ConfiguredTenantId
        }
    }
    
    return $null
}

function Write-ConnectWiseOutput {
    param([hashtable]$Data)
    
    Write-DetectionLog -Message "Writing output" -Level 'Information'
    Write-DetectionLog -Message "Status: $($Data.OneDrive_Status)" -Level 'Information'
    
    # Build output as single string for RMM
    $output = @(
        "OneDrive_Status: $($Data.OneDrive_Status)",
        "OneDrive_Reason: $($Data.OneDrive_Reason)",
        "OneDrive_Installed: $($Data.OneDrive_Installed)",
        "OneDrive_Running: $($Data.OneDrive_Running)",
        "OneDrive_TenantConfigured: $($Data.OneDrive_TenantConfigured)",
        "OneDrive_FilesOnDemand: $($Data.OneDrive_FilesOnDemand)",
        "OneDrive_KFMConfigured: $($Data.OneDrive_KFMConfigured)",
        "OneDrive_StorageSense: $($Data.OneDrive_StorageSense)",
        "OneDrive_CheckDate: $($Data.OneDrive_CheckDate)"
    ) -join "`n"
    
    Write-Output $output
}
#endregion

# Main detection logic
Write-DetectionLog -Message "Starting OneDrive detection" -Level 'Information'

try {
    # Get actual user context
    $targetUser = Get-LoggedInUser
    $userProfile = if ($targetUser) { Get-UserProfilePath -Username $targetUser } else { $env:USERPROFILE }
    
    if (-not $userProfile -or -not (Test-Path $userProfile)) {
        Write-DetectionLog -Message "Could not determine valid user profile path" -Level 'Error'
        $script:outputData.OneDrive_Status = "ERROR"
        $script:outputData.OneDrive_Reason = "No valid user profile found"
        throw "No valid user profile found"
    }
    
    Write-DetectionLog -Message "Target user: $targetUser" -Level 'Information'
    Write-DetectionLog -Message "User profile: $userProfile" -Level 'Information'
    
    # 1. Check OneDrive Installation
    Write-DetectionLog -Message "Checking OneDrive installation..." -Level 'Information'
    
    $oneDrivePaths = @(
        "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
        "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
        "$userProfile\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
    )
    
    $oneDriveFound = $false
    $oneDriveVersion = $null
    
    foreach ($path in $oneDrivePaths) {
        if (Test-Path $path) {
            $versionInfo = (Get-Item $path).VersionInfo
            $oneDriveVersion = $versionInfo.FileVersion
            Write-DetectionLog -Message "OneDrive found: $path (v$oneDriveVersion)" -Level 'Information'
            $oneDriveFound = $true
            $script:outputData.OneDrive_Installed = "YES"
            break
        }
    }
    
    if (-not $oneDriveFound) {
        Write-DetectionLog -Message "OneDrive is NOT installed" -Level 'Error'
        $script:outputData.OneDrive_Status = "NOT_CONFIGURED"
        $script:outputData.OneDrive_Reason = "OneDrive not installed"
        $script:exitCode = 1
    }
    
    # 2. Check if OneDrive is Running
    Write-DetectionLog -Message "Checking if OneDrive is running..." -Level 'Information'
    
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($oneDriveProcess) {
        Write-DetectionLog -Message "OneDrive is running (PID: $($oneDriveProcess.Id))" -Level 'Information'
        $script:outputData.OneDrive_Running = "YES"
    } else {
        Write-DetectionLog -Message "OneDrive is NOT running" -Level 'Warning'
        $script:exitCode = 1
    }
    
    # 3. Check Tenant ID
    Write-DetectionLog -Message "Checking tenant ID configuration..." -Level 'Information'
    
    # First check if tenant ID is in user's OneDrive config
    $tenantId = Get-OneDriveTenantId -Username $targetUser
    
    # If not in user config, check if it's in policy (waiting to be applied)
    if (-not $tenantId) {
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        if (Test-Path $policyPath) {
            $kfmValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
            if ($kfmValue -and $kfmValue.KFMSilentOptIn) {
                $tenantId = $kfmValue.KFMSilentOptIn
                Write-DetectionLog -Message "Tenant ID found in policy (pending application): $tenantId" -Level 'Warning'
                Write-DetectionLog -Message "OneDrive needs to restart or user needs to log off/on to apply" -Level 'Warning'
            }
        }
    }
    
    if ($tenantId) {
        Write-DetectionLog -Message "Tenant ID configured: $tenantId" -Level 'Information'
        $script:outputData.OneDrive_TenantConfigured = "YES"
        # Don't set exit code to 1 if found in policy - it's configured, just pending application
    } else {
        Write-DetectionLog -Message "Tenant ID not configured" -Level 'Error'
        $script:exitCode = 1
    }
    
    # 4. Check Files On-Demand
    Write-DetectionLog -Message "Checking Files On-Demand (OneDrive feature)..." -Level 'Information'
    
    $fodEnabled = $false
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    if (Test-Path $policyPath) {
        $fodValue = Get-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
        if ($fodValue -and $fodValue.FilesOnDemandEnabled -eq 1) {
            $fodEnabled = $true
            Write-DetectionLog -Message "Files On-Demand: ENABLED via policy" -Level 'Information'
        }
    }
    
    # Check version (23.066+ has it by default)
    $script:supportsDownloadsKFM = $false
    if ($oneDriveVersion) {
        $version = $oneDriveVersion.Split('.')
        if ([int]$version[0] -ge 23 -and [int]$version[1] -ge 66) {
            $fodEnabled = $true
            Write-DetectionLog -Message "Files On-Demand: ENABLED by default since OneDrive March 2024 (v23.066+)" -Level 'Information'
        }
        
        # Check if version supports Downloads folder KFM (23.002.0102 or higher)
        if ([int]$version[0] -gt 23 -or ([int]$version[0] -eq 23 -and [int]$version[1] -ge 2)) {
            $script:supportsDownloadsKFM = $true
            Write-DetectionLog -Message "OneDrive version supports Downloads folder KFM" -Level 'Information'
        } else {
            Write-DetectionLog -Message "OneDrive version does NOT support Downloads folder KFM (requires 23.002+)" -Level 'Warning'
        }
    }
    
    if ($fodEnabled) {
        Write-DetectionLog -Message "Files On-Demand allows files to show in File Explorer without using disk space" -Level 'Information'
        Write-DetectionLog -Message "Users see cloud icons: cloud=online-only, checkmark=downloaded, pin=always keep on device" -Level 'Information'
        $script:outputData.OneDrive_FilesOnDemand = "YES"
    } else {
        Write-DetectionLog -Message "Files On-Demand NOT enabled - all synced files will use local disk space" -Level 'Error'
        $script:exitCode = 1
    }
    
    # 5. Check KFM (simplified check)
    Write-DetectionLog -Message "Checking Known Folder Move..." -Level 'Information'
    
    $kfmConfigured = $false
    if (Test-Path $policyPath) {
        # Check if KFM folders are configured
        $kfmDesktop = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInDesktop" -ErrorAction SilentlyContinue
        $kfmDocuments = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInDocuments" -ErrorAction SilentlyContinue
        $kfmPictures = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInPictures" -ErrorAction SilentlyContinue
        $kfmDownloads = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInDownloads" -ErrorAction SilentlyContinue
        
        # Check core folders (always supported)
        $coreKfmConfigured = ($kfmDesktop -and $kfmDesktop.KFMSilentOptInDesktop -eq 1) -and
                            ($kfmDocuments -and $kfmDocuments.KFMSilentOptInDocuments -eq 1) -and
                            ($kfmPictures -and $kfmPictures.KFMSilentOptInPictures -eq 1)
        
        # Check Downloads folder based on version support
        $downloadsKfmConfigured = $false
        if ($script:supportsDownloadsKFM) {
            $downloadsKfmConfigured = ($kfmDownloads -and $kfmDownloads.KFMSilentOptInDownloads -eq 1)
            
            if ($coreKfmConfigured -and $downloadsKfmConfigured) {
                $kfmConfigured = $true
                Write-DetectionLog -Message "KFM (Known Folder Move) configured for all 4 folders:" -Level 'Information'
                Write-DetectionLog -Message "  - Desktop: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "  - Documents: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "  - Pictures: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "  - Downloads: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "These folders will be protected and backed up by OneDrive" -Level 'Information'
                $script:outputData.OneDrive_KFMConfigured = "YES"
            }
        } else {
            # Version doesn't support Downloads KFM, only check core folders
            if ($coreKfmConfigured) {
                $kfmConfigured = $true
                Write-DetectionLog -Message "KFM (Known Folder Move) configured for 3 core folders:" -Level 'Information'
                Write-DetectionLog -Message "  - Desktop: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "  - Documents: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "  - Pictures: Will redirect to OneDrive" -Level 'Information'
                Write-DetectionLog -Message "  - Downloads: NOT supported (requires OneDrive 23.002+)" -Level 'Warning'
                Write-DetectionLog -Message "Core folders will be protected and backed up by OneDrive" -Level 'Information'
                $script:outputData.OneDrive_KFMConfigured = "YES"
            }
        }
    }
    
    if (-not $kfmConfigured) {
        if ($script:supportsDownloadsKFM) {
            Write-DetectionLog -Message "KFM not configured for all required folders" -Level 'Warning'
        } else {
            Write-DetectionLog -Message "KFM not configured for core folders (Desktop/Documents/Pictures)" -Level 'Warning'
        }
        $script:exitCode = 1
    }
    
    # 6. Check Storage Sense
    Write-DetectionLog -Message "Checking Storage Sense (Windows disk space management feature)..." -Level 'Information'
    
    $storageSenseEnabled = $false
    $storagePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
    
    if (Test-Path $storagePolicyPath) {
        $ssEnabled = Get-ItemProperty -Path $storagePolicyPath -Name "AllowStorageSenseGlobal" -ErrorAction SilentlyContinue
        if ($ssEnabled -and $ssEnabled.AllowStorageSenseGlobal -eq 1) {
            $storageSenseEnabled = $true
            Write-DetectionLog -Message "Storage Sense: ENABLED (Windows feature, not OneDrive)" -Level 'Information'
            Write-DetectionLog -Message "Storage Sense is a Windows 10/11 feature that automatically manages disk space" -Level 'Information'
            $script:outputData.OneDrive_StorageSense = "YES"
            
            $dehydration = Get-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -ErrorAction SilentlyContinue
            if ($dehydration) {
                $days = $dehydration.ConfigStorageSenseCloudContentDehydrationThreshold
                Write-DetectionLog -Message "Storage Sense auto-conversion configured:" -Level 'Information'
                Write-DetectionLog -Message "  - Files unused for $days days will convert to online-only" -Level 'Information'
                Write-DetectionLog -Message "  - This means files remain in OneDrive but don't use local disk space" -Level 'Information'
                Write-DetectionLog -Message "  - Users can still access files - they download on-demand when opened" -Level 'Information'
                Write-DetectionLog -Message "  - This is different from Files On-Demand which just enables the feature" -Level 'Information'
            }
        }
    }
    
    if (-not $storageSenseEnabled) {
        Write-DetectionLog -Message "Storage Sense NOT enabled - disk space won't be automatically freed" -Level 'Warning'
    }
    
    # Determine final status based on all checks
    $allChecksPass = $true
    $failureReasons = @()
    
    if ($script:outputData.OneDrive_Installed -ne "YES") {
        $allChecksPass = $false
        $failureReasons += "OneDrive not installed"
    }
    if ($script:outputData.OneDrive_Running -ne "YES") {
        $allChecksPass = $false
        $failureReasons += "OneDrive not running"
    }
    if ($script:outputData.OneDrive_TenantConfigured -ne "YES") {
        $allChecksPass = $false
        $failureReasons += "Tenant ID not configured"
    }
    if ($script:outputData.OneDrive_FilesOnDemand -ne "YES") {
        $allChecksPass = $false
        $failureReasons += "Files On-Demand not enabled"
    }
    if ($script:outputData.OneDrive_KFMConfigured -ne "YES") {
        $allChecksPass = $false
        $failureReasons += "KFM not configured"
    }
    # Storage Sense is optional but recommended
    
    if ($allChecksPass) {
        $script:outputData.OneDrive_Status = "CONFIGURED"
        $script:outputData.OneDrive_Reason = "All requirements met"
        $script:exitCode = 0
        
        # Add summary explanation when everything is configured
        Write-DetectionLog -Message "`n=== DISK SPACE OPTIMIZATION SUMMARY ===" -Level 'Information'
        Write-DetectionLog -Message "OneDrive Features:" -Level 'Information'
        Write-DetectionLog -Message "  * Files On-Demand: Files appear in Explorer but only download when needed" -Level 'Information'
        Write-DetectionLog -Message "  * KFM: Desktop, Documents, Pictures, Downloads backed up to cloud" -Level 'Information'
        Write-DetectionLog -Message "`nWindows Features:" -Level 'Information'
        Write-DetectionLog -Message "  * Storage Sense: Automatically converts unused files to online-only after 30 days" -Level 'Information'
        Write-DetectionLog -Message "`nHow they work together:" -Level 'Information'
        Write-DetectionLog -Message "  1. OneDrive syncs your KFM folders to the cloud" -Level 'Information'
        Write-DetectionLog -Message "  2. Files On-Demand shows all files but doesn't download them" -Level 'Information'
        Write-DetectionLog -Message "  3. Storage Sense frees disk space by making old files online-only" -Level 'Information'
        Write-DetectionLog -Message "  4. Result: Full file access with minimal disk usage" -Level 'Information'
    } else {
        $script:outputData.OneDrive_Status = "NOT_CONFIGURED"
        $script:outputData.OneDrive_Reason = $failureReasons -join "; "
        $script:exitCode = 1
    }
}
catch {
    Write-DetectionError -Message "Critical error during detection" -ErrorRecord $_
    $script:outputData.OneDrive_Status = "ERROR"
    $script:outputData.OneDrive_Reason = $_.Exception.Message
    $script:exitCode = 1
}

# Output results
Write-ConnectWiseOutput -Data $script:outputData

# Log completion
Write-DetectionLog -Message "Detection completed with exit code: $script:exitCode" -Level 'Information'

# Cleanup logging
if ($script:LoggingEnabled) {
    try {
        Stop-UniversalTranscript -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore transcript errors
    }
}

exit $script:exitCode