#Requires -Version 5.1

<#
.SYNOPSIS
    Remediates OneDrive configuration for disk space optimization with Storage Sense
.DESCRIPTION
    Enhanced RMM-compatible remediation script that:
    - Configures OneDrive (Files On-Demand, KFM, etc.)
    - Enables and configures Windows Storage Sense for automatic space management
    - Sets up automatic conversion of unused files to online-only
    - Optionally installs OneDrive if missing (default behavior)
    - Can run in ConfigurationOnly mode to skip installation
.PARAMETER TenantId
    Your organization's Azure AD Tenant ID (optional)
    Example: "336dbee2-bd39-4116-b305-3105539e416f"
    If not provided, script will auto-detect from device configuration
    Auto-detection sources: Azure AD join, OneDrive registry, Group Policy
.PARAMETER ConfigurationOnly
    When specified, skips OneDrive installation and only configures existing OneDrive.
    Use this when OneDrive deployment is handled separately.
.PARAMETER StorageSenseDays
    Number of days before unused files are converted to online-only (default: 30)
.PARAMETER SkipAutoDetection
    Disables auto-detection and requires explicit TenantId parameter
    Use this if you want to ensure a specific tenant ID is used
.NOTES
    Designed to run from SYSTEM context via RMM
    Storage Sense automates Files On-Demand to free disk space
    For production RMM deployment, consider using -ConfigurationOnly
#>

param(
    [Parameter(Mandatory = $false, HelpMessage = "Your Azure AD Tenant ID (e.g., 336dbee2-bd39-4116-b305-3105539e416f)")]
    [ValidatePattern('^$|^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [string]$TenantId = "",
    
    [string]$LogPath = "$env:TEMP\OneDrive-Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log",
    [string]$DetectionResultsPath = "$env:TEMP\OneDrive-Detection-Results.json",
    [int]$StorageSenseDays = 30,  # Days before converting files to online-only
    [switch]$EnableDebug = $false,  # Enable console output for testing
    [switch]$ConfigurationOnly = $false,  # Skip OneDrive installation, only configure existing
    [switch]$SkipAutoDetection = $false  # Skip auto-detection and require explicit TenantId
)

# Initialize
$VerbosePreference = 'SilentlyContinue'
$script:exitCode = 0
$script:remediationSuccess = $true
$script:supportsDownloadsKFM = $false

#region Logging Module Configuration
# Import logging module - use local copy only
$LoggingModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "logging\logging.psm1"
$script:LoggingEnabled = $false
$script:LoggingMode = if ($EnableDebug) { 'EnableDebug' } else { 'SilentMode' }

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
        Initialize-Logging -BaseLogPath "C:\ProgramData\OneDriveRemediation\Logs" `
                          -JobName "OneDriveRemediation" `
                          -ParentScriptName "Remediate-OneDriveConfiguration-RMM"
        
        # Set global EnableDebug for logging module
        $global:EnableDebug = $EnableDebug
        
        if ($EnableDebug) {
            Write-Host "[DEBUG] Logging initialized. Global EnableDebug = $($global:EnableDebug)" -ForegroundColor Cyan
        }
        
        Write-AppDeploymentLog -Message "OneDrive Remediation Script Started" -Level "INFO" -Mode $script:LoggingMode
        Write-AppDeploymentLog -Message "Computer: $env:COMPUTERNAME" -Level "INFO" -Mode $script:LoggingMode
        Write-AppDeploymentLog -Message "Running as: $env:USERNAME" -Level "INFO" -Mode $script:LoggingMode
        Write-AppDeploymentLog -Message "Tenant ID: $TenantId" -Level "INFO" -Mode $script:LoggingMode
        Write-AppDeploymentLog -Message "Storage Sense Days: $StorageSenseDays" -Level "INFO" -Mode $script:LoggingMode
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

# Logging function wrapper
function Write-RemediationLog {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    
    if ($script:LoggingEnabled) {
        try {
            # Force EnableDebug mode if global debug is set
            $actualMode = if ($global:EnableDebug) { 'EnableDebug' } else { $script:LoggingMode }
            Write-AppDeploymentLog -Message $Message -Level $Level -Mode $actualMode
        }
        catch {
            # Logging failed, fall back to simple logging
        }
    }
    else {
        # Fallback logging if module not available
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logMessage = "$timestamp [$Level] $Message"
        Add-Content -Path $LogPath -Value $logMessage -Force -ErrorAction SilentlyContinue
        
        # Only write to console if debug is enabled or it's an error
        if ($EnableDebug -or $Level -eq "ERROR") {
            $color = switch ($Level) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "INFO" { "White" }
                "DEBUG" { "Gray" }
                default { "White" }
            }
            Write-Host $Message -ForegroundColor $color
        }
    }
}

# Function to configure Storage Sense
function Configure-StorageSense {
    param([int]$DaysUntilOnlineOnly = 30)
    
    Write-RemediationLog "Configuring Windows Storage Sense..."
    
    try {
        # Storage Sense registry path
        $storagePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
        
        # Create policy key if it doesn't exist
        if (!(Test-Path $storagePolicyPath)) {
            New-Item -Path $storagePolicyPath -Force | Out-Null
            Write-RemediationLog "Created Storage Sense policy registry key"
        }
        
        # Enable Storage Sense
        Set-ItemProperty -Path $storagePolicyPath -Name "AllowStorageSenseGlobal" -Value 1 -Type DWord
        Write-RemediationLog "Enabled Storage Sense globally"
        
        # Configure Storage Sense to run automatically
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseGlobalCadence" -Value 7 -Type DWord  # Weekly
        Write-RemediationLog "Set Storage Sense to run weekly"
        
        # Configure cloud content dehydration
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -Value $DaysUntilOnlineOnly -Type DWord
        Write-RemediationLog "Set Files On-Demand conversion threshold to $DaysUntilOnlineOnly days"
        
        # Additional Storage Sense settings for disk cleanup
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseRecycleBinCleanupThreshold" -Value 30 -Type DWord
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseDownloadsCleanupThreshold" -Value 0 -Type DWord  # Never delete downloads
        
        # Also configure user-level Storage Sense settings if possible
        $userStoragePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
        if (Test-Path "HKCU:\") {
            if (!(Test-Path $userStoragePath)) {
                New-Item -Path $userStoragePath -Force | Out-Null
            }
            
            # Enable Storage Sense for user
            Set-ItemProperty -Path $userStoragePath -Name "01" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            # Set cloud content settings
            Set-ItemProperty -Path $userStoragePath -Name "04" -Value 1 -Type DWord -ErrorAction SilentlyContinue  # Enable cloud content cleanup
            Set-ItemProperty -Path $userStoragePath -Name "08" -Value $DaysUntilOnlineOnly -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $userStoragePath -Name "32" -Value 7 -Type DWord -ErrorAction SilentlyContinue  # Run weekly
            
            Write-RemediationLog "Configured user-level Storage Sense settings"
        }
        
        Write-RemediationLog "Storage Sense configuration completed" "SUCCESS"
        return $true
    }
    catch {
        Write-RemediationLog "Failed to configure Storage Sense: $_" "ERROR"
        return $false
    }
}

# Auto-detect Tenant ID if not provided (default behavior)
if (-not $TenantId -and -not $SkipAutoDetection) {
    Write-RemediationLog "No Tenant ID provided, attempting auto-detection..." "INFO"
    
    # Inline auto-detection function
    function Get-AutoDetectedTenantID {
        # Method 1: Azure AD Join Status (Most Reliable for unconfigured machines)
        try {
            $dsregOutput = & dsregcmd /status 2>$null
            if ($dsregOutput) {
                $dsregText = $dsregOutput -join "`n"
                if ($dsregText -match 'TenantId\s*:\s*([a-fA-F0-9\-]{36})') {
                    $tenantId = $matches[1]
                    if ($tenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-RemediationLog "Tenant ID found via dsregcmd (Azure AD): $tenantId" "SUCCESS"
                        return $tenantId
                    }
                }
            }
        }
        catch {
            Write-RemediationLog "dsregcmd check failed: $_" "DEBUG"
        }
        
        # Method 2: Check existing user OneDrive configurations (for non-Azure AD joined)
        # Since we're running as SYSTEM, check all user profiles
        try {
            $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
            
            foreach ($profile in $userProfiles) {
                # Try to get SID for the user
                try {
                    $sid = $null
                    # First try with domain prefix
                    try {
                        $sid = (New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$($profile.Name)")).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                    catch {
                        # Try without domain prefix
                        $sid = (New-Object System.Security.Principal.NTAccount($profile.Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                    
                    if ($sid) {
                        $userRegPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\OneDrive\Accounts\Business1"
                        
                        if (Test-Path $userRegPath) {
                            $configuredTenantId = Get-ItemPropertyValue -Path $userRegPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
                            if ($configuredTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                                Write-RemediationLog "Tenant ID found in user profile ($($profile.Name)): $configuredTenantId" "SUCCESS"
                                return $configuredTenantId
                            }
                        }
                    }
                }
                catch {
                    Write-RemediationLog "Could not check profile $($profile.Name): $_" "DEBUG"
                }
            }
            
            # If running as user (not SYSTEM), also check HKCU
            if ($env:USERNAME -ne 'SYSTEM') {
                $regPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
                if (Test-Path $regPath) {
                    $configuredTenantId = Get-ItemPropertyValue -Path $regPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
                    if ($configuredTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-RemediationLog "Tenant ID found in current user registry: $configuredTenantId" "SUCCESS"
                        return $configuredTenantId
                    }
                }
            }
        }
        catch {
            Write-RemediationLog "User profile registry check failed: $_" "DEBUG"
        }
        
        # Method 3: Check Office 365 identity (if Office is installed)
        try {
            $officePaths = @(
                "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration"
            )
            
            foreach ($path in $officePaths) {
                if (Test-Path $path) {
                    $o365Config = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($o365Config.TenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-RemediationLog "Tenant ID found in Office 365 configuration: $($o365Config.TenantId)" "SUCCESS"
                        return $o365Config.TenantId
                    }
                }
            }
        }
        catch {
            Write-RemediationLog "Office 365 configuration check failed: $_" "DEBUG"
        }
        
        # Method 4: OneDrive Group Policy (LAST - might be from our own configuration)
        try {
            $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
            if (Test-Path $policyPath) {
                $kfmTenantId = Get-ItemPropertyValue -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
                if ($kfmTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                    Write-RemediationLog "Tenant ID found in OneDrive policy (might be from previous run): $kfmTenantId" "WARNING"
                    return $kfmTenantId
                }
            }
        }
        catch {
            Write-RemediationLog "OneDrive policy check failed: $_" "DEBUG"
        }
        
        return $null
    }
        
    $detectedTenantId = Get-AutoDetectedTenantID
    if ($detectedTenantId) {
        $TenantId = $detectedTenantId
        Write-RemediationLog "Auto-detected Tenant ID: $TenantId" "SUCCESS"
    }
    else {
        Write-RemediationLog "Failed to auto-detect Tenant ID" "ERROR"
        Write-RemediationLog "Please provide Tenant ID using -TenantId parameter" "ERROR"
        Write-RemediationLog "Find your Tenant ID in Azure AD portal or use: (Get-AzureADTenantDetail).ObjectId" "INFO"
        $script:exitCode = 1
        exit $script:exitCode
    }
}
elseif (-not $TenantId -and $SkipAutoDetection) {
    Write-RemediationLog "No Tenant ID provided and auto-detection is disabled" "ERROR"
    Write-RemediationLog "Please provide -TenantId parameter" "ERROR"
    Write-RemediationLog "Example: .\$($MyInvocation.MyCommand.Name) -TenantId 'your-tenant-id'" "INFO"
    $script:exitCode = 1
    exit $script:exitCode
}

# These are already logged by the logging module initialization above
if (-not $script:LoggingEnabled) {
    Write-RemediationLog "Starting OneDrive configuration remediation with Storage Sense"
    Write-RemediationLog "Running as: $env:USERNAME"
    Write-RemediationLog "Tenant ID: $TenantId"
    Write-RemediationLog "Storage Sense Days: $StorageSenseDays"
}

try {
    # Load detection results if available
    $detectionResults = @{}
    if (Test-Path $DetectionResultsPath) {
        Write-RemediationLog "Loading detection results from: $DetectionResultsPath"
        $detectionResults = Get-Content -Path $DetectionResultsPath -Raw | ConvertFrom-Json
    } else {
        Write-RemediationLog "No detection results found, will perform full remediation" "WARNING"
    }
    
    # 1. Install OneDrive if needed (skip if ConfigurationOnly)
    if ($detectionResults.OneDriveInstalled -eq $false) {
        if ($ConfigurationOnly) {
            Write-RemediationLog "OneDrive not installed, but ConfigurationOnly mode is set - skipping installation" "WARNING"
            Write-RemediationLog "OneDrive deployment should be handled separately" "INFO"
            
            # Exit early if OneDrive not installed and we're in ConfigurationOnly mode
            Write-RemediationLog "Cannot configure OneDrive when it's not installed" "ERROR"
            $script:exitCode = 1
            
            Write-RemediationLog "`nRemediation completed. Exit code: $script:exitCode"
            
            # Cleanup logging
            if ($script:LoggingEnabled) {
                try {
                    $null = Stop-UniversalTranscript -ErrorAction SilentlyContinue
                }
                catch {
                    # Ignore transcript errors
                }
            }
            
            exit $script:exitCode
        }
        else {
            Write-RemediationLog "OneDrive not installed - attempting installation..."
            
            # Download OneDrive installer
            $installerUrl = "https://go.microsoft.com/fwlink/?linkid=844652"
            $installerPath = "$env:TEMP\OneDriveSetup.exe"
            
            try {
                Write-RemediationLog "Downloading OneDrive installer..."
                Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
                
                Write-RemediationLog "Installing OneDrive..."
                Start-Process -FilePath $installerPath -ArgumentList "/allusers" -Wait -NoNewWindow
                
                Write-RemediationLog "OneDrive installation completed" "SUCCESS"
                
                # Clean up installer
                Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-RemediationLog "Failed to install OneDrive: $_" "ERROR"
                $script:remediationSuccess = $false
            }
        }
    }
    
    # 2. Configure Group Policy settings
    Write-RemediationLog "Configuring OneDrive Group Policy settings..."
    
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    # Create policy key if it doesn't exist
    if (!(Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
        Write-RemediationLog "Created policy registry key"
    }
    
    # Configure tenant ID for KFM
    Set-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -Value $TenantId -Type String
    Write-RemediationLog "Configured tenant ID for KFM: $TenantId" "SUCCESS"
    
    # Enable Files On-Demand (Note: Already on by default since March 2024)
    Set-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -Value 1 -Type DWord
    Write-RemediationLog "Ensured Files On-Demand is enabled" "SUCCESS"
    
    # Check OneDrive version to determine Downloads folder support
    $oneDrivePaths = @(
        "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
        "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    )
    
    foreach ($path in $oneDrivePaths) {
        if (Test-Path $path) {
            $versionInfo = (Get-Item $path).VersionInfo
            $oneDriveVersion = $versionInfo.FileVersion
            Write-RemediationLog "OneDrive version: $oneDriveVersion"
            
            # Check if version supports Downloads folder KFM (23.002+)
            $version = $oneDriveVersion.Split('.')
            if ([int]$version[0] -gt 23 -or ([int]$version[0] -eq 23 -and [int]$version[1] -ge 2)) {
                $script:supportsDownloadsKFM = $true
                Write-RemediationLog "OneDrive version supports Downloads folder KFM"
            } else {
                Write-RemediationLog "OneDrive version does NOT support Downloads folder KFM (requires 23.002+)" "WARNING"
            }
            break
        }
    }
    
    # Configure KFM for folders based on version support
    $kfmSettings = @{
        "KFMSilentOptInDesktop" = 1
        "KFMSilentOptInDocuments" = 1
        "KFMSilentOptInPictures" = 1
        "KFMBlockOptIn" = 0  # Ensure KFM is not blocked
        "KFMBlockOptOut" = 1  # Prevent users from opting out
    }
    
    # Only add Downloads if version supports it
    if ($script:supportsDownloadsKFM) {
        $kfmSettings["KFMSilentOptInDownloads"] = 1
        Write-RemediationLog "Including Downloads folder in KFM configuration"
    } else {
        Write-RemediationLog "Skipping Downloads folder KFM (not supported by this OneDrive version)"
    }
    
    foreach ($setting in $kfmSettings.GetEnumerator()) {
        Set-ItemProperty -Path $policyPath -Name $setting.Key -Value $setting.Value -Type DWord
        Write-RemediationLog "Set $($setting.Key) = $($setting.Value)"
    }
    
    if ($script:supportsDownloadsKFM) {
        Write-RemediationLog "KFM configured for all 4 folders" "SUCCESS"
    } else {
        Write-RemediationLog "KFM configured for 3 core folders (Desktop/Documents/Pictures)" "SUCCESS"
        Write-RemediationLog "Downloads folder will be added when OneDrive is updated to 23.002+" "INFO"
    }
    
    # 3. Additional optimization settings
    Write-RemediationLog "Applying additional optimization settings..."
    
    # Prevent sync of certain file types
    $excludedTypes = "*.pst;*.ost"
    Set-ItemProperty -Path $policyPath -Name "FileSyncExcludedExtensions" -Value $excludedTypes -Type String
    Write-RemediationLog "Excluded file types: $excludedTypes"
    
    # Set maximum file size (15GB)
    Set-ItemProperty -Path $policyPath -Name "ForcedLocalMassDeleteDetection" -Value 1 -Type DWord
    
    # Enable automatic sign-in with Windows credentials
    Set-ItemProperty -Path $policyPath -Name "SilentAccountConfig" -Value 1 -Type DWord
    Write-RemediationLog "Enabled silent account configuration - users will auto-login with Windows credentials"
    
    # Disable personal OneDrive accounts (security setting)
    Set-ItemProperty -Path $policyPath -Name "DisablePersonalSync" -Value 1 -Type DWord
    Write-RemediationLog "Disabled personal OneDrive accounts - prevents data leakage to personal storage"
    
    # 4. Configure Storage Sense for automatic disk space management
    $storageSenseSuccess = Configure-StorageSense -DaysUntilOnlineOnly $StorageSenseDays
    if (-not $storageSenseSuccess) {
        Write-RemediationLog "Storage Sense configuration failed - files will need manual conversion to online-only" "WARNING"
    }
    
    # 5. Start OneDrive if not running
    if ($detectionResults.OneDriveRunning -eq $false) {
        Write-RemediationLog "OneDrive not running - attempting to start..."
        
        # Find OneDrive.exe
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
            # Get logged-in user
            $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
            if ($loggedInUser -and $loggedInUser -notmatch "^NT AUTHORITY") {
                Write-RemediationLog "Starting OneDrive for user: $loggedInUser"
                
                # Create scheduled task to start OneDrive as user
                $taskName = "StartOneDrive_Remediation"
                $action = New-ScheduledTaskAction -Execute $oneDriveExe
                $principal = New-ScheduledTaskPrincipal -UserId $loggedInUser -LogonType Interactive
                $task = New-ScheduledTask -Action $action -Principal $principal
                
                Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
                Start-ScheduledTask -TaskName $taskName
                
                Start-Sleep -Seconds 5
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                
                Write-RemediationLog "OneDrive start initiated" "SUCCESS"
            } else {
                Write-RemediationLog "No interactive user found - OneDrive will start at next login" "WARNING"
            }
        } else {
            Write-RemediationLog "OneDrive.exe not found after installation" "ERROR"
            $script:remediationSuccess = $false
        }
    }
    
    # 6. Verify remediation
    Write-RemediationLog "`n=== REMEDIATION SUMMARY ===" "INFO"
    
    # Check if all critical settings are in place
    $verifySettings = @{
        "KFMSilentOptIn" = $TenantId
        "FilesOnDemandEnabled" = 1
        "KFMSilentOptInDesktop" = 1
        "KFMSilentOptInDocuments" = 1
        "KFMSilentOptInPictures" = 1
        "SilentAccountConfig" = 1
        "DisablePersonalSync" = 1
    }
    
    # Only verify Downloads if version supports it
    if ($script:supportsDownloadsKFM) {
        $verifySettings["KFMSilentOptInDownloads"] = 1
    }
    
    $allConfigured = $true
    foreach ($setting in $verifySettings.GetEnumerator()) {
        $value = Get-ItemProperty -Path $policyPath -Name $setting.Key -ErrorAction SilentlyContinue
        if ($value.$($setting.Key) -eq $setting.Value) {
            Write-RemediationLog "$($setting.Key): Configured correctly" "SUCCESS"
        } else {
            Write-RemediationLog "$($setting.Key): NOT configured correctly" "ERROR"
            $allConfigured = $false
        }
    }
    
    # Check Storage Sense
    $storageSenseEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "AllowStorageSenseGlobal" -ErrorAction SilentlyContinue
    if ($storageSenseEnabled.AllowStorageSenseGlobal -eq 1) {
        Write-RemediationLog "Storage Sense: Enabled" "SUCCESS"
        Write-RemediationLog "Files will automatically convert to online-only after $StorageSenseDays days of non-use"
    } else {
        Write-RemediationLog "Storage Sense: Not enabled" "WARNING"
    }
    
    if ($allConfigured -and $script:remediationSuccess) {
        Write-RemediationLog "`nREMEDIATION SUCCESSFUL" "SUCCESS"
        Write-RemediationLog "OneDrive is configured for disk space optimization"
        Write-RemediationLog "Storage Sense will automatically free space by converting unused files to online-only"
        Write-RemediationLog "Settings will take effect at next user login or policy refresh"
        $script:exitCode = 0
    } else {
        Write-RemediationLog "`nREMEDIATION PARTIALLY SUCCESSFUL" "WARNING"
        Write-RemediationLog "Some settings may require manual intervention"
        $script:exitCode = 1
    }
    
    # Force group policy update
    Write-RemediationLog "`nForcing group policy update..."
    & gpupdate /force /wait:0 2>&1 | Out-Null
    Write-RemediationLog "Group policy update initiated"
    
    # Additional info about disk space savings
    Write-RemediationLog "`n=== DISK SPACE OPTIMIZATION INFO ===" "INFO"
    Write-RemediationLog "Files On-Demand: Enabled by default since OneDrive March 2024"
    Write-RemediationLog "Storage Sense: Configured to run weekly"
    Write-RemediationLog "Automatic conversion: Files unused for $StorageSenseDays days become online-only"
    Write-RemediationLog "Manual conversion: Users can right-click files and select 'Free up space'"
    Write-RemediationLog "Protected files: Files marked 'Always keep on this device' won't be converted"
}
catch {
    Write-RemediationLog "CRITICAL ERROR during remediation: $_" "ERROR"
    $script:exitCode = 1
}

Write-RemediationLog "`nRemediation completed. Exit code: $script:exitCode"

# Only log path if not using logging module (which saves to its own location)
if (-not $script:LoggingEnabled) {
    Write-RemediationLog "Log saved to: $LogPath"
}

# Cleanup logging
if ($script:LoggingEnabled) {
    try {
        $null = Stop-UniversalTranscript -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore transcript errors
    }
}

# Return exit code for RMM
exit $script:exitCode