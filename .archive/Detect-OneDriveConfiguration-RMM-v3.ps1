#Requires -Version 5.1

<#
.SYNOPSIS
    Detects if OneDrive is properly configured with accurate KFM detection
.DESCRIPTION
    Fixed RMM-compatible detection script that checks:
    - OneDrive configuration
    - ACTUAL folder redirection (not just policy)
    - Storage Sense configuration
.NOTES
    v3 - Fixed KFM detection to check actual folder paths
#>

param(
    [string]$LogPath = "$env:TEMP\OneDrive-Detection-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Initialize
$VerbosePreference = 'SilentlyContinue'
$script:exitCode = 0
$script:remediationNeeded = $false
$script:detectionResults = @{}

# Logging function
function Write-DetectionLog {
    param($Message, $Level = "INFO")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp [$Level] $Message"
    Add-Content -Path $LogPath -Value $logMessage -Force -ErrorAction SilentlyContinue
    
    if ($Level -eq "ERROR") {
        Write-Host $Message -ForegroundColor Red
    } elseif ($Level -eq "WARNING") {
        Write-Host $Message -ForegroundColor Yellow
    } else {
        Write-Host $Message
    }
}

# Function to detect tenant ID automatically
function Get-OneDriveTenantId {
    $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path $businessPath) {
        $keys = Get-ItemProperty -Path $businessPath
        if ($keys.ConfiguredTenantId) {
            return $keys.ConfiguredTenantId
        }
    }
    return $null
}

Write-DetectionLog "Starting OneDrive configuration detection v3"
Write-DetectionLog "Running as: $env:USERNAME"

try {
    # 1. Check OneDrive Installation
    Write-DetectionLog "Checking OneDrive installation..."
    
    $oneDrivePaths = @(
        "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
        "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    )
    
    $oneDriveInstalled = $false
    foreach ($path in $oneDrivePaths) {
        if (Test-Path $path) {
            $oneDriveInstalled = $true
            $script:detectionResults.OneDrivePath = $path
            
            # Get OneDrive version
            $versionInfo = (Get-Item $path).VersionInfo
            $script:detectionResults.OneDriveVersion = $versionInfo.FileVersion
            
            Write-DetectionLog "OneDrive found at: $path (Version: $($versionInfo.FileVersion))" "SUCCESS"
            
            # Check if version supports Files On-Demand by default (23.066 or later)
            $versionParts = $versionInfo.FileVersion.Split('.')
            if ($versionParts[0] -ge 23 -and $versionParts[1] -ge 66) {
                Write-DetectionLog "OneDrive version supports Files On-Demand by default" "SUCCESS"
                $script:detectionResults.FilesOnDemandDefault = $true
            } else {
                $script:detectionResults.FilesOnDemandDefault = $false
            }
            break
        }
    }
    
    if (-not $oneDriveInstalled) {
        Write-DetectionLog "OneDrive is NOT installed" "ERROR"
        $script:remediationNeeded = $true
        $script:detectionResults.OneDriveInstalled = $false
    } else {
        $script:detectionResults.OneDriveInstalled = $true
    }
    
    # 2. Check if OneDrive is Running
    Write-DetectionLog "Checking if OneDrive is running..."
    
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($oneDriveProcess) {
        Write-DetectionLog "OneDrive is running (PID: $($oneDriveProcess.Id))" "SUCCESS"
        $script:detectionResults.OneDriveRunning = $true
    } else {
        Write-DetectionLog "OneDrive is NOT running" "WARNING"
        $script:remediationNeeded = $true
        $script:detectionResults.OneDriveRunning = $false
    }
    
    # 3. Check Tenant ID Configuration (Auto-detect)
    Write-DetectionLog "Checking tenant ID configuration..."
    
    $detectedTenantId = Get-OneDriveTenantId
    if ($detectedTenantId) {
        Write-DetectionLog "Auto-detected tenant ID: $detectedTenantId" "SUCCESS"
        $script:detectionResults.TenantId = $detectedTenantId
        $script:detectionResults.TenantIdConfigured = $true
        
        # Check if it's also in policy
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        if (Test-Path $policyPath) {
            $kfmValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
            if ($kfmValue -and $kfmValue.KFMSilentOptIn -eq $detectedTenantId) {
                Write-DetectionLog "Tenant ID also configured in policy" "SUCCESS"
            } else {
                Write-DetectionLog "Tenant ID not in policy (may need remediation for new users)" "WARNING"
            }
        }
    } else {
        Write-DetectionLog "Tenant ID not found" "ERROR"
        $script:remediationNeeded = $true
        $script:detectionResults.TenantIdConfigured = $false
    }
    
    # 4. Check Files On-Demand
    Write-DetectionLog "Checking Files On-Demand configuration..."
    
    $fodEnabled = $false
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    if (Test-Path $policyPath) {
        $fodValue = Get-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
        if ($fodValue -and $fodValue.FilesOnDemandEnabled -eq 1) {
            Write-DetectionLog "Files On-Demand is enabled in policy" "SUCCESS"
            $fodEnabled = $true
        }
    }
    
    # Check if Files On-Demand is on by default
    if (-not $fodEnabled -and $script:detectionResults.FilesOnDemandDefault) {
        Write-DetectionLog "Files On-Demand is enabled by default (OneDrive version 23.066+)" "SUCCESS"
        $fodEnabled = $true
    }
    
    $script:detectionResults.FilesOnDemandEnabled = $fodEnabled
    
    # 5. Check Known Folder Move (KFM) - ACTUAL PATHS
    Write-DetectionLog "Checking Known Folder Move configuration (actual paths)..."
    
    $kfmConfigured = 0
    $requiredFolders = @{
        "Desktop" = $false
        "Documents" = $false
        "Pictures" = $false
        "Downloads" = $false
    }
    
    # Get OneDrive folder path
    $oneDrivePath = $null
    $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path $businessPath) {
        $userFolder = Get-ItemProperty -Path $businessPath -Name "UserFolder" -ErrorAction SilentlyContinue
        if ($userFolder) {
            $oneDrivePath = $userFolder.UserFolder
            Write-DetectionLog "OneDrive path: $oneDrivePath"
        }
    }
    
    if ($oneDrivePath) {
        # Check actual folder locations
        $folderChecks = @(
            @{Name = "Desktop"; Path = [Environment]::GetFolderPath('Desktop')},
            @{Name = "Documents"; Path = [Environment]::GetFolderPath('MyDocuments')},
            @{Name = "Pictures"; Path = [Environment]::GetFolderPath('MyPictures')},
            @{Name = "Downloads"; Path = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path}
        )
        
        foreach ($folder in $folderChecks) {
            if ($folder.Path -like "$oneDrivePath*") {
                $requiredFolders[$folder.Name] = $true
                $kfmConfigured++
                Write-DetectionLog "$($folder.Name) is redirected to OneDrive: $($folder.Path)" "SUCCESS"
            } else {
                Write-DetectionLog "$($folder.Name) is NOT redirected: $($folder.Path)" "WARNING"
            }
        }
    } else {
        Write-DetectionLog "Could not determine OneDrive path" "ERROR"
    }
    
    $script:detectionResults.KFMFolders = $requiredFolders
    $script:detectionResults.KFMConfiguredCount = $kfmConfigured
    
    if ($kfmConfigured -lt 4) {
        Write-DetectionLog "KFM not configured for all folders ($kfmConfigured/4)" "ERROR"
        $script:remediationNeeded = $true
    } else {
        Write-DetectionLog "KFM configured for all 4 folders" "SUCCESS"
    }
    
    # 6. Check Storage Sense Configuration
    Write-DetectionLog "Checking Storage Sense configuration..."
    
    $storageSenseConfigured = $false
    $storagePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
    
    if (Test-Path $storagePolicyPath) {
        # Check if Storage Sense is enabled
        $storageSenseEnabled = Get-ItemProperty -Path $storagePolicyPath -Name "AllowStorageSenseGlobal" -ErrorAction SilentlyContinue
        if ($storageSenseEnabled -and $storageSenseEnabled.AllowStorageSenseGlobal -eq 1) {
            Write-DetectionLog "Storage Sense is enabled" "SUCCESS"
            
            # Check cloud content dehydration threshold
            $dehydrationThreshold = Get-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -ErrorAction SilentlyContinue
            if ($dehydrationThreshold) {
                $days = $dehydrationThreshold.ConfigStorageSenseCloudContentDehydrationThreshold
                Write-DetectionLog "Files convert to online-only after $days days" "SUCCESS"
                $script:detectionResults.StorageSenseDays = $days
            }
            
            # Check cadence
            $cadence = Get-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseGlobalCadence" -ErrorAction SilentlyContinue
            if ($cadence) {
                $cadenceValue = $cadence.ConfigStorageSenseGlobalCadence
                $cadenceText = switch ($cadenceValue) {
                    1 { "Daily" }
                    7 { "Weekly" }
                    30 { "Monthly" }
                    0 { "During low disk space" }
                    default { "Unknown ($cadenceValue)" }
                }
                Write-DetectionLog "Storage Sense runs: $cadenceText" "SUCCESS"
                $script:detectionResults.StorageSenseCadence = $cadenceText
            }
            
            $storageSenseConfigured = $true
        } else {
            Write-DetectionLog "Storage Sense is NOT enabled" "WARNING"
        }
    } else {
        Write-DetectionLog "Storage Sense policy not configured" "WARNING"
    }
    
    $script:detectionResults.StorageSenseEnabled = $storageSenseConfigured
    
    if (-not $storageSenseConfigured) {
        Write-DetectionLog "Storage Sense not configured - automatic space management disabled" "WARNING"
        Write-DetectionLog "Files will need to be manually converted to online-only" "WARNING"
        # Not marking as remediation needed since Files On-Demand still works manually
    }
    
    # Final Detection Result
    Write-DetectionLog "`n=== DETECTION SUMMARY ===" "INFO"
    Write-DetectionLog "OneDrive Installed: $($script:detectionResults.OneDriveInstalled)"
    Write-DetectionLog "OneDrive Running: $($script:detectionResults.OneDriveRunning)"
    Write-DetectionLog "Tenant ID Configured: $($script:detectionResults.TenantIdConfigured)"
    Write-DetectionLog "Files On-Demand Enabled: $($script:detectionResults.FilesOnDemandEnabled)"
    Write-DetectionLog "KFM Folders Configured: $($script:detectionResults.KFMConfiguredCount)/4"
    Write-DetectionLog "Storage Sense Enabled: $($script:detectionResults.StorageSenseEnabled)"
    
    if ($script:remediationNeeded) {
        Write-DetectionLog "`nREMEDIATION NEEDED" "ERROR"
        $script:exitCode = 1
    } else {
        Write-DetectionLog "`nCONFIGURATION OK - No remediation needed" "SUCCESS"
        
        if (-not $storageSenseConfigured) {
            Write-DetectionLog "Note: Storage Sense recommended for automatic space management" "WARNING"
        }
        
        $script:exitCode = 0
    }
    
    # Store results for remediation script
    $resultsPath = "$env:TEMP\OneDrive-Detection-Results.json"
    $script:detectionResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $resultsPath -Force
    Write-DetectionLog "Detection results saved to: $resultsPath"
}
catch {
    Write-DetectionLog "CRITICAL ERROR during detection: $_" "ERROR"
    $script:exitCode = 1
}

Write-DetectionLog "Detection completed. Exit code: $script:exitCode"
Write-DetectionLog "Log saved to: $LogPath"

# Return exit code for RMM
exit $script:exitCode