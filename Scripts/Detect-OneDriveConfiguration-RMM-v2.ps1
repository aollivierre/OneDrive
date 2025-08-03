#Requires -Version 5.1

<#
.SYNOPSIS
    Detects if OneDrive is properly configured with Storage Sense for disk space optimization
.DESCRIPTION
    Enhanced RMM-compatible detection script that checks:
    - OneDrive configuration (Files On-Demand, KFM, etc.)
    - Storage Sense configuration for automatic space management
    Returns 0 if properly configured, 1 if remediation needed
.NOTES
    Designed to run from SYSTEM context via RMM
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

Write-DetectionLog "Starting OneDrive configuration detection with Storage Sense check"
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
    
    # 3. Check Tenant ID Configuration
    Write-DetectionLog "Checking tenant ID configuration..."
    
    $tenantIdFound = $false
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    if (Test-Path $policyPath) {
        $kfmValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
        if ($kfmValue -and $kfmValue.KFMSilentOptIn) {
            $tenantId = $kfmValue.KFMSilentOptIn
            
            # Validate tenant ID format (GUID)
            if ($tenantId -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                Write-DetectionLog "Valid tenant ID configured: $tenantId" "SUCCESS"
                $tenantIdFound = $true
                $script:detectionResults.TenantId = $tenantId
            } else {
                Write-DetectionLog "Invalid tenant ID format: $tenantId" "ERROR"
            }
        }
    }
    
    if (-not $tenantIdFound) {
        Write-DetectionLog "Tenant ID not properly configured" "ERROR"
        $script:remediationNeeded = $true
        $script:detectionResults.TenantIdConfigured = $false
    } else {
        $script:detectionResults.TenantIdConfigured = $true
    }
    
    # 4. Check Files On-Demand
    Write-DetectionLog "Checking Files On-Demand configuration..."
    
    $fodEnabled = $false
    
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
    
    if (-not $fodEnabled) {
        Write-DetectionLog "Files On-Demand is NOT enabled" "ERROR"
        $script:remediationNeeded = $true
        $script:detectionResults.FilesOnDemandEnabled = $false
    } else {
        $script:detectionResults.FilesOnDemandEnabled = $true
    }
    
    # 5. Check Known Folder Move (KFM)
    Write-DetectionLog "Checking Known Folder Move configuration..."
    
    $kfmConfigured = 0
    $requiredFolders = @{
        "Desktop" = $false
        "Documents" = $false
        "Pictures" = $false
        "Downloads" = $false
    }
    
    # Check policy settings
    if (Test-Path $policyPath) {
        # Check if KFM is enabled
        $kfmBlockValue = Get-ItemProperty -Path $policyPath -Name "KFMBlockOptIn" -ErrorAction SilentlyContinue
        if ($kfmBlockValue -and $kfmBlockValue.KFMBlockOptIn -eq 1) {
            Write-DetectionLog "KFM is BLOCKED by policy!" "ERROR"
            $script:remediationNeeded = $true
        } else {
            # Check which folders are included
            $includedFolders = @()
            
            # Desktop
            $desktopValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInDesktop" -ErrorAction SilentlyContinue
            if ($desktopValue -and $desktopValue.KFMSilentOptInDesktop -eq 1) {
                $requiredFolders["Desktop"] = $true
                $includedFolders += "Desktop"
                $kfmConfigured++
            }
            
            # Documents
            $documentsValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInDocuments" -ErrorAction SilentlyContinue
            if ($documentsValue -and $documentsValue.KFMSilentOptInDocuments -eq 1) {
                $requiredFolders["Documents"] = $true
                $includedFolders += "Documents"
                $kfmConfigured++
            }
            
            # Pictures
            $picturesValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInPictures" -ErrorAction SilentlyContinue
            if ($picturesValue -and $picturesValue.KFMSilentOptInPictures -eq 1) {
                $requiredFolders["Pictures"] = $true
                $includedFolders += "Pictures"
                $kfmConfigured++
            }
            
            # Downloads (custom implementation)
            $downloadsValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptInDownloads" -ErrorAction SilentlyContinue
            if ($downloadsValue -and $downloadsValue.KFMSilentOptInDownloads -eq 1) {
                $requiredFolders["Downloads"] = $true
                $includedFolders += "Downloads"
                $kfmConfigured++
            }
            
            if ($includedFolders.Count -gt 0) {
                Write-DetectionLog "KFM configured for: $($includedFolders -join ', ')" "SUCCESS"
            }
        }
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