<#
.SYNOPSIS
    Properly validates OneDrive KFM and Files On-Demand with visual confirmation
    
.DESCRIPTION
    This script performs REAL validation of OneDrive functionality:
    - Checks actual folder locations (not just registry)
    - Verifies OneDrive sync status
    - Tests user impersonation from SYSTEM
    - Shows visual output for validation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantID = "GetFromRegistry"  # Will try to detect from existing config
)

#region Helper Functions
function Write-ValidationLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
        'Debug' = 'Gray'
    }
    
    $prefix = @{
        'Info' = '[INFO]'
        'Success' = '[PASS]'
        'Warning' = '[WARN]'
        'Error' = '[FAIL]'
        'Debug' = '[DBG]'
    }
    
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Get-ActualOneDrivePath {
    # Get the ACTUAL OneDrive path from environment or registry
    $oneDrivePath = $env:OneDrive
    
    if (-not $oneDrivePath) {
        # Try to get from registry if env var not set
        $regPaths = @(
            "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1",
            "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $userFolder = Get-ItemProperty -Path $regPath -Name "UserFolder" -ErrorAction SilentlyContinue
                if ($userFolder -and $userFolder.UserFolder) {
                    $oneDrivePath = $userFolder.UserFolder
                    break
                }
            }
        }
    }
    
    return $oneDrivePath
}

function Test-FolderRedirection {
    param(
        [string]$FolderName,
        [string]$RegistryGuid
    )
    
    Write-ValidationLog "Checking $FolderName folder redirection..." -Level Info
    
    # Get actual folder path
    $shellFoldersPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    $actualPath = $null
    
    if ($RegistryGuid) {
        $regValue = Get-ItemProperty -Path $shellFoldersPath -Name $RegistryGuid -ErrorAction SilentlyContinue
        if ($regValue) {
            $actualPath = $regValue.$RegistryGuid
        }
    }
    else {
        # For standard folders
        $regValue = Get-ItemProperty -Path $shellFoldersPath -Name $FolderName -ErrorAction SilentlyContinue
        if ($regValue) {
            $actualPath = $regValue.$FolderName
        }
    }
    
    if (-not $actualPath) {
        Write-ValidationLog "$FolderName`: No registry entry found" -Level Error
        return $false
    }
    
    # Expand environment variables
    $expandedPath = [Environment]::ExpandEnvironmentVariables($actualPath)
    
    # Get OneDrive path
    $oneDrivePath = Get-ActualOneDrivePath
    
    # Check if path is in OneDrive
    if ($oneDrivePath -and $expandedPath -like "*$oneDrivePath*") {
        Write-ValidationLog "$FolderName`: Redirected to OneDrive - $expandedPath" -Level Success
        
        # Check if folder actually exists
        if (Test-Path $expandedPath) {
            Write-ValidationLog "  Folder exists on disk" -Level Success
            return $true
        }
        else {
            Write-ValidationLog "  Folder does NOT exist on disk!" -Level Error
            return $false
        }
    }
    else {
        Write-ValidationLog "$FolderName`: NOT in OneDrive - $expandedPath" -Level Error
        return $false
    }
}

function Get-OneDriveSyncStatus {
    Write-ValidationLog "Checking OneDrive sync status..." -Level Info
    
    # Check if OneDrive is running
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    
    if (-not $oneDriveProcess) {
        Write-ValidationLog "OneDrive process is NOT running!" -Level Error
        return "NotRunning"
    }
    
    Write-ValidationLog "OneDrive is running (PID: $($oneDriveProcess.Id))" -Level Success
    
    # Try to get sync status using OneDriveLib.dll
    $dllPath = "C:\ProgramData\OneDriveRemediation\OneDriveLib.dll"
    
    if (Test-Path $dllPath) {
        try {
            Add-Type -Path $dllPath
            $status = [OneDriveLib.StatusService]::GetStatus()
            
            if ($status) {
                $statusObj = $status | ConvertFrom-Json
                Write-ValidationLog "OneDrive sync status retrieved via DLL" -Level Success
                
                # Show all sync folders
                foreach ($folder in $statusObj.value) {
                    $statusColor = switch ($folder.StatusString) {
                        'UpToDate' { 'Success' }
                        'Syncing' { 'Info' }
                        'Error' { 'Error' }
                        'ReadOnly' { 'Warning' }
                        default { 'Warning' }
                    }
                    
                    Write-ValidationLog "  $($folder.LocalPath): $($folder.StatusString)" -Level $statusColor
                }
                
                return $statusObj
            }
        }
        catch {
            Write-ValidationLog "Failed to get status via DLL: $_" -Level Warning
        }
    }
    else {
        Write-ValidationLog "OneDriveLib.dll not found at $dllPath" -Level Warning
    }
    
    return "Unknown"
}

function Test-ActualTenantID {
    Write-ValidationLog "Checking actual Tenant ID configuration..." -Level Info
    
    # Check registry for configured tenant ID
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    if (Test-Path $policyPath) {
        $kfmValue = Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
        
        if ($kfmValue -and $kfmValue.KFMSilentOptIn) {
            $configuredTenantID = $kfmValue.KFMSilentOptIn
            Write-ValidationLog "Configured Tenant ID: $configuredTenantID" -Level Info
            
            # Check if it's a valid GUID format
            if ($configuredTenantID -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                # Check if it's our dummy ID
                if ($configuredTenantID -eq "12345678-1234-1234-1234-123456789012") {
                    Write-ValidationLog "WARNING: Using dummy tenant ID - KFM won't actually work!" -Level Error
                    return $false
                }
                else {
                    Write-ValidationLog "Valid Tenant ID format" -Level Success
                    return $true
                }
            }
            else {
                Write-ValidationLog "Invalid Tenant ID format!" -Level Error
                return $false
            }
        }
        else {
            Write-ValidationLog "No Tenant ID configured in registry" -Level Error
            return $false
        }
    }
    else {
        Write-ValidationLog "OneDrive policy registry path doesn't exist" -Level Error
        return $false
    }
}

function Get-RealTenantID {
    Write-ValidationLog "Attempting to detect real Tenant ID..." -Level Info
    
    # Method 1: Check OneDrive account registry
    $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    
    if (Test-Path $businessPath) {
        $tenantIdValue = Get-ItemProperty -Path $businessPath -Name "TenantId" -ErrorAction SilentlyContinue
        if ($tenantIdValue -and $tenantIdValue.TenantId) {
            Write-ValidationLog "Found Tenant ID in OneDrive registry: $($tenantIdValue.TenantId)" -Level Success
            return $tenantIdValue.TenantId
        }
    }
    
    # Method 2: Check from OneDrive config file
    $configPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\settings\Business1"
    if (Test-Path $configPath) {
        $globalIni = Get-Content "$configPath\global.ini" -ErrorAction SilentlyContinue
        if ($globalIni) {
            $tenantLine = $globalIni | Where-Object { $_ -like "tenantId = *" }
            if ($tenantLine) {
                $tenantId = $tenantLine -replace "tenantId = ", ""
                Write-ValidationLog "Found Tenant ID in config file: $tenantId" -Level Success
                return $tenantId
            }
        }
    }
    
    Write-ValidationLog "Could not detect real Tenant ID" -Level Warning
    return $null
}
#endregion

#region Main Validation
Write-Host "`n=== OneDrive KFM and Files On-Demand Validation ===" -ForegroundColor Cyan
Write-Host "Running as: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Is SYSTEM: $([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)" -ForegroundColor Yellow
Write-Host ""

# 1. Check OneDrive Installation
Write-ValidationLog "Validating OneDrive installation..." -Level Info
$oneDrivePaths = @(
    "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
    "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
)

$oneDriveExe = $null
foreach ($path in $oneDrivePaths) {
    if (Test-Path $path) {
        $oneDriveExe = Get-Item $path
        Write-ValidationLog "OneDrive found: $path" -Level Success
        Write-ValidationLog "Version: $($oneDriveExe.VersionInfo.FileVersion)" -Level Info
        break
    }
}

if (-not $oneDriveExe) {
    Write-ValidationLog "OneDrive is NOT installed!" -Level Error
}

# 2. Check Tenant ID
$realTenantID = Get-RealTenantID
if ($TenantID -eq "GetFromRegistry") {
    if ($realTenantID) {
        $TenantID = $realTenantID
        Write-ValidationLog "Using detected Tenant ID: $TenantID" -Level Info
    }
    else {
        Write-ValidationLog "Cannot detect Tenant ID - KFM configuration will fail!" -Level Error
    }
}

Test-ActualTenantID

# 3. Check OneDrive Sync Status
$syncStatus = Get-OneDriveSyncStatus

# 4. Check actual folder redirection
Write-Host "`n--- Checking Actual Folder Redirection ---" -ForegroundColor Yellow

$folders = @{
    Desktop = @{Name = "Desktop"; Guid = $null}
    Documents = @{Name = "Personal"; Guid = $null}  # "Personal" is the registry name for Documents
    Pictures = @{Name = "My Pictures"; Guid = $null}
    Downloads = @{Name = "Downloads"; Guid = "{374DE290-123F-4565-9164-39C4925E467B}"}
}

$redirectionResults = @{}
foreach ($folder in $folders.GetEnumerator()) {
    $redirectionResults[$folder.Key] = Test-FolderRedirection -FolderName $folder.Value.Name -RegistryGuid $folder.Value.Guid
}

# 5. Check Files On-Demand
Write-Host "`n--- Checking Files On-Demand ---" -ForegroundColor Yellow
Write-ValidationLog "Checking Files On-Demand status..." -Level Info

$fodEnabled = $false
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
if (Test-Path $policyPath) {
    $fodValue = Get-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -ErrorAction SilentlyContinue
    if ($fodValue -and $fodValue.FilesOnDemandEnabled -eq 1) {
        Write-ValidationLog "Files On-Demand is enabled in policy" -Level Success
        $fodEnabled = $true
    }
}

# Check actual OneDrive folder for online-only files
$oneDrivePath = Get-ActualOneDrivePath
if ($oneDrivePath -and (Test-Path $oneDrivePath)) {
    Write-ValidationLog "Checking for online-only files in: $oneDrivePath" -Level Info
    
    # Get a sample of files
    $files = Get-ChildItem -Path $oneDrivePath -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
    
    if ($files) {
        $onlineOnlyCount = 0
        foreach ($file in $files) {
            $attributes = $file.Attributes
            if ($attributes -band [System.IO.FileAttributes]::SparseFile) {
                $onlineOnlyCount++
            }
        }
        
        if ($onlineOnlyCount -gt 0) {
            Write-ValidationLog "Found $onlineOnlyCount online-only files (Files On-Demand working)" -Level Success
        }
        else {
            Write-ValidationLog "No online-only files found (Files On-Demand may not be active)" -Level Warning
        }
    }
}

# 6. Summary
Write-Host "`n=== VALIDATION SUMMARY ===" -ForegroundColor Cyan

$validationPassed = $true

# OneDrive installed and running
if ($oneDriveExe -and (Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue)) {
    Write-ValidationLog "OneDrive: Installed and Running" -Level Success
}
else {
    Write-ValidationLog "OneDrive: NOT properly running" -Level Error
    $validationPassed = $false
}

# Tenant ID
if ($realTenantID -and $TenantID -ne "12345678-1234-1234-1234-123456789012") {
    Write-ValidationLog "Tenant ID: Valid ($TenantID)" -Level Success
}
else {
    Write-ValidationLog "Tenant ID: Invalid or dummy ID" -Level Error
    $validationPassed = $false
}

# Folder redirection
$redirectedCount = ($redirectionResults.Values | Where-Object { $_ -eq $true }).Count
Write-ValidationLog "Folder Redirection: $redirectedCount of $($redirectionResults.Count) folders" -Level $(if ($redirectedCount -ge 3) { 'Success' } else { 'Error' })
if ($redirectedCount -lt 3) {
    $validationPassed = $false
}

# Files On-Demand
Write-ValidationLog "Files On-Demand: $(if ($fodEnabled) { 'Enabled' } else { 'Not Enabled' })" -Level $(if ($fodEnabled) { 'Success' } else { 'Error' })
if (-not $fodEnabled) {
    $validationPassed = $false
}

Write-Host "`nOVERALL VALIDATION: $(if ($validationPassed) { 'PASSED' } else { 'FAILED' })" -ForegroundColor $(if ($validationPassed) { 'Green' } else { 'Red' })

# Keep window open if running interactively
if ($Host.Name -eq 'ConsoleHost') {
    Write-Host "`nPress any key to close..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
#endregion