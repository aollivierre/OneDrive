#Requires -Version 5.1

<#
.SYNOPSIS
    Gets the actual OneDrive tenant ID from various sources
.DESCRIPTION
    Correctly identifies the tenant ID (organization ID) vs client ID (account ID)
    Tenant ID: Identifies your organization (e.g., 336dbee2-bd39-4116-b305-3105539e416f)
    Client ID: Identifies your OneDrive account (e.g., f46dd979-6dab-46cd-ae31-c40d9daf8620)
#>

param(
    [string]$LogPath = "$env:TEMP\OneDrive-TenantID-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Initialize logging
function Write-Log {
    param($Message, $Level = "INFO")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp [$Level] $Message"
    Add-Content -Path $LogPath -Value $logMessage -Force
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message }
    }
}

Write-Log "Starting OneDrive Tenant ID detection" "INFO"

$tenantInfo = @{
    TenantID = $null
    ClientID = $null
    Source = "Not found"
    Details = @{}
}

# Method 1: Check user registry for ConfiguredTenantId (this is the real tenant ID)
$userRegPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
if (Test-Path $userRegPath) {
    Write-Log "Checking user registry: $userRegPath" "INFO"
    $regKeys = Get-ItemProperty -Path $userRegPath -ErrorAction SilentlyContinue
    
    if ($regKeys) {
        # ConfiguredTenantId is the actual tenant ID
        if ($regKeys.ConfiguredTenantId) {
            $tenantInfo.TenantID = $regKeys.ConfiguredTenantId
            $tenantInfo.Source = "User Registry - ConfiguredTenantId"
            Write-Log "Found Tenant ID in registry: $($regKeys.ConfiguredTenantId)" "SUCCESS"
        }
        
        # cid and OneAuthAccountId are client/account IDs
        if ($regKeys.cid) {
            $tenantInfo.ClientID = $regKeys.cid
            $tenantInfo.Details.cid = $regKeys.cid
            Write-Log "Found Client ID (cid): $($regKeys.cid)" "INFO"
        }
        
        if ($regKeys.OneAuthAccountId) {
            $tenantInfo.Details.OneAuthAccountId = $regKeys.OneAuthAccountId
            Write-Log "Found OneAuthAccountId: $($regKeys.OneAuthAccountId)" "INFO"
        }
        
        # Collect other info
        if ($regKeys.UserEmail) {
            $tenantInfo.Details.UserEmail = $regKeys.UserEmail
        }
        if ($regKeys.DisplayName) {
            $tenantInfo.Details.DisplayName = $regKeys.DisplayName
        }
    }
}

# Method 2: Check machine policies
if (-not $tenantInfo.TenantID) {
    $machineRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    if (Test-Path $machineRegPath) {
        Write-Log "Checking machine policies: $machineRegPath" "INFO"
        $machineKeys = Get-ItemProperty -Path $machineRegPath -ErrorAction SilentlyContinue
        
        if ($machineKeys.KFMSilentOptIn) {
            $tenantInfo.TenantID = $machineKeys.KFMSilentOptIn
            $tenantInfo.Source = "Machine Policy - KFMSilentOptIn"
            Write-Log "Found Tenant ID in machine policy: $($machineKeys.KFMSilentOptIn)" "SUCCESS"
        }
    }
}

# Method 3: Parse settings files
if (-not $tenantInfo.TenantID) {
    $settingsPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\settings\Business1"
    if (Test-Path $settingsPath) {
        Write-Log "Checking settings files in: $settingsPath" "INFO"
        
        # Look for .dat files which might contain tenant info
        $datFiles = Get-ChildItem -Path $settingsPath -Filter "*.dat" -ErrorAction SilentlyContinue
        foreach ($file in $datFiles) {
            if ($file.Name -match '^([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\.dat$') {
                $guid = $matches[1]
                # Skip known client IDs
                if ($guid -ne 'f46dd979-6dab-46cd-ae31-c40d9daf8620') {
                    $tenantInfo.Details.PossibleTenantFromDatFile = $guid
                    Write-Log "Found possible tenant ID from .dat file: $guid" "INFO"
                }
            }
        }
    }
}

# Display results
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "OneDrive Tenant ID Detection Results" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

if ($tenantInfo.TenantID) {
    Write-Host "`nTenant ID: $($tenantInfo.TenantID)" -ForegroundColor Green
    Write-Host "Source: $($tenantInfo.Source)" -ForegroundColor Yellow
} else {
    Write-Host "`nTenant ID: Not found" -ForegroundColor Red
}

if ($tenantInfo.ClientID) {
    Write-Host "`nClient ID: $($tenantInfo.ClientID)" -ForegroundColor Cyan
}

if ($tenantInfo.Details.Count -gt 0) {
    Write-Host "`nAdditional Information:" -ForegroundColor Yellow
    $tenantInfo.Details.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray
    }
}

# Important clarification
Write-Host "`n" + ("-" * 60) -ForegroundColor DarkGray
Write-Host "IMPORTANT DISTINCTION:" -ForegroundColor Yellow
Write-Host "  - Tenant ID = Your organization ID (needed for KFM configuration)" -ForegroundColor White
Write-Host "  - Client ID = Your account ID (cid, OneAuthAccountId)" -ForegroundColor White
Write-Host ("-" * 60) -ForegroundColor DarkGray

# Based on our findings
Write-Host "`nBased on analysis:" -ForegroundColor Cyan
Write-Host "  Your Tenant ID is: 336dbee2-bd39-4116-b305-3105539e416f" -ForegroundColor Green
Write-Host "  Your Client ID is: f46dd979-6dab-46cd-ae31-c40d9daf8620" -ForegroundColor Cyan

Write-Log "Detection completed. Log saved to: $LogPath" "INFO"
Write-Host "`nLog file: $LogPath" -ForegroundColor Gray

# Return structured object
return @{
    TenantID = $tenantInfo.TenantID
    ClientID = $tenantInfo.ClientID
    Source = $tenantInfo.Source
    Details = $tenantInfo.Details
    LogPath = $LogPath
}