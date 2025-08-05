#Requires -Version 5.1

<#
.SYNOPSIS
    Enhanced Tenant ID Detection with Multiple Methods
.DESCRIPTION
    Detects tenant ID from multiple sources with reliability scoring:
    - Azure AD/Entra ID join status (most reliable)
    - OneDrive registry configuration
    - Office 365 configuration
    - Domain controller queries
    Returns the most reliable tenant ID found
.PARAMETER EnableDebug
    Shows detailed debug information
.PARAMETER TestAllMethods
    Tests all detection methods even after finding a tenant ID
#>

[CmdletBinding()]
param(
    [switch]$EnableDebug,
    [switch]$TestAllMethods
)

# Initialize results
$results = @{
    TenantID = $null
    Source = "Not found"
    Reliability = 0  # 0-100 score
    AllFindings = @()
    Errors = @()
}

function Write-DebugInfo {
    param($Message, $Level = "INFO")
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "DEBUG" { "Gray" }
        default { "White" }
    }
    
    if ($EnableDebug -or $Level -in @("ERROR", "WARNING", "SUCCESS")) {
        Write-Host "[$Level] $Message" -ForegroundColor $color
    }
}

function Test-TenantID {
    param($TenantID)
    # Validate GUID format
    return $TenantID -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
}

Write-Host "=== Enhanced Tenant ID Detection ===" -ForegroundColor Cyan
Write-DebugInfo "Starting comprehensive tenant ID detection" "INFO"

# Method 1: Azure AD / Entra ID Join Status (Most Reliable - Score: 100)
Write-DebugInfo "Method 1: Checking Azure AD/Entra ID join status..." "INFO"
try {
    $dsregOutput = & dsregcmd /status 2>$null
    if ($dsregOutput) {
        # Parse dsregcmd output
        $dsregText = $dsregOutput -join "`n"
        
        # Check Azure AD Join section
        if ($dsregText -match 'AzureAdJoined\s*:\s*YES') {
            Write-DebugInfo "Device is Azure AD joined" "SUCCESS"
            if ($dsregText -match 'TenantId\s*:\s*([a-fA-F0-9\-]{36})') {
                $tenantId = $matches[1]
                if (Test-TenantID $tenantId) {
                    $results.AllFindings += @{
                        Method = "Azure AD Join"
                        TenantID = $tenantId
                        Reliability = 100
                        Details = "Device is Azure AD joined"
                    }
                    if ($results.Reliability -lt 100) {
                        $results.TenantID = $tenantId
                        $results.Source = "Azure AD Join (dsregcmd)"
                        $results.Reliability = 100
                    }
                    Write-DebugInfo "Found Tenant ID from Azure AD join: $tenantId" "SUCCESS"
                }
            }
        }
        
        # Check Workplace Join section (Azure AD Registered)
        elseif ($dsregText -match 'WorkplaceJoined\s*:\s*YES') {
            Write-DebugInfo "Device is Azure AD registered (not joined)" "INFO"
            if ($dsregText -match 'TenantId\s*:\s*([a-fA-F0-9\-]{36})') {
                $tenantId = $matches[1]
                if (Test-TenantID $tenantId) {
                    $results.AllFindings += @{
                        Method = "Azure AD Registered"
                        TenantID = $tenantId
                        Reliability = 95
                        Details = "Device is Azure AD registered"
                    }
                    if ($results.Reliability -lt 95) {
                        $results.TenantID = $tenantId
                        $results.Source = "Azure AD Registered (dsregcmd)"
                        $results.Reliability = 95
                    }
                    Write-DebugInfo "Found Tenant ID from Azure AD registration: $tenantId" "SUCCESS"
                }
            }
        }
        else {
            Write-DebugInfo "Device is not Azure AD joined or registered" "INFO"
        }
    }
}
catch {
    $results.Errors += "dsregcmd error: $_"
    Write-DebugInfo "Error running dsregcmd: $_" "ERROR"
}

# Method 2: Certificate Store (Score: 90)
if (!$results.TenantID -or $TestAllMethods) {
    Write-DebugInfo "Method 2: Checking certificate store..." "INFO"
    try {
        $certs = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue
        foreach ($cert in $certs) {
            if ($cert.Subject -match 'CN=([a-fA-F0-9\-]{36})' -or $cert.Issuer -match 'DC=([a-fA-F0-9\-]{36})') {
                $possibleTenantId = $matches[1]
                if (Test-TenantID $possibleTenantId) {
                    $results.AllFindings += @{
                        Method = "Certificate Store"
                        TenantID = $possibleTenantId
                        Reliability = 90
                        Details = "From certificate: $($cert.Subject)"
                    }
                    if ($results.Reliability -lt 90) {
                        $results.TenantID = $possibleTenantId
                        $results.Source = "Certificate Store"
                        $results.Reliability = 90
                    }
                    Write-DebugInfo "Found possible Tenant ID in certificate: $possibleTenantId" "INFO"
                }
            }
        }
    }
    catch {
        $results.Errors += "Certificate store error: $_"
        Write-DebugInfo "Error checking certificates: $_" "WARNING"
    }
}

# Method 3: OneDrive Registry Configuration (Score: 85)
if (!$results.TenantID -or $TestAllMethods) {
    Write-DebugInfo "Method 3: Checking OneDrive registry configuration..." "INFO"
    
    # Check HKCU for current user
    $userRegPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path $userRegPath) {
        try {
            $regKeys = Get-ItemProperty -Path $userRegPath -ErrorAction SilentlyContinue
            if ($regKeys.ConfiguredTenantId -and (Test-TenantID $regKeys.ConfiguredTenantId)) {
                $results.AllFindings += @{
                    Method = "OneDrive User Registry"
                    TenantID = $regKeys.ConfiguredTenantId
                    Reliability = 85
                    Details = "ConfiguredTenantId in HKCU"
                }
                if ($results.Reliability -lt 85) {
                    $results.TenantID = $regKeys.ConfiguredTenantId
                    $results.Source = "OneDrive Registry (HKCU)"
                    $results.Reliability = 85
                }
                Write-DebugInfo "Found Tenant ID in OneDrive registry: $($regKeys.ConfiguredTenantId)" "SUCCESS"
            }
        }
        catch {
            $results.Errors += "OneDrive registry error: $_"
        }
    }
    
    # Check HKLM policies
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    if (Test-Path $policyPath) {
        try {
            $policyKeys = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
            if ($policyKeys.KFMSilentOptIn -and (Test-TenantID $policyKeys.KFMSilentOptIn)) {
                $results.AllFindings += @{
                    Method = "OneDrive Group Policy"
                    TenantID = $policyKeys.KFMSilentOptIn
                    Reliability = 80
                    Details = "KFMSilentOptIn in HKLM"
                }
                if ($results.Reliability -lt 80) {
                    $results.TenantID = $policyKeys.KFMSilentOptIn
                    $results.Source = "OneDrive Policy (HKLM)"
                    $results.Reliability = 80
                }
                Write-DebugInfo "Found Tenant ID in OneDrive policy: $($policyKeys.KFMSilentOptIn)" "SUCCESS"
            }
        }
        catch {
            $results.Errors += "OneDrive policy error: $_"
        }
    }
}

# Method 4: Office 365 Configuration (Score: 75)
if (!$results.TenantID -or $TestAllMethods) {
    Write-DebugInfo "Method 4: Checking Office 365 configuration..." "INFO"
    
    # Check Office identity
    $officeIdentityPaths = @(
        "HKCU:\Software\Microsoft\Office\16.0\Common\Identity",
        "HKCU:\Software\Microsoft\Office\15.0\Common\Identity"
    )
    
    foreach ($path in $officeIdentityPaths) {
        if (Test-Path $path) {
            try {
                $identityKeys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                # Look for ADUserName which might contain tenant info
                if ($identityKeys.ADUserName -match '@(.+)\.onmicrosoft\.com') {
                    Write-DebugInfo "Found Office 365 identity: $($identityKeys.ADUserName)" "INFO"
                }
                
                # Check connected accounts
                $connectedPath = Join-Path $path "ConnectedAccounts"
                if (Test-Path $connectedPath) {
                    $accounts = Get-ChildItem $connectedPath
                    foreach ($account in $accounts) {
                        $accountProps = Get-ItemProperty -Path $account.PSPath -ErrorAction SilentlyContinue
                        if ($accountProps.UserTenantId -and (Test-TenantID $accountProps.UserTenantId)) {
                            $results.AllFindings += @{
                                Method = "Office 365 Connected Account"
                                TenantID = $accountProps.UserTenantId
                                Reliability = 75
                                Details = "From account: $($accountProps.UserPrincipalName)"
                            }
                            if ($results.Reliability -lt 75) {
                                $results.TenantID = $accountProps.UserTenantId
                                $results.Source = "Office 365 Configuration"
                                $results.Reliability = 75
                            }
                            Write-DebugInfo "Found Tenant ID in Office config: $($accountProps.UserTenantId)" "SUCCESS"
                        }
                    }
                }
            }
            catch {
                $results.Errors += "Office configuration error: $_"
            }
        }
    }
}

# Method 5: WMI/CIM Azure AD Info (Score: 70)
if (!$results.TenantID -or $TestAllMethods) {
    Write-DebugInfo "Method 5: Checking WMI for Azure AD info..." "INFO"
    try {
        # Check MDM enrollment
        $mdmEnrollment = Get-CimInstance -Namespace "root/cimv2/mdm/dmmap" -ClassName "MDM_EnrollmentStatusTracking_Setup01" -ErrorAction SilentlyContinue
        if ($mdmEnrollment) {
            Write-DebugInfo "Found MDM enrollment information" "INFO"
        }
    }
    catch {
        Write-DebugInfo "No MDM enrollment found or access denied" "DEBUG"
    }
}

# Method 6: Event Log Analysis (Score: 65)
if (!$results.TenantID -or $TestAllMethods) {
    Write-DebugInfo "Method 6: Checking event logs for Azure AD activity..." "INFO"
    try {
        $aadEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AAD/Operational'; ID=1098} -MaxEvents 10 -ErrorAction SilentlyContinue
        foreach ($event in $aadEvents) {
            if ($event.Message -match 'TenantId:\s*([a-fA-F0-9\-]{36})') {
                $tenantId = $matches[1]
                if (Test-TenantID $tenantId) {
                    $results.AllFindings += @{
                        Method = "AAD Event Log"
                        TenantID = $tenantId
                        Reliability = 65
                        Details = "From AAD operational log"
                    }
                    if ($results.Reliability -lt 65) {
                        $results.TenantID = $tenantId
                        $results.Source = "AAD Event Log"
                        $results.Reliability = 65
                    }
                    Write-DebugInfo "Found Tenant ID in event log: $tenantId" "INFO"
                    break
                }
            }
        }
    }
    catch {
        Write-DebugInfo "Could not access AAD event logs" "DEBUG"
    }
}

# Display Results
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "TENANT ID DETECTION RESULTS" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

if ($results.TenantID) {
    Write-Host "`nBEST MATCH FOUND:" -ForegroundColor Green
    Write-Host "  Tenant ID: $($results.TenantID)" -ForegroundColor Green
    Write-Host "  Source: $($results.Source)" -ForegroundColor Yellow
    Write-Host "  Reliability: $($results.Reliability)%" -ForegroundColor Yellow
} else {
    Write-Host "`nNO TENANT ID FOUND" -ForegroundColor Red
    Write-Host "This device may not be connected to any Azure AD tenant." -ForegroundColor Yellow
}

if ($TestAllMethods -and $results.AllFindings.Count -gt 0) {
    Write-Host "`nALL FINDINGS:" -ForegroundColor Cyan
    $results.AllFindings | Sort-Object -Property Reliability -Descending | ForEach-Object {
        Write-Host "`n  Method: $($_.Method)" -ForegroundColor White
        Write-Host "  Tenant ID: $($_.TenantID)" -ForegroundColor Gray
        Write-Host "  Reliability: $($_.Reliability)%" -ForegroundColor Gray
        Write-Host "  Details: $($_.Details)" -ForegroundColor Gray
    }
}

if ($results.Errors.Count -gt 0 -and $EnableDebug) {
    Write-Host "`nERRORS ENCOUNTERED:" -ForegroundColor Red
    $results.Errors | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Red
    }
}

Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan

# Return the most reliable tenant ID found
return $results