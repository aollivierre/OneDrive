#Requires -Version 5.1

<#
.SYNOPSIS
    Auto-detects Azure AD Tenant ID from most reliable source
.DESCRIPTION
    Lightweight function for integration into other scripts.
    Returns tenant ID or $null if not found.
.EXAMPLE
    $tenantId = & .\Get-AutoDetectedTenantID.ps1
    if ($tenantId) {
        Write-Host "Detected Tenant ID: $tenantId"
    }
#>

function Get-AutoDetectedTenantID {
    [CmdletBinding()]
    param()
    
    # Method 1: Azure AD Join Status (Most Reliable)
    try {
        $dsregOutput = & dsregcmd /status 2>$null
        if ($dsregOutput) {
            $dsregText = $dsregOutput -join "`n"
            if ($dsregText -match 'TenantId\s*:\s*([a-fA-F0-9\-]{36})') {
                $tenantId = $matches[1]
                if ($tenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                    Write-Verbose "Tenant ID found via dsregcmd: $tenantId"
                    return $tenantId
                }
            }
        }
    }
    catch {
        Write-Verbose "dsregcmd failed: $_"
    }
    
    # Method 2: OneDrive Registry (Current User)
    try {
        $regPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
        if (Test-Path $regPath) {
            $configuredTenantId = Get-ItemPropertyValue -Path $regPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
            if ($configuredTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                Write-Verbose "Tenant ID found in OneDrive registry: $configuredTenantId"
                return $configuredTenantId
            }
        }
    }
    catch {
        Write-Verbose "OneDrive registry check failed: $_"
    }
    
    # Method 3: OneDrive Group Policy
    try {
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        if (Test-Path $policyPath) {
            $kfmTenantId = Get-ItemPropertyValue -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
            if ($kfmTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                Write-Verbose "Tenant ID found in OneDrive policy: $kfmTenantId"
                return $kfmTenantId
            }
        }
    }
    catch {
        Write-Verbose "OneDrive policy check failed: $_"
    }
    
    # Method 4: Office 365 Connected Accounts
    try {
        $officePaths = @(
            "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\ConnectedAccounts",
            "HKCU:\Software\Microsoft\Office\15.0\Common\Identity\ConnectedAccounts"
        )
        
        foreach ($path in $officePaths) {
            if (Test-Path $path) {
                $accounts = Get-ChildItem $path -ErrorAction SilentlyContinue
                foreach ($account in $accounts) {
                    $userTenantId = Get-ItemPropertyValue -Path $account.PSPath -Name "UserTenantId" -ErrorAction SilentlyContinue
                    if ($userTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-Verbose "Tenant ID found in Office 365: $userTenantId"
                        return $userTenantId
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Office 365 check failed: $_"
    }
    
    Write-Verbose "No tenant ID found through auto-detection"
    return $null
}

# If script is run directly, execute the function
if ($MyInvocation.InvocationName -ne '.') {
    Get-AutoDetectedTenantID -Verbose:$VerbosePreference
}