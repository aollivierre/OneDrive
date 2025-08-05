# OneDrive RMM Scripts for Disk Space Remediation

## Overview
These scripts configure OneDrive for optimal disk space usage in preparation for Windows 11 upgrades.

## Scripts

### 1. Detect-OneDriveConfiguration-RMM.ps1
- **Purpose**: Detects current OneDrive configuration state
- **Parameters**:
  - `-ExpectedTenantId`: Optional tenant ID to verify (e.g., "336dbee2-bd39-4116-b305-3105539e416f")
  - `-ConfigurationOnly`: Returns success if OneDrive not installed (nothing to configure)
  - `-EnableDebug`: Enable verbose logging for troubleshooting
- **Exit Codes**: 
  - 0 = Properly configured (or not applicable in ConfigurationOnly mode)
  - 1 = Remediation needed
- **Checks**:
  - OneDrive installation
  - OneDrive running state
  - Tenant ID configuration (optional verification)
  - Files On-Demand enabled
  - Known Folder Move (KFM) for all 4 folders
  - Storage Sense configuration
  - Auto-login (SilentAccountConfig)
  - Personal account blocking (DisablePersonalSync)

### 2. Remediate-OneDriveConfiguration-RMM.ps1
- **Purpose**: Applies OneDrive configuration for disk space optimization
- **Parameters**:
  - `-TenantId`: Your organization's Azure AD tenant ID (optional - auto-detects by default)
  - `-SkipAutoDetection`: Disables auto-detection, requires explicit TenantId
  - `-StorageSenseDays`: Days before converting files to online-only (default: 30)
  - `-ConfigurationOnly`: Skip OneDrive installation, only configure existing
  - `-EnableDebug`: Enable verbose logging for troubleshooting
- **Auto-Detection** (Default Behavior):
  - Automatically detects tenant ID from device configuration
  - Detection methods (in order of reliability):
    1. Azure AD/Entra ID join status via `dsregcmd`
    2. OneDrive registry configuration (HKCU)
    3. OneDrive Group Policy (HKLM)
- **Actions**:
  - Installs OneDrive if missing (unless -ConfigurationOnly)
  - Configures your specified tenant ID
  - Enables Files On-Demand
  - Configures KFM for Desktop, Documents, Pictures, Downloads
  - Enables Storage Sense for automatic disk space management
  - Excludes PST/OST files from sync
  - Enables auto-login with Windows credentials
  - Blocks personal OneDrive accounts
  - Starts OneDrive if not running

## RMM Deployment

### Production Deployment (Configuration-Only)

For production environments where OneDrive is pre-installed with Windows:

```powershell
# Detection - configuration only mode
powershell.exe -ExecutionPolicy Bypass -File Detect-OneDriveConfiguration-RMM.ps1 -ConfigurationOnly

# Detection - with tenant verification
powershell.exe -ExecutionPolicy Bypass -File Detect-OneDriveConfiguration-RMM.ps1 -ConfigurationOnly -ExpectedTenantId "YOUR-TENANT-ID-HERE"

# Remediation - auto-detection (default)
powershell.exe -ExecutionPolicy Bypass -File Remediate-OneDriveConfiguration-RMM.ps1 -ConfigurationOnly

# Remediation - with explicit tenant ID (skip auto-detection)
powershell.exe -ExecutionPolicy Bypass -File Remediate-OneDriveConfiguration-RMM.ps1 -TenantId "YOUR-TENANT-ID-HERE" -ConfigurationOnly -SkipAutoDetection
```

In ConfigurationOnly mode:
- Detection returns success (0) if OneDrive not installed
- Remediation exits with error (1) if OneDrive not installed
- No downloads or installations are attempted

### ConnectWise Automate
1. Create Detection script:
   - Script Type: PowerShell
   - Exit Code Success: 0
   - Exit Code Failure: 1

2. Create Remediation script:
   - Script Type: PowerShell
   - Exit Code Success: 0
   - **Parameters**: Add `-ConfigurationOnly` for production

3. Create monitor/policy:
   - Run detection daily/weekly
   - If detection fails, run remediation
   - Alert on remediation failures

## Testing

### Test as SYSTEM (mimics RMM):
```powershell
.\Test-OneDriveRMM-AsSystem.ps1
```

### Simple test (current user):
```powershell
.\Test-OneDriveRMM-Simple.ps1
```

## Important Notes

1. **SYSTEM Context**: These scripts are designed to run as SYSTEM via RMM
2. **User Login**: Some settings take effect only after user login
3. **Group Policy**: Scripts use Group Policy registry keys for configuration
4. **Logs**: Check %TEMP%\OneDrive-*.log for detailed logging

## Configuration Details

- **Tenant ID**: Must be provided as parameter (e.g., "336dbee2-bd39-4116-b305-3105539e416f")
- **Registry Path**: HKLM:\SOFTWARE\Policies\Microsoft\OneDrive
- **Key Settings**:
  - FilesOnDemandEnabled = 1
  - KFMSilentOptIn = [Your-TenantID]
  - KFMSilentOptInDesktop = 1
  - KFMSilentOptInDocuments = 1
  - KFMSilentOptInPictures = 1
  - KFMSilentOptInDownloads = 1 (if OneDrive version 23.002+)
  - SilentAccountConfig = 1
  - DisablePersonalSync = 1
  
## Finding Your Tenant ID

1. **Azure AD Portal**: 
   - Go to portal.azure.com
   - Navigate to Azure Active Directory
   - Find "Tenant ID" in the Overview section

2. **Microsoft 365 Admin Center**:
   - Go to admin.microsoft.com
   - Settings → Org settings → Organization profile
   - Look for "Tenant ID"

3. **PowerShell** (on a domain-joined machine):
   ```powershell
   (Get-AzureADTenantDetail).ObjectId
   ```

4. **Auto-Detection Script**:
   ```powershell
   # Test auto-detection capabilities
   .\Get-TenantID-Enhanced.ps1 -EnableDebug -TestAllMethods
   ```