# OneDrive RMM Scripts for Disk Space Remediation

## Overview
These scripts configure OneDrive for optimal disk space usage in preparation for Windows 11 upgrades.

## Scripts

### 1. Detect-OneDriveConfiguration-RMM.ps1
- **Purpose**: Detects current OneDrive configuration state
- **Parameters**:
  - `-ConfigurationOnly`: Returns success if OneDrive not installed (nothing to configure)
  - `-EnableDebug`: Enable verbose logging for troubleshooting
- **Exit Codes**: 
  - 0 = Properly configured (or not applicable in ConfigurationOnly mode)
  - 1 = Remediation needed
- **Checks**:
  - OneDrive installation
  - OneDrive running state
  - Tenant ID configuration
  - Files On-Demand enabled
  - Known Folder Move (KFM) for all 4 folders

### 2. Remediate-OneDriveConfiguration-RMM.ps1
- **Purpose**: Applies OneDrive configuration for disk space optimization
- **Parameters**:
  - `-ConfigurationOnly`: Skip OneDrive installation, only configure existing
  - `-EnableDebug`: Enable verbose logging for troubleshooting
- **Actions**:
  - Installs OneDrive if missing (unless -ConfigurationOnly)
  - Configures tenant ID: 336dbee2-bd39-4116-b305-3105539e416f
  - Enables Files On-Demand
  - Configures KFM for Desktop, Documents, Pictures, Downloads
  - Excludes PST/OST files from sync
  - Starts OneDrive if not running

## RMM Deployment

### Production Deployment (Configuration-Only)

For production environments where OneDrive is pre-installed with Windows:

```powershell
# Detection - configuration only mode
powershell.exe -ExecutionPolicy Bypass -File Detect-OneDriveConfiguration-RMM.ps1 -ConfigurationOnly

# Remediation - configuration only, no download/install
powershell.exe -ExecutionPolicy Bypass -File Remediate-OneDriveConfiguration-RMM.ps1 -ConfigurationOnly
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

- **Tenant ID**: 336dbee2-bd39-4116-b305-3105539e416f
- **Registry Path**: HKLM:\SOFTWARE\Policies\Microsoft\OneDrive
- **Key Settings**:
  - FilesOnDemandEnabled = 1
  - KFMSilentOptIn = [TenantID]
  - KFMSilentOptInDesktop = 1
  - KFMSilentOptInDocuments = 1
  - KFMSilentOptInPictures = 1
  - KFMSilentOptInDownloads = 1