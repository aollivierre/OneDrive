# OneDrive Detection and Remediation Scripts

This collection of PowerShell scripts provides comprehensive OneDrive for Business detection and remediation capabilities for enterprise environments, with a focus on RMM deployment and Windows 11 upgrade preparation.

## Script Overview

### 1. Invoke-OneDriveDetectionRemediationV2.ps1 (Recommended)
The most comprehensive script that incorporates community best practices from:
- **CyberDrain**: Process impersonation and user context execution
- **Jos Lieben**: Silent configuration and VBS wrapper support
- **Per Larsen**: Registry-based KFM configuration

**Key Features:**
- ✅ Robust user impersonation from SYSTEM context
- ✅ JSON-based status tracking with OneDriveLib.dll
- ✅ x86/x64 architecture auto-detection and switching
- ✅ Downloads folder redirection with optional content migration
- ✅ VBS wrapper creation for silent logon execution
- ✅ Comprehensive error handling and logging
- ✅ Files On-Demand optimization for disk space

**Usage:**
```powershell
# Detection only
.\Invoke-OneDriveDetectionRemediationV2.ps1 -TenantID "your-tenant-id"

# Detection and remediation
.\Invoke-OneDriveDetectionRemediationV2.ps1 -TenantID "your-tenant-id" -RemediationMode $true

# Full remediation with content copy and VBS wrapper
.\Invoke-OneDriveDetectionRemediationV2.ps1 -TenantID "your-tenant-id" -RemediationMode $true -CopyFolderContents $true -CreateVBSWrapper $true
```

### 2. Detect-OneDriveConfiguration.ps1
Lightweight detection script optimized for RMM scheduled tasks.

**Features:**
- Simple exit codes (0 = healthy, 1 = issues detected)
- Minimal dependencies
- Fast execution
- Clear console output

**Usage:**
```powershell
.\Detect-OneDriveConfiguration.ps1 -TenantID "your-tenant-id"
```

### 3. Remediate-OneDriveConfiguration.ps1
Focused remediation script for RMM deployment.

**Features:**
- Registry-based configuration
- Scheduled task creation for user context operations
- Logging to ProgramData

**Usage:**
```powershell
.\Remediate-OneDriveConfiguration.ps1 -TenantID "your-tenant-id"
```

### 4. Test-OneDriveScripts.ps1
Testing utility for validation and troubleshooting.

**Features:**
- Tests both user and SYSTEM contexts
- Displays current configuration
- Validates registry settings

**Usage:**
```powershell
.\Test-OneDriveScripts.ps1 -TenantID "your-tenant-id"
```

## Key Technologies Used

### User Impersonation (CyberDrain Method)
The scripts use advanced Windows API calls to execute OneDrive operations in user context when running from SYSTEM:
- `CreateProcessAsUser` for process creation
- `WTSEnumerateSessions` for active session detection
- `DuplicateTokenEx` for token management

### OneDriveLib.dll Integration
- Automatically downloads from official GitHub repository
- Provides access to OneDrive sync status APIs
- Supports both Windows 10 and Windows 11

### Registry Configuration
All scripts implement Microsoft's recommended registry settings:
- `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive`
  - `KFMSilentOptIn`: Your Tenant ID
  - `FilesOnDemandEnabled`: 1
  - `SilentAccountConfig`: 1
  - `KFMBlockOptOut`: 1

### Downloads Folder Redirection
Since Downloads isn't included in native KFM, the scripts implement custom redirection:
- Registry modification of shell folder paths
- Optional content migration with robocopy
- Proper GUID-based folder identification

## RMM Deployment Guide

### Detection Schedule
1. Deploy `Detect-OneDriveConfiguration.ps1` as a scheduled script
2. Run every 4-6 hours
3. Alert on exit code 1

### Remediation Workflow
1. Use detection script to identify issues
2. Deploy `Remediate-OneDriveConfiguration.ps1` when issues detected
3. Re-run detection after 30 minutes to verify

### Best Practices
- Always test with a pilot group first
- Monitor network bandwidth during KFM rollout
- Allow 2-4 weeks for full sync before Windows 11 upgrade
- Limit to 1,000 devices per day for large deployments

## Disk Space Optimization

The scripts support Windows 11 upgrade preparation by:
1. Enabling Files On-Demand
2. Converting existing files to online-only placeholders
3. Redirecting user folders to OneDrive
4. Monitoring free space against 32GB requirement

Expected space savings:
- KFM with Files On-Demand: 40-60GB per device
- Downloads folder redirection: Additional 5-15GB
- Total potential: 45-75GB freed

## Troubleshooting

### Common Issues

1. **"No user logged in"**
   - Normal when running as SYSTEM with no active session
   - Script will attempt remediation but some features require user context

2. **"Failed to download OneDriveLib.dll"**
   - Check internet connectivity
   - Verify GitHub access isn't blocked
   - Manually download and place in `C:\ProgramData\OneDriveRemediation`

3. **"OneDrive not starting"**
   - Verify OneDrive is installed
   - Check for conflicting GPOs
   - Review Windows Event Log

### Log Locations
- Main logs: `C:\ProgramData\OneDriveRemediation\OneDriveRemediation_*.log`
- Status files: `C:\ProgramData\OneDriveRemediation\*.json`
- Robocopy logs: `C:\ProgramData\OneDriveRemediation\Downloads_*.log`

## Security Considerations

- Scripts require administrative privileges
- Tenant ID is stored in registry (not considered sensitive)
- No user credentials are handled by the scripts
- All operations use Windows security context

## Version History

### V2.0.0 (Current)
- Incorporated CyberDrain's process impersonation
- Added Jos Lieben's VBS wrapper support
- Enhanced architecture detection
- Improved error handling

### V1.0.0
- Initial release with basic detection and remediation
- Registry-based configuration
- Simple user context handling

## Credits

These scripts incorporate ideas and code from:
- **CyberDrain** (Kelvin Tegelaar): OneDrive monitoring and user impersonation
- **Jos Lieben**: Silent configuration and folder redirection
- **Per Larsen**: Registry-based KFM implementation
- **Microsoft**: Official OneDrive documentation and samples

## License

These scripts are provided as-is for educational and enterprise use. Please review and test thoroughly before production deployment.