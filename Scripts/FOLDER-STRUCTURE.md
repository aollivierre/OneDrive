# OneDrive Scripts - Organized Folder Structure

## 📁 Directory Layout

```
Scripts/
├── src/                        # Production-ready scripts
│   ├── Detect-OneDriveConfiguration-RMM.ps1
│   ├── Remediate-OneDriveConfiguration-RMM.ps1
│   ├── Test-OneDriveRMM-AsSystem-StayOpen.ps1
│   └── README-RMM.md
│
├── tests/                      # Test scripts
│   ├── Test-OneDrive-As-SYSTEM-Interactive.ps1
│   ├── Test-OneDriveAutomated.ps1
│   ├── Test-SimpleLogging.ps1
│   ├── Test-StandardizedLogging.ps1
│   ├── test-logging-fix.ps1
│   ├── test-minimal-logging-v2.ps1
│   ├── test-minimal-logging.ps1
│   ├── test-module-version.ps1
│   └── test-rmm-style-logging.ps1
│
├── utils/                      # Utility scripts
│   ├── Get-ActualTenantID.ps1
│   ├── Get-AutoDetectedTenantID.ps1
│   ├── Get-OneDriveRealStatus.ps1
│   ├── Get-OptimalOneDriveLibVersion.ps1
│   ├── Get-TenantID-Enhanced.ps1
│   ├── Find-TenantInfo.ps1
│   ├── Check-StorageSense-Current.ps1
│   ├── Collect-OneDriveStatus-Adaptive.ps1
│   └── Collect-OneDriveStatus-UserContext.ps1
│
├── dev/                        # Development/debugging scripts
│   ├── Fix-OneDriveKFM-Properly.ps1
│   ├── Force-KFMRedirection.ps1
│   ├── Force-OneDrivePolicyApplication.ps1
│   ├── Invoke-OneDriveDetectionRemediation.ps1
│   ├── Invoke-OneDriveDetectionRemediationV2.ps1
│   └── Detect-OneDriveConfiguration.ps1
│
├── Archive/                    # Archived/backup files
│   ├── Test-OneDriveRMM-AsSystem-Production.ps1.bak
│   ├── Archive.ps1
│   ├── archive-files.ps1
│   ├── Detect-OneDriveConfiguration-RMM-Production.ps1
│   └── Remediate-OneDriveConfiguration-RMM-Production.ps1
│
├── logging/                    # Universal logging module (unchanged)
│   ├── logging.psm1           # Main logging module v3.0.0
│   ├── logging.psd1           # Module manifest
│   ├── simple-logging.psm1    # Simplified version
│   ├── logging-original-broken.psm1.bak
│   ├── MODULE-INFO.md
│   ├── README-IMPORTANT.md
│   ├── UNIVERSAL-USAGE.md
│   └── UNIVERSAL_LOGGING_PATTERN.md
│
└── (root)                      # Maintenance/meta scripts
    ├── push-to-github.ps1
    ├── sync-logging-docs.ps1
    ├── check-unicode.ps1
    ├── organize-files.ps1     # Script used for organization
    ├── create-folders.ps1     # Script used to create folders
    ├── move-files.ps1         # Script used to move files
    ├── README.md
    └── FOLDER-STRUCTURE.md    # This file
```

## 📝 Folder Descriptions

### `src/` - Source/Production
Contains the main production-ready scripts that are deployed via RMM:
- **Detection Script**: Checks OneDrive configuration status
- **Remediation Script**: Fixes OneDrive configuration issues
- **Test Wrapper**: Simulates RMM deployment for testing
- **RMM Documentation**: Deployment instructions

### `tests/` - Test Scripts
Contains all test scripts used during development:
- Various logging tests
- SYSTEM context tests
- Automated testing scripts

### `utils/` - Utilities
Helper scripts for specific tasks:
- Tenant ID detection utilities
- OneDrive status collection
- Storage Sense checking

### `dev/` - Development
Scripts used during development and debugging:
- Force policy application
- KFM fixing attempts
- Early detection/remediation versions

### `Archive/` - Archived Files
Older versions and backup files:
- Production versions (now superseded)
- Archive management scripts

### `logging/` - Logging Module
The universal logging module and documentation:
- Main module with fixed line number tracking
- Documentation for usage patterns
- Backup of original broken version

## 🚀 Quick Start

For production deployment, use scripts from the `src/` folder:

```powershell
# Navigate to source folder
cd C:\code\OneDrive\Scripts\src

# Run test wrapper
.\Test-OneDriveRMM-AsSystem-StayOpen.ps1

# Or deploy via RMM directly
powershell.exe -ExecutionPolicy Bypass -File "Detect-OneDriveConfiguration-RMM.ps1"
powershell.exe -ExecutionPolicy Bypass -File "Remediate-OneDriveConfiguration-RMM.ps1"
```

## ⚠️ Important Notes

1. **Path Updates**: The production scripts in `src/` have been updated to reference the logging module correctly using: `Join-Path (Split-Path $PSScriptRoot -Parent) "logging\logging.psm1"`

2. **Test Wrapper**: The test wrapper dynamically determines script locations, so it works regardless of where it's placed.

3. **No Files Deleted**: All files have been moved to appropriate folders, nothing was deleted.

4. **Logging Module**: Remains in its original location as it's referenced by multiple scripts.

---

Last Updated: August 2025