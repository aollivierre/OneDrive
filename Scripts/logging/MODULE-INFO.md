# Logging Module Information

## Module Details

- **Module Name**: logging
- **Version**: 2.0.0
- **Author**: System Administrator
- **Last Updated**: 2025-08-02
- **PowerShell Version Required**: 5.1+

## Module Files

### Primary Location (Used by RMM Scripts)
```
C:\code\Win11UpgradeScheduler\Win11Detection\src\logging\
├── logging.psm1     # Main module file (with comment-based help)
├── logging.psd1     # Module manifest (versioning & metadata)
├── UNIVERSAL_LOGGING_PATTERN.md
└── README-IMPORTANT.md
```

### Secondary Location
```
C:\code\OneDrive\Scripts\logging\
├── logging.psm1     # Main module file (identical to primary)
├── logging.psd1     # Module manifest (identical to primary)
├── simple-logging.psm1     # Alternative simple implementation
├── logging-original-broken.psm1.bak     # Archive of broken version
├── UNIVERSAL_LOGGING_PATTERN.md
├── README-IMPORTANT.md
└── MODULE-INFO.md   # This file
```

## Import Methods

### Method 1: Using Module Manifest (Recommended)
```powershell
Import-Module "C:\code\Win11UpgradeScheduler\Win11Detection\src\logging\logging.psd1"
```

### Method 2: Direct Module Import
```powershell
Import-Module "C:\code\OneDrive\Scripts\logging\logging.psm1"
```

## Key Features

1. **Accurate Line Numbers**: Shows exact line numbers where logging functions are called
2. **Wrapper Function Support**: Works correctly with functions like Write-DetectionLog
3. **Multiple Log Levels**: Information, Warning, Error, Debug
4. **Console & File Output**: Configurable output destinations
5. **CSV Logging**: Structured data export for analysis
6. **Version Tracking**: Built-in version management

## Version History

### Version 2.0.0 (2025-08-02)
- Fixed line number detection for wrapper functions
- Added comprehensive module documentation
- Created module manifest (.psd1)
- Enhanced call stack navigation

### Version 1.0.0 (Original)
- Basic logging functionality
- Had issues with line number detection

## Testing

To verify the module is working correctly:

```powershell
# Import module
Import-Module ".\logging.psd1"

# Check version
Get-LoggingModuleVersion

# Test logging
Write-AppDeploymentLog -Message "Test message" -Level "Information"
```

## Notes

- Both module locations contain identical, fixed versions
- The RMM scripts prioritize the Win11Detection path
- Always update both locations when making changes
- The module now includes full comment-based help accessible via Get-Help