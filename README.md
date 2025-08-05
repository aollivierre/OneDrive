# OneDrive RMM Automation Scripts

A comprehensive PowerShell automation solution for OneDrive for Business deployment and configuration through RMM tools. Features enterprise-grade logging, SYSTEM context support, and dual-version architecture for development and production use.

## 🎯 Purpose

These scripts provide enterprise IT administrators with:
- **RMM-Ready Deployment**: Detection and remediation scripts designed for RMM tools
- **Dual Version Architecture**: Development scripts with modular logging and production scripts with embedded logging
- **SYSTEM Context Support**: Full functionality when running as SYSTEM (typical for RMM deployments)
- **Known Folder Move (KFM)**: Silent configuration including Desktop, Documents, Pictures, and Downloads
- **Files On-Demand**: Automatic enablement to save disk space
- **Tenant Auto-Detection**: Automatically discovers tenant ID from multiple sources
- **Universal Logging**: Advanced logging module with line number tracking and proper error handling

## 📁 Repository Structure

```
OneDrive/
├── Scripts/
│   ├── src/                     # Production scripts (embedded logging)
│   │   ├── Detect-OneDriveConfiguration-RMM-Production.ps1
│   │   ├── Remediate-OneDriveConfiguration-RMM-Production.ps1
│   │   └── Test-OneDriveRMM-AsSystem-StayOpen-Production.ps1
│   ├── dev/                     # Development scripts (modular logging)
│   │   ├── Detect-OneDriveConfiguration-RMM-Dev.ps1
│   │   ├── Remediate-OneDriveConfiguration-RMM-Dev.ps1
│   │   └── Test-OneDriveRMM-AsSystem-StayOpen-Dev.ps1
│   ├── logging/                 # Universal logging module
│   │   └── logging.psm1         # v3.0.0 with line number tracking
│   └── Archive/                 # Historical versions and backups
├── Claude-History/              # Development history and documentation
└── Documentation/               # Additional documentation
```

## 🚀 Key Scripts Overview

### Production Scripts (Scripts/src/)
These scripts have the entire logging module embedded within them for standalone RMM deployment:

1. **Detect-OneDriveConfiguration-RMM-Production.ps1**
   - Detects OneDrive configuration status
   - Returns exit code 0 (configured) or 1 (needs remediation)
   - Outputs RMM-friendly key-value pairs
   - Runs silently by default, use `-EnableDebug` for verbose output

2. **Remediate-OneDriveConfiguration-RMM-Production.ps1**
   - Configures OneDrive with all enterprise settings
   - Enables KFM for all folders including Downloads
   - Configures Files On-Demand and Storage Sense
   - Auto-detects tenant ID from multiple sources

3. **Test-OneDriveRMM-AsSystem-StayOpen-Production.ps1**
   - Test wrapper for production scripts
   - Runs scripts as SYSTEM with PSExec
   - Keeps windows open for debugging
   - Use `-NoDebug` to simulate RMM execution

### Development Scripts (Scripts/dev/)
These scripts import the logging module for easier development and debugging:

1. **Detect-OneDriveConfiguration-RMM-Dev.ps1**
   - Same functionality as production detection
   - Imports logging module from Scripts/logging/
   - Easier to modify during development

2. **Remediate-OneDriveConfiguration-RMM-Dev.ps1**
   - Same functionality as production remediation
   - Imports logging module for cleaner code
   - Use for testing new features

3. **Test-OneDriveRMM-AsSystem-StayOpen-Dev.ps1**
   - Test wrapper for development scripts
   - Identical to production wrapper but points to dev scripts
   - Use for development and testing

## 🛠️ Requirements

- Windows 10 1709+ or Windows 11
- OneDrive for Business client
- PowerShell 5.1 or higher
- Administrative privileges
- Azure AD joined or Hybrid joined devices (for silent config)

## 📖 Quick Start

### For RMM Deployment (Production)
```powershell
# Detection script - returns 0 if configured, 1 if needs remediation
& "C:\Scripts\Detect-OneDriveConfiguration-RMM-Production.ps1"

# Remediation script - configures OneDrive with all settings
& "C:\Scripts\Remediate-OneDriveConfiguration-RMM-Production.ps1" -TenantId "your-tenant-id"

# Or let it auto-detect the tenant ID
& "C:\Scripts\Remediate-OneDriveConfiguration-RMM-Production.ps1"
```

### For Testing (Development)
```powershell
# Test as SYSTEM with debug output
& "C:\code\OneDrive\Scripts\src\Test-OneDriveRMM-AsSystem-StayOpen-Production.ps1"

# Test in production mode (minimal output)
& "C:\code\OneDrive\Scripts\src\Test-OneDriveRMM-AsSystem-StayOpen-Production.ps1" -NoDebug

# Test detection only
& "C:\code\OneDrive\Scripts\src\Test-OneDriveRMM-AsSystem-StayOpen-Production.ps1" -DetectionOnly
```

## 🔧 Key Features

### Detection Capabilities
- OneDrive installation and running status
- Tenant ID configuration and validation
- Known Folder Move (KFM) status for all folders
- Files On-Demand configuration
- Storage Sense integration
- Silent account configuration (SilentAccountConfig)
- Personal sync restrictions

### Remediation Capabilities
- Silent OneDrive installation (optional)
- Automatic tenant ID detection from:
  - Current OneDrive configuration
  - User's email domain
  - Registry policies
  - System management data
- KFM enablement for Desktop, Documents, Pictures, and Downloads
- Files On-Demand activation
- Storage Sense configuration
- Personal account blocking
- Comprehensive registry policy application

### Logging Features
- Universal logging module v3.0.0
- Automatic line number tracking
- Call stack analysis
- SYSTEM context support
- CSV and transcript logging
- Configurable log levels
- RMM-friendly output formatting

## 🏢 Enterprise Deployment

### RMM Tools (Recommended)
Deploy the production scripts directly through your RMM platform:
- **ConnectWise Automate**: Import as PowerShell scripts
- **NinjaRMM**: Create script policies
- **Datto RMM**: Add as components
- **N-able N-central**: Deploy as automation policies

### Configuration Options
```powershell
# Basic deployment with auto-detection
& "Remediate-OneDriveConfiguration-RMM-Production.ps1"

# Specify tenant ID explicitly
& "Remediate-OneDriveConfiguration-RMM-Production.ps1" -TenantId "336dbee2-bd39-4116-b305-3105539e416f"

# Configuration only mode (skip OneDrive installation)
& "Remediate-OneDriveConfiguration-RMM-Production.ps1" -ConfigurationOnly

# Skip auto-detection and require explicit tenant ID
& "Remediate-OneDriveConfiguration-RMM-Production.ps1" -SkipAutoDetection -TenantId "your-tenant-id"
```

## ⚠️ Important Notes

1. **Dual Version System**: 
   - Use production scripts (src/) for RMM deployment
   - Use development scripts (dev/) for testing and development
   - Both versions are functionally identical

2. **SYSTEM Context**: Scripts are designed to work when run as SYSTEM
   - Automatically detects logged-in users
   - Finds user profiles and registry hives
   - Handles both user and machine policies

3. **Logging Locations**:
   - User context: `%TEMP%\OneDrive-*.log`
   - SYSTEM context: `C:\ProgramData\OneDriveRMM\Logs\`
   - Transcripts and CSV logs are automatically created

4. **Downloads Folder KFM**: Requires OneDrive client version 23.174.0827.0001 or later

## 🤝 Contributing

Contributions are welcome! Please:
1. Use the dev scripts for development
2. Test thoroughly with the test wrappers
3. Ensure changes work in SYSTEM context
4. Update both dev and production versions
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Microsoft OneDrive Documentation](https://docs.microsoft.com/en-us/onedrive/)
- [CyberDrain OneDrive Scripts](https://www.cyberdrain.com/automating-with-powershell-deploying-onedrive-and-known-folder-move/)
- [MSEndpointMgr OneDrive Articles](https://msendpointmgr.com/onedrive/)
- PowerShell community for logging best practices
- IT professionals who provided feedback and testing

## 📞 Support

For issues and questions:
- Open an issue in this repository
- Check existing issues for solutions
- Review documentation for common scenarios

---

**Note**: These scripts are provided as-is. Always test in your environment before production deployment.