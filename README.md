# OneDrive Enterprise Automation Scripts

A comprehensive collection of PowerShell scripts for OneDrive for Business automation, focusing on enterprise deployment, Known Folder Move (KFM), Files On-Demand, and Windows 11 upgrade disk space remediation.

## 🎯 Purpose

These scripts are designed to help IT administrators:
- Automate OneDrive deployment and configuration at scale
- Enable Known Folder Move (KFM) silently across the organization
- Configure Files On-Demand to save disk space
- Prepare Windows 10 devices for Windows 11 upgrade by freeing disk space
- Monitor OneDrive sync status across endpoints
- Redirect user folders including Downloads to OneDrive

## 📁 Repository Structure

```
OneDrive/
├── Examples/                    # Production-tested example scripts
├── Scripts/                     # Main automation scripts
├── Modules/                     # PowerShell modules
├── Documentation/               # Detailed documentation
└── Tests/                       # Test scripts and validation
```

## 🚀 Key Features

### Detection & Monitoring
- Check OneDrive installation status
- Monitor sync status (syncing, complete, error states)
- Verify KFM and Files On-Demand configuration
- Run from SYSTEM context (RMM-friendly)

### Configuration & Remediation
- Silent account configuration
- Enable Known Folder Move for Desktop, Documents, Pictures
- Custom Downloads folder redirection
- Files On-Demand activation
- Registry-based policy configuration

### Disk Space Management
- Free up space for Windows 11 upgrades
- Convert files to online-only (Files On-Demand)
- Backup user data before conversion
- Calculate potential space savings

## 🛠️ Requirements

- Windows 10 1709+ or Windows 11
- OneDrive for Business client
- PowerShell 5.1 or higher
- Administrative privileges
- Azure AD joined or Hybrid joined devices (for silent config)

## 📖 Quick Start

### Basic OneDrive Configuration
```powershell
# Configure OneDrive with KFM and Files On-Demand
.\Scripts\Configure-OneDriveKFM.ps1 -TenantID "your-tenant-id"
```

### Monitor OneDrive Status
```powershell
# Check OneDrive sync status from RMM
.\Scripts\Get-OneDriveStatus.ps1
```

### Enable Files On-Demand
```powershell
# Convert all files to online-only to save space
.\Scripts\Enable-FilesOnDemand.ps1 -FreeSpaceTarget 32GB
```

## 📚 Documentation

- [Deployment Guide](./Documentation/DeploymentGuide.md)
- [RMM Integration](./Documentation/RMMIntegration.md)
- [Troubleshooting](./Documentation/Troubleshooting.md)
- [Best Practices](./Documentation/BestPractices.md)

## 🔧 Script Categories

### Core Scripts
- **Configure-OneDriveKFM.ps1** - Main configuration script for KFM and policies
- **Get-OneDriveStatus.ps1** - Monitor sync status from SYSTEM context
- **Enable-FilesOnDemand.ps1** - Activate and manage Files On-Demand
- **Backup-UserData.ps1** - Backup user files before operations

### Utility Scripts
- **Download-OneDriveLib.ps1** - Download required DLL files
- **Clear-OneDriveCache.ps1** - Clear OneDrive cache
- **Test-OneDriveHealth.ps1** - Comprehensive health check

### Migration Scripts
- **Migrate-ToOneDrive.ps1** - Migrate local folders to OneDrive
- **Redirect-DownloadsFolder.ps1** - Redirect Downloads folder

## 🏢 Enterprise Deployment

### Intune
```powershell
# Deploy via Intune Win32 app
.\Deploy-OneDriveConfig.intunewin
```

### SCCM/ConfigMgr
```powershell
# Deploy via Configuration Manager
.\Deploy-OneDriveConfig.ps1 -DeploymentMethod SCCM
```

### RMM Tools
- ConnectWise Automate
- NinjaRMM
- Datto RMM
- N-able N-central

## ⚠️ Important Notes

1. **Test First**: Always test in a pilot group before organization-wide deployment
2. **Backup**: Ensure users have backups before enabling KFM
3. **Network**: Consider network bandwidth when deploying to many devices
4. **Licensing**: Requires appropriate Microsoft 365 licenses

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Microsoft OneDrive team for official documentation
- PowerShell community for script contributions
- IT professionals who shared their experiences

## 📞 Support

For issues and questions:
- Open an issue in this repository
- Check existing issues for solutions
- Review documentation for common scenarios

---

**Note**: These scripts are provided as-is. Always test in your environment before production deployment.