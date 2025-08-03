# Universal Logging Pattern for Detection Scripts

This document describes how to use the enhanced logging module universally across different detection scripts and projects.

## Overview

The logging module has been enhanced with an `Initialize-Logging` function that allows you to configure custom paths and names for any project, making it truly universal and reusable.

## Basic Usage Pattern

```powershell
# 1. Import the logging module
$LoggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
if (Test-Path $LoggingModulePath) {
    Import-Module $LoggingModulePath -Force -WarningAction SilentlyContinue
    
    # 2. Initialize logging with your custom configuration
    Initialize-Logging -BaseLogPath "C:\ProgramData\YourApp\Logs" `
                      -JobName "YourJobName" `
                      -ParentScriptName "Your_Script_Name"
    
    # 3. Set logging mode (optional, defaults to 'Off')
    $LoggingMode = 'SilentMode'  # Options: 'EnableDebug', 'SilentMode', 'Off'
    
    # 4. Start logging
    Write-AppDeploymentLog -Message "Script started" -Level "Information" -Mode $LoggingMode
}
```

## Configuration Parameters

### Initialize-Logging Parameters

- **BaseLogPath** (Required): The root directory for your logs (e.g., `C:\ProgramData\YourApp\Logs`)
- **JobName** (Required): A descriptive name for the job/task (e.g., `"Detection"`, `"Installation"`)
- **ParentScriptName** (Required): The name of your script (e.g., `"Win11_Detection_ConnectWise"`)
- **CustomLogPath** (Optional): Override the automatic path generation with a specific file path

### Logging Modes

- **EnableDebug**: Logs to both file and console
- **SilentMode**: Logs to file only (recommended for production)
- **Off**: No logging (default if not specified)

## Example Implementations

### Example 1: Windows 11 Detection Script
```powershell
Initialize-Logging -BaseLogPath "C:\ProgramData\Win11Scheduler\Logs\Detection" `
                  -JobName "Win11Detection" `
                  -ParentScriptName "Win11_Detection_ConnectWise"
```

### Example 2: Software Installation Script
```powershell
Initialize-Logging -BaseLogPath "C:\ProgramData\MyCompany\Logs\Installations" `
                  -JobName "SoftwareDeployment" `
                  -ParentScriptName "Install_Office365"
```

### Example 3: System Health Check Script
```powershell
Initialize-Logging -BaseLogPath "C:\ProgramData\HealthChecks\Logs" `
                  -JobName "SystemHealth" `
                  -ParentScriptName "Daily_Health_Check"
```

## Log File Structure

The logging module automatically creates a structured directory hierarchy:
```
BaseLogPath\
├── YYYY-MM-DD\
│   └── ParentScriptName\
│       └── ComputerName-ScriptName-UserType-UserName-ParentScriptName-activity-timestamp.log
```

## Advanced Features

### CSV Logging
The module also creates CSV logs for structured data analysis:
```
BaseLogPath\CSV\
├── YYYY-MM-DD\
│   └── ParentScriptName\
│       └── *.csv
```

### Network Logging
If configured, logs can also be written to network shares for centralized collection.

### Log Rotation
The module automatically manages log rotation:
- Local logs: Keeps maximum 7 files
- Network logs: Keeps maximum 5 files

## Best Practices

1. **Always Initialize First**: Call `Initialize-Logging` before any logging operations
2. **Use Silent Mode in Production**: Prevents console output in automated environments
3. **Consistent Naming**: Use consistent JobName and ParentScriptName across runs
4. **Error Handling**: The module handles its own errors gracefully - logging failures won't crash your script
5. **Module Location**: Keep the logging module in a `logging` subdirectory relative to your script

## Migration from Custom Logging

If you have existing scripts with custom logging:

1. Copy the enhanced logging module to your script's directory
2. Replace custom logging code with `Initialize-Logging` and `Write-AppDeploymentLog` calls
3. Update any custom log readers to look in the new location

## Troubleshooting

### Logs Not Being Created
- Verify the BaseLogPath exists and is writable
- Check that the logging module loaded successfully
- Ensure Initialize-Logging is called before any logging attempts
- Verify the Mode parameter is not 'Off'

### Wrong Log Location
- Check that Initialize-Logging is called with correct parameters
- Ensure no global variables are overriding the configuration

## Complete Working Example

```powershell
#region Logging Setup
$LoggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
$script:LoggingEnabled = $false
$script:LoggingMode = 'SilentMode'

if (Test-Path $LoggingModulePath) {
    try {
        Import-Module $LoggingModulePath -Force -WarningAction SilentlyContinue
        $script:LoggingEnabled = $true
        
        # Initialize with your custom paths
        Initialize-Logging -BaseLogPath "C:\ProgramData\MyApp\Logs\Detection" `
                          -JobName "AppDetection" `
                          -ParentScriptName "Detect_MyApp_Installation"
        
        # Start logging
        Write-AppDeploymentLog -Message "Detection script started" -Level "Information" -Mode $script:LoggingMode
        Write-AppDeploymentLog -Message "Computer: $env:COMPUTERNAME" -Level "Information" -Mode $script:LoggingMode
    }
    catch {
        $script:LoggingEnabled = $false
        # Continue without logging
    }
}

# Helper function for consistent logging
function Write-DetectionLog {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Information'
    )
    
    if ($script:LoggingEnabled) {
        Write-AppDeploymentLog -Message $Message -Level $Level -Mode $script:LoggingMode
    }
}
#endregion

# Your script logic here
Write-DetectionLog -Message "Performing detection checks..." -Level "Information"
```

This pattern ensures consistent, reliable logging across all your detection scripts while maintaining the full power of the enhanced logging module.