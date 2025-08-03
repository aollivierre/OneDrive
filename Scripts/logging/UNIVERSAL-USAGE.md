# Universal PowerShell Logging Module - Usage Guide

## Why This Module is Truly Universal

This logging module is **100% generic and application-agnostic**. It contains:
- ❌ NO hardcoded paths (except configurable defaults)
- ❌ NO application-specific logic
- ❌ NO external dependencies
- ❌ NO proprietary code
- ✅ ONLY pure PowerShell logging functionality

## Use It Anywhere

### 1. Server Administration
```powershell
Import-Module .\logging.psm1
Initialize-Logging -BaseLogPath "E:\ServerLogs" -JobName "ServerMaint" -ParentScriptName "Maintenance"
Write-AppDeploymentLog "Cleaning up old files" -Level "Information"
```

### 2. DevOps Automation
```powershell
Import-Module .\logging.psm1
Initialize-Logging -BaseLogPath "C:\DevOps\Logs" -JobName "CI-CD" -ParentScriptName "Deploy-Pipeline"
Write-AppDeploymentLog "Starting deployment pipeline" -Level "Information"
```

### 3. Database Management
```powershell
Import-Module .\logging.psm1
Initialize-Logging -BaseLogPath "D:\Database\Logs" -JobName "DBMaint" -ParentScriptName "SQL-Maintenance"
Write-AppDeploymentLog "Beginning database backup" -Level "Information"
```

### 4. Security Auditing
```powershell
Import-Module .\logging.psm1
Initialize-Logging -BaseLogPath "C:\Security\Audit" -JobName "SecAudit" -ParentScriptName "Security-Scan"
Write-AppDeploymentLog "Running security compliance check" -Level "Information"
```

### 5. User Management
```powershell
Import-Module .\logging.psm1
Initialize-Logging -BaseLogPath "C:\IT\UserMgmt\Logs" -JobName "UserMgmt" -ParentScriptName "AD-UserSync"
Write-AppDeploymentLog "Synchronizing Active Directory users" -Level "Information"
```

## Extending for Your Needs

### Create Application-Specific Wrappers
```powershell
# For a backup application
function Write-BackupLog {
    param(
        [string]$Message,
        [string]$Level = 'Information',
        [string]$BackupSet
    )
    $fullMessage = if ($BackupSet) { "[$BackupSet] $Message" } else { $Message }
    Write-AppDeploymentLog -Message $fullMessage -Level $Level
}

# For a monitoring system
function Write-MonitorLog {
    param(
        [string]$Message,
        [string]$Level = 'Information',
        [string]$Component,
        [int]$MetricValue
    )
    $fullMessage = "[$Component] $Message"
    if ($MetricValue) { $fullMessage += " (Value: $MetricValue)" }
    Write-AppDeploymentLog -Message $fullMessage -Level $Level
}
```

### Add Custom Log Destinations
```powershell
# Extend to send to syslog
function Write-SyslogAndFile {
    param($Message, $Level)
    
    # Use the module for file logging
    Write-AppDeploymentLog -Message $Message -Level $Level
    
    # Also send to syslog server
    Send-SyslogMessage -Server "syslog.company.com" -Message $Message -Severity $Level
}

# Extend to write to database
function Write-DatabaseLog {
    param($Message, $Level)
    
    # Use the module for file logging
    Write-AppDeploymentLog -Message $Message -Level $Level
    
    # Also write to SQL
    Invoke-SqlCmd -Query "INSERT INTO Logs (Message, Level, Timestamp) VALUES (@msg, @lvl, @time)" `
                  -Parameters @{msg=$Message; lvl=$Level; time=(Get-Date)}
}
```

## Integration Examples

### PowerShell Modules
```powershell
# In your module's .psm1 file
Import-Module "$PSScriptRoot\Logging\logging.psm1"

function Start-MyModule {
    Initialize-Logging -BaseLogPath "$env:APPDATA\MyModule\Logs" `
                      -JobName "MyModule" `
                      -ParentScriptName $MyInvocation.MyCommand.Module.Name
    
    Write-AppDeploymentLog "Module initialized" -Level "Information"
}
```

### Scheduled Tasks
```powershell
# In your scheduled task script
Import-Module "C:\Scripts\Common\logging.psm1"
Initialize-Logging -BaseLogPath "C:\ScheduledTasks\Logs" `
                  -JobName $env:COMPUTERNAME `
                  -ParentScriptName (Split-Path $PSCommandPath -Leaf)

Write-AppDeploymentLog "Scheduled task started" -Level "Information"
```

### Azure Automation Runbooks
```powershell
# In your runbook
Import-Module .\logging.psm1
Initialize-Logging -BaseLogPath "C:\Temp" `
                  -JobName $env:AUTOMATION_RUNBOOK_NAME `
                  -ParentScriptName "AzureRunbook"

Write-AppDeploymentLog "Runbook execution started" -Level "Information"
```

## Distribution

### As a Git Submodule
```bash
git submodule add https://github.com/yourorg/powershell-logging.git Modules/Logging
```

### As a PowerShell Gallery Module
```powershell
# Publish to PowerShell Gallery
Publish-Module -Path ".\logging" -NuGetApiKey $apiKey

# Install from Gallery
Install-Module -Name UniversalLogging
```

### In Your Module Structure
```
YourProject/
├── Modules/
│   └── Logging/
│       ├── logging.psd1
│       └── logging.psm1
├── Scripts/
│   └── Main.ps1
└── README.md
```

## License

This module is provided as-is and can be freely used, modified, and distributed in any project, commercial or otherwise.