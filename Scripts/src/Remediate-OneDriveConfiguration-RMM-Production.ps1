#Requires -Version 5.1

<#
.SYNOPSIS
    Remediates OneDrive configuration for disk space optimization with Storage Sense
.DESCRIPTION
    Enhanced RMM-compatible remediation script that:
    - Configures OneDrive (Files On-Demand, KFM, etc.)
    - Enables and configures Windows Storage Sense for automatic space management
    - Sets up automatic conversion of unused files to online-only
    - Optionally installs OneDrive if missing (default behavior)
    - Can run in ConfigurationOnly mode to skip installation
.PARAMETER TenantId
    Your organization's Azure AD Tenant ID (optional)
    Example: "336dbee2-bd39-4116-b305-3105539e416f"
    If not provided, script will auto-detect from device configuration
    Auto-detection sources: Azure AD join, OneDrive registry, Group Policy
.PARAMETER ConfigurationOnly
    When specified, skips OneDrive installation and only configures existing OneDrive.
    Use this when OneDrive deployment is handled separately.
.PARAMETER StorageSenseDays
    Number of days before unused files are converted to online-only (default: 30)
.PARAMETER SkipAutoDetection
    Disables auto-detection and requires explicit TenantId parameter
    Use this if you want to ensure a specific tenant ID is used
.NOTES
    Designed to run from SYSTEM context via RMM
    Storage Sense automates Files On-Demand to free disk space
    For production RMM deployment, consider using -ConfigurationOnly
#>

param(
    [Parameter(Mandatory = $false, HelpMessage = "Your Azure AD Tenant ID (e.g., 336dbee2-bd39-4116-b305-3105539e416f)")]
    [ValidatePattern('^$|^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [string]$TenantId = "",
    
    [string]$LogPath = "$env:TEMP\OneDrive-Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log",
    [string]$DetectionResultsPath = "$env:TEMP\OneDrive-Detection-Results.json",
    [int]$StorageSenseDays = 30,  # Days before converting files to online-only
    [switch]$EnableDebug = $false,  # Enable console output for testing
    [switch]$ConfigurationOnly = $false,  # Skip OneDrive installation, only configure existing
    [switch]$SkipAutoDetection = $false  # Skip auto-detection and require explicit TenantId
)

# Initialize
$VerbosePreference = 'SilentlyContinue'
$script:exitCode = 0
$script:remediationSuccess = $true
$script:supportsDownloadsKFM = $false
$script:DisableFileLogging = $false  # Initialize to allow file logging

#region Logging Module Configuration
# FOR PRODUCTION RMM DEPLOYMENT:
# 1. Comment out or remove the Import-Module section below (lines marked with #REMOVE-FOR-RMM)
# 2. Insert the entire contents of logging.psm1 into the #region Embedded Logging Module below
# 3. Keep the Initialize-Logging and logging setup code

#REMOVE-FOR-RMM# Import logging module - use local copy only
#REMOVE-FOR-RMM $LoggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
#REMOVE-FOR-RMM $script:LoggingEnabled = $false
#REMOVE-FOR-RMM $script:LoggingMode = if ($EnableDebug) { 'EnableDebug' } else { 'SilentMode' }
#REMOVE-FOR-RMM 
#REMOVE-FOR-RMM if (Test-Path $LoggingModulePath) {
#REMOVE-FOR-RMM     try {
#REMOVE-FOR-RMM         if ($EnableDebug) {
#REMOVE-FOR-RMM             Write-Host "[DEBUG] Found logging module at: $LoggingModulePath" -ForegroundColor Cyan
#REMOVE-FOR-RMM         }
#REMOVE-FOR-RMM         
#REMOVE-FOR-RMM         Import-Module $LoggingModulePath -Force -WarningAction SilentlyContinue
#REMOVE-FOR-RMM         $script:LoggingEnabled = $true

#region Embedded Logging Module
# PASTE THE ENTIRE CONTENTS OF logging.psm1 HERE FOR RMM DEPLOYMENT
# START PASTE

<#
.SYNOPSIS
    Universal PowerShell Logging Module - Generic, Reusable, and Extensible
    
.DESCRIPTION
    A fully generic and reusable logging module that can be used in ANY PowerShell project.
    This module is completely independent and has no hardcoded dependencies on specific
    applications. It provides comprehensive logging capabilities with automatic line number
    detection, call stack analysis, and support for wrapper functions.
    
    KEY FEATURES:
    - 100% Generic - No application-specific code
    - Fully Reusable - Use in any PowerShell project
    - Highly Extensible - Easy to build custom logging functions on top
    - Zero Dependencies - Works with PowerShell 5.1+ only
    - Configurable - All paths and names are customizable
    
.NOTES
    Version:        3.0.0
    Author:         System Administrator
    Creation Date:  2024-01-01
    Last Modified:  2025-08-02
    License:        MIT (Free to use, modify, and distribute)
    
.FUNCTIONALITY
    - Universal logging for any PowerShell application
    - Console and file logging with multiple severity levels
    - Automatic line number detection from call stack
    - Support for wrapper functions (e.g., Write-DetectionLog)
    - CSV logging for structured data analysis
    - Configurable log paths and rotation
    - Silent, standard, and debug logging modes
    - No hardcoded paths or application-specific logic
    
.EXAMPLE
    # Example 1: Use in a backup script
    Import-Module .\logging.psm1
    Initialize-Logging -BaseLogPath "D:\BackupLogs" -JobName "DailyBackup" -ParentScriptName "Backup-Database"
    Write-AppDeploymentLog -Message "Backup started" -Level "INFO"
    
.EXAMPLE
    # Example 2: Use in an installation script
    Import-Module .\logging.psm1
    Initialize-Logging -BaseLogPath "$env:TEMP\Install" -JobName "AppInstaller" -ParentScriptName "Install-Software"
    Write-AppDeploymentLog -Message "Installation beginning" -Level "INFO"
    
.EXAMPLE
    # Example 3: Use in a monitoring tool with network logging
    Import-Module .\logging.psm1
    Initialize-Logging -BaseLogPath "C:\Monitoring\Logs" -JobName "ServerMonitor" -ParentScriptName "Monitor-Services" -NetworkLogPath "\\CentralServer\Logs"
    Write-AppDeploymentLog -Message "Monitoring check started" -Level "INFO"
    
.EXAMPLE
    # Example 4: Extend with custom wrapper
    function Write-MyAppLog {
        param([string]$Message, [string]$Level = 'Information')
        Write-AppDeploymentLog -Message $Message -Level $Level
    }
    Write-MyAppLog "This will show the correct line number!"
    
.LINK
    https://github.com/YourOrg/PowerShell-Logging
    
.COMPONENT
    Universal Logging
    
.ROLE
    Infrastructure / DevOps / Automation
#>

#Requires -Version 5.1

#region Module Metadata
$script:ModuleVersion = '2.0.0'
$script:ModuleDescription = 'Universal PowerShell Logging Module with Line Number Support'
#endregion

#region Logging Configuration

# Global configuration variables for the logging module
$script:LogConfig = @{
    BaseLogPath = "$env:ProgramData\UniversalLogs"  # Generic default path
    JobName = "DefaultJob"
    ParentScriptName = "DefaultScript"
    CustomLogPath = $null
    Initialized = $false
    NetworkLogPath = $null  # Optional network path for centralized logging
}

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging module with custom configuration
    
    .DESCRIPTION
        Sets up the logging module for a specific application/script with custom paths and names.
        This allows the logging module to be used universally across different projects.
    
    .PARAMETER BaseLogPath
        The base path where logs should be stored (e.g., "C:\ProgramData\YourApp\Logs")
    
    .PARAMETER JobName
        The name of the job/application for log categorization
    
    .PARAMETER ParentScriptName
        The name of the parent script for log file naming
    
    .PARAMETER CustomLogPath
        Optional: Full custom log file path (overrides automatic path generation)
    
    .EXAMPLE
        Initialize-Logging -BaseLogPath "C:\ProgramData\MyApp\Logs" -JobName "DataProcessing" -ParentScriptName "Process-CustomerData"
    
    .EXAMPLE
        # With network logging
        Initialize-Logging -BaseLogPath "C:\Logs\Local" -JobName "Backup" -ParentScriptName "Backup-Database" -NetworkLogPath "\\FileServer\CentralLogs"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseLogPath,
        
        [Parameter(Mandatory = $true)]
        [string]$JobName,
        
        [Parameter(Mandatory = $true)]
        [string]$ParentScriptName,
        
        [Parameter(Mandatory = $false)]
        [string]$CustomLogPath = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$NetworkLogPath = $null
    )
    
    # Update configuration
    $script:LogConfig.BaseLogPath = $BaseLogPath
    $script:LogConfig.JobName = $JobName
    $script:LogConfig.ParentScriptName = $ParentScriptName
    $script:LogConfig.CustomLogPath = $CustomLogPath
    $script:LogConfig.NetworkLogPath = $NetworkLogPath
    $script:LogConfig.Initialized = $true
    
    # Set global variables for backward compatibility
    $global:JobName = $JobName
    $global:ParentScriptName = $ParentScriptName
    
    # Create base directory if it doesn't exist
    if (-not (Test-Path -Path $BaseLogPath)) {
        New-Item -ItemType Directory -Path $BaseLogPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Set up session variables to ensure single log file per execution
    $userContext = Get-CurrentUser
    $callingScript = Get-CallingScriptName
    $dateFolder = Get-Date -Format "yyyy-MM-dd"
    $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
    
    # Build log directory path
    $script:SessionFullLogDirectory = Join-Path -Path $BaseLogPath -ChildPath $dateFolder
    $script:SessionFullLogDirectory = Join-Path -Path $script:SessionFullLogDirectory -ChildPath $ParentScriptName
    
    # Build log file path
    $logFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$ParentScriptName-activity-$timestamp.log"
    $script:SessionLogFilePath = Join-Path -Path $script:SessionFullLogDirectory -ChildPath $logFileName
    
    # Also set CSV paths
    $script:SessionFullCSVDirectory = Join-Path -Path $BaseLogPath -ChildPath "CSV\$dateFolder\$ParentScriptName"
    $csvFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$ParentScriptName-activity-$timestamp.csv"
    $script:SessionCSVFilePath = Join-Path -Path $script:SessionFullCSVDirectory -ChildPath $csvFileName
    
    # Set other session variables
    $script:SessionUserContext = $userContext
    $script:SessionCallingScript = $callingScript
    $script:SessionParentScript = $ParentScriptName
    
    Write-Verbose "Logging initialized with BaseLogPath: $BaseLogPath, JobName: $JobName, ParentScriptName: $ParentScriptName"
    Write-Verbose "Log file will be: $($script:SessionLogFilePath)"
    
    # Log the execution policy and PowerShell version
    $executionPolicy = Get-ExecutionPolicy
    $psVersion = $PSVersionTable.PSVersion.ToString()
    $edition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { "Desktop" }
    
    if ($script:LogConfig.Initialized) {
        # Create simple log entries for environment info
        $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Ensure directory exists
        if (-not (Test-Path -Path $script:SessionFullLogDirectory)) {
            New-Item -ItemType Directory -Path $script:SessionFullLogDirectory -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Write environment info to log file
        $envMessages = @(
            "[$timeStamp] [Information] [Initialize-Logging:0] - Execution Policy: $executionPolicy"
            "[$timeStamp] [Information] [Initialize-Logging:0] - PowerShell Version: $psVersion ($edition)"
            "[$timeStamp] [Information] [Initialize-Logging:0] - PowerShell Host: $($Host.Name)"
        )
        
        foreach ($message in $envMessages) {
            Add-Content -Path $script:SessionLogFilePath -Value $message -ErrorAction SilentlyContinue
        }
    }
}

#endregion Logging Configuration

#region Logging Function


function Write-AppDeploymentLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter()]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG', 'SUCCESS')]
        [string]$Level = 'INFO',
        [Parameter()]
        [ValidateSet('EnableDebug', 'SilentMode', 'Off')]
        [string]$Mode = 'Off'
    )

    # Determine logging mode - check EnableDebug first, then parameter, then default to Off
    $loggingMode = if ($global:EnableDebug) { 
        'EnableDebug' 
    } elseif ($Mode -ne 'Off') { 
        $Mode 
    } else { 
        'Off' 
    }

    # Exit early if logging is completely disabled
    if ($loggingMode -eq 'Off') {
        return
    }

    # Enhanced caller information using improved logic from Write-EnhancedLog
    $callStack = Get-PSCallStack
    
    # Look for the actual calling function, skipping wrapper functions
    $callerFunction = '<Unknown>'
    $callerIndex = 1
    $lineNumber = 0
    $actualCaller = $null
    
    # Skip known wrapper functions to find the real caller
    # Stack[0] = Write-AppDeploymentLog (this function)
    # Stack[1] = Write-DetectionLog/Write-RemediationLog (wrapper) OR direct caller
    # Stack[2] = Actual caller if wrapper exists
    
    $throughWrapper = $false
    $wrapperFunction = ''
    
    # Check if we're being called through a wrapper
    if ($callStack.Count -ge 2 -and $callStack[1].Command -match '^(Write-DetectionLog|Write-RemediationLog)$') {
        $throughWrapper = $true
        $wrapperFunction = $callStack[1].Command
    }
    
    if ($throughWrapper -and $callStack.Count -ge 3) {
        # We're called through a wrapper, get the actual caller
        $actualCaller = $callStack[2]
        $lineNumber = $actualCaller.ScriptLineNumber
        
        if ($actualCaller.Command -like "*.ps1") {
            # Called from main script
            $callerFunction = $wrapperFunction
        } else {
            # Called from a function
            $callerFunction = $actualCaller.Command
        }
    } else {
        # Direct call, no wrapper
        if ($callStack.Count -ge 2) {
            $actualCaller = $callStack[1]
            $lineNumber = $actualCaller.ScriptLineNumber
            
            if ($actualCaller.Command -like "*.ps1") {
                $callerFunction = 'MainScript'
            } else {
                $callerFunction = $actualCaller.Command
            }
        }
    }
    
    if ($callerIndex -ge $callStack.Count) {
        # Fallback to original logic
        if ($callStack.Count -ge 2) {
            $caller = $callStack[1]
            if ($caller.Command -and $caller.Command -notlike "*.ps1") {
                $callerFunction = $caller.Command
            } else {
                $callerFunction = 'MainScript'
            }
            # Also capture line number in fallback case
            $lineNumber = $caller.ScriptLineNumber
            $actualCaller = $caller
        }
    }
    
    # Get parent script name
    $parentScriptName = try {
        Get-ParentScriptName
    } catch {
        "UnknownScript"
    }
    
    # Line number was already captured when we found the actual caller
    # Get script file name from the actual caller we found
    $scriptFileName = if ($actualCaller -and $actualCaller.ScriptName) { 
        Split-Path -Leaf $actualCaller.ScriptName 
    } else { 
        $parentScriptName 
    }
    

    # Create enhanced caller information combining both approaches
    $enhancedCallerInfo = "[$parentScriptName.$callerFunction]"
    $detailedCallerInfo = "[$scriptFileName`:$lineNumber $callerFunction]"

    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Include line number in file log message
    $fileLogMessage = "[$timeStamp] [$Level] [$parentScriptName.$callerFunction`:$lineNumber] - $Message"
    # Build console message with line number if available
    if ($lineNumber -and $lineNumber -ne 0) {
        $consoleLogMessage = "[$Level] [$parentScriptName.$callerFunction`:$lineNumber] - $Message"
    } else {
        $consoleLogMessage = "[$Level] [$parentScriptName.$callerFunction] - $Message"
        # ALWAYS show debug info when line number is missing and we're in debug mode
        if ($loggingMode -eq 'EnableDebug') {
            Write-Host "[LOGGING DEBUG] Missing line number! LineNumber='$lineNumber' CallerFunction='$callerFunction' ThroughWrapper=$throughWrapper" -ForegroundColor Magenta
            Write-Host "[LOGGING DEBUG] Call stack analysis:" -ForegroundColor Magenta
            for ($i = 0; $i -lt [Math]::Min($callStack.Count, 5); $i++) {
                Write-Host "[LOGGING DEBUG]   Stack[$i]: Command='$($callStack[$i].Command)' Line=$($callStack[$i].ScriptLineNumber) ScriptName='$(if($callStack[$i].ScriptName){Split-Path -Leaf $callStack[$i].ScriptName}else{'null'})'" -ForegroundColor Magenta
            }
            Write-Host "[LOGGING DEBUG] ActualCaller: $($actualCaller.Command) at line $($actualCaller.ScriptLineNumber)" -ForegroundColor Magenta
        }
    }
    

    #region Local File Logging
    # Skip all file logging if DisableFileLogging is set
    if ($script:DisableFileLogging) {
        return
    }
    
    # Use session-based paths if available, otherwise fall back to per-call generation
    if ($script:SessionLogFilePath -and $script:SessionFullLogDirectory) {
        $logFilePath = $script:SessionLogFilePath
        $logDirectory = $script:SessionFullLogDirectory
    } else {
        # Fallback to old method if session variables aren't set
        $userContext = Get-CurrentUser
        $callingScript = Get-CallingScriptName
        $parentScriptName = Get-ParentScriptName
        $dateFolder = Get-Date -Format "yyyy-MM-dd"
        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        
        # Use configured base path or fall back to default
        $logDirectory = if ($script:LogConfig.Initialized) {
            $script:LogConfig.BaseLogPath
        } elseif ($global:CustomLogBase) { 
            $global:CustomLogBase 
        } else { 
            "$env:ProgramData\UniversalLogs" 
        }
        $fullLogDirectory = Join-Path -Path $logDirectory -ChildPath $dateFolder
        $fullLogDirectory = Join-Path -Path $fullLogDirectory -ChildPath $parentScriptName
        $logFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-activity-$timestamp.log"
        $logFilePath = Join-Path -Path $fullLogDirectory -ChildPath $logFileName
        $logDirectory = $fullLogDirectory
    }
    
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    if (Test-Path -Path $logDirectory) {
        Add-Content -Path $logFilePath -Value $fileLogMessage -ErrorAction SilentlyContinue
        
        # Log rotation for local files (keep max 7 files)
        try {
            $parentScriptForFilter = if ($script:SessionParentScript) { $script:SessionParentScript } else { "Discovery" }
            $logFiles = Get-ChildItem -Path $logDirectory -Filter "*-*-*-*-$parentScriptForFilter-activity*.log" | Sort-Object LastWriteTime -Descending
            if ($logFiles.Count -gt 7) {
                $filesToRemove = $logFiles | Select-Object -Skip 7
                foreach ($file in $filesToRemove) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            # Silent error handling for log rotation
        }
    }
    #endregion Local File Logging

    #region Network Share CSV Logging
    # Network logging: Only save CSV format logs under a parent job folder for better organization
    try {
        $hostname = $env:COMPUTERNAME
        $jobName = $script:LogConfig.JobName  # Use configured job name
        # Only try network logging if NetworkLogPath is configured
        if ($script:LogConfig.NetworkLogPath) {
            $networkBasePath = Join-Path $script:LogConfig.NetworkLogPath "$jobName\$hostname"
            
            # Test network connectivity first
            $networkAvailable = Test-Path $script:LogConfig.NetworkLogPath -ErrorAction SilentlyContinue
        } else {
            $networkAvailable = $false
        }
        
        if ($networkAvailable) {
            # Use session-based paths if available
            if ($script:SessionDateFolder -and $script:SessionParentScript -and $script:SessionCSVFileName) {
                $fullNetworkCSVPath = Join-Path -Path $networkBasePath -ChildPath $script:SessionDateFolder
                $fullNetworkCSVPath = Join-Path -Path $fullNetworkCSVPath -ChildPath $script:SessionParentScript
                $networkCSVFile = Join-Path -Path $fullNetworkCSVPath -ChildPath $script:SessionCSVFileName
            } else {
                # Fallback method
                $dateFolder = Get-Date -Format "yyyy-MM-dd"
                $parentScriptName = Get-ParentScriptName
                $userContext = Get-CurrentUser
                $callingScript = Get-CallingScriptName
                $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
                
                $fullNetworkCSVPath = Join-Path -Path $networkBasePath -ChildPath $dateFolder
                $fullNetworkCSVPath = Join-Path -Path $fullNetworkCSVPath -ChildPath $parentScriptName
                $networkCSVFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-activity-$timestamp.csv"
                $networkCSVFile = Join-Path -Path $fullNetworkCSVPath -ChildPath $networkCSVFileName
            }
            
            if (-not (Test-Path -Path $fullNetworkCSVPath)) {
                New-Item -ItemType Directory -Path $fullNetworkCSVPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            if (Test-Path -Path $fullNetworkCSVPath) {
                # Create CSV entry for network logging
                $userContext = if ($script:SessionUserContext) { $script:SessionUserContext } else { Get-CurrentUser }
                $callingScript = if ($script:SessionCallingScript) { $script:SessionCallingScript } else { Get-CallingScriptName }
                $parentScriptName = if ($script:SessionParentScript) { $script:SessionParentScript } else { Get-ParentScriptName }
                
                # Get caller information
                $callStack = Get-PSCallStack
                $callerFunction = '<Unknown>'
                if ($callStack.Count -ge 2) {
                    $caller = $callStack[1]
                    if ($caller.Command -and $caller.Command -notlike "*.ps1") {
                        $callerFunction = $caller.Command
                    } else {
                        $callerFunction = 'MainScript'
                    }
                }
                
                $lineNumber = if ($callStack.Count -ge 2) { $callStack[1].ScriptLineNumber } else { 0 }
                $scriptFileName = if ($callStack.Count -ge 2 -and $callStack[1].ScriptName) { 
                    Split-Path -Leaf $callStack[1].ScriptName 
                } else { 
                    $parentScriptName 
                }
                
                $enhancedCallerInfo = "[$parentScriptName.$callerFunction]"
                
                $networkCSVEntry = [PSCustomObject]@{
                    Timestamp       = $timeStamp
                    Level           = $Level
                    ParentScript    = $parentScriptName
                    CallingScript   = $callingScript
                    ScriptName      = $scriptFileName
                    FunctionName    = $callerFunction
                    LineNumber      = $lineNumber
                    Message         = $Message
                    Hostname        = $env:COMPUTERNAME
                    UserType        = $userContext.UserType
                    UserName        = $userContext.UserName
                    FullUserContext = $userContext.FullUserContext
                    CallerInfo      = $enhancedCallerInfo
                    JobName         = $jobName
                    LogType         = "NetworkCSV"
                }
                
                # Check if network CSV exists, if not create with headers
                if (-not (Test-Path -Path $networkCSVFile)) {
                    $networkCSVEntry | Export-Csv -Path $networkCSVFile -NoTypeInformation -ErrorAction SilentlyContinue
                } else {
                    $networkCSVEntry | Export-Csv -Path $networkCSVFile -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
                
                # Network CSV log rotation (keep max 5 files per machine per script)
                try {
                    $parentScriptForFilter = if ($script:SessionParentScript) { $script:SessionParentScript } else { "Discovery" }
                    $networkCSVFiles = Get-ChildItem -Path $fullNetworkCSVPath -Filter "*-*-*-*-$parentScriptForFilter-activity*.csv" | Sort-Object LastWriteTime -Descending
                    if ($networkCSVFiles.Count -gt 5) {
                        $filesToRemove = $networkCSVFiles | Select-Object -Skip 5
                        foreach ($file in $filesToRemove) {
                            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                catch {
                    # Silent error handling for network CSV log rotation
                }
            }
        }
    }
    catch {
        # Silent error handling for network CSV logging - don't interfere with main script
    }
    #endregion Network Share CSV Logging

    #region CSV Logging
    try {
        # Use session-based paths if available
        if ($script:SessionCSVFilePath -and $script:SessionFullCSVDirectory) {
            $csvLogPath = $script:SessionCSVFilePath
            $csvDirectory = $script:SessionFullCSVDirectory
        } else {
            # Fallback method
            $userContext = Get-CurrentUser
            $callingScript = Get-CallingScriptName
            $parentScriptName = Get-ParentScriptName
            $dateFolder = Get-Date -Format "yyyy-MM-dd"
            $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
            
            $csvLogDirectory = Join-Path $script:LogConfig.BaseLogPath "CSV"
            $fullCSVDirectory = Join-Path -Path $csvLogDirectory -ChildPath $dateFolder
            $fullCSVDirectory = Join-Path -Path $fullCSVDirectory -ChildPath $parentScriptName
            $csvFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-activity-$timestamp.csv"
            $csvLogPath = Join-Path -Path $fullCSVDirectory -ChildPath $csvFileName
            $csvDirectory = $fullCSVDirectory
        }
        
        if (-not (Test-Path -Path $csvDirectory)) {
            New-Item -ItemType Directory -Path $csvDirectory -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Use session context if available, otherwise get fresh context
        $userContext = if ($script:SessionUserContext) { $script:SessionUserContext } else { Get-CurrentUser }
        $callingScript = if ($script:SessionCallingScript) { $script:SessionCallingScript } else { Get-CallingScriptName }
        $parentScriptName = if ($script:SessionParentScript) { $script:SessionParentScript } else { Get-ParentScriptName }
        
        $csvEntry = [PSCustomObject]@{
            Timestamp       = $timeStamp
            Level           = $Level
            ParentScript    = $parentScriptName
            CallingScript   = $callingScript
            ScriptName      = $scriptFileName
            FunctionName    = $callerFunction
            LineNumber      = $lineNumber
            Message         = $Message
            Hostname        = $env:COMPUTERNAME
            UserType        = $userContext.UserType
            UserName        = $userContext.UserName
            FullUserContext = $userContext.FullUserContext
            CallerInfo      = $enhancedCallerInfo
        }
        
        # Check if CSV exists, if not create with headers
        if (-not (Test-Path -Path $csvLogPath)) {
            $csvEntry | Export-Csv -Path $csvLogPath -NoTypeInformation -ErrorAction SilentlyContinue
        } else {
            $csvEntry | Export-Csv -Path $csvLogPath -NoTypeInformation -Append -ErrorAction SilentlyContinue
        }
        
        # CSV log rotation
        try {
            $parentScriptForFilter = if ($script:SessionParentScript) { $script:SessionParentScript } else { "Discovery" }
            $csvFiles = Get-ChildItem -Path $csvDirectory -Filter "*-*-*-*-$parentScriptForFilter-activity*.csv" | Sort-Object LastWriteTime -Descending
            if ($csvFiles.Count -gt 7) {
                $filesToRemove = $csvFiles | Select-Object -Skip 7
                foreach ($file in $filesToRemove) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            # Silent error handling for CSV log rotation
        }
    }
    catch {
        # Silent error handling for CSV logging
    }
    #endregion CSV Logging

    #region Console Output (only in EnableDebug mode)
    if ($loggingMode -eq 'EnableDebug') {
        
        switch ($Level.ToUpper()) {
            'ERROR' { Write-Host $consoleLogMessage -ForegroundColor Red }
            'WARNING' { Write-Host $consoleLogMessage -ForegroundColor Yellow }
            'INFO' { Write-Host $consoleLogMessage -ForegroundColor White }
            'DEBUG' { Write-Host $consoleLogMessage -ForegroundColor Gray }
            'SUCCESS' { Write-Host $consoleLogMessage -ForegroundColor Green }
        }
    }
    #endregion Console Output
}

function Write-EnhancedLog {
    [CmdletBinding()]
    param (
        [string]$Message,
        [string]$Level = 'INFO',
        [string]$LoggingMode = 'SilentMode'
    )

    # Get the PowerShell call stack to determine the actual calling function
    $callStack = Get-PSCallStack
    $callerFunction = if ($callStack.Count -ge 2) { $callStack[1].Command } else { '<Unknown>' }

    # Get the parent script name
    $parentScriptName = Get-ParentScriptName

    # Map enhanced log levels to standard log levels
    $mappedLevel = switch ($Level.ToUpper()) {
        'CRITICAL' { 'ERROR' }
        'ERROR'    { 'ERROR' }
        'WARNING'  { 'WARNING' }
        'INFO'     { 'INFO' }
        'INFORMATION' { 'INFO' }  # Support old verbose name
        'DEBUG'    { 'DEBUG' }
        'NOTICE'   { 'INFO' }
        'IMPORTANT' { 'INFO' }
        'OUTPUT'   { 'INFO' }
        'SIGNIFICANT' { 'INFO' }
        'VERBOSE'  { 'DEBUG' }
        'SUCCESS'  { 'SUCCESS' }
        'VERYVERBOSE' { 'DEBUG' }
        'SOMEWHATVERBOSE' { 'DEBUG' }
        'SYSTEM'   { 'INFO' }
        'INTERNALCOMMENT' { 'DEBUG' }
        default    { 'INFO' }
    }

    # Format message with caller information
    $formattedMessage = "[$parentScriptName.$callerFunction] $Message"

    # Use the existing Write-AppDeploymentLog function
    Write-AppDeploymentLog -Message $formattedMessage -Level $mappedLevel -Mode $LoggingMode
}

#region Helper Functions


#region Error Handling
function Handle-Error {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$CustomMessage = "",
        [string]$LoggingMode = "SilentMode"
    )

    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $fullErrorDetails = Get-Error -InputObject $ErrorRecord | Out-String
        } else {
            $fullErrorDetails = $ErrorRecord.Exception | Format-List * -Force | Out-String
        }

        $errorMessage = if ($CustomMessage) {
            "$CustomMessage - Exception: $($ErrorRecord.Exception.Message)"
        } else {
            "Exception Message: $($ErrorRecord.Exception.Message)"
        }

        Write-AppDeploymentLog -Message $errorMessage -Level Error -Mode $LoggingMode
        Write-AppDeploymentLog -Message "Full Exception Details: $fullErrorDetails" -Level Debug -Mode $LoggingMode
        Write-AppDeploymentLog -Message "Script Line Number: $($ErrorRecord.InvocationInfo.ScriptLineNumber)" -Level Debug -Mode $LoggingMode
        Write-AppDeploymentLog -Message "Position Message: $($ErrorRecord.InvocationInfo.PositionMessage)" -Level Debug -Mode $LoggingMode
    } 
    catch {
        # Fallback error handling in case of an unexpected error in the try block
        Write-AppDeploymentLog -Message "An error occurred while handling another error. Original Exception: $($ErrorRecord.Exception.Message)" -Level Error -Mode $LoggingMode
        Write-AppDeploymentLog -Message "Handler Exception: $($_.Exception.Message)" -Level Error -Mode $LoggingMode
    }
}
#endregion Error Handling

function Get-ParentScriptName {
    [CmdletBinding()]
    param ()

    # Return configured parent script name if available
    if ($script:LogConfig.Initialized -and $script:LogConfig.ParentScriptName) {
        return $script:LogConfig.ParentScriptName
    }

    try {
        # Get the current call stack
        $callStack = Get-PSCallStack

        # If there is a call stack, return the top-most script name
        if ($callStack.Count -gt 0) {
            foreach ($frame in $callStack) {
                if ($frame.ScriptName) {
                    $parentScriptName = $frame.ScriptName
                    # Write-EnhancedLog -Message "Found script in call stack: $parentScriptName" -Level "INFO"
                }
            }

            if (-not [string]::IsNullOrEmpty($parentScriptName)) {
                $parentScriptName = [System.IO.Path]::GetFileNameWithoutExtension($parentScriptName)
                return $parentScriptName
            }
        }

        # If no script name was found, return 'UnknownScript'
        Write-EnhancedLog -Message "No script name found in the call stack." -Level "WARNING"
        return "UnknownScript"
    }
    catch {
        Write-EnhancedLog -Message "An error occurred while retrieving the parent script name: $_" -Level "ERROR"
        return "UnknownScript"
    }
}

function Get-CurrentUser {
    [CmdletBinding()]
    param()
    
    try {
        # Get the current user context
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $computerName = $env:COMPUTERNAME
        
        # Check if running as SYSTEM
        if ($currentUser -like "*SYSTEM*" -or $currentUser -eq "NT AUTHORITY\SYSTEM") {
            return @{
                UserType = "SYSTEM"
                UserName = "LocalSystem"
                ComputerName = $computerName
                FullUserContext = "SYSTEM-LocalSystem"
            }
        }
        
        # Extract domain and username
        if ($currentUser.Contains('\')) {
            $domain = $currentUser.Split('\')[0]
            $userName = $currentUser.Split('\')[1]
        } else {
            $domain = $env:USERDOMAIN
            $userName = $currentUser
        }
        
        # Determine user type based on group membership
        $userType = "User"
        try {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            if ($isAdmin) {
                $userType = "Admin"
            }
        }
        catch {
            # If we can't determine admin status, default to User
            $userType = "User"
        }
        
        # Sanitize names for file naming (remove invalid characters)
        $userName = $userName -replace '[<>:"/\\|?*]', '_'
        $userType = $userType -replace '[<>:"/\\|?*]', '_'
        
        return @{
            UserType = $userType
            UserName = $userName
            ComputerName = $computerName
            FullUserContext = "$userType-$userName"
        }
    }
    catch {
        Write-AppDeploymentLog -Message "Failed to get current user context: $($_.Exception.Message)" -Level Error -Mode SilentMode
        return @{
            UserType = "Unknown"
            UserName = "UnknownUser"
            ComputerName = $env:COMPUTERNAME
            FullUserContext = "Unknown-UnknownUser"
        }
    }
}

function Get-CallingScriptName {
    [CmdletBinding()]
    param()
    
    try {
        # Get the call stack
        $callStack = Get-PSCallStack
        
        # Look for the actual calling script (not this script or logging functions)
        $callingScript = "UnknownCaller"
        
        # Skip internal logging functions and Discovery script itself
        $skipFunctions = @('Write-AppDeploymentLog', 'Write-EnhancedLog', 'Handle-Error', 'Get-CallingScriptName', 'Get-CurrentUser')
        $skipScripts = @('Discovery', 'Discovery.ps1')
        
        # Start from index 1 to skip the current function
        for ($i = 1; $i -lt $callStack.Count; $i++) {
            $frame = $callStack[$i]
            
            # Check if this frame should be skipped
            $shouldSkip = $false
            
            # Skip if it's one of our internal functions
            if ($frame.Command -and $frame.Command -in $skipFunctions) {
                $shouldSkip = $true
            }
            
            # Skip if it's the Discovery script itself
            if ($frame.ScriptName) {
                $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($frame.ScriptName)
                if ($scriptName -in $skipScripts) {
                    $shouldSkip = $true
                }
            }
            
            # If we shouldn't skip this frame, use it
            if (-not $shouldSkip) {
                if ($frame.ScriptName) {
                    $callingScript = [System.IO.Path]::GetFileNameWithoutExtension($frame.ScriptName)
                    break
                }
                elseif ($frame.Command -and $frame.Command -ne "<ScriptBlock>") {
                    $callingScript = $frame.Command
                    break
                }
            }
        }
        
        # If we still haven't found a caller, determine the execution context
        if ($callingScript -eq "UnknownCaller") {
            # Check execution context
            if ($callStack.Count -le 3) {
                # Very short call stack suggests direct execution
                $callingScript = "DirectExecution"
            }
            elseif ($MyInvocation.InvocationName -and $MyInvocation.InvocationName -ne "Get-CallingScriptName") {
                # Use the invocation name if available
                $callingScript = $MyInvocation.InvocationName
            }
            elseif ($PSCommandPath) {
                # Check if we have a command path (script execution)
                $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
                if ($scriptName -and $scriptName -notin $skipScripts) {
                    $callingScript = $scriptName
                } else {
                    $callingScript = "PowerShellExecution"
                }
            }
            else {
                # Check the host name to determine execution context
                $hostName = $Host.Name
                switch ($hostName) {
                    "ConsoleHost" { $callingScript = "PowerShellConsole" }
                    "Windows PowerShell ISE Host" { $callingScript = "PowerShell_ISE" }
                    "ServerRemoteHost" { $callingScript = "RemoteExecution" }
                    "Visual Studio Code Host" { $callingScript = "VSCode" }
                    default { $callingScript = "PowerShellHost-$hostName" }
                }
            }
        }
        
        return $callingScript
    }
    catch {
        # In case of any error, provide a meaningful fallback
        try {
            $hostName = $Host.Name
            return "ErrorFallback-$hostName"
        }
        catch {
            return "ErrorFallback-Unknown"
        }
    }
}


#region Transcript Management Functions
function Start-UniversalTranscript {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = $script:LogConfig.BaseLogPath,
        [string]$LoggingMode = "SilentMode"
    )
    
    try {
        # Check if file logging is disabled
        if ($script:DisableFileLogging) {
            Write-AppDeploymentLog -Message "Transcript not started - file logging is disabled" -Level Debug -Mode $LoggingMode
            return $null
        }
        
        # Get current user context and calling script
        $userContext = Get-CurrentUser
        $callingScript = Get-CallingScriptName
        $parentScriptName = Get-ParentScriptName
        $dateFolder = Get-Date -Format "yyyy-MM-dd"
        
        # Create directory structure: Logs/Transcript/{Date}/{ParentScript}
        $transcriptDirectory = Join-Path -Path $LogDirectory -ChildPath "Transcript"
        $fullTranscriptDirectory = Join-Path -Path $transcriptDirectory -ChildPath $dateFolder
        $fullTranscriptDirectory = Join-Path -Path $fullTranscriptDirectory -ChildPath $parentScriptName
        
        if (-not (Test-Path -Path $fullTranscriptDirectory)) {
            New-Item -ItemType Directory -Path $fullTranscriptDirectory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        $transcriptFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-transcript-$timestamp.log"
        $transcriptPath = Join-Path -Path $fullTranscriptDirectory -ChildPath $transcriptFileName
        
        # Start transcript with error handling and suppress all console output
        try {
            Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Null
            Write-AppDeploymentLog -Message "Transcript started successfully at: $transcriptPath" -Level Information -Mode $LoggingMode
        }
        catch {
            Handle-Error -ErrorRecord $_ -CustomMessage "Failed to start transcript at $transcriptPath" -LoggingMode $LoggingMode
            return $null
        }
        
        # Transcript rotation
        try {
            $transcriptFiles = Get-ChildItem -Path $fullTranscriptDirectory -Filter "*-*-*-*-$parentScriptName-transcript*.log" | Sort-Object LastWriteTime -Descending
            if ($transcriptFiles.Count -gt 7) {
                $filesToRemove = $transcriptFiles | Select-Object -Skip 7
                foreach ($file in $filesToRemove) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-AppDeploymentLog -Message "Removed old transcript file: $($file.FullName)" -Level Debug -Mode $LoggingMode
                }
            }
        }
        catch {
            Handle-Error -ErrorRecord $_ -CustomMessage "Error during transcript file rotation" -LoggingMode $LoggingMode
        }
        
        return $transcriptPath
    }
    catch {
        Handle-Error -ErrorRecord $_ -CustomMessage "Error in Start-UniversalTranscript function" -LoggingMode $LoggingMode
        return $null
    }
}

function Stop-UniversalTranscript {
    [CmdletBinding()]
    param(
        [string]$LoggingMode = "SilentMode"
    )
    
    try {
        # Check if file logging is disabled
        if ($script:DisableFileLogging) {
            Write-AppDeploymentLog -Message "Transcript not stopped - file logging is disabled" -Level Debug -Mode $LoggingMode
            return $false
        }
        
        # Check if transcript is running before attempting to stop
        $transcriptRunning = $false
        try {
            # Try to stop transcript and suppress all console output
            Stop-Transcript -ErrorAction Stop | Out-Null
            $transcriptRunning = $true
            Write-AppDeploymentLog -Message "Transcript stopped successfully." -Level Information -Mode $LoggingMode
        }
        catch [System.InvalidOperationException] {
            # This is expected if no transcript is running
            Write-AppDeploymentLog -Message "No active transcript to stop." -Level Debug -Mode $LoggingMode
        }
        catch {
            # Other transcript-related errors
            Handle-Error -ErrorRecord $_ -CustomMessage "Error stopping transcript" -LoggingMode $LoggingMode
        }
        
        return $transcriptRunning
    }
    catch {
        Handle-Error -ErrorRecord $_ -CustomMessage "Error in Stop-UniversalTranscript function" -LoggingMode $LoggingMode
        return $false
    }
}

function Get-TranscriptFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TranscriptsPath,
        [Parameter(Mandatory = $true)]
        [string]$JobName,
        [Parameter(Mandatory = $true)]
        [string]$parentScriptName
    )
    
    try {
        # Get current user context and calling script
        $userContext = Get-CurrentUser
        $callingScript = Get-CallingScriptName
        
        # Generate date folder (YYYY-MM-DD format)
        $dateFolder = Get-Date -Format "yyyy-MM-dd"
        
        # Create the full directory path: Transcript/{Date}/{ParentScript}
        $fullDirectoryPath = Join-Path -Path $TranscriptsPath -ChildPath $dateFolder
        $fullDirectoryPath = Join-Path -Path $fullDirectoryPath -ChildPath $parentScriptName
        
        # Ensure the directory exists
        if (-not (Test-Path -Path $fullDirectoryPath)) {
            New-Item -ItemType Directory -Path $fullDirectoryPath -Force | Out-Null
        }
        
        # Generate timestamp for unique transcript file
        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        
        # Create the transcript file name following the convention:
        # {ComputerName}-{CallingScript}-{UserType}-{UserName}-{ParentScript}-transcript-{Timestamp}.log
        $transcriptFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-transcript-$timestamp.log"
        
        # Combine the full path
        $transcriptFilePath = Join-Path -Path $fullDirectoryPath -ChildPath $transcriptFileName
        
        return $transcriptFilePath
    }
    catch {
        Write-AppDeploymentLog -Message "Failed to generate transcript file path: $($_.Exception.Message)" -Level Error -Mode SilentMode
        # Return a fallback path with user context
        $userContext = Get-CurrentUser
        $callingScript = Get-CallingScriptName
        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        $dateFolder = Get-Date -Format "yyyy-MM-dd"
        $fallbackPath = Join-Path -Path $TranscriptsPath -ChildPath $dateFolder
        $fallbackPath = Join-Path -Path $fallbackPath -ChildPath $parentScriptName
        if (-not (Test-Path -Path $fallbackPath)) {
            New-Item -ItemType Directory -Path $fallbackPath -Force | Out-Null
        }
        return Join-Path -Path $fallbackPath -ChildPath "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-transcript-fallback-$timestamp.log"
    }
}
#endregion Transcript Management Functions
function Get-CSVLogFilePath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogsPath,
        [Parameter(Mandatory = $true)]
        [string]$JobName,
        [Parameter(Mandatory = $true)]
        [string]$parentScriptName
    )

    try {
        # Get current user context and calling script
        $userContext = Get-CurrentUser
        $callingScript = Get-CallingScriptName
        
        # Generate date folder (YYYY-MM-DD format)
        $dateFolder = Get-Date -Format "yyyy-MM-dd"
        
        # Create the full directory path: PSF/{Date}/{ParentScript}
        $fullDirectoryPath = Join-Path -Path $LogsPath -ChildPath $dateFolder
        $fullDirectoryPath = Join-Path -Path $fullDirectoryPath -ChildPath $parentScriptName
        
        # Ensure the directory exists
        if (-not (Test-Path -Path $fullDirectoryPath)) {
            New-Item -ItemType Directory -Path $fullDirectoryPath -Force | Out-Null
        }

        # Generate timestamp for unique log file
        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        
        # Create the log file name following the convention:
        # {ComputerName}-{CallingScript}-{UserType}-{UserName}-{ParentScript}-log-{Timestamp}.csv
        $logFileName = "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-log-$timestamp.csv"
        
        # Combine the full path
        $csvLogFilePath = Join-Path -Path $fullDirectoryPath -ChildPath $logFileName
        
        return $csvLogFilePath
    }
    catch {
        Write-AppDeploymentLog -Message "Failed to generate CSV log file path: $($_.Exception.Message)" -Level Error -Mode SilentMode
        # Return a fallback path with user context
        $userContext = Get-CurrentUser
        $callingScript = Get-CallingScriptName
        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        $dateFolder = Get-Date -Format "yyyy-MM-dd"
        $fallbackPath = Join-Path -Path $LogsPath -ChildPath $dateFolder
        $fallbackPath = Join-Path -Path $fallbackPath -ChildPath $parentScriptName
        if (-not (Test-Path -Path $fallbackPath)) {
            New-Item -ItemType Directory -Path $fallbackPath -Force | Out-Null
        }
        return Join-Path -Path $fallbackPath -ChildPath "$($userContext.ComputerName)-$callingScript-$($userContext.UserType)-$($userContext.UserName)-$parentScriptName-log-fallback-$timestamp.csv"
    }
}




#endregion Helper Functions


#endregion Logging Function

function Get-LoggingModuleVersion {
    <#
    .SYNOPSIS
        Returns the version of the logging module
        
    .DESCRIPTION
        Gets the current version number of the logging module for version tracking
        and compatibility checking.
        
    .EXAMPLE
        $version = Get-LoggingModuleVersion
        Write-Host "Logging module version: $version"
        
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param()
    
    return $script:ModuleVersion
}

# # Export module members
# Export-ModuleMember -Function @(
#     'Initialize-Logging',
#     'Write-AppDeploymentLog',
#     'Write-EnhancedLog',
#     'Handle-Error',
#     'Get-ParentScriptName',
#     'Get-LoggingModuleVersion',
#     'Get-CurrentUser',
#     'Get-CallingScriptName',
#     'Start-UniversalTranscript',
#     'Stop-UniversalTranscript',
#     'Get-TranscriptFilePath',
#     'Get-CSVLogFilePath'
# )

# END PASTE
#endregion Embedded Logging Module

# After embedding the module above, these lines will work:
$script:LoggingEnabled = $true
$script:LoggingMode = if ($EnableDebug) { 'EnableDebug' } else { 'SilentMode' }

#REMOVE-FOR-RMM         
#REMOVE-FOR-RMM         if ($EnableDebug) {
#REMOVE-FOR-RMM             Write-Host "[DEBUG] Logging module imported successfully" -ForegroundColor Cyan
#REMOVE-FOR-RMM             Write-Host "[DEBUG] LoggingMode: $script:LoggingMode" -ForegroundColor Cyan
#REMOVE-FOR-RMM         }

# Initialize logging - KEEP THIS for production
Initialize-Logging -BaseLogPath "C:\ProgramData\OneDriveRemediation\Logs" `
                  -JobName "OneDriveRemediation" `
                  -ParentScriptName "Remediate-OneDriveConfiguration-RMM"

# Set global EnableDebug for logging module
$global:EnableDebug = $EnableDebug

if ($EnableDebug) {
    Write-Host "[DEBUG] Logging initialized. Global EnableDebug = $($global:EnableDebug)" -ForegroundColor Cyan
}

Write-AppDeploymentLog -Message "OneDrive Remediation Script Started" -Level "INFO" -Mode $script:LoggingMode
Write-AppDeploymentLog -Message "Computer: $env:COMPUTERNAME" -Level "INFO" -Mode $script:LoggingMode
Write-AppDeploymentLog -Message "Running as: $env:USERNAME" -Level "INFO" -Mode $script:LoggingMode
Write-AppDeploymentLog -Message "Tenant ID: $TenantId" -Level "INFO" -Mode $script:LoggingMode
Write-AppDeploymentLog -Message "Storage Sense Days: $StorageSenseDays" -Level "INFO" -Mode $script:LoggingMode

#REMOVE-FOR-RMM     }
#REMOVE-FOR-RMM     catch {
#REMOVE-FOR-RMM         $script:LoggingEnabled = $false
#REMOVE-FOR-RMM         if ($EnableDebug) {
#REMOVE-FOR-RMM             Write-Host "[DEBUG ERROR] Logging initialization failed: $_" -ForegroundColor Red
#REMOVE-FOR-RMM             Write-Host "[DEBUG ERROR] Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
#REMOVE-FOR-RMM         }
#REMOVE-FOR-RMM     }
#REMOVE-FOR-RMM }
#REMOVE-FOR-RMM else {
#REMOVE-FOR-RMM     if ($EnableDebug) {
#REMOVE-FOR-RMM         Write-Host "[DEBUG WARNING] Logging module not found at: $LoggingModulePath" -ForegroundColor Yellow
#REMOVE-FOR-RMM     }
#REMOVE-FOR-RMM }
#endregion

# Logging function wrapper
function Write-RemediationLog {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    
    if ($script:LoggingEnabled) {
        try {
            # Force EnableDebug mode if global debug is set
            $actualMode = if ($global:EnableDebug) { 'EnableDebug' } else { $script:LoggingMode }
            Write-AppDeploymentLog -Message $Message -Level $Level -Mode $actualMode
        }
        catch {
            # Logging failed, fall back to simple logging
        }
    }
    else {
        # Fallback logging if module not available
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logMessage = "$timestamp [$Level] $Message"
        Add-Content -Path $LogPath -Value $logMessage -Force -ErrorAction SilentlyContinue
        
        # Only write to console if debug is enabled or it's an error
        if ($EnableDebug -or $Level -eq "ERROR") {
            $color = switch ($Level) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "INFO" { "White" }
                "DEBUG" { "Gray" }
                default { "White" }
            }
            Write-Host $Message -ForegroundColor $color
        }
    }
}

# Function to configure Storage Sense
function Configure-StorageSense {
    param([int]$DaysUntilOnlineOnly = 30)
    
    Write-RemediationLog "Configuring Windows Storage Sense..."
    
    try {
        # Storage Sense registry path
        $storagePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
        
        # Create policy key if it doesn't exist
        if (!(Test-Path $storagePolicyPath)) {
            New-Item -Path $storagePolicyPath -Force | Out-Null
            Write-RemediationLog "Created Storage Sense policy registry key"
        }
        
        # Enable Storage Sense
        Set-ItemProperty -Path $storagePolicyPath -Name "AllowStorageSenseGlobal" -Value 1 -Type DWord
        Write-RemediationLog "Enabled Storage Sense globally"
        
        # Configure Storage Sense to run automatically
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseGlobalCadence" -Value 7 -Type DWord  # Weekly
        Write-RemediationLog "Set Storage Sense to run weekly"
        
        # Configure cloud content dehydration
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -Value $DaysUntilOnlineOnly -Type DWord
        Write-RemediationLog "Set Files On-Demand conversion threshold to $DaysUntilOnlineOnly days"
        
        # Additional Storage Sense settings for disk cleanup
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseRecycleBinCleanupThreshold" -Value 30 -Type DWord
        Set-ItemProperty -Path $storagePolicyPath -Name "ConfigStorageSenseDownloadsCleanupThreshold" -Value 0 -Type DWord  # Never delete downloads
        
        # Also configure user-level Storage Sense settings if possible
        $userStoragePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
        if (Test-Path "HKCU:\") {
            if (!(Test-Path $userStoragePath)) {
                New-Item -Path $userStoragePath -Force | Out-Null
            }
            
            # Enable Storage Sense for user
            Set-ItemProperty -Path $userStoragePath -Name "01" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            # Set cloud content settings
            Set-ItemProperty -Path $userStoragePath -Name "04" -Value 1 -Type DWord -ErrorAction SilentlyContinue  # Enable cloud content cleanup
            Set-ItemProperty -Path $userStoragePath -Name "08" -Value $DaysUntilOnlineOnly -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $userStoragePath -Name "32" -Value 7 -Type DWord -ErrorAction SilentlyContinue  # Run weekly
            
            Write-RemediationLog "Configured user-level Storage Sense settings"
        }
        
        Write-RemediationLog "Storage Sense configuration completed" "SUCCESS"
        return $true
    }
    catch {
        Write-RemediationLog "Failed to configure Storage Sense: $_" "ERROR"
        return $false
    }
}

# Auto-detect Tenant ID if not provided (default behavior)
if (-not $TenantId -and -not $SkipAutoDetection) {
    Write-RemediationLog "No Tenant ID provided, attempting auto-detection..." "INFO"
    
    # Inline auto-detection function
    function Get-AutoDetectedTenantID {
        # Method 1: Azure AD Join Status (Most Reliable for unconfigured machines)
        try {
            $dsregOutput = & dsregcmd /status 2>$null
            if ($dsregOutput) {
                $dsregText = $dsregOutput -join "`n"
                if ($dsregText -match 'TenantId\s*:\s*([a-fA-F0-9\-]{36})') {
                    $tenantId = $matches[1]
                    if ($tenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-RemediationLog "Tenant ID found via dsregcmd (Azure AD): $tenantId" "SUCCESS"
                        return $tenantId
                    }
                }
            }
        }
        catch {
            Write-RemediationLog "dsregcmd check failed: $_" "DEBUG"
        }
        
        # Method 2: Check existing user OneDrive configurations (for non-Azure AD joined)
        # Since we're running as SYSTEM, check all user profiles
        try {
            $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
            
            foreach ($profile in $userProfiles) {
                # Try to get SID for the user
                try {
                    $sid = $null
                    # First try with domain prefix
                    try {
                        $sid = (New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$($profile.Name)")).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                    catch {
                        # Try without domain prefix
                        $sid = (New-Object System.Security.Principal.NTAccount($profile.Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                    
                    if ($sid) {
                        $userRegPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\OneDrive\Accounts\Business1"
                        
                        if (Test-Path $userRegPath) {
                            $configuredTenantId = Get-ItemPropertyValue -Path $userRegPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
                            if ($configuredTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                                Write-RemediationLog "Tenant ID found in user profile ($($profile.Name)): $configuredTenantId" "SUCCESS"
                                return $configuredTenantId
                            }
                        }
                    }
                }
                catch {
                    Write-RemediationLog "Could not check profile $($profile.Name): $_" "DEBUG"
                }
            }
            
            # If running as user (not SYSTEM), also check HKCU
            if ($env:USERNAME -ne 'SYSTEM') {
                $regPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
                if (Test-Path $regPath) {
                    $configuredTenantId = Get-ItemPropertyValue -Path $regPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
                    if ($configuredTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-RemediationLog "Tenant ID found in current user registry: $configuredTenantId" "SUCCESS"
                        return $configuredTenantId
                    }
                }
            }
        }
        catch {
            Write-RemediationLog "User profile registry check failed: $_" "DEBUG"
        }
        
        # Method 3: Check Office 365 identity (if Office is installed)
        try {
            $officePaths = @(
                "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration"
            )
            
            foreach ($path in $officePaths) {
                if (Test-Path $path) {
                    $o365Config = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($o365Config.TenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                        Write-RemediationLog "Tenant ID found in Office 365 configuration: $($o365Config.TenantId)" "SUCCESS"
                        return $o365Config.TenantId
                    }
                }
            }
        }
        catch {
            Write-RemediationLog "Office 365 configuration check failed: $_" "DEBUG"
        }
        
        # Method 4: OneDrive Group Policy (LAST - might be from our own configuration)
        try {
            $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
            if (Test-Path $policyPath) {
                $kfmTenantId = Get-ItemPropertyValue -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue
                if ($kfmTenantId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
                    Write-RemediationLog "Tenant ID found in OneDrive policy (might be from previous run): $kfmTenantId" "WARNING"
                    return $kfmTenantId
                }
            }
        }
        catch {
            Write-RemediationLog "OneDrive policy check failed: $_" "DEBUG"
        }
        
        return $null
    }
        
    $detectedTenantId = Get-AutoDetectedTenantID
    if ($detectedTenantId) {
        $TenantId = $detectedTenantId
        Write-RemediationLog "Auto-detected Tenant ID: $TenantId" "SUCCESS"
    }
    else {
        Write-RemediationLog "Failed to auto-detect Tenant ID" "ERROR"
        Write-RemediationLog "Please provide Tenant ID using -TenantId parameter" "ERROR"
        Write-RemediationLog "Find your Tenant ID in Azure AD portal or use: (Get-AzureADTenantDetail).ObjectId" "INFO"
        $script:exitCode = 1
        exit $script:exitCode
    }
}
elseif (-not $TenantId -and $SkipAutoDetection) {
    Write-RemediationLog "No Tenant ID provided and auto-detection is disabled" "ERROR"
    Write-RemediationLog "Please provide -TenantId parameter" "ERROR"
    Write-RemediationLog "Example: .\$($MyInvocation.MyCommand.Name) -TenantId 'your-tenant-id'" "INFO"
    $script:exitCode = 1
    exit $script:exitCode
}

# These are already logged by the logging module initialization above
if (-not $script:LoggingEnabled) {
    Write-RemediationLog "Starting OneDrive configuration remediation with Storage Sense"
    Write-RemediationLog "Running as: $env:USERNAME"
    Write-RemediationLog "Tenant ID: $TenantId"
    Write-RemediationLog "Storage Sense Days: $StorageSenseDays"
}

try {
    # Load detection results if available
    $detectionResults = @{}
    if (Test-Path $DetectionResultsPath) {
        Write-RemediationLog "Loading detection results from: $DetectionResultsPath"
        $detectionResults = Get-Content -Path $DetectionResultsPath -Raw | ConvertFrom-Json
    } else {
        Write-RemediationLog "No detection results found, will perform full remediation" "WARNING"
    }
    
    # 1. Install OneDrive if needed (skip if ConfigurationOnly)
    if ($detectionResults.OneDriveInstalled -eq $false) {
        if ($ConfigurationOnly) {
            Write-RemediationLog "OneDrive not installed, but ConfigurationOnly mode is set - skipping installation" "WARNING"
            Write-RemediationLog "OneDrive deployment should be handled separately" "INFO"
            
            # Exit early if OneDrive not installed and we're in ConfigurationOnly mode
            Write-RemediationLog "Cannot configure OneDrive when it's not installed" "ERROR"
            $script:exitCode = 1
            
            Write-RemediationLog "`nRemediation completed. Exit code: $script:exitCode"
            
            # Cleanup logging
            if ($script:LoggingEnabled) {
                try {
                    $null = Stop-UniversalTranscript -ErrorAction SilentlyContinue
                }
                catch {
                    # Ignore transcript errors
                }
            }
            
            exit $script:exitCode
        }
        else {
            Write-RemediationLog "OneDrive not installed - attempting installation..."
            
            # Download OneDrive installer
            $installerUrl = "https://go.microsoft.com/fwlink/?linkid=844652"
            $installerPath = "$env:TEMP\OneDriveSetup.exe"
            
            try {
                Write-RemediationLog "Downloading OneDrive installer..."
                Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
                
                Write-RemediationLog "Installing OneDrive..."
                Start-Process -FilePath $installerPath -ArgumentList "/allusers" -Wait -NoNewWindow
                
                Write-RemediationLog "OneDrive installation completed" "SUCCESS"
                
                # Clean up installer
                Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-RemediationLog "Failed to install OneDrive: $_" "ERROR"
                $script:remediationSuccess = $false
            }
        }
    }
    
    # 2. Configure Group Policy settings
    Write-RemediationLog "Configuring OneDrive Group Policy settings..."
    
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    # Create policy key if it doesn't exist
    if (!(Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
        Write-RemediationLog "Created policy registry key"
    }
    
    # Configure tenant ID for KFM
    Set-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -Value $TenantId -Type String
    Write-RemediationLog "Configured tenant ID for KFM: $TenantId" "SUCCESS"
    
    # Enable Files On-Demand (Note: Already on by default since March 2024)
    Set-ItemProperty -Path $policyPath -Name "FilesOnDemandEnabled" -Value 1 -Type DWord
    Write-RemediationLog "Ensured Files On-Demand is enabled" "SUCCESS"
    
    # Check OneDrive version to determine Downloads folder support
    $oneDrivePaths = @(
        "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
        "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    )
    
    foreach ($path in $oneDrivePaths) {
        if (Test-Path $path) {
            $versionInfo = (Get-Item $path).VersionInfo
            $oneDriveVersion = $versionInfo.FileVersion
            Write-RemediationLog "OneDrive version: $oneDriveVersion"
            
            # Check if version supports Downloads folder KFM (23.002+)
            $version = $oneDriveVersion.Split('.')
            if ([int]$version[0] -gt 23 -or ([int]$version[0] -eq 23 -and [int]$version[1] -ge 2)) {
                $script:supportsDownloadsKFM = $true
                Write-RemediationLog "OneDrive version supports Downloads folder KFM"
            } else {
                Write-RemediationLog "OneDrive version does NOT support Downloads folder KFM (requires 23.002+)" "WARNING"
            }
            break
        }
    }
    
    # Configure KFM for folders based on version support
    $kfmSettings = @{
        "KFMSilentOptInDesktop" = 1
        "KFMSilentOptInDocuments" = 1
        "KFMSilentOptInPictures" = 1
        "KFMBlockOptIn" = 0  # Ensure KFM is not blocked
        "KFMBlockOptOut" = 1  # Prevent users from opting out
    }
    
    # Only add Downloads if version supports it
    if ($script:supportsDownloadsKFM) {
        $kfmSettings["KFMSilentOptInDownloads"] = 1
        Write-RemediationLog "Including Downloads folder in KFM configuration"
    } else {
        Write-RemediationLog "Skipping Downloads folder KFM (not supported by this OneDrive version)"
    }
    
    foreach ($setting in $kfmSettings.GetEnumerator()) {
        Set-ItemProperty -Path $policyPath -Name $setting.Key -Value $setting.Value -Type DWord
        Write-RemediationLog "Set $($setting.Key) = $($setting.Value)"
    }
    
    if ($script:supportsDownloadsKFM) {
        Write-RemediationLog "KFM configured for all 4 folders" "SUCCESS"
    } else {
        Write-RemediationLog "KFM configured for 3 core folders (Desktop/Documents/Pictures)" "SUCCESS"
        Write-RemediationLog "Downloads folder will be added when OneDrive is updated to 23.002+" "INFO"
    }
    
    # 3. Additional optimization settings
    Write-RemediationLog "Applying additional optimization settings..."
    
    # Prevent sync of certain file types
    $excludedTypes = "*.pst;*.ost"
    Set-ItemProperty -Path $policyPath -Name "FileSyncExcludedExtensions" -Value $excludedTypes -Type String
    Write-RemediationLog "Excluded file types: $excludedTypes"
    
    # Set maximum file size (15GB)
    Set-ItemProperty -Path $policyPath -Name "ForcedLocalMassDeleteDetection" -Value 1 -Type DWord
    
    # Enable automatic sign-in with Windows credentials
    Set-ItemProperty -Path $policyPath -Name "SilentAccountConfig" -Value 1 -Type DWord
    Write-RemediationLog "Enabled silent account configuration - users will auto-login with Windows credentials"
    
    # Disable personal OneDrive accounts (security setting)
    Set-ItemProperty -Path $policyPath -Name "DisablePersonalSync" -Value 1 -Type DWord
    Write-RemediationLog "Disabled personal OneDrive accounts - prevents data leakage to personal storage"
    
    # 4. Configure Storage Sense for automatic disk space management
    $storageSenseSuccess = Configure-StorageSense -DaysUntilOnlineOnly $StorageSenseDays
    if (-not $storageSenseSuccess) {
        Write-RemediationLog "Storage Sense configuration failed - files will need manual conversion to online-only" "WARNING"
    }
    
    # 5. Start OneDrive if not running
    if ($detectionResults.OneDriveRunning -eq $false) {
        Write-RemediationLog "OneDrive not running - attempting to start..."
        
        # Find OneDrive.exe
        $oneDrivePaths = @(
            "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
            "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe",
            "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
        )
        
        $oneDriveExe = $null
        foreach ($path in $oneDrivePaths) {
            if (Test-Path $path) {
                $oneDriveExe = $path
                break
            }
        }
        
        if ($oneDriveExe) {
            # Get logged-in user
            $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
            if ($loggedInUser -and $loggedInUser -notmatch "^NT AUTHORITY") {
                Write-RemediationLog "Starting OneDrive for user: $loggedInUser"
                
                # Create scheduled task to start OneDrive as user
                $taskName = "StartOneDrive_Remediation"
                $action = New-ScheduledTaskAction -Execute $oneDriveExe
                $principal = New-ScheduledTaskPrincipal -UserId $loggedInUser -LogonType Interactive
                $task = New-ScheduledTask -Action $action -Principal $principal
                
                Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
                Start-ScheduledTask -TaskName $taskName
                
                Start-Sleep -Seconds 5
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                
                Write-RemediationLog "OneDrive start initiated" "SUCCESS"
            } else {
                Write-RemediationLog "No interactive user found - OneDrive will start at next login" "WARNING"
            }
        } else {
            Write-RemediationLog "OneDrive.exe not found after installation" "ERROR"
            $script:remediationSuccess = $false
        }
    }
    
    # 6. Verify remediation
    Write-RemediationLog "`n=== REMEDIATION SUMMARY ===" "INFO"
    
    # Check if all critical settings are in place
    $verifySettings = @{
        "KFMSilentOptIn" = $TenantId
        "FilesOnDemandEnabled" = 1
        "KFMSilentOptInDesktop" = 1
        "KFMSilentOptInDocuments" = 1
        "KFMSilentOptInPictures" = 1
        "SilentAccountConfig" = 1
        "DisablePersonalSync" = 1
    }
    
    # Only verify Downloads if version supports it
    if ($script:supportsDownloadsKFM) {
        $verifySettings["KFMSilentOptInDownloads"] = 1
    }
    
    $allConfigured = $true
    foreach ($setting in $verifySettings.GetEnumerator()) {
        $value = Get-ItemProperty -Path $policyPath -Name $setting.Key -ErrorAction SilentlyContinue
        if ($value.$($setting.Key) -eq $setting.Value) {
            Write-RemediationLog "$($setting.Key): Configured correctly" "SUCCESS"
        } else {
            Write-RemediationLog "$($setting.Key): NOT configured correctly" "ERROR"
            $allConfigured = $false
        }
    }
    
    # Check Storage Sense
    $storageSenseEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "AllowStorageSenseGlobal" -ErrorAction SilentlyContinue
    if ($storageSenseEnabled.AllowStorageSenseGlobal -eq 1) {
        Write-RemediationLog "Storage Sense: Enabled" "SUCCESS"
        Write-RemediationLog "Files will automatically convert to online-only after $StorageSenseDays days of non-use"
    } else {
        Write-RemediationLog "Storage Sense: Not enabled" "WARNING"
    }
    
    if ($allConfigured -and $script:remediationSuccess) {
        Write-RemediationLog "`nREMEDIATION SUCCESSFUL" "SUCCESS"
        Write-RemediationLog "OneDrive is configured for disk space optimization"
        Write-RemediationLog "Storage Sense will automatically free space by converting unused files to online-only"
        Write-RemediationLog "Settings will take effect at next user login or policy refresh"
        $script:exitCode = 0
    } else {
        Write-RemediationLog "`nREMEDIATION PARTIALLY SUCCESSFUL" "WARNING"
        Write-RemediationLog "Some settings may require manual intervention"
        $script:exitCode = 1
    }
    
    # Force group policy update
    Write-RemediationLog "`nForcing group policy update..."
    & gpupdate /force /wait:0 2>&1 | Out-Null
    Write-RemediationLog "Group policy update initiated"
    
    # Additional info about disk space savings
    Write-RemediationLog "`n=== DISK SPACE OPTIMIZATION INFO ===" "INFO"
    Write-RemediationLog "Files On-Demand: Enabled by default since OneDrive March 2024"
    Write-RemediationLog "Storage Sense: Configured to run weekly"
    Write-RemediationLog "Automatic conversion: Files unused for $StorageSenseDays days become online-only"
    Write-RemediationLog "Manual conversion: Users can right-click files and select 'Free up space'"
    Write-RemediationLog "Protected files: Files marked 'Always keep on this device' won't be converted"
}
catch {
    Write-RemediationLog "CRITICAL ERROR during remediation: $_" "ERROR"
    $script:exitCode = 1
}

Write-RemediationLog "`nRemediation completed. Exit code: $script:exitCode"

# Only log path if not using logging module (which saves to its own location)
if (-not $script:LoggingEnabled) {
    Write-RemediationLog "Log saved to: $LogPath"
}

# Cleanup logging
if ($script:LoggingEnabled) {
    try {
        $null = Stop-UniversalTranscript -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore transcript errors
    }
}

# Return exit code for RMM
exit $script:exitCode