#Requires -Version 5.1

# Minimal test case for logging module line numbers
Write-Host "=== Minimal Logging Module Test ===" -ForegroundColor Cyan

# Set debug mode
$global:EnableDebug = $true

# Import the logging module
$loggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
Write-Host "Importing logging module from: $loggingModulePath" -ForegroundColor Yellow

Import-Module $loggingModulePath -Force

# Initialize logging
$logPath = Join-Path $env:TEMP "test-logging-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Write-Host "Log file: $logPath" -ForegroundColor Yellow

Initialize-AppDeploymentLogging -LogPath $logPath -LoggingMode "EnableDebug"

# Test wrapper function (mimics Write-DetectionLog)
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = 'Information'
    )
    
    Write-AppDeploymentLog -Message $Message -Level $Level -Source ${CmdletName}
}

# Direct logging tests
Write-Host "`n--- Testing Direct Calls ---" -ForegroundColor Green
Write-AppDeploymentLog -Message "Direct call from line 34" -Level "Information"
Write-AppDeploymentLog -Message "Another direct call from line 35" -Level "Information"

# Wrapper function tests
Write-Host "`n--- Testing Wrapper Function Calls ---" -ForegroundColor Green
Write-TestLog -Message "Call through wrapper from line 39"
Write-TestLog -Message "Another wrapper call from line 40"

# Test from within a function
function Test-FunctionCalls {
    Write-Host "`n--- Testing Calls from Function ---" -ForegroundColor Green
    Write-AppDeploymentLog -Message "Direct call from function line 45" -Level "Information"
    Write-TestLog -Message "Wrapper call from function line 46"
}

Test-FunctionCalls

Write-Host "`n--- Test Complete ---" -ForegroundColor Cyan
Write-Host "Check the console output above for line numbers" -ForegroundColor Yellow
Write-Host "Expected format: [Level] [ScriptName.FunctionName:LineNumber] - Message" -ForegroundColor Yellow