#Requires -Version 5.1

# Minimal test case for logging module line numbers
Write-Host "=== Minimal Logging Module Test V2 ===" -ForegroundColor Cyan

# Set debug mode
$global:EnableDebug = $true

# Import the logging module
$loggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
Write-Host "Importing logging module from: $loggingModulePath" -ForegroundColor Yellow

Import-Module $loggingModulePath -Force

# Initialize logging using the correct function name
$logPath = Join-Path $env:TEMP "test-logging-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Write-Host "Log file: $logPath" -ForegroundColor Yellow

Initialize-Logging -ScriptPath $PSCommandPath -LogPath $logPath

# Test wrapper function (mimics Write-DetectionLog)
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = 'Information'
    )
    
    Write-AppDeploymentLog -Message $Message -Level $Level
}

# Direct logging tests
Write-Host "`n--- Testing Direct Calls ---" -ForegroundColor Green
Write-AppDeploymentLog -Message "Direct call from line 33" -Level "Information"
Write-AppDeploymentLog -Message "Another direct call from line 34" -Level "Information"

# Wrapper function tests
Write-Host "`n--- Testing Wrapper Function Calls ---" -ForegroundColor Green
Write-TestLog -Message "Call through wrapper from line 38"
Write-TestLog -Message "Another wrapper call from line 39"

# Test from within a function
function Test-FunctionCalls {
    Write-Host "`n--- Testing Calls from Function ---" -ForegroundColor Green
    Write-AppDeploymentLog -Message "Direct call from function line 44" -Level "Information"
    Write-TestLog -Message "Wrapper call from function line 45"
}

Test-FunctionCalls

# Test deeply nested calls
function Level1-Function {
    Write-Host "`n--- Testing Nested Function Calls ---" -ForegroundColor Green
    Write-AppDeploymentLog -Message "Direct from Level1 line 53" -Level "Information"
    Level2-Function
}

function Level2-Function {
    Write-TestLog -Message "Wrapper from Level2 line 58"
}

Level1-Function

Write-Host "`n--- Test Complete ---" -ForegroundColor Cyan
Write-Host "Check the console output above for line numbers" -ForegroundColor Yellow
Write-Host "Expected format: [Level] [ScriptName.FunctionName:LineNumber] - Message" -ForegroundColor Yellow