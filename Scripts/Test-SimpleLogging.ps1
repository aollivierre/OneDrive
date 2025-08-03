#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$EnableDebug
)

# Import the simple logging module
$loggingPath = Join-Path $PSScriptRoot "logging\simple-logging.psm1"
Import-Module $loggingPath -Force

# Initialize logging
Initialize-SimpleLogging -EnableDebug:$EnableDebug

# Test various logging scenarios
Write-Host "`n=== Testing Simple Logging Module ===" -ForegroundColor Cyan

# Direct calls from main script
Write-SimpleLog -Message "Test message from main script" -Level Information
Write-SimpleLog -Message "Debug message from main script" -Level Debug
Write-SimpleLog -Message "Warning message from main script" -Level Warning
Write-SimpleLog -Message "Error message from main script" -Level Error

# Test with wrapper function (like Write-DetectionLog)
function Write-DetectionLog {
    param(
        [string]$Message,
        [string]$Level = 'Information'
    )
    Write-SimpleLog -Message $Message -Level $Level
}

Write-Host "`n--- Testing through wrapper function ---" -ForegroundColor Yellow
Write-DetectionLog -Message "Starting detection process" -Level Information
Write-DetectionLog -Message "Checking system state" -Level Debug
Write-DetectionLog -Message "Found potential issue" -Level Warning

# Test from within another function
function Test-NestedFunction {
    Write-SimpleLog -Message "Message from nested function" -Level Information
    Write-DetectionLog -Message "Message via wrapper in nested function" -Level Information
}

Write-Host "`n--- Testing from nested function ---" -ForegroundColor Yellow
Test-NestedFunction

Write-Host "`n=== Test Complete ===" -ForegroundColor Green