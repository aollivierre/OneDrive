#Requires -Version 5.1

# Test script that mimics RMM script structure
Write-Host "=== Testing RMM-Style Logging ===" -ForegroundColor Cyan

# Set debug mode
$global:EnableDebug = $true

# Import the logging module
$loggingModulePath = Join-Path $PSScriptRoot "logging\logging.psm1"
Import-Module $loggingModulePath -Force

# Initialize logging (mimicking RMM script)
$script:LoggingEnabled = $true
$script:LoggingMode = 'EnableDebug'

# Exact wrapper function from RMM script
function Write-DetectionLog {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Information'
    )
    
    # Get the calling line number
    $callStack = Get-PSCallStack
    $lineNumber = if ($callStack.Count -ge 2) { $callStack[1].ScriptLineNumber } else { 0 }
    
    if ($script:LoggingEnabled) {
        try {
            # Force EnableDebug mode if global debug is set
            $actualMode = if ($global:EnableDebug) { 'EnableDebug' } else { $script:LoggingMode }
            Write-AppDeploymentLog -Message $Message -Level $Level -Mode $actualMode
        }
        catch {
            # Logging failed, continue
        }
    }
    
    # Also write to console if debug enabled
    if ($EnableDebug -or $Level -eq 'Error') {
        $color = switch ($Level) {
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Debug' { 'Gray' }
            default { 'White' }
        }
        Write-Host $Message -ForegroundColor $color
    }
}

Write-Host "`nTesting Write-DetectionLog calls (should show actual line numbers):" -ForegroundColor Yellow

# Line 52: First test
Write-DetectionLog -Message "Starting OneDrive detection" -Level 'Information'

# Line 55: Second test
Write-DetectionLog -Message "Test from line 55" -Level 'Information'

# Line 58: Test from function
function Test-Function {
    Write-DetectionLog -Message "Called from Test-Function at line 60" -Level 'Information'
}
Test-Function

Write-Host "`n--- Test Complete ---" -ForegroundColor Cyan
Write-Host "Expected: Line numbers should be 52, 55, and 60" -ForegroundColor Yellow