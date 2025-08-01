#requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive test script for OneDrive detection and remediation scripts.

.DESCRIPTION
    This script tests all OneDrive scripts in various contexts and validates their functionality.

.PARAMETER TenantID
    Your Azure AD Tenant ID for testing

.PARAMETER TestRemediation
    Include remediation testing (makes changes to system)

.PARAMETER TestSystemContext
    Test scripts in SYSTEM context using PSExec

.EXAMPLE
    .\Test-ComprehensiveOneDrive.ps1 -TenantID "12345678-1234-1234-1234-123456789012"

.NOTES
    Requires administrative privileges for full testing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantID,
    
    [switch]$TestRemediation,
    
    [switch]$TestSystemContext
)

#region Initialization
$ErrorActionPreference = 'Continue'
$testResults = @{
    TotalTests = 0
    Passed = 0
    Failed = 0
    Skipped = 0
    Details = @()
}

$scriptPath = "C:\code\OneDrive\Scripts"
$logPath = "C:\code\OneDrive\TestResults"
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Create test results directory
if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

$testLogFile = Join-Path $logPath "TestResults_$timestamp.log"
#endregion

#region Helper Functions
function Write-TestLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Pass', 'Fail', 'Warning', 'Skip')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $testLogFile -Value $logEntry -Force
    
    # Write to console with color
    switch ($Level) {
        'Info' { Write-Host $logEntry -ForegroundColor Cyan }
        'Pass' { Write-Host $logEntry -ForegroundColor Green }
        'Fail' { Write-Host $logEntry -ForegroundColor Red }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Skip' { Write-Host $logEntry -ForegroundColor Gray }
    }
}

function Test-Script {
    param(
        [string]$TestName,
        [string]$ScriptPath,
        [hashtable]$Parameters,
        [scriptblock]$ValidationScript,
        [switch]$RunAsSystem
    )
    
    $testResults.TotalTests++
    Write-TestLog "Starting test: $TestName" -Level Info
    
    try {
        if ($RunAsSystem) {
            if (-not $TestSystemContext) {
                Write-TestLog "Skipping SYSTEM context test (use -TestSystemContext to enable)" -Level Skip
                $testResults.Skipped++
                return
            }
            
            # Check for PSExec
            $psexecPath = Get-Command psexec.exe -ErrorAction SilentlyContinue
            if (-not $psexecPath) {
                Write-TestLog "PSExec not found in PATH - cannot test SYSTEM context" -Level Warning
                $testResults.Skipped++
                return
            }
            
            # Build PSExec command
            $paramString = ($Parameters.GetEnumerator() | ForEach-Object { "-$($_.Key) `"$($_.Value)`"" }) -join " "
            $psexecCmd = "psexec.exe -s -accepteula powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`" $paramString"
            
            Write-TestLog "Executing as SYSTEM: $psexecCmd" -Level Info
            $output = & cmd /c $psexecCmd 2>&1
            $exitCode = $LASTEXITCODE
        }
        else {
            # Run normally
            $output = & powershell.exe -ExecutionPolicy Bypass -File $ScriptPath @Parameters 2>&1
            $exitCode = $LASTEXITCODE
        }
        
        Write-TestLog "Script output: $($output -join ' ')" -Level Info
        Write-TestLog "Exit code: $exitCode" -Level Info
        
        # Run validation
        $validationResult = & $ValidationScript -Output $output -ExitCode $exitCode
        
        if ($validationResult.Success) {
            Write-TestLog "Test passed: $($validationResult.Message)" -Level Pass
            $testResults.Passed++
            $testResults.Details += @{
                Test = $TestName
                Result = "Pass"
                Message = $validationResult.Message
            }
        }
        else {
            Write-TestLog "Test failed: $($validationResult.Message)" -Level Fail
            $testResults.Failed++
            $testResults.Details += @{
                Test = $TestName
                Result = "Fail"
                Message = $validationResult.Message
                Output = $output
            }
        }
    }
    catch {
        Write-TestLog "Test error: $_" -Level Fail
        $testResults.Failed++
        $testResults.Details += @{
            Test = $TestName
            Result = "Error"
            Message = $_.Exception.Message
        }
    }
}

function Test-RegistryKey {
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue
    )
    
    if (Test-Path $Path) {
        $actualValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($actualValue) {
            return $actualValue.$Name -eq $ExpectedValue
        }
    }
    return $false
}

function Test-OneDriveRunning {
    $process = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    return $null -ne $process
}
#endregion

#region Main Test Execution
Write-TestLog "=== OneDrive Script Comprehensive Testing Started ===" -Level Info
Write-TestLog "TenantID: $TenantID" -Level Info
Write-TestLog "Test Remediation: $TestRemediation" -Level Info
Write-TestLog "Test System Context: $TestSystemContext" -Level Info
Write-TestLog "Current User: $env:USERNAME" -Level Info
Write-TestLog "Is Administrator: $([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -Level Info

# Test 1: Basic Detection Script
Test-Script -TestName "Detection Script - User Context" `
    -ScriptPath "$scriptPath\Detect-OneDriveConfiguration.ps1" `
    -Parameters @{TenantID = $TenantID} `
    -ValidationScript {
        param($Output, $ExitCode)
        
        # Exit code 0 = healthy, 1 = issues detected
        if ($ExitCode -in @(0, 1)) {
            return @{
                Success = $true
                Message = "Detection script executed successfully with exit code $ExitCode"
            }
        }
        else {
            return @{
                Success = $false
                Message = "Unexpected exit code: $ExitCode"
            }
        }
    }

# Test 2: Detection Script in SYSTEM Context
Test-Script -TestName "Detection Script - SYSTEM Context" `
    -ScriptPath "$scriptPath\Detect-OneDriveConfiguration.ps1" `
    -Parameters @{TenantID = $TenantID} `
    -RunAsSystem `
    -ValidationScript {
        param($Output, $ExitCode)
        
        if ($ExitCode -in @(0, 1)) {
            return @{
                Success = $true
                Message = "SYSTEM context detection completed with exit code $ExitCode"
            }
        }
        else {
            return @{
                Success = $false
                Message = "SYSTEM context detection failed with exit code $ExitCode"
            }
        }
    }

# Test 3: V2 Detection Script
Test-Script -TestName "V2 Detection Script - User Context" `
    -ScriptPath "$scriptPath\Invoke-OneDriveDetectionRemediationV2.ps1" `
    -Parameters @{TenantID = $TenantID} `
    -ValidationScript {
        param($Output, $ExitCode)
        
        # Check for JSON output file
        $jsonFile = "C:\ProgramData\OneDriveRemediation\DetectionResults.json"
        $jsonExists = Test-Path $jsonFile
        
        if ($ExitCode -in @(0, 1) -and $jsonExists) {
            return @{
                Success = $true
                Message = "V2 script executed successfully, JSON results created"
            }
        }
        else {
            return @{
                Success = $false
                Message = "V2 script failed - Exit: $ExitCode, JSON exists: $jsonExists"
            }
        }
    }

# Test 4: Registry Configuration
Write-TestLog "Testing registry configuration state" -Level Info
$registryTests = @{
    "KFM Policy Path Exists" = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    "OneDrive Running" = Test-OneDriveRunning
}

foreach ($test in $registryTests.GetEnumerator()) {
    $testResults.TotalTests++
    if ($test.Value) {
        Write-TestLog "$($test.Key): Pass" -Level Pass
        $testResults.Passed++
    }
    else {
        Write-TestLog "$($test.Key): Fail" -Level Fail
        $testResults.Failed++
    }
}

# Test 5: OneDriveLib.dll Download
Write-TestLog "Testing OneDriveLib.dll functionality" -Level Info
$testResults.TotalTests++

$dllTestScript = {
    $testPath = "C:\ProgramData\OneDriveRemediation"
    if (-not (Test-Path $testPath)) {
        New-Item -Path $testPath -ItemType Directory -Force | Out-Null
    }
    
    $dllPath = Join-Path $testPath "OneDriveLib.dll"
    if (Test-Path $dllPath) {
        Remove-Item $dllPath -Force
    }
    
    # Test download
    $dllUrl = "https://raw.githubusercontent.com/rodneyviana/ODSyncService/master/Binaries/PowerShell/OneDriveLib.dll"
    try {
        Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing
        return Test-Path $dllPath
    }
    catch {
        return $false
    }
}

if (& $dllTestScript) {
    Write-TestLog "OneDriveLib.dll download test: Pass" -Level Pass
    $testResults.Passed++
}
else {
    Write-TestLog "OneDriveLib.dll download test: Fail" -Level Fail
    $testResults.Failed++
}

# Test 6: Remediation (if enabled)
if ($TestRemediation) {
    Write-TestLog "Starting remediation tests" -Level Warning
    
    Test-Script -TestName "Remediation Script - User Context" `
        -ScriptPath "$scriptPath\Remediate-OneDriveConfiguration.ps1" `
        -Parameters @{TenantID = $TenantID} `
        -ValidationScript {
            param($Output, $ExitCode)
            
            # Check if registry keys were created
            $kfmSet = Test-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" `
                -Name "KFMSilentOptIn" -ExpectedValue $TenantID
            
            if ($ExitCode -eq 0 -and $kfmSet) {
                return @{
                    Success = $true
                    Message = "Remediation completed successfully"
                }
            }
            else {
                return @{
                    Success = $false
                    Message = "Remediation failed - Exit: $ExitCode, KFM Set: $kfmSet"
                }
            }
        }
}
else {
    Write-TestLog "Skipping remediation tests (use -TestRemediation to enable)" -Level Skip
}

#endregion

#region Test Summary
Write-TestLog "`n=== Test Summary ===" -Level Info
Write-TestLog "Total Tests: $($testResults.TotalTests)" -Level Info
Write-TestLog "Passed: $($testResults.Passed)" -Level Pass
Write-TestLog "Failed: $($testResults.Failed)" -Level Fail
Write-TestLog "Skipped: $($testResults.Skipped)" -Level Skip

$successRate = if ($testResults.TotalTests -gt 0) { 
    [math]::Round(($testResults.Passed / ($testResults.TotalTests - $testResults.Skipped)) * 100, 2) 
} else { 0 }

Write-TestLog "Success Rate: $successRate%" -Level Info

# Export detailed results
$resultsFile = Join-Path $logPath "TestResults_$timestamp.json"
$testResults | ConvertTo-Json -Depth 10 | Out-File $resultsFile -Force
Write-TestLog "Detailed results saved to: $resultsFile" -Level Info

# Final result
if ($testResults.Failed -eq 0) {
    Write-TestLog "`nALL TESTS PASSED!" -Level Pass
    exit 0
}
else {
    Write-TestLog "`nSOME TESTS FAILED - Review the log for details" -Level Fail
    
    # Show failed test details
    Write-TestLog "`nFailed Tests:" -Level Fail
    $testResults.Details | Where-Object { $_.Result -eq "Fail" } | ForEach-Object {
        Write-TestLog "  - $($_.Test): $($_.Message)" -Level Fail
    }
    
    exit 1
}
#endregion