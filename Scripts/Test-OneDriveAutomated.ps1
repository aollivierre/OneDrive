#requires -Version 5.1
<#
.SYNOPSIS
    Automated OneDrive validation with NO user interaction
    
.DESCRIPTION
    This script validates OneDrive configuration and outputs:
    - Exit code 0: Everything is working
    - Exit code 1: Issues detected
    - Exit code 2: Critical failure
    
    NO prompts, NO "press any key", just results.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$exitCode = 0

try {
    # Capture output from status check
    $outputFile = Join-Path $env:TEMP "onedrive-status-temp.txt"
    & "$PSScriptRoot\Get-OneDriveRealStatus.ps1" > $outputFile 2>&1
    $output = Get-Content $outputFile -Raw
    Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
    
    if ($output -match "KFM is properly configured and working") {
        Write-Output "PASS: OneDrive KFM is working correctly"
        $exitCode = 0
    }
    elseif ($output -match "(\d+) of 4 folders are in OneDrive") {
        $folderCount = $matches[1]
        if ($folderCount -ge 3) {
            Write-Output "PASS: $folderCount of 4 folders redirected to OneDrive"
            $exitCode = 0
        }
        else {
            Write-Output "FAIL: Only $folderCount of 4 folders redirected"
            $exitCode = 1
        }
    }
    else {
        Write-Output "FAIL: OneDrive KFM not configured properly"
        $exitCode = 1
    }
    
    # Check specific issues
    if ($output -match "OneDrive is NOT running") {
        Write-Output "ISSUE: OneDrive process not running"
        $exitCode = 1
    }
    
    if ($output -match "dummy tenant ID") {
        Write-Output "ISSUE: Using invalid dummy tenant ID"
        $exitCode = 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    $exitCode = 2
}

# Exit with appropriate code - NO user interaction
exit $exitCode