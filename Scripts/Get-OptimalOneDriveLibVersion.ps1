#Requires -Version 5.1

<#
.SYNOPSIS
    Detects Windows version and returns the appropriate OneDrive status checking method
.DESCRIPTION
    Windows 10 (older builds): Use OneDriveLib.dll from ODSyncService
    Windows 10 (newer builds) and Windows 11: Use ODSyncUtil.exe
    Based on Rodney Viana's recommendations for each OS version
#>

function Get-OptimalOneDriveLibVersion {
    [CmdletBinding()]
    param()
    
    # Get OS version details
    $os = [System.Environment]::OSVersion
    $version = $os.Version
    $buildNumber = $version.Build
    
    # Get more detailed Windows info
    $winVer = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $displayVersion = $winVer.DisplayVersion
    $productName = $winVer.ProductName
    
    Write-Host "Detecting Windows Version..." -ForegroundColor Cyan
    Write-Host "  Product: $productName" -ForegroundColor Gray
    Write-Host "  Version: $($version.Major).$($version.Minor).$buildNumber" -ForegroundColor Gray
    Write-Host "  Display Version: $displayVersion" -ForegroundColor Gray
    
    $result = @{
        OSVersion = $version
        BuildNumber = $buildNumber
        ProductName = $productName
        DisplayVersion = $displayVersion
        RecommendedMethod = $null
        DownloadUrl = $null
        Description = $null
    }
    
    # Windows 11 detection (Build 22000+)
    if ($buildNumber -ge 22000) {
        Write-Host "`nDetected: Windows 11" -ForegroundColor Green
        $result.RecommendedMethod = "ODSyncUtil"
        $result.DownloadUrl = "https://github.com/rodneyviana/ODSyncUtil/releases/latest"
        $result.Description = "Use ODSyncUtil.exe with Get-ODStatus.ps1 for Windows 11"
    }
    # Windows 10 newer builds (20H1 and later - Build 19041+)
    elseif ($buildNumber -ge 19041) {
        Write-Host "`nDetected: Windows 10 (newer build)" -ForegroundColor Green
        Write-Host "  This build supports both methods" -ForegroundColor Yellow
        $result.RecommendedMethod = "ODSyncUtil"
        $result.DownloadUrl = "https://github.com/rodneyviana/ODSyncUtil/releases/latest"
        $result.Description = "ODSyncUtil is recommended for Windows 10 build 19041+"
    }
    # Windows 10 older builds
    elseif ($version.Major -eq 10) {
        Write-Host "`nDetected: Windows 10 (older build)" -ForegroundColor Green
        $result.RecommendedMethod = "OneDriveLib"
        $result.DownloadUrl = "https://github.com/rodneyviana/ODSyncService/releases/latest"
        $result.Description = "Use OneDriveLib.dll for older Windows 10 builds"
    }
    # Windows 8.1 or older (not supported)
    else {
        Write-Host "`nDetected: Unsupported Windows version" -ForegroundColor Red
        $result.RecommendedMethod = "Unsupported"
        $result.Description = "OneDrive status checking requires Windows 10 or later"
    }
    
    # Check current installation
    Write-Host "`nChecking current installation..." -ForegroundColor Cyan
    
    $oneDriveLibPath = "C:\ProgramData\OneDriveRemediation\OneDriveLib.dll"
    $odSyncUtilPath = "C:\ProgramData\OneDriveRemediation\ODSyncUtil.exe"
    
    if (Test-Path $oneDriveLibPath) {
        Write-Host "  Found: OneDriveLib.dll" -ForegroundColor Green
        $result.CurrentOneDriveLib = $true
    }
    
    if (Test-Path $odSyncUtilPath) {
        Write-Host "  Found: ODSyncUtil.exe" -ForegroundColor Green
        $result.CurrentODSyncUtil = $true
    }
    
    # Recommendation
    Write-Host "`nRECOMMENDATION:" -ForegroundColor Yellow
    Write-Host "  Method: $($result.RecommendedMethod)" -ForegroundColor White
    Write-Host "  $($result.Description)" -ForegroundColor Gray
    
    if ($result.RecommendedMethod -eq "ODSyncUtil" -and -not $result.CurrentODSyncUtil) {
        Write-Host "`n  ACTION NEEDED: Download ODSyncUtil from:" -ForegroundColor Red
        Write-Host "  $($result.DownloadUrl)" -ForegroundColor Cyan
    }
    
    return $result
}

# Self-test if run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-OptimalOneDriveLibVersion
}