#Requires -Version 5.1

<#
.SYNOPSIS
    Adaptive OneDrive status collector that uses the right method for the OS
.DESCRIPTION
    Automatically detects Windows version and uses:
    - OneDriveLib.dll for older Windows 10
    - ODSyncUtil.exe for newer Windows 10 and Windows 11
    Falls back gracefully if preferred method unavailable
#>

param(
    [string]$LogFolder = "$env:USERPROFILE\logs",
    [string]$StatusFileName = "OneDriveStatus.json"
)

# Initialize logging
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$logPath = Join-Path $LogFolder "OneDriveStatusCollection.log"

if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

Add-Content -Path $logPath -Value "$timestamp [INFO] Starting adaptive OneDrive status collection" -Force

try {
    # Security check
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.IsSystem) {
        throw "This script must NOT run as SYSTEM. Use scheduled task with user context."
    }
    
    # Detect OS version
    $buildNumber = [System.Environment]::OSVersion.Version.Build
    Add-Content -Path $logPath -Value "$timestamp [INFO] Windows build: $buildNumber" -Force
    
    # Initialize result
    $result = @{
        timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        username = "$env:COMPUTERNAME\$env:USERNAME"
        userSID = $currentUser.User.Value
        windowsBuild = $buildNumber
        collectionMethod = "Unknown"
        oneDriveStatus = @{
            currentStateString = "Unknown"
            isRunning = $false
            syncFolders = @()
        }
        errors = @()
    }
    
    # Check OneDrive process
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($oneDriveProcess) {
        $result.oneDriveStatus.isRunning = $true
    }
    
    # Try ODSyncUtil first for newer Windows
    $odSyncUtilPath = "C:\ProgramData\OneDriveRemediation\ODSyncUtil.exe"
    $odSyncScriptPath = "C:\ProgramData\OneDriveRemediation\Get-ODStatus.ps1"
    
    if ($buildNumber -ge 19041 -and (Test-Path $odSyncUtilPath) -and (Test-Path $odSyncScriptPath)) {
        try {
            Add-Content -Path $logPath -Value "$timestamp [INFO] Using ODSyncUtil method (recommended for build $buildNumber)" -Force
            $result.collectionMethod = "ODSyncUtil"
            
            # Run ODSyncUtil
            & $odSyncScriptPath -ExePath $odSyncUtilPath | ForEach-Object {
                if ($_.CurrentStateString) {
                    $result.oneDriveStatus.currentStateString = $_.CurrentStateString
                }
                
                $folderInfo = @{
                    localPath = $_.FolderPath
                    statusString = $_.CurrentStateString
                    displayName = $_.Label
                    serviceType = $_.ServiceName
                    userName = $_.UserName
                    quotaInfo = @{
                        isAvailable = $_.isQuotaAvailable
                        total = $_.TotalQuota
                        used = $_.UsedQuota
                        label = $_.QuotaLabel
                    }
                }
                $result.oneDriveStatus.syncFolders += $folderInfo
            }
            
            Add-Content -Path $logPath -Value "$timestamp [SUCCESS] ODSyncUtil data collected" -Force
        }
        catch {
            Add-Content -Path $logPath -Value "$timestamp [WARN] ODSyncUtil failed, falling back to OneDriveLib: $_" -Force
            $result.errors += "ODSyncUtil failed: $_"
        }
    }
    
    # Fall back to OneDriveLib.dll if ODSyncUtil didn't work
    if ($result.oneDriveStatus.currentStateString -eq "Unknown") {
        $dllPath = "C:\ProgramData\OneDriveRemediation\OneDriveLib.dll"
        
        if (Test-Path $dllPath) {
            try {
                Add-Content -Path $logPath -Value "$timestamp [INFO] Using OneDriveLib.dll method" -Force
                $result.collectionMethod = "OneDriveLib"
                
                Unblock-File $dllPath -ErrorAction SilentlyContinue
                Import-Module $dllPath -Force
                
                # Try regular status
                $status = $null
                try {
                    $status = Get-ODStatus -Verbose
                }
                catch {
                    # Try OnDemandOnly if regular fails
                    $status = Get-ODStatus -OnDemandOnly
                }
                
                if ($status) {
                    # Handle array or single result
                    if ($status -is [Array]) {
                        foreach ($instance in $status) {
                            if ($instance.StatusString) {
                                $result.oneDriveStatus.currentStateString = $instance.StatusString
                            }
                            
                            $folderInfo = @{
                                localPath = $instance.LocalPath
                                statusString = $instance.StatusString
                                displayName = $instance.DisplayName
                                serviceType = $instance.ServiceType
                                userName = $instance.UserName
                            }
                            $result.oneDriveStatus.syncFolders += $folderInfo
                        }
                    }
                    elseif ($status.StatusString) {
                        $result.oneDriveStatus.currentStateString = $status.StatusString
                    }
                    
                    Add-Content -Path $logPath -Value "$timestamp [SUCCESS] OneDriveLib data collected" -Force
                }
            }
            catch {
                $errorMsg = "OneDriveLib.dll failed: $_"
                Add-Content -Path $logPath -Value "$timestamp [ERROR] $errorMsg" -Force
                $result.errors += $errorMsg
            }
        }
    }
    
    # Calculate duration
    $result.collectionDuration = ((Get-Date) - [DateTime]::ParseExact($result.timestamp, 'yyyy-MM-ddTHH:mm:ssZ', $null)).ToString("c")
    
    # Write status file
    $statusFilePath = Join-Path $LogFolder $StatusFileName
    $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $statusFilePath -Encoding UTF8 -Force
    
    Add-Content -Path $logPath -Value "$timestamp [SUCCESS] Status file written to: $statusFilePath" -Force
    
    Write-Host "OneDrive status collection completed successfully"
    Write-Host "Method: $($result.collectionMethod)"
    Write-Host "Status: $($result.oneDriveStatus.currentStateString)"
    Write-Host "File: $statusFilePath"
}
catch {
    $errorMsg = "Critical error: $($_.Exception.Message)"
    Add-Content -Path $logPath -Value "$timestamp [ERROR] $errorMsg" -Force
    
    # Write error result
    $errorResult = @{
        timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        username = "$env:COMPUTERNAME\$env:USERNAME"
        errors = @($errorMsg)
        collectionMethod = "Error"
    }
    
    $statusFilePath = Join-Path $LogFolder $StatusFileName
    $errorResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $statusFilePath -Encoding UTF8 -Force
    
    Write-Host "ERROR: $errorMsg" -ForegroundColor Red
    exit 1
}