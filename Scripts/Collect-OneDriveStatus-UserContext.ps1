#Requires -Version 5.1

<#
.SYNOPSIS
    Collects OneDrive status in user context and writes to JSON file
.DESCRIPTION
    This script runs in user context to collect real OneDrive status using OneDriveLib.dll
    and writes structured results to JSON file for SYSTEM context to read.
    Based on DMU pattern for reliable SYSTEM-to-user communication.
#>

param(
    [string]$LogFolder = "$env:USERPROFILE\logs",
    [string]$StatusFileName = "OneDriveStatus.json"
)

# Initialize logging
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$logMessage = "$timestamp [INFO] Starting OneDrive status collection in user context"

# Ensure log directory exists
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

$logPath = Join-Path $LogFolder "OneDriveStatusCollection.log"
Add-Content -Path $logPath -Value $logMessage -Force

try {
    # Security check: Ensure we're NOT running as SYSTEM (DMU pattern)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.IsSystem) {
        throw "This script must NOT run as SYSTEM. Use scheduled task with user context."
    }
    
    # Allow elevated context if running as user (scheduled tasks may run elevated)
    # Only block if running as SYSTEM account
    
    Add-Content -Path $logPath -Value "$timestamp [INFO] Running as user: $($currentUser.Name)" -Force
    
    # Initialize result object
    $result = @{
        timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        username = "$env:COMPUTERNAME\$env:USERNAME"
        userSID = $currentUser.User.Value
        oneDriveStatus = @{
            currentStateString = "Unknown"
            isRunning = $false
            syncFolders = @()
        }
        errors = @()
        collectionDuration = ""
    }
    
    $startTime = Get-Date
    
    # Check if OneDrive is running
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($oneDriveProcess) {
        $result.oneDriveStatus.isRunning = $true
        Add-Content -Path $logPath -Value "$timestamp [INFO] OneDrive process found (PID: $($oneDriveProcess.Id))" -Force
    } else {
        $result.oneDriveStatus.isRunning = $false
        Add-Content -Path $logPath -Value "$timestamp [WARN] OneDrive process not found" -Force
    }
    
    # Try to load OneDriveLib.dll and get status (DMU pattern)
    $dllPath = "C:\ProgramData\OneDriveRemediation\OneDriveLib.dll"
    
    if (Test-Path $dllPath) {
        try {
            Add-Content -Path $logPath -Value "$timestamp [INFO] Loading OneDriveLib.dll from: $dllPath" -Force
            
            # Unblock and import module (DMU pattern)
            Unblock-File $dllPath -ErrorAction SilentlyContinue
            Import-Module $dllPath -Force
            
            # Get OneDrive status using DMU method
            # Try different methods based on documentation
            $status = $null
            
            # Method 1: Regular status check
            try {
                $status = Get-ODStatus -Verbose
                Add-Content -Path $logPath -Value "$timestamp [INFO] Get-ODStatus returned: $($status | ConvertTo-Json -Compress)" -Force
            }
            catch {
                Add-Content -Path $logPath -Value "$timestamp [WARN] Regular Get-ODStatus failed: $_" -Force
                
                # Method 2: Try OnDemandOnly if regular fails
                try {
                    $status = Get-ODStatus -OnDemandOnly
                    Add-Content -Path $logPath -Value "$timestamp [INFO] OnDemandOnly status returned: $($status | ConvertTo-Json -Compress)" -Force
                }
                catch {
                    Add-Content -Path $logPath -Value "$timestamp [ERROR] OnDemandOnly also failed: $_" -Force
                }
            }
            
            if ($status) {
                Add-Content -Path $logPath -Value "$timestamp [SUCCESS] OneDrive status retrieved via DLL" -Force
                
                # Parse status - Handle different output formats
                if ($status -is [Array]) {
                    # Multiple OneDrive instances
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
                elseif ($status) {
                    # Single instance or different format
                    if ($status.StatusString) {
                        $result.oneDriveStatus.currentStateString = $status.StatusString
                    }
                    elseif ($status -is [String]) {
                        # Direct status string
                        $result.oneDriveStatus.currentStateString = $status.ToString()
                    }
                }
            } else {
                Add-Content -Path $logPath -Value "$timestamp [WARN] No status returned from OneDriveLib.dll" -Force
                $result.errors += "No status returned from OneDriveLib.dll"
            }
        }
        catch {
            $errorMsg = "Failed to use OneDriveLib.dll: $($_.Exception.Message)"
            Add-Content -Path $logPath -Value "$timestamp [ERROR] $errorMsg" -Force
            $result.errors += $errorMsg
        }
    } else {
        $errorMsg = "OneDriveLib.dll not found at: $dllPath"
        Add-Content -Path $logPath -Value "$timestamp [ERROR] $errorMsg" -Force
        $result.errors += $errorMsg
    }
    
    # Calculate duration
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $result.collectionDuration = $duration.ToString("c")
    
    # Write status file (DMU pattern)
    $statusFilePath = Join-Path $LogFolder $StatusFileName
    $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $statusFilePath -Encoding UTF8 -Force
    
    Add-Content -Path $logPath -Value "$timestamp [SUCCESS] Status file written to: $statusFilePath" -Force
    Add-Content -Path $logPath -Value "$timestamp [INFO] Collection completed in: $($result.collectionDuration)" -Force
    
    Write-Host "OneDrive status collection completed successfully"
    Write-Host "Status: $($result.oneDriveStatus.currentStateString)"
    Write-Host "Running: $($result.oneDriveStatus.isRunning)"
    Write-Host "File: $statusFilePath"
}
catch {
    $errorMsg = "Critical error in OneDrive status collection: $($_.Exception.Message)"
    Add-Content -Path $logPath -Value "$timestamp [ERROR] $errorMsg" -Force
    
    # Still write a status file with error info
    $errorResult = @{
        timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        username = "$env:COMPUTERNAME\$env:USERNAME"
        errors = @($errorMsg)
        collectionDuration = "Error"
    }
    
    $statusFilePath = Join-Path $LogFolder $StatusFileName
    $errorResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $statusFilePath -Encoding UTF8 -Force
    
    Write-Host "ERROR: $errorMsg" -ForegroundColor Red
    exit 1
}