#Requires -Version 5.1

<#
.SYNOPSIS
    OneDrive validation using DMU-style scheduled task approach
.DESCRIPTION
    Runs OneDrive validation from SYSTEM context using proven DMU pattern:
    1. Creates scheduled task in user context
    2. Task collects OneDrive status via OneDriveLib.dll
    3. Reads status file and performs validation
    Based on successful Device Migration Utility architecture.
#>

param(
    [string]$LogFile = "$env:TEMP\OneDrive-Validation-DMU-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Initialize logging
function Write-Log {
    param($Message, $Level = "INFO")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage -Force
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message }
    }
}

Write-Log "Starting OneDrive validation using DMU pattern" "INFO"
Write-Log "Running as: $env:USERNAME" "INFO"
Write-Log "Is SYSTEM: $([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)" "INFO"

try {
    # Step 1: Find logged-in user (DMU pattern - explorer.exe owner)
    Write-Log "Detecting logged-in user..." "INFO"
    
    $loggedInUser = $null
    $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
    
    if ($explorerProcesses) {
        $userProcess = $explorerProcesses[0]
        try {
            $owner = (Get-WmiObject Win32_Process -Filter "ProcessId = $($userProcess.Id)").GetOwner()
            if ($owner.User) {
                $loggedInUser = $owner.User
                Write-Log "Found logged-in user: $($owner.Domain)\$loggedInUser" "SUCCESS"
            }
        }
        catch {
            Write-Log "Could not determine logged-in user: $($_.Exception.Message)" "ERROR"
            throw "No logged-in user found"
        }
    } else {
        throw "No explorer.exe process found - no user logged in"
    }
    
    # Step 2: Create scheduled task (DMU pattern)
    Write-Log "Creating user context scheduled task..." "INFO"
    
    $taskName = "OneDriveValidation_" + (Get-Random)
    # Use adaptive collector for Windows 10/11 compatibility
    $scriptPath = "C:\code\OneDrive\Scripts\Collect-OneDriveStatus-Adaptive.ps1"
    
    # Verify collector script exists
    if (-not (Test-Path $scriptPath)) {
        throw "User context collector script not found: $scriptPath"
    }
    
    # Create task action
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    
    # Create task trigger (immediate execution)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    
    # Create task principal (DMU pattern - run as logged-in user)
    $principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$loggedInUser" -LogonType Interactive
    
    # Register task
    try {
        $task = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "OneDrive status collection for validation"
        Write-Log "Scheduled task created: $taskName" "SUCCESS"
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" "ERROR"
        throw "Task creation failed"
    }
    
    # Step 3: Start task and wait for completion
    Write-Log "Starting task and waiting for completion..." "INFO"
    
    try {
        Start-ScheduledTask -TaskName $taskName
        
        # Wait for task completion (DMU pattern - timeout mechanism)
        $maxWaitTime = 60 # seconds
        $waitInterval = 2 # seconds
        $waited = 0
        
        do {
            Start-Sleep -Seconds $waitInterval
            $waited += $waitInterval
            $taskInfo = Get-ScheduledTask -TaskName $taskName
            $taskState = $taskInfo.State
            
            Write-Log "Task state: $taskState (waited $waited seconds)" "INFO"
            
            if ($taskState -eq "Ready" -and $waited -gt 10) {
                # Task completed
                break
            }
            
        } while ($waited -lt $maxWaitTime)
        
        if ($waited -ge $maxWaitTime) {
            Write-Log "Task execution timed out after $maxWaitTime seconds" "WARNING"
        }
    }
    catch {
        Write-Log "Error during task execution: $($_.Exception.Message)" "ERROR"
    }
    
    # Step 4: Read status file (DMU pattern)
    Write-Log "Reading OneDrive status file..." "INFO"
    
    $statusFilePath = "C:\Users\$loggedInUser\logs\OneDriveStatus.json"
    $maxFileWait = 30 # seconds
    $fileWaited = 0
    
    # Wait for status file to be created
    while (-not (Test-Path $statusFilePath) -and $fileWaited -lt $maxFileWait) {
        Start-Sleep -Seconds 2
        $fileWaited += 2
        Write-Log "Waiting for status file... ($fileWaited seconds)" "INFO"
    }
    
    if (Test-Path $statusFilePath) {
        try {
            $statusContent = Get-Content -Path $statusFilePath -Raw
            $status = $statusContent | ConvertFrom-Json
            
            Write-Log "Status file read successfully" "SUCCESS"
            Write-Log "User: $($status.username)" "INFO"
            Write-Log "OneDrive Status: $($status.oneDriveStatus.currentStateString)" "INFO"
            Write-Log "OneDrive Running: $($status.oneDriveStatus.isRunning)" "INFO"
            Write-Log "Collection Duration: $($status.collectionDuration)" "INFO"
            
            if ($status.errors -and $status.errors.Count -gt 0) {
                Write-Log "Errors encountered during collection:" "WARNING"
                foreach ($error in $status.errors) {
                    Write-Log "  - $error" "WARNING"
                }
            }
            
            # Simple status categorization (DMU pattern)
            $healthyStates = @("Synced", "UpToDate", "Up To Date")
            $inProgressStates = @("Syncing", "SharedSync", "Shared Sync")
            $failedStates = @("Error", "ReadOnly", "Read Only", "OnDemandOrUnknown", "Paused")
            
            $currentState = $status.oneDriveStatus.currentStateString
            
            if ($currentState -in $healthyStates) {
                Write-Log "OneDrive Status: HEALTHY ($currentState)" "SUCCESS"
            }
            elseif ($currentState -in $inProgressStates) {
                Write-Log "OneDrive Status: IN PROGRESS ($currentState)" "WARNING"
            }
            elseif ($currentState -in $failedStates) {
                Write-Log "OneDrive Status: FAILED ($currentState)" "ERROR"
            }
            else {
                Write-Log "OneDrive Status: UNKNOWN ($currentState)" "WARNING"
            }
            
            # Show sync folders if available
            if ($status.oneDriveStatus.syncFolders -and $status.oneDriveStatus.syncFolders.Count -gt 0) {
                Write-Log "Sync Folders:" "INFO"
                foreach ($folder in $status.oneDriveStatus.syncFolders) {
                    Write-Log "  $($folder.localPath): $($folder.statusString)" "INFO"
                }
            }
        }
        catch {
            Write-Log "Failed to parse status file: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Status file not found after waiting $maxFileWait seconds" "ERROR"
    }
    
    # Step 5: Cleanup (DMU pattern)
    Write-Log "Cleaning up scheduled task..." "INFO"
    
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Scheduled task removed: $taskName" "SUCCESS"
    }
    catch {
        Write-Log "Failed to remove scheduled task: $($_.Exception.Message)" "WARNING"
    }
    
    Write-Log "OneDrive validation completed" "SUCCESS"
    Write-Log "Log file: $LogFile" "INFO"
}
catch {
    Write-Log "Critical error during OneDrive validation: $($_.Exception.Message)" "ERROR"
    
    # Cleanup on error
    if ($taskName) {
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        } catch { }
    }
    
    throw $_
}