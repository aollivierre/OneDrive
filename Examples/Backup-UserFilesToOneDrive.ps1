function Backup-UserFilesToOneDrive {
    <#
    .SYNOPSIS
    Backs up user files to a specified OneDrive folder and logs the results.

    .DESCRIPTION
    The Backup-UserFilesToOneDrive function copies files from a specified source directory to a OneDrive backup directory. 
    It verifies the operation, logs the results, and saves the status to a JSON file. The function handles errors gracefully and appends the backup status to the JSON file.

    .PARAMETER SourcePath
    The path to the directory containing the files to be backed up.

    .PARAMETER BackupFolderName
    The name of the folder where the backup will be stored in the OneDrive directory.

    .PARAMETER Exclude
    A list of files or directories to exclude from the backup operation.

    .PARAMETER RetryCount
    The number of times to retry the backup operation if it fails.

    .PARAMETER WaitTime
    The time to wait between retry attempts, in seconds.

    .PARAMETER RequiredSpaceGB
    The amount of free space required at the destination in gigabytes.

    .PARAMETER OneDriveBackupPath
    The path to the OneDrive directory where the backup will be stored.

    .PARAMETER Scriptbasepath
    The base path of the script, used to determine where to store logs.

    .PARAMETER ClearPreviousStatus
    If set to $true, removes the existing JSON status file before starting the backup. Defaults to $false.

    .EXAMPLE
    Backup-UserFilesToOneDrive -SourcePath "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default" `
                               -BackupFolderName "ChromeBackup" `
                               -OneDriveBackupPath "$env:OneDrive\Backups" `
                               -Scriptbasepath "$PSScriptRoot" `
                               -ClearPreviousStatus $true

    This command backs up Chrome bookmarks to the OneDrive backup folder and removes the existing JSON status file before starting.

    .EXAMPLE
    Backup-UserFilesToOneDrive -SourcePath "$env:USERPROFILE\AppData\Roaming\Microsoft\Signatures" `
                               -BackupFolderName "OutlookSignatures" `
                               -OneDriveBackupPath "$env:OneDrive\Backups" `
                               -Scriptbasepath "$PSScriptRoot"

    This command backs up Outlook signatures to the OneDrive backup folder without clearing the existing JSON status file.

    .NOTES
    The function handles verification of the copy operation and appends the results to a JSON log file.

    .LINK
    https://docs.microsoft.com/en-us/powershell/scripting
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$BackupFolderName,
        [Parameter(Mandatory = $false)]
        [string[]]$Exclude,
        [Parameter(Mandatory = $false)]
        [int]$RetryCount = 2,
        [Parameter(Mandatory = $false)]
        [int]$WaitTime = 5,
        [Parameter(Mandatory = $false)]
        [int]$RequiredSpaceGB = 10,
        [Parameter(Mandatory = $true)]
        [string]$OneDriveBackupPath,
        [Parameter(Mandatory = $true)]
        [string]$Scriptbasepath
        # [Parameter(Mandatory = $false)]
        # [bool]$ClearPreviousStatus = $true
    )

    Begin {
        Write-EnhancedLog -Message "Starting Backup-UserFilesToOneDrive function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Define the log file path
        $logFolder = Join-Path -Path $env:USERPROFILE -ChildPath "logs"
        $statusFile = Join-Path -Path $logFolder -ChildPath "UserFilesBackupStatus.json"


        # Ensure the log directory exists
        if (-not (Test-Path -Path $logFolder)) {
            New-Item -Path $logFolder -ItemType Directory | Out-Null
        }

        # # Clear the existing JSON status file if specified
        # if ($ClearPreviousStatus -and (Test-Path -Path $statusFile)) {
        #     Remove-Item -Path $statusFile -Force
        #     Write-EnhancedLog -Message "Previous JSON status file removed: $statusFile" -Level "INFO"
        # }

        # Ensure the backup directory exists
        $backupPath = Join-Path -Path $OneDriveBackupPath -ChildPath $BackupFolderName
        if (-not (Test-Path -Path $backupPath)) {
            New-Item -Path $backupPath -ItemType Directory | Out-Null
        }
    }

    Process {
        try {
            # Perform the backup operation
            $CopyFilesWithRobocopyParams = @{
                Source          = $SourcePath
                Destination     = $backupPath
                Exclude         = $Exclude
                RetryCount      = $RetryCount
                WaitTime        = $WaitTime
                RequiredSpaceGB = $RequiredSpaceGB
            }
            
            Copy-FilesWithRobocopy @CopyFilesWithRobocopyParams

            # Verify the copy operation
            $verificationResults = Verify-CopyOperation -SourcePath $SourcePath -DestinationPath $backupPath

            # $DBG

            # Determine backup status based on verification results
            $backupStatus = if ($verificationResults.Count -eq 0) { "Success" } else { "Failed" }

            # Prepare the status entry
            $status = @{
                SourcePath          = $SourcePath
                BackupFolderName    = $BackupFolderName
                BackupPath          = $backupPath
                BackupStatus        = $backupStatus
                VerificationResults = if ($verificationResults.Count -eq 0) { @() } else { $verificationResults }
                Timestamp           = (Get-Date).ToString("o")
            }

            # Load existing JSON file content if it exists, ensuring it's treated as an array
            $existingStatus = @()
            if (Test-Path -Path $statusFile) {
                $existingStatus = Get-Content -Path $statusFile | ConvertFrom-Json
                if ($existingStatus -isnot [System.Collections.ArrayList] -and $existingStatus -is [PSCustomObject]) {
                    $existingStatus = @($existingStatus)
                }
            }

            # Append the new status entry
            $updatedStatus = $existingStatus + $status

            # Save the updated status to the JSON file
            $updatedStatus | ConvertTo-Json -Depth 5 | Out-File -FilePath $statusFile -Force -Encoding utf8

            Write-EnhancedLog -Message "Backup status has been saved to $statusFile" -Level "INFO"
        }
        catch {
            $status = @{
                SourcePath       = $SourcePath
                BackupFolderName = $BackupFolderName
                BackupPath       = $backupPath
                BackupStatus     = "Failed"
                ErrorMessage     = $_.Exception.Message
                Timestamp        = (Get-Date).ToString("o")
            }

            # Load existing JSON file content if it exists, ensuring it's treated as an array
            $existingStatus = @()
            if (Test-Path -Path $statusFile) {
                $existingStatus = Get-Content -Path $statusFile | ConvertFrom-Json
                if ($existingStatus -isnot [System.Collections.ArrayList] -and $existingStatus -is [PSCustomObject]) {
                    $existingStatus = @($existingStatus)
                }
            }

            # Append the new failure entry
            $updatedStatus = $existingStatus + $status

            # Save the updated status to the JSON file
            $updatedStatus | ConvertTo-Json -Depth 5 | Out-File -FilePath $statusFile -Force -Encoding utf8

            Write-EnhancedLog -Message "An error occurred during backup: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
        }
    }

    End {
        Write-EnhancedLog -Message "Exiting Backup-UserFilesToOneDrive function" -Level "Notice"
    }
}
