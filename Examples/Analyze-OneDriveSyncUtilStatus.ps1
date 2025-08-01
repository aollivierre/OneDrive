function Analyze-OneDriveSyncUtilStatus {
    <#
    .SYNOPSIS
    Analyzes the OneDrive sync status from a JSON file.

    .DESCRIPTION
    The Analyze-OneDriveSyncUtilStatus function removes existing status files, finds the new status file, reads it, and categorizes the sync status as healthy, in progress, or failed based on predefined conditions.

    .PARAMETER LogFolder
    The path to the folder where the log files are stored. If running as SYSTEM, this will be ignored, and the function will analyze logs across all user profiles.

    .PARAMETER StatusFileName
    The name of the JSON file containing the OneDrive sync status.

    .PARAMETER MaxRetries
    The maximum number of retries to find the new status file.

    .PARAMETER RetryInterval
    The interval in seconds between retries.

    .EXAMPLE
    $result = Analyze-OneDriveSyncUtilStatus -LogFolder "C:\Users\YourUserProfile\Logs" -StatusFileName "ODSyncUtilStatus.json" -MaxRetries 5 -RetryInterval 10
    if ($result.Status -eq "Healthy") {
        # Do something if healthy
    }
    # Analyzes the OneDrive sync status from the specified JSON file and returns an object.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogFolder,

        [Parameter(Mandatory = $true)]
        [string]$StatusFileName,

        [Parameter(Mandatory = $true)]
        [int]$MaxRetries = 5,

        [Parameter(Mandatory = $true)]
        [int]$RetryInterval = 10
    )

    Begin {
        Write-EnhancedLog -Message "Starting Analyze-OneDriveSyncUtilStatus function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    Process {
        try {
            # # Step 1: Remove existing status files
            # Remove-ExistingStatusFiles -LogFolder $LogFolder -StatusFileName $StatusFileName

            # Step 2: Find the new status file
            # Define a hashtable for splatting
            $findStatusFileParams = @{
                LogFolder      = $LogFolder
                StatusFileName = $StatusFileName
                MaxRetries     = $MaxRetries
                RetryInterval  = $RetryInterval
            }

            # Use splatting to call the function
            $statusFile = Find-NewStatusFile @findStatusFileParams

            # Wait-Debugger

            # Step 3: Analyze the new status file
            Write-EnhancedLog -Message "Reading status file: $($statusFile.FullName)" -Level "INFO"
            $Status = Get-Content -Path $statusFile.FullName | ConvertFrom-Json

            # Define the status categories
            Write-EnhancedLog -Message "Defining status categories for analysis" -Level "INFO"
            $Success = @("Synced", "UpToDate", "Up To Date")
            $InProgress = @("Syncing", "SharedSync", "Shared Sync")
            $Failed = @("Error", "ReadOnly", "Read Only", "OnDemandOrUnknown", "On Demand or Unknown", "Paused")

            # Analyze the status and return an object
            Write-EnhancedLog -Message "Analyzing status from the JSON data" -Level "INFO"
            $StatusString = $Status.CurrentStateString
            $UserName = $Status.UserName
            $result = [PSCustomObject]@{
                UserName = $UserName
                Status   = $null
                Message  = $null
            }

            if ($StatusString -in $Success) {
                $result.Status = "Healthy"
                $result.Message = "OneDrive sync status is healthy"
                Write-EnhancedLog -Message "$($result.Message): User: $UserName, Status: $StatusString" -Level "INFO"
            }
            elseif ($StatusString -in $InProgress) {
                $result.Status = "InProgress"
                $result.Message = "OneDrive sync status is currently syncing"
                Write-EnhancedLog -Message "$($result.Message): User: $UserName, Status: $StatusString" -Level "WARNING"
            }
            elseif ($StatusString -in $Failed) {
                $result.Status = "Failed"
                $result.Message = "OneDrive sync status is in a known error state"
                Write-EnhancedLog -Message "$($result.Message): User: $UserName, Status: $StatusString" -Level "ERROR"
            }
            else {
                $result.Status = "Unknown"
                $result.Message = "Unable to determine OneDrive Sync Status"
                Write-EnhancedLog -Message "$($result.Message) for User: $UserName" -Level "WARNING"
            }

            return $result
        }
        catch {
            Write-EnhancedLog -Message "An error occurred in Analyze-OneDriveSyncUtilStatus function: $($_.Exception.Message)" -Level "ERROR"
            Write-EnhancedLog -Message "Please check if you are logged in to OneDrive and try again." -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    End {
        Write-EnhancedLog -Message "Exiting Analyze-OneDriveSyncUtilStatus function" -Level "Notice"
    }
}



# # Step 1: Remove existing status files
# Remove-ExistingStatusFiles -LogFolder "C:\Users\YourUserProfile\Logs" -StatusFileName "ODSyncUtilStatus.json"

# # Step 2: Find the new status file
# $statusFile = Find-NewStatusFile -LogFolder "C:\Users\YourUserProfile\Logs" -StatusFileName "ODSyncUtilStatus.json" -MaxRetries 5 -RetryInterval 10

# # Step 3: Analyze the new status file
# $result = Analyze-OneDriveSyncUtilStatus -StatusFile $statusFile

# # Check the result
# if ($result.Status -eq "Healthy") {
#     # Do something if healthy
# }
