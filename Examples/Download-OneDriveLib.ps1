function Download-OneDriveLib {
    <#
    .SYNOPSIS
    Downloads the latest OneDriveLib.dll from the OneDrive Sync Util GitHub repository.

    .DESCRIPTION
    The Download-OneDriveLib function retrieves the latest release of OneDriveLib.dll from the GitHub repository of the OneDrive Sync Util and downloads it to the specified destination folder.

    .PARAMETER Destination
    The destination folder where OneDriveLib.dll will be stored.

    .PARAMETER ApiUrl
    The GitHub API URL to retrieve the latest release information.

    .PARAMETER FileName
    The name of the file to be downloaded (e.g., "OneDriveLib.dll").

    .PARAMETER MaxRetries
    The maximum number of retries for the download process.

    .EXAMPLE
    $params = @{
        Destination = "C:\YourPath\Files\OneDriveLib.dll"
        ApiUrl      = "https://api.github.com/repos/rodneyviana/ODSyncService/releases/latest"
        FileName    = "OneDriveLib.dll"
        MaxRetries  = 3
    }
    Download-OneDriveLib @params
    Downloads OneDriveLib.dll to the specified destination folder.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$ApiUrl,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )

    Begin {
        Write-EnhancedLog -Message "Starting Download-OneDriveLib function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    Process {
        try {
            # Get the latest release info from GitHub
            Write-EnhancedLog -Message "Retrieving latest release info from GitHub API: $ApiUrl" -Level "INFO"
            $releaseInfo = Invoke-RestMethod -Uri $ApiUrl

            # Find the download URL for the specified file
            $downloadUrl = $releaseInfo.assets | Where-Object { $_.name -eq $FileName } | Select-Object -ExpandProperty browser_download_url

            if (-not $downloadUrl) {
                $errorMessage = "No matching file found for $FileName"
                Write-EnhancedLog -Message $errorMessage -Level "Critical"
                throw $errorMessage
            }

            # Define the splatting parameters for the download
            $downloadParams = @{
                Source      = $downloadUrl
                Destination = $Destination
                MaxRetries  = $MaxRetries
            }

            Write-EnhancedLog -Message "Downloading $FileName from: $downloadUrl to: $Destination" -Level "INFO"
            Start-FileDownloadWithRetry @downloadParams
        }
        catch {
            Write-EnhancedLog -Message "An error occurred in Download-OneDriveLib function: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    End {
        Write-EnhancedLog -Message "Exiting Download-OneDriveLib function" -Level "Notice"
    }
}

# # Example usage
# $params = @{
#     Destination = "C:\YourPath\Files\OneDriveLib.dll"
#     ApiUrl      = "https://api.github.com/repos/rodneyviana/ODSyncService/releases/latest"
#     FileName    = "OneDriveLib.dll"
#     MaxRetries  = 3
# }
# Download-OneDriveLib @params
