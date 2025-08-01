# Function to download OneDrive setup with retry logic
function Download-OneDriveSetup {
    <#
    .SYNOPSIS
        Downloads the OneDrive setup executable.

    .DESCRIPTION
        Downloads the OneDrive setup executable from the specified URL to the given destination path.
        Uses the Start-FileDownloadWithRetry function for robust download handling with retries.

    .PARAMETER ODSetupUri
        The URL of the OneDrive setup executable.

    .PARAMETER ODSetupPath
        The file path where the OneDrive setup executable will be saved.

    .EXAMPLE
        Download-OneDriveSetup -ODSetupUri "https://go.microsoft.com/fwlink/?linkid=844652" -ODSetupPath "C:\Temp\OneDriveSetup.exe"

    .NOTES
        Author: Abdullah Ollivierre
        Date: 2024-08-15
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ODSetupUri,

        [Parameter(Mandatory = $true)]
        [string]$ODSetupPath
    )

    Begin {
        Write-EnhancedLog -Message "Starting Download-OneDriveSetup function" -Level "NOTICE"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    Process {
        Write-EnhancedLog -Message "Starting Start-FileDownloadWithRetry function" -Level "NOTICE"
        Start-FileDownloadWithRetry -Source $ODSetupUri -Destination $ODSetupPath -MaxRetries 3
        Write-EnhancedLog -Message "Downloaded OneDrive setup to $ODSetupPath" -Level "INFO"
    }

    End {
        Write-EnhancedLog -Message "Exiting Download-OneDriveSetup function" -Level "NOTICE"
    }
}
# Function to install OneDrive