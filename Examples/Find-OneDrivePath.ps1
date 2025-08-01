function Find-OneDrivePath {
    <#
    .SYNOPSIS
    Finds the path to the OneDrive executable in common installation directories.
  
    .DESCRIPTION
    The Find-OneDrivePath function searches for the OneDrive executable in various common installation directories and returns the path if found.
  
    .EXAMPLE
    $oneDrivePath = Find-OneDrivePath
    #>

    [CmdletBinding()]
    param ()

    Begin {
        Write-EnhancedLog -Message "Starting Find-OneDrivePath function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    Process {
        try {
            $possiblePaths = @(
                "C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe",
                "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
                "$env:LOCALAPPDATA\Microsoft\OneDrive\Update\OneDriveSetup.exe",
                "C:\Users\$env:USERNAME\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
            )

            foreach ($path in $possiblePaths) {
                if (Test-Path -Path $path) {
                    Write-EnhancedLog -Message "Found OneDrive at: $path" -Level "INFO"
                    return $path
                }
            }

            Write-EnhancedLog -Message "OneDrive executable not found in common directories." -Level "WARNING"
            return $null
        }
        catch {
            Write-EnhancedLog -Message "An error occurred in Find-OneDrivePath function: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    End {
        Write-EnhancedLog -Message "Exiting Find-OneDrivePath function" -Level "Notice"
    }
}

# Example usage
# $oneDrivePath = Find-OneDrivePath
