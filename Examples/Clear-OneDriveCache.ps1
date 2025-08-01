function Clear-OneDriveCache {
    <#
    .SYNOPSIS
    Clears the OneDrive cache.
  
    .DESCRIPTION
    The Clear-OneDriveCache function clears the OneDrive cache by restarting the OneDrive process.
  
    .EXAMPLE
    Clear-OneDriveCache
    Clears the OneDrive cache by restarting the OneDrive process.
    #>
  
    [CmdletBinding()]
    param ()
  
    Begin {
        Write-EnhancedLog -Message "Starting Clear-OneDriveCache function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }
  
    Process {
        try {
            Write-EnhancedLog -Message "Searching for OneDrive executable path" -Level "INFO"
            $oneDrivePath = Find-OneDrivePath

            if ($oneDrivePath) {
                Write-EnhancedLog -Message "Restarting OneDrive process to clear cache" -Level "INFO"
                Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                Start-Process -FilePath $oneDrivePath -ErrorAction Stop
                Write-EnhancedLog -Message "Successfully restarted OneDrive process" -Level "INFO"
            }
            else {
                Write-EnhancedLog -Message "OneDrive executable not found in any known locations" -Level "WARNING"
            }
        }
        catch {
            Write-EnhancedLog -Message "An error occurred in Clear-OneDriveCache function: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }
  
    End {
        Write-EnhancedLog -Message "Exiting Clear-OneDriveCache function" -Level "Notice"
    }
}

# Example usage
# Clear-OneDriveCache
