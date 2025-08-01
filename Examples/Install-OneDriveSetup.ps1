function Install-OneDriveSetup {
    param (
        [string]$ODSetupPath,
        [string]$SetupArgumentList
    )
    
    Write-Log "Installing OneDrive setup from $ODSetupPath..." -Level "INFO"
    $startProcessParams = @{
        FilePath     = $ODSetupPath
        ArgumentList = $SetupArgumentList
        Wait         = $true
        NoNewWindow  = $true
    }
    
    try {
        Start-Process @startProcessParams
        Write-Log "OneDrive installation completed." -Level "INFO"
    }
    catch {
        Write-Log "An error occurred during OneDrive installation: $($_.Exception.Message)" -Level "ERROR"
        throw $_
    }
}