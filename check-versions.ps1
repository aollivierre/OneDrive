# Check if -Production versions have embedded logging
$files = @(
    "Detect-OneDriveConfiguration-RMM.ps1",
    "Detect-OneDriveConfiguration-RMM-Production.ps1",
    "Remediate-OneDriveConfiguration-RMM.ps1", 
    "Remediate-OneDriveConfiguration-RMM-Production.ps1"
)

foreach ($file in $files) {
    $path = "C:\code\OneDrive\Scripts\$file"
    if (Test-Path $path) {
        $content = Get-Content $path -Raw
        $hasModule = $content -match "Import-Module.*logging"
        $hasEmbedded = $content -match "function Write-(Detection|Remediation)Log" -and -not $hasModule
        
        Write-Host ""
        Write-Host "$($file):"
        Write-Host "  - Imports logging module: $hasModule"
        Write-Host "  - Has embedded logging: $hasEmbedded"
    }
}