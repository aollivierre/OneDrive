# Search for scripts with full embedded logging
$searchPath = "C:\code\OneDrive"
$loggingFunctions = @(
    "function Initialize-Logging",
    "function Write-AppDeploymentLog",
    "function Start-UniversalTranscript"
)

Write-Host "Searching for scripts with embedded logging functions..." -ForegroundColor Cyan
Write-Host ""

Get-ChildItem -Path $searchPath -Filter "*.ps1" -Recurse | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    $hasEmbedded = $true
    
    foreach ($func in $loggingFunctions) {
        if ($content -notmatch [regex]::Escape($func)) {
            $hasEmbedded = $false
            break
        }
    }
    
    if ($hasEmbedded) {
        Write-Host "Found script with embedded logging: $($_.FullName)" -ForegroundColor Green
        $lineCount = (Get-Content $_.FullName).Count
        Write-Host "  Line count: $lineCount" -ForegroundColor Yellow
    }
}

Write-Host "`nChecking specific scripts in Archive and src:" -ForegroundColor Cyan
$checkScripts = @(
    "C:\code\OneDrive\Scripts\Archive\Detect-OneDriveConfiguration-RMM-Production.ps1",
    "C:\code\OneDrive\Scripts\Archive\Remediate-OneDriveConfiguration-RMM-Production.ps1",
    "C:\code\OneDrive\Scripts\src\Detect-OneDriveConfiguration-RMM.ps1",
    "C:\code\OneDrive\Scripts\src\Remediate-OneDriveConfiguration-RMM.ps1"
)

foreach ($script in $checkScripts) {
    if (Test-Path $script) {
        $content = Get-Content $script -Raw
        $hasImport = $content -match "Import-Module.*logging"
        $hasWrapperFunctions = $content -match "function Write-(Detection|Remediation)Log"
        
        Write-Host "`n$($script | Split-Path -Leaf):" -ForegroundColor Yellow
        Write-Host "  Has Import-Module: $hasImport"
        Write-Host "  Has wrapper functions: $hasWrapperFunctions"
    }
}