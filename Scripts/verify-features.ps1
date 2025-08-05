# Verification script for key features
$features = @(
    "DisablePersonalSync",
    "SkipAutoDetection", 
    "ConfigurationOnly",
    "ExpectedTenantId",
    "StorageSense",
    "dsregcmd",
    "KFMSilentOptInDownloads"
)

foreach ($feature in $features) {
    Write-Host "`nChecking for feature: $feature" -ForegroundColor Cyan
    $results = Select-String -Path "C:\code\OneDrive\Scripts\src\*Production*.ps1", "C:\code\OneDrive\Scripts\dev\*Dev*.ps1" -Pattern $feature | 
        Select-Object Path -Unique | 
        ForEach-Object { Split-Path $_.Path -Leaf }
    
    if ($results) {
        $results | ForEach-Object { Write-Host "  [OK] $_" -ForegroundColor Green }
    } else {
        Write-Host "  [X] NOT FOUND!" -ForegroundColor Red
    }
}