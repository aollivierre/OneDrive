# Test for Unicode in our scripts
$scriptFiles = @(
    "C:\code\OneDrive\Scripts\Detect-OneDriveConfiguration.ps1",
    "C:\code\OneDrive\Scripts\Remediate-OneDriveConfiguration.ps1",
    "C:\code\OneDrive\Scripts\Invoke-OneDriveDetectionRemediation.ps1",
    "C:\code\OneDrive\Scripts\Invoke-OneDriveDetectionRemediationV2.ps1",
    "C:\code\OneDrive\Scripts\Test-OneDriveScripts.ps1"
)

$hasUnicode = $false

foreach ($file in $scriptFiles) {
    if (Test-Path $file) {
        Write-Host "`nChecking: $(Split-Path $file -Leaf)" -ForegroundColor Cyan
        $content = Get-Content -Path $file -Raw
        
        # Check each character
        for ($i = 0; $i -lt $content.Length; $i++) {
            $charCode = [int]$content[$i]
            if ($charCode -gt 127) {
                $hasUnicode = $true
                $lineNumber = ($content.Substring(0, $i) -split "`n").Count
                Write-Host "Found Unicode at line $lineNumber`: Character code $charCode" -ForegroundColor Red
            }
        }
    }
}

if (-not $hasUnicode) {
    Write-Host "`nNo Unicode characters found in any scripts!" -ForegroundColor Green
}
else {
    Write-Host "`nUnicode characters need to be removed!" -ForegroundColor Red
}