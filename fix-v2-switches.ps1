# Fix all boolean comparisons in V2 script for switch parameters
$scriptPath = "C:\code\OneDrive\Scripts\Invoke-OneDriveDetectionRemediationV2.ps1"
$content = Get-Content -Path $scriptPath -Raw

# Fix all references to switch parameters (no longer need .IsPresent)
$replacements = @(
    @{
        Old = 'if (!$IncludeDownloadsFolder)'
        New = 'if (-not $IncludeDownloadsFolder)'
    },
    @{
        Old = 'if (!$CreateVBSWrapper)'
        New = 'if (-not $CreateVBSWrapper)'
    },
    @{
        Old = '$IncludeDownloadsFolder -and'
        New = '$IncludeDownloadsFolder.IsPresent -and'
    }
)

foreach ($replacement in $replacements) {
    $content = $content -replace [regex]::Escape($replacement.Old), $replacement.New
}

# Save the fixed content
$content | Set-Content -Path $scriptPath -Force

Write-Host "Fixed switch parameter references in V2 script" -ForegroundColor Green