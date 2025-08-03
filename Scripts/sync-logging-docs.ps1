Copy-Item "C:\code\Win11UpgradeScheduler\Win11Detection\src\logging\*" -Destination "C:\code\OneDrive\Scripts\logging\" -Force
Write-Host "All documentation synced!" -ForegroundColor Green
Write-Host ""
Write-Host "Files updated:" -ForegroundColor Yellow
Write-Host "- logging.psm1 (enhanced module-level docs)"
Write-Host "- logging.psd1 (updated description)"  
Write-Host "- UNIVERSAL-USAGE.md (new comprehensive guide)"