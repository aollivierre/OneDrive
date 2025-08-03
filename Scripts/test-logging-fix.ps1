# Test script to verify logging module fix
Write-Host "Testing logging module line number fix..." -ForegroundColor Cyan
Write-Host "Running: Test-OneDriveRMM-AsSystem-StayOpen.ps1 -DetectionOnly" -ForegroundColor Yellow
Write-Host ""

# Run the test command
& 'C:\code\OneDrive\Scripts\Test-OneDriveRMM-AsSystem-StayOpen.ps1' -DetectionOnly

Write-Host ""
Write-Host "Test command completed. Check the SYSTEM window for output." -ForegroundColor Green
Write-Host "Look for line numbers in format: [Level] [ScriptName.FunctionName:LineNumber] - Message" -ForegroundColor Cyan