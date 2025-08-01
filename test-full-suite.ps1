# Full test suite including SYSTEM context
$tenantID = "12345678-1234-1234-1234-123456789012"

Write-Host "=== Full OneDrive Script Test Suite ===" -ForegroundColor Cyan
Write-Host ""

# Add PSExec to PATH temporarily
$psexecDir = "C:\Users\Public\Desktop\Sysinternals"
if (Test-Path $psexecDir) {
    $env:PATH = "$psexecDir;$env:PATH"
    Write-Host "Added Sysinternals to PATH" -ForegroundColor Green
}

# Accept PSExec EULA
Write-Host "Accepting PSExec EULA..." -ForegroundColor Yellow
& psexec.exe -accepteula -nobanner 2>$null

# Run comprehensive tests with all options
Write-Host "`nRunning comprehensive tests with SYSTEM context and remediation..." -ForegroundColor Yellow
& powershell.exe -ExecutionPolicy Bypass -File "C:\code\OneDrive\Test-ComprehensiveOneDrive.ps1" `
    -TenantID $tenantID `
    -TestRemediation `
    -TestSystemContext

Write-Host "`nFull test suite completed!" -ForegroundColor Cyan