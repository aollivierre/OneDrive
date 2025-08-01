# Check if PSExec is available
$psexecPath = Get-Command psexec.exe -ErrorAction SilentlyContinue

if ($psexecPath) {
    Write-Host "PSExec found at: $($psexecPath.Source)" -ForegroundColor Green
    Write-Host "Version:" -ForegroundColor Cyan
    & psexec.exe -version 2>&1 | ForEach-Object { Write-Host "  $_" }
}
else {
    Write-Host "PSExec not found in PATH" -ForegroundColor Yellow
    Write-Host "Checking common locations..." -ForegroundColor Cyan
    
    $commonPaths = @(
        "C:\Tools\PSTools\psexec.exe",
        "C:\PSTools\psexec.exe",
        "C:\Windows\System32\psexec.exe",
        "C:\Temp\psexec.exe"
    )
    
    $found = $false
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-Host "Found at: $path" -ForegroundColor Green
            $found = $true
            break
        }
    }
    
    if (-not $found) {
        Write-Host "PSExec not found. You can download it from:" -ForegroundColor Yellow
        Write-Host "https://docs.microsoft.com/en-us/sysinternals/downloads/psexec" -ForegroundColor Cyan
    }
}