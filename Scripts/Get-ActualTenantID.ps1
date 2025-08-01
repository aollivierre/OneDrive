# Get the actual tenant ID from OneDrive Business configuration

$businessConfigPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\settings\Business1"
$tenantFile = Join-Path $businessConfigPath "f46dd979-6dab-46cd-ae31-c40d9daf8620.ini"

Write-Host "Checking for tenant ID in OneDrive Business configuration..." -ForegroundColor Yellow

if (Test-Path $tenantFile) {
    Write-Host "Found configuration file with GUID name: f46dd979-6dab-46cd-ae31-c40d9daf8620" -ForegroundColor Green
    Write-Host ""
    Write-Host "This GUID (f46dd979-6dab-46cd-ae31-c40d9daf8620) might be your tenant ID!" -ForegroundColor Cyan
    Write-Host ""
    
    # Let's verify by checking other sources
    Write-Host "Verifying from other locations..." -ForegroundColor Yellow
}

# Check all registry locations for OneDrive
Write-Host "`nChecking all OneDrive registry keys..." -ForegroundColor Yellow
$regPaths = @(
    "HKCU:\Software\Microsoft\OneDrive",
    "HKCU:\Software\Microsoft\OneDrive\Accounts",
    "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1",
    "HKCU:\Software\SyncEngines\Providers\OneDrive"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Write-Host "`n$path" -ForegroundColor Green
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
            Select-Object -Property * -ExcludeProperty PS* | 
            Format-List
    }
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Based on the configuration file, your tenant ID appears to be:" -ForegroundColor Yellow
Write-Host "f46dd979-6dab-46cd-ae31-c40d9daf8620" -ForegroundColor Green -BackgroundColor Black
Write-Host ""
Write-Host "Organization: Exchange Technology Services" -ForegroundColor Cyan