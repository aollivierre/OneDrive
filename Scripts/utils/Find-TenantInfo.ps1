# Try to find tenant information from various sources

Write-Host "=== Searching for Tenant Information ===" -ForegroundColor Cyan

# 1. Check OneDrive config files
Write-Host "`nChecking OneDrive config files..." -ForegroundColor Yellow
$configPaths = @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive\settings\Business1",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\settings\Personal"
)

foreach ($path in $configPaths) {
    if (Test-Path $path) {
        Write-Host "  Found config: $path" -ForegroundColor Green
        
        # Check for .ini files
        $iniFiles = Get-ChildItem -Path $path -Filter "*.ini" -ErrorAction SilentlyContinue
        foreach ($ini in $iniFiles) {
            Write-Host "    Reading: $($ini.Name)" -ForegroundColor Gray
            $content = Get-Content $ini.FullName -ErrorAction SilentlyContinue
            $tenantLine = $content | Where-Object { $_ -like "*tenantId*" -or $_ -like "*tenant*" }
            if ($tenantLine) {
                Write-Host "      Found: $tenantLine" -ForegroundColor Cyan
            }
        }
        
        # Check for .dat files
        $datFiles = Get-ChildItem -Path $path -Filter "*.dat" -ErrorAction SilentlyContinue
        foreach ($dat in $datFiles) {
            if ($dat.Name -like "*tenant*") {
                Write-Host "    Found tenant file: $($dat.Name)" -ForegroundColor Cyan
            }
        }
    }
}

# 2. Check from OneDrive folder name
Write-Host "`nChecking OneDrive folder names..." -ForegroundColor Yellow
$userProfile = $env:USERPROFILE
$oneDriveFolders = Get-ChildItem -Path $userProfile -Directory -Filter "OneDrive*" -ErrorAction SilentlyContinue

foreach ($folder in $oneDriveFolders) {
    Write-Host "  OneDrive folder: $($folder.Name)" -ForegroundColor Green
    if ($folder.Name -match "OneDrive - (.+)") {
        $orgName = $matches[1]
        Write-Host "    Organization: $orgName" -ForegroundColor Cyan
    }
}

# 3. Check environment variables
Write-Host "`nChecking environment variables..." -ForegroundColor Yellow
$envVars = Get-ChildItem env: | Where-Object { $_.Name -like "*OneDrive*" -or $_.Name -like "*Office*" }
foreach ($var in $envVars) {
    Write-Host "  $($var.Name) = $($var.Value)" -ForegroundColor Gray
}

# 4. Check Office/Azure registry
Write-Host "`nChecking Office/Azure registry..." -ForegroundColor Yellow
$officePaths = @(
    "HKCU:\Software\Microsoft\Office\16.0\Common\Identity",
    "HKCU:\Software\Microsoft\Office\15.0\Common\Identity",
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC"
)

foreach ($path in $officePaths) {
    if (Test-Path $path) {
        Write-Host "  Found: $path" -ForegroundColor Green
        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($props.ADUserName) {
            Write-Host "    User: $($props.ADUserName)" -ForegroundColor Cyan
        }
    }
}

# 5. Check Windows credentials
Write-Host "`nChecking for stored credentials..." -ForegroundColor Yellow
try {
    $creds = cmdkey /list | Select-String "OneDrive" -Context 0,1
    if ($creds) {
        Write-Host "  Found OneDrive credentials:" -ForegroundColor Green
        $creds | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    }
}
catch {
    Write-Host "  Could not check credentials" -ForegroundColor Gray
}

Write-Host "`nNote: If you can't find the tenant ID, you need to:" -ForegroundColor Yellow
Write-Host "  1. Sign into OneDrive for Business first" -ForegroundColor Cyan
Write-Host "  2. Or get the tenant ID from your Azure AD admin" -ForegroundColor Cyan
Write-Host "  3. Or check in Office 365 admin center" -ForegroundColor Cyan