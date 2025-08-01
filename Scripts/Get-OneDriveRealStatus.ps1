# Get REAL OneDrive status - no user interaction, just facts

Write-Host "=== REAL OneDrive Status Check ===" -ForegroundColor Red
Write-Host ""

# 1. Get actual tenant ID
Write-Host "TENANT ID:" -ForegroundColor Yellow
$tenantId = $null

# Check Business1 account
$businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
if (Test-Path $businessPath) {
    $props = Get-ItemProperty -Path $businessPath
    if ($props.TenantId) {
        $tenantId = $props.TenantId
        Write-Host "  Real Tenant ID: $tenantId" -ForegroundColor Green
        Write-Host "  Display Name: $($props.DisplayName)" -ForegroundColor Cyan
        Write-Host "  User Email: $($props.UserEmail)" -ForegroundColor Cyan
        Write-Host "  User Folder: $($props.UserFolder)" -ForegroundColor Cyan
    }
}

# Check what's in the policy
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$kfmValue = $null
if (Test-Path $policyPath) {
    $kfmValue = (Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue).KFMSilentOptIn
    Write-Host "  Policy Tenant ID: $kfmValue" -ForegroundColor $(if ($kfmValue -eq $tenantId) { 'Green' } else { 'Red' })
    
    if ($kfmValue -eq "12345678-1234-1234-1234-123456789012") {
        Write-Host "  WARNING: Using dummy tenant ID - KFM WILL NOT WORK!" -ForegroundColor Red -BackgroundColor Yellow
    }
}
else {
    Write-Host "  No policy path found" -ForegroundColor Red
}

# 2. Check actual folder locations
Write-Host "`nFOLDER LOCATIONS:" -ForegroundColor Yellow
$shellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$oneDrivePath = $env:OneDrive

$folders = @(
    @{Name="Desktop"; RegName="Desktop"},
    @{Name="Documents"; RegName="Personal"},
    @{Name="Pictures"; RegName="My Pictures"},
    @{Name="Downloads"; RegName="{374DE290-123F-4565-9164-39C4925E467B}"}
)

$redirectedCount = 0
foreach ($folder in $folders) {
    $path = (Get-ItemProperty -Path $shellFolders -Name $folder.RegName -ErrorAction SilentlyContinue).($folder.RegName)
    if ($path) {
        $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
        $isInOneDrive = $oneDrivePath -and ($expandedPath -like "*$oneDrivePath*")
        
        if ($isInOneDrive) {
            Write-Host "  $($folder.Name): IN OneDrive - $expandedPath" -ForegroundColor Green
            $redirectedCount++
        }
        else {
            Write-Host "  $($folder.Name): NOT in OneDrive - $expandedPath" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  $($folder.Name): No registry entry" -ForegroundColor Red
    }
}

Write-Host "`nSUMMARY: $redirectedCount of 4 folders are in OneDrive" -ForegroundColor $(if ($redirectedCount -eq 4) { 'Green' } else { 'Red' })

# 3. OneDrive process
Write-Host "`nONEDRIVE PROCESS:" -ForegroundColor Yellow
$process = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "  Running (PID: $($process.Id))" -ForegroundColor Green
}
else {
    Write-Host "  NOT RUNNING!" -ForegroundColor Red
}

# 4. Final verdict
Write-Host "`n=== VERDICT ===" -ForegroundColor Yellow

# If no tenant ID from registry, use the one from policy
if (-not $tenantId -and $kfmValue) {
    $tenantId = $kfmValue
}

if ($tenantId -and ($kfmValue -eq $tenantId) -and ($redirectedCount -ge 3)) {
    Write-Host "KFM is properly configured and working" -ForegroundColor Green
}
else {
    Write-Host "KFM configuration status:" -ForegroundColor Yellow
    Write-Host ""
    if (-not $tenantId) {
        Write-Host "  - No tenant ID detected in OneDrive account" -ForegroundColor Yellow
    }
    if ($kfmValue -and $tenantId -and ($kfmValue -ne $tenantId)) {
        Write-Host "  - Policy tenant ID doesn't match account tenant ID" -ForegroundColor Red
    }
    elseif ($kfmValue) {
        Write-Host "  - Policy tenant ID is configured: $kfmValue" -ForegroundColor Green
    }
    if ($redirectedCount -ge 3) {
        Write-Host "  - Folders ARE redirected: $redirectedCount of 4" -ForegroundColor Green
    }
    else {
        Write-Host "  - Only $redirectedCount folders redirected (need at least 3)" -ForegroundColor Red
    }
}

# NO USER INTERACTION - Script ends here