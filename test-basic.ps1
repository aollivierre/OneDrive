# Basic test with a dummy tenant ID for initial validation
$testTenantID = "12345678-1234-1234-1234-123456789012"

Write-Host "Running basic OneDrive script tests..." -ForegroundColor Cyan
Write-Host "Using test tenant ID: $testTenantID" -ForegroundColor Yellow
Write-Host ""

# Test 1: Check if OneDrive is installed
Write-Host "Test 1: Checking OneDrive installation..." -ForegroundColor Green
$oneDrivePaths = @(
    "$env:PROGRAMFILES\Microsoft OneDrive\OneDrive.exe",
    "$env:PROGRAMFILES(x86)\Microsoft OneDrive\OneDrive.exe",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
)

$oneDriveFound = $false
foreach ($path in $oneDrivePaths) {
    if (Test-Path $path) {
        Write-Host "  OneDrive found at: $path" -ForegroundColor Green
        $oneDriveFound = $true
        break
    }
}

if (-not $oneDriveFound) {
    Write-Host "  OneDrive NOT found!" -ForegroundColor Red
}

# Test 2: Check if OneDrive is running
Write-Host "`nTest 2: Checking if OneDrive is running..." -ForegroundColor Green
$oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($oneDriveProcess) {
    Write-Host "  OneDrive is running (PID: $($oneDriveProcess.Id))" -ForegroundColor Green
}
else {
    Write-Host "  OneDrive is NOT running" -ForegroundColor Yellow
}

# Test 3: Check registry policies
Write-Host "`nTest 3: Checking OneDrive policies..." -ForegroundColor Green
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
if (Test-Path $policyPath) {
    Write-Host "  Policy path exists" -ForegroundColor Green
    $policies = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
    
    @("KFMSilentOptIn", "FilesOnDemandEnabled", "SilentAccountConfig") | ForEach-Object {
        $value = $policies.$_
        if ($null -ne $value) {
            Write-Host "  $_`: $value" -ForegroundColor Cyan
        }
        else {
            Write-Host "  $_`: Not Set" -ForegroundColor Gray
        }
    }
}
else {
    Write-Host "  Policy path does not exist" -ForegroundColor Yellow
}

# Test 4: Run detection script
Write-Host "`nTest 4: Running detection script..." -ForegroundColor Green
$detectionScript = "C:\code\OneDrive\Scripts\Detect-OneDriveConfiguration.ps1"
if (Test-Path $detectionScript) {
    $output = & powershell.exe -ExecutionPolicy Bypass -File $detectionScript -TenantID $testTenantID 2>&1
    $exitCode = $LASTEXITCODE
    
    Write-Host "  Exit Code: $exitCode" -ForegroundColor Cyan
    Write-Host "  Output:" -ForegroundColor Cyan
    $output | ForEach-Object { Write-Host "    $_" }
}
else {
    Write-Host "  Detection script not found!" -ForegroundColor Red
}

Write-Host "`nBasic tests completed!" -ForegroundColor Cyan