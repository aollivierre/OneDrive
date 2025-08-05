<#
.SYNOPSIS
    Tests OneDrive detection/remediation scripts as SYSTEM with interactive window
    
.DESCRIPTION
    Uses PSExec to run scripts as SYSTEM in a new PowerShell window
    that stays open so you can see the output directly and validate
    that user impersonation is working properly
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Detection', 'Remediation', 'V2Detection', 'Validation', 'DMU')]
    [string]$TestScript = 'Validation',
    
    [Parameter()]
    [string]$TenantID = "GetFromRegistry"
)

# Find PSExec
$psExecPath = $null
$psExecLocations = @(
    "C:\Users\Public\Desktop\Sysinternals\PsExec.exe",
    "C:\Tools\PSTools\PsExec.exe",
    "C:\Temp\PsExec.exe",
    "C:\Windows\System32\PsExec.exe"
)

foreach ($location in $psExecLocations) {
    if (Test-Path $location) {
        $psExecPath = $location
        break
    }
}

if (-not $psExecPath) {
    Write-Host "PSExec not found. Downloading..." -ForegroundColor Yellow
    $psExecPath = "C:\Temp\PsExec.exe"
    New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
    Invoke-WebRequest 'https://live.sysinternals.com/PsExec.exe' -OutFile $psExecPath
}

# Ensure C:\Temp exists
if (-not (Test-Path "C:\Temp")) {
    New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
    Write-Host "Created C:\Temp directory" -ForegroundColor Green
}

Write-Host "`n=== Testing OneDrive Scripts as SYSTEM (Interactive Window) ===" -ForegroundColor Cyan
Write-Host "This will open a new PowerShell window running as SYSTEM`n" -ForegroundColor Gray

# Select script to test
$scriptPath = switch ($TestScript) {
    'Detection' { "C:\code\OneDrive\Scripts\Detect-OneDriveConfiguration.ps1" }
    'Remediation' { "C:\code\OneDrive\Scripts\Remediate-OneDriveConfiguration.ps1" }
    'V2Detection' { "C:\code\OneDrive\Scripts\Invoke-OneDriveDetectionRemediationV2.ps1" }
    'Validation' { "C:\code\OneDrive\Scripts\Test-OneDriveValidation-Interactive.ps1" }
    'DMU' { "C:\code\OneDrive\Scripts\Test-OneDriveValidation-DMU-Style.ps1" }
}

Write-Host "Testing: $TestScript" -ForegroundColor Yellow
Write-Host "Script: $scriptPath" -ForegroundColor Yellow

# Get real tenant ID if needed
if ($TenantID -eq "GetFromRegistry") {
    $businessPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path $businessPath) {
        $tenantIdValue = Get-ItemProperty -Path $businessPath -Name "TenantId" -ErrorAction SilentlyContinue
        if ($tenantIdValue -and $tenantIdValue.TenantId) {
            $TenantID = $tenantIdValue.TenantId
            Write-Host "Detected Tenant ID: $TenantID" -ForegroundColor Green
        }
    }
}

# Create wrapper script that shows SYSTEM context clearly
$wrapperScript = @"
Write-Host '=== RUNNING AS SYSTEM ===' -ForegroundColor Green -BackgroundColor Black
Write-Host ''

# Show current context
`$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Current Security Context:" -ForegroundColor Yellow
Write-Host "  User: `$(`$currentUser.Name)" -ForegroundColor Cyan
Write-Host "  IsSystem: `$(`$currentUser.IsSystem)" -ForegroundColor Cyan
Write-Host "  Computer: `$env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ""

# Show environment variables
Write-Host "Environment Variables:" -ForegroundColor Yellow
Write-Host "  USERNAME: `$env:USERNAME" -ForegroundColor Cyan
Write-Host "  USERPROFILE: `$env:USERPROFILE" -ForegroundColor Cyan
Write-Host "  OneDrive: `$env:OneDrive" -ForegroundColor Cyan
Write-Host ""

# Check for logged-in users
Write-Host "Checking for logged-in users:" -ForegroundColor Yellow
`$explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
if (`$explorerProcesses) {
    foreach (`$proc in `$explorerProcesses) {
        try {
            `$owner = (Get-WmiObject Win32_Process -Filter "ProcessId = `$(`$proc.Id)").GetOwner()
            if (`$owner.User) {
                Write-Host "  Found explorer.exe for user: `$(`$owner.Domain)\`$(`$owner.User) (PID: `$(`$proc.Id))" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  Could not get owner for explorer.exe PID: `$(`$proc.Id)" -ForegroundColor Gray
        }
    }
}
else {
    Write-Host "  No explorer.exe processes found" -ForegroundColor Red
}

Write-Host "`n--- Running OneDrive Script ---`n" -ForegroundColor Yellow

# Run the selected script
try {
    if ('$TestScript' -eq 'V2Detection') {
        & '$scriptPath' -TenantID '$TenantID'
    }
    elseif ('$TestScript' -in @('Detection', 'Remediation')) {
        & '$scriptPath' -TenantID '$TenantID'
    }
    else {
        & '$scriptPath'
    }
}
catch {
    Write-Host "`nERROR: `$_" -ForegroundColor Red
}

Write-Host "`n`nScript completed. Press any key to close this window..." -ForegroundColor Yellow -BackgroundColor Black
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@

# Save wrapper script
$wrapperPath = "C:\Temp\OneDriveSystemTestWrapper.ps1"
$wrapperScript | Out-File -FilePath $wrapperPath -Encoding UTF8 -Force

# PSExec arguments for interactive SYSTEM execution
$psexecArgs = @(
    "-accepteula",      # Accept EULA silently
    "-s",               # Run as SYSTEM
    "-i",               # Interactive in current session (shows window)
    # Removed -d flag so window stays open
    "powershell.exe",   # Run PowerShell
    "-ExecutionPolicy", "Bypass",
    "-NoProfile",
    "-File", $wrapperPath
)

Write-Host "`nCurrent user: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Launching SYSTEM PowerShell window..." -ForegroundColor Green
Write-Host "Command: $psExecPath $($psexecArgs -join ' ')" -ForegroundColor Gray

# Execute as SYSTEM in new window
& $psExecPath @psexecArgs

Write-Host "`nA new PowerShell window should have opened running as SYSTEM." -ForegroundColor Green
Write-Host "Check that window for:" -ForegroundColor Yellow
Write-Host "  - Confirmation that it's running as NT AUTHORITY\SYSTEM" -ForegroundColor Cyan
Write-Host "  - Detection of logged-in users via explorer.exe" -ForegroundColor Cyan
Write-Host "  - OneDrive script output and any errors" -ForegroundColor Cyan
Write-Host "`nThe window will stay open until you press a key." -ForegroundColor Gray
Write-Host "(Without -d flag, this command will wait for the SYSTEM window to close)" -ForegroundColor Yellow