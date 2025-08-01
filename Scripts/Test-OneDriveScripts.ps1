#requires -Version 5.1
<#
.SYNOPSIS
    Test script for OneDrive detection and remediation scripts.

.DESCRIPTION
    This script helps test the OneDrive scripts in different contexts (user vs SYSTEM).

.PARAMETER TenantID
    Your Azure AD Tenant ID

.PARAMETER TestAsSystem
    Run tests simulating SYSTEM context

.EXAMPLE
    .\Test-OneDriveScripts.ps1 -TenantID "your-tenant-id"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    
    [switch]$TestAsSystem
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== OneDrive Scripts Test Suite ===" -ForegroundColor Cyan
Write-Host "Current user: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Is System: $([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)" -ForegroundColor Yellow
Write-Host ""

# Test 1: Run Detection Script
Write-Host "--- Running Detection Script ---" -ForegroundColor Green
$detectionScript = Join-Path $scriptPath "Detect-OneDriveConfiguration.ps1"

if ($TestAsSystem) {
    Write-Host "Creating scheduled task to run as SYSTEM..." -ForegroundColor Yellow
    $taskName = "OneDriveDetectionTest_$(Get-Random)"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$detectionScript`" -TenantID `"$TenantID`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
    Start-ScheduledTask -TaskName $taskName
    
    Start-Sleep -Seconds 5
    
    # Get task result
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
    Write-Host "Task Last Result: $($taskInfo.LastTaskResult)" -ForegroundColor Yellow
    
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
else {
    & $detectionScript -TenantID $TenantID
    Write-Host "Detection script exit code: $LASTEXITCODE" -ForegroundColor Yellow
}

Write-Host ""

# Test 2: Check Registry Settings
Write-Host "--- Current Registry Settings ---" -ForegroundColor Green
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"

if (Test-Path $policyPath) {
    Write-Host "Policy path exists" -ForegroundColor Green
    $policies = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
    
    @(
        "KFMSilentOptIn",
        "FilesOnDemandEnabled",
        "SilentAccountConfig",
        "KFMBlockOptOut"
    ) | ForEach-Object {
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
    Write-Host "Policy path does not exist" -ForegroundColor Red
}

Write-Host ""

# Test 3: OneDrive Process Status
Write-Host "--- OneDrive Process Status ---" -ForegroundColor Green
$process = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "OneDrive is running (PID: $($process.Id))" -ForegroundColor Green
}
else {
    Write-Host "OneDrive is not running" -ForegroundColor Red
}

Write-Host ""

# Test 4: Disk Space
Write-Host "--- Disk Space Status ---" -ForegroundColor Green
$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
$totalGB = [math]::Round($disk.Size / 1GB, 2)

Write-Host "Total: ${totalGB}GB, Free: ${freeGB}GB" -ForegroundColor Cyan
if ($freeGB -ge 32) {
    Write-Host "Sufficient space for Windows 11 upgrade" -ForegroundColor Green
}
else {
    Write-Host "Insufficient space for Windows 11 upgrade (need $([math]::Round(32 - $freeGB, 2))GB more)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan