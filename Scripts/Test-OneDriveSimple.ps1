# Simple automated OneDrive test - NO user interaction
param()

# Check registry for tenant ID
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$tenantID = (Get-ItemProperty -Path $policyPath -Name "KFMSilentOptIn" -ErrorAction SilentlyContinue).KFMSilentOptIn

# Check folder redirection
$shellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$oneDrivePath = $env:OneDrive

$redirectedCount = 0
@("Desktop", "Personal", "My Pictures", "{374DE290-123F-4565-9164-39C4925E467B}") | ForEach-Object {
    $path = (Get-ItemProperty -Path $shellFolders -Name $_ -ErrorAction SilentlyContinue).$_
    if ($path -and $oneDrivePath -and ($path -like "*$oneDrivePath*")) {
        $redirectedCount++
    }
}

# Check OneDrive process
$processRunning = $null -ne (Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue)

# Results
if ($tenantID -and ($tenantID -ne "12345678-1234-1234-1234-123456789012") -and ($redirectedCount -ge 3) -and $processRunning) {
    Write-Output "PASS"
    exit 0
}
else {
    Write-Output "FAIL: TenantID=$($null -ne $tenantID), Folders=$redirectedCount/4, Process=$processRunning"
    exit 1
}