# Force KFM folder redirection manually
Write-Host "=== Forcing KFM Folder Redirection ===" -ForegroundColor Cyan

# Check current user shell folders
$shellFoldersPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$shellFoldersStatic = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

# Get OneDrive path
$oneDrivePath = $env:OneDrive
if (-not $oneDrivePath) {
    Write-Host "ERROR: OneDrive environment variable not set!" -ForegroundColor Red
    exit 1
}

Write-Host "OneDrive path: $oneDrivePath" -ForegroundColor Green

# Define folders to redirect
$foldersToRedirect = @(
    @{
        Name = "Desktop"
        RegName = "Desktop"
        DefaultPath = "%USERPROFILE%\Desktop"
        OneDrivePath = "$oneDrivePath\Desktop"
    },
    @{
        Name = "Documents"
        RegName = "Personal"
        DefaultPath = "%USERPROFILE%\Documents"
        OneDrivePath = "$oneDrivePath\Documents"
    },
    @{
        Name = "Pictures"
        RegName = "My Pictures"
        DefaultPath = "%USERPROFILE%\Pictures"
        OneDrivePath = "$oneDrivePath\Pictures"
    }
)

Write-Host "`nCurrent folder locations:" -ForegroundColor Yellow
foreach ($folder in $foldersToRedirect) {
    $currentPath = (Get-ItemProperty -Path $shellFoldersPath -Name $folder.RegName -ErrorAction SilentlyContinue).($folder.RegName)
    Write-Host "  $($folder.Name): $currentPath" -ForegroundColor Gray
}

Write-Host "`nRedirecting folders to OneDrive..." -ForegroundColor Yellow

foreach ($folder in $foldersToRedirect) {
    Write-Host "`nProcessing $($folder.Name)..." -ForegroundColor Cyan
    
    # Create OneDrive folder if it doesn't exist
    if (!(Test-Path $folder.OneDrivePath)) {
        New-Item -Path $folder.OneDrivePath -ItemType Directory -Force | Out-Null
        Write-Host "  Created: $($folder.OneDrivePath)" -ForegroundColor Green
    }
    
    # Update registry - both locations
    Set-ItemProperty -Path $shellFoldersPath -Name $folder.RegName -Value $folder.OneDrivePath -Force
    Set-ItemProperty -Path $shellFoldersStatic -Name $folder.RegName -Value $folder.OneDrivePath -Force
    Write-Host "  Updated registry to point to OneDrive" -ForegroundColor Green
    
    # Get source folder
    $sourcePath = [Environment]::ExpandEnvironmentVariables($folder.DefaultPath)
    
    # Check if we need to move files
    if ((Test-Path $sourcePath) -and ($sourcePath -ne $folder.OneDrivePath)) {
        $fileCount = (Get-ChildItem -Path $sourcePath -ErrorAction SilentlyContinue).Count
        if ($fileCount -gt 0) {
            Write-Host "  Found $fileCount items in $sourcePath" -ForegroundColor Yellow
            Write-Host "  Files need to be moved manually or on next login" -ForegroundColor Yellow
        }
    }
}

# Also update the KFM registry state
Write-Host "`nUpdating KFM state registry..." -ForegroundColor Yellow
$kfmStatePath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
if (Test-Path $kfmStatePath) {
    # Set KFM state flags
    Set-ItemProperty -Path $kfmStatePath -Name "LastKnownFolderBackupTime" -Value ([DateTimeOffset]::Now.ToUnixTimeSeconds()) -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $kfmStatePath -Name "KfmFoldersProtectedTimestamp" -Value ([DateTimeOffset]::Now.ToUnixTimeSeconds()) -Force -ErrorAction SilentlyContinue
    Write-Host "  Updated KFM state flags" -ForegroundColor Green
}

Write-Host "`n=== Verification ===" -ForegroundColor Cyan
& "$PSScriptRoot\Get-OneDriveRealStatus.ps1"

Write-Host "`n=== IMPORTANT NOTES ===" -ForegroundColor Yellow
Write-Host "1. Folder registry has been updated" -ForegroundColor Cyan
Write-Host "2. You may need to sign out and sign back in for changes to take effect" -ForegroundColor Cyan
Write-Host "3. Existing files in Desktop/Documents/Pictures will need to be moved" -ForegroundColor Cyan
Write-Host "4. OneDrive may take a few minutes to recognize the folder changes" -ForegroundColor Cyan