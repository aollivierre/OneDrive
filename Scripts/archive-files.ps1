# Archive temporary files
$archivePath = "C:\code\Archive"

# Create Archive directory if it doesn't exist
if (-not (Test-Path $archivePath)) {
    New-Item -Path $archivePath -ItemType Directory -Force
}

# Move files to archive
$files = @(
    "C:\code\create-github-repo.ps1",
    "C:\code\push-to-github.ps1"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        $fileName = Split-Path $file -Leaf
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $archiveFileName = "$timestamp`_$fileName"
        Move-Item -Path $file -Destination (Join-Path $archivePath $archiveFileName) -Force
        Write-Host "Archived: $fileName to $archiveFileName"
    }
}