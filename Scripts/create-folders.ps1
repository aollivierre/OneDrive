# Create folder structure
$baseDir = "C:\code\OneDrive\Scripts"

# Create folders if they don't exist
$folders = @("src", "tests", "utils", "dev")

foreach ($folder in $folders) {
    $path = Join-Path $baseDir $folder
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "Created folder: $folder" -ForegroundColor Green
    } else {
        Write-Host "Folder already exists: $folder" -ForegroundColor Yellow
    }
}