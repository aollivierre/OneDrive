# Find files with embedded logging
$scriptsPath = "C:\code\OneDrive\Scripts"
Get-ChildItem -Path $scriptsPath -Filter "*.ps1" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match "function Write-(Detection|Remediation|Test)Log" -and 
        $content -notmatch "Import-Module.*logging") {
        Write-Host "File with embedded logging: $($_.Name)"
    }
}

# Also check for files that import the logging module
Get-ChildItem -Path $scriptsPath -Filter "*.ps1" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match "Import-Module.*logging") {
        Write-Host "File that imports logging module: $($_.Name)"
    }
}