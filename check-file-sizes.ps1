param($ScriptsPath = "C:\code\OneDrive\Scripts")

Get-ChildItem -Path $ScriptsPath -Recurse -Filter "*.ps1" | ForEach-Object {
    $lineCount = (Get-Content $_.FullName).Count
    [PSCustomObject]@{
        File = $_.FullName
        Lines = $lineCount
        Directory = $_.Directory.Name
    }
} | Sort-Object Lines -Descending | Format-Table -AutoSize