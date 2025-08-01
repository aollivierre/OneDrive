# Script to check for Unicode symbols in PowerShell files
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = Get-ChildItem -Path $scriptPath -Filter "*.ps1" -Exclude "check-unicode.ps1"

foreach ($file in $files) {
    Write-Host "Checking: $($file.Name)" -ForegroundColor Yellow
    $content = Get-Content -Path $file.FullName -Raw
    
    $unicodeChars = @()
    for ($i = 0; $i -lt $content.Length; $i++) {
        $char = $content[$i]
        $charCode = [int]$char
        
        # Check for non-ASCII characters (above 127)
        if ($charCode -gt 127) {
            $unicodeChars += @{
                Character = $char
                Code = $charCode
                Position = $i
                Line = ($content.Substring(0, $i) -split "`n").Count
            }
        }
    }
    
    if ($unicodeChars.Count -gt 0) {
        Write-Host "  Found $($unicodeChars.Count) Unicode characters:" -ForegroundColor Red
        $unicodeChars | ForEach-Object {
            Write-Host "    Line $($_.Line): Character '$($_.Character)' (Code: $($_.Code))" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  No Unicode characters found" -ForegroundColor Green
    }
}