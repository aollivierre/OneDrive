$bp=Join-Path ((Get-ChildItem "$env:USERPROFILE" -Filter "OneDrive - *" -dir).FullName) "DownloadsBackup";if (Test-Path $bp) {if ((Get-ChildItem -Path $bp -Recurse -File).Count -gt 0) {Write-Output "DownloadsBackup folder detected with files at $bp.";exit 0}else{exit 1}}else{exit 1}

