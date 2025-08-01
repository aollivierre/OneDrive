# Create GitHub repository
$token = "github_pat_"
$headers = @{
    "Authorization" = "Bearer $token"
    "Accept" = "application/vnd.github.v3+json"
}

$body = @{
    "name" = "OneDrive"
    "description" = "OneDrive automation scripts for enterprise deployment, KFM, Files On-Demand, and Windows 11 upgrade disk space remediation"
    "private" = $false
    "auto_init" = $false
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Method Post -Headers $headers -Body $body -ContentType "application/json"
    Write-Host "Repository created successfully!"
    Write-Host "Clone URL: $($response.clone_url)"
    Write-Host "SSH URL: $($response.ssh_url)"
} catch {
    Write-Host "Error creating repository: $_"
    if ($_.Exception.Response.StatusCode -eq 422) {
        Write-Host "Repository might already exist"
    }
}