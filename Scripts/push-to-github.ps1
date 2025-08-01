# Configure git and push to GitHub
$token = "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"
$remoteUrl = "https://aollivierre:$token@github.com/aollivierre/OneDrive.git"

# Update the remote URL with authentication
git remote set-url origin $remoteUrl

# Push to GitHub
git push -u origin main