# Configure git and push to GitHub
$token = "github_pat_"
$remoteUrl = "https://aollivierre:$token@github.com/aollivierre/OneDrive.git"

# Update the remote URL with authentication
git remote set-url origin $remoteUrl

# Push to GitHub
git push -u origin main