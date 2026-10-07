# Daily security-issues routine sync.
# Run this after writing the daily report:
# 1) node build.mjs  -> regenerates index.html and other derived files (for offline viewing)
# 2) git add/commit/push, scoped to the security-issues folder only
# The public site is rebuilt by GitHub Actions on push (it runs build.mjs again there too).
$ErrorActionPreference = "Stop"
$repo = "D:\98. blog"
$dir = Join-Path $repo "보안이슈"

Write-Host "[1/3] running node build.mjs..." -ForegroundColor Cyan
Push-Location $dir
node build.mjs
Pop-Location

Write-Host "[2/3] git add/commit..." -ForegroundColor Cyan
git -C $repo add "보안이슈"
$changes = git -C $repo status --porcelain -- "보안이슈"
if (-not $changes) {
    Write-Host "No changes to commit." -ForegroundColor Yellow
    exit 0
}
$msg = "security-issues: daily sync " + (Get-Date -Format "yyyy-MM-dd")
git -C $repo commit -m $msg | Out-Null

Write-Host "[3/3] push..." -ForegroundColor Cyan
$push = git -C $repo push 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "Done - site updates in 1-2 min." -ForegroundColor Green
} else {
    Write-Host "Push failed: $push" -ForegroundColor Red
    exit 1
}
