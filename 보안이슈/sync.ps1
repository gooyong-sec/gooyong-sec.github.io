# Daily security-issues routine sync (local-only; GitHub origin push is disabled).
# Run this after writing the daily report:
# 1) node build.mjs  -> regenerates index.html and other derived files (for offline viewing)
# 2) git add/commit, scoped to the security-issues folder only (no push)
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot
$repo = Split-Path $dir -Parent

Write-Host "[1/2] running node build.mjs..." -ForegroundColor Cyan
Push-Location $dir
node build.mjs
Pop-Location

$folderName = Split-Path $dir -Leaf

Write-Host "[2/2] git add/commit (local only)..." -ForegroundColor Cyan
git -C $repo add $folderName
$changes = git -C $repo status --porcelain -- $folderName
if (-not $changes) {
    Write-Host "No changes to commit." -ForegroundColor Yellow
    exit 0
}
$msg = "security-issues: daily sync " + (Get-Date -Format "yyyy-MM-dd")
git -C $repo commit -m $msg | Out-Null
Write-Host "Done - committed locally. index.html: $dir\index.html" -ForegroundColor Green
