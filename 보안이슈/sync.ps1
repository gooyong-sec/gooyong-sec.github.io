# Daily security-issues routine sync (local-only; GitHub origin push is disabled).
# Run this after writing the daily report:
# 1) node build.mjs  -> regenerates index.html and other derived files (for offline viewing)
# 2) git add/commit, scoped to the security-issues folder only (no push)
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot
$repo = Split-Path $dir -Parent

Write-Host "[1/3] running node build.mjs..." -ForegroundColor Cyan
Push-Location $dir
node build.mjs
Pop-Location

$folderName = Split-Path $dir -Leaf

# 로컬 quartz 서버(public/)가 이미 떠 있으면 바로 복사한다.
# quartz는 content/ 변경에만 재빌드하므로, 이 폴더만 고쳤을 때는 이게 없으면
# 다음 콘텐츠 변경이 있을 때까지 화면에 반영되지 않는다.
$publicTarget = Join-Path $repo "public\security-issues"
if (Test-Path (Join-Path $repo "public")) {
    Write-Host "[2/3] live public/ 폴더에 바로 복사..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $publicTarget | Out-Null
    Copy-Item "$dir\index.html" "$publicTarget\index.html" -Force
}

Write-Host "[3/3] git add/commit (local only)..." -ForegroundColor Cyan
git -C $repo add $folderName
$changes = git -C $repo status --porcelain -- $folderName
if (-not $changes) {
    Write-Host "No changes to commit." -ForegroundColor Yellow
    exit 0
}
$msg = "security-issues: daily sync " + (Get-Date -Format "yyyy-MM-dd")
git -C $repo commit -m $msg | Out-Null
Write-Host "Done - committed locally. index.html: $dir\index.html" -ForegroundColor Green
