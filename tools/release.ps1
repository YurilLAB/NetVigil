# Builds, signs and (optionally) publishes a NetVigil release.
#
#   pwsh -File tools\release.ps1 -Version 1.0.1              # build + sign into dist\, publish nothing
#   pwsh -File tools\release.ps1 -Version 1.0.1 -Publish     # ...and create the GitHub release
#
# What "release" means here: dist\NetVigil.exe plus dist\manifest.txt, a small
# text file naming the version, size and SHA-256 of that exe, signed with the
# update key (see tools\new-signing-key.ps1). Installed copies check that
# signature against the public key baked into them before they will use the
# download, so this script is the only way an update can be produced.
#
# It refuses to go on unless every one of these holds:
#   * -Version matches src\version.h (bump the file first, commit, push)
#   * the working tree is clean and HEAD is exactly origin/main
#   * the unit tests pass
#   * the built exe contains no test-only update settings
#   * the manifest it just signed verifies against the key COMPILED INTO that
#     very exe (proves the private key on this PC matches src\update_pubkey.h)
param(
    [Parameter(Mandatory)][string]$Version,
    [switch]$Publish,
    [string]$Notes = ''
)
$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repo
function Step($t) { Write-Host "`n== $t" -ForegroundColor Cyan }
function Fail($t) { Write-Host "REFUSING: $t" -ForegroundColor Red; exit 1 }

Step 'version'
if ($Version -notmatch '^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})$') { Fail "'$Version' is not a.b.c" }
$declared = ((Get-Content src\version.h -Raw) | Select-String 'NETVIGIL_VERSION "([^"]+)"').Matches[0].Groups[1].Value
if ($declared -ne $Version) { Fail "src\version.h says $declared but you asked for $Version" }
Write-Host "version $Version"

Step 'git state'
if (git status --porcelain) { Fail 'the working tree has uncommitted changes' }
git fetch origin --quiet
$head = (git rev-parse HEAD).Trim(); $remote = (git rev-parse origin/main).Trim()
if ($head -ne $remote) { Fail "HEAD ($($head.Substring(0,7))) is not origin/main ($($remote.Substring(0,7))) — push first" }
Write-Host "HEAD = origin/main = $($head.Substring(0,7))"

Step 'build + unit tests'
cmd /c "call .\build.bat 2>&1"; if ($LASTEXITCODE -ne 0) { Fail 'build failed' }
$testOut = cmd /c "call .\build.bat test 2>&1"; $testRc = $LASTEXITCODE
$testOut | Select-String 'passed|FAIL'
if ($testRc -ne 0) { Fail 'unit tests failed' }

Step 'the exe must not carry test-only settings'
$exe = Join-Path $repo 'build\NetVigil.exe'
$bytes = [IO.File]::ReadAllBytes($exe)
$text16 = [Text.Encoding]::Unicode.GetString($bytes); $text8 = [Text.Encoding]::ASCII.GetString($bytes)
foreach ($needle in '127.0.0.1:8765', 'TEST BUILD') {
    if ($text16.Contains($needle) -or $text8.Contains($needle)) { Fail "build\NetVigil.exe contains '$needle' — a test build must never be released" }
}
Write-Host 'clean'

Step 'sign'
$dist = Join-Path $repo 'dist'
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory $dist | Out-Null
Copy-Item $exe (Join-Path $dist 'NetVigil.exe')
pwsh -NoProfile -File (Join-Path $PSScriptRoot 'sign-manifest.ps1') -Exe (Join-Path $dist 'NetVigil.exe') -Version $Version -Out (Join-Path $dist 'manifest.txt')
if ($LASTEXITCODE -ne 0) { Fail 'signing failed' }

Step 'verify against the key compiled into the exe'
$check = & (Join-Path $repo 'build\update_tests.exe') (Join-Path $dist 'manifest.txt') (Join-Path $dist 'NetVigil.exe')
$check
if ($LASTEXITCODE -ne 0) { Fail 'the signed manifest does NOT verify against src\update_pubkey.h — wrong key on this PC?' }

$sha = (Get-FileHash (Join-Path $dist 'NetVigil.exe') -Algorithm SHA256).Hash.ToLower()
if (-not $Publish) {
    Write-Host "`nDry run complete. dist\ is ready; nothing was published." -ForegroundColor Green
    Write-Host "sha256 $sha"
    exit 0
}

Step 'publish'
$body = if ($Notes) { $Notes } else { "NetVigil $Version" }
$body += "`n`nSHA-256 of NetVigil.exe: ``$sha```n`nInstalled copies verify ``manifest.txt`` against the release key built into them before installing anything."
gh release create "v$Version" (Join-Path $dist 'NetVigil.exe') (Join-Path $dist 'manifest.txt') --target main --title "NetVigil $Version" --notes $body
if ($LASTEXITCODE -ne 0) { Fail 'gh release create failed' }

Step 'verify the public download (no credentials)'
$tmp = Join-Path $env:TEMP "nv-release-check-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory $tmp | Out-Null
try {
    Invoke-WebRequest -UseBasicParsing 'https://github.com/YurilLAB/NetVigil/releases/latest/download/manifest.txt' -OutFile (Join-Path $tmp 'manifest.txt')
    Invoke-WebRequest -UseBasicParsing "https://github.com/YurilLAB/NetVigil/releases/download/v$Version/NetVigil.exe" -OutFile (Join-Path $tmp 'NetVigil.exe')
    $c2 = & (Join-Path $repo 'build\update_tests.exe') (Join-Path $tmp 'manifest.txt') (Join-Path $tmp 'NetVigil.exe')
    $c2
    if ($LASTEXITCODE -ne 0) { Fail 'the PUBLISHED artifacts do not verify' }
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
Write-Host "`nReleased v$Version." -ForegroundColor Green
