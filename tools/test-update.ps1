# End-to-end test of the self-updater against a local stand-in for GitHub.
#
#   build.bat                           # produces build\NetVigil.exe (the "new release" stand-in)
#   pwsh -File tools\test-update.ps1
#
# It builds a TEST-ONLY exe (build.bat updatetest) that trusts a throwaway key,
# talks to http://127.0.0.1:<port> and stages into a scratch folder without ever
# launching an installer, then throws real and hostile releases at it:
#   good update, wrong key, altered / longer / truncated exe, an edited manifest,
#   versions that are not newer, an off-allow-list redirect, 404, captive-portal
#   HTML, and a dead server. Every attack must be refused with nothing staged.
# The test exe shares your normal NetVigil log (%LOCALAPPDATA%\NetVigil).
param([int]$Port = 8765)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$src  = Join-Path $repo 'build\NetVigil.exe'
if (-not (Test-Path $src)) { throw 'build\NetVigil.exe is missing - run build.bat first' }

$work = Join-Path $env:TEMP 'netvigil-update-test'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
$root = Join-Path $work 'root'; $stageDir = Join-Path $work 'stage'; $tb = Join-Path $work 'tb'
New-Item -ItemType Directory -Force -Path $root, $stageDir, $tb | Out-Null

# --- two throwaway keys: "trusted" is baked into the test exe, "other" is an attacker's
function New-Key($name) {
    $ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $p = $ec.ExportParameters($true)
    Set-Content -Path (Join-Path $work "$name.raw") -NoNewline `
        -Value (([BitConverter]::ToString([byte[]]($p.D + $p.Q.X + $p.Q.Y))).Replace('-', '').ToLower())
    if ($name -eq 'trusted') {
        $pub = [byte[]](@(0x04) + $p.Q.X + $p.Q.Y)
        $lines = for ($i = 0; $i -lt 65; $i += 13) { '    ' + (($pub[$i..([Math]::Min($i + 12, 64))] | ForEach-Object { '0x{0:x2}' -f $_ }) -join ', ') + ',' }
        "#pragma once`nstatic const unsigned char kUpdatePubKey[65] = {`n$($lines -join "`n")`n};`n" |
            Set-Content (Join-Path $work 'pubkey_test.h') -Encoding ascii
    }
}
New-Key 'trusted'; New-Key 'other'

# --- test-only build
$env:NV_TEST_BASE   = "http://127.0.0.1:$Port"
$env:NV_TEST_STAGE  = $stageDir.Replace('\', '/')
$env:NV_TEST_PUBKEY = (Join-Path $work 'pubkey_test.h').Replace('\', '/')
$env:NV_TEST_OUT    = $tb
Push-Location $repo
try { cmd /c "call .\build.bat updatetest 2>&1" | Select-String 'error|Built'; if ($LASTEXITCODE -ne 0) { throw 'test build failed' } }
finally { Pop-Location }
$exe = Join-Path $tb 'NetVigilTest.exe'
if (-not (Test-Path $exe)) { throw 'test exe was not produced' }

$sign  = Join-Path $PSScriptRoot 'sign-manifest.ps1'
$serve = Join-Path $PSScriptRoot 'test-update-server.ps1'
$log   = Join-Path $env:LOCALAPPDATA 'NetVigil\netvigil.log'
$staged = Join-Path $stageDir 'NetVigil-update.exe'
$results = [System.Collections.Generic.List[object]]::new()

function Sha($p) { (Get-FileHash $p -Algorithm SHA256).Hash.ToLower() }
function Reset-Root { Get-ChildItem $root | Remove-Item -Recurse -Force }
function Make-Manifest($version, $key = 'trusted') {
    pwsh -NoProfile -File $sign -Exe (Join-Path $root 'NetVigil.exe') -Version $version `
         -Out (Join-Path $root 'manifest.txt') -RawKey (Get-Content (Join-Path $work "$key.raw") -Raw) | Out-Null
}
function Start-Server($mode = 'good') {
    $p = Start-Process pwsh -ArgumentList '-NoProfile', '-File', $serve, '-Root', $root, '-Mode', $mode, '-Port', $Port -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1500
    $p
}
function Stop-Server($p) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } }
function Run-Exe($argList) {
    $before = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }
    $pr = Start-Process $exe -ArgumentList $argList -PassThru -Wait
    Start-Sleep -Milliseconds 600
    $text = ''
    if (Test-Path $log) {
        $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); $fs.Seek($before, 'Begin') | Out-Null
        $buf = [byte[]]::new($fs.Length - $before); [void]$fs.Read($buf, 0, $buf.Length); $fs.Close()
        $text = [Text.Encoding]::UTF8.GetString($buf)
    }
    @{ Code = $pr.ExitCode; Log = $text }
}
function Clear-Stage { Get-ChildItem $stageDir -ErrorAction SilentlyContinue | Remove-Item -Force }
function Expect($name, $cond, $detail) { $results.Add([pscustomobject]@{ Test = $name; Pass = [bool]$cond; Detail = $detail }) }
function Fresh-Release($version = '1.0.1', $key = 'trusted') { Reset-Root; Copy-Item $src (Join-Path $root 'NetVigil.exe'); Make-Manifest $version $key }

$srv = $null
try {
    Fresh-Release; $srv = Start-Server; Clear-Stage
    $r = Run-Exe '--check-update'
    Expect 'good release is found and verified (exit 10)' ($r.Code -eq 10 -and $r.Log -match 'latest:\s+1\.0\.1 \(signature verified\)') "exit=$($r.Code)"
    $r = Run-Exe '--update'
    Expect 'good release: exe staged, byte-identical' ($r.Code -eq 0 -and (Test-Path $staged) -and (Sha $staged) -eq (Sha (Join-Path $root 'NetVigil.exe'))) "exit=$($r.Code)"
    Expect 'good release: installer not launched by the test build' ($r.Log -match 'TEST BUILD: staged and verified') ''
    Stop-Server $srv

    Fresh-Release '1.0.1' 'other'; $srv = Start-Server; Clear-Stage
    $r = Run-Exe '--check-update'
    Expect 'signed by another key: rejected' ($r.Code -eq 1 -and $r.Log -match 'not signed with NetVigil') "exit=$($r.Code)"
    $r = Run-Exe '--update'
    Expect 'signed by another key: nothing staged' ($r.Code -eq 1 -and -not (Test-Path $staged)) ''
    Stop-Server $srv

    Fresh-Release
    $bytes = [IO.File]::ReadAllBytes((Join-Path $root 'NetVigil.exe')); $bytes[5000] = $bytes[5000] -bxor 0xFF
    [IO.File]::WriteAllBytes((Join-Path $root 'NetVigil.exe'), $bytes)
    $srv = Start-Server; Clear-Stage
    $r = Run-Exe '--update'
    Expect 'exe altered after signing: discarded' ($r.Code -eq 1 -and $r.Log -match 'does not match the signed size and SHA-256' -and -not (Test-Path $staged)) ''
    Stop-Server $srv

    foreach ($v in '1.0.0', '0.9.0') {
        Fresh-Release $v; $srv = Start-Server; Clear-Stage
        $r = Run-Exe '--check-update'
        Expect "version $v is not newer: up to date" ($r.Code -eq 0 -and $r.Log -match 'up to date') "exit=$($r.Code)"
        $r = Run-Exe '--update'
        Expect "version $v is not newer: nothing staged" ($r.Code -eq 0 -and -not (Test-Path $staged)) ''
        Stop-Server $srv
    }

    Fresh-Release
    $m = (Get-Content (Join-Path $root 'manifest.txt') -Raw).Replace('version=1.0.1', 'version=9.9.9')
    [IO.File]::WriteAllText((Join-Path $root 'manifest.txt'), $m, [Text.UTF8Encoding]::new($false))
    $srv = Start-Server; Clear-Stage
    $r = Run-Exe '--update'
    Expect 'manifest edited to claim 9.9.9: rejected' ($r.Code -eq 1 -and $r.Log -match 'not signed with NetVigil' -and -not (Test-Path $staged)) ''
    Stop-Server $srv

    Fresh-Release
    $f = [IO.File]::Open((Join-Path $root 'NetVigil.exe'), 'Append'); $f.Write([byte[]](1, 2, 3, 4), 0, 4); $f.Close()
    $srv = Start-Server; Clear-Stage
    $r = Run-Exe '--update'
    Expect 'download longer than the signed size: refused' ($r.Code -eq 1 -and $r.Log -match 'larger than allowed' -and -not (Test-Path $staged)) ''
    Stop-Server $srv

    Fresh-Release
    $b = [IO.File]::ReadAllBytes((Join-Path $root 'NetVigil.exe')); [IO.File]::WriteAllBytes((Join-Path $root 'NetVigil.exe'), $b[0..($b.Length - 100)])
    $srv = Start-Server; Clear-Stage
    $r = Run-Exe '--update'
    Expect 'truncated download: refused' ($r.Code -eq 1 -and $r.Log -match 'does not match' -and -not (Test-Path $staged)) ''
    Stop-Server $srv

    Fresh-Release; $srv = Start-Server 'redirect'; Clear-Stage
    $r = Run-Exe '--check-update'
    Expect 'redirect to a host off the allow-list: refused' ($r.Code -eq 1 -and $r.Log -match 'outside the update allow-list') ''
    Stop-Server $srv

    Reset-Root; $srv = Start-Server 'notfound'
    $r = Run-Exe '--check-update'
    Expect 'HTTP 404: fails cleanly' ($r.Code -eq 1 -and $r.Log -match 'HTTP 404') ''
    Stop-Server $srv

    Reset-Root; [IO.File]::WriteAllText((Join-Path $root 'manifest.txt'), '<html>captive portal login</html>', [Text.UTF8Encoding]::new($false))
    $srv = Start-Server
    $r = Run-Exe '--check-update'
    Expect 'captive-portal HTML instead of a manifest: ignored' ($r.Code -eq 1 -and $r.Log -match 'could not be read') ''
    Stop-Server $srv

    $r = Run-Exe '--check-update'
    Expect 'update server unreachable: fails cleanly' ($r.Code -eq 1 -and $r.Log -match 'update server') ''
} finally {
    Stop-Server $srv
    Remove-Item Env:NV_TEST_BASE, Env:NV_TEST_STAGE, Env:NV_TEST_PUBKEY, Env:NV_TEST_OUT -ErrorAction SilentlyContinue
}

$results | ForEach-Object { '{0}  {1}   {2}' -f $(if ($_.Pass) { 'PASS' } else { 'FAIL' }), $_.Test, $_.Detail }
$pass = ($results | Where-Object Pass).Count; $fail = ($results | Where-Object { -not $_.Pass }).Count
"{0} passed, {1} failed" -f $pass, $fail
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 }
