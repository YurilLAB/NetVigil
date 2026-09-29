param([Parameter(Mandatory)][string]$Root, [string]$Mode = 'good', [int]$Port = 8765)
# Stand-in for GitHub's release endpoints, used by tools\test-update.ps1.
#   /latest/download/manifest.txt        -> $Root\manifest.txt
#   /download/v<anything>/NetVigil.exe   -> $Root\NetVigil.exe
# Modes: good | redirect (the manifest 302s to another host) | notfound (404)
$l = [System.Net.HttpListener]::new()
$l.Prefixes.Add("http://127.0.0.1:$Port/")
$l.Start()
while ($l.IsListening) {
    $ctx = $l.GetContext()
    $p = $ctx.Request.Url.AbsolutePath
    $res = $ctx.Response
    try {
        if ($Mode -eq 'notfound') { $res.StatusCode = 404; $res.Close(); continue }
        if ($Mode -eq 'redirect' -and $p -like '*manifest.txt') {
            $res.StatusCode = 302
            $res.RedirectLocation = "http://127.0.0.2:$Port/latest/download/manifest.txt"
            $res.Close(); continue
        }
        $file = $null
        if ($p -eq '/latest/download/manifest.txt') { $file = Join-Path $Root 'manifest.txt' }
        elseif ($p -match '^/download/v[0-9.]+/NetVigil\.exe$') { $file = Join-Path $Root 'NetVigil.exe' }
        if ($file -and (Test-Path $file)) {
            $bytes = [IO.File]::ReadAllBytes($file)
            $res.StatusCode = 200
            $res.ContentLength64 = $bytes.Length
            $res.OutputStream.Write($bytes, 0, $bytes.Length)
            $res.Close()
        } else { $res.StatusCode = 404; $res.Close() }
    } catch { try { $res.Abort() } catch {} }
}
