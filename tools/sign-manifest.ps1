# Builds and signs an update manifest for an exe.
#
#   manifest layout (UTF-8, LF line endings, exactly this shape):
#       netvigil-update-v1
#       version=<a.b.c>
#       size=<bytes>
#       sha256=<64 lowercase hex>
#       sig=<128 hex chars: ECDSA P-256 / SHA-256 over the four lines above, r||s>
#
# The signed payload is the first four lines INCLUDING their trailing newlines.
# NetVigil.exe verifies the signature against the public key compiled into it
# (src\update_pubkey.h), then checks the downloaded exe against size + sha256.
#
# Usage: pwsh -File tools\sign-manifest.ps1 -Exe build\NetVigil.exe -Version 1.0.0 -Out dist\manifest.txt
#        [-KeyFile <dpapi blob>]   (default: %USERPROFILE%\.netvigil\update-signing-key.dpapi)
#        [-RawKey <hex D||X||Y>]   (tests only: sign with a throwaway key instead)
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Out,
    [string]$KeyFile = (Join-Path $env:USERPROFILE '.netvigil\update-signing-key.dpapi'),
    [string]$RawKey
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData

if ($Version -notmatch '^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})$') {
    throw "Version '$Version' must be a.b.c with numbers up to 9999 and no leading zeros"
}
$bytes = [IO.File]::ReadAllBytes((Resolve-Path $Exe))
if ($bytes.Length -lt 1024 -or $bytes.Length -gt 16MB) { throw "exe size $($bytes.Length) is outside the accepted range" }
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw 'not a PE file (no MZ header)' }
$sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($bytes)).Replace('-', '').ToLower()

$payload = "netvigil-update-v1`nversion=$Version`nsize=$($bytes.Length)`nsha256=$sha`n"

if ($RawKey) {
    $secret = [byte[]]::new(96)
    for ($i = 0; $i -lt 96; $i++) { $secret[$i] = [Convert]::ToByte($RawKey.Substring(2 * $i, 2), 16) }
} else {
    if (-not (Test-Path $KeyFile)) { throw "No signing key at $KeyFile — run tools\new-signing-key.ps1 first" }
    $entropy = [Text.Encoding]::ASCII.GetBytes('netvigil-update-signing-key-v1')
    $secret = [System.Security.Cryptography.ProtectedData]::Unprotect(
                 [IO.File]::ReadAllBytes($KeyFile), $entropy,
                 [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}
$prm = [System.Security.Cryptography.ECParameters]::new()
$prm.Curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
$prm.D = $secret[0..31]
$prm.Q.X = $secret[32..63]
$prm.Q.Y = $secret[64..95]
$ec = [System.Security.Cryptography.ECDsa]::Create($prm)
[Array]::Clear($secret, 0, $secret.Length)

$sig = $ec.SignData([Text.Encoding]::UTF8.GetBytes($payload), [System.Security.Cryptography.HashAlgorithmName]::SHA256)
if ($sig.Length -ne 64) { throw "unexpected signature length $($sig.Length)" }
$sigHex = [BitConverter]::ToString($sig).Replace('-', '').ToLower()

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
# LF endings, no BOM — the parser in NetVigil is strict about both.
[IO.File]::WriteAllText($Out, $payload + "sig=$sigHex`n", [Text.UTF8Encoding]::new($false))
Write-Host "manifest    : $Out"
Write-Host "version     : $Version   size: $($bytes.Length)   sha256: $sha"
