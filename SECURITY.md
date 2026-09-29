# Security policy

## Reporting a vulnerability

Please report it privately: use **Report a vulnerability** on the repository's
*Security* tab (GitHub private vulnerability reporting). Do not open a public
issue for anything exploitable. You will get an answer as soon as the
maintainer sees it; a fix is released through the signed update channel.

## What NetVigil trusts, and what it does not

NetVigil normally runs **elevated** (its startup task uses the highest run
level), while everything else running as the same user is not. It is built so
that unprivileged code cannot steer it:

- **Files it writes** live in `%LOCALAPPDATA%\NetVigil`. The folder is located
  through the user's profile record in HKLM, refused if it is a junction/link,
  and held open so it cannot be swapped while NetVigil runs. The log and
  settings file are never written through a link, a directory or a hard link;
  if the folder is unsafe NetVigil runs without persistence and says so.
- **Where it installs** comes from the shell's known-folder API, never from an
  environment variable a user can override. The startup task only ever points
  at the admin-only copy under `%ProgramFiles%`.
- **Nothing elevated is run from a user-writable location.** (Uninstall used to
  stage a helper in `%TEMP%`; it no longer does.)
- **Its named mutex and stop event** grant the signed-in user only the rights
  `--stop` needs — not "everyone interactive", and no delete/write-DAC.
- **Process hardening:** DLLs load from System32 only, no remote or
  low-integrity images, extension points (AppInit, legacy IMEs, winsock LSPs)
  disabled, the Windows 11 redirection guard when elevated, and the exe is
  built with control-flow guard, CET shadow-stack compatibility, high-entropy
  ASLR, DEP and `/sdl`.
- **Network-supplied text** (SSIDs, profile names) never reaches a command
  line — Wi-Fi is driven through the WLAN API — and control characters are
  stripped before anything is logged.

Deliberately not enabled, because each would break or endanger a watchdog:
child-process restrictions (it runs `schtasks`, `ipconfig`, …), win32k
lockdown (it is a GUI), dynamic-code and signature-only policies (shell and
security-software DLLs live in-process) and strict handle checks.

Known limits, stated plainly:

- Any process running as the signed-in user can stop NetVigil (`--stop`, or the
  tray's Exit) — that is a feature, not a boundary.
- It is not an anti-malware product and does not defend itself against code
  already running as administrator.

## Updates

Updates are **opt-out** (Settings → *Install updates automatically*). An update
is applied only if all of these hold, each unit-tested with reject-path cases:

1. The release's `manifest.txt` has a valid **ECDSA P-256 / SHA-256 signature**
   from the release key whose public half is compiled into the exe
   (`src/update_pubkey.h`, fingerprint printed in that file).
2. Its version is **strictly newer** than the running one — no downgrades.
3. The downloaded exe has **exactly the signed size and SHA-256**.

Transport is HTTPS with normal certificate validation, redirects are followed
by hand and limited to GitHub hosts, and sizes and timeouts are capped — but
that is defence in depth: a hijacked connection still cannot make NetVigil run
an unsigned binary.

The update is applied only by an **elevated** process, staged inside the
admin-only install folder, re-verified from disk, and installed through the
same code path as a manual `--install`. A non-elevated window never writes
there; it asks for elevation and the elevated helper repeats the whole check.

**Trust anchor:** the private signing key lives only on the maintainer's PC,
encrypted with DPAPI for that Windows account (`tools/new-signing-key.ps1`).
Whoever holds it can ship code to every installed copy, so it is treated like a
password: it is never committed (`*.dpapi`, `*.key`, `*.pem` are git-ignored).

There is **no remote revocation**. A key can be rotated only while it is still
secret: ship a release carrying the new public key, signed with the old one.
If the key is lost, installed copies can no longer be updated in place; if it
is *exposed*, copies must be reinstalled from a fresh, manually verified
download, because the old key would still be trusted by every installed copy.
