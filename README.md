# NetVigil

Small Windows watchdog that keeps your internet connection alive. It runs at
logon from a scheduled task, probes connectivity every 10 minutes (configurable)
and, when the connection is confirmed down, escalates through increasingly
heavy repairs until it is back:

1. **Rejoin Wi-Fi** — re-enable a software-disabled radio and a disabled WLAN
   auto-config, scan, and walk the in-range remembered networks best-signal
   first (falling back to the saved profile list for hidden APs). Each
   candidate is verified for actual internet after associating — a
   strong-signal but internet-dead network doesn't shadow a weaker one that
   works. If Wi-Fi says "connected" but the internet is dead, the association
   is bounced (disconnect + reconnect).
2. **Repair the IP layer** — if the link is up but the IP config is broken
   (APIPA `169.254.x.x` self-assigned address, no address, or a lost default
   gateway after a router restart), release + renew the DHCP lease. Virtual
   and VPN adapters (Tailscale, Hyper-V, WSL, etc.) are never touched, and a
   wired subnet with no default route (NAS/lab link) is not treated as broken.
   If the Wi-Fi network's *own* gateway answers pings while the internet is
   dead, the outage is upstream (ISP/router WAN) — NetVigil says so, leaves
   the healthy association alone, and skips the driver reset instead of
   thrashing hardware that isn't the problem. This triage runs *before* any
   reconnect, so a working association is never bounced during an ISP outage.
3. **Reset the adapter driver** — disable/enable the Wi-Fi adapter device via
   SetupAPI (the same thing Device Manager does). Works for internal and
   external/USB adapters; if the adapter has wedged so hard it no longer shows
   up in WlanSvc, a heuristic pass resets any present wireless-looking network
   device instead. If driver resets keep turning out to be the thing that
   revives the connection (twice, with the connection actually coming back
   each time), Windows' permission to power the adapter down is removed
   (`PnPCapabilities=0x18`) — the classic cure for USB Wi-Fi adapters that
   die from selective suspend. Futile resets during AP/ISP outages never
   trigger this.
4. **Restart WlanSvc** (the WLAN AutoConfig service) and reconnect again.

The **degraded** state (pings work, HTTP/DNS dead) gets its own lightweight,
rate-limited repair without touching Wi-Fi: if a proxy-bypassing request
works, the system proxy is named as the culprit; otherwise the DNS resolver
cache is flushed and connectivity re-tested.

Driver resets are rate-limited to once per 15 minutes so a dead ISP or captive
portal can't make it thrash your hardware. While the connection is down, checks
tighten to every 2 minutes.

## Build

Requires Visual Studio (or Build Tools) with the C++ x64 toolset:

```bat
build.bat
```

Produces `build\NetVigil.exe` (x64, no console window; it attaches to your
terminal when run from one). **x64 matters** — a 32-bit build cannot
disable/enable devices on 64-bit Windows.

## Usage

```
NetVigil.exe                 run the monitor loop (default 10 min interval)
NetVigil.exe --interval N    monitor with an N-minute check interval (1-1440)
NetVigil.exe --install       register + start the logon task (prompts for UAC)
NetVigil.exe --uninstall     stop the monitor and remove the task
NetVigil.exe --stop          signal a running monitor to exit
NetVigil.exe --status        show adapters, probe results, task state, verdict
NetVigil.exe --once          one check; remediate if offline; exit
```

`--install` copies the exe to `%ProgramFiles%\NetVigil\` and points the
scheduled task there — the task runs elevated at every logon, so it must never
execute from a user-writable directory where any process running as you could
swap the binary. `--uninstall` removes the task and that copy. The task runs
with highest privileges (needed for the driver reset and service restart)
after a 30 s delay, so the network stack has settled. `--stop` works from a
normal (non-elevated) shell; the named control objects are ACL'd to the
interactive session — meaning any process in your session can also stop the
watchdog, which is intentional (it's a convenience, not a security boundary).

Log: `%LOCALAPPDATA%\NetVigil\netvigil.log` (rotated at 1 MiB to `.old`).

## How it decides "online"

Two independent HTTP probes (Microsoft NCSI `connecttest.txt`, Google
`generate_204`) with redirects disabled, then ICMP pings to 1.1.1.1 / 8.8.8.8:

- Any HTTP probe returning the expected content → **online**.
- Pings work but HTTP doesn't → **degraded** (DNS/filtering problem — resetting
  Wi-Fi won't help, so it logs and leaves things alone).
- HTTP answers but with the wrong content → **captive portal** (reconnect is
  attempted, but the driver is never reset for a portal; sign in via browser).
- Everything fails → **offline** → full remediation ladder.

A loss is only acted on after a 30 s confirmation re-check (90 s for the first
check after start, to let logon settle). Resume from sleep is detected and
triggers an immediate check instead of waiting out the interval. When a loss
is confirmed, a snapshot of every adapter (IP, gateway, DNS, APIPA state) is
logged, and recovery lines report how long the connection was down.

## Limitations

- Airplane mode and a hardware radio kill-switch cannot be undone from
  software; both are logged.
- Without elevation only stage 1 (reconnect) is available — that's why the
  scheduled task runs elevated.
- It connects only to networks you have saved profiles for; it never joins
  unknown open networks.
