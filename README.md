# NetVigil

Small Windows watchdog that keeps your internet connection alive. It starts
with Windows from a scheduled task, lives in the system tray, probes
connectivity every 10 minutes (configurable, and at once when Windows reports
a connectivity change or the machine wakes from sleep) and, when the
connection is confirmed down, **works out why before touching anything** —
then runs only the repairs that can fix that particular cause, cheapest
first, verifying after each one.

A dead ISP, a stale proxy, a disabled adapter and a wedged driver all look
like "no internet", but each has exactly one repair that helps. Resetting the
Wi-Fi driver during an ISP outage fixes nothing and drops the connection for
everything else on the machine, so heavy repairs (driver reset, WLAN service
restart) are only ever planned for faults they can actually fix.

## How it diagnoses

On a confirmed loss NetVigil observes the machine — adapters (physical vs.
virtual, link, IP configuration, address conflicts), device-manager state
(disabled, driver error codes), Wi-Fi radio and association, airplane mode,
the services networking depends on, which adapter carries the route to the
internet, whether that adapter's router answers (ping, or a fresh ARP request
for routers that ignore ping), and — when the internet still answers by IP —
DNS, the proxy and plain web requests. It then names the fault and plans:

| Diagnosis | What it means | Repair plan |
|---|---|---|
| ISP / router outage | Your router answers, nothing beyond it does | None — waits, never resets hardware. After a few minutes, optionally switches to another saved Wi-Fi network that has internet (see Settings), returning to yours if none does |
| VPN not passing traffic | Everything is routed into a VPN tunnel while the network under it is fine | None — tells you to reconnect or quit the VPN |
| Captive portal | A sign-in page intercepts traffic | None — the notification (and a tray menu entry) opens the sign-in page |
| Proxy not working | The configured proxy is the broken part | A proxy on `localhost` that is still silent 30 s later (a debugging or filtering tool that crashed and left every browser pointed at a dead port) is switched off, keeping "automatically detect settings" and any setup script as they were; any other proxy is reported |
| DNS not resolving | The internet answers by IP, names don't resolve | Flush the DNS cache; renew the DHCP lease when the router-provided DNS servers are dead; DNS servers you typed in yourself are reported, not changed |
| Web traffic blocked | IP and DNS work, web requests don't | Flush the DNS cache (a stale record); otherwise reported (firewall / filter) |
| Router not responding | Link up, IP fine, router silent | Flush the ARP cache → renew the DHCP lease → Wi-Fi: reconnect from scratch → reset the adapter driver → restart WLAN AutoConfig; wired: reset the adapter |
| No valid IP address | Self-assigned 169.254 address, no address, an address conflict, or (Wi-Fi) no gateway | Renew the DHCP lease, then the link-level steps above |
| Network service stopped | DHCP Client, WLAN AutoConfig or Network Store Interface stopped | Start it (a service set to *Disabled* is reported, not overridden; a disabled WLAN AutoConfig never hides a wired problem) |
| Adapter disabled | Turned off in Device Manager / Network Connections | Enable it and reconnect (wired adapters only when nothing else is left) |
| Adapter driver problem | Device Manager error code (10, 43, …), or WLAN AutoConfig can't see a healthy adapter | Reset the driver (disable + enable), restart WLAN AutoConfig; code 14 or a hung driver → tells you to restart Windows |
| Network adapter missing | A Wi-Fi adapter seen recently has vanished (a USB dongle that dropped off the bus) | Scan for hardware changes, restart WLAN AutoConfig |
| Airplane mode / Wi-Fi switch off | You (or a key) switched the radio off | None — NetVigil respects airplane mode and cannot flip a hardware switch |
| Wi-Fi radio off | The Wi-Fi radio is off in software | Switch it on, reconnect |
| Wi-Fi password rejected | A saved network keeps failing its security handshake | Other saved networks go first for 30 minutes; one adapter reset early in the outage (a wedged driver fails the handshake the same way), then it tells you to re-enter the password |
| No saved network in range | The radio works and sees networks, none of yours | Keeps trying saved networks (hidden ones never show up in a scan); no hardware resets |
| Wi-Fi not connected | Not associated | Rejoin the best in-range saved network; driver reset / service restart only if that fails (and immediately suspect the radio if it sees no networks at all) |
| Network cable unplugged | Wired link down, no Wi-Fi to fall back to | One adapter reset per outage (for NIC links that wedge), then reported |
| System clock is wrong | Online, but the clock is over an hour off — HTTPS sites fail | Ask Windows Time to resync; if it refuses to jump that far, tells you to set the time |

After each repair NetVigil re-checks connectivity; when a plan runs out it
observes and diagnoses again (an enabled adapter still has to associate, a
started service still has to connect). The log shows every step:

```
diagnosis: Router not responding — 'Wi-Fi' is connected but its router (192.168.1.1) is not responding
  plan: flush the ARP cache on 'Wi-Fi' → renew the DHCP lease on 'Wi-Fi' → reconnect Wi-Fi from scratch → …
repair: flush the ARP cache on 'Wi-Fi'
  -> OFFLINE
repair: renew the DHCP lease on 'Wi-Fi'
  -> ONLINE
fixed by: renew the DHCP lease on 'Wi-Fi' (Router not responding)
```

Repairs are rate-limited individually (driver resets and WLAN service
restarts at most every 15 minutes, DHCP renewals every 10, …), so a long
outage never turns into hardware thrashing. While the connection is down,
checks tighten to every 2 minutes. Faults only you can finish fixing
(airplane mode, a wrong saved password, an ISP outage, a VPN, a portal) get
one tray notification per outage. Which repairs actually worked is counted
in `netvigil.ini` (`[repairs]`) and shown by `--status`.

### Wi-Fi details

Rejoining walks the in-range remembered networks best-signal first (falling
back to the saved profile list for hidden APs), honouring each network's
auto-connect policy. Each candidate is verified for actual internet after
associating — a strong-signal but internet-dead network doesn't shadow a
weaker one that works. WLAN auto-config is re-enabled if something turned it
off. Connection failures are logged with Windows' own reason text.

Driver resets use SetupAPI (the same thing Device Manager does) and work for
internal and external/USB adapters. If resets keep turning out to be what
revives a particular adapter (twice, with the connection actually coming back
each time), Windows' permission to power it down is removed
(`PnPCapabilities=0x18`) — the classic cure for USB Wi-Fi adapters that die
from selective suspend. Futile resets during AP/ISP outages never count. A
driver so wedged that it doesn't answer a reset within 90 s is left alone and
reported ("restart Windows"); the watchdog itself carries on.

Virtual and VPN adapters (Tailscale, WireGuard, Hyper-V, WSL, …) are never
reset or DHCP-renewed; physical vs. virtual comes from NDIS itself, not from
adapter names. A wired subnet with no default route (NAS/lab link) is not
treated as broken.

## Build

Requires Visual Studio (or Build Tools) with the C++ x64 toolset:

```bat
build.bat          :: build\NetVigil.exe
build.bat test     :: build and run the unit tests (diagnosis + update verification)
```

Produces `build\NetVigil.exe` (x64, no console window; it attaches to your
terminal when run from one). **x64 matters** — a 32-bit build cannot
disable/enable devices on 64-bit Windows.

The decision logic (`src/diagnose.cpp`) has no Windows dependencies; its
tests also build anywhere with a C++17 compiler:

```sh
g++ -std=c++17 -Isrc tests/diagnose_tests.cpp src/diagnose.cpp -o diagnose_tests && ./diagnose_tests
```

## Usage

```
NetVigil.exe                 open the window (starts the watchdog if it isn't running)
NetVigil.exe --tray          start hidden in the tray
NetVigil.exe --autostart     what the startup task runs (see below)
NetVigil.exe --interval N    check every N minutes (1-1440; persisted in netvigil.ini)
NetVigil.exe --install       register + start the startup task (prompts for UAC)
NetVigil.exe --uninstall     stop the watchdog and remove the task
NetVigil.exe --stop          signal the running watchdog to exit
NetVigil.exe --check-update  look for a newer signed release — changes nothing
NetVigil.exe --update        install the newer signed release (prompts for UAC)
NetVigil.exe --status        adapters, probes, startup task, and a diagnosis with its
                             repair plan — changes nothing
NetVigil.exe --once          one check; diagnose and repair if needed; exit
```

## Starting with Windows

`--install` (or *Install at startup* in the window) copies the exe to
`%ProgramFiles%\NetVigil\` and registers a Task Scheduler task — through the
Task Scheduler API with an explicit definition, because the `schtasks`
defaults are wrong for a watchdog:

- **Starts at your sign-in, elevated**, 15 s after logon (NetVigil's own first
  check waits for the network stack to settle before acting).
- **Starts and keeps running on battery.** A default `schtasks` logon task
  does neither — on an unplugged laptop the watchdog simply never ran.
- **No execution time limit.** The default kills a task after 72 hours, which
  on a machine that sleeps instead of logging off silently ended the watchdog
  three days in.
- **Relaunches NetVigil if it stops** — a repetition every 10 minutes that is
  a no-op while it runs, plus restart-on-failure. Choosing *Exit* in the tray
  (or `--stop`) is respected until your next sign-in; starting NetVigil by
  hand re-arms the relaunch.
- **Runs for the account that is signed in**, even when a standard user
  approves the UAC prompt with an administrator's password (the task used to
  be created for the administrator and never started for the actual user).
- An elevated copy started by the task **replaces a non-elevated copy** you
  started by hand, so adapter resets are never silently unavailable.
- Tasks created by older NetVigil versions are **upgraded in place** the next
  time the installed copy runs; the Settings page also shows a task that is
  outdated, disabled in Task Scheduler, or pointing at a missing file, with a
  one-click repair.
- The installed exe is updated through a temporary file and an atomic rename,
  so an interrupted update never leaves a half-written binary for an elevated
  task to run; reinstalling right after an uninstall cancels the uninstall's
  delete-at-reboot; after installing, NetVigil confirms the task actually
  started.

The task must never point at a user-writable directory where any process
running as you could swap the binary — hence the `%ProgramFiles%` copy.
`--uninstall` removes the task and that copy.

## Updates

The running copy checks GitHub for a newer release a minute and a half after it
starts and then once a day (retrying hourly after a failure), and only while
the connection is up and no repair is running. What it does with one:

- **Automatic (default).** An elevated installed copy downloads, verifies and
  installs the update itself, then restarts in the tray — no prompt. Turn it
  off in *Settings → Install updates automatically*.
- **Manual.** *Settings → Check for updates* / *Install update…*; a copy that is
  not running elevated asks for UAC and an elevated helper redoes the whole
  check. A copy that was never installed at startup cannot update itself, so
  the button opens the release page instead.
- **From a terminal:** `--check-update` (exit code 0 up to date, 10 available,
  1 failed) and `--update`.

An update is used **only** if its `manifest.txt` carries a valid ECDSA P-256
signature from the release key compiled into the exe, its version is newer
than the running one, and the downloaded exe has exactly the signed size and
SHA-256. HTTPS is defence in depth, not the trust anchor. Details, and what is
deliberately *not* protected, are in [SECURITY.md](SECURITY.md).

Publishing a release is `tools\release.ps1 -Version X.Y.Z -Publish` (bump
`src\version.h` first). It builds, runs the tests, signs with the DPAPI-protected
key from `tools\new-signing-key.ps1`, and refuses to publish unless the signed
manifest verifies against the key compiled into that very exe.

## Security

NetVigil runs elevated while everything else you run does not, so it is built
not to trust anything an unprivileged process can influence: its data folder
is checked and pinned against junction swaps, its log and settings are never
written through a link, its install location and update channel do not come
from overridable environment variables, its mutex/stop-event permissions are
scoped to you, and the exe ships with control-flow guard, CET, ASLR, DEP and
System32-only DLL loading. See [SECURITY.md](SECURITY.md) for the full list,
the limits, and how to report a problem.

## The window

A single small window with two tabs (Status, Settings), plain Win32, nothing
to install. **Closing it does not stop NetVigil** — the window hides and the
watchdog keeps running in the tray; exit from the tray icon's menu. Launching
`NetVigil.exe` again just brings the running instance's window back (even from
a non-elevated shell). The tray icon is a coloured dot: green online, red
offline, amber degraded / portal / checking / clock wrong, grey paused.

- **Status line** — online/offline/degraded/portal and the diagnosis, the
  network you're on, the adapter, last and next check, how long you've been
  offline, and what the repair is doing right now.
- **Diagnosis** — the cause in one sentence while there is a problem, or the
  last repair that worked and how long ago.
- **Networks** — every saved Wi-Fi profile plus every network NetVigil has
  seen you connected to, with signal (or "not in range"), last-connected time
  and connect count. Select one and choose its **auto-connect policy**:
  - *Preferred* — tried first whenever it is in range (one network at a time).
  - *Allowed* (default) — tried in signal-strength order.
  - *Never connect* — skipped by the reconnect logic and by ISP-outage
    failover, even if it has a saved profile (good for the neighbour's
    hotspot you joined once, or a metered phone hotspot).
  **Connect now** (or double-click) switches to the selected network on the
  spot and verifies internet a few seconds later.
- **Check now / Pause** — force a check, or pause the watchdog (e.g. while you
  deliberately work offline or sign into a captive portal).
- **Recent activity** — the live tail of the log.

The **Settings** tab is deliberately tiny:

- **Check every N minutes** — change the interval live; it persists.
- **Show tray notifications** — balloons when the connection drops or comes
  back, and for faults only you can fix.
- **During an ISP outage, switch to another saved Wi-Fi network** — on by
  default; networks marked *Never connect* are never used.
- **Start with Windows** — the startup task's state (installed, outdated,
  disabled, or a different build than this window) with a button that
  installs, repairs or updates it (UAC prompt; NetVigil restarts hidden in
  the tray).
- **Settings and log** — the data folder, with an *Open folder* button.
- **Uninstall NetVigil** — stops the watchdog, removes the startup task and
  the installed copy in `%ProgramFiles%\NetVigil`, then closes. Your settings
  and log folder are kept (delete `%LOCALAPPDATA%\NetVigil` yourself for a
  clean slate). If NetVigil is running *from* the installed copy, a helper
  copy in `%TEMP%` performs the removal and deletes itself at the next reboot.

Preferences and the remembered-network list live in
`%LOCALAPPDATA%\NetVigil\netvigil.ini` (UTF-16, plain INI: `[settings]`,
`[networks]`, `[seen]`, `[repairs]`, `[resets]`). NetVigil records the
network it is on at every check, so the list fills itself in over time.

## Resource use

The UI thread sleeps in `GetMessage`; the watchdog runs on a below-normal
priority worker thread that waits on events between checks (no polling —
Windows pushes connectivity changes to it), and the process trims its working
set before every idle interval. With the window hidden it sits at a few
hundred KB and 0% CPU; the window is only refreshed while it is visible. The
full observation (device enumeration, DNS and gateway probes) only runs when
something is wrong. The exe is built with whole-program optimization, is
statically linked and has no runtime dependencies.

Anything that can hang when a driver wedges — device operations, device
enumeration, the system resolver — runs with a time limit on a helper thread,
so a hung adapter cannot freeze the watchdog that is supposed to report it.

`--stop` works from a normal (non-elevated) shell; the named control objects
are ACL'd to the interactive session — meaning any process in your session
can also stop the watchdog, which is intentional (it's a convenience, not a
security boundary).

Log: `%LOCALAPPDATA%\NetVigil\netvigil.log` (rotated at 1 MiB to `.old`).

## How it decides "online"

Two independent HTTP probes (Microsoft NCSI `connecttest.txt`, Google
`generate_204`) with redirects disabled, then ICMP pings to 1.1.1.1 / 8.8.8.8,
and — for networks that drop ICMP — a TCP handshake with the same addresses:

- Any HTTP probe returning the expected content → **online**.
- The internet answers by IP but HTTP doesn't → **degraded** (DNS, proxy or
  filtering problem — gets the diagnosis above, never a Wi-Fi or driver reset).
- HTTP answers but with the wrong content → **captive portal**.
- Everything fails → **offline** → diagnose and repair.

A loss is only acted on after a 30 s confirmation re-check (90 s for the first
check after start, to let logon settle) — cut short if Windows reports the
internet is back. Resume from sleep triggers an immediate check instead of
waiting out the interval, and so does Windows reporting that connectivity
dropped (Windows 10 2004 and later). Recovery lines report how long the
connection was down.

## Limitations

- Airplane mode and a hardware radio switch are respected, not overridden;
  both are reported.
- Without elevation only the unprivileged repairs run (Wi-Fi reconnects,
  DNS cache flush, proxy fix) — that's why the startup task runs elevated.
- It connects only to networks you have saved profiles for; it never joins
  unknown open networks.
- NetVigil starts at sign-in, not at boot: before anyone signs in, Windows is
  on its own.
