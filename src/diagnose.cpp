// diagnose.cpp — see diagnose.h. Standard C++ only: no Windows headers.

#include "diagnose.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cwctype>

namespace nv {

namespace {

std::wstring Fmt(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vswprintf(buf, sizeof buf / sizeof buf[0], fmt, ap);
    va_end(ap);
    if (n < 0) buf[sizeof buf / sizeof buf[0] - 1] = L'\0'; // truncated
    return buf;
}

long long Abs(long long v) { return v < 0 ? -v : v; }

void Add(Diagnosis& d, Act a, int adapter = -1) { d.plan.push_back(Step{ a, adapter }); }

// Re-attach Wi-Fi after the step just added (enable, reset, service start).
void AddReconnect(Diagnosis& d) { d.plan.push_back(Step{ Act::ConnectWifi, -1, true }); }

bool IpBroken(const AdapterObs& a, bool wantGateway)
{
    return !a.hasIpv4 || a.apipa || a.duplicate || (wantGateway && !a.hasGateway);
}

const wchar_t* IpProblem(const AdapterObs& a)
{
    if (!a.hasIpv4)    return L"no IPv4 address";
    if (a.duplicate)   return L"an address that conflicts with another device";
    if (a.apipa)       return L"a self-assigned 169.254 address (DHCP did not answer)";
    if (!a.hasGateway) return L"no default gateway";
    return L"an unusable IP configuration";
}

int RouteAdapter(const Observation& o)
{
    for (size_t i = 0; i < o.adapters.size(); ++i)
        if (o.adapters[i].routesInternet) return (int)i;
    return -1;
}

// The physical adapter of a kind most worth working on:
// has link > working > failed > disabled.
int PickAdapter(const Observation& o, Kind k)
{
    int best = -1, bestScore = 0;
    for (size_t i = 0; i < o.adapters.size(); ++i) {
        const AdapterObs& a = o.adapters[i];
        if (a.virt || a.kind != k) continue;
        int score = a.dev == Dev::Disabled ? 1
                  : a.dev == Dev::Failed   ? 2
                  : a.media                ? 4
                                           : 3;
        if (score > bestScore) {
            best = (int)i;
            bestScore = score;
        }
    }
    return best;
}

int FindDisabled(const Observation& o, Kind k)
{
    for (size_t i = 0; i < o.adapters.size(); ++i)
        if (!o.adapters[i].virt && o.adapters[i].kind == k &&
            o.adapters[i].dev == Dev::Disabled)
            return (int)i;
    return -1;
}

bool AnyPhysicalGatewayAnswers(const Observation& o)
{
    for (const auto& a : o.adapters)
        if (!a.virt && a.gateway == 1) return true;
    return false;
}

std::wstring Join(const std::vector<std::wstring>& v)
{
    std::wstring s;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) s += i + 1 == v.size() ? L" and " : L", ";
        s += v[i];
    }
    return s;
}

// A driver-level problem on one adapter: reset it, then reattach Wi-Fi.
bool DeviceFault(const Observation& o, int i, Diagnosis& d)
{
    const AdapterObs& a = o.adapters[(size_t)i];
    if (a.dev == Dev::Disabled) {
        d.fault = Fault::AdapterDisabled;
        d.adapter = i;
        d.detail = Fmt(L"the adapter '%ls' is disabled", a.name.c_str());
        Add(d, Act::EnableAdapter, i);
        if (a.kind == Kind::Wifi) AddReconnect(d);
        return true;
    }
    if (a.dev == Dev::Failed) {
        d.fault = Fault::AdapterFailed;
        d.adapter = i;
        if (a.problem == kProbNeedRestart) {
            d.userAction = true;
            d.detail = Fmt(L"'%ls' cannot work until Windows restarts (device code 14)",
                           a.name.c_str());
            return true;
        }
        d.detail = Fmt(L"'%ls' reports a driver problem (device code %u)",
                       a.name.c_str(), a.problem);
        Add(d, Act::ResetAdapter, i);
        if (a.kind == Kind::Wifi) {
            AddReconnect(d);
            Add(d, Act::RestartWlanSvc);
            AddReconnect(d);
        }
        return true;
    }
    return false;
}

// Link-level repairs for the adapter carrying (or meant to carry) traffic,
// after the cheap IP-level steps already in the plan.
void LinkRepairs(const Observation& o, Diagnosis& d, int i)
{
    const AdapterObs& a = o.adapters[(size_t)i];
    if (a.kind == Kind::Wifi) {
        Add(d, Act::Reassociate);
        Add(d, Act::ResetAdapter, i);
        AddReconnect(d);
        Add(d, Act::RestartWlanSvc);
        AddReconnect(d);
    } else if (a.kind == Kind::Ethernet) {
        Add(d, Act::ResetAdapter, i);
    }
}

// Other links that lost their lease too — a router whose DHCP server
// restarted strands a docked laptop's wired and Wi-Fi links at once.
void RenewOtherBrokenLinks(const Observation& o, Diagnosis& d, int except)
{
    for (size_t i = 0; i < o.adapters.size(); ++i) {
        const AdapterObs& a = o.adapters[i];
        if ((int)i == except || a.virt || !a.hasIf || !a.media || !a.dhcp) continue;
        if (IpBroken(a, a.kind == Kind::Wifi)) Add(d, Act::RenewDhcp, (int)i);
    }
}

// Wi-Fi path, from the device outward. False when there is no Wi-Fi hardware.
bool DiagnoseWifi(const Observation& o, Diagnosis& d)
{
    const WifiObs& wf = o.wifi;
    int w = PickAdapter(o, Kind::Wifi);
    if (w < 0 && wf.interfaces == 0) return false;
    std::wstring name = w >= 0 ? o.adapters[(size_t)w].name : std::wstring(L"Wi-Fi");
    d.adapter = w;

    if (w >= 0 && DeviceFault(o, w, d)) return true;

    if (wf.serviceStopped) {
        d.fault = Fault::ServiceStopped;
        d.detail = L"WLAN AutoConfig is stopped, so Wi-Fi cannot connect";
        Add(d, Act::StartServices);
        AddReconnect(d);
        return true;
    }

    if (wf.interfaces == 0) {
        // The device is fine but WLAN AutoConfig does not see it.
        d.fault = Fault::AdapterFailed;
        d.detail = Fmt(L"the WLAN service cannot see '%ls'", name.c_str());
        Add(d, Act::RestartWlanSvc);
        AddReconnect(d);
        Add(d, Act::ResetAdapter, w);
        AddReconnect(d);
        return true;
    }

    if (!wf.associated) {
        if (wf.radioHardOff) {
            d.fault = Fault::RadioSwitchOff;
            d.userAction = true;
            d.detail = L"the Wi-Fi hardware switch (or keyboard key) is off — switch it on";
            return true;
        }
        if (wf.airplane && wf.radioSoftOff) {
            d.fault = Fault::AirplaneMode;
            d.userAction = true;
            d.detail = L"airplane mode is on — NetVigil will not override it; turn it off to reconnect";
            return true;
        }
        if (wf.radioSoftOff) {
            d.fault = Fault::RadioOff;
            d.detail = Fmt(L"the Wi-Fi radio on '%ls' is switched off", name.c_str());
            Add(d, Act::RadioOn);
            AddReconnect(d);
            return true;
        }
        if (!wf.authFailed.empty()) {
            // Usually a changed router password — but a driver that wedged
            // mid-handshake fails the same way until it is reset, so allow
            // one reset early in the outage before leaving it to the user.
            d.fault = Fault::WifiAuthFailed;
            d.userAction = true;
            d.detail = Fmt(L"Wi-Fi keeps failing the security handshake with '%ls' — if its "
                           L"password changed, connect to it once yourself to update it",
                           wf.authFailed.c_str());
            Add(d, Act::ConnectWifi);   // other saved networks first, then this one
            if (o.failStreak <= 2) {
                Add(d, Act::ResetAdapter, w);
                AddReconnect(d);
            }
            return true;
        }
        if (wf.visible > 0 && wf.knownInRange == 0) {
            d.fault = Fault::NoKnownNetwork;
            d.userAction = true;
            d.detail = Fmt(L"Wi-Fi works (%d network%ls visible) but none of your saved "
                           L"networks is in range", wf.visible, wf.visible == 1 ? L"" : L"s");
            Add(d, Act::ConnectWifi);   // saved hidden networks never show up in a scan
            return true;
        }
        d.fault = Fault::WifiDisconnected;
        d.detail = wf.visible == 0
            ? Fmt(L"'%ls' sees no Wi-Fi networks at all — the radio may be stuck", name.c_str())
            : Fmt(L"'%ls' is not connected to a network", name.c_str());
        Add(d, Act::ConnectWifi);
        Add(d, Act::ResetAdapter, w);
        AddReconnect(d);
        Add(d, Act::RestartWlanSvc);
        AddReconnect(d);
        return true;
    }

    // Associated, yet no internet.
    if (w < 0) {
        d.fault = Fault::Unknown;
        d.detail = L"Wi-Fi is connected but there is no internet";
        Add(d, Act::Reassociate);
        Add(d, Act::RestartWlanSvc);
        AddReconnect(d);
        return true;
    }
    const AdapterObs& a = o.adapters[(size_t)w];
    if (IpBroken(a, /*wantGateway=*/true)) {
        d.fault = Fault::IpConfigBroken;
        d.detail = Fmt(L"'%ls' is connected but has %ls", a.name.c_str(), IpProblem(a));
        if (a.dhcp) Add(d, Act::RenewDhcp, w);
        RenewOtherBrokenLinks(o, d, w);
    } else if (a.gateway == 1) {
        d.fault = Fault::UpstreamOutage;
        d.userAction = true;
        d.detail = Fmt(L"the router on '%ls' (%ls) answers, but nothing beyond it does — "
                       L"waiting for the internet link to come back", a.name.c_str(),
                       a.gw.c_str());
        return true;
    } else if (a.gateway == 0) {
        d.fault = Fault::GatewayUnreachable;
        d.detail = Fmt(L"'%ls' is connected but its router (%ls) is not responding",
                       a.name.c_str(), a.gw.c_str());
        Add(d, Act::FlushArp, w);
        if (a.dhcp) Add(d, Act::RenewDhcp, w);
    } else {
        d.fault = Fault::Unknown;
        d.detail = Fmt(L"'%ls' is connected but there is no internet", a.name.c_str());
    }
    LinkRepairs(o, d, w);
    return true;
}

// Stopped services go first: nothing further down works without them.
void StartServicesFirst(const Observation& o, Diagnosis& d)
{
    if (o.stoppedServices.empty()) return;
    if (!d.plan.empty() && d.plan.front().act == Act::StartServices) return;
    d.plan.insert(d.plan.begin(), Step{ Act::StartServices, -1 });
}

Diagnosis DiagnoseOffline(const Observation& o)
{
    Diagnosis d;
    int route = RouteAdapter(o);

    // Traffic is routed into a tunnel while the network under it is fine:
    // the VPN is the problem, and no local repair can fix it.
    if (route >= 0 && o.adapters[(size_t)route].virt && AnyPhysicalGatewayAnswers(o)) {
        d.fault = Fault::VpnDown;
        d.adapter = route;
        d.userAction = true;
        d.detail = Fmt(L"all traffic is routed into '%ls', which is not passing it — the "
                       L"local network is fine; reconnect or quit the VPN",
                       o.adapters[(size_t)route].name.c_str());
        return d;
    }

    // A physical adapter holds the default route: walk it outward.
    int path = route >= 0 && !o.adapters[(size_t)route].virt ? route : -1;
    if (path >= 0) {
        const AdapterObs& a = o.adapters[(size_t)path];
        d.adapter = path;
        if (a.kind == Kind::Wifi && !a.media) {
            // Routing table still points at Wi-Fi, but the association is gone.
            DiagnoseWifi(o, d);
        } else if (IpBroken(a, false)) {
            d.fault = Fault::IpConfigBroken;
            d.detail = Fmt(L"'%ls' has %ls", a.name.c_str(), IpProblem(a));
            if (a.dhcp) Add(d, Act::RenewDhcp, path);
            RenewOtherBrokenLinks(o, d, path);
            LinkRepairs(o, d, path);
        } else if (a.gateway == 1) {
            d.fault = Fault::UpstreamOutage;
            d.userAction = true;
            d.detail = Fmt(L"the router on '%ls' (%ls) answers, but nothing beyond it does — "
                           L"waiting for the internet link to come back", a.name.c_str(),
                           a.gw.c_str());
            // Another saved Wi-Fi network may have its own, working uplink —
            // but give a router reboot a few minutes before moving away.
            if (a.kind == Kind::Wifi && o.allowFailover && o.failStreak >= 2 &&
                o.wifi.knownInRange > 1)
                Add(d, Act::SwitchNetwork);
        } else if (a.gateway == 0) {
            d.fault = Fault::GatewayUnreachable;
            d.detail = Fmt(L"'%ls' has link but its router (%ls) is not responding",
                           a.name.c_str(), a.gw.c_str());
            Add(d, Act::FlushArp, path);
            if (a.dhcp) Add(d, Act::RenewDhcp, path);
            LinkRepairs(o, d, path);
        } else {
            d.fault = Fault::Unknown;
            d.detail = Fmt(L"no internet through '%ls', and its router could not be tested",
                           a.name.c_str());
            if (a.dhcp) Add(d, Act::RenewDhcp, path);
            LinkRepairs(o, d, path);
        }
        StartServicesFirst(o, d);
        return d;
    }

    // No usable route at all.
    if (!o.disabledServices.empty() || !o.stoppedServices.empty()) {
        d.fault = Fault::ServiceStopped;
        if (!o.disabledServices.empty()) {
            d.userAction = true;
            d.detail = Fmt(L"%ls %ls disabled — networking cannot work without %ls",
                           Join(o.disabledServices).c_str(),
                           o.disabledServices.size() == 1 ? L"is" : L"are",
                           o.disabledServices.size() == 1 ? L"it" : L"them");
        } else {
            d.detail = Fmt(L"%ls %ls stopped", Join(o.stoppedServices).c_str(),
                           o.stoppedServices.size() == 1 ? L"is" : L"are");
        }
        if (!o.stoppedServices.empty()) {
            Add(d, Act::StartServices);
            if (o.wifi.hardware) AddReconnect(d);
        }
        return d;
    }

    // A wired link that did not get a working address.
    int eth = PickAdapter(o, Kind::Ethernet);
    if (eth >= 0) {
        const AdapterObs& a = o.adapters[(size_t)eth];
        if (a.hasIf && a.media && a.dev != Dev::Disabled && a.dev != Dev::Failed &&
            IpBroken(a, false)) {
            d.fault = Fault::IpConfigBroken;
            d.adapter = eth;
            d.detail = Fmt(L"'%ls' has link but %ls", a.name.c_str(), IpProblem(a));
            if (a.dhcp) Add(d, Act::RenewDhcp, eth);
            RenewOtherBrokenLinks(o, d, eth);
            if (o.wifi.hardware && !o.wifi.associated) Add(d, Act::ConnectWifi);
            Add(d, Act::ResetAdapter, eth);
            return d;
        }
    }

    // With WLAN AutoConfig disabled, Wi-Fi is off the table: a wired
    // adapter is then the only way back and gets the diagnosis.
    if (!o.wifi.serviceDisabled && DiagnoseWifi(o, d)) return d;
    if (o.wifi.hardware && o.wifi.serviceDisabled && eth < 0) {
        d.fault = Fault::ServiceStopped;
        d.userAction = true;
        d.detail = L"WLAN AutoConfig is disabled — Wi-Fi cannot work without it";
        return d;
    }

    // A Wi-Fi adapter that was here recently has vanished — typically a USB
    // dongle that dropped off the bus. A hardware rescan often brings it back.
    if (o.wifi.expected && !o.wifi.hardware) {
        d.fault = Fault::AdapterMissing;
        d.detail = L"the Wi-Fi adapter has disappeared (unplugged, or dropped off the USB bus)";
        Add(d, Act::RescanDevices);
        Add(d, Act::RestartWlanSvc);
        AddReconnect(d);
        return d;
    }

    if (eth >= 0) {
        const AdapterObs& a = o.adapters[(size_t)eth];
        if (DeviceFault(o, eth, d)) return d;
        if (!a.media) {
            // The link may be in a disabled sibling port.
            int dis = FindDisabled(o, Kind::Ethernet);
            if (dis >= 0 && dis != eth) {
                DeviceFault(o, dis, d);
                return d;
            }
            d.fault = Fault::CableUnplugged;
            d.adapter = eth;
            d.userAction = true;
            d.detail = Fmt(L"the network cable on '%ls' is unplugged (or its link is down)",
                           a.name.c_str());
            // A NIC whose link state wedged comes back with one reset;
            // for a genuinely unplugged cable, one attempt per outage is enough.
            if (o.failStreak <= 1) Add(d, Act::ResetAdapter, eth);
            return d;
        }
        d.fault = Fault::Unknown;
        d.adapter = eth;
        d.detail = Fmt(L"'%ls' is connected to a network with no route to the internet "
                       L"(no default gateway)", a.name.c_str());
        if (a.dhcp) Add(d, Act::RenewDhcp, eth);
        return d;
    }

    d.fault = Fault::AdapterMissing;
    d.userAction = true;
    d.detail = L"no usable network adapter is present — is it unplugged, or disabled in the "
               L"firmware?";
    Add(d, Act::RescanDevices);
    return d;
}

} // namespace

Diagnosis Diagnose(const Observation& o)
{
    const ProbeObs& p = o.probe;
    Diagnosis d;

    if (p.httpOk) {
        if (p.clockKnown && Abs(p.clockSkew) >= kClockSkewLimitSec) {
            d.fault = Fault::ClockSkew;
            d.detail = Fmt(L"the system clock is %ls by %ls — secure (HTTPS) sites will "
                           L"fail certificate checks", p.clockSkew > 0 ? L"ahead" : L"behind",
                           DurationText(p.clockSkew).c_str());
            Add(d, Act::ResyncClock);
            return d;
        }
        d.fault = Fault::None;
        return d;
    }

    if (p.httpAnswered) {
        d.fault = Fault::CaptivePortal;
        d.userAction = true;
        d.detail = L"a sign-in page is intercepting web traffic — sign in to the network "
                   L"in your browser";
        return d;
    }

    if (p.pingOk || p.tcpOk) {
        // The internet answers by IP, so the link, router and ISP are fine:
        // only the layers above IP are broken — no hardware reset can help.
        int route = RouteAdapter(o);
        if (p.proxyOn && (p.proxyDead || p.directOk)) {
            d.fault = Fault::ProxyDead;
            if (p.proxyDead) {
                d.detail = Fmt(L"web traffic is sent to the proxy %ls, but nothing is "
                               L"listening there (a proxy or debugging tool that exited?)",
                               p.proxy.c_str());
                Add(d, Act::DisableProxy);
            } else {
                d.userAction = true;
                d.detail = Fmt(L"direct connections work, but the configured proxy %ls "
                               L"does not — check the proxy settings", p.proxy.c_str());
            }
            return d;
        }
        if (!p.dnsOk) {
            d.fault = Fault::DnsBroken;
            Add(d, Act::FlushDns);
            if (route >= 0) {
                const AdapterObs& a = o.adapters[(size_t)route];
                d.adapter = route;
                bool allDead = a.dnsServers > 0 && a.dnsDead >= a.dnsServers;
                if (allDead && a.staticDns) {
                    d.userAction = true;
                    d.detail = Fmt(L"the DNS server%ls set by hand on '%ls' %ls not answering "
                                   L"— fix or remove %ls (the internet itself is reachable)",
                                   a.dnsServers == 1 ? L"" : L"s", a.name.c_str(),
                                   a.dnsServers == 1 ? L"is" : L"are",
                                   a.dnsServers == 1 ? L"it" : L"them");
                } else if (allDead || a.dnsServers == 0) {
                    d.detail = a.dnsServers == 0
                        ? Fmt(L"'%ls' has no DNS servers", a.name.c_str())
                        : Fmt(L"the DNS server%ls handed out on '%ls' %ls not answering",
                              a.dnsServers == 1 ? L"" : L"s", a.name.c_str(),
                              a.dnsServers == 1 ? L"is" : L"are");
                    if (a.dhcp && !a.virt) Add(d, Act::RenewDhcp, route);
                    else d.userAction = true;
                } else {
                    d.detail = L"names are not resolving although the internet is reachable";
                }
            } else {
                d.detail = L"names are not resolving although the internet is reachable";
            }
            if (!p.dnsPublicOk) d.detail += L" (public DNS is unreachable too)";
            return d;
        }
        d.fault = Fault::WebBlocked;
        d.userAction = true;
        d.detail = L"the internet answers and names resolve, but web requests fail — a "
                   L"firewall, filter or security tool may be blocking them";
        Add(d, Act::FlushDns); // a stale cached record pointing at a dead address
        return d;
    }

    return DiagnoseOffline(o);
}

// ---------------------------------------------------------------- names

const wchar_t* FaultName(Fault f)
{
    switch (f) {
    case Fault::None:               return L"Online";
    case Fault::ClockSkew:          return L"System clock is wrong";
    case Fault::CaptivePortal:      return L"Captive portal";
    case Fault::ProxyDead:          return L"Proxy not working";
    case Fault::DnsBroken:          return L"DNS not resolving";
    case Fault::WebBlocked:         return L"Web traffic blocked";
    case Fault::VpnDown:            return L"VPN not passing traffic";
    case Fault::UpstreamOutage:     return L"ISP / router outage";
    case Fault::AirplaneMode:       return L"Airplane mode is on";
    case Fault::RadioSwitchOff:     return L"Wi-Fi switch is off";
    case Fault::ServiceStopped:     return L"Network service stopped";
    case Fault::AdapterDisabled:    return L"Adapter disabled";
    case Fault::AdapterFailed:      return L"Adapter driver problem";
    case Fault::AdapterMissing:     return L"Network adapter missing";
    case Fault::RadioOff:           return L"Wi-Fi radio off";
    case Fault::WifiAuthFailed:     return L"Wi-Fi password rejected";
    case Fault::NoKnownNetwork:     return L"No saved network in range";
    case Fault::WifiDisconnected:   return L"Wi-Fi not connected";
    case Fault::CableUnplugged:     return L"Network cable unplugged";
    case Fault::IpConfigBroken:     return L"No valid IP address";
    case Fault::GatewayUnreachable: return L"Router not responding";
    default:                        return L"No internet";
    }
}

const wchar_t* ActName(Act a)
{
    switch (a) {
    case Act::StartServices:  return L"start stopped network services";
    case Act::EnableAdapter:  return L"enable the adapter";
    case Act::RescanDevices:  return L"rescan for hardware changes";
    case Act::RadioOn:        return L"switch the Wi-Fi radio on";
    case Act::ConnectWifi:    return L"connect Wi-Fi";
    case Act::Reassociate:    return L"reconnect Wi-Fi from scratch";
    case Act::SwitchNetwork:  return L"switch to another saved network";
    case Act::RenewDhcp:      return L"renew the DHCP lease";
    case Act::FlushArp:       return L"flush the ARP cache";
    case Act::FlushDns:       return L"flush the DNS cache";
    case Act::DisableProxy:   return L"turn off the dead proxy";
    case Act::ResetAdapter:   return L"reset the adapter driver";
    case Act::RestartWlanSvc: return L"restart the WLAN service";
    case Act::ResyncClock:    return L"resync the system clock";
    default:                  return L"?";
    }
}

const wchar_t* ActKey(Act a)
{
    switch (a) {
    case Act::StartServices:  return L"start-services";
    case Act::EnableAdapter:  return L"enable-adapter";
    case Act::RescanDevices:  return L"rescan-devices";
    case Act::RadioOn:        return L"radio-on";
    case Act::ConnectWifi:    return L"connect-wifi";
    case Act::Reassociate:    return L"reassociate";
    case Act::SwitchNetwork:  return L"switch-network";
    case Act::RenewDhcp:      return L"renew-dhcp";
    case Act::FlushArp:       return L"flush-arp";
    case Act::FlushDns:       return L"flush-dns";
    case Act::DisableProxy:   return L"disable-proxy";
    case Act::ResetAdapter:   return L"reset-adapter";
    case Act::RestartWlanSvc: return L"restart-wlansvc";
    case Act::ResyncClock:    return L"resync-clock";
    default:                  return L"unknown";
    }
}

bool ActIsHeavy(Act a)
{
    return a == Act::ResetAdapter || a == Act::RestartWlanSvc;
}

bool ActNeedsAdmin(Act a)
{
    switch (a) {
    case Act::StartServices:
    case Act::EnableAdapter:
    case Act::RescanDevices:
    case Act::RenewDhcp:
    case Act::FlushArp:
    case Act::ResetAdapter:
    case Act::RestartWlanSvc:
    case Act::ResyncClock:
        return true;
    default:
        return false;
    }
}

// ---------------------------------------------------------------- execution

PlanRun RunPlan(const std::vector<Step>& plan, std::set<std::wstring>& done,
                const std::function<std::wstring(const Step&)>& key,
                const std::function<bool()>& stopped,
                const std::function<bool(const Step&)>& execute,
                const std::function<Verdict(const Step&)>& verify)
{
    PlanRun r;
    int pending = -1;   // step whose ConnectWifi follow-up is still to run
    for (size_t i = 0; i < plan.size(); ++i) {
        if (stopped()) {
            r.aborted = true;
            break;
        }
        const Step& s = plan[i];
        // Completing a step that did not run: nothing new to try.
        if (s.completes && pending < 0) continue;
        bool followUp = s.completes;
        if (s.act != Act::ConnectWifi && !done.insert(key(s)).second) continue;
        bool ran = execute(s);
        if (!ran && !followUp) continue;
        r.acted = r.acted || ran;
        if (!s.completes && i + 1 < plan.size() && plan[i + 1].completes) {
            pending = (int)i;   // verify after the reconnect, not before
            continue;
        }
        size_t principal = followUp ? (size_t)pending : i;
        pending = -1;
        Verdict v = verify(plan[principal]);
        if (v == Verdict::Fixed) {
            r.fixedBy = (int)principal;
            break;
        }
        if (v == Verdict::Abort) {
            r.aborted = true;
            break;
        }
    }
    return r;
}

// ---------------------------------------------------------------- helpers

std::wstring DurationText(long long s)
{
    s = Abs(s);
    if (s < 90) return Fmt(L"%lld s", s);
    long long m = s / 60;
    if (m < 90) return Fmt(L"%lld min", m);
    long long h = m / 60;
    if (h < 48) return m % 60 ? Fmt(L"%lld h %lld min", h, m % 60) : Fmt(L"%lld h", h);
    long long days = h / 24;
    if (days < 730) return Fmt(L"%lld days", days);
    return Fmt(L"%lld years", days / 365);
}

WlanFail ClassifyWlanReason(uint32_t code)
{
    if (code == 0) return WlanFail::None;
    // L2 reason-code groups (l2cmn.h), 0x10000 apart: 0x20000 802.11 auto-
    // config, 0x30000 802.11 MSM (association), 0x40000 802.11 security,
    // 0x50000 802.1X, 0x80000 profile.
    switch (code & 0xFFFF0000u) {
    case 0x40000u:
    case 0x50000u: return WlanFail::Security;
    case 0x30000u: return WlanFail::Association;
    case 0x80000u: return WlanFail::Profile;
    default:       return WlanFail::Other;
    }
}

std::vector<uint8_t> BuildDnsQuery(uint16_t id, const std::string& host)
{
    std::vector<uint8_t> q = {
        uint8_t(id >> 8), uint8_t(id & 0xFF),
        0x01, 0x00,             // standard query, recursion desired
        0x00, 0x01,             // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    size_t start = 0;
    while (start < host.size()) {
        size_t dot = host.find('.', start);
        if (dot == std::string::npos) dot = host.size();
        size_t len = dot - start;
        if (len == 0 || len > 63) return {};
        q.push_back(uint8_t(len));
        q.insert(q.end(), host.begin() + (std::ptrdiff_t)start, host.begin() + (std::ptrdiff_t)dot);
        start = dot + 1;
    }
    if (q.size() == 12 || q.size() - 12 > 254) return {}; // empty or overlong name
    q.push_back(0);             // root label
    q.push_back(0x00); q.push_back(0x01);   // QTYPE  A
    q.push_back(0x00); q.push_back(0x01);   // QCLASS IN
    return q;
}

int ParseDnsReply(const uint8_t* p, size_t n, uint16_t id, int* answers)
{
    if (!p || n < 12) return -1;
    if ((uint16_t)((p[0] << 8) | p[1]) != id) return -1;
    if (!(p[2] & 0x80)) return -1;          // not a response
    if ((p[2] >> 3) & 0x0F) return -1;      // not a standard query
    if (answers) *answers = (p[6] << 8) | p[7];
    return p[3] & 0x0F;                     // RCODE
}

namespace {

std::wstring Trim(const std::wstring& s)
{
    size_t b = 0, e = s.size();
    while (b < e && std::iswspace((wint_t)s[b])) ++b;
    while (e > b && std::iswspace((wint_t)s[e - 1])) --e;
    return s.substr(b, e - b);
}

std::wstring LowerW(std::wstring s)
{
    for (auto& c : s) c = (wchar_t)std::towlower((wint_t)c);
    return s;
}

bool ParsePort(const std::wstring& s, unsigned& port)
{
    if (s.empty() || s.size() > 5) return false;
    unsigned v = 0;
    for (wchar_t c : s) {
        if (c < L'0' || c > L'9') return false;
        v = v * 10 + (unsigned)(c - L'0');
    }
    if (v == 0 || v > 65535) return false;
    port = v;
    return true;
}

bool ParseEndpoint(std::wstring s, ProxyEndpoint& out)
{
    s = Trim(s);
    size_t scheme = s.find(L"://");
    if (scheme != std::wstring::npos) s = s.substr(scheme + 3);
    size_t slash = s.find(L'/');
    if (slash != std::wstring::npos) s = s.substr(0, slash);
    if (s.empty()) return false;
    std::wstring host;
    unsigned port = 80;                     // WinINET's default proxy port
    if (s[0] == L'[') {
        size_t close = s.find(L']');
        if (close == std::wstring::npos || close == 1) return false;
        host = s.substr(1, close - 1);
        std::wstring rest = s.substr(close + 1);
        if (!rest.empty() && (rest[0] != L':' || !ParsePort(rest.substr(1), port)))
            return false;
    } else {
        size_t colon = s.find(L':');
        if (colon == std::wstring::npos) {
            host = s;
        } else {
            if (s.find(L':', colon + 1) != std::wstring::npos) return false; // bare IPv6
            host = s.substr(0, colon);
            if (!ParsePort(s.substr(colon + 1), port)) return false;
        }
    }
    if (host.empty()) return false;
    out.host = host;
    out.port = port;
    return true;
}

} // namespace

bool PickHttpProxy(const std::wstring& spec, ProxyEndpoint& out)
{
    // Entries separated by ';' (or whitespace); "proto=endpoint" or a bare
    // endpoint used for every protocol. Plain HTTP uses http=, then the bare
    // entry; https= is the fallback since browsers mostly speak HTTPS.
    std::wstring http, bare, https;
    size_t i = 0;
    while (i < spec.size()) {
        size_t j = spec.find_first_of(L"; \t", i);
        if (j == std::wstring::npos) j = spec.size();
        std::wstring entry = Trim(spec.substr(i, j - i));
        i = j + 1;
        if (entry.empty()) continue;
        size_t eq = entry.find(L'=');
        if (eq == std::wstring::npos) {
            if (bare.empty()) bare = entry;
            continue;
        }
        std::wstring proto = LowerW(Trim(entry.substr(0, eq)));
        std::wstring ep = entry.substr(eq + 1);
        if (proto == L"http" && http.empty()) http = ep;
        else if (proto == L"https" && https.empty()) https = ep;
    }
    const std::wstring& pick = !http.empty() ? http : !bare.empty() ? bare : https;
    return !pick.empty() && ParseEndpoint(pick, out);
}

bool IsLoopbackHost(const std::wstring& host)
{
    std::wstring h = LowerW(Trim(host));
    if (!h.empty() && h.front() == L'[' && h.back() == L']') h = h.substr(1, h.size() - 2);
    return h == L"localhost" || h == L"localhost." || h.rfind(L"127.", 0) == 0 ||
           h == L"::1" || h == L"0:0:0:0:0:0:0:1";
}

// ---------------------------------------------------------------- task xml

std::wstring XmlEscape(const std::wstring& s)
{
    std::wstring o;
    o.reserve(s.size());
    for (wchar_t c : s) {
        switch (c) {
        case L'&':  o += L"&amp;";  break;
        case L'<':  o += L"&lt;";   break;
        case L'>':  o += L"&gt;";   break;
        case L'"':  o += L"&quot;"; break;
        case L'\'': o += L"&apos;"; break;
        default:
            if (c >= 0x20 || c == L'\t' || c == L'\r' || c == L'\n') o += c; // XML 1.0 chars
            break;
        }
    }
    return o;
}

std::wstring TaskDescription()
{
    return L"Starts the NetVigil connectivity watchdog hidden in the tray at sign-in and "
           L"relaunches it if it stops. [format " + std::to_wstring(kTaskFormat) + L"]";
}

int TaskFormatOf(const std::wstring& description)
{
    size_t p = description.find(L"[format ");
    if (p == std::wstring::npos) return 1;
    int v = 0;
    for (size_t i = p + 8; i < description.size() && std::iswdigit((wint_t)description[i]); ++i)
        v = v * 10 + (description[i] - L'0');
    return v > 0 ? v : 1;
}

std::wstring BuildTaskXml(const TaskSpec& s)
{
    std::wstring x;
    x += L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
         L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
         L"  <RegistrationInfo>\r\n"
         L"    <Author>NetVigil</Author>\r\n";
    x += L"    <Description>" + XmlEscape(TaskDescription()) + L"</Description>\r\n";
    x += L"  </RegistrationInfo>\r\n"
         L"  <Triggers>\r\n"
         L"    <LogonTrigger>\r\n";
    if (s.relaunchMin) {
        // While the watchdog runs, IgnoreNew makes each repetition a no-op;
        // if it crashed or was killed, the next one starts it again.
        x += L"      <Repetition>\r\n"
             L"        <Interval>PT" + std::to_wstring(s.relaunchMin) + L"M</Interval>\r\n"
             L"        <StopAtDurationEnd>false</StopAtDurationEnd>\r\n"
             L"      </Repetition>\r\n";
    }
    x += L"      <Enabled>true</Enabled>\r\n";
    if (!s.userId.empty())
        x += L"      <UserId>" + XmlEscape(s.userId) + L"</UserId>\r\n";
    x += L"      <Delay>PT" + std::to_wstring(s.logonDelaySec) + L"S</Delay>\r\n"
         L"    </LogonTrigger>\r\n"
         L"  </Triggers>\r\n"
         L"  <Principals>\r\n"
         L"    <Principal id=\"Author\">\r\n";
    if (!s.userId.empty())
        x += L"      <UserId>" + XmlEscape(s.userId) + L"</UserId>\r\n";
    x += L"      <LogonType>InteractiveToken</LogonType>\r\n"
         L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
         L"    </Principal>\r\n"
         L"  </Principals>\r\n"
         // Unlike schtasks /SC ONLOGON defaults: start and keep running on
         // battery, and no 3-day execution limit that would kill a watchdog
         // on a machine that sleeps instead of logging off.
         L"  <Settings>\r\n"
         L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
         L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
         L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
         L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
         L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
         L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
         L"    <IdleSettings>\r\n"
         L"      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n"
         L"      <RestartOnIdle>false</RestartOnIdle>\r\n"
         L"    </IdleSettings>\r\n"
         L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
         L"    <Enabled>true</Enabled>\r\n"
         L"    <Hidden>false</Hidden>\r\n"
         L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n"
         L"    <WakeToRun>false</WakeToRun>\r\n"
         L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n"
         L"    <Priority>6</Priority>\r\n"
         L"    <RestartOnFailure>\r\n"
         L"      <Interval>PT1M</Interval>\r\n"
         L"      <Count>3</Count>\r\n"
         L"    </RestartOnFailure>\r\n"
         L"  </Settings>\r\n"
         L"  <Actions Context=\"Author\">\r\n"
         L"    <Exec>\r\n";
    x += L"      <Command>" + XmlEscape(s.command) + L"</Command>\r\n";
    if (!s.arguments.empty())
        x += L"      <Arguments>" + XmlEscape(s.arguments) + L"</Arguments>\r\n";
    if (!s.workDir.empty())
        x += L"      <WorkingDirectory>" + XmlEscape(s.workDir) + L"</WorkingDirectory>\r\n";
    x += L"    </Exec>\r\n"
         L"  </Actions>\r\n"
         L"</Task>\r\n";
    return x;
}

} // namespace nv
