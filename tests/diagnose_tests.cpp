// diagnose_tests.cpp — unit tests for NetVigil's platform-independent
// decision logic (src/diagnose.cpp). Build and run from the repo root:
//
//   Windows:  build.bat test
//   Linux:    g++ -std=c++17 -Wall -Wextra -Isrc tests/diagnose_tests.cpp
//                 src/diagnose.cpp -o diagnose_tests && ./diagnose_tests
//
// An optional argument writes a sample startup-task XML (UTF-16LE + BOM,
// exactly what gets registered) to that path for schema/lint checks.

#define _CRT_SECURE_NO_WARNINGS // plain fopen, portable
#include "diagnose.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace nv;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (cond) ++g_pass;                                                     \
        else {                                                                  \
            ++g_fail;                                                           \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                       \
    } while (0)

// ---------------------------------------------------------------- fixtures

static AdapterObs WifiAd(const wchar_t* name = L"Wi-Fi")
{
    AdapterObs a;
    a.name = name;
    a.id = L"{11111111-1111-1111-1111-111111111111}";
    a.kind = Kind::Wifi;
    a.dev = Dev::Ok;
    a.up = a.media = a.dhcp = a.hasIpv4 = a.hasGateway = true;
    a.gw = L"192.168.1.1";
    a.dnsServers = 1;
    return a;
}

static AdapterObs EthAd(const wchar_t* name = L"Ethernet")
{
    AdapterObs a;
    a.name = name;
    a.id = L"{22222222-2222-2222-2222-222222222222}";
    a.kind = Kind::Ethernet;
    a.dev = Dev::Ok;
    a.up = a.media = a.dhcp = a.hasIpv4 = a.hasGateway = true;
    a.gw = L"10.0.0.1";
    a.dnsServers = 2;
    return a;
}

static AdapterObs VpnAd()
{
    AdapterObs a;
    a.name = L"WireGuard Tunnel";
    a.kind = Kind::Other;
    a.virt = true;
    a.up = a.media = a.hasIpv4 = a.hasGateway = true;
    return a;
}

// A laptop on Wi-Fi: associated, routing, no internet. Tests flip fields.
static Observation WifiLaptop()
{
    Observation o;
    o.wifi.hardware = o.wifi.expected = true;
    o.wifi.interfaces = 1;
    o.wifi.associated = true;
    o.wifi.visible = 6;
    o.wifi.knownInRange = 1;
    o.adapters.push_back(WifiAd());
    o.adapters[0].routesInternet = true;
    o.failStreak = 1;
    return o;
}

// A desktop on Ethernet only.
static Observation Desktop()
{
    Observation o;
    o.adapters.push_back(EthAd());
    o.adapters[0].routesInternet = true;
    o.failStreak = 1;
    return o;
}

static int IndexOf(const Diagnosis& d, Act a, int from = 0)
{
    for (size_t i = (size_t)from; i < d.plan.size(); ++i)
        if (d.plan[i].act == a) return (int)i;
    return -1;
}

static bool Has(const Diagnosis& d, Act a) { return IndexOf(d, a) >= 0; }

static bool AnyHeavy(const Diagnosis& d)
{
    for (const auto& s : d.plan)
        if (ActIsHeavy(s.act)) return true;
    return false;
}

// Properties every diagnosis must satisfy.
static void CheckInvariants(const Observation& o, const Diagnosis& d)
{
    for (const auto& s : d.plan)
        CHECK(s.adapter >= -1 && s.adapter < (int)o.adapters.size());
    // A completing reconnect always follows the step it completes.
    for (size_t i = 0; i < d.plan.size(); ++i)
        if (d.plan[i].completes)
            CHECK(i > 0 && d.plan[i].act == Act::ConnectWifi && !d.plan[i - 1].completes);
    CHECK(d.adapter >= -1 && d.adapter < (int)o.adapters.size());
    CHECK(d.fault == Fault::None || !d.detail.empty());
    // Faults a hardware reset cannot fix must never plan one.
    switch (d.fault) {
    case Fault::None: case Fault::ClockSkew: case Fault::CaptivePortal:
    case Fault::ProxyDead: case Fault::DnsBroken: case Fault::WebBlocked:
    case Fault::VpnDown: case Fault::UpstreamOutage: case Fault::AirplaneMode:
    case Fault::RadioSwitchOff: case Fault::NoKnownNetwork: case Fault::ServiceStopped:
        CHECK(!AnyHeavy(d));
        break;
    default:
        break;
    }
    // Cheap before heavy.
    int firstHeavy = -1;
    for (size_t i = 0; i < d.plan.size(); ++i)
        if (ActIsHeavy(d.plan[i].act)) { firstHeavy = (int)i; break; }
    if (firstHeavy >= 0)
        for (int i = firstHeavy; i < (int)d.plan.size(); ++i)
            CHECK(d.plan[(size_t)i].act != Act::FlushArp && d.plan[(size_t)i].act != Act::FlushDns &&
                  d.plan[(size_t)i].act != Act::RenewDhcp);
}

static Diagnosis Run(const Observation& o)
{
    Diagnosis d = Diagnose(o);
    CheckInvariants(o, d);
    return d;
}

// ---------------------------------------------------------------- online side

static void TestOnline()
{
    Observation o = WifiLaptop();
    o.probe.httpOk = true;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::None);
    CHECK(d.plan.empty());

    o.probe.clockKnown = true;
    o.probe.clockSkew = 600;                 // 10 min: tolerated
    CHECK(Run(o).fault == Fault::None);
    o.probe.clockSkew = -3 * 86400;          // 3 days behind
    d = Run(o);
    CHECK(d.fault == Fault::ClockSkew);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::ResyncClock);
    CHECK(d.detail.find(L"behind by 3 days") != std::wstring::npos);
}

static void TestPortal()
{
    Observation o = WifiLaptop();
    o.probe.httpAnswered = true;
    o.probe.pingOk = true;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::CaptivePortal);
    CHECK(d.userAction);
    CHECK(d.plan.empty());
}

// ---------------------------------------------------------------- above IP

static void TestDns()
{
    Observation o = WifiLaptop();
    o.probe.pingOk = true;
    o.probe.dnsOk = false;
    o.probe.dnsPublicOk = true;
    o.adapters[0].dnsDead = 1;               // the router's DNS is dead
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::DnsBroken);
    CHECK(IndexOf(d, Act::FlushDns) == 0);
    CHECK(IndexOf(d, Act::RenewDhcp) == 1 && d.plan[1].adapter == 0);
    CHECK(!d.userAction);

    o.adapters[0].staticDns = true;          // typed in by hand: tell the user
    d = Run(o);
    CHECK(d.fault == Fault::DnsBroken);
    CHECK(d.userAction);
    CHECK(!Has(d, Act::RenewDhcp));

    o.adapters[0].staticDns = false;
    o.adapters[0].dnsDead = 0;               // servers alive: resolver problem
    o.probe.dnsPublicOk = false;
    d = Run(o);
    CHECK(d.fault == Fault::DnsBroken);
    CHECK(d.plan.size() == 1);
    CHECK(d.detail.find(L"public DNS") != std::wstring::npos);

    // ICMP filtered but TCP gets through: still "above IP", never a reset.
    o = WifiLaptop();
    o.probe.tcpOk = true;
    o.probe.dnsOk = false;
    CHECK(Run(o).fault == Fault::DnsBroken);
}

static void TestProxyAndWeb()
{
    Observation o = WifiLaptop();
    o.probe.pingOk = true;
    o.probe.proxyOn = true;
    o.probe.proxy = L"127.0.0.1:8888";
    o.probe.proxyDead = true;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::ProxyDead);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::DisableProxy);

    o.probe.proxyDead = false;               // remote proxy, direct works
    o.probe.directOk = true;
    o.probe.proxy = L"proxy.corp:3128";
    d = Run(o);
    CHECK(d.fault == Fault::ProxyDead);
    CHECK(d.userAction && d.plan.empty());

    o.probe.directOk = false;                // proxy fine, web blocked
    d = Run(o);
    CHECK(d.fault == Fault::WebBlocked);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::FlushDns);
}

// ---------------------------------------------------------------- beyond the LAN

static void TestVpn()
{
    Observation o = WifiLaptop();
    o.adapters[0].routesInternet = false;
    o.adapters[0].gateway = 1;
    o.adapters.push_back(VpnAd());
    o.adapters[1].routesInternet = true;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::VpnDown);
    CHECK(d.adapter == 1);
    CHECK(d.plan.empty() && d.userAction);

    // The network under the VPN is down too: fix that, not the VPN.
    o.adapters[0].gateway = 0;
    d = Run(o);
    CHECK(d.fault == Fault::GatewayUnreachable);
    CHECK(d.adapter == 0);
    CHECK(Has(d, Act::ResetAdapter));
}

static void TestUpstream()
{
    Observation o = WifiLaptop();
    o.adapters[0].gateway = 1;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::UpstreamOutage);
    CHECK(d.plan.empty());                   // first round: wait, don't flap

    o.failStreak = 2;
    o.wifi.knownInRange = 2;
    d = Run(o);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::SwitchNetwork);

    o.allowFailover = false;
    CHECK(Run(o).plan.empty());
    o.allowFailover = true;
    o.wifi.knownInRange = 1;                 // nowhere else to go
    CHECK(Run(o).plan.empty());

    Observation e = Desktop();
    e.adapters[0].gateway = 1;
    e.failStreak = 5;
    d = Run(e);
    CHECK(d.fault == Fault::UpstreamOutage);
    CHECK(d.plan.empty());                   // wired: nothing to switch to
}

// ---------------------------------------------------------------- local network

static void TestGateway()
{
    Observation o = WifiLaptop();
    o.adapters[0].gateway = 0;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::GatewayUnreachable);
    CHECK(IndexOf(d, Act::FlushArp) == 0);
    CHECK(IndexOf(d, Act::RenewDhcp) == 1);
    CHECK(IndexOf(d, Act::Reassociate) == 2);
    CHECK(IndexOf(d, Act::ResetAdapter) > IndexOf(d, Act::Reassociate));
    CHECK(IndexOf(d, Act::RestartWlanSvc) > IndexOf(d, Act::ResetAdapter));
    CHECK(IndexOf(d, Act::ConnectWifi, IndexOf(d, Act::ResetAdapter)) > 0);

    // Wired machine: reset the NIC, never touch the WLAN service (the old
    // ladder restarted WlanSvc on Ethernet-only desktops).
    Observation e = Desktop();
    e.adapters[0].gateway = 0;
    d = Run(e);
    CHECK(d.fault == Fault::GatewayUnreachable);
    CHECK(Has(d, Act::FlushArp) && Has(d, Act::RenewDhcp));
    CHECK(Has(d, Act::ResetAdapter) && d.plan.back().adapter == 0);
    CHECK(!Has(d, Act::RestartWlanSvc) && !Has(d, Act::Reassociate) && !Has(d, Act::ConnectWifi));

    e.adapters[0].dhcp = false;              // static IP: nothing to renew
    CHECK(!Has(Run(e), Act::RenewDhcp));
}

static void TestIpConfig()
{
    Observation o = WifiLaptop();
    o.adapters[0].routesInternet = false;
    o.adapters[0].apipa = true;
    o.adapters[0].hasGateway = false;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::IpConfigBroken);
    CHECK(IndexOf(d, Act::RenewDhcp) == 0);
    CHECK(Has(d, Act::Reassociate) && Has(d, Act::ResetAdapter));
    CHECK(d.detail.find(L"169.254") != std::wstring::npos);

    o.adapters[0].apipa = false;             // lease without a gateway
    d = Run(o);
    CHECK(d.fault == Fault::IpConfigBroken);
    CHECK(d.detail.find(L"gateway") != std::wstring::npos);

    // Address conflict on the routing adapter.
    Observation e = Desktop();
    e.adapters[0].duplicate = true;
    d = Run(e);
    CHECK(d.fault == Fault::IpConfigBroken);
    CHECK(IndexOf(d, Act::RenewDhcp) == 0);
    CHECK(d.detail.find(L"conflicts") != std::wstring::npos);

    // Docked laptop: wired link stuck on APIPA, Wi-Fi idle — renew the wired
    // lease, then fall back to Wi-Fi before resetting the NIC.
    Observation dock = WifiLaptop();
    dock.adapters[0].routesInternet = false;
    dock.adapters[0].media = false;
    dock.wifi.associated = false;
    dock.adapters.push_back(EthAd());
    dock.adapters[1].apipa = true;
    dock.adapters[1].hasGateway = false;
    d = Run(dock);
    CHECK(d.fault == Fault::IpConfigBroken);
    CHECK(d.adapter == 1);
    CHECK(IndexOf(d, Act::RenewDhcp) == 0 && d.plan[0].adapter == 1);
    CHECK(IndexOf(d, Act::ConnectWifi) == 1);
    CHECK(IndexOf(d, Act::ResetAdapter) == 2 && d.plan[2].adapter == 1);

    // Router's DHCP server restarted: both links stranded — renew both.
    Observation both = dock;
    both.wifi.associated = true;
    both.adapters[0].media = true;
    both.adapters[0].apipa = true;
    d = Run(both);
    CHECK(d.fault == Fault::IpConfigBroken);
    CHECK(IndexOf(d, Act::RenewDhcp) == 0 && d.plan[0].adapter == 1);
    CHECK(IndexOf(d, Act::RenewDhcp, 1) == 1 && d.plan[1].adapter == 0);
    CHECK(!Has(d, Act::ConnectWifi) || IndexOf(d, Act::ConnectWifi) > 1);

    // A wired lab/NAS link without a gateway is legitimate: look at Wi-Fi.
    dock.adapters[1].apipa = false;
    d = Run(dock);
    CHECK(d.fault == Fault::WifiDisconnected);
    CHECK(d.adapter == 0);
}

// ---------------------------------------------------------------- services

static void TestServices()
{
    Observation o = WifiLaptop();
    o.adapters[0].routesInternet = false;
    o.adapters[0].media = false;
    o.wifi.associated = false;
    o.wifi.serviceStopped = true;
    o.wifi.interfaces = 0;               // WlanSvc down: no interfaces listed
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::ServiceStopped);
    CHECK(IndexOf(d, Act::StartServices) == 0);
    CHECK(IndexOf(d, Act::ConnectWifi) == 1 && d.plan[1].completes);
    CHECK(!d.userAction);

    // WLAN AutoConfig disabled on a Wi-Fi-only machine: the user must act.
    o.wifi.serviceStopped = false;
    o.wifi.serviceDisabled = true;
    d = Run(o);
    CHECK(d.fault == Fault::ServiceStopped);
    CHECK(d.userAction && d.plan.empty());

    // ...but on a desktop with an unused Wi-Fi card it must not hide a
    // wired fault ("debloated" WlanSvc + unplugged cable).
    Observation desk = Desktop();
    desk.adapters[0].routesInternet = false;
    desk.adapters[0].media = false;
    desk.adapters.push_back(WifiAd(L"Wi-Fi (unused)"));
    desk.adapters[1].media = false;
    desk.wifi.hardware = true;
    desk.wifi.serviceDisabled = true;
    d = Run(desk);
    CHECK(d.fault == Fault::CableUnplugged);
    CHECK(d.adapter == 0);

    o.wifi.serviceDisabled = false;
    o.wifi.interfaces = 1;
    o.disabledServices = { L"DHCP Client" };
    d = Run(o);
    CHECK(d.fault == Fault::ServiceStopped);
    CHECK(d.userAction && d.plan.empty());
    CHECK(d.detail.find(L"DHCP Client is disabled") != std::wstring::npos);

    // A path exists but a service is stopped: start it before anything else.
    Observation e = Desktop();
    e.adapters[0].gateway = 0;
    e.stoppedServices = { L"DHCP Client" };
    d = Run(e);
    CHECK(d.fault == Fault::GatewayUnreachable);
    CHECK(IndexOf(d, Act::StartServices) == 0);
}

// ---------------------------------------------------------------- Wi-Fi

static Observation Disconnected()
{
    Observation o = WifiLaptop();
    o.adapters[0].routesInternet = false;
    o.adapters[0].media = false;
    o.adapters[0].hasGateway = false;
    o.wifi.associated = false;
    return o;
}

static void TestWifiDevice()
{
    Observation o = Disconnected();
    o.adapters[0].dev = Dev::Disabled;
    o.adapters[0].hasIf = false;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::AdapterDisabled);
    CHECK(IndexOf(d, Act::EnableAdapter) == 0 && d.plan[0].adapter == 0);
    CHECK(IndexOf(d, Act::ConnectWifi) == 1);

    o.adapters[0].dev = Dev::Failed;
    o.adapters[0].problem = 43;
    d = Run(o);
    CHECK(d.fault == Fault::AdapterFailed);
    CHECK(IndexOf(d, Act::ResetAdapter) == 0);
    CHECK(Has(d, Act::RestartWlanSvc));
    CHECK(d.detail.find(L"43") != std::wstring::npos);

    o.adapters[0].problem = kProbNeedRestart;
    d = Run(o);
    CHECK(d.fault == Fault::AdapterFailed);
    CHECK(d.userAction && d.plan.empty());

    // Device fine, WlanSvc blind to it.
    o = Disconnected();
    o.wifi.interfaces = 0;
    d = Run(o);
    CHECK(d.fault == Fault::AdapterFailed);
    CHECK(IndexOf(d, Act::RestartWlanSvc) == 0);

    // A healthy second Wi-Fi adapter wins over a disabled one.
    o = Disconnected();
    o.adapters.push_back(WifiAd(L"Wi-Fi 2"));
    o.adapters[1].media = false;
    o.adapters[0].dev = Dev::Disabled;
    d = Run(o);
    CHECK(d.fault == Fault::WifiDisconnected);
    CHECK(d.adapter == 1);
}

static void TestWifiRadio()
{
    Observation o = Disconnected();
    o.wifi.radioSoftOff = true;
    o.wifi.airplane = true;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::AirplaneMode);
    CHECK(d.plan.empty() && d.userAction);   // respect it: never RadioOn

    o.wifi.radioSoftOff = false;             // Wi-Fi re-enabled in flight
    d = Run(o);
    CHECK(d.fault == Fault::WifiDisconnected);
    CHECK(!Has(d, Act::RadioOn));

    o.wifi.airplane = false;
    o.wifi.radioSoftOff = true;
    d = Run(o);
    CHECK(d.fault == Fault::RadioOff);
    CHECK(IndexOf(d, Act::RadioOn) == 0 && IndexOf(d, Act::ConnectWifi) == 1);

    o.wifi.radioHardOff = true;
    d = Run(o);
    CHECK(d.fault == Fault::RadioSwitchOff);
    CHECK(d.plan.empty());
}

static void TestWifiAssociation()
{
    Observation o = Disconnected();
    o.wifi.authFailed = L"HomeNet";
    o.wifi.knownInRange = 0;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::WifiAuthFailed);
    CHECK(d.userAction);
    CHECK(d.detail.find(L"HomeNet") != std::wstring::npos);
    // Early in the outage: try again, and give a wedged driver one reset.
    CHECK(IndexOf(d, Act::ConnectWifi) == 0 && !d.plan[0].completes);
    CHECK(IndexOf(d, Act::ResetAdapter) == 1 && d.plan[2].completes);
    CHECK(!Has(d, Act::RestartWlanSvc));
    o.failStreak = 3;                        // it survived a reset: the password
    d = Run(o);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::ConnectWifi);

    o = Disconnected();
    o.wifi.visible = 5;
    o.wifi.knownInRange = 0;
    d = Run(o);
    CHECK(d.fault == Fault::NoKnownNetwork);  // radio fine: no reset, but hidden
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::ConnectWifi);   // SSIDs may connect

    o.wifi.visible = 0;                      // sees nothing: radio suspect
    d = Run(o);
    CHECK(d.fault == Fault::WifiDisconnected);
    CHECK(IndexOf(d, Act::ConnectWifi) == 0);
    CHECK(Has(d, Act::ResetAdapter) && Has(d, Act::RestartWlanSvc));
    CHECK(d.detail.find(L"no Wi-Fi networks") != std::wstring::npos);

    o.wifi.visible = 4;
    o.wifi.knownInRange = 2;
    d = Run(o);
    CHECK(d.fault == Fault::WifiDisconnected);
    CHECK(IndexOf(d, Act::ConnectWifi) == 0);
}

static void TestMissingAndWired()
{
    // USB Wi-Fi dongle fell off the bus.
    Observation o;
    o.wifi.expected = true;
    Diagnosis d = Run(o);
    CHECK(d.fault == Fault::AdapterMissing);
    CHECK(IndexOf(d, Act::RescanDevices) == 0);
    CHECK(Has(d, Act::RestartWlanSvc));

    // Nothing at all.
    o.wifi.expected = false;
    d = Run(o);
    CHECK(d.fault == Fault::AdapterMissing);
    CHECK(d.userAction);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::RescanDevices);

    // Wired only, cable out: one NIC reset early in the outage, then leave it.
    Observation e = Desktop();
    e.adapters[0].routesInternet = false;
    e.adapters[0].media = false;
    e.adapters[0].up = false;
    d = Run(e);
    CHECK(d.fault == Fault::CableUnplugged);
    CHECK(d.userAction);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::ResetAdapter);
    e.failStreak = 4;
    CHECK(Run(e).plan.empty());

    // The cable is in a port that is disabled.
    e.adapters.push_back(EthAd(L"Ethernet 2"));
    e.adapters[1].dev = Dev::Disabled;
    e.adapters[1].hasIf = false;
    e.adapters[1].media = false;
    d = Run(e);
    CHECK(d.fault == Fault::AdapterDisabled);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::EnableAdapter && d.plan[0].adapter == 1);

    // Wired adapter with a failed driver.
    Observation f = Desktop();
    f.adapters[0].routesInternet = false;
    f.adapters[0].dev = Dev::Failed;
    f.adapters[0].problem = 10;
    d = Run(f);
    CHECK(d.fault == Fault::AdapterFailed);
    CHECK(d.plan.size() == 1 && d.plan[0].act == Act::ResetAdapter);

    // Ethernet with Wi-Fi hardware: an unplugged cable is not the fault.
    Observation g = Disconnected();
    g.adapters.push_back(EthAd());
    g.adapters[1].media = false;
    d = Run(g);
    CHECK(d.fault == Fault::WifiDisconnected);
}

static void TestNames()
{
    for (int f = 0; f < (int)Fault::Count; ++f)
        CHECK(FaultName((Fault)f)[0] != L'\0');
    for (int a = 0; a < (int)Act::Count; ++a) {
        CHECK(std::wcscmp(ActName((Act)a), L"?") != 0);
        CHECK(std::wcscmp(ActKey((Act)a), L"unknown") != 0);
        for (int b = 0; b < a; ++b)
            CHECK(std::wcscmp(ActKey((Act)a), ActKey((Act)b)) != 0);
    }
    CHECK(ActIsHeavy(Act::ResetAdapter) && ActIsHeavy(Act::RestartWlanSvc));
    CHECK(!ActIsHeavy(Act::RenewDhcp) && !ActIsHeavy(Act::ConnectWifi));
    CHECK(ActNeedsAdmin(Act::RenewDhcp) && !ActNeedsAdmin(Act::DisableProxy));
}

// ---------------------------------------------------------------- plan execution

// execute() returns `runs[act]` (default: ran); verify() hands out `verdicts`
// in order (default: Continue). `log` records "x:<act>" per execute and
// "v:<act>" per verify of the credited step.
struct Script {
    std::vector<std::pair<Act, bool>> runs;
    std::vector<Verdict> verdicts;
    std::vector<std::wstring> log;
    bool stop = false;
};

static PlanRun Play(const std::vector<Step>& plan, Script& sc, std::set<std::wstring>& done)
{
    size_t next = 0;
    return RunPlan(
        plan, done,
        [](const Step& s) { return std::wstring(ActKey(s.act)) + L":" + std::to_wstring(s.adapter); },
        [&] { return sc.stop; },
        [&](const Step& s) {
            sc.log.push_back(L"x:" + std::wstring(ActKey(s.act)));
            for (const auto& r : sc.runs)
                if (r.first == s.act) return r.second;
            return true;
        },
        [&](const Step& p) {
            sc.log.push_back(L"v:" + std::wstring(ActKey(p.act)));
            return next < sc.verdicts.size() ? sc.verdicts[next++] : Verdict::Continue;
        });
}

static std::wstring Joined(const Script& sc)
{
    std::wstring s;
    for (const auto& l : sc.log) s += (s.empty() ? L"" : L" ") + l;
    return s;
}

static void TestRunPlan()
{
    const Step reconnect = { Act::ConnectWifi, -1, true };

    // A reset is verified after its reconnect, and credited with the fix.
    {
        Script sc;
        sc.verdicts = { Verdict::Fixed };
        std::set<std::wstring> done;
        PlanRun r = Play({ { Act::ResetAdapter, 0 }, reconnect }, sc, done);
        CHECK(Joined(sc) == L"x:reset-adapter x:connect-wifi v:reset-adapter");
        CHECK(r.fixedBy == 0 && r.acted && !r.aborted);
    }
    // A reset that could not run (cooldown) takes its reconnect with it.
    {
        Script sc;
        sc.runs = { { Act::ResetAdapter, false } };
        std::set<std::wstring> done;
        Play({ { Act::ResetAdapter, 0 }, reconnect, { Act::RestartWlanSvc, -1 }, reconnect },
             sc, done);
        CHECK(Joined(sc) == L"x:reset-adapter x:restart-wlansvc x:connect-wifi v:restart-wlansvc");
    }
    // An independent reconnect still runs when the step before it could not
    // (a non-elevated instance cannot start services).
    {
        Script sc;
        sc.runs = { { Act::StartServices, false } };
        std::set<std::wstring> done;
        Play({ { Act::StartServices, -1 }, { Act::ConnectWifi, -1 }, { Act::ResetAdapter, 0 },
               reconnect }, sc, done);
        CHECK(Joined(sc) == L"x:start-services x:connect-wifi v:connect-wifi x:reset-adapter "
                            L"x:connect-wifi v:reset-adapter");
    }
    // A reconnect after a non-prep step is its own step (wired -> Wi-Fi failover).
    {
        Script sc;
        std::set<std::wstring> done;
        Play({ { Act::RenewDhcp, 1 }, { Act::ConnectWifi, -1 }, { Act::ResetAdapter, 1 } },
             sc, done);
        CHECK(Joined(sc) == L"x:renew-dhcp v:renew-dhcp x:connect-wifi v:connect-wifi "
                            L"x:reset-adapter v:reset-adapter");
    }
    // The follow-up failing still verifies what the prep step did.
    {
        Script sc;
        sc.runs = { { Act::ConnectWifi, false } };
        sc.verdicts = { Verdict::Continue };
        std::set<std::wstring> done;
        PlanRun r = Play({ { Act::EnableAdapter, 0 }, reconnect }, sc, done);
        CHECK(Joined(sc) == L"x:enable-adapter x:connect-wifi v:enable-adapter");
        CHECK(r.acted && r.fixedBy == -1);
    }
    // Nothing ran: no verification, not "acted".
    {
        Script sc;
        sc.runs = { { Act::FlushArp, false }, { Act::RenewDhcp, false } };
        std::set<std::wstring> done;
        PlanRun r = Play({ { Act::FlushArp, 0 }, { Act::RenewDhcp, 0 } }, sc, done);
        CHECK(Joined(sc) == L"x:flush-arp x:renew-dhcp");
        CHECK(!r.acted && r.fixedBy == -1 && !r.aborted);
    }
    // Credit goes to the step that was verified as fixed.
    {
        Script sc;
        sc.verdicts = { Verdict::Continue, Verdict::Fixed };
        std::set<std::wstring> done;
        PlanRun r = Play({ { Act::FlushArp, 0 }, { Act::RenewDhcp, 0 }, { Act::Reassociate, -1 } },
                         sc, done);
        CHECK(r.fixedBy == 1);
        CHECK(Joined(sc) == L"x:flush-arp v:flush-arp x:renew-dhcp v:renew-dhcp");
    }
    // A second round skips what already ran; a lone reconnect may repeat.
    {
        std::vector<Step> plan = { { Act::ConnectWifi, -1 }, { Act::ResetAdapter, 0 }, reconnect };
        std::set<std::wstring> done;
        Script one;
        Play(plan, one, done);
        CHECK(Joined(one) == L"x:connect-wifi v:connect-wifi x:reset-adapter x:connect-wifi "
                             L"v:reset-adapter");
        Script two;
        PlanRun r = Play(plan, two, done);
        CHECK(Joined(two) == L"x:connect-wifi v:connect-wifi");
        CHECK(r.acted);
        // Same step on another adapter is a different step.
        Script three;
        Play({ { Act::ResetAdapter, 1 } }, three, done);
        CHECK(Joined(three) == L"x:reset-adapter v:reset-adapter");
    }
    // Abort (portal reached / stop) ends the plan at once.
    {
        Script sc;
        sc.verdicts = { Verdict::Abort };
        std::set<std::wstring> done;
        PlanRun r = Play({ { Act::FlushDns, -1 }, { Act::RenewDhcp, 0 } }, sc, done);
        CHECK(r.aborted && Joined(sc) == L"x:flush-dns v:flush-dns");
        Script st;
        st.stop = true;
        std::set<std::wstring> done2;
        r = Play({ { Act::FlushDns, -1 } }, st, done2);
        CHECK(r.aborted && st.log.empty());
    }
}

// ---------------------------------------------------------------- helpers

static void TestDuration()
{
    CHECK(DurationText(30) == L"30 s");
    CHECK(DurationText(120) == L"2 min");
    CHECK(DurationText(3700) == L"61 min");
    CHECK(DurationText(6000) == L"1 h 40 min");
    CHECK(DurationText(7200) == L"2 h");
    CHECK(DurationText(-7200) == L"2 h");
    CHECK(DurationText(3 * 86400) == L"3 days");
    CHECK(DurationText(800LL * 86400) == L"2 years");
}

static void TestWlanReason()
{
    CHECK(ClassifyWlanReason(0) == WlanFail::None);
    CHECK(ClassifyWlanReason(0x48014) == WlanFail::Security);   // PSK mismatch range
    CHECK(ClassifyWlanReason(0x50001) == WlanFail::Security);   // 802.1X
    CHECK(ClassifyWlanReason(0x38001) == WlanFail::Association);
    CHECK(ClassifyWlanReason(0x80001) == WlanFail::Profile);
    CHECK(ClassifyWlanReason(0x28002) == WlanFail::Other);
}

static void TestDnsPacket()
{
    std::vector<uint8_t> q = BuildDnsQuery(0xBEEF, "www.msftconnecttest.com");
    CHECK(q.size() == 12 + 1 + 3 + 1 + 15 + 1 + 3 + 1 + 4);
    CHECK(q[0] == 0xBE && q[1] == 0xEF);
    CHECK(q[2] == 0x01 && q[5] == 0x01);     // RD, QDCOUNT 1
    CHECK(q[12] == 3 && std::memcmp(&q[13], "www", 3) == 0);
    CHECK(q[16] == 15);
    CHECK(q[q.size() - 5] == 0);             // root label
    CHECK(q[q.size() - 3] == 1 && q[q.size() - 1] == 1);   // A, IN
    CHECK(BuildDnsQuery(1, "example.com.").size() == BuildDnsQuery(1, "example.com").size());
    CHECK(BuildDnsQuery(1, "").empty());
    CHECK(BuildDnsQuery(1, "a..b").empty());
    CHECK(BuildDnsQuery(1, std::string(64, 'x') + ".com").empty());

    uint8_t r[12] = { 0xBE, 0xEF, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0 };
    int answers = -1;
    CHECK(ParseDnsReply(r, sizeof r, 0xBEEF, &answers) == 0 && answers == 2);
    CHECK(ParseDnsReply(r, sizeof r, 0xBEEE, nullptr) == -1);        // not ours
    CHECK(ParseDnsReply(r, 11, 0xBEEF, nullptr) == -1);              // truncated
    r[3] = 0x83;                                                    // NXDOMAIN
    CHECK(ParseDnsReply(r, sizeof r, 0xBEEF, nullptr) == 3);
    r[2] = 0x01;                                                    // a query, not a reply
    CHECK(ParseDnsReply(r, sizeof r, 0xBEEF, nullptr) == -1);
}

static void TestProxyParse()
{
    ProxyEndpoint e;
    CHECK(PickHttpProxy(L"127.0.0.1:8888", e) && e.host == L"127.0.0.1" && e.port == 8888);
    CHECK(PickHttpProxy(L"http=proxy:3128;https=sproxy:3129", e) &&
          e.host == L"proxy" && e.port == 3128);
    CHECK(PickHttpProxy(L"https=sp:1;socks=s:2", e) && e.host == L"sp" && e.port == 1);
    CHECK(PickHttpProxy(L" HTTP=h:1 ; ", e) && e.host == L"h" && e.port == 1);
    CHECK(PickHttpProxy(L"ftp=f:21 http=h:2", e) && e.host == L"h" && e.port == 2);
    CHECK(PickHttpProxy(L"http://localhost:8080/", e) && e.host == L"localhost" && e.port == 8080);
    CHECK(PickHttpProxy(L"[::1]:8888", e) && e.host == L"::1" && e.port == 8888);
    CHECK(PickHttpProxy(L"proxy", e) && e.host == L"proxy" && e.port == 80);
    CHECK(!PickHttpProxy(L"socks=s:1080", e));
    CHECK(!PickHttpProxy(L"host:port", e));
    CHECK(!PickHttpProxy(L"fe80::1", e));
    CHECK(!PickHttpProxy(L"h:70000", e));
    CHECK(!PickHttpProxy(L"", e));

    CHECK(IsLoopbackHost(L"localhost") && IsLoopbackHost(L"LocalHost"));
    CHECK(IsLoopbackHost(L"127.0.0.1") && IsLoopbackHost(L"127.5.5.5"));
    CHECK(IsLoopbackHost(L"::1") && IsLoopbackHost(L"[::1]"));
    CHECK(!IsLoopbackHost(L"10.0.0.1") && !IsLoopbackHost(L"proxy.corp"));
    CHECK(!IsLoopbackHost(L"1270.0.0.1") && !IsLoopbackHost(L"128.0.0.1"));
}

static void TestTaskXml(const char* dumpPath)
{
    CHECK(XmlEscape(L"a&b<c>\"d'") == L"a&amp;b&lt;c&gt;&quot;d&apos;");
    CHECK(XmlEscape(std::wstring(L"x\x01y")) == L"xy");
    CHECK(TaskFormatOf(TaskDescription()) == kTaskFormat);
    CHECK(TaskFormatOf(L"") == 1);
    CHECK(TaskFormatOf(L"made by schtasks") == 1);
    CHECK(TaskFormatOf(L"x [format 7] y") == 7);

    TaskSpec s;
    s.userId = L"S-1-5-21-1000";
    s.command = L"\"C:\\Program Files\\Net&Vigil\\NetVigil.exe\"";
    s.arguments = L"--autostart --interval 10";
    s.workDir = L"C:\\Program Files\\Net&Vigil";
    std::wstring x = BuildTaskXml(s);
    auto has = [&](const wchar_t* t) { return x.find(t) != std::wstring::npos; };
    CHECK(has(L"encoding=\"UTF-16\""));
    CHECK(has(L"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    CHECK(has(L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
    CHECK(has(L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
    CHECK(has(L"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
    CHECK(has(L"<RunLevel>HighestAvailable</RunLevel>"));
    CHECK(has(L"<LogonType>InteractiveToken</LogonType>"));
    CHECK(has(L"<Interval>PT10M</Interval>"));
    CHECK(has(L"<Delay>PT15S</Delay>"));
    CHECK(has(L"Net&amp;Vigil"));
    CHECK(!has(L"Net&Vigil"));
    CHECK(has(L"<Arguments>--autostart --interval 10</Arguments>"));
    size_t first = x.find(L"<UserId>S-1-5-21-1000</UserId>");
    CHECK(first != std::wstring::npos &&
          x.find(L"<UserId>S-1-5-21-1000</UserId>", first + 1) != std::wstring::npos);
    CHECK(has((L"[format " + std::to_wstring(kTaskFormat) + L"]").c_str()));

    s.relaunchMin = 0;
    s.userId.clear();
    std::wstring y = BuildTaskXml(s);
    CHECK(y.find(L"<Repetition>") == std::wstring::npos);
    CHECK(y.find(L"<UserId>") == std::wstring::npos);

    if (dumpPath) {
        if (FILE* f = std::fopen(dumpPath, "wb")) {
            std::fputc(0xFF, f);
            std::fputc(0xFE, f);
            for (wchar_t c : x) {                // task XML is BMP-only
                std::fputc((int)((unsigned)c & 0xFF), f);
                std::fputc((int)(((unsigned)c >> 8) & 0xFF), f);
            }
            std::fclose(f);
        }
    }
}

int main(int argc, char** argv)
{
    TestOnline();
    TestPortal();
    TestDns();
    TestProxyAndWeb();
    TestVpn();
    TestUpstream();
    TestGateway();
    TestIpConfig();
    TestServices();
    TestWifiDevice();
    TestWifiRadio();
    TestWifiAssociation();
    TestMissingAndWired();
    TestNames();
    TestRunPlan();
    TestDuration();
    TestWlanReason();
    TestDnsPacket();
    TestProxyParse();
    TestTaskXml(argc > 1 ? argv[1] : nullptr);

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
