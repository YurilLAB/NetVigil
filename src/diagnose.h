// diagnose.h — NetVigil's decision logic, free of Windows headers so the
// whole symptom -> fault -> repair table can be unit-tested on any platform
// (tests/diagnose_tests.cpp). main.cpp gathers an Observation from the live
// system, Diagnose() names the fault and orders the repairs cheapest-first,
// and main.cpp executes them.
//
// The point of the table is differentiation: a dead ISP, a stale proxy, a
// disabled adapter and a wedged driver all look like "no internet", but each
// has exactly one repair that helps — and heavy ones (driver resets, service
// restarts) are only ever planned for faults they can actually fix.
#pragma once
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace nv {

// ---------------------------------------------------------------- inputs

enum class Kind : uint8_t { Wifi, Ethernet, Cellular, Other };

enum class Dev : uint8_t {
    Unknown,    // no device node matched (virtual adapters, failed lookups)
    Ok,         // started, no problem code
    Disabled,   // CM_PROB_DISABLED: turned off in Device Manager / Network Connections
    Failed,     // any other problem code (driver failed to start, Code 10/43/...)
};

const unsigned kProbNeedRestart = 14;   // CM_PROB_NEED_RESTART

struct AdapterObs {
    std::wstring name;            // friendly name ("Wi-Fi", "Ethernet 2")
    std::wstring id;              // NetCfgInstanceId GUID — opaque here
    Kind kind = Kind::Other;
    bool virt = false;            // VPN / tunnel / virtual switch / Wi-Fi Direct
    bool hasIf = true;            // visible to the IP stack (false: device node only)
    Dev  dev = Dev::Unknown;
    unsigned problem = 0;         // device problem code when dev == Failed
    bool up = false;              // operationally up
    bool media = false;           // link: cable in / Wi-Fi associated
    bool dhcp = false;
    bool hasIpv4 = false;
    bool apipa = false;           // 169.254.x.x: DHCP never answered
    bool duplicate = false;       // Windows detected an address conflict
    bool hasGateway = false;
    bool staticDns = false;       // DNS servers typed in by hand (not from DHCP)
    bool routesInternet = false;  // carries the best route to the internet
    int  gateway = -1;            // -1 not probed, 0 silent, 1 answered (ping / fresh ARP)
    int  dnsServers = 0;          // configured IPv4 DNS servers
    int  dnsDead = 0;             // ...of which this many ignored a direct query
    std::wstring gw;              // gateway address, for messages
    std::wstring ip;              // IPv4 address, for messages
    // Filled and used by the Windows side only.
    unsigned long ifIndex = 0;
    uint64_t luid = 0;
    uint32_t gatewayIp = 0;       // network byte order
    std::vector<uint32_t> dnsIps; // network byte order
};

struct WifiObs {
    bool hardware = false;        // a Wi-Fi adapter exists (WLAN interface or device node)
    bool expected = false;        // ...or existed recently (a USB dongle that vanished)
    int  interfaces = 0;          // WLAN interfaces WlanSvc reports
    bool associated = false;      // some interface is connected
    bool radioSoftOff = false;    // a radio is switched off in software
    bool radioHardOff = false;    // hardware switch / keyboard kill key
    bool airplane = false;        // Windows airplane mode is on
    int  visible = -1;            // networks seen in the last scan; -1 = unknown
    int  knownInRange = 0;        // saved, connectable, allowed networks in range
    std::wstring authFailed;      // profile whose security handshake keeps failing
    bool serviceStopped = false;  // WLAN AutoConfig stopped (startable)
    bool serviceDisabled = false; // WLAN AutoConfig set to Disabled
};

struct ProbeObs {
    bool httpOk = false;          // an HTTP probe returned the expected content
    bool httpAnswered = false;    // an HTTP answer arrived, but not the expected one
    bool pingOk = false;          // public IPs answer ICMP
    bool tcpOk = false;           // public IPs accept TCP (ICMP may be filtered)
    bool dnsOk = true;            // the system resolver resolves the probe host
    bool dnsPublicOk = false;     // a public resolver answered a direct query
    bool proxyOn = false;         // a manual proxy is configured for this user
    bool proxyDead = false;       // ...on a loopback address with nothing listening
    bool directOk = false;        // an HTTP request bypassing the proxy works
    std::wstring proxy;           // host:port of the configured proxy
    bool clockKnown = false;
    long long clockSkew = 0;      // local clock minus server clock, seconds
};

struct Observation {
    ProbeObs probe;
    WifiObs wifi;
    std::vector<AdapterObs> adapters;
    // Services every path needs (Network Store Interface, DHCP Client);
    // WLAN AutoConfig is in WifiObs, since only the Wi-Fi path needs it.
    std::vector<std::wstring> stoppedServices;   // stopped, startable
    std::vector<std::wstring> disabledServices;  // start type Disabled
    int  failStreak = 0;          // confirmed failed checks in this outage
    bool allowFailover = true;    // user lets NetVigil change networks in an ISP outage
};

// ---------------------------------------------------------------- outputs

enum class Fault : uint8_t {
    None,
    ClockSkew,          // online, but the clock is far off — HTTPS fails
    CaptivePortal,      // a sign-in page intercepts traffic
    ProxyDead,          // the configured proxy is what is broken
    DnsBroken,          // IP connectivity fine, name resolution failing
    WebBlocked,         // IP and DNS fine, web requests blocked
    VpnDown,            // traffic routed into a VPN that is not passing it
    UpstreamOutage,     // local network healthy, ISP / router WAN down
    AirplaneMode,
    RadioSwitchOff,     // hardware Wi-Fi switch off
    ServiceStopped,     // a service the network stack needs is stopped/disabled
    AdapterDisabled,
    AdapterFailed,      // the driver reports a problem
    AdapterMissing,     // no usable network adapter present
    RadioOff,           // Wi-Fi radio switched off in software
    WifiAuthFailed,     // saved password rejected
    NoKnownNetwork,     // radio works, no remembered network in range
    WifiDisconnected,   // Wi-Fi not associated
    CableUnplugged,     // Ethernet link down and nothing else to use
    IpConfigBroken,     // APIPA / no address / conflict / no gateway
    GatewayUnreachable, // link up, router silent
    Unknown,            // no internet path, no specific cause found
    Count
};

enum class Act : uint8_t {
    StartServices,      // start stopped network services
    EnableAdapter,      // enable a disabled adapter
    RescanDevices,      // "scan for hardware changes"
    RadioOn,            // switch a software-off Wi-Fi radio on
    ConnectWifi,        // attach disconnected Wi-Fi interfaces
    Reassociate,        // drop and re-establish the Wi-Fi association
    SwitchNetwork,      // try another saved Wi-Fi network (ISP outage failover)
    RenewDhcp,          // release + renew the DHCP lease
    FlushArp,           // drop stale neighbour (ARP) entries
    FlushDns,           // flush the DNS resolver cache
    DisableProxy,       // turn off a manual proxy nothing is listening on
    ResetAdapter,       // disable/enable the adapter driver
    RestartWlanSvc,     // restart WLAN AutoConfig
    ResyncClock,        // ask Windows Time to resync
    Count
};

struct Step {
    Act act;
    int adapter;            // index into Observation::adapters, -1 = not adapter-specific
    bool completes = false; // a ConnectWifi finishing the step before it (enable, reset,
                            // service start...): runs only if that step ran, and the
                            // pair is verified together
};

struct Diagnosis {
    Fault fault = Fault::Unknown;
    int adapter = -1;             // adapter the fault was found on
    std::vector<Step> plan;       // cheapest / most targeted first
    bool userAction = false;      // only the user can finish the fix — tell them
    std::wstring detail;          // one-line explanation for log, tooltip and balloon
};

const long long kClockSkewLimitSec = 3600;

Diagnosis Diagnose(const Observation& o);

const wchar_t* FaultName(Fault f);   // "ISP / router outage"
const wchar_t* ActName(Act a);       // "renew the DHCP lease"
const wchar_t* ActKey(Act a);        // "renew-dhcp" (stable, for the ini)
bool ActIsHeavy(Act a);              // interrupts the link for everything on it
bool ActNeedsAdmin(Act a);

// ---------------------------------------------------------------- execution

// Runs a plan: skips steps already in `done` (it spans diagnosis rounds; a
// ConnectWifi is never deduplicated), runs a `completes` step only when the
// step it completes ran and verifies the two together, and verifies after
// every other step that ran. `verify` settles, re-probes and credits the
// step it is given.
enum class Verdict : uint8_t { Continue, Fixed, Abort };
struct PlanRun {
    bool acted = false;          // some step actually ran
    int  fixedBy = -1;           // plan index credited with the fix
    bool aborted = false;        // stop requested, or verify said Abort
};
PlanRun RunPlan(const std::vector<Step>& plan, std::set<std::wstring>& done,
                const std::function<std::wstring(const Step&)>& key,
                const std::function<bool()>& stopped,
                const std::function<bool(const Step&)>& execute,
                const std::function<Verdict(const Step& principal)>& verify);

// ---------------------------------------------------------------- helpers

// Human duration, "3 min", "2 h 5 min", "4 days".
std::wstring DurationText(long long seconds);

// WLAN reason codes, bucketed by the L2 reason-code group they fall in.
enum class WlanFail : uint8_t { None, Security, Association, Profile, Other };
WlanFail ClassifyWlanReason(uint32_t reasonCode);

// Raw DNS: an A query for `host` (ASCII labels) with transaction id `id`,
// and a parser for the answer. ParseDnsReply returns the RCODE (0..15) of a
// well-formed response to that id, or -1; `answers` receives ANCOUNT.
std::vector<uint8_t> BuildDnsQuery(uint16_t id, const std::string& host);
int ParseDnsReply(const uint8_t* p, size_t n, uint16_t id, int* answers);

// WinINET proxy strings: "host:port", "http=h:p;https=h:p", "http://h:p",
// "[::1]:8888". Picks the endpoint plain HTTP would use.
struct ProxyEndpoint {
    std::wstring host;
    unsigned port = 0;
};
bool PickHttpProxy(const std::wstring& spec, ProxyEndpoint& out);
bool IsLoopbackHost(const std::wstring& host);

// Task Scheduler definition for the logon task.
const int kTaskFormat = 2;          // bump when the task definition changes
struct TaskSpec {
    std::wstring userId;            // SID (or DOMAIN\user) the task runs as
    std::wstring command;           // full exe path
    std::wstring arguments;
    std::wstring workDir;
    unsigned logonDelaySec = 15;
    unsigned relaunchMin = 10;      // repetition that restarts a stopped watchdog; 0 = none
};
std::wstring BuildTaskXml(const TaskSpec& s);
std::wstring TaskDescription();     // carries the "[format N]" marker
int TaskFormatOf(const std::wstring& description);   // 1 for anything unmarked
std::wstring XmlEscape(const std::wstring& s);

} // namespace nv
