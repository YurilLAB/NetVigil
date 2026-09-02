// NetVigil — Wi-Fi connectivity watchdog for Windows.
//
// Runs at logon (scheduled task), probes internet connectivity on an interval
// (default 10 min) and, when the connection is confirmed down, escalates:
//   stage 1: rejoin Wi-Fi (radio on, scan, connect best remembered network)
//   stage 2: reset the Wi-Fi adapter driver (disable/enable via SetupAPI),
//            restart WlanSvc if that yields nothing, then reconnect again.
// Works with any WLAN interface Windows knows about, including external
// USB adapters — interfaces are re-enumerated on every cycle, and if an
// adapter has wedged so hard it vanished from WlanSvc, a heuristic pass
// resets present wireless-looking net devices instead.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <initguid.h>
#include <devguid.h>
#include <wlanapi.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <setupapi.h>
#include <shellapi.h>
#include <sddl.h>

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

// ---------------------------------------------------------------- constants

static const wchar_t* kTaskName      = L"NetVigil";
static const wchar_t* kMutexName     = L"Local\\NetVigil.single";
static const wchar_t* kStopEventName = L"Local\\NetVigil.stop";

static const DWORD     kDefaultIntervalMin = 10;   // normal check cadence
static const DWORD     kOfflineRetryMin    = 2;    // cadence while still down
static const ULONGLONG kResetCooldownMs    = 15ull * 60 * 1000; // between driver resets
static const ULONGLONG kLogRotateBytes     = 1ull << 20;        // 1 MiB

// ---------------------------------------------------------------- globals

static std::wstring g_logPath;
static bool         g_elevated  = false;
static HANDLE       g_stopEvent = nullptr;

// ---------------------------------------------------------------- utilities

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) {
        std::wstring w;
        for (unsigned char c : s) w.push_back(c < 0x80 ? (wchar_t)c : L'?');
        return w;
    }
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring Lower(std::wstring s)
{
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static std::wstring ExeDir()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p = buf;
    size_t slash = p.find_last_of(L'\\');
    return slash == std::wstring::npos ? p : p.substr(0, slash);
}

static std::wstring ExePath()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return buf;
}

static std::wstring Sys32(const wchar_t* exe)
{
    wchar_t s[MAX_PATH] = {};
    GetSystemDirectoryW(s, MAX_PATH);
    return std::wstring(s) + L"\\" + exe;
}

static void LogLine(const std::wstring& msg)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t stamp[40];
    swprintf_s(stamp, L"%04u-%02u-%02u %02u:%02u:%02u  ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::string console = WideToUtf8(std::wstring(stamp) + msg + L"\n");
    fputs(console.c_str(), stdout);
    fflush(stdout);

    if (g_logPath.empty()) return;
    HANDLE h = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(h, &sz) && (ULONGLONG)sz.QuadPart > kLogRotateBytes) {
        CloseHandle(h);
        MoveFileExW(g_logPath.c_str(), (g_logPath + L".old").c_str(),
                    MOVEFILE_REPLACE_EXISTING);
        h = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA,
                        FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
    }
    std::string line = WideToUtf8(std::wstring(stamp) + msg + L"\r\n");
    DWORD written = 0;
    WriteFile(h, line.data(), (DWORD)line.size(), &written, nullptr);
    CloseHandle(h);
}

static void Logf(const wchar_t* fmt, ...)
{
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    LogLine(buf);
}

static void InitLog()
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::wstring dir = (n > 0 && n < MAX_PATH) ? std::wstring(buf) + L"\\NetVigil"
                                               : ExeDir();
    CreateDirectoryW(dir.c_str(), nullptr);
    g_logPath = dir + L"\\netvigil.log";
}

// Attach to the parent console (when launched from a terminal) so command
// output is visible; as a /SUBSYSTEM:WINDOWS binary we otherwise have none.
static void BindConsole()
{
    HANDLE prevOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE prevErr = GetStdHandle(STD_ERROR_HANDLE);
    bool hadOut = prevOut != nullptr && prevOut != INVALID_HANDLE_VALUE;
    bool hadErr = prevErr != nullptr && prevErr != INVALID_HANDLE_VALUE;
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* f = nullptr;
        if (!hadOut) freopen_s(&f, "CONOUT$", "w", stdout);
        if (!hadErr) freopen_s(&f, "CONOUT$", "w", stderr);
        SetConsoleOutputCP(CP_UTF8);
    }
}

static bool IsElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{};
    DWORD n = 0;
    bool ok = GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n) &&
              el.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

static ULONGLONG WallMs()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{};
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart / 10000ull;
}

// Milliseconds of machine-awake time; used with WallMs() to spot resume
// from sleep. Loaded dynamically so a missing export degrades gracefully.
typedef BOOL(WINAPI* PfnQueryUnbiased)(PULONGLONG);
static PfnQueryUnbiased g_queryUnbiased = nullptr;

static ULONGLONG UnbiasedMs()
{
    ULONGLONG t = 0;
    if (g_queryUnbiased && g_queryUnbiased(&t)) return t / 10000ull;
    return GetTickCount64();
}

// Wait that honours the stop event. Returns true if stop was signalled.
static bool WaitStop(DWORD ms)
{
    if (!g_stopEvent) { Sleep(ms); return false; }
    return WaitForSingleObject(g_stopEvent, ms) == WAIT_OBJECT_0;
}

static bool StopRequested()
{
    return g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0;
}

// The monitor usually runs elevated (scheduled task) while --stop or a second
// launch run non-elevated. An elevated token's default DACL grants only
// Administrators/SYSTEM, which would make the named mutex/event unopenable
// from a normal shell — so both are created with an explicit DACL that also
// grants the interactive session access.
static SECURITY_ATTRIBUTES* NamedObjSa()
{
    static PSECURITY_DESCRIPTOR sd = nullptr;
    static SECURITY_ATTRIBUTES sa{};
    if (!sd) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
                SDDL_REVISION_1, &sd, nullptr))
            return nullptr; // fall back to default security
        sa.nLength = sizeof sa;
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = FALSE;
    }
    return &sa;
}

// ---------------------------------------------------------------- probes

enum class Net { Online, Degraded, Portal, Offline };

static const wchar_t* NetToStr(Net n)
{
    switch (n) {
    case Net::Online:   return L"ONLINE";
    case Net::Degraded: return L"DEGRADED (ICMP ok, HTTP/DNS failing)";
    case Net::Portal:   return L"CAPTIVE PORTAL / FILTERED";
    default:            return L"OFFLINE";
    }
}

struct ProbeResult {
    bool ok = false;          // endpoint returned the expected content
    bool gotResponse = false; // some HTTP response arrived (portal suspect)
};

static ProbeResult HttpProbe(const wchar_t* host, const wchar_t* path,
                             bool expect204, const char* expectBody)
{
    ProbeResult r;
    HINTERNET ses = WinHttpOpen(L"NetVigil/1.0",
                                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        ses = WinHttpOpen(L"NetVigil/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return r;
    WinHttpSetTimeouts(ses, 5000, 5000, 5000, 5000);

    HINTERNET con = WinHttpConnect(ses, host, INTERNET_DEFAULT_HTTP_PORT, 0);
    HINTERNET req = con ? WinHttpOpenRequest(con, L"GET", path, nullptr,
                                             WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, 0)
                        : nullptr;
    if (req) {
        DWORD disable = WINHTTP_DISABLE_REDIRECTS; // a portal 302 must not pass
        WinHttpSetOption(req, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof disable);
        if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(req, nullptr)) {
            r.gotResponse = true;
            DWORD status = 0, len = sizeof status;
            WinHttpQueryHeaders(req,
                                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                                WINHTTP_NO_HEADER_INDEX);
            if (expect204) {
                r.ok = (status == 204);
            } else if (status == 200 && expectBody) {
                char body[64] = {};
                DWORD rd = 0;
                WinHttpReadData(req, body, sizeof body - 1, &rd);
                r.ok = strncmp(body, expectBody, strlen(expectBody)) == 0;
            }
        }
    }
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return r;
}

static bool PingProbe(const char* ipStr)
{
    IN_ADDR addr{};
    if (InetPtonA(AF_INET, ipStr, &addr) != 1) return false;
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return false;
    char payload[32] = "NetVigil-probe";
    BYTE reply[sizeof(ICMP_ECHO_REPLY) + sizeof payload + 8] = {};
    DWORD n = IcmpSendEcho(h, addr.S_un.S_addr, payload, sizeof payload,
                           nullptr, reply, sizeof reply, 3000);
    IcmpCloseHandle(h);
    if (n == 0) return false;
    return ((PICMP_ECHO_REPLY)reply)->Status == IP_SUCCESS;
}

static Net CheckInternet()
{
    ProbeResult a = HttpProbe(L"www.msftconnecttest.com", L"/connecttest.txt",
                              false, "Microsoft Connect Test");
    if (a.ok) return Net::Online;
    ProbeResult b = HttpProbe(L"www.gstatic.com", L"/generate_204", true, nullptr);
    if (b.ok) return Net::Online;

    bool ping = PingProbe("1.1.1.1") || PingProbe("8.8.8.8");
    bool httpResponded = a.gotResponse || b.gotResponse;

    if (ping)          return httpResponded ? Net::Portal : Net::Degraded;
    if (httpResponded) return Net::Portal;
    return Net::Offline;
}

// ---------------------------------------------------------------- WLAN

struct WlanIfaceInfo {
    GUID guid{};
    std::wstring desc;
    WLAN_INTERFACE_STATE state = wlan_interface_state_not_ready;
};

static const wchar_t* IfStateStr(WLAN_INTERFACE_STATE s)
{
    switch (s) {
    case wlan_interface_state_connected:      return L"connected";
    case wlan_interface_state_disconnected:   return L"disconnected";
    case wlan_interface_state_disconnecting:  return L"disconnecting";
    case wlan_interface_state_associating:    return L"associating";
    case wlan_interface_state_authenticating: return L"authenticating";
    case wlan_interface_state_discovering:    return L"discovering";
    case wlan_interface_state_ad_hoc_network_formed: return L"ad-hoc";
    default:                                  return L"not ready";
    }
}

static HANDLE OpenWlan()
{
    DWORD ver = 0;
    HANDLE h = nullptr;
    if (WlanOpenHandle(2, nullptr, &ver, &h) != ERROR_SUCCESS) return nullptr;
    return h;
}

static std::vector<WlanIfaceInfo> EnumWlanIfaces(HANDLE h)
{
    std::vector<WlanIfaceInfo> out;
    PWLAN_INTERFACE_INFO_LIST list = nullptr;
    if (WlanEnumInterfaces(h, nullptr, &list) == ERROR_SUCCESS && list) {
        for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
            const WLAN_INTERFACE_INFO& it = list->InterfaceInfo[i];
            WlanIfaceInfo inf;
            inf.guid  = it.InterfaceGuid;
            inf.desc  = it.strInterfaceDescription;
            inf.state = it.isState;
            out.push_back(std::move(inf));
        }
        WlanFreeMemory(list);
    }
    return out;
}

static WLAN_INTERFACE_STATE GetIfaceState(HANDLE h, const GUID& g)
{
    WLAN_INTERFACE_STATE st = wlan_interface_state_not_ready;
    PVOID data = nullptr;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_interface_state, nullptr,
                           &sz, &data, &t) == ERROR_SUCCESS && data) {
        st = *(WLAN_INTERFACE_STATE*)data;
        WlanFreeMemory(data);
    }
    return st;
}

static std::wstring GetConnectedSsid(HANDLE h, const GUID& g)
{
    std::wstring ssid;
    PVOID data = nullptr;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_current_connection, nullptr,
                           &sz, &data, &t) == ERROR_SUCCESS && data) {
        const WLAN_CONNECTION_ATTRIBUTES* attr = (const WLAN_CONNECTION_ATTRIBUTES*)data;
        const DOT11_SSID& s = attr->wlanAssociationAttributes.dot11Ssid;
        std::string raw((const char*)s.ucSSID,
                        s.uSSIDLength <= DOT11_SSID_MAX_LENGTH ? s.uSSIDLength : 0);
        ssid = Utf8ToWide(raw);
        WlanFreeMemory(data);
    }
    return ssid;
}

// Turn on any software-disabled radio; returns true if something was flipped.
static bool EnsureRadioOn(HANDLE h, const GUID& g)
{
    bool flipped = false;
    PVOID data = nullptr;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_radio_state, nullptr,
                           &sz, &data, &t) != ERROR_SUCCESS || !data)
        return false;
    WLAN_RADIO_STATE* rs = (WLAN_RADIO_STATE*)data;
    for (DWORD i = 0; i < rs->dwNumberOfPhys && i < WLAN_MAX_PHY_INDEX; ++i) {
        const WLAN_PHY_RADIO_STATE& phy = rs->PhyRadioState[i];
        if (phy.dot11SoftwareRadioState == dot11_radio_state_off) {
            WLAN_PHY_RADIO_STATE set{};
            set.dwPhyIndex = phy.dwPhyIndex;
            set.dot11SoftwareRadioState = dot11_radio_state_on;
            DWORD rc = WlanSetInterface(h, &g, wlan_intf_opcode_radio_state,
                                        sizeof set, &set, nullptr);
            Logf(L"  radio phy %u was software-off -> on (rc=%u)", phy.dwPhyIndex, rc);
            flipped = flipped || rc == ERROR_SUCCESS;
        }
        if (phy.dot11HardwareRadioState == dot11_radio_state_off)
            Logf(L"  WARNING: hardware radio/airplane switch is OFF (phy %u) — "
                 L"cannot be enabled from software", phy.dwPhyIndex);
    }
    WlanFreeMemory(data);
    return flipped;
}

struct Candidate {
    std::wstring profile;
    DOT11_BSS_TYPE bss = dot11_BSS_type_infrastructure;
    ULONG quality = 0; // 0..100
};

static std::vector<Candidate> GetCandidates(HANDLE h, const GUID& g)
{
    std::vector<Candidate> v;
    PWLAN_AVAILABLE_NETWORK_LIST list = nullptr;
    if (WlanGetAvailableNetworkList(h, &g,
            WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
            nullptr, &list) == ERROR_SUCCESS && list) {
        for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
            const WLAN_AVAILABLE_NETWORK& n = list->Network[i];
            if (!(n.dwFlags & WLAN_AVAILABLE_NETWORK_HAS_PROFILE)) continue;
            if (!n.bNetworkConnectable) continue;
            if (!n.strProfileName[0]) continue;
            bool dup = false;
            for (auto& c : v) {
                if (c.profile == n.strProfileName) {
                    dup = true;
                    if (n.wlanSignalQuality > c.quality) {
                        c.quality = n.wlanSignalQuality;
                        c.bss = n.dot11BssType;
                    }
                    break;
                }
            }
            if (!dup) {
                Candidate c;
                c.profile = n.strProfileName;
                c.bss = n.dot11BssType;
                c.quality = n.wlanSignalQuality;
                v.push_back(std::move(c));
            }
        }
        WlanFreeMemory(list);
    }
    std::sort(v.begin(), v.end(),
              [](const Candidate& a, const Candidate& b) { return a.quality > b.quality; });
    return v;
}

static bool WaitConnected(HANDLE h, const GUID& g, DWORD ms)
{
    ULONGLONG end = GetTickCount64() + ms;
    while (GetTickCount64() < end) {
        if (GetIfaceState(h, g) == wlan_interface_state_connected) return true;
        if (WaitStop(1000)) return false;
    }
    return GetIfaceState(h, g) == wlan_interface_state_connected;
}

// Try to get one interface associated to a remembered network.
static bool ReconnectIface(HANDLE h, const WlanIfaceInfo& inf, bool bounceIfConnected)
{
    if (EnsureRadioOn(h, inf.guid)) Sleep(3000);

    WLAN_INTERFACE_STATE st = GetIfaceState(h, inf.guid);
    if (st == wlan_interface_state_connected) {
        if (!bounceIfConnected) {
            Logf(L"  [%ls] already associated to '%ls' — leaving as-is",
                 inf.desc.c_str(), GetConnectedSsid(h, inf.guid).c_str());
            return true;
        }
        Logf(L"  [%ls] associated to '%ls' but internet is down — bouncing connection",
             inf.desc.c_str(), GetConnectedSsid(h, inf.guid).c_str());
        WlanDisconnect(h, &inf.guid, nullptr);
        if (WaitStop(2000)) return false;
    }

    DWORD src = WlanScan(h, &inf.guid, nullptr, nullptr, nullptr);
    if (WaitStop(src == ERROR_SUCCESS ? 4500 : 1000)) // scan completes asynchronously
        return false;

    std::vector<Candidate> cands = GetCandidates(h, inf.guid);
    if (cands.empty()) {
        // Hidden APs may not show up in scan results — fall back to the saved
        // profile list in preference order.
        PWLAN_PROFILE_INFO_LIST pl = nullptr;
        if (WlanGetProfileList(h, &inf.guid, nullptr, &pl) == ERROR_SUCCESS && pl) {
            for (DWORD i = 0; i < pl->dwNumberOfItems && i < 5; ++i) {
                Candidate c;
                c.profile = pl->ProfileInfo[i].strProfileName;
                cands.push_back(std::move(c));
            }
            WlanFreeMemory(pl);
        }
    }
    if (cands.empty()) {
        Logf(L"  [%ls] no in-range remembered networks and no saved profiles",
             inf.desc.c_str());
        return false;
    }

    // Walk the candidate list; association alone is not success — a saved
    // network with a strong signal but dead internet must not shadow a
    // weaker one that actually works.
    size_t tries = cands.size() < 4 ? cands.size() : 4;
    for (size_t i = 0; i < tries; ++i) {
        if (StopRequested()) return false;
        const Candidate& c = cands[i];
        Logf(L"  [%ls] connecting to '%ls' (signal %u%%)",
             inf.desc.c_str(), c.profile.c_str(), c.quality);
        WLAN_CONNECTION_PARAMETERS p{};
        p.wlanConnectionMode = wlan_connection_mode_profile;
        p.strProfile   = c.profile.c_str();
        p.dot11BssType = c.bss;
        DWORD rc = WlanConnect(h, &inf.guid, &p, nullptr);
        if (rc != ERROR_SUCCESS || !WaitConnected(h, inf.guid, 20000)) {
            Logf(L"  [%ls] connect to '%ls' failed (rc=%u)",
                 inf.desc.c_str(), c.profile.c_str(), rc);
            continue;
        }
        Logf(L"  [%ls] associated to '%ls' — verifying internet",
             inf.desc.c_str(), c.profile.c_str());
        if (WaitStop(3000)) return true; // let DHCP/DNS settle
        Net check = CheckInternet();
        if (check == Net::Online || check == Net::Degraded) {
            Logf(L"  [%ls] '%ls' has working internet", inf.desc.c_str(), c.profile.c_str());
            return true;
        }
        if (check == Net::Portal) {
            Logf(L"  [%ls] '%ls' is behind a captive portal — keeping it; "
                 L"sign in via browser", inf.desc.c_str(), c.profile.c_str());
            return true;
        }
        if (i + 1 < tries) {
            Logf(L"  [%ls] '%ls' associated but internet still dead — trying next candidate",
                 inf.desc.c_str(), c.profile.c_str());
            WlanDisconnect(h, &inf.guid, nullptr);
            if (WaitStop(2000)) return true;
        } else {
            Logf(L"  [%ls] keeping association to '%ls' despite dead internet "
                 L"(no better candidate)", inf.desc.c_str(), c.profile.c_str());
            return true;
        }
    }
    return false;
}

static bool StartOrRestartWlanSvc(bool forceRestart); // fwd

// Rejoin Wi-Fi on every interface. Returns true if at least one interface
// ended up associated.
static bool WifiReconnectAll(bool bounceIfConnected)
{
    HANDLE h = OpenWlan();
    if (!h && g_elevated) {
        Logf(L"WlanOpenHandle failed — making sure WlanSvc is running");
        StartOrRestartWlanSvc(false);
        Sleep(3000);
        h = OpenWlan();
    }
    if (!h) {
        Logf(L"cannot talk to WLAN service (WlanOpenHandle failed)");
        return false;
    }
    std::vector<WlanIfaceInfo> ifs = EnumWlanIfaces(h);
    if (ifs.empty())
        Logf(L"no WLAN interfaces present (adapter unplugged, disabled, or driver wedged)");
    bool any = false;
    for (const auto& i : ifs)
        any = ReconnectIface(h, i, bounceIfConnected) || any;
    WlanCloseHandle(h, nullptr);
    return any;
}

// NetCfgInstanceId strings ("{...}") of current WLAN interfaces, physical
// ones preferred (skip Wi-Fi Direct style virtual interfaces).
static std::vector<std::wstring> CurrentWlanAdapterIds()
{
    std::vector<std::wstring> ids;
    HANDLE h = OpenWlan();
    if (!h) return ids;
    for (const auto& i : EnumWlanIfaces(h)) {
        if (Lower(i.desc).find(L"virtual") != std::wstring::npos) continue;
        wchar_t g[64] = {};
        if (StringFromGUID2(i.guid, g, 64) > 0) ids.push_back(g);
    }
    WlanCloseHandle(h, nullptr);
    return ids;
}

// ---------------------------------------------------------------- device reset

static std::wstring DevRegString(HDEVINFO devs, SP_DEVINFO_DATA* did, DWORD prop)
{
    wchar_t buf[512] = {};
    DWORD type = 0, need = 0;
    if (SetupDiGetDeviceRegistryPropertyW(devs, did, prop, &type,
                                          (PBYTE)buf, sizeof buf - sizeof(wchar_t), &need))
        return buf;
    return L"";
}

static std::wstring DevNetCfgInstanceId(HDEVINFO devs, SP_DEVINFO_DATA* did)
{
    std::wstring id;
    HKEY hk = SetupDiOpenDevRegKey(devs, did, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
    if (hk != INVALID_HANDLE_VALUE) {
        wchar_t buf[64] = {};
        DWORD sz = sizeof buf - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(hk, L"NetCfgInstanceId", nullptr, &type,
                             (PBYTE)buf, &sz) == ERROR_SUCCESS && type == REG_SZ)
            id = buf;
        RegCloseKey(hk);
    }
    return id;
}

static bool ChangeDevState(HDEVINFO devs, SP_DEVINFO_DATA* did, DWORD newState)
{
    SP_PROPCHANGE_PARAMS pcp{};
    pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    pcp.StateChange = newState;
    pcp.Scope       = DICS_FLAG_GLOBAL;
    pcp.HwProfile   = 0;
    if (!SetupDiSetClassInstallParamsW(devs, did, &pcp.ClassInstallHeader, sizeof pcp))
        return false;
    return SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, devs, did) != FALSE;
}

static bool LooksWireless(const std::wstring& descLower)
{
    static const wchar_t* kExclude[] = { L"virtual", L"vpn", L"tap", L"loopback",
                                         L"bluetooth", L"tunnel" };
    for (const wchar_t* e : kExclude)
        if (descLower.find(e) != std::wstring::npos) return false;
    static const wchar_t* kInclude[] = { L"wireless", L"wi-fi", L"wifi",
                                         L"802.11", L"wlan" };
    for (const wchar_t* k : kInclude)
        if (descLower.find(k) != std::wstring::npos) return true;
    return false;
}

// Disable/enable Wi-Fi adapters (a driver-level reset). If targetIds is
// empty — the adapter vanished from WlanSvc — fall back to resetting present
// net-class devices that look wireless. Returns how many were reset.
static int ResetWifiAdapters(const std::vector<std::wstring>& targetIds)
{
    int resetCount = 0;
    HDEVINFO devs = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr,
                                         DIGCF_PRESENT);
    if (devs == INVALID_HANDLE_VALUE) {
        Logf(L"SetupDiGetClassDevs failed (%u)", GetLastError());
        return 0;
    }
    SP_DEVINFO_DATA did{};
    did.cbSize = sizeof did;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devs, i, &did); ++i) {
        std::wstring id   = DevNetCfgInstanceId(devs, &did);
        std::wstring desc = DevRegString(devs, &did, SPDRP_FRIENDLYNAME);
        if (desc.empty()) desc = DevRegString(devs, &did, SPDRP_DEVICEDESC);

        bool match = false;
        if (!targetIds.empty()) {
            for (const auto& t : targetIds)
                if (!id.empty() && _wcsicmp(t.c_str(), id.c_str()) == 0) match = true;
        } else {
            match = LooksWireless(Lower(desc));
        }
        if (!match) continue;

        Logf(L"resetting adapter driver: %ls", desc.c_str());
        if (!ChangeDevState(devs, &did, DICS_DISABLE)) {
            Logf(L"  disable failed (%u)", GetLastError());
            continue;
        }
        Sleep(3000);
        if (!ChangeDevState(devs, &did, DICS_ENABLE)) {
            Logf(L"  enable failed (%u) — retrying", GetLastError());
            Sleep(2000);
            if (!ChangeDevState(devs, &did, DICS_ENABLE)) {
                Logf(L"  enable failed again (%u) — adapter may need a re-plug",
                     GetLastError());
                continue;
            }
        }
        ++resetCount;
    }
    SetupDiDestroyDeviceInfoList(devs);
    if (resetCount) {
        Logf(L"%d adapter(s) reset — waiting for driver re-init", resetCount);
        WaitStop(8000);
    }
    return resetCount;
}

// ---------------------------------------------------------------- WlanSvc

static bool StartOrRestartWlanSvc(bool forceRestart)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        Logf(L"OpenSCManager failed (%u)", GetLastError());
        return false;
    }
    SC_HANDLE svc = OpenServiceW(scm, L"WlanSvc",
                                 SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        Logf(L"OpenService(WlanSvc) failed (%u)", GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    bool ok = true;
    SERVICE_STATUS ss{};
    QueryServiceStatus(svc, &ss);

    if (forceRestart && ss.dwCurrentState != SERVICE_STOPPED) {
        Logf(L"stopping WlanSvc...");
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &ss))
            Logf(L"  stop request failed (%u)", GetLastError());
        for (int i = 0; i < 30; ++i) {
            QueryServiceStatus(svc, &ss);
            if (ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(1000);
        }
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            Logf(L"  WlanSvc did not stop within 30 s");
            ok = false;
        }
    }

    if (ss.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(svc, 0, nullptr)) {
            DWORD e = GetLastError();
            if (e != ERROR_SERVICE_ALREADY_RUNNING) {
                Logf(L"  StartService(WlanSvc) failed (%u)", e);
                ok = false;
            }
        }
        for (int i = 0; i < 30; ++i) {
            QueryServiceStatus(svc, &ss);
            if (ss.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(1000);
        }
        ok = ok && ss.dwCurrentState == SERVICE_RUNNING;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    Logf(L"WlanSvc %ls %ls", forceRestart ? L"restart" : L"start-check",
         ok ? L"ok" : L"FAILED");
    return ok;
}

// ---------------------------------------------------------------- remediation

// Escalating repair. Returns connectivity state afterwards.
static Net Remediate(Net current, ULONGLONG& lastResetTick)
{
    // Stage 1: rejoin Wi-Fi. Behind a captive portal the AP itself works,
    // so only attach disconnected interfaces instead of bouncing good ones.
    Logf(L"remediation stage 1: Wi-Fi reconnect");
    WifiReconnectAll(/*bounceIfConnected=*/current != Net::Portal);
    if (WaitStop(5000)) return current;
    Net n = CheckInternet();
    Logf(L"after stage 1: %ls", NetToStr(n));
    if (n == Net::Online || n == Net::Degraded) return n;
    if (n == Net::Portal) {
        Logf(L"captive portal suspected — driver reset would not help; "
             L"complete the portal sign-in in a browser");
        return n;
    }

    // Stage 2: driver-level reset.
    if (StopRequested()) return n;
    if (!g_elevated) {
        Logf(L"stage 2 skipped: not elevated — cannot reset adapters or restart WlanSvc");
        return n;
    }
    ULONGLONG now = GetTickCount64();
    if (lastResetTick != 0 && now - lastResetTick < kResetCooldownMs) {
        Logf(L"stage 2 skipped: last driver reset was %llu min ago (cooldown %llu min)",
             (now - lastResetTick) / 60000ull, kResetCooldownMs / 60000ull);
        return n;
    }
    lastResetTick = now;

    Logf(L"remediation stage 2: Wi-Fi adapter driver reset");
    std::vector<std::wstring> ids = CurrentWlanAdapterIds();
    int cnt = ResetWifiAdapters(ids);
    if (cnt == 0) {
        Logf(L"no adapter could be reset — restarting WlanSvc instead");
        StartOrRestartWlanSvc(true);
    }
    if (WaitStop(3000)) return n;
    WifiReconnectAll(true);
    if (WaitStop(5000)) return n;
    n = CheckInternet();
    Logf(L"after stage 2: %ls", NetToStr(n));
    if (n == Net::Online || n == Net::Degraded || n == Net::Portal) return n;

    // Stage 3: WlanSvc restart as the last resort (unless it was just done).
    if (cnt > 0 && !StopRequested()) {
        Logf(L"remediation stage 3: restarting WlanSvc");
        StartOrRestartWlanSvc(true);
        if (WaitStop(5000)) return n;
        WifiReconnectAll(true);
        if (WaitStop(5000)) return n;
        n = CheckInternet();
        Logf(L"after stage 3: %ls", NetToStr(n));
    }
    return n;
}

// ---------------------------------------------------------------- monitor loop

// Interval wait with stop-event and resume-from-sleep detection.
// Returns true if stop was requested.
static bool IntervalWait(DWORD minutes)
{
    ULONGLONG w0 = WallMs(), u0 = UnbiasedMs();
    ULONGLONG total = (ULONGLONG)minutes * 60000ull, slept = 0;
    while (slept < total) {
        DWORD chunk = (DWORD)((total - slept) < 15000ull ? (total - slept) : 15000ull);
        if (WaitStop(chunk)) return true;
        slept += chunk;
        ULONGLONG wallD = WallMs() - w0, unbD = UnbiasedMs() - u0;
        if (wallD > unbD + 90000ull) {
            Logf(L"resume from sleep detected — checking connectivity now");
            return false;
        }
    }
    return false;
}

static int RunMonitor(DWORD intervalMin)
{
    SECURITY_ATTRIBUTES* sa = NamedObjSa();
    HANDLE mutex = CreateMutexW(sa, FALSE, kMutexName);
    DWORD mutexErr = GetLastError();
    if (!mutex) {
        // NULL + ACCESS_DENIED means the mutex exists but was created by a
        // differently-privileged instance — that still counts as "already
        // running". Any other failure: refuse to run unguarded.
        Logf(mutexErr == ERROR_ACCESS_DENIED
                 ? L"another NetVigil instance is already running "
                   L"(different elevation) — exiting"
                 : L"single-instance mutex unavailable (%u) — exiting", mutexErr);
        return 1;
    }
    if (mutexErr == ERROR_ALREADY_EXISTS) {
        Logf(L"another NetVigil instance is already running — exiting");
        CloseHandle(mutex);
        return 1;
    }

    g_stopEvent = CreateEventW(sa, TRUE, FALSE, kStopEventName);
    DWORD evErr = GetLastError();
    if (!g_stopEvent)
        Logf(L"warning: stop event unavailable (%u) — --stop will not reach "
             L"this instance", evErr);
    else if (evErr == ERROR_ALREADY_EXISTS)
        ResetEvent(g_stopEvent); // clear a stale signal from a previous run

    Logf(L"=== NetVigil started (interval %u min, %ls) ===", intervalMin,
         g_elevated ? L"elevated"
                    : L"NOT elevated — stage-2 driver reset unavailable");

    bool firstCycle = true;
    int  failStreak = 0;
    ULONGLONG lastReset = 0;
    ULONGLONG lastOkLog = 0;

    for (;;) {
        Net n = CheckInternet();

        if (n == Net::Online || n == Net::Degraded) {
            if (failStreak > 0) Logf(L"connectivity restored");
            if (n == Net::Degraded)
                Logf(L"degraded: ICMP works but HTTP/DNS failing — no action taken");
            else if (GetTickCount64() - lastOkLog > 3600000ull) {
                Logf(L"online");
                lastOkLog = GetTickCount64();
            }
            failStreak = 0;
            firstCycle = false;
            if (IntervalWait(intervalMin)) break;
            continue;
        }

        // Confirm before acting — give transient blips (and the network stack
        // right after logon) a chance to settle.
        DWORD confirmMs = firstCycle ? 90000 : 30000;
        Logf(L"%ls detected — confirming in %u s",
             n == Net::Portal ? L"captive portal" : L"connection loss",
             confirmMs / 1000);
        if (WaitStop(confirmMs)) break;
        firstCycle = false;

        Net n2 = CheckInternet();
        if (n2 == Net::Online || n2 == Net::Degraded) {
            Logf(L"false alarm — back online");
            failStreak = 0;
            if (IntervalWait(intervalMin)) break;
            continue;
        }

        ++failStreak;
        Logf(L"confirmed %ls (streak %d) — starting remediation",
             NetToStr(n2), failStreak);
        Net after = Remediate(n2, lastReset);

        if (after == Net::Online || after == Net::Degraded) {
            Logf(L"remediation succeeded — back online");
            failStreak = 0;
            if (IntervalWait(intervalMin)) break;
        } else {
            Logf(L"still %ls — next attempt in %u min", NetToStr(after), kOfflineRetryMin);
            if (IntervalWait(kOfflineRetryMin)) break;
        }
    }

    Logf(L"stop requested — NetVigil exiting");
    if (g_stopEvent) CloseHandle(g_stopEvent);
    if (mutex) CloseHandle(mutex);
    return 0;
}

// ---------------------------------------------------------------- task mgmt

static DWORD RunProcess(const std::wstring& cmdLine, bool quiet)
{
    STARTUPINFOW si{};
    si.cb = sizeof si;
    HANDLE nul = INVALID_HANDLE_VALUE;
    if (quiet) {
        SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa,
                          OPEN_EXISTING, 0, nullptr);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = nul;
        si.hStdError  = nul;
        si.hStdInput  = nullptr;
    }
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');
    DWORD code = (DWORD)-1;
    if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, 0,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000); // bounded
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    return code;
}

static bool TaskInstalled()
{
    std::wstring cmd = L"\"" + Sys32(L"schtasks.exe") + L"\" /Query /TN " + kTaskName;
    return RunProcess(cmd, true) == 0;
}

static void SignalRunningInstance()
{
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, kStopEventName);
    if (ev) {
        SetEvent(ev);
        CloseHandle(ev);
        Logf(L"stop signal sent to running instance");
    }
}

// Wait until no instance holds the single-instance mutex any more.
static bool WaitInstanceExit(DWORD ms)
{
    ULONGLONG end = GetTickCount64() + ms;
    for (;;) {
        HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
        if (!m) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) return true;
        } else {
            CloseHandle(m);
        }
        if (GetTickCount64() >= end) return false;
        Sleep(1000);
    }
}

// Admin-writable-only home for the installed copy. The logon task runs
// elevated, so it must never point at an exe a non-admin process can swap.
static std::wstring InstallDirPath()
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramFiles", buf, MAX_PATH);
    std::wstring pf = (n > 0 && n < MAX_PATH) ? buf : L"C:\\Program Files";
    return pf + L"\\NetVigil";
}

static bool RelaunchElevated(const wchar_t* args)
{
    std::wstring exe = ExePath();
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exe.c_str();
    sei.lpParameters = args;
    sei.nShow  = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) return false;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 120000);
        CloseHandle(sei.hProcess);
    }
    return true;
}

static int CmdInstall(DWORD intervalMin)
{
    if (!g_elevated) {
        Logf(L"elevation required to register the startup task — requesting UAC...");
        std::wstring args = L"--install --interval " + std::to_wstring(intervalMin);
        if (!RelaunchElevated(args.c_str())) {
            Logf(L"elevation was declined — run --install from an elevated terminal");
            return 1;
        }
        Logf(L"done (details in %ls)", g_logPath.c_str());
        return 0;
    }

    // Stop any running instance first (also releases the installed exe for
    // overwriting), and wait for it to actually exit.
    SignalRunningInstance();
    if (!WaitInstanceExit(30000))
        Logf(L"warning: a previous instance is still shutting down — "
             L"the new task instance may exit at startup; re-run "
             L"'schtasks /Run /TN NetVigil' if the monitor is not running");

    std::wstring destDir = InstallDirPath();
    std::wstring destExe = destDir + L"\\NetVigil.exe";
    if (_wcsicmp(ExePath().c_str(), destExe.c_str()) != 0) {
        CreateDirectoryW(destDir.c_str(), nullptr);
        BOOL copied = CopyFileW(ExePath().c_str(), destExe.c_str(), FALSE);
        if (!copied) {
            Sleep(2000); // previous instance may still be releasing the file
            copied = CopyFileW(ExePath().c_str(), destExe.c_str(), FALSE);
        }
        if (!copied) {
            Logf(L"failed to copy exe to %ls (%u) — aborting install",
                 destExe.c_str(), GetLastError());
            return 1;
        }
        Logf(L"installed to %ls (admin-only location, so the elevated task "
             L"cannot be pointed at a user-writable binary)", destExe.c_str());
    }

    std::wstring tr = L"\\\"" + destExe + L"\\\" --interval " +
                      std::to_wstring(intervalMin);
    std::wstring cmd = L"\"" + Sys32(L"schtasks.exe") +
                       L"\" /Create /F /TN " + kTaskName +
                       L" /SC ONLOGON /DELAY 0000:30 /RL HIGHEST /TR \"" + tr + L"\"";
    DWORD rc = RunProcess(cmd, false);
    if (rc != 0) {
        Logf(L"schtasks /Create failed (exit %u)", rc);
        return 1;
    }
    Logf(L"startup task '%ls' installed (runs at logon, elevated, interval %u min)",
         kTaskName, intervalMin);

    // Start it now so no re-logon is needed.
    std::wstring runCmd = L"\"" + Sys32(L"schtasks.exe") + L"\" /Run /TN " + kTaskName;
    if (RunProcess(runCmd, false) == 0)
        Logf(L"monitor started (log: %ls)", g_logPath.c_str());
    return 0;
}

static int CmdUninstall()
{
    if (!g_elevated) {
        Logf(L"elevation required to remove the startup task — requesting UAC...");
        if (!RelaunchElevated(L"--uninstall")) {
            Logf(L"elevation was declined — run --uninstall from an elevated terminal");
            return 1;
        }
        return 0;
    }
    SignalRunningInstance();
    WaitInstanceExit(30000);
    std::wstring cmd = L"\"" + Sys32(L"schtasks.exe") + L"\" /Delete /F /TN " + kTaskName;
    DWORD rc = RunProcess(cmd, false);
    Logf(rc == 0 ? L"startup task removed" : L"schtasks /Delete failed (exit %u)", rc);

    // Remove the installed copy (never the exe the user launched from
    // elsewhere). If we ARE that copy, it cannot delete itself — defer.
    std::wstring destDir = InstallDirPath();
    std::wstring destExe = destDir + L"\\NetVigil.exe";
    if (GetFileAttributesW(destExe.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (_wcsicmp(ExePath().c_str(), destExe.c_str()) == 0) {
            MoveFileExW(destExe.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            MoveFileExW(destDir.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            Logf(L"installed copy removes itself at next reboot");
        } else {
            BOOL deleted = FALSE;
            for (int i = 0; i < 3 && !(deleted = DeleteFileW(destExe.c_str())); ++i)
                Sleep(2000);
            if (deleted) {
                RemoveDirectoryW(destDir.c_str());
                Logf(L"installed copy removed");
            } else {
                Logf(L"could not delete %ls (%u) — remove it manually",
                     destExe.c_str(), GetLastError());
            }
        }
    }
    return rc == 0 ? 0 : 1;
}

static int CmdStop()
{
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, kStopEventName);
    if (!ev) {
        Logf(L"no running NetVigil instance found in this session");
        return 1;
    }
    SetEvent(ev);
    CloseHandle(ev);
    Logf(L"stop signal sent");
    return 0;
}

// ---------------------------------------------------------------- status/once

static int CmdStatus()
{
    Logf(L"NetVigil status");
    Logf(L"  exe:       %ls", ExePath().c_str());
    Logf(L"  elevated:  %ls", g_elevated ? L"yes" : L"no");
    Logf(L"  log:       %ls", g_logPath.c_str());
    Logf(L"  task:      %ls", TaskInstalled() ? L"installed" : L"not installed");

    HANDLE h = OpenWlan();
    if (!h) {
        Logf(L"  WLAN:      unavailable (WlanSvc not running?)");
    } else {
        std::vector<WlanIfaceInfo> ifs = EnumWlanIfaces(h);
        if (ifs.empty()) Logf(L"  WLAN:      no interfaces");
        for (size_t i = 0; i < ifs.size(); ++i) {
            WLAN_INTERFACE_STATE st = GetIfaceState(h, ifs[i].guid);
            std::wstring extra;
            if (st == wlan_interface_state_connected)
                extra = L" (SSID '" + GetConnectedSsid(h, ifs[i].guid) + L"')";
            Logf(L"  WLAN[%zu]:   %ls — %ls%ls", i, ifs[i].desc.c_str(),
                 IfStateStr(st), extra.c_str());
        }
        WlanCloseHandle(h, nullptr);
    }

    ProbeResult a = HttpProbe(L"www.msftconnecttest.com", L"/connecttest.txt",
                              false, "Microsoft Connect Test");
    Logf(L"  probe msftconnecttest: %ls", a.ok ? L"ok" : a.gotResponse
         ? L"unexpected response (portal?)" : L"no response");
    ProbeResult b = HttpProbe(L"www.gstatic.com", L"/generate_204", true, nullptr);
    Logf(L"  probe gstatic-204:     %ls", b.ok ? L"ok" : b.gotResponse
         ? L"unexpected response (portal?)" : L"no response");
    Logf(L"  probe ping 1.1.1.1:    %ls", PingProbe("1.1.1.1") ? L"ok" : L"failed");
    Logf(L"  probe ping 8.8.8.8:    %ls", PingProbe("8.8.8.8") ? L"ok" : L"failed");
    Logf(L"  verdict:   %ls", NetToStr(CheckInternet()));
    return 0;
}

static int CmdOnce()
{
    Net n = CheckInternet();
    Logf(L"connectivity: %ls", NetToStr(n));
    if (n == Net::Online || n == Net::Degraded) return 0;
    ULONGLONG dummy = 0;
    Net after = Remediate(n, dummy);
    Logf(L"final state: %ls", NetToStr(after));
    return after == Net::Online || after == Net::Degraded ? 0 : 1;
}

static void PrintHelp()
{
    fputs(
        "NetVigil - Wi-Fi connectivity watchdog\n"
        "\n"
        "  NetVigil.exe                 run the monitor loop (default 10 min interval)\n"
        "  NetVigil.exe --interval N    monitor with an N-minute check interval\n"
        "  NetVigil.exe --install       register + start the logon task (elevates)\n"
        "  NetVigil.exe --uninstall     stop the monitor and remove the task\n"
        "  NetVigil.exe --stop          signal a running monitor to exit\n"
        "  NetVigil.exe --status        show adapters, probes, task and verdict\n"
        "  NetVigil.exe --once          one check; remediate if offline; exit\n"
        "\n"
        "Escalation on confirmed loss: rejoin Wi-Fi -> disable/enable the Wi-Fi\n"
        "adapter driver -> restart WlanSvc -> reconnect. Driver reset needs the\n"
        "elevated task (or an elevated shell) and is rate-limited to once per 15 min.\n",
        stdout);
    fflush(stdout);
}

// ---------------------------------------------------------------- entry

static BOOL WINAPI CtrlHandler(DWORD)
{
    // Monitor mode: request a clean stop. Other modes have no stop event —
    // fall through to the default handler so Ctrl+C still terminates.
    if (g_stopEvent) {
        SetEvent(g_stopEvent);
        return TRUE;
    }
    return FALSE;
}

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
    BindConsole();

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    g_queryUnbiased = (PfnQueryUnbiased)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "QueryUnbiasedInterruptTime");
    g_elevated = IsElevated();
    InitLog();
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    enum class Mode { Monitor, Once, Status, Install, Uninstall, Stop, Help };
    Mode mode = Mode::Monitor;
    DWORD interval = kDefaultIntervalMin;

    for (int i = 1; argv && i < argc; ++i) {
        std::wstring a = Lower(argv[i]);
        if      (a == L"--once")      mode = Mode::Once;
        else if (a == L"--status")    mode = Mode::Status;
        else if (a == L"--install")   mode = Mode::Install;
        else if (a == L"--uninstall") mode = Mode::Uninstall;
        else if (a == L"--stop")      mode = Mode::Stop;
        else if (a == L"--help" || a == L"-h" || a == L"/?") mode = Mode::Help;
        else if (a == L"--interval" && i + 1 < argc) {
            unsigned long v = wcstoul(argv[++i], nullptr, 10);
            if (v < 1)    v = 1;
            if (v > 1440) v = 1440;
            interval = (DWORD)v;
        } else {
            Logf(L"unknown argument: %ls (see --help)", argv[i]);
            LocalFree(argv);
            WSACleanup();
            return 2;
        }
    }
    if (argv) LocalFree(argv);

    int rc = 0;
    switch (mode) {
    case Mode::Once:      rc = CmdOnce();            break;
    case Mode::Status:    rc = CmdStatus();          break;
    case Mode::Install:   rc = CmdInstall(interval); break;
    case Mode::Uninstall: rc = CmdUninstall();       break;
    case Mode::Stop:      rc = CmdStop();            break;
    case Mode::Help:      PrintHelp();               break;
    default:              rc = RunMonitor(interval); break;
    }

    WSACleanup();
    return rc;
}
