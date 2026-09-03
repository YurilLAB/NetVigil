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

// ------------------------------------------------- RAII resource wrappers
// Every early return frees its resources through these — no manual cleanup
// paths to get wrong.

struct ScopedHandle {                 // CloseHandle (NULL/INVALID = empty)
    HANDLE h = nullptr;
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE v) : h(v) {}
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ~ScopedHandle() { reset(); }
    bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
    void reset(HANDLE v = nullptr) { if (valid()) CloseHandle(h); h = v; }
};

struct ScopedWlan {                   // WlanCloseHandle
    HANDLE h = nullptr;
    explicit ScopedWlan(HANDLE v = nullptr) : h(v) {}
    ScopedWlan(const ScopedWlan&) = delete;
    ScopedWlan& operator=(const ScopedWlan&) = delete;
    ~ScopedWlan() { reset(); }
    void reset(HANDLE v = nullptr) { if (h) WlanCloseHandle(h, nullptr); h = v; }
};

struct ScopedWlanMem {                // WlanFreeMemory
    void* p = nullptr;
    ScopedWlanMem() = default;
    ScopedWlanMem(const ScopedWlanMem&) = delete;
    ScopedWlanMem& operator=(const ScopedWlanMem&) = delete;
    ~ScopedWlanMem() { if (p) WlanFreeMemory(p); }
    template <typename T> T* as() const { return static_cast<T*>(p); }
};

struct ScopedWinHttp {                // WinHttpCloseHandle
    HINTERNET h = nullptr;
    explicit ScopedWinHttp(HINTERNET v) : h(v) {}
    ScopedWinHttp(const ScopedWinHttp&) = delete;
    ScopedWinHttp& operator=(const ScopedWinHttp&) = delete;
    ~ScopedWinHttp() { if (h) WinHttpCloseHandle(h); }
};

struct ScopedSvc {                    // CloseServiceHandle
    SC_HANDLE h = nullptr;
    explicit ScopedSvc(SC_HANDLE v) : h(v) {}
    ScopedSvc(const ScopedSvc&) = delete;
    ScopedSvc& operator=(const ScopedSvc&) = delete;
    ~ScopedSvc() { if (h) CloseServiceHandle(h); }
};

struct ScopedDevInfo {                // SetupDiDestroyDeviceInfoList
    HDEVINFO h = INVALID_HANDLE_VALUE;
    explicit ScopedDevInfo(HDEVINFO v) : h(v) {}
    ScopedDevInfo(const ScopedDevInfo&) = delete;
    ScopedDevInfo& operator=(const ScopedDevInfo&) = delete;
    ~ScopedDevInfo() { if (h != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(h); }
};

struct ScopedRegKey {                 // RegCloseKey
    HKEY k = nullptr;
    explicit ScopedRegKey(HKEY v) : k(v) {}
    ScopedRegKey(const ScopedRegKey&) = delete;
    ScopedRegKey& operator=(const ScopedRegKey&) = delete;
    ~ScopedRegKey() { if (k && k != (HKEY)INVALID_HANDLE_VALUE) RegCloseKey(k); }
};

struct ScopedIcmp {                   // IcmpCloseHandle
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit ScopedIcmp(HANDLE v) : h(v) {}
    ScopedIcmp(const ScopedIcmp&) = delete;
    ScopedIcmp& operator=(const ScopedIcmp&) = delete;
    ~ScopedIcmp() { if (h != INVALID_HANDLE_VALUE) IcmpCloseHandle(h); }
};

static void TrimWorkingSet()
{
    // Long-lived background process about to idle for minutes: hand unneeded
    // pages back to the OS (they page back in on demand).
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
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

// One WinHTTP session for the whole process — proxy discovery and session
// setup are not redone for every probe. The OS reclaims it at exit.
static HINTERNET HttpSession()
{
    static HINTERNET ses = nullptr;
    static bool warned = false;
    if (!ses) {
        ses = WinHttpOpen(L"NetVigil/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!ses)
            ses = WinHttpOpen(L"NetVigil/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (ses)
            WinHttpSetTimeouts(ses, 5000, 5000, 5000, 5000);
        else if (!warned) {
            warned = true;
            Logf(L"WinHttpOpen failed (%u) — HTTP probes unavailable", GetLastError());
        }
    }
    return ses;
}

static ProbeResult HttpProbe(const wchar_t* host, const wchar_t* path,
                             bool expect204, const char* expectBody)
{
    ProbeResult r;
    HINTERNET ses = HttpSession();
    if (!ses) return r;

    ScopedWinHttp con(WinHttpConnect(ses, host, INTERNET_DEFAULT_HTTP_PORT, 0));
    if (!con.h) return r;
    ScopedWinHttp req(WinHttpOpenRequest(con.h, L"GET", path, nullptr,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    if (!req.h) return r;

    DWORD disable = WINHTTP_DISABLE_REDIRECTS; // a portal 302 must not pass
    WinHttpSetOption(req.h, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof disable);
    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req.h, nullptr))
        return r;

    r.gotResponse = true;
    DWORD status = 0, len = sizeof status;
    if (!WinHttpQueryHeaders(req.h,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                             WINHTTP_NO_HEADER_INDEX))
        return r;
    if (expect204) {
        r.ok = (status == 204);
    } else if (status == 200 && expectBody) {
        char body[64] = {};
        DWORD rd = 0;
        if (WinHttpReadData(req.h, body, sizeof body - 1, &rd))
            r.ok = strncmp(body, expectBody, strlen(expectBody)) == 0;
    }
    return r;
}

static bool PingAddr(IPAddr addr)
{
    ScopedIcmp icmp(IcmpCreateFile());
    if (icmp.h == INVALID_HANDLE_VALUE) return false;
    char payload[32] = "NetVigil-probe";
    BYTE reply[sizeof(ICMP_ECHO_REPLY) + sizeof payload + 8] = {};
    DWORD n = IcmpSendEcho(icmp.h, addr, payload, sizeof payload,
                           nullptr, reply, sizeof reply, 3000);
    if (n == 0) return false;
    return ((PICMP_ECHO_REPLY)reply)->Status == IP_SUCCESS;
}

static bool PingProbe(const char* ipStr)
{
    IN_ADDR addr{};
    if (InetPtonA(AF_INET, ipStr, &addr) != 1) return false;
    return PingAddr(addr.S_un.S_addr);
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

// ---------------------------------------------------------------- IP layer

static DWORD RunProcess(const std::wstring& cmdLine, bool quiet); // fwd

struct AdapterIpInfo {
    std::wstring name;
    DWORD  ifIndex   = 0;
    bool   up        = false;
    bool   wireless  = false;
    bool   virt      = false;   // virtual/VPN/tunnel — never DHCP-repair these
    bool   dhcp      = false;
    bool   hasIpv4   = false;
    bool   apipa     = false;   // 169.254.x.x — DHCP never answered
    bool   hasGateway = false;
    IN_ADDR gateway{};
    std::wstring ipv4, gatewayStr, dns;
};

static std::wstring Ipv4ToStr(const IN_ADDR& a)
{
    wchar_t buf[32] = {};
    InetNtopW(AF_INET, (PVOID)&a, buf, 32);
    return buf;
}

static bool LooksVirtualAdapter(const std::wstring& lowerText)
{
    static const wchar_t* kVirt[] = { L"virtual", L"vpn", L"tap", L"tun",
                                      L"loopback", L"vethernet", L"hyper-v",
                                      L"wsl", L"bluetooth", L"tunnel",
                                      L"tailscale", L"zerotier", L"wireguard",
                                      L"wintun" };
    for (const wchar_t* k : kVirt)
        if (lowerText.find(k) != std::wstring::npos) return true;
    return false;
}

static std::vector<AdapterIpInfo> SnapshotAdapters()
{
    std::vector<AdapterIpInfo> out;
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST;
    ULONG sz = 16 * 1024;
    std::vector<BYTE> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.resize(sz);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                  (IP_ADAPTER_ADDRESSES*)buf.data(), &sz);
    }
    if (rc != ERROR_SUCCESS) {
        Logf(L"GetAdaptersAddresses failed (%u)", rc);
        return out;
    }
    for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        AdapterIpInfo inf;
        inf.name     = a->FriendlyName ? a->FriendlyName : L"";
        inf.ifIndex  = a->IfIndex;
        inf.up       = (a->OperStatus == IfOperStatusUp);
        inf.wireless = (a->IfType == IF_TYPE_IEEE80211);
        inf.dhcp     = (a->Dhcpv4Enabled != 0);
        std::wstring desc = a->Description ? a->Description : L"";
        inf.virt     = LooksVirtualAdapter(Lower(inf.name + L" " + desc));
        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr && ua->Address.lpSockaddr->sa_family == AF_INET) {
                IN_ADDR ip = ((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr;
                inf.hasIpv4 = true;
                inf.apipa = (ip.S_un.S_un_b.s_b1 == 169 && ip.S_un.S_un_b.s_b2 == 254);
                inf.ipv4 = Ipv4ToStr(ip);
                break;
            }
        }
        for (auto* ga = a->FirstGatewayAddress; ga; ga = ga->Next) {
            if (ga->Address.lpSockaddr && ga->Address.lpSockaddr->sa_family == AF_INET) {
                inf.gateway = ((sockaddr_in*)ga->Address.lpSockaddr)->sin_addr;
                inf.hasGateway = true;
                inf.gatewayStr = Ipv4ToStr(inf.gateway);
                break;
            }
        }
        int dnsCount = 0;
        for (auto* da = a->FirstDnsServerAddress; da && dnsCount < 2; da = da->Next) {
            if (da->Address.lpSockaddr && da->Address.lpSockaddr->sa_family == AF_INET) {
                if (dnsCount) inf.dns += L", ";
                inf.dns += Ipv4ToStr(((sockaddr_in*)da->Address.lpSockaddr)->sin_addr);
                ++dnsCount;
            }
        }
        out.push_back(std::move(inf));
    }
    return out;
}

static void LogNetSnapshot()
{
    std::vector<AdapterIpInfo> ads = SnapshotAdapters();
    if (ads.empty()) {
        Logf(L"  [ip] no adapters visible to the IP stack");
        return;
    }
    for (const auto& a : ads) {
        if (!a.up && !a.wireless) continue; // down virtual clutter
        Logf(L"  [ip] %ls: %ls, ip %ls%ls, gw %ls, dns %ls",
             a.name.c_str(), a.up ? L"up" : L"down",
             a.hasIpv4 ? a.ipv4.c_str() : L"none",
             a.apipa ? L" (APIPA — DHCP failed)" : L"",
             a.hasGateway ? a.gatewayStr.c_str() : L"none",
             a.dns.empty() ? L"none" : a.dns.c_str());
    }
}

// Release + renew the DHCP lease on one adapter — the fix for an APIPA
// address or a lost gateway after the AP/router restarted.
static bool RenewDhcp(DWORD ifIndex, const std::wstring& name)
{
    ULONG sz = 0;
    DWORD rc = GetInterfaceInfo(nullptr, &sz);
    if (rc != ERROR_INSUFFICIENT_BUFFER || sz == 0) {
        Logf(L"  GetInterfaceInfo failed (%u)", rc);
        return false;
    }
    std::vector<BYTE> buf(sz);
    IP_INTERFACE_INFO* info = (IP_INTERFACE_INFO*)buf.data();
    rc = GetInterfaceInfo(info, &sz);
    if (rc != NO_ERROR) {
        Logf(L"  GetInterfaceInfo failed (%u)", rc);
        return false;
    }
    for (LONG i = 0; i < info->NumAdapters; ++i) {
        if (info->Adapter[i].Index != ifIndex) continue;
        Logf(L"  [%ls] releasing + renewing DHCP lease", name.c_str());
        DWORD rr = IpReleaseAddress(&info->Adapter[i]);
        if (rr != NO_ERROR)
            Logf(L"  IpReleaseAddress rc=%u (continuing)", rr);
        Sleep(1000);
        rr = IpRenewAddress(&info->Adapter[i]);
        Logf(rr == NO_ERROR ? L"  [%ls] DHCP renew ok"
                            : L"  [%ls] DHCP renew failed (%u)", name.c_str(), rr);
        return rr == NO_ERROR;
    }
    Logf(L"  [%ls] not in the DHCP interface table (static IP?)", name.c_str());
    return false;
}

static void FlushDnsCache()
{
    typedef BOOL(WINAPI* PfnFlush)(void);
    static PfnFlush flush = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        if (HMODULE m = LoadLibraryW(Sys32(L"dnsapi.dll").c_str()))
            flush = (PfnFlush)GetProcAddress(m, "DnsFlushResolverCache");
    }
    if (flush && flush()) {
        Logf(L"DNS resolver cache flushed");
        return;
    }
    DWORD rc = RunProcess(L"\"" + Sys32(L"ipconfig.exe") + L"\" /flushdns", true);
    Logf(rc == 0 ? L"DNS resolver cache flushed (ipconfig)"
                 : L"DNS cache flush failed (rc=%u)", rc);
}

// Degraded = ICMP works but HTTP/DNS fails. Try cheap repairs without
// touching Wi-Fi: proxy diagnosis, DNS cache flush. Rate-limited so a real
// upstream DNS outage doesn't get flushed every cycle.
static Net DiagnoseDegraded()
{
    static ULONGLONG lastFix = 0;
    ULONGLONG now = GetTickCount64();
    if (lastFix != 0 && now - lastFix < 30ull * 60 * 1000) return Net::Degraded;
    lastFix = now;

    // If a proxy-bypassing request works, the system proxy is the problem —
    // not something a watchdog should rewrite, but worth naming precisely.
    ScopedWinHttp direct(WinHttpOpen(L"NetVigil/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (direct.h) {
        WinHttpSetTimeouts(direct.h, 5000, 5000, 5000, 5000);
        ScopedWinHttp con(WinHttpConnect(direct.h, L"www.msftconnecttest.com",
                                         INTERNET_DEFAULT_HTTP_PORT, 0));
        ScopedWinHttp req(con.h ? WinHttpOpenRequest(con.h, L"GET", L"/connecttest.txt",
                                                     nullptr, WINHTTP_NO_REFERER,
                                                     WINHTTP_DEFAULT_ACCEPT_TYPES, 0)
                                : nullptr);
        if (req.h &&
            WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(req.h, nullptr)) {
            Logf(L"proxy failure suspected: direct HTTP works but the configured "
                 L"proxy path fails — check the system proxy settings");
            return Net::Degraded;
        }
    }

    FlushDnsCache();
    Sleep(2000);
    Net n = CheckInternet();
    Logf(n == Net::Online ? L"DNS cache flush restored HTTP connectivity"
                          : L"still degraded after DNS flush (upstream DNS problem?)");
    return n;
}

// Does any Wi-Fi adapter's own gateway answer? That specific combination —
// wireless link up, its router reachable, internet dead — proves the Wi-Fi
// path is healthy and the outage is upstream. A live gateway on some OTHER
// NIC (ethernet to a NAS subnet, a phone tether) proves nothing about Wi-Fi.
static bool WifiGatewayAlive()
{
    for (const auto& a : SnapshotAdapters()) {
        if (!a.up || a.virt || !a.wireless || !a.hasGateway) continue;
        if (PingAddr(a.gateway.S_un.S_addr)) {
            Logf(L"[%ls] gateway %ls answers ping", a.name.c_str(),
                 a.gatewayStr.c_str());
            return true;
        }
    }
    return false;
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
    DWORD rc = WlanOpenHandle(2, nullptr, &ver, &h);
    if (rc != ERROR_SUCCESS) {
        Logf(L"WlanOpenHandle failed (%u)", rc);
        return nullptr;
    }
    return h;
}

static std::vector<WlanIfaceInfo> EnumWlanIfaces(HANDLE h)
{
    std::vector<WlanIfaceInfo> out;
    PWLAN_INTERFACE_INFO_LIST list = nullptr;
    DWORD rc = WlanEnumInterfaces(h, nullptr, &list);
    if (rc != ERROR_SUCCESS || !list) {
        if (rc != ERROR_SUCCESS)
            Logf(L"WlanEnumInterfaces failed (%u)", rc);
        return out;
    }
    ScopedWlanMem mem;
    mem.p = list;
    out.reserve(list->dwNumberOfItems);
    for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
        const WLAN_INTERFACE_INFO& it = list->InterfaceInfo[i];
        WlanIfaceInfo inf;
        inf.guid  = it.InterfaceGuid;
        inf.desc  = it.strInterfaceDescription;
        inf.state = it.isState;
        out.push_back(std::move(inf));
    }
    return out;
}

static WLAN_INTERFACE_STATE GetIfaceState(HANDLE h, const GUID& g)
{
    WLAN_INTERFACE_STATE st = wlan_interface_state_not_ready;
    ScopedWlanMem mem;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_interface_state, nullptr,
                           &sz, &mem.p, &t) == ERROR_SUCCESS &&
        mem.p && sz >= sizeof(WLAN_INTERFACE_STATE))
        st = *mem.as<WLAN_INTERFACE_STATE>();
    return st;
}

static std::wstring GetConnectedSsid(HANDLE h, const GUID& g)
{
    std::wstring ssid;
    ScopedWlanMem mem;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_current_connection, nullptr,
                           &sz, &mem.p, &t) == ERROR_SUCCESS &&
        mem.p && sz >= sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
        const WLAN_CONNECTION_ATTRIBUTES* attr = mem.as<WLAN_CONNECTION_ATTRIBUTES>();
        const DOT11_SSID& s = attr->wlanAssociationAttributes.dot11Ssid;
        std::string raw((const char*)s.ucSSID,
                        s.uSSIDLength <= DOT11_SSID_MAX_LENGTH ? s.uSSIDLength : 0);
        ssid = Utf8ToWide(raw);
    }
    return ssid;
}

// Turn on any software-disabled radio; returns true if something was flipped.
static bool EnsureRadioOn(HANDLE h, const GUID& g)
{
    bool flipped = false;
    ScopedWlanMem mem;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_radio_state, nullptr,
                           &sz, &mem.p, &t) != ERROR_SUCCESS ||
        !mem.p || sz < sizeof(WLAN_RADIO_STATE))
        return false;
    WLAN_RADIO_STATE* rs = mem.as<WLAN_RADIO_STATE>();
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
    return flipped;
}

// Windows only auto-reconnects when WLAN auto-config is on; something (a
// tool, a stray netsh) can leave it off and strand the interface.
static void EnsureAutoConfig(HANDLE h, const GUID& g, const std::wstring& desc)
{
    ScopedWlanMem mem;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_autoconf_enabled, nullptr,
                           &sz, &mem.p, &t) != ERROR_SUCCESS ||
        !mem.p || sz < sizeof(BOOL))
        return;
    if (*mem.as<BOOL>()) return;
    BOOL on = TRUE;
    DWORD rc = WlanSetInterface(h, &g, wlan_intf_opcode_autoconf_enabled,
                                sizeof on, &on, nullptr);
    Logf(L"  [%ls] WLAN auto-config was disabled -> re-enabled (rc=%u)",
         desc.c_str(), rc);
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
        ScopedWlanMem mem;
        mem.p = list;
        v.reserve(list->dwNumberOfItems);
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
    EnsureAutoConfig(h, inf.guid, inf.desc);
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
    if (src != ERROR_SUCCESS)
        Logf(L"  [%ls] WlanScan failed (%u) — using cached scan results",
             inf.desc.c_str(), src);
    if (WaitStop(src == ERROR_SUCCESS ? 4500 : 1000)) // scan completes asynchronously
        return false;

    std::vector<Candidate> cands = GetCandidates(h, inf.guid);
    if (cands.empty()) {
        // Hidden APs may not show up in scan results — fall back to the saved
        // profile list in preference order.
        PWLAN_PROFILE_INFO_LIST pl = nullptr;
        if (WlanGetProfileList(h, &inf.guid, nullptr, &pl) == ERROR_SUCCESS && pl) {
            ScopedWlanMem mem;
            mem.p = pl;
            for (DWORD i = 0; i < pl->dwNumberOfItems && i < 5; ++i) {
                Candidate c;
                c.profile = pl->ProfileInfo[i].strProfileName;
                cands.push_back(std::move(c));
            }
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
    ScopedWlan wl(OpenWlan());
    if (!wl.h && g_elevated) {
        Logf(L"WlanOpenHandle failed — making sure WlanSvc is running");
        StartOrRestartWlanSvc(false);
        Sleep(3000);
        wl.reset(OpenWlan());
    }
    if (!wl.h) {
        Logf(L"cannot talk to WLAN service (WlanOpenHandle failed)");
        return false;
    }
    std::vector<WlanIfaceInfo> ifs = EnumWlanIfaces(wl.h);
    if (ifs.empty())
        Logf(L"no WLAN interfaces present (adapter unplugged, disabled, or driver wedged)");
    bool any = false;
    for (const auto& i : ifs)
        any = ReconnectIface(wl.h, i, bounceIfConnected) || any;
    return any;
}

// NetCfgInstanceId strings ("{...}") of current WLAN interfaces, physical
// ones preferred (skip Wi-Fi Direct style virtual interfaces).
static std::vector<std::wstring> CurrentWlanAdapterIds()
{
    std::vector<std::wstring> ids;
    ScopedWlan wl(OpenWlan());
    if (!wl.h) return ids;
    for (const auto& i : EnumWlanIfaces(wl.h)) {
        if (Lower(i.desc).find(L"virtual") != std::wstring::npos) continue;
        wchar_t g[64] = {};
        if (StringFromGUID2(i.guid, g, 64) > 0) ids.push_back(g);
    }
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
    ScopedRegKey key(SetupDiOpenDevRegKey(devs, did, DICS_FLAG_GLOBAL, 0,
                                          DIREG_DRV, KEY_READ));
    if (key.k != (HKEY)INVALID_HANDLE_VALUE) {
        wchar_t buf[64] = {};
        DWORD sz = sizeof buf - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(key.k, L"NetCfgInstanceId", nullptr, &type,
                             (PBYTE)buf, &sz) == ERROR_SUCCESS && type == REG_SZ)
            id = buf;
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

// A repeatedly-dying adapter (USB Wi-Fi especially) is often being powered
// down by Windows. PnPCapabilities=0x18 removes the power-off capability;
// it takes effect on the disable/enable cycle that follows.
static void DisableAdapterPowerSaving(HDEVINFO devs, SP_DEVINFO_DATA* did,
                                      const std::wstring& desc)
{
    ScopedRegKey key(SetupDiOpenDevRegKey(devs, did, DICS_FLAG_GLOBAL, 0,
                                          DIREG_DRV, KEY_READ | KEY_SET_VALUE));
    if (key.k == (HKEY)INVALID_HANDLE_VALUE) {
        Logf(L"  [%ls] cannot open driver key to adjust power management (%u)",
             desc.c_str(), GetLastError());
        return;
    }
    DWORD val = 0x18;
    DWORD cur = 0, curSz = sizeof cur, type = 0;
    if (RegQueryValueExW(key.k, L"PnPCapabilities", nullptr, &type,
                         (PBYTE)&cur, &curSz) == ERROR_SUCCESS &&
        type == REG_DWORD && cur == val)
        return; // already applied
    LONG rc = RegSetValueExW(key.k, L"PnPCapabilities", 0, REG_DWORD,
                             (const BYTE*)&val, sizeof val);
    Logf(rc == ERROR_SUCCESS
             ? L"  [%ls] repeated resets needed — disabled Windows power-down "
               L"for this adapter (PnPCapabilities=0x18)"
             : L"  [%ls] failed to adjust adapter power management (rc=%ld)",
         desc.c_str(), rc);
}

// Disable/enable Wi-Fi adapters (a driver-level reset). If targetIds is
// empty — the adapter vanished from WlanSvc — fall back to resetting present
// net-class devices that look wireless. When fixPower is set, also stop
// Windows from powering the adapter down. Returns how many were reset.
static int ResetWifiAdapters(const std::vector<std::wstring>& targetIds, bool fixPower)
{
    int resetCount = 0;
    ScopedDevInfo devInfo(SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr,
                                               DIGCF_PRESENT));
    HDEVINFO devs = devInfo.h;
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
        if (fixPower)
            DisableAdapterPowerSaving(devs, &did, desc); // applies on the enable
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
    if (resetCount) {
        Logf(L"%d adapter(s) reset — waiting for driver re-init", resetCount);
        WaitStop(8000);
    }
    return resetCount;
}

// ---------------------------------------------------------------- WlanSvc

static bool StartOrRestartWlanSvc(bool forceRestart)
{
    ScopedSvc scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) {
        Logf(L"OpenSCManager failed (%u)", GetLastError());
        return false;
    }
    ScopedSvc svcGuard(OpenServiceW(scm.h, L"WlanSvc",
                                    SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS));
    SC_HANDLE svc = svcGuard.h;
    if (!svc) {
        Logf(L"OpenService(WlanSvc) failed (%u)", GetLastError());
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

    Logf(L"WlanSvc %ls %ls", forceRestart ? L"restart" : L"start-check",
         ok ? L"ok" : L"FAILED");
    return ok;
}

// ---------------------------------------------------------------- remediation

// Driver resets that were followed by connectivity coming back — evidence
// that the adapter keeps dying and the reset is what revives it. Two of
// those justify the persistent power-management fix; futile resets (AP down,
// ISP out) never count.
static int g_effectiveResets = 0;

static ULONGLONG kDhcpRenewCooldownMs = 10ull * 60 * 1000;
static ULONGLONG g_lastDhcpRenew = 0;

// Escalating repair. Returns connectivity state afterwards.
static Net Remediate(Net current, ULONGLONG& lastResetTick)
{
    // Stage 0: IP-layer triage BEFORE touching the association, so a healthy
    // link is never bounced when the problem is not the Wi-Fi link at all.
    bool upstreamSuspected = false;
    {
        std::vector<AdapterIpInfo> ads = SnapshotAdapters();
        bool renewed = false;
        for (const auto& a : ads) {
            if (!a.up || a.virt || !a.dhcp) continue;
            // A gateway-less lease is only "broken" on Wi-Fi — wired subnets
            // can legitimately have no default route (NAS/lab links).
            bool broken = !a.hasIpv4 || a.apipa || (a.wireless && !a.hasGateway);
            if (!broken) continue;
            Logf(L"[%ls] broken IP configuration (%ls)", a.name.c_str(),
                 !a.hasIpv4 ? L"no IPv4 address"
                            : a.apipa ? L"APIPA self-assigned address"
                                      : L"no default gateway");
            if (!g_elevated) {
                Logf(L"  DHCP repair skipped: not elevated");
                continue;
            }
            ULONGLONG now = GetTickCount64();
            if (g_lastDhcpRenew != 0 && now - g_lastDhcpRenew < kDhcpRenewCooldownMs) {
                Logf(L"  DHCP repair skipped: cooldown");
                continue;
            }
            g_lastDhcpRenew = now;
            renewed = RenewDhcp(a.ifIndex, a.name) || renewed;
        }
        if (renewed) {
            if (WaitStop(3000)) return current;
            Net r = CheckInternet();
            Logf(L"after DHCP repair: %ls", NetToStr(r));
            if (r != Net::Offline) return r;
        }
        upstreamSuspected = WifiGatewayAlive();
        if (upstreamSuspected)
            Logf(L"Wi-Fi gateway responds while the internet is down — "
                 L"upstream/ISP outage suspected; keeping the current association");
    }

    // Stage 1: rejoin Wi-Fi. Behind a captive portal or during an upstream
    // outage the association itself is fine — only attach disconnected
    // interfaces instead of bouncing a good one.
    Logf(L"remediation stage 1: Wi-Fi reconnect");
    WifiReconnectAll(/*bounceIfConnected=*/current != Net::Portal && !upstreamSuspected);
    if (WaitStop(5000)) return current;
    Net n = CheckInternet();
    Logf(L"after stage 1: %ls", NetToStr(n));
    if (n == Net::Online || n == Net::Degraded) return n;
    if (n == Net::Portal) {
        Logf(L"captive portal suspected — driver reset would not help; "
             L"complete the portal sign-in in a browser");
        return n;
    }

    // If the Wi-Fi path's own gateway answers, the driver is fine and the
    // outage is upstream — resetting hardware cannot bring the internet back.
    if (StopRequested()) return n;
    if (WifiGatewayAlive()) {
        Logf(L"upstream/ISP outage — skipping driver reset, retrying on the "
             L"short interval");
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
    int cnt = ResetWifiAdapters(ids, g_effectiveResets >= 2);
    if (cnt == 0) {
        Logf(L"no adapter could be reset — restarting WlanSvc instead");
        StartOrRestartWlanSvc(true);
    }
    if (WaitStop(3000)) return n;
    WifiReconnectAll(true);
    if (WaitStop(5000)) return n;
    n = CheckInternet();
    Logf(L"after stage 2: %ls", NetToStr(n));
    if (cnt > 0 && n != Net::Offline) ++g_effectiveResets; // the reset worked
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
    TrimWorkingSet();
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
    ScopedHandle mutex(CreateMutexW(sa, FALSE, kMutexName));
    DWORD mutexErr = GetLastError();
    if (!mutex.valid()) {
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
        return 1;
    }

    // A watchdog should never compete with foreground work for the CPU.
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);

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
    ULONGLONG offlineSince = 0;

    for (;;) {
        Net n = CheckInternet();

        if (n == Net::Online || n == Net::Degraded) {
            if (failStreak > 0) {
                Logf(L"connectivity restored after %llu min offline",
                     offlineSince ? (GetTickCount64() - offlineSince) / 60000ull : 0);
                offlineSince = 0;
            }
            if (n == Net::Degraded) {
                Logf(L"degraded: ICMP works but HTTP/DNS failing — "
                     L"attempting lightweight repair");
                DiagnoseDegraded(); // proxy diagnosis + DNS flush, rate-limited
            } else if (GetTickCount64() - lastOkLog > 3600000ull) {
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
        if (failStreak == 1) {
            offlineSince = GetTickCount64();
            LogNetSnapshot(); // adapter/IP/gateway/DNS state at the moment of loss
        }
        Logf(L"confirmed %ls (streak %d) — starting remediation",
             NetToStr(n2), failStreak);
        Net after = Remediate(n2, lastReset);

        if (after == Net::Online || after == Net::Degraded) {
            Logf(L"remediation succeeded — back online after %llu min",
                 offlineSince ? (GetTickCount64() - offlineSince) / 60000ull : 0);
            offlineSince = 0;
            failStreak = 0;
            if (IntervalWait(intervalMin)) break;
        } else {
            Logf(L"still %ls — next attempt in %u min", NetToStr(after), kOfflineRetryMin);
            if (IntervalWait(kOfflineRetryMin)) break;
        }
    }

    Logf(L"stop requested — NetVigil exiting");
    if (g_stopEvent) {
        HANDLE ev = g_stopEvent;
        g_stopEvent = nullptr; // CtrlHandler must not touch a closed handle
        CloseHandle(ev);
    }
    return 0;
}

// ---------------------------------------------------------------- task mgmt

static DWORD RunProcess(const std::wstring& cmdLine, bool quiet)
{
    STARTUPINFOW si{};
    si.cb = sizeof si;
    ScopedHandle nul;
    if (quiet) {
        SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        nul.reset(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa,
                              OPEN_EXISTING, 0, nullptr));
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = nul.h;
        si.hStdError  = nul.h;
        si.hStdInput  = nullptr;
    }
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, 0,
                        nullptr, nullptr, &si, &pi)) {
        Logf(L"CreateProcess failed (%u): %ls", GetLastError(), cmdLine.c_str());
        return (DWORD)-1;
    }
    ScopedHandle proc(pi.hProcess), thread(pi.hThread);
    if (WaitForSingleObject(proc.h, 60000) == WAIT_TIMEOUT) // bounded
        Logf(L"child process still running after 60 s: %ls", cmdLine.c_str());
    DWORD code = (DWORD)-1;
    GetExitCodeProcess(proc.h, &code);
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
    if (!ShellExecuteExW(&sei)) {
        Logf(L"elevation request failed (%u)", GetLastError());
        return false;
    }
    DWORD code = 0;
    if (sei.hProcess) {
        ScopedHandle proc(sei.hProcess);
        if (WaitForSingleObject(proc.h, 120000) == WAIT_TIMEOUT) {
            Logf(L"elevated helper still running after 120 s — see the log for its outcome");
            return true;
        }
        GetExitCodeProcess(proc.h, &code);
    }
    if (code != 0)
        Logf(L"elevated helper finished with exit code %u", code);
    return code == 0;
}

static int CmdInstall(DWORD intervalMin)
{
    if (!g_elevated) {
        Logf(L"elevation required to register the startup task — requesting UAC...");
        std::wstring args = L"--install --interval " + std::to_wstring(intervalMin);
        if (!RelaunchElevated(args.c_str())) {
            Logf(L"elevation was declined or the helper failed — "
                 L"run --install from an elevated terminal (see %ls)",
                 g_logPath.c_str());
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
            Logf(L"elevation was declined or the helper failed — "
                 L"run --uninstall from an elevated terminal (see %ls)",
                 g_logPath.c_str());
            return 1;
        }
        return 0;
    }
    SignalRunningInstance();
    WaitInstanceExit(30000);
    DWORD rc = 0;
    if (!TaskInstalled()) {
        Logf(L"startup task was not installed — nothing to remove");
    } else {
        std::wstring cmd = L"\"" + Sys32(L"schtasks.exe") + L"\" /Delete /F /TN " + kTaskName;
        rc = RunProcess(cmd, false);
        Logf(rc == 0 ? L"startup task removed" : L"schtasks /Delete failed (exit %u)", rc);
    }

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

    ScopedWlan wl(OpenWlan());
    if (!wl.h) {
        Logf(L"  WLAN:      unavailable (WlanSvc not running?)");
    } else {
        std::vector<WlanIfaceInfo> ifs = EnumWlanIfaces(wl.h);
        if (ifs.empty()) Logf(L"  WLAN:      no interfaces");
        for (size_t i = 0; i < ifs.size(); ++i) {
            WLAN_INTERFACE_STATE st = GetIfaceState(wl.h, ifs[i].guid);
            std::wstring extra;
            if (st == wlan_interface_state_connected)
                extra = L" (SSID '" + GetConnectedSsid(wl.h, ifs[i].guid) + L"')";
            Logf(L"  WLAN[%zu]:   %ls — %ls%ls", i, ifs[i].desc.c_str(),
                 IfStateStr(st), extra.c_str());
        }
    }
    LogNetSnapshot();

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
    if (n == Net::Degraded) {
        n = DiagnoseDegraded();
        Logf(L"after lightweight repair: %ls", NetToStr(n));
    }
    if (n == Net::Online || n == Net::Degraded) return 0;
    LogNetSnapshot();
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

// Last-gasp logging so a crash of the long-running monitor is visible in the
// log instead of the process just vanishing.
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    Logf(L"FATAL: unhandled exception 0x%08X at %p — exiting",
         ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0,
         ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr);
    return EXCEPTION_EXECUTE_HANDLER;
}

static bool g_wsaOk = false;

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
    BindConsole();
    InitLog();
    SetUnhandledExceptionFilter(CrashFilter);

    WSADATA wsa;
    int wsaRc = WSAStartup(MAKEWORD(2, 2), &wsa);
    g_wsaOk = (wsaRc == 0);
    if (!g_wsaOk)
        Logf(L"WSAStartup failed (%d) — continuing; probes are unaffected", wsaRc);
    g_queryUnbiased = (PfnQueryUnbiased)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "QueryUnbiasedInterruptTime");
    g_elevated = IsElevated();
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
            if (g_wsaOk) WSACleanup();
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

    if (g_wsaOk) WSACleanup();
    return rc;
}
