// NetVigil — connectivity watchdog for Windows.
//
// Runs at logon (scheduled task), probes internet connectivity on an interval
// (default 10 min; at once when Windows reports a connectivity change or the
// machine wakes) and, when the connection is confirmed down, works out WHY
// before touching anything:
//   observe   adapters, driver state, Wi-Fi radio and association, services,
//             routing, gateway reachability, DNS, proxy, clock
//   diagnose  nv::Diagnose (diagnose.cpp) names the fault and orders the
//             repairs cheapest-first — heavy ones (driver reset, WlanSvc
//             restart) only for faults they can actually fix
//   repair    every step is verified; the situation is re-diagnosed when a
//             plan runs out
// Works with internal and USB Wi-Fi as well as wired adapters; interfaces
// and devices are re-enumerated on every cycle.

#include "core.h"
#include "diagnose.h"
#include "startup.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <initguid.h>
#include <devguid.h>
#include <wlanapi.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <windns.h>
#include <shellapi.h>
#include <sddl.h>

#include <cstddef>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <ctime>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <deque>
#include <memory>
#include <atomic>
#include <functional>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

bool DisableManualProxy(std::wstring* previous); // proxy.cpp

// ---------------------------------------------------------------- constants

static const wchar_t* kTaskName      = L"NetVigil";
static const wchar_t* kMutexName     = L"Local\\NetVigil.single";
static const wchar_t* kStopEventName = L"Local\\NetVigil.stop";
const wchar_t* const  kPortalUrl     = L"http://www.msftconnecttest.com/redirect";
static const char*    kDnsProbeHost  = "www.msftconnecttest.com";

static const DWORD     kDefaultIntervalMin = 10;   // normal check cadence
static const DWORD     kOfflineRetryMin    = 2;    // cadence while still down
static const DWORD     kRelaunchMin        = 10;   // task repetition that restarts a dead watchdog
static const ULONGLONG kResetCooldownMs    = 15ull * 60 * 1000; // between driver resets
static const ULONGLONG kAuthFailWindowMs   = 30ull * 60 * 1000; // skip a rejected profile this long
static const long long kWifiMemorySec      = 7ll * 86400;       // a vanished Wi-Fi adapter counts as missing
static const ULONGLONG kLogRotateBytes     = 1ull << 20;        // 1 MiB

// ---------------------------------------------------------------- globals

static std::wstring g_logPath;
static std::wstring g_iniPath;
static std::wstring g_dataDir;
static bool         g_elevated  = false;
static bool         g_helper    = false;     // --helper: temp copy running an uninstall
static bool         g_wsaOk     = false;
static HANDLE       g_stopEvent = nullptr;   // manual-reset, named: "exit"
static HANDLE       g_wakeEvent = nullptr;   // auto-reset: "check now"
static HANDLE       g_hintEvent = nullptr;   // auto-reset: Windows' connectivity level changed
static volatile LONG g_hintLevel = -1;       // NL_NETWORK_CONNECTIVITY_LEVEL_HINT, -1 = unknown
static volatile LONG g_resumed   = 0;        // set by NotifyResumed()

static CRITICAL_SECTION g_logCs, g_stateCs, g_cfgCs, g_wlanCs;
static std::deque<std::wstring> g_logRing;   // tail shown in the GUI
static unsigned long long g_logSeq = 0;      // lines ever logged
static const size_t kLogRingMax = 400;

static MonitorState g_state;
static volatile LONG g_paused      = 0;
static volatile LONG g_intervalMin = (LONG)kDefaultIntervalMin;
static volatile LONG g_notify      = 1;
static volatile LONG g_failover    = 1;
static HWND g_uiHwnd = nullptr;
static UINT g_uiMsg  = 0;

static void NotifyUi(UiEvent ev, LPARAM lp = 0)
{
    if (g_uiHwnd) PostMessageW(g_uiHwnd, g_uiMsg, ev, lp);
}

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

static void AppendLogFile(const std::string& bytes)
{
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
    DWORD written = 0;
    WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
    CloseHandle(h);
}

// Called from the worker, the UI thread and WLAN/helper threads.
static void LogLine(const std::wstring& msg)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t stamp[40];
    swprintf_s(stamp, L"%04u-%02u-%02u %02u:%02u:%02u  ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::wstring line = std::wstring(stamp) + msg;
    std::string console = WideToUtf8(line + L"\n");

    EnterCriticalSection(&g_logCs);
    fputs(console.c_str(), stdout);
    fflush(stdout);
    g_logRing.push_back(line);
    if (g_logRing.size() > kLogRingMax) g_logRing.pop_front();
    ++g_logSeq;
    if (!g_logPath.empty()) AppendLogFile(WideToUtf8(line + L"\r\n"));
    LeaveCriticalSection(&g_logCs);

    NotifyUi(UiLogAppended);
}

void Logf(const wchar_t* fmt, ...)
{
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    LogLine(buf);
}

std::vector<std::wstring> GetLogSince(unsigned long long& seq)
{
    std::vector<std::wstring> out;
    EnterCriticalSection(&g_logCs);
    unsigned long long oldest = g_logSeq - g_logRing.size(); // seq of ring[0]
    unsigned long long from = seq < oldest ? oldest : seq;
    for (unsigned long long i = from; i < g_logSeq; ++i)
        out.push_back(g_logRing[(size_t)(i - oldest)]);
    seq = g_logSeq;
    LeaveCriticalSection(&g_logCs);
    return out;
}

const std::wstring& LogPath() { return g_logPath; }

static void InitCore()
{
    InitializeCriticalSection(&g_logCs);
    InitializeCriticalSection(&g_stateCs);
    InitializeCriticalSection(&g_cfgCs);
    InitializeCriticalSection(&g_wlanCs);
    g_wakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_hintEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

static void InitLog()
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::wstring dir = (n > 0 && n < MAX_PATH) ? std::wstring(buf) + L"\\NetVigil"
                                               : ExeDir();
    CreateDirectoryW(dir.c_str(), nullptr);
    g_dataDir = dir;
    g_logPath = dir + L"\\netvigil.log";
    g_iniPath = dir + L"\\netvigil.ini";
}

const std::wstring& DataDir() { return g_dataDir; }

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

static bool TokenIsElevated(HANDLE tok)
{
    TOKEN_ELEVATION el{};
    DWORD n = 0;
    return GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n) && el.TokenIsElevated;
}

static bool IsElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    bool ok = TokenIsElevated(tok);
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

// Runs fn on a helper thread and waits at most `ms`. A wedged driver can
// block SetupAPI, WLAN or resolver calls indefinitely; on timeout the helper
// is abandoned (fn must own everything it touches — capture by value or
// shared_ptr) and the watchdog carries on instead of hanging with it.
static DWORD WINAPI BoundedThunk(LPVOID p)
{
    std::unique_ptr<std::function<void()>> fn(static_cast<std::function<void()>*>(p));
    (*fn)();
    return 0;
}

static bool RunBounded(DWORD ms, std::function<void()> fn)
{
    auto* job = new std::function<void()>(std::move(fn));
    HANDLE t = CreateThread(nullptr, 0, BoundedThunk, job, 0, nullptr);
    if (!t) {                       // no thread to spare: run it inline
        (*job)();
        delete job;
        return true;
    }
    bool done = WaitForSingleObject(t, ms) == WAIT_OBJECT_0;
    CloseHandle(t);
    return done;
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

struct ScopedSocket {                 // closesocket
    SOCKET s = INVALID_SOCKET;
    explicit ScopedSocket(SOCKET v) : s(v) {}
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;
    ~ScopedSocket() { if (s != INVALID_SOCKET) closesocket(s); }
    bool valid() const { return s != INVALID_SOCKET; }
};

static void TrimWorkingSet()
{
    // Long-lived background process about to idle for minutes: hand unneeded
    // pages back to the OS (they page back in on demand).
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

static bool RegReadDword(HKEY root, const std::wstring& path, const wchar_t* value, DWORD& out)
{
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return false;
    ScopedRegKey guard(k);
    DWORD v = 0, sz = sizeof v, type = 0;
    if (RegQueryValueExW(k, value, nullptr, &type, (BYTE*)&v, &sz) != ERROR_SUCCESS ||
        type != REG_DWORD)
        return false;
    out = v;
    return true;
}

static std::wstring RegReadString(HKEY root, const std::wstring& path, const wchar_t* value)
{
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return L"";
    ScopedRegKey guard(k);
    wchar_t buf[512] = {};
    DWORD sz = sizeof buf - sizeof(wchar_t), type = 0;
    if (RegQueryValueExW(k, value, nullptr, &type, (BYTE*)buf, &sz) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_MULTI_SZ && type != REG_EXPAND_SZ))
        return L"";
    return buf;
}

// ---------------------------------------------------------------- monitor state

template <typename F>
static void UpdateState(F fn)
{
    EnterCriticalSection(&g_stateCs);
    fn(g_state);
    LeaveCriticalSection(&g_stateCs);
    NotifyUi(UiStateChanged);
}

MonitorState GetMonitorState()
{
    EnterCriticalSection(&g_stateCs);
    MonitorState s = g_state;
    LeaveCriticalSection(&g_stateCs);
    return s;
}

void SetUiNotify(HWND hwnd, UINT msg)
{
    g_uiHwnd = hwnd;
    g_uiMsg  = msg;
}

void RequestCheckNow()
{
    if (g_wakeEvent) SetEvent(g_wakeEvent);
}

void NotifyResumed()
{
    InterlockedExchange(&g_resumed, 1);
    RequestCheckNow();
}

void SetPaused(bool paused)
{
    InterlockedExchange(&g_paused, paused ? 1 : 0);
    UpdateState([&](MonitorState& s) { s.paused = paused; });
    Logf(paused ? L"monitoring paused" : L"monitoring resumed");
    RequestCheckNow(); // wake the worker so it notices either way
}

static void MarkUserExit(); // fwd (config)

void RequestStop(bool byUser)
{
    if (byUser) MarkUserExit();
    if (g_stopEvent) SetEvent(g_stopEvent);
    UpdateState([](MonitorState& s) { s.stopping = true; });
}

// ---------------------------------------------------------------- config (ini)
//
// %LOCALAPPDATA%\NetVigil\netvigil.ini
//   [settings]  interval=10  notifications=1  failover=1  wifiSeen=<unix>
//               exitedLogon=<logon stamp>  disabledProxy=<server>
//   [networks]  <profile>=preferred|never        (absent = allowed)
//   [seen]      <profile>=<unix-time>|<connects>|<ssid>
//   [repairs]   <repair>=<times it brought the connection back>
//   [resets]    <adapter guid>=<driver resets that revived it>

struct SeenInfo {
    long long lastSeen = 0;
    int connects = 0;
    std::wstring ssid;
};
static std::map<std::wstring, NetMode>  g_modes;
static std::map<std::wstring, SeenInfo> g_seen;
static std::wstring g_lastRecordedProfile;

static const wchar_t* ModeStr(NetMode m)
{
    switch (m) {
    case NetMode::Preferred: return L"preferred";
    case NetMode::Never:     return L"never";
    default:                 return L"allowed";
    }
}

static NetMode ParseMode(const std::wstring& s)
{
    std::wstring l = Lower(s);
    if (l == L"preferred") return NetMode::Preferred;
    if (l == L"never")     return NetMode::Never;
    return NetMode::Allowed;
}

// INI keys cannot carry these characters; such profile names are simply not
// persisted (they still work for connecting).
static bool IniSafeKey(const std::wstring& k)
{
    return !k.empty() && k.find_first_of(L"=[]\r\n") == std::wstring::npos;
}

// WritePrivateProfileStringW only preserves non-ASCII (SSIDs!) in a file that
// is already UTF-16LE — create it with a BOM before first use.
static void EnsureUnicodeIni()
{
    if (GetFileAttributesW(g_iniPath.c_str()) != INVALID_FILE_ATTRIBUTES) return;
    ScopedHandle f(CreateFileW(g_iniPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!f.valid()) return;
    const BYTE bom[] = { 0xFF, 0xFE, '\r', 0, '\n', 0 };
    DWORD w = 0;
    WriteFile(f.h, bom, sizeof bom, &w, nullptr);
}

static std::vector<std::pair<std::wstring, std::wstring>> ReadIniSection(const wchar_t* section)
{
    std::vector<std::pair<std::wstring, std::wstring>> out;
    std::vector<wchar_t> buf(32768);
    DWORD n = GetPrivateProfileSectionW(section, buf.data(), (DWORD)buf.size(),
                                        g_iniPath.c_str());
    if (n == 0) return out;
    for (const wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) {
        const wchar_t* eq = wcschr(p, L'=');
        if (!eq) continue;
        out.emplace_back(std::wstring(p, eq), std::wstring(eq + 1));
    }
    return out;
}

static void SaveSetting(const wchar_t* key, const std::wstring& value)
{
    EnsureUnicodeIni();
    WritePrivateProfileStringW(L"settings", key, value.c_str(), g_iniPath.c_str());
}

static long long ReadSettingInt64(const wchar_t* key)
{
    wchar_t buf[32] = {};
    GetPrivateProfileStringW(L"settings", key, L"", buf, 32, g_iniPath.c_str());
    return _wtoi64(buf);
}

static void LoadConfig(DWORD intervalArg)
{
    EnsureUnicodeIni();
    UINT iv = GetPrivateProfileIntW(L"settings", L"interval", 0, g_iniPath.c_str());
    InterlockedExchange(&g_intervalMin, (iv >= 1 && iv <= 1440) ? (LONG)iv : (LONG)intervalArg);
    InterlockedExchange(&g_notify,
        GetPrivateProfileIntW(L"settings", L"notifications", 1, g_iniPath.c_str()) ? 1 : 0);
    InterlockedExchange(&g_failover,
        GetPrivateProfileIntW(L"settings", L"failover", 1, g_iniPath.c_str()) ? 1 : 0);

    EnterCriticalSection(&g_cfgCs);
    for (const auto& kv : ReadIniSection(L"networks"))
        g_modes[kv.first] = ParseMode(kv.second);
    for (const auto& kv : ReadIniSection(L"seen")) {
        SeenInfo s;
        const std::wstring& v = kv.second;
        size_t p1 = v.find(L'|');
        size_t p2 = p1 == std::wstring::npos ? p1 : v.find(L'|', p1 + 1);
        s.lastSeen = _wtoi64(v.c_str());
        if (p1 != std::wstring::npos) s.connects = _wtoi(v.c_str() + p1 + 1);
        if (p2 != std::wstring::npos) s.ssid = v.substr(p2 + 1);
        g_seen[kv.first] = s;
    }
    size_t modes = g_modes.size(), seen = g_seen.size();
    LeaveCriticalSection(&g_cfgCs);
    Logf(L"config: %zu network preference(s), %zu remembered network(s), interval %u min",
         modes, seen, (unsigned)g_intervalMin);
}

static void SaveSeen(const std::wstring& profile, const SeenInfo& s)
{
    std::wstring v = std::to_wstring(s.lastSeen) + L"|" +
                     std::to_wstring(s.connects) + L"|" + s.ssid;
    WritePrivateProfileStringW(L"seen", profile.c_str(), v.c_str(), g_iniPath.c_str());
}

// Remember the network the machine is on. Writes only on a change of
// network or every 30 min, so the ini is not churned every cycle.
static void RecordConnected(const std::wstring& profile, const std::wstring& ssid)
{
    if (!IniSafeKey(profile)) return;
    long long now = (long long)_time64(nullptr);
    EnterCriticalSection(&g_cfgCs);
    SeenInfo& s = g_seen[profile];
    bool changed = profile != g_lastRecordedProfile;
    if (changed) {
        ++s.connects;
        g_lastRecordedProfile = profile;
    }
    if (changed || now - s.lastSeen > 1800) {
        s.lastSeen = now;
        s.ssid = ssid;
        SaveSeen(profile, s);
    }
    int connects = s.connects;
    LeaveCriticalSection(&g_cfgCs);
    if (changed)
        Logf(L"on network '%ls' (remembered; connected %d time%ls)",
             profile.c_str(), connects, connects == 1 ? L"" : L"s");
}

static NetMode ModeOf(const std::wstring& profile)
{
    EnterCriticalSection(&g_cfgCs);
    auto it = g_modes.find(profile);
    NetMode m = it == g_modes.end() ? NetMode::Allowed : it->second;
    LeaveCriticalSection(&g_cfgCs);
    return m;
}

void SetNetworkMode(const std::wstring& profile, NetMode mode)
{
    if (!IniSafeKey(profile)) {
        Logf(L"cannot save a preference for '%ls' (unsupported characters in name)",
             profile.c_str());
        return;
    }
    EnterCriticalSection(&g_cfgCs);
    if (mode == NetMode::Preferred) { // only one preferred network at a time
        for (auto& kv : g_modes) {
            if (kv.second == NetMode::Preferred && kv.first != profile) {
                kv.second = NetMode::Allowed;
                WritePrivateProfileStringW(L"networks", kv.first.c_str(), nullptr,
                                           g_iniPath.c_str());
            }
        }
    }
    if (mode == NetMode::Allowed) {
        g_modes.erase(profile);
        WritePrivateProfileStringW(L"networks", profile.c_str(), nullptr, g_iniPath.c_str());
    } else {
        g_modes[profile] = mode;
        WritePrivateProfileStringW(L"networks", profile.c_str(), ModeStr(mode),
                                   g_iniPath.c_str());
    }
    LeaveCriticalSection(&g_cfgCs);
    Logf(L"network '%ls' set to: %ls", profile.c_str(), ModeStr(mode));
    NotifyUi(UiStateChanged);
}

DWORD GetIntervalMin() { return (DWORD)g_intervalMin; }

void SetIntervalMin(DWORD minutes)
{
    if (minutes < 1) minutes = 1;
    if (minutes > 1440) minutes = 1440;
    InterlockedExchange(&g_intervalMin, (LONG)minutes);
    SaveSetting(L"interval", std::to_wstring(minutes));
    Logf(L"check interval set to %u min", minutes);
}

bool GetNotifications() { return g_notify != 0; }

void SetNotifications(bool on)
{
    InterlockedExchange(&g_notify, on ? 1 : 0);
    SaveSetting(L"notifications", on ? L"1" : L"0");
}

bool GetFailover() { return g_failover != 0; }

void SetFailover(bool on)
{
    InterlockedExchange(&g_failover, on ? 1 : 0);
    SaveSetting(L"failover", on ? L"1" : L"0");
    Logf(on ? L"ISP-outage failover to other saved networks enabled"
            : L"ISP-outage failover to other saved networks disabled");
}

// "Exit" from the tray (or --stop) means: stay stopped until the next
// sign-in — the startup task's relaunch trigger checks this marker.
static void MarkUserExit()
{
    long long stamp = SessionLogonStamp();
    if (stamp) SaveSetting(L"exitedLogon", std::to_wstring(stamp));
}

static void ClearUserExit()
{
    WritePrivateProfileStringW(L"settings", L"exitedLogon", nullptr, g_iniPath.c_str());
}

static bool UserExitedThisSession()
{
    long long stamp = SessionLogonStamp();
    return stamp != 0 && ReadSettingInt64(L"exitedLogon") == stamp;
}

// Wi-Fi hardware memory, so a USB dongle that dropped off the bus is
// recognised as missing rather than as "no Wi-Fi on this machine".
static void RememberWifiSeen()
{
    static long long lastSaved = 0;
    long long now = (long long)_time64(nullptr);
    if (now - lastSaved < 3600) return;
    lastSaved = now;
    SaveSetting(L"wifiSeen", std::to_wstring(now));
}

static bool WifiSeenRecently()
{
    long long seen = ReadSettingInt64(L"wifiSeen");
    return seen > 0 && (long long)_time64(nullptr) - seen < kWifiMemorySec;
}

static int IniCount(const wchar_t* section, const std::wstring& key)
{
    return (int)GetPrivateProfileIntW(section, key.c_str(), 0, g_iniPath.c_str());
}

static void IniBump(const wchar_t* section, const std::wstring& key)
{
    if (!IniSafeKey(key)) return;
    EnsureUnicodeIni();
    WritePrivateProfileStringW(section, key.c_str(),
                               std::to_wstring(IniCount(section, key) + 1).c_str(),
                               g_iniPath.c_str());
}

static std::wstring RepairStats()
{
    std::wstring s;
    for (const auto& kv : ReadIniSection(L"repairs")) {
        if (!s.empty()) s += L", ";
        s += kv.first + L" ×" + kv.second;
    }
    return s;
}

// ---------------------------------------------------------------- probes

const wchar_t* NetToStr(Net n)
{
    switch (n) {
    case Net::Online:   return L"ONLINE";
    case Net::Degraded: return L"DEGRADED (internet reachable by IP, web/DNS failing)";
    case Net::Portal:   return L"CAPTIVE PORTAL / FILTERED";
    default:            return L"OFFLINE";
    }
}

struct ProbeResult {
    bool ok = false;          // endpoint returned the expected content
    bool gotResponse = false; // some HTTP response arrived (portal suspect)
    bool dateKnown = false;   // server sent a usable Date header
    long long skewSec = 0;    // local clock minus server clock
};

// One WinHTTP session for the probes — proxy discovery and session setup are
// not redone every check. Reset after NetVigil changes the proxy settings.
static HINTERNET g_httpSession = nullptr;

static HINTERNET HttpSession()
{
    static bool warned = false;
    if (!g_httpSession) {
        g_httpSession = WinHttpOpen(L"NetVigil/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!g_httpSession)
            g_httpSession = WinHttpOpen(L"NetVigil/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (g_httpSession)
            WinHttpSetTimeouts(g_httpSession, 5000, 5000, 5000, 5000);
        else if (!warned) {
            warned = true;
            Logf(L"WinHttpOpen failed (%u) — HTTP probes unavailable", GetLastError());
        }
    }
    return g_httpSession;
}

static void ResetHttpSession()
{
    if (g_httpSession) WinHttpCloseHandle(g_httpSession);
    g_httpSession = nullptr;
}

// Server time from the Date header (plus Age, for a cached answer).
static void ReadServerClock(HINTERNET req, ProbeResult& r)
{
    SYSTEMTIME st{};
    DWORD len = sizeof st;
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_DATE | WINHTTP_QUERY_FLAG_SYSTEMTIME,
                             WINHTTP_HEADER_NAME_BY_INDEX, &st, &len, WINHTTP_NO_HEADER_INDEX))
        return;
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft)) return;
    ULARGE_INTEGER u{};
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    DWORD age = 0;
    len = sizeof age;
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_AGE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &age, &len, WINHTTP_NO_HEADER_INDEX))
        age = 0;
    long long serverMs = (long long)(u.QuadPart / 10000ull) + (long long)age * 1000;
    r.dateKnown = true;
    r.skewSec = ((long long)WallMs() - serverMs) / 1000;
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
    if (r.ok) ReadServerClock(req.h, r);
    return r;
}

// Does a request that bypasses the configured proxy get an answer?
static bool DirectHttpWorks()
{
    ScopedWinHttp direct(WinHttpOpen(L"NetVigil/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!direct.h) return false;
    WinHttpSetTimeouts(direct.h, 5000, 5000, 5000, 5000);
    ScopedWinHttp con(WinHttpConnect(direct.h, L"www.msftconnecttest.com",
                                     INTERNET_DEFAULT_HTTP_PORT, 0));
    ScopedWinHttp req(con.h ? WinHttpOpenRequest(con.h, L"GET", L"/connecttest.txt",
                                                 nullptr, WINHTTP_NO_REFERER,
                                                 WINHTTP_DEFAULT_ACCEPT_TYPES, 0)
                            : nullptr);
    return req.h &&
           WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
           WinHttpReceiveResponse(req.h, nullptr);
}

static bool PingAddr(IPAddr addr, DWORD timeoutMs = 3000)
{
    ScopedIcmp icmp(IcmpCreateFile());
    if (icmp.h == INVALID_HANDLE_VALUE) return false;
    char payload[32] = "NetVigil-probe";
    BYTE reply[sizeof(ICMP_ECHO_REPLY) + sizeof payload + 8] = {};
    DWORD n = IcmpSendEcho(icmp.h, addr, payload, sizeof payload,
                           nullptr, reply, sizeof reply, timeoutMs);
    if (n == 0) return false;
    return ((PICMP_ECHO_REPLY)reply)->Status == IP_SUCCESS;
}

static uint32_t Ipv4(const char* s)
{
    IN_ADDR addr{};
    return InetPtonA(AF_INET, s, &addr) == 1 ? addr.S_un.S_addr : 0;
}

static bool PingProbe(const char* ipStr)
{
    uint32_t a = Ipv4(ipStr);
    return a && PingAddr(a);
}

// A TCP handshake completed within the timeout?
static bool TcpConnect(const sockaddr* to, int toLen, DWORD timeoutMs)
{
    if (!g_wsaOk) return false;
    ScopedSocket s(socket(to->sa_family, SOCK_STREAM, IPPROTO_TCP));
    if (!s.valid()) return false;
    u_long nonBlocking = 1;
    ioctlsocket(s.s, FIONBIO, &nonBlocking);
    if (connect(s.s, to, toLen) == 0) return true;
    if (WSAGetLastError() != WSAEWOULDBLOCK) return false;
    fd_set wr, ex;
    FD_ZERO(&wr);
    FD_ZERO(&ex);
    FD_SET(s.s, &wr);
    FD_SET(s.s, &ex);
    timeval tv{ (long)(timeoutMs / 1000), (long)((timeoutMs % 1000) * 1000) };
    return select(0, nullptr, &wr, &ex, &tv) > 0 && FD_ISSET(s.s, &wr);
}

// Proves IP connectivity on networks that drop ICMP, without needing DNS.
static bool TcpProbe(uint32_t addr, unsigned short port, DWORD timeoutMs)
{
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.S_un.S_addr = addr;
    return TcpConnect((const sockaddr*)&to, sizeof to, timeoutMs);
}

struct Connectivity {
    Net  verdict = Net::Offline;
    bool httpOk = false;       // expected content from an HTTP probe
    bool httpAnswered = false; // an HTTP answer, but not the expected one
    bool pingOk = false;
    bool tcpOk = false;
    bool clockKnown = false;
    long long clockSkew = 0;
};

static Connectivity Probe()
{
    Connectivity c;
    ProbeResult a = HttpProbe(L"www.msftconnecttest.com", L"/connecttest.txt",
                              false, "Microsoft Connect Test");
    ProbeResult b;
    if (!a.ok) b = HttpProbe(L"www.gstatic.com", L"/generate_204", true, nullptr);
    if (a.ok || b.ok) {
        const ProbeResult& good = a.ok ? a : b;
        c.verdict    = Net::Online;
        c.httpOk     = true;
        c.clockKnown = good.dateKnown;
        c.clockSkew  = good.skewSec;
        return c;
    }
    c.httpAnswered = a.gotResponse || b.gotResponse;
    c.pingOk = PingProbe("1.1.1.1") || PingProbe("8.8.8.8");
    if (!c.pingOk && !c.httpAnswered)   // ICMP may just be filtered
        c.tcpOk = TcpProbe(Ipv4("1.1.1.1"), 443, 3000) || TcpProbe(Ipv4("8.8.8.8"), 443, 3000);
    c.verdict = c.httpAnswered ? Net::Portal
              : (c.pingOk || c.tcpOk) ? Net::Degraded
                                       : Net::Offline;
    return c;
}

static Net CheckInternet() { return Probe().verdict; }

// ---------------------------------------------------------------- IP layer

static DWORD RunProcess(const std::wstring& cmdLine, bool quiet); // fwd

static std::wstring Ipv4ToStr(uint32_t netOrder)
{
    IN_ADDR a{};
    a.S_un.S_addr = netOrder;
    wchar_t buf[32] = {};
    InetNtopW(AF_INET, &a, buf, 32);
    return buf;
}

static bool LooksVirtualAdapter(const std::wstring& lowerText)
{
    static const wchar_t* kVirt[] = { L"virtual", L"vpn", L"tap", L"tun",
                                      L"loopback", L"vethernet", L"hyper-v",
                                      L"wsl", L"bluetooth", L"tunnel",
                                      L"tailscale", L"zerotier", L"wireguard",
                                      L"wintun", L"miniport", L"kernel debug" };
    for (const wchar_t* k : kVirt)
        if (lowerText.find(k) != std::wstring::npos) return true;
    return false;
}

// DNS servers typed in by hand live in NameServer; DHCP-provided ones in
// DhcpNameServer.
static bool HasStaticDns(const std::wstring& guid)
{
    return !RegReadString(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
                              guid, L"NameServer").empty();
}

// Every IP-stack adapter, classified. Device state and device-only (e.g.
// disabled) adapters are merged in later by MergeDevices.
static std::vector<nv::AdapterObs> SnapshotAdapters()
{
    std::vector<nv::AdapterObs> out;
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
        nv::AdapterObs o;
        o.name    = a->FriendlyName ? a->FriendlyName : L"";
        o.id      = Utf8ToWide(a->AdapterName ? a->AdapterName : "");
        o.ifIndex = a->IfIndex;
        o.luid    = a->Luid.Value;
        o.up      = (a->OperStatus == IfOperStatusUp);
        o.dhcp    = (a->Dhcpv4Enabled != 0);
        o.kind    = a->IfType == IF_TYPE_IEEE80211 ? nv::Kind::Wifi
                  : a->IfType == IF_TYPE_ETHERNET_CSMACD ? nv::Kind::Ethernet
                  : a->IfType == IF_TYPE_WWANPP || a->IfType == IF_TYPE_WWANPP2
                        ? nv::Kind::Cellular
                        : nv::Kind::Other;

        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            if (ua->DadState == IpDadStateDuplicate) { // Windows saw an address conflict
                o.duplicate = true;
                continue;
            }
            IN_ADDR ip = ((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr;
            if (o.hasIpv4 && ua->DadState != IpDadStatePreferred) continue;
            o.hasIpv4 = true;
            o.apipa = (ip.S_un.S_un_b.s_b1 == 169 && ip.S_un.S_un_b.s_b2 == 254);
            o.ip = Ipv4ToStr(ip.S_un.S_addr);
            if (ua->DadState == IpDadStatePreferred) break;
        }
        for (auto* ga = a->FirstGatewayAddress; ga; ga = ga->Next) {
            if (ga->Address.lpSockaddr && ga->Address.lpSockaddr->sa_family == AF_INET) {
                o.gatewayIp = ((sockaddr_in*)ga->Address.lpSockaddr)->sin_addr.S_un.S_addr;
                o.hasGateway = true;
                o.gw = Ipv4ToStr(o.gatewayIp);
                break;
            }
        }
        for (auto* da = a->FirstDnsServerAddress; da && o.dnsIps.size() < 3; da = da->Next)
            if (da->Address.lpSockaddr && da->Address.lpSockaddr->sa_family == AF_INET)
                o.dnsIps.push_back(((sockaddr_in*)da->Address.lpSockaddr)->sin_addr.S_un.S_addr);
        o.dnsServers = (int)o.dnsIps.size();
        o.staticDns  = o.dnsServers > 0 && (!o.dhcp || HasStaticDns(o.id));

        // Physical or not: NDIS knows (the same flag Get-NetAdapter -Physical
        // uses); descriptions are only the fallback.
        std::wstring text = Lower(o.name + L" " + (a->Description ? a->Description : L""));
        MIB_IF_ROW2 row{};
        row.InterfaceLuid = a->Luid;
        bool haveRow = GetIfEntry2(&row) == NO_ERROR;
        bool hardware = haveRow ? row.InterfaceAndOperStatusFlags.HardwareInterface != FALSE
                                : !LooksVirtualAdapter(text);
        o.media = haveRow ? row.MediaConnectState == MediaConnectStateConnected : o.up;
        if (text.find(L"hyper-v virtual ethernet") != std::wstring::npos && o.hasGateway) {
            // Host side of an external virtual switch: this IS the uplink
            // (the physical NIC under it has no IP). Never reset it, though.
            o.virt = false;
            o.kind = nv::Kind::Other;
        } else {
            o.virt = !hardware || text.find(L"bluetooth") != std::wstring::npos;
        }
        out.push_back(std::move(o));
    }
    return out;
}

static std::wstring DnsListStr(const std::vector<uint32_t>& ips)
{
    std::wstring s;
    for (uint32_t ip : ips) {
        if (!s.empty()) s += L", ";
        s += Ipv4ToStr(ip);
    }
    return s.empty() ? L"none" : s;
}

// Release + renew the DHCP lease on one adapter — the fix for an APIPA
// address, an address conflict, or a lost gateway after the router restarted.
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
            flush = (PfnFlush)(void*)GetProcAddress(m, "DnsFlushResolverCache");
    }
    if (flush && flush()) {
        Logf(L"  DNS resolver cache flushed");
        return;
    }
    DWORD rc = RunProcess(L"\"" + Sys32(L"ipconfig.exe") + L"\" /flushdns", true);
    Logf(rc == 0 ? L"  DNS resolver cache flushed (ipconfig)"
                 : L"  DNS cache flush failed (rc=%u)", rc);
}

// Stale neighbour entries (a router swapped for one with the same address,
// a MAC that moved) blackhole traffic until they age out.
static bool FlushArpCache(DWORD ifIndex, const std::wstring& name)
{
    DWORD rc = FlushIpNetTable2(AF_INET, ifIndex);
    Logf(rc == NO_ERROR ? L"  [%ls] ARP cache flushed" : L"  [%ls] ARP flush failed (%u)",
         name.c_str(), rc);
    return rc == NO_ERROR;
}

// Does the adapter's router answer? Ping first; many routers also answer a
// fresh ARP request when they ignore ping, which still proves the link.
static int ProbeGateway(const nv::AdapterObs& a)
{
    if (!a.gatewayIp) return -1;
    if (PingAddr(a.gatewayIp, 1500)) return 1;
    MIB_IPNET_ROW2 row{};
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.S_un.S_addr = a.gatewayIp;
    row.InterfaceIndex = a.ifIndex;
    row.InterfaceLuid.Value = a.luid;
    DWORD rc = ResolveIpNetEntry2(&row, nullptr);   // flushes the entry, re-ARPs
    if (rc == NO_ERROR) return row.PhysicalAddressLength > 0 ? 1 : 0;
    if (rc == ERROR_ACCESS_DENIED) {
        // Not elevated, so no fresh ARP: a cached entry may be stale, and
        // only one Windows confirmed recently proves the router is there.
        MIB_IPNET_ROW2 cur{};
        cur.Address = row.Address;
        cur.InterfaceIndex = a.ifIndex;
        cur.InterfaceLuid.Value = a.luid;
        return GetIpNetEntry2(&cur) == NO_ERROR && cur.State == NlnsReachable ? 1 : -1;
    }
    return 0;
}

// One A query to each server at once; alive[i] = server i answered at all
// (any RCODE: a dead server is silent, a picky one still answers).
static std::vector<bool> DnsServersAnswer(const std::vector<uint32_t>& servers, DWORD timeoutMs)
{
    std::vector<bool> alive(servers.size(), false);
    if (!g_wsaOk || servers.empty()) return alive;
    ScopedSocket s(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (!s.valid()) return alive;
    uint16_t base = (uint16_t)(GetTickCount64() ^ ((ULONGLONG)GetCurrentProcessId() << 5));
    for (size_t i = 0; i < servers.size(); ++i) {
        std::vector<uint8_t> q = nv::BuildDnsQuery((uint16_t)(base + i), kDnsProbeHost);
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = htons(53);
        to.sin_addr.S_un.S_addr = servers[i];
        sendto(s.s, (const char*)q.data(), (int)q.size(), 0, (const sockaddr*)&to, sizeof to);
    }
    size_t pending = servers.size();
    ULONGLONG end = GetTickCount64() + timeoutMs;
    while (pending) {
        ULONGLONG now = GetTickCount64();
        if (now >= end) break;
        ULONGLONG left = end - now;
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(s.s, &rd);
        timeval tv{ (long)(left / 1000), (long)((left % 1000) * 1000) };
        if (select(0, &rd, nullptr, nullptr, &tv) <= 0) break;
        uint8_t reply[512];
        sockaddr_in from{};
        int fromLen = sizeof from;
        int n = recvfrom(s.s, (char*)reply, sizeof reply, 0, (sockaddr*)&from, &fromLen);
        if (n <= 0) continue; // e.g. WSAECONNRESET from an ICMP port-unreachable
        for (size_t i = 0; i < servers.size(); ++i) {
            if (!alive[i] && from.sin_addr.S_un.S_addr == servers[i] &&
                nv::ParseDnsReply(reply, (size_t)n, (uint16_t)(base + i), nullptr) >= 0) {
                alive[i] = true;
                --pending;
            }
        }
    }
    return alive;
}

// The system resolver, bypassing its cache — what every application uses.
// Bounded: with dead servers the resolver retries for ~10 s.
static bool SystemDnsWorks(DWORD timeoutMs)
{
    auto result = std::make_shared<std::atomic<int>>(0);
    bool finished = RunBounded(timeoutMs, [result] {
        PDNS_RECORD rec = nullptr;
        DNS_STATUS st = DnsQuery_W(L"www.msftconnecttest.com", DNS_TYPE_A,
                                   DNS_QUERY_BYPASS_CACHE, nullptr, &rec, nullptr);
        if (rec) DnsRecordListFree(rec, DnsFreeRecordList);
        *result = st == 0 ? 1 : -1;
    });
    return finished && *result == 1;
}

static bool TcpLoopbackAlive(const std::wstring& host, unsigned port)
{
    std::wstring h = Lower(host);
    if (h.size() > 2 && h.front() == L'[' && h.back() == L']') h = h.substr(1, h.size() - 2);
    sockaddr_in6 v6{};
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons((unsigned short)port);
    v6.sin6_addr.s6_addr[15] = 1;                    // ::1
    if (h.find(L':') != std::wstring::npos)
        return TcpConnect((const sockaddr*)&v6, sizeof v6, 1500);
    if (h == L"localhost" || h == L"localhost.")
        return TcpProbe(htonl(INADDR_LOOPBACK), (unsigned short)port, 1500) ||
               TcpConnect((const sockaddr*)&v6, sizeof v6, 1500);
    IN_ADDR a{};
    if (InetPtonW(AF_INET, h.c_str(), &a) != 1) return true; // can't tell: assume alive
    return TcpProbe(a.S_un.S_addr, (unsigned short)port, 1500);
}

static void ObserveProxy(nv::ProbeObs& p)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg{};
    if (!WinHttpGetIEProxyConfigForCurrentUser(&cfg)) return;
    std::wstring spec = cfg.lpszProxy ? cfg.lpszProxy : L"";
    if (cfg.lpszProxy) GlobalFree(cfg.lpszProxy);
    if (cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);
    if (cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);
    nv::ProxyEndpoint ep;
    if (spec.empty() || !nv::PickHttpProxy(spec, ep)) return;
    p.proxyOn = true;
    p.proxy = (ep.host.find(L':') != std::wstring::npos ? L"[" + ep.host + L"]" : ep.host) +
              L":" + std::to_wstring(ep.port);
    if (nv::IsLoopbackHost(ep.host))
        p.proxyDead = !TcpLoopbackAlive(ep.host, ep.port);
    if (!p.proxyDead) p.directOk = DirectHttpWorks();
}

// Hand-set proxy nothing listens on: switch it off, and say what it was.
static bool DisableDeadProxy(const nv::ProbeObs& p)
{
    // A proxy tool restarting (they often do on a network change) is not a
    // dead one: it must still be silent half a minute later.
    nv::ProxyEndpoint ep;
    if (!nv::PickHttpProxy(p.proxy, ep)) return false;
    Logf(L"  making sure nothing is listening on %ls (30 s)", p.proxy.c_str());
    if (WaitStop(30000)) return false;
    if (TcpLoopbackAlive(ep.host, ep.port)) {
        Logf(L"  the proxy at %ls answers again — leaving it on", p.proxy.c_str());
        return false;
    }
    std::wstring was;
    if (!DisableManualProxy(&was)) return false;
    Logf(L"  manual proxy '%ls' switched off — turn it back on under Settings > Network > "
         L"Proxy if the tool that used it returns", was.c_str());
    SaveSetting(L"disabledProxy", was);
    ResetHttpSession(); // drop the probe session's cached proxy configuration
    return true;
}

// Mark the adapter holding the best route to the internet.
static void MarkRouteAdapter(std::vector<nv::AdapterObs>& ads)
{
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.S_un.S_addr = Ipv4("1.1.1.1");
    DWORD idx = 0;
    if (GetBestInterfaceEx((sockaddr*)&dst, &idx) != NO_ERROR) return;
    for (auto& a : ads) {
        if (a.hasIf && a.ifIndex == idx) {
            a.routesInternet = true;
            break;
        }
    }
}

// Windows airplane mode (the radio-management system state).
static bool AirplaneModeOn()
{
    DWORD v = 0;
    return RegReadDword(HKEY_LOCAL_MACHINE,
                        L"SYSTEM\\CurrentControlSet\\Control\\RadioManagement\\SystemRadioState",
                        nullptr, v) && v == 1;
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

static HANDLE OpenWlan(bool quiet = false)
{
    DWORD ver = 0;
    HANDLE h = nullptr;
    DWORD rc = WlanOpenHandle(2, nullptr, &ver, &h);
    if (rc != ERROR_SUCCESS) {
        if (!quiet) Logf(L"WlanOpenHandle failed (%u)", rc);
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

// SSID + profile of the network an interface is currently connected to.
static bool GetConnection(HANDLE h, const GUID& g, std::wstring& ssid, std::wstring& profile)
{
    ScopedWlanMem mem;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_current_connection, nullptr,
                           &sz, &mem.p, &t) != ERROR_SUCCESS ||
        !mem.p || sz < sizeof(WLAN_CONNECTION_ATTRIBUTES))
        return false;
    const WLAN_CONNECTION_ATTRIBUTES* attr = mem.as<WLAN_CONNECTION_ATTRIBUTES>();
    if (attr->isState != wlan_interface_state_connected) return false;
    const DOT11_SSID& s = attr->wlanAssociationAttributes.dot11Ssid;
    std::string raw((const char*)s.ucSSID,
                    s.uSSIDLength <= DOT11_SSID_MAX_LENGTH ? s.uSSIDLength : 0);
    ssid    = Utf8ToWide(raw);
    profile = attr->strProfileName;
    return true;
}

static std::wstring GetConnectedSsid(HANDLE h, const GUID& g)
{
    std::wstring ssid, profile;
    GetConnection(h, g, ssid, profile);
    return ssid;
}

// First connected WLAN interface: what the machine is on right now.
static bool CurrentConnection(std::wstring& ssid, std::wstring& iface, std::wstring& profile)
{
    ScopedWlan wl(OpenWlan(true));
    if (!wl.h) return false;
    for (const auto& i : EnumWlanIfaces(wl.h)) {
        if (GetConnection(wl.h, i.guid, ssid, profile)) {
            iface = i.desc;
            return true;
        }
    }
    return false;
}

// Radio switches of one interface: any PHY off in software / in hardware.
static void RadioState(HANDLE h, const GUID& g, bool& softOff, bool& hardOff)
{
    ScopedWlanMem mem;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE t;
    if (WlanQueryInterface(h, &g, wlan_intf_opcode_radio_state, nullptr,
                           &sz, &mem.p, &t) != ERROR_SUCCESS ||
        !mem.p || sz < sizeof(WLAN_RADIO_STATE))
        return;
    const WLAN_RADIO_STATE* rs = mem.as<WLAN_RADIO_STATE>();
    for (DWORD i = 0; i < rs->dwNumberOfPhys && i < WLAN_MAX_PHY_INDEX; ++i) {
        if (rs->PhyRadioState[i].dot11SoftwareRadioState == dot11_radio_state_off) softOff = true;
        if (rs->PhyRadioState[i].dot11HardwareRadioState == dot11_radio_state_off) hardOff = true;
    }
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

// Connection failures reported by WlanSvc, per profile. A profile whose
// security negotiation keeps failing has a stale saved password: retrying it
// (or resetting hardware over it) cannot help — the user must re-enter it.
struct WlanFailure {
    int securityFails = 0;       // consecutive credential/handshake failures
    DWORD reason = 0;            // last reason code
    ULONGLONG tick = 0;          // when it was recorded
};
static std::map<std::wstring, WlanFailure> g_wlanFails;   // guarded by g_wlanCs

static VOID WINAPI OnWlanNotify(PWLAN_NOTIFICATION_DATA data, PVOID)
{
    if (!data || data->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM) return;
    if (data->NotificationCode != (DWORD)wlan_notification_acm_connection_complete &&
        data->NotificationCode != (DWORD)wlan_notification_acm_connection_attempt_fail)
        return;
    if (!data->pData ||
        data->dwDataSize < offsetof(WLAN_CONNECTION_NOTIFICATION_DATA, strProfileXml))
        return;
    const auto* c = (const WLAN_CONNECTION_NOTIFICATION_DATA*)data->pData;
    std::wstring profile(c->strProfileName, wcsnlen(c->strProfileName, WLAN_MAX_NAME_LENGTH));
    if (profile.empty()) return;
    EnterCriticalSection(&g_wlanCs);
    if (c->wlanReasonCode == 0) {
        g_wlanFails.erase(profile);
    } else {
        WlanFailure& f = g_wlanFails[profile];
        if (nv::ClassifyWlanReason(c->wlanReasonCode) == nv::WlanFail::Security)
            ++f.securityFails;
        f.reason = c->wlanReasonCode;
        f.tick = GetTickCount64();
    }
    LeaveCriticalSection(&g_wlanCs);
}

// Registers for WlanSvc connection notifications on a handle while in scope.
struct WlanFailureWatch {
    HANDLE h = nullptr;
    explicit WlanFailureWatch(HANDLE wl)
    {
        if (WlanRegisterNotification(wl, WLAN_NOTIFICATION_SOURCE_ACM, TRUE, OnWlanNotify,
                                     nullptr, nullptr, nullptr) == ERROR_SUCCESS)
            h = wl;
    }
    ~WlanFailureWatch()
    {
        if (h) WlanRegisterNotification(h, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, nullptr,
                                        nullptr, nullptr, nullptr);
    }
    WlanFailureWatch(const WlanFailureWatch&) = delete;
    WlanFailureWatch& operator=(const WlanFailureWatch&) = delete;
};

static bool AuthFailedRecently(const std::wstring& profile)
{
    EnterCriticalSection(&g_wlanCs);
    auto it = g_wlanFails.find(profile);
    bool failed = it != g_wlanFails.end() && it->second.securityFails >= 2 &&
                  GetTickCount64() - it->second.tick < kAuthFailWindowMs;
    LeaveCriticalSection(&g_wlanCs);
    return failed;
}

// Reason code of the latest failure for a profile at or after `since`.
static DWORD WlanFailureSince(const std::wstring& profile, ULONGLONG since)
{
    EnterCriticalSection(&g_wlanCs);
    auto it = g_wlanFails.find(profile);
    DWORD r = it != g_wlanFails.end() && it->second.tick >= since ? it->second.reason : 0;
    LeaveCriticalSection(&g_wlanCs);
    return r;
}

static std::wstring WlanReasonText(DWORD reason)
{
    wchar_t buf[256] = {};
    if (WlanReasonCodeToString(reason, 256, buf, nullptr) != ERROR_SUCCESS || !buf[0])
        return L"reason unknown";
    std::wstring s = buf;
    while (!s.empty() && (s.back() == L'.' || iswspace(s.back()))) s.pop_back();
    return s;
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

// Apply the user's per-network policy: drop "never" networks and profiles
// whose saved password keeps being rejected, put the preferred one first (it
// still has to be in the list, i.e. in range).
static void ApplyNetworkPreferences(std::vector<Candidate>& cands, const std::wstring& desc)
{
    std::vector<Candidate> kept, failing;
    for (auto& c : cands) {
        if (ModeOf(c.profile) == NetMode::Never)
            Logf(L"  [%ls] skipping '%ls' (marked never connect)", desc.c_str(), c.profile.c_str());
        else if (AuthFailedRecently(c.profile))
            failing.push_back(std::move(c));
        else
            kept.push_back(std::move(c));
    }
    // A network whose security handshake keeps failing is skipped while
    // anything else is in range — and still tried when nothing is (the
    // failure may be a wedged driver's, not a changed password).
    for (auto& c : failing) {
        Logf(kept.empty() ? L"  [%ls] '%ls' keeps failing its security handshake — trying it "
                            L"anyway (nothing else in range)"
                          : L"  [%ls] skipping '%ls' for now (its security handshake keeps failing)",
             desc.c_str(), c.profile.c_str());
    }
    if (kept.empty()) kept.swap(failing);
    std::stable_partition(kept.begin(), kept.end(), [](const Candidate& c) {
        return ModeOf(c.profile) == NetMode::Preferred;
    });
    cands.swap(kept);
    if (!cands.empty() && ModeOf(cands[0].profile) == NetMode::Preferred)
        Logf(L"  [%ls] preferred network '%ls' goes first", desc.c_str(),
             cands[0].profile.c_str());
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

// Associate one interface to one profile; on failure log WlanSvc's reason
// and whether the saved password is the likely culprit.
static bool ConnectProfile(HANDLE h, const WlanIfaceInfo& inf, const Candidate& c)
{
    WLAN_CONNECTION_PARAMETERS p{};
    p.wlanConnectionMode = wlan_connection_mode_profile;
    p.strProfile   = c.profile.c_str();
    p.dot11BssType = c.bss;
    ULONGLONG started = GetTickCount64();
    DWORD rc = WlanConnect(h, &inf.guid, &p, nullptr);
    if (rc == ERROR_SUCCESS && WaitConnected(h, inf.guid, 20000)) return true;
    DWORD reason = WlanFailureSince(c.profile, started);
    if (reason)
        Logf(L"  [%ls] connect to '%ls' failed: %ls (0x%X)", inf.desc.c_str(),
             c.profile.c_str(), WlanReasonText(reason).c_str(), reason);
    else
        Logf(L"  [%ls] connect to '%ls' failed (rc=%u)", inf.desc.c_str(), c.profile.c_str(), rc);
    if (AuthFailedRecently(c.profile))
        Logf(L"  [%ls] '%ls' keeps failing its security handshake (changed password?) — other "
             L"networks go first for %llu min", inf.desc.c_str(), c.profile.c_str(),
             kAuthFailWindowMs / 60000ull);
    return false;
}

// Try to get one interface associated to a remembered network.
static bool ReconnectIface(HANDLE h, const WlanIfaceInfo& inf, bool bounceIfConnected)
{
    EnsureAutoConfig(h, inf.guid, inf.desc);
    if (AirplaneModeOn()) {
        bool soft = false, hard = false;
        RadioState(h, inf.guid, soft, hard);
        if (soft) {
            Logf(L"  [%ls] airplane mode is on — not overriding it", inf.desc.c_str());
            return false;
        }
    } else if (EnsureRadioOn(h, inf.guid)) {
        Sleep(3000);
    }

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
    ApplyNetworkPreferences(cands, inf.desc);
    if (cands.empty()) {
        Logf(L"  [%ls] no usable remembered network in range", inf.desc.c_str());
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
        if (!ConnectProfile(h, inf, c)) continue;
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
    WlanFailureWatch watch(wl.h);
    std::vector<WlanIfaceInfo> ifs = EnumWlanIfaces(wl.h);
    if (ifs.empty())
        Logf(L"no WLAN interfaces present (adapter unplugged, disabled, or driver wedged)");
    bool any = false;
    for (const auto& i : ifs)
        any = ReconnectIface(wl.h, i, bounceIfConnected) || any;
    return any;
}

static bool RadioOnAll()
{
    if (AirplaneModeOn()) {
        Logf(L"  airplane mode is on — leaving the radio alone");
        return false;
    }
    ScopedWlan wl(OpenWlan());
    if (!wl.h) return false;
    bool any = false;
    for (const auto& i : EnumWlanIfaces(wl.h))
        any = EnsureRadioOn(wl.h, i.guid) || any;
    return any;
}

// ISP outage on the current Wi-Fi network: try other in-range saved networks
// (policy order), keep the first that really has internet, otherwise go back
// to the original one.
static bool SwitchWifiNetwork()
{
    ScopedWlan wl(OpenWlan());
    if (!wl.h) return false;
    WlanFailureWatch watch(wl.h);
    for (const auto& inf : EnumWlanIfaces(wl.h)) {
        std::wstring ssid, current;
        if (!GetConnection(wl.h, inf.guid, ssid, current)) continue;
        std::vector<Candidate> cands = GetCandidates(wl.h, inf.guid);
        ApplyNetworkPreferences(cands, inf.desc);
        cands.erase(std::remove_if(cands.begin(), cands.end(),
                                   [&](const Candidate& c) { return c.profile == current; }),
                    cands.end());
        if (cands.empty()) {
            Logf(L"  [%ls] no other saved network in range", inf.desc.c_str());
            continue;
        }
        size_t tries = cands.size() < 2 ? cands.size() : 2;
        for (size_t i = 0; i < tries; ++i) {
            if (StopRequested()) return false;
            Logf(L"  [%ls] '%ls' has no internet upstream — trying '%ls' (signal %u%%)",
                 inf.desc.c_str(), current.c_str(), cands[i].profile.c_str(), cands[i].quality);
            if (!ConnectProfile(wl.h, inf, cands[i])) continue;
            if (WaitStop(3000)) return false;
            Net n = CheckInternet();
            if (n == Net::Online || n == Net::Degraded) {
                Logf(L"  [%ls] switched to '%ls' — it has working internet",
                     inf.desc.c_str(), cands[i].profile.c_str());
                return true;
            }
            Logf(L"  [%ls] '%ls' has no working internet either", inf.desc.c_str(),
                 cands[i].profile.c_str());
        }
        Logf(L"  [%ls] no alternative worked — returning to '%ls'", inf.desc.c_str(),
             current.c_str());
        Candidate back;
        back.profile = current;
        ConnectProfile(wl.h, inf, back);
    }
    return false;
}

// What the diagnosis needs to know about Wi-Fi. Scans first when nothing is
// associated, so "no networks visible" is fresh, not a stale cache.
static void ObserveWlan(nv::WifiObs& w, std::vector<std::wstring>& guids, bool scanIfIdle)
{
    ScopedWlan wl(OpenWlan(true));
    if (!wl.h) return;
    std::vector<WlanIfaceInfo> ifs = EnumWlanIfaces(wl.h);
    w.interfaces = (int)ifs.size();
    for (const auto& i : ifs) {
        wchar_t g[64] = {};
        if (StringFromGUID2(i.guid, g, 64) > 0) guids.push_back(g);
        if (GetIfaceState(wl.h, i.guid) == wlan_interface_state_connected) w.associated = true;
        RadioState(wl.h, i.guid, w.radioSoftOff, w.radioHardOff);
    }
    if (ifs.empty()) return;
    if (!w.associated && scanIfIdle && !w.radioSoftOff && !w.radioHardOff) {
        for (const auto& i : ifs) WlanScan(wl.h, &i.guid, nullptr, nullptr, nullptr);
        WaitStop(4000);
    }
    std::set<std::string> ssids;
    std::set<std::wstring> known;
    for (const auto& i : ifs) {
        PWLAN_AVAILABLE_NETWORK_LIST list = nullptr;
        if (WlanGetAvailableNetworkList(wl.h, &i.guid,
                WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
                nullptr, &list) != ERROR_SUCCESS || !list)
            continue;
        ScopedWlanMem mem;
        mem.p = list;
        for (DWORD n = 0; n < list->dwNumberOfItems; ++n) {
            const WLAN_AVAILABLE_NETWORK& a = list->Network[n];
            ssids.insert(std::string((const char*)a.dot11Ssid.ucSSID,
                                     a.dot11Ssid.uSSIDLength <= DOT11_SSID_MAX_LENGTH
                                         ? a.dot11Ssid.uSSIDLength : 0));
            if (!(a.dwFlags & WLAN_AVAILABLE_NETWORK_HAS_PROFILE) || !a.strProfileName[0] ||
                !a.bNetworkConnectable)
                continue;
            std::wstring profile = a.strProfileName;
            if (AuthFailedRecently(profile)) {
                if (w.authFailed.empty()) w.authFailed = profile;
            } else if (ModeOf(profile) != NetMode::Never) {
                known.insert(profile);
            }
        }
    }
    w.visible = (int)ssids.size();
    w.knownInRange = (int)known.size();
}

// Everything the GUI lists: saved profiles + remembered networks, annotated
// with live availability (no scan is triggered — cached results only).
std::vector<KnownNetwork> GetKnownNetworks()
{
    std::map<std::wstring, KnownNetwork> m;
    EnterCriticalSection(&g_cfgCs);
    for (const auto& kv : g_seen) {
        KnownNetwork& k = m[kv.first];
        k.profile  = kv.first;
        k.ssid     = kv.second.ssid;
        k.lastSeen = kv.second.lastSeen;
        k.connects = kv.second.connects;
    }
    for (const auto& kv : g_modes) {
        KnownNetwork& k = m[kv.first];
        k.profile = kv.first;
        k.mode    = kv.second;
    }
    LeaveCriticalSection(&g_cfgCs);

    ScopedWlan wl(OpenWlan(true));
    if (wl.h) {
        for (const auto& i : EnumWlanIfaces(wl.h)) {
            PWLAN_PROFILE_INFO_LIST pl = nullptr;
            if (WlanGetProfileList(wl.h, &i.guid, nullptr, &pl) == ERROR_SUCCESS && pl) {
                ScopedWlanMem mem;
                mem.p = pl;
                for (DWORD n = 0; n < pl->dwNumberOfItems; ++n) {
                    KnownNetwork& k = m[pl->ProfileInfo[n].strProfileName];
                    k.profile = pl->ProfileInfo[n].strProfileName;
                }
            }
            PWLAN_AVAILABLE_NETWORK_LIST list = nullptr;
            if (WlanGetAvailableNetworkList(wl.h, &i.guid,
                    WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
                    nullptr, &list) == ERROR_SUCCESS && list) {
                ScopedWlanMem mem;
                mem.p = list;
                for (DWORD n = 0; n < list->dwNumberOfItems; ++n) {
                    const WLAN_AVAILABLE_NETWORK& a = list->Network[n];
                    if (!(a.dwFlags & WLAN_AVAILABLE_NETWORK_HAS_PROFILE) ||
                        !a.strProfileName[0])
                        continue;
                    KnownNetwork& k = m[a.strProfileName];
                    k.profile = a.strProfileName;
                    k.inRange = true;
                    if (a.wlanSignalQuality > k.signal) k.signal = a.wlanSignalQuality;
                    if (a.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) k.connected = true;
                    if (k.ssid.empty()) {
                        std::string raw((const char*)a.dot11Ssid.ucSSID,
                                        a.dot11Ssid.uSSIDLength <= DOT11_SSID_MAX_LENGTH
                                            ? a.dot11Ssid.uSSIDLength : 0);
                        k.ssid = Utf8ToWide(raw);
                    }
                }
            }
        }
    }

    std::vector<KnownNetwork> out;
    out.reserve(m.size());
    for (auto& kv : m) {
        kv.second.mode = ModeOf(kv.first);
        out.push_back(std::move(kv.second));
    }
    std::sort(out.begin(), out.end(), [](const KnownNetwork& a, const KnownNetwork& b) {
        if (a.connected != b.connected) return a.connected;
        bool ap = a.mode == NetMode::Preferred, bp = b.mode == NetMode::Preferred;
        if (ap != bp) return ap;
        if (a.inRange != b.inRange) return a.inRange;
        if (a.inRange && a.signal != b.signal) return a.signal > b.signal;
        return a.lastSeen > b.lastSeen;
    });
    return out;
}

// User-initiated connect from the GUI; asynchronous (WlanConnect returns as
// soon as the request is accepted).
bool ConnectToNetwork(const std::wstring& profile)
{
    ScopedWlan wl(OpenWlan());
    if (!wl.h) return false;
    for (const auto& i : EnumWlanIfaces(wl.h)) {
        WLAN_CONNECTION_PARAMETERS p{};
        p.wlanConnectionMode = wlan_connection_mode_profile;
        p.strProfile   = profile.c_str();
        p.dot11BssType = dot11_BSS_type_infrastructure;
        DWORD rc = WlanConnect(wl.h, &i.guid, &p, nullptr);
        if (rc == ERROR_SUCCESS) {
            Logf(L"connect to '%ls' requested on %ls", profile.c_str(), i.desc.c_str());
            return true;
        }
        Logf(L"connect to '%ls' on %ls failed (rc=%u)", profile.c_str(), i.desc.c_str(), rc);
    }
    return false;
}

// ---------------------------------------------------------------- devices

static std::wstring DevRegString(HDEVINFO devs, SP_DEVINFO_DATA* did, DWORD prop)
{
    wchar_t buf[512] = {};
    DWORD type = 0, need = 0;
    if (SetupDiGetDeviceRegistryPropertyW(devs, did, prop, &type,
                                          (PBYTE)buf, sizeof buf - sizeof(wchar_t), &need))
        return buf;
    return L"";
}

static std::wstring DevDriverString(HDEVINFO devs, SP_DEVINFO_DATA* did, const wchar_t* value,
                                    DWORD* dword = nullptr)
{
    std::wstring s;
    ScopedRegKey key(SetupDiOpenDevRegKey(devs, did, DICS_FLAG_GLOBAL, 0,
                                          DIREG_DRV, KEY_READ));
    if (key.k == (HKEY)INVALID_HANDLE_VALUE) return s;
    BYTE buf[256] = {};
    DWORD sz = sizeof buf - sizeof(wchar_t), type = 0;
    if (RegQueryValueExW(key.k, value, nullptr, &type, buf, &sz) != ERROR_SUCCESS) return s;
    if (type == REG_SZ) s = (const wchar_t*)buf;
    else if (type == REG_DWORD && dword && sz >= sizeof(DWORD)) *dword = *(const DWORD*)buf;
    return s;
}

static std::wstring DevNetCfgInstanceId(HDEVINFO devs, SP_DEVINFO_DATA* did)
{
    return DevDriverString(devs, did, L"NetCfgInstanceId");
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

// Real hardware sits on a bus; software adapters (VPN, virtual switches, WAN
// miniports, Wi-Fi Direct, Bluetooth PAN) are enumerated by software.
static bool IsPhysicalInstance(const std::wstring& instanceId)
{
    std::wstring u = Lower(instanceId);
    static const wchar_t* kSoft[] = { L"root\\", L"swd\\", L"bth", L"{", L"umb\\",
                                      L"compositebus\\" };
    for (const wchar_t* p : kSoft)
        if (u.rfind(p, 0) == 0) return false;
    return !u.empty();
}

struct NetDevice {
    std::wstring id;          // NetCfgInstanceId
    std::wstring name;        // connection name ("Wi-Fi"), else the device description
    nv::Dev state = nv::Dev::Unknown;
    unsigned problem = 0;
    bool physical = false;
    bool wireless = false;
    bool cellular = false;
};

static std::vector<NetDevice> EnumNetDevices()
{
    std::vector<NetDevice> out;
    ScopedDevInfo devInfo(SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr,
                                               DIGCF_PRESENT));
    if (devInfo.h == INVALID_HANDLE_VALUE) return out;
    SP_DEVINFO_DATA did{};
    did.cbSize = sizeof did;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo.h, i, &did); ++i) {
        NetDevice d;
        d.id = DevNetCfgInstanceId(devInfo.h, &did);
        if (d.id.empty()) continue;
        std::wstring desc = DevRegString(devInfo.h, &did, SPDRP_FRIENDLYNAME);
        if (desc.empty()) desc = DevRegString(devInfo.h, &did, SPDRP_DEVICEDESC);
        wchar_t inst[512] = {};
        SetupDiGetDeviceInstanceIdW(devInfo.h, &did, inst, 512, nullptr);
        d.physical = IsPhysicalInstance(inst) && !LooksVirtualAdapter(Lower(desc));
        ULONG status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, did.DevInst, 0) == CR_SUCCESS) {
            if (status & DN_HAS_PROBLEM) {
                d.state = problem == CM_PROB_DISABLED ? nv::Dev::Disabled : nv::Dev::Failed;
                d.problem = (unsigned)problem;
            } else {
                d.state = nv::Dev::Ok;
            }
        }
        DWORD media = 0;
        DevDriverString(devInfo.h, &did, L"*PhysicalMediaType", &media);
        d.wireless = media == 9 || media == 1 || LooksWireless(Lower(desc)); // native 802.11 / WLAN
        d.cellular = media == 8;                                           // wireless WAN
        std::wstring conn = RegReadString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Network\\"
            L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + d.id + L"\\Connection", L"Name");
        d.name = conn.empty() ? desc : conn;
        out.push_back(std::move(d));
    }
    return out;
}

static bool DeviceOpHung(); // fwd

// Device enumeration can stall while a wedged driver holds the PnP lock —
// and then every further attempt would strand one more thread behind it.
static std::vector<NetDevice> EnumNetDevicesBounded(DWORD ms)
{
    static std::shared_ptr<std::atomic<bool>> lastFinished;
    if (DeviceOpHung() || (lastFinished && !*lastFinished)) return {};
    auto finished = std::make_shared<std::atomic<bool>>(false);
    auto out = std::make_shared<std::vector<NetDevice>>();
    lastFinished = finished;
    if (!RunBounded(ms, [out, finished] {
            *out = EnumNetDevices();
            *finished = true;
        })) {
        Logf(L"device enumeration did not finish in %u s — device manager busy?", ms / 1000);
        return {};
    }
    return *out;
}

// Attach device state to IP adapters, and add adapters the IP stack cannot
// see because they are disabled or their driver failed.
static void MergeDevices(std::vector<nv::AdapterObs>& ads, const std::vector<NetDevice>& devs,
                         const std::vector<std::wstring>& wlanGuids)
{
    for (const auto& d : devs) {
        bool wlan = false;
        for (const auto& g : wlanGuids)
            if (_wcsicmp(g.c_str(), d.id.c_str()) == 0) wlan = true;
        nv::AdapterObs* match = nullptr;
        for (auto& a : ads)
            if (_wcsicmp(a.id.c_str(), d.id.c_str()) == 0) match = &a;
        if (match) {
            match->dev = d.state;
            match->problem = d.problem;
            if (wlan && !match->virt) match->kind = nv::Kind::Wifi;
            continue;
        }
        // A physical adapter the IP stack cannot see is a symptom when it is
        // disabled or failed — or when it is Wi-Fi (a half-loaded driver
        // WLAN AutoConfig no longer lists).
        bool wifi = wlan || d.wireless;
        if (!d.physical || d.state == nv::Dev::Unknown) continue;
        if (d.state == nv::Dev::Ok && !wifi) continue;
        nv::AdapterObs a;
        a.name    = d.name;
        a.id      = d.id;
        a.hasIf   = false;
        a.dev     = d.state;
        a.problem = d.problem;
        a.kind    = wifi ? nv::Kind::Wifi : d.cellular ? nv::Kind::Cellular : nv::Kind::Ethernet;
        ads.push_back(std::move(a));
    }
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

struct DevOpResult {
    bool found = false;
    bool ok = false;
    bool needReboot = false;
    DWORD error = 0;
};

// Disable+enable (a driver-level reset) or just enable one net device.
// Runs on a RunBounded helper, so it opens its own device list.
static DevOpResult DeviceOp(const std::wstring& id, bool cycle, bool fixPower,
                            const std::wstring& name)
{
    DevOpResult r;
    ScopedDevInfo devInfo(SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr,
                                               DIGCF_PRESENT));
    if (devInfo.h == INVALID_HANDLE_VALUE) {
        r.error = GetLastError();
        return r;
    }
    SP_DEVINFO_DATA did{};
    did.cbSize = sizeof did;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo.h, i, &did); ++i) {
        if (_wcsicmp(DevNetCfgInstanceId(devInfo.h, &did).c_str(), id.c_str()) != 0) continue;
        r.found = true;
        if (cycle) {
            if (!ChangeDevState(devInfo.h, &did, DICS_DISABLE)) {
                r.error = GetLastError();
                break;
            }
            if (fixPower) DisableAdapterPowerSaving(devInfo.h, &did, name);
            Sleep(3000);
        }
        r.ok = ChangeDevState(devInfo.h, &did, DICS_ENABLE);
        if (!r.ok) {
            Sleep(2000);
            r.ok = ChangeDevState(devInfo.h, &did, DICS_ENABLE);
        }
        if (!r.ok) r.error = GetLastError();
        SP_DEVINSTALL_PARAMS_W ip{};
        ip.cbSize = sizeof ip;
        if (SetupDiGetDeviceInstallParamsW(devInfo.h, &did, &ip))
            r.needReboot = (ip.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
        break;
    }
    return r;
}

// A device operation that never returned: the driver is hung inside the PnP
// manager, and further device operations would just pile up behind it.
static std::shared_ptr<std::atomic<bool>> g_hungDevOp;

static bool DeviceOpHung() { return g_hungDevOp && !*g_hungDevOp; }

static void AdviseRestart(const std::wstring& detail); // fwd

static bool RunDeviceOp(const nv::AdapterObs& a, bool cycle, bool fixPower)
{
    auto finished = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<DevOpResult>();
    std::wstring id = a.id, name = a.name;
    bool done = RunBounded(90000, [=] {
        *result = DeviceOp(id, cycle, fixPower, name);
        *finished = true;
    });
    if (!done) {
        g_hungDevOp = finished;
        Logf(L"  [%ls] the driver did not respond within 90 s — it is hung; only a Windows "
             L"restart can recover it", a.name.c_str());
        AdviseRestart(L"the driver for '" + a.name + L"' is hung — restart Windows to recover "
                      L"the network adapter");
        return false;
    }
    if (!result->found) {
        Logf(L"  [%ls] device not found (unplugged?)", a.name.c_str());
        return false;
    }
    if (!result->ok) {
        Logf(L"  [%ls] %ls failed (%u) — the adapter may need a re-plug", a.name.c_str(),
             cycle ? L"driver reset" : L"enable", result->error);
        return false;
    }
    if (result->needReboot) {
        Logf(L"  [%ls] Windows reports a restart is needed to finish this", a.name.c_str());
        AdviseRestart(L"'" + a.name + L"' needs Windows to restart before it works again");
    }
    return true;
}

static int EffectiveResets(const std::wstring& id) { return IniCount(L"resets", id); }

static bool ResetAdapterDevice(const nv::AdapterObs& a)
{
    // Evidence-based power fix: resets that actually revived this adapter
    // twice mean Windows keeps powering it down (USB selective suspend).
    bool fixPower = EffectiveResets(a.id) >= 2;
    Logf(L"  [%ls] resetting the adapter driver (disable + enable)", a.name.c_str());
    if (!RunDeviceOp(a, /*cycle=*/true, fixPower)) return false;
    Logf(L"  [%ls] adapter reset — waiting for the driver to re-initialise", a.name.c_str());
    WaitStop(8000);
    return true;
}

static bool EnableAdapterDevice(const nv::AdapterObs& a)
{
    if (!RunDeviceOp(a, /*cycle=*/false, false)) return false;
    Logf(L"  [%ls] adapter enabled", a.name.c_str());
    return true;
}

// "Scan for hardware changes": brings back devices that dropped off the bus
// (a USB Wi-Fi dongle after a power glitch) without a re-plug.
static bool RescanHardware()
{
    auto rc = std::make_shared<std::atomic<int>>((int)CR_FAILURE);
    bool done = RunBounded(30000, [rc] {
        DEVINST root = 0;
        CONFIGRET cr = CM_Locate_DevNodeW(&root, nullptr, CM_LOCATE_DEVNODE_NORMAL);
        if (cr == CR_SUCCESS) cr = CM_Reenumerate_DevNode(root, CM_REENUMERATE_SYNCHRONOUS);
        *rc = (int)cr;
    });
    if (!done) {
        Logf(L"  hardware rescan still running after 30 s — continuing");
        return true;
    }
    Logf(*rc == (int)CR_SUCCESS ? L"  rescanned for hardware changes"
                                : L"  hardware rescan failed (CONFIGRET %d)", (int)*rc);
    return *rc == (int)CR_SUCCESS;
}

// ---------------------------------------------------------------- services

static bool StartServiceAndWait(SC_HANDLE scm, const wchar_t* name, DWORD ms)
{
    ScopedSvc svc(OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc.h) {
        Logf(L"  OpenService(%ls) failed (%u)", name, GetLastError());
        return false;
    }
    if (!StartServiceW(svc.h, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        Logf(L"  StartService(%ls) failed (%u)", name, GetLastError());
        return false;
    }
    SERVICE_STATUS ss{};
    ULONGLONG end = GetTickCount64() + ms;
    while (QueryServiceStatus(svc.h, &ss) && ss.dwCurrentState != SERVICE_RUNNING &&
           GetTickCount64() < end)
        Sleep(500);
    return ss.dwCurrentState == SERVICE_RUNNING;
}

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

// Services the network stack cannot work without.
struct NetService {
    const wchar_t* name;
    const wchar_t* label;
};
static const NetService kNsi  = { L"nsi",     L"Network Store Interface" };
static const NetService kDhcp = { L"Dhcp",    L"DHCP Client" };
static const NetService kWlan = { L"WlanSvc", L"WLAN AutoConfig" };

// 1 running, 0 stopped (startable), -1 disabled, -2 unknown.
static int ServiceState(SC_HANDLE scm, const wchar_t* name)
{
    ScopedSvc svc(OpenServiceW(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!svc.h) return -2;
    SERVICE_STATUS ss{};
    if (!QueryServiceStatus(svc.h, &ss)) return -2;
    if (ss.dwCurrentState == SERVICE_RUNNING || ss.dwCurrentState == SERVICE_START_PENDING ||
        ss.dwCurrentState == SERVICE_CONTINUE_PENDING)
        return 1;
    DWORD need = 0;
    QueryServiceConfigW(svc.h, nullptr, 0, &need);
    if (need) {
        std::vector<BYTE> buf(need);
        auto* cfg = (QUERY_SERVICE_CONFIGW*)buf.data();
        if (QueryServiceConfigW(svc.h, cfg, need, &need) && cfg->dwStartType == SERVICE_DISABLED)
            return -1;
    }
    return 0;
}

static std::vector<const NetService*> RelevantServices(bool wifi, bool dhcp)
{
    std::vector<const NetService*> v = { &kNsi };
    if (dhcp) v.push_back(&kDhcp);
    if (wifi) v.push_back(&kWlan);
    return v;
}

static bool g_obsWifi = false, g_obsDhcp = false; // what the last observation needed

static void ObserveServices(nv::Observation& o, bool wifi, bool dhcp)
{
    g_obsWifi = wifi;
    g_obsDhcp = dhcp;
    ScopedSvc scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) return;
    for (const NetService* s : RelevantServices(wifi, dhcp)) {
        int st = ServiceState(scm.h, s->name);
        if (s == &kWlan) {                 // only the Wi-Fi path needs it
            o.wifi.serviceStopped  = st == 0;
            o.wifi.serviceDisabled = st == -1;
        } else if (st == 0) {
            o.stoppedServices.push_back(s->label);
        } else if (st == -1) {
            o.disabledServices.push_back(s->label);
        }
    }
}

static bool StartStoppedServices()
{
    ScopedSvc scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) return false;
    bool any = false;
    for (const NetService* s : RelevantServices(g_obsWifi, g_obsDhcp)) {
        if (ServiceState(scm.h, s->name) != 0) continue;
        bool ok = StartServiceAndWait(scm.h, s->name, 20000);
        Logf(ok ? L"  %ls started" : L"  %ls did not start", s->label);
        any = any || ok;
    }
    return any;
}

static bool ResyncClock()
{
    ScopedSvc scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.h) {
        int st = ServiceState(scm.h, L"W32Time");
        if (st == -1) {
            Logf(L"  the Windows Time service is disabled — cannot resync");
            return false;
        }
        if (st == 0 && !StartServiceAndWait(scm.h, L"W32Time", 15000)) return false;
    }
    DWORD rc = RunProcess(L"\"" + Sys32(L"w32tm.exe") + L"\" /resync /rediscover", true);
    Logf(rc == 0 ? L"  clock resync done" : L"  clock resync failed (w32tm exit %u)", rc);
    return rc == 0;
}

// ---------------------------------------------------------------- observe

// Everything the diagnosis looks at, gathered fresh. When the web answers
// (online, or a portal) the probe results are all it needs.
static nv::Observation Observe(const Connectivity& c, int failStreak, bool full)
{
    nv::Observation o;
    o.failStreak    = failStreak;
    o.allowFailover = GetFailover();
    nv::ProbeObs& p = o.probe;
    p.httpOk       = c.httpOk;
    p.httpAnswered = c.httpAnswered;
    p.pingOk       = c.pingOk;
    p.tcpOk        = c.tcpOk;
    p.clockKnown   = c.clockKnown;
    p.clockSkew    = c.clockSkew;
    if (!full && (c.httpOk || c.httpAnswered)) return o;

    bool ipReach = c.pingOk || c.tcpOk;
    o.adapters = SnapshotAdapters();
    std::vector<std::wstring> wlanGuids;
    ObserveWlan(o.wifi, wlanGuids, /*scanIfIdle=*/!ipReach);
    MergeDevices(o.adapters, EnumNetDevicesBounded(10000), wlanGuids);
    MarkRouteAdapter(o.adapters);

    bool anyDhcp = false;
    for (const auto& a : o.adapters) {
        if (a.virt) continue;
        if (a.kind == nv::Kind::Wifi) o.wifi.hardware = true;
        if (a.dhcp) anyDhcp = true;
    }
    if (o.wifi.interfaces > 0) o.wifi.hardware = true;
    if (o.wifi.hardware) RememberWifiSeen();
    o.wifi.expected = o.wifi.hardware || WifiSeenRecently();
    o.wifi.airplane = AirplaneModeOn();
    ObserveServices(o, o.wifi.hardware, anyDhcp);

    if (ipReach || full) {
        // Above IP: name resolution and the proxy.
        p.dnsOk = SystemDnsWorks(6000);
        int route = -1;
        for (size_t i = 0; i < o.adapters.size(); ++i)
            if (o.adapters[i].routesInternet) route = (int)i;
        std::vector<uint32_t> servers;
        if (route >= 0) servers = o.adapters[(size_t)route].dnsIps;
        size_t own = servers.size();
        servers.push_back(Ipv4("1.1.1.1"));
        servers.push_back(Ipv4("8.8.8.8"));
        std::vector<bool> alive = DnsServersAnswer(servers, 2000);
        if (route >= 0) {
            int dead = 0;
            for (size_t i = 0; i < own; ++i) dead += alive[i] ? 0 : 1;
            o.adapters[(size_t)route].dnsDead = dead;
        }
        p.dnsPublicOk = alive[own] || alive[own + 1];
        ObserveProxy(p);
    }
    if (!ipReach || full) {
        // Below: is each physical link's router there? The routing adapter
        // first; the others matter for telling a dead VPN from a dead LAN.
        std::vector<size_t> order;
        for (size_t i = 0; i < o.adapters.size(); ++i) {
            if (o.adapters[i].routesInternet) order.insert(order.begin(), i);
            else order.push_back(i);
        }
        int probed = 0;
        for (size_t i : order) {
            nv::AdapterObs& a = o.adapters[i];
            if (probed >= 3) break;
            if (a.virt || !a.hasIf || !a.up || !a.hasGateway) continue;
            a.gateway = ProbeGateway(a);
            ++probed;
        }
    }
    return o;
}

static const wchar_t* KindStr(nv::Kind k)
{
    switch (k) {
    case nv::Kind::Wifi:     return L"Wi-Fi";
    case nv::Kind::Ethernet: return L"Ethernet";
    case nv::Kind::Cellular: return L"cellular";
    default:                 return L"other";
    }
}

static void LogObservation(const nv::Observation& o)
{
    const nv::ProbeObs& p = o.probe;
    Logf(L"  observed: web %ls, ping %ls, tcp %ls%ls",
         p.httpOk ? L"ok" : p.httpAnswered ? L"wrong answer" : L"no answer",
         p.pingOk ? L"ok" : L"no",
         p.tcpOk ? L"ok" : (p.pingOk || p.httpOk || p.httpAnswered) ? L"not needed" : L"no",
         g_hintLevel == 3 ? L", Windows says: internet"
         : g_hintLevel == 2 ? L", Windows says: local network only"
         : g_hintLevel == 1 ? L", Windows says: no connectivity"
         : g_hintLevel == 4 ? L", Windows says: limited (sign-in?)" : L"");
    for (const auto& a : o.adapters) {
        if (a.virt && !a.routesInternet) continue;
        if (a.hasIf && !a.up && a.kind != nv::Kind::Wifi && a.dev != nv::Dev::Failed) continue;
        std::wstring dev = a.dev == nv::Dev::Disabled ? L"DISABLED, "
                         : a.dev == nv::Dev::Failed
                               ? L"DRIVER PROBLEM (code " + std::to_wstring(a.problem) + L"), "
                               : L"";
        std::wstring link = !a.hasIf ? L"no IP interface"
                          : a.kind == nv::Kind::Wifi ? (a.media ? L"associated" : L"not associated")
                          : (a.media ? L"link up" : L"no link");
        std::wstring gw = !a.hasGateway ? L"none"
                        : a.gw + (a.gateway == 1 ? L" (answers)" : a.gateway == 0 ? L" (silent)" : L"");
        Logf(L"  [%ls] %ls%ls%ls: %ls%ls, ip %ls%ls%ls, gw %ls, dns %ls%ls%ls",
             a.name.c_str(), KindStr(a.kind), a.virt ? L" (virtual)" : L"",
             a.routesInternet ? L", ROUTE" : L"", dev.c_str(), link.c_str(),
             a.hasIpv4 ? a.ip.c_str() : L"none", a.apipa ? L" (APIPA — DHCP failed)" : L"",
             a.duplicate ? L" (ADDRESS CONFLICT)" : L"", gw.c_str(),
             DnsListStr(a.dnsIps).c_str(), a.staticDns ? L" (set by hand)" : L"",
             a.dnsDead > 0 ? (L" (" + std::to_wstring(a.dnsDead) + L" silent)").c_str() : L"");
    }
    const nv::WifiObs& w = o.wifi;
    if (w.hardware || w.expected)
        Logf(L"  Wi-Fi: %d interface%ls, %ls, radio %ls%ls, %d network%ls visible, %d saved "
             L"in range%ls%ls",
             w.interfaces, w.interfaces == 1 ? L"" : L"s",
             w.associated ? L"associated" : L"not associated",
             w.radioHardOff ? L"OFF (hardware switch)" : w.radioSoftOff ? L"off" : L"on",
             w.airplane ? L", AIRPLANE MODE" : L"", w.visible < 0 ? 0 : w.visible,
             w.visible == 1 ? L"" : L"s", w.knownInRange,
             w.authFailed.empty() ? L"" : (L", password rejected: " + w.authFailed).c_str(),
             w.hardware ? L"" : L", ADAPTER MISSING");
    std::vector<std::wstring> stopped = o.stoppedServices, disabled = o.disabledServices;
    if (w.serviceStopped) stopped.push_back(kWlan.label);
    if (w.serviceDisabled) disabled.push_back(kWlan.label);
    if (!stopped.empty() || !disabled.empty()) {
        std::wstring s;
        for (const auto& n : stopped) s += (s.empty() ? L"" : L", ") + n + L" stopped";
        for (const auto& n : disabled) s += (s.empty() ? L"" : L", ") + n + L" DISABLED";
        Logf(L"  services: %ls", s.c_str());
    }
    if (p.pingOk || p.tcpOk)
        Logf(L"  dns: system resolver %ls, public DNS %ls", p.dnsOk ? L"ok" : L"FAILING",
             p.dnsPublicOk ? L"answers" : L"silent");
    if (p.proxyOn)
        Logf(L"  proxy: %ls%ls", p.proxy.c_str(),
             p.proxyDead ? L" — nothing is listening there"
                         : p.directOk ? L" — direct connections work" : L"");
}

// ---------------------------------------------------------------- repair

static std::map<std::wstring, ULONGLONG> g_lastRun;   // step key -> tick it last ran
static unsigned long long g_advised = 0;              // faults already told this episode
static std::wstring g_lastDiagKey;
static ULONGLONG g_lastDiagTick = 0;

static ULONGLONG ActCooldownMs(nv::Act a)
{
    const ULONGLONG minute = 60ull * 1000;
    switch (a) {
    case nv::Act::ResetAdapter:
    case nv::Act::RestartWlanSvc: return kResetCooldownMs;
    case nv::Act::RenewDhcp:      return 10 * minute;
    case nv::Act::RescanDevices:  return 10 * minute;
    case nv::Act::SwitchNetwork:  return 20 * minute;
    case nv::Act::FlushDns:
    case nv::Act::FlushArp:
    case nv::Act::EnableAdapter:  return 5 * minute;
    case nv::Act::StartServices:  return 2 * minute;
    case nv::Act::ResyncClock:    return 6 * 60 * minute;
    default:                      return 0;   // Wi-Fi (re)connects, radio, proxy
    }
}


// Time for a repair to take effect before connectivity is re-checked.
static DWORD ActSettleMs(nv::Act a)
{
    switch (a) {
    case nv::Act::EnableAdapter:
    case nv::Act::RescanDevices:  return 8000;
    case nv::Act::StartServices:
    case nv::Act::RestartWlanSvc: return 5000;
    case nv::Act::RenewDhcp:
    case nv::Act::ResetAdapter:   return 3000;
    default:                      return 1500;
    }
}

static std::wstring StepText(const nv::Step& s, const nv::Observation& o)
{
    std::wstring t = nv::ActName(s.act);
    if (s.adapter >= 0 && (size_t)s.adapter < o.adapters.size())
        t += L" on '" + o.adapters[(size_t)s.adapter].name + L"'";
    return t;
}

static std::wstring StepKey(const nv::Step& s, const nv::Observation& o)
{
    std::wstring k = nv::ActKey(s.act);
    if (s.adapter >= 0 && (size_t)s.adapter < o.adapters.size())
        k += L":" + o.adapters[(size_t)s.adapter].id;
    return k;
}

static void PublishDiagnosis(const nv::Diagnosis& d)
{
    UpdateState([&](MonitorState& s) {
        s.fault           = (int)d.fault;
        s.faultNeedsUser  = d.userAction;
        s.diagnosis       = d.fault == nv::Fault::None ? L"" : nv::FaultName(d.fault);
        s.diagnosisDetail = d.fault == nv::Fault::None ? L"" : d.detail;
    });
}

static void ClearDiagnosis()
{
    g_advised = 0;
    g_lastDiagKey.clear();
    UpdateState([](MonitorState& s) {
        s.fault = 0;
        s.faultNeedsUser = false;
        s.diagnosis.clear();
        s.diagnosisDetail.clear();
    });
}

// Tell the user once per outage about a fault only they can finish fixing.
static void Advise(const nv::Diagnosis& d)
{
    if (!d.userAction) return;
    unsigned long long bit = 1ull << (unsigned)d.fault;
    if (g_advised & bit) return;
    g_advised |= bit;
    NotifyUi(UiAdvice, (LPARAM)d.fault);
}

static void AdviseRestart(const std::wstring& detail)
{
    nv::Diagnosis d;
    d.fault = nv::Fault::AdapterFailed;
    d.userAction = true;
    d.detail = detail;
    PublishDiagnosis(d);
    Advise(d);
}

static void LogDiagnosis(const nv::Diagnosis& d, const nv::Observation& o)
{
    if (d.fault == nv::Fault::None) {
        Logf(L"diagnosis: healthy — nothing to repair");
        return;
    }
    Logf(L"diagnosis: %ls — %ls", nv::FaultName(d.fault), d.detail.c_str());
    if (d.plan.empty()) {
        Logf(L"  no repair applies from this computer%ls",
             d.userAction ? L" — this needs a person" : L"");
        return;
    }
    std::wstring plan;
    for (const auto& s : d.plan) {
        if (!plan.empty()) plan += L" → ";
        plan += StepText(s, o);
    }
    Logf(L"  plan: %ls", plan.c_str());
}

static void ReportDiagnosis(const nv::Diagnosis& d, const nv::Observation& o)
{
    PublishDiagnosis(d);
    std::wstring key = std::to_wstring((int)d.fault) + L"|" + d.detail;
    ULONGLONG now = GetTickCount64();
    if (key != g_lastDiagKey || now - g_lastDiagTick > 30ull * 60 * 1000) {
        g_lastDiagKey = key;
        g_lastDiagTick = now;
        LogObservation(o);
        LogDiagnosis(d, o);
    } else {
        Logf(L"diagnosis unchanged: %ls", nv::FaultName(d.fault));
    }
    Advise(d);
}

static void RecordFix(const nv::Step& s, const nv::Observation& o, const nv::Diagnosis& d)
{
    std::wstring what = StepText(s, o);
    Logf(L"fixed by: %ls (%ls)", what.c_str(), nv::FaultName(d.fault));
    IniBump(L"repairs", nv::ActKey(s.act));
    if (s.act == nv::Act::ResetAdapter && s.adapter >= 0)
        IniBump(L"resets", o.adapters[(size_t)s.adapter].id);
    long long now = (long long)_time64(nullptr);
    UpdateState([&](MonitorState& st) {
        st.lastRepair = what + L" (" + nv::FaultName(d.fault) + L")";
        st.lastRepairAt = now;
    });
}

// Runs one repair step. True if it actually did something worth verifying.
static bool Execute(const nv::Step& s, const nv::Observation& o)
{
    const nv::AdapterObs* ad =
        s.adapter >= 0 && (size_t)s.adapter < o.adapters.size() ? &o.adapters[(size_t)s.adapter]
                                                               : nullptr;
    std::wstring what = StepText(s, o);
    if (nv::ActNeedsAdmin(s.act) && !g_elevated) {
        Logf(L"  skipped: %ls (needs admin rights — install NetVigil at startup)", what.c_str());
        return false;
    }
    std::wstring key = StepKey(s, o);
    ULONGLONG now = GetTickCount64(), cooldown = ActCooldownMs(s.act);
    auto last = g_lastRun.find(key);
    if (cooldown && last != g_lastRun.end() && now - last->second < cooldown) {
        Logf(L"  skipped: %ls (ran %llu min ago; at most every %llu min)", what.c_str(),
             (now - last->second) / 60000ull, cooldown / 60000ull);
        return false;
    }
    bool deviceOp = s.act == nv::Act::ResetAdapter || s.act == nv::Act::EnableAdapter ||
                    s.act == nv::Act::RescanDevices;
    if (deviceOp && DeviceOpHung()) {
        Logf(L"  skipped: %ls (an earlier device operation is still hung)", what.c_str());
        return false;
    }
    g_lastRun[key] = now;
    Logf(L"repair: %ls", what.c_str());
    UpdateState([&](MonitorState& st) { st.lastAction = L"trying: " + what; });
    switch (s.act) {
    case nv::Act::StartServices:  return StartStoppedServices();
    case nv::Act::EnableAdapter:  return ad && EnableAdapterDevice(*ad);
    case nv::Act::RescanDevices:  return RescanHardware();
    case nv::Act::RadioOn:        return RadioOnAll();
    case nv::Act::ConnectWifi:    return WifiReconnectAll(false);
    case nv::Act::Reassociate:    return WifiReconnectAll(true);
    case nv::Act::SwitchNetwork:  return SwitchWifiNetwork();
    case nv::Act::RenewDhcp:      return ad && RenewDhcp(ad->ifIndex, ad->name);
    case nv::Act::FlushArp:       return ad && FlushArpCache(ad->ifIndex, ad->name);
    case nv::Act::FlushDns:       FlushDnsCache(); return true;
    case nv::Act::DisableProxy:   return DisableDeadProxy(o.probe);
    case nv::Act::ResetAdapter:   return ad && ResetAdapterDevice(*ad);
    case nv::Act::RestartWlanSvc: return StartOrRestartWlanSvc(true);
    case nv::Act::ResyncClock:    return ResyncClock();
    default:                      return false;
    }
}

// Observe -> diagnose -> repair, re-diagnosing when a plan runs out (the
// situation changes as repairs land: an enabled adapter still has to
// associate, a started service still has to connect).
static Net RunRepairs(Connectivity c, int failStreak, int maxRounds)
{
    std::set<std::wstring> done; // steps already run in this call
    for (int round = 0; round < maxRounds && !StopRequested(); ++round) {
        Net start = c.verdict;
        nv::Observation o = Observe(c, failStreak, false);
        nv::Diagnosis d = nv::Diagnose(o);
        ReportDiagnosis(d, o);
        if (d.fault == nv::Fault::None) return c.verdict;

        nv::PlanRun run = nv::RunPlan(
            d.plan, done,
            [&](const nv::Step& s) { return StepKey(s, o); },
            [] { return StopRequested(); },
            [&](const nv::Step& s) { return Execute(s, o); },
            [&](const nv::Step& principal) {
                if (WaitStop(ActSettleMs(principal.act))) return nv::Verdict::Abort;
                c = Probe();
                Logf(L"  -> %ls", NetToStr(c.verdict));
                // Only progress counts: from offline, getting IP back (even
                // with DNS still failing) does; from degraded, only online.
                if (c.verdict == Net::Online ||
                    (c.verdict == Net::Degraded && start != Net::Degraded)) {
                    RecordFix(principal, o, d);
                    return nv::Verdict::Fixed;
                }
                // Behind a sign-in page now: nothing more to repair here.
                return c.verdict == Net::Portal ? nv::Verdict::Abort : nv::Verdict::Continue;
            });
        if (run.fixedBy >= 0 && c.verdict == Net::Online) break;
        if (run.fixedBy >= 0) continue;  // IP is back, web/DNS still fail: diagnose that
        if (run.aborted || !run.acted) break;
    }
    return c.verdict;
}

// Degraded (the internet answers by IP, web requests fail): diagnosis-driven
// repair above the IP layer only. Rate-limited; cooldowns do the rest.
static Net RepairDegraded(const Connectivity& c)
{
    static ULONGLONG last = 0;
    ULONGLONG now = GetTickCount64();
    if (last && now - last < 10ull * 60 * 1000) return Net::Degraded;
    last = now;
    return RunRepairs(c, 0, 1);
}

// Online, but the clock is far off — HTTPS certificate checks fail.
static void RepairClock(const Connectivity& c)
{
    static ULONGLONG last = 0;
    ULONGLONG now = GetTickCount64();
    if (last && now - last < 6ull * 3600 * 1000) return;
    last = now;
    nv::Observation o = Observe(c, 0, false);
    nv::Diagnosis d = nv::Diagnose(o);
    if (d.fault != nv::Fault::ClockSkew) return;
    ReportDiagnosis(d, o);
    for (const auto& s : d.plan) Execute(s, o);
    if (WaitStop(5000)) return;
    Connectivity after = Probe();
    if (after.clockKnown && llabs(after.clockSkew) < nv::kClockSkewLimitSec) {
        RecordFix(d.plan.front(), o, d);
        ClearDiagnosis();
        return;
    }
    // Windows Time refused (it won't jump that far) or failed: over to the user.
    d.userAction = true;
    d.detail += L" — set the time under Settings > Time & language";
    PublishDiagnosis(d);
    Advise(d);
}

// ---------------------------------------------------------------- connectivity hints
//
// Windows' own connectivity verdict (NCSI), pushed on every change, so a drop
// is noticed at once instead of at the next interval. Windows 10 2004+;
// loaded dynamically — without it NetVigil just polls.

struct NvConnectivityHint {   // mirrors NL_NETWORK_CONNECTIVITY_HINT
    int level;                // 0 unknown, 1 none, 2 local, 3 internet, 4 constrained, 5 hidden
    int cost;
    BOOLEAN approachingDataLimit;
    BOOLEAN overDataLimit;
    BOOLEAN roaming;
};
enum : LONG { HintUnknown = 0, HintNone, HintLocal, HintInternet, HintConstrained, HintHidden };
typedef VOID(CALLBACK* PfnHintCallback)(PVOID, NvConnectivityHint);
typedef DWORD(WINAPI* PfnNotifyHint)(PfnHintCallback, PVOID, BOOLEAN, PHANDLE);
typedef DWORD(WINAPI* PfnGetHint)(NvConnectivityHint*);

static HANDLE g_hintHandle = nullptr;

static VOID CALLBACK OnConnectivityHint(PVOID, NvConnectivityHint hint)
{
    LONG prev = InterlockedExchange(&g_hintLevel, (LONG)hint.level);
    if (prev != (LONG)hint.level && g_hintEvent) SetEvent(g_hintEvent);
}

static const wchar_t* HintText(LONG level)
{
    switch (level) {
    case HintNone:        return L"no connectivity";
    case HintLocal:       return L"local network only";
    case HintInternet:    return L"internet access";
    case HintConstrained: return L"limited internet (sign-in page?)";
    default:              return L"unknown connectivity";
    }
}

static void StartConnectivityHints()
{
    HMODULE m = GetModuleHandleW(L"iphlpapi.dll");
    auto notify = m ? (PfnNotifyHint)(void*)GetProcAddress(m, "NotifyNetworkConnectivityHintChange")
                    : nullptr;
    auto get = m ? (PfnGetHint)(void*)GetProcAddress(m, "GetNetworkConnectivityHint") : nullptr;
    if (!notify) {
        Logf(L"connectivity change notifications unavailable (Windows 10 2004+) — "
             L"checking on the interval only");
        return;
    }
    NvConnectivityHint h{};
    if (get && get(&h) == NO_ERROR) InterlockedExchange(&g_hintLevel, (LONG)h.level);
    DWORD rc = notify(OnConnectivityHint, nullptr, FALSE, &g_hintHandle);
    if (rc != NO_ERROR) {
        g_hintHandle = nullptr;
        Logf(L"connectivity change notifications unavailable (%u)", rc);
        return;
    }
    UpdateState([](MonitorState& s) { s.windowsLevel = (int)g_hintLevel; });
}

static void StopConnectivityHints()
{
    if (g_hintHandle) CancelMibChangeNotify2(g_hintHandle);
    g_hintHandle = nullptr;
}

// ---------------------------------------------------------------- monitor loop

// Wait until the next check: honours stop, "check now", resume from sleep, a
// live interval change from the GUI, and Windows reporting that connectivity
// changed in a way that contradicts `last`. Returns true if stop was
// requested. `liveInterval` re-reads the configured interval each tick;
// otherwise `minutes` is fixed (the short offline retry).
static bool IntervalWait(DWORD minutes, bool liveInterval, Net last)
{
    static ULONGLONG lastHintCheck = 0;
    TrimWorkingSet();
    ULONGLONG start = GetTickCount64();
    ULONGLONG w0 = WallMs(), u0 = UnbiasedMs();
    ULONGLONG shown = 0;
    HANDLE evs[3];
    DWORD nEvs = 0;
    evs[nEvs++] = g_stopEvent;
    if (g_wakeEvent) evs[nEvs++] = g_wakeEvent;
    DWORD hintIdx = nEvs;
    if (g_hintEvent) evs[nEvs++] = g_hintEvent;
    for (;;) {
        ULONGLONG total = (ULONGLONG)(liveInterval ? GetIntervalMin() : minutes) * 60000ull;
        ULONGLONG deadline = start + total;
        if (deadline != shown) {
            shown = deadline;
            UpdateState([&](MonitorState& s) { s.nextCheck = deadline; });
        }
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) return false;
        ULONGLONG left = deadline - now;
        DWORD chunk = (DWORD)(left < 15000ull ? left : 15000ull);
        DWORD r = g_stopEvent ? WaitForMultipleObjects(nEvs, evs, FALSE, chunk)
                              : (Sleep(chunk), WAIT_TIMEOUT);
        if (r == WAIT_OBJECT_0) return true;               // stop
        if (r == WAIT_OBJECT_0 + 1 && g_wakeEvent) {       // check now / pause / resume
            Logf(InterlockedExchange(&g_resumed, 0) ? L"resume from sleep — checking connectivity now"
                                                    : L"check requested");
            return false;
        }
        if (g_hintEvent && r == WAIT_OBJECT_0 + hintIdx) {
            LONG lvl = g_hintLevel;
            UpdateState([&](MonitorState& s) { s.windowsLevel = (int)lvl; });
            bool worse  = last == Net::Online &&
                          (lvl == HintNone || lvl == HintLocal || lvl == HintConstrained);
            bool better = last != Net::Online && lvl == HintInternet;
            if ((worse || better) && GetTickCount64() - lastHintCheck > 20000ull) {
                lastHintCheck = GetTickCount64();
                Logf(L"Windows reports %ls — checking now", HintText(lvl));
                if (worse && WaitStop(5000)) return true;  // let a blip settle
                return false;
            }
            continue;
        }
        ULONGLONG wallD = WallMs() - w0, unbD = UnbiasedMs() - u0;
        if (wallD > unbD + 90000ull) {
            InterlockedExchange(&g_resumed, 0);
            Logf(L"resume from sleep detected — checking connectivity now");
            return false;
        }
    }
}

// The confirmation delay before acting on a loss — cut short when Windows
// reports internet access again. Returns true if stop was requested.
static bool ConfirmWait(DWORD ms)
{
    ULONGLONG end = GetTickCount64() + ms;
    for (;;) {
        ULONGLONG now = GetTickCount64();
        if (now >= end) return false;
        HANDLE evs[2];
        DWORD n = 0;
        if (g_stopEvent) evs[n++] = g_stopEvent;
        DWORD hintIdx = n;
        if (g_hintEvent) evs[n++] = g_hintEvent;
        if (n == 0) {
            Sleep((DWORD)(end - now));
            return false;
        }
        DWORD r = WaitForMultipleObjects(n, evs, FALSE, (DWORD)(end - now));
        if (g_stopEvent && r == WAIT_OBJECT_0) return true;
        if (r == WAIT_OBJECT_0 + hintIdx && g_hintLevel == HintInternet) {
            Logf(L"Windows reports internet access again — re-checking early");
            return false;
        }
        if (r == WAIT_TIMEOUT || r == WAIT_FAILED) return false;
    }
}

// After a check: remember the network we are on and publish the result.
static void PublishCheck(Net n, int failStreak, ULONGLONG offlineSince)
{
    std::wstring ssid, iface, profile;
    bool wifi = CurrentConnection(ssid, iface, profile);
    if (wifi) RecordConnected(profile, ssid);
    UpdateState([&](MonitorState& s) {
        s.haveStatus   = true;
        s.status       = n;
        s.lastCheck    = GetTickCount64();
        s.ssid         = wifi ? ssid : L"";
        s.iface        = wifi ? iface : L"";
        s.failStreak   = failStreak;
        s.offlineSince = offlineSince;
        s.remediating  = false;
    });
}

static bool IsRunningInstalledCopy(); // fwd (task mgmt)
static std::wstring AutostartArgs();      // fwd

// An elevated installed copy keeps its own startup task current: tasks made
// by older versions (schtasks defaults) are killed after 72 h and never
// start on battery. Tasks the user edited to the current format are left be.
static void MaintainStartupTask()
{
    if (!g_elevated || !IsRunningInstalledCopy()) return;
    StartupTaskInfo t;
    std::wstring err;
    if (!QueryStartupTask(t, &err) || !t.exists || !t.readable) return;
    if (t.format >= nv::kTaskFormat) return;
    if (_wcsicmp(t.command.c_str(), ExePath().c_str()) != 0) return;
    if (RegisterStartupTask(ExePath(), AutostartArgs(), SessionUserSid(nullptr), &err))
        Logf(L"startup task upgraded: no 3-day time limit, starts on battery, and relaunches "
             L"NetVigil within %u min if it stops", kRelaunchMin);
    else
        Logf(L"startup task upgrade failed: %ls", err.c_str());
}

// The watchdog loop. Runs on its own thread under the GUI and exits when the
// stop event is signalled.
DWORD WINAPI MonitorThreadProc(LPVOID)
{
    Logf(L"=== NetVigil started (interval %u min, %ls) ===", GetIntervalMin(),
         g_elevated ? L"elevated"
                    : L"NOT elevated — adapter resets and service repairs unavailable");
    UpdateState([](MonitorState& s) {
        s.elevated = g_elevated;
        s.paused   = g_paused != 0;
    });
    MaintainStartupTask();
    StartConnectivityHints();

    bool firstCycle = true;
    int  failStreak = 0;
    ULONGLONG lastOkLog = 0, offlineSince = 0;

    for (;;) {
        if (StopRequested()) break;
        if (g_paused) {
            HANDLE evs[2] = { g_stopEvent, g_wakeEvent };
            if (WaitForMultipleObjects(2, evs, FALSE, INFINITE) == WAIT_OBJECT_0) break;
            InterlockedExchange(&g_resumed, 0);
            continue;
        }

        Connectivity c = Probe();
        Net n = c.verdict;
        PublishCheck(n, failStreak, offlineSince);

        if (n == Net::Online || n == Net::Degraded) {
            if (failStreak > 0) {
                ULONGLONG mins = offlineSince ? (GetTickCount64() - offlineSince) / 60000ull : 0;
                Logf(L"connectivity restored after %llu min offline", mins);
                NotifyUi(UiRestored, (LPARAM)mins);
                offlineSince = 0;
            }
            if (n == Net::Degraded) {
                Logf(L"degraded: the internet answers by IP but web requests fail — diagnosing");
                if (RepairDegraded(c) == Net::Online) {
                    n = Net::Online;
                    PublishCheck(n, 0, 0);
                    ClearDiagnosis();
                }
            } else if (c.clockKnown && llabs(c.clockSkew) >= nv::kClockSkewLimitSec) {
                RepairClock(c);
            } else {
                if (GetMonitorState().fault) ClearDiagnosis();
                if (GetTickCount64() - lastOkLog > 3600000ull) {
                    Logf(L"online");
                    lastOkLog = GetTickCount64();
                }
            }
            failStreak = 0;
            firstCycle = false;
            UpdateState([](MonitorState& s) { s.failStreak = 0; s.offlineSince = 0; });
            if (IntervalWait(0, true, n)) break;
            continue;
        }

        // Confirm before acting — give transient blips (and the network stack
        // right after logon) a chance to settle.
        DWORD confirmMs = firstCycle ? 90000 : 30000;
        Logf(L"%ls detected — confirming in %u s",
             n == Net::Portal ? L"captive portal" : L"connection loss",
             confirmMs / 1000);
        UpdateState([](MonitorState& s) {
            s.remediating = true;
            s.lastAction  = L"confirming the loss";
        });
        if (ConfirmWait(confirmMs)) break;
        firstCycle = false;

        Connectivity c2 = Probe();
        if (c2.verdict == Net::Online || c2.verdict == Net::Degraded) {
            if (failStreak > 0) {   // mid-outage: this is the recovery
                ULONGLONG mins = offlineSince ? (GetTickCount64() - offlineSince) / 60000ull : 0;
                Logf(L"connectivity restored after %llu min offline", mins);
                NotifyUi(UiRestored, (LPARAM)mins);
                offlineSince = 0;
            } else {
                Logf(L"false alarm — back online");
            }
            failStreak = 0;
            ClearDiagnosis();
            PublishCheck(c2.verdict, 0, 0);
            if (IntervalWait(0, true, c2.verdict)) break;
            continue;
        }

        ++failStreak;
        if (failStreak == 1) offlineSince = GetTickCount64();
        Logf(L"confirmed %ls (streak %d) — diagnosing", NetToStr(c2.verdict), failStreak);
        UpdateState([&](MonitorState& s) {
            s.status       = c2.verdict;
            s.failStreak   = failStreak;
            s.offlineSince = offlineSince;
            s.remediating  = true;
            s.lastAction   = L"diagnosing";
        });
        Net after = RunRepairs(c2, failStreak, 3);
        PublishCheck(after, failStreak, offlineSince);

        if (after == Net::Online || after == Net::Degraded) {
            ULONGLONG mins = offlineSince ? (GetTickCount64() - offlineSince) / 60000ull : 0;
            Logf(L"repaired — back online after %llu min", mins);
            NotifyUi(UiRestored, (LPARAM)mins);
            offlineSince = 0;
            failStreak = 0;
            ClearDiagnosis();
            UpdateState([](MonitorState& s) {
                s.failStreak = 0;
                s.offlineSince = 0;
                s.lastAction = L"repaired";
            });
            if (IntervalWait(0, true, after)) break;
        } else {
            Logf(L"still %ls — next attempt in %u min", NetToStr(after), kOfflineRetryMin);
            NotifyUi(UiFailed, (LPARAM)failStreak);
            UpdateState([](MonitorState& s) { s.lastAction = L"waiting to retry"; });
            if (IntervalWait(kOfflineRetryMin, false, after)) break;
        }
    }

    StopConnectivityHints();
    Logf(L"stop requested — NetVigil exiting");
    UpdateState([](MonitorState& s) { s.stopping = true; });
    NotifyUi(UiStopped);
    return 0;
}

static ScopedHandle g_instanceMutex; // held for the process lifetime

static void EnableDpiAwareness()
{
    typedef BOOL(WINAPI* PfnSetCtx)(DPI_AWARENESS_CONTEXT);
    PfnSetCtx set = (PfnSetCtx)(void*)GetProcAddress(GetModuleHandleW(L"user32.dll"),
                                                     "SetProcessDpiAwarenessContext");
    if (!set || !set(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE)) SetProcessDPIAware();
}

static bool SignalRunningInstance();        // fwd (task mgmt)
static bool WaitInstanceExit(DWORD ms);     // fwd

// The startup task runs elevated; if the user started a normal copy first,
// the elevated one replaces it — otherwise adapter resets would be off.
static bool TakeOverFromNonElevated()
{
    HWND w = FindWindowW(kWndClass, nullptr);
    DWORD pid = 0;
    if (!w || !GetWindowThreadProcessId(w, &pid) || !pid) return false;
    ScopedHandle proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!proc.valid()) return false;
    HANDLE tok = nullptr;
    if (!OpenProcessToken(proc.h, TOKEN_QUERY, &tok)) return false;
    ScopedHandle tokGuard(tok);
    if (TokenIsElevated(tok)) return false;
    Logf(L"NetVigil is running without admin rights — replacing it with this elevated instance");
    SignalRunningInstance();
    return WaitInstanceExit(30000);
}

// A copy is running but owns no window: an older build that predates the GUI
// (typically the one the logon task started), or one still starting up. This
// is a windowed app, so silently exiting would look like "nothing happened" —
// ask instead, and replace the old copy if the user agrees. Returns true when
// the running copy is gone and this instance may take over.
static bool ReplaceWindowlessInstance()
{
    // A copy that is merely mid-startup gets its window within moments.
    for (int i = 0; i < 8; ++i) {
        if (FindWindowW(kWndClass, nullptr)) return false; // caller hands off to it
        Sleep(250);
    }
    int answer = MessageBoxW(nullptr,
        L"NetVigil is already running in the background, but that copy has no "
        L"window. It is an older version, most likely the one started at sign-in.\n\n"
        L"Stop it and open this version instead?",
        L"NetVigil", MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND | MB_TOPMOST);
    if (answer != IDYES) {
        Logf(L"another NetVigil instance is already running (no window) — left it running");
        return false;
    }
    if (!SignalRunningInstance()) {
        DWORD err = GetLastError();
        Logf(L"could not reach the running instance to stop it (%u)", err);
        MessageBoxW(nullptr,
            err == ERROR_ACCESS_DENIED
                ? L"Could not stop the running copy — it is running as administrator.\n\n"
                  L"End \"NetVigil.exe\" in Task Manager (Details tab), or start this "
                  L"version as administrator, then try again."
                : L"Could not stop the running copy — it does not respond to a stop request.\n\n"
                  L"End \"NetVigil.exe\" in Task Manager (Details tab), then try again.",
            L"NetVigil", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
        return false;
    }
    if (!WaitInstanceExit(20000)) {
        Logf(L"running instance did not exit within 20 s");
        MessageBoxW(nullptr,
            L"The running copy did not stop in time. End \"NetVigil.exe\" in Task "
            L"Manager (Details tab) and try again.",
            L"NetVigil", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
        return false;
    }
    Logf(L"replaced the running windowless instance");
    return true;
}

// Monitor mode: claim the single instance (or hand off to the running one),
// create the control events, load config and run the tray/window front end
// with the watchdog on a worker thread. `autostart` = launched by the
// startup task (at sign-in, or its relaunch trigger).
static int StartMonitorGui(HINSTANCE hInst, bool startHidden, bool autostart, DWORD intervalArg)
{
    // "Exit" in the tray means exit until the next sign-in.
    if (autostart && UserExitedThisSession()) return 0;

    SECURITY_ATTRIBUTES* sa = NamedObjSa();
    g_instanceMutex.reset(CreateMutexW(sa, FALSE, kMutexName));
    DWORD mutexErr = GetLastError();
    bool running = !g_instanceMutex.valid() || mutexErr == ERROR_ALREADY_EXISTS;
    if (running && autostart && g_elevated) {
        g_instanceMutex.reset();
        if (TakeOverFromNonElevated()) {
            g_instanceMutex.reset(CreateMutexW(sa, FALSE, kMutexName));
            mutexErr = GetLastError();
            running = !g_instanceMutex.valid() || mutexErr == ERROR_ALREADY_EXISTS;
        }
    }
    if (running && !autostart && !startHidden && !FindWindowW(kWndClass, nullptr)) {
        g_instanceMutex.reset(); // our handle would keep the old mutex alive
        if (ReplaceWindowlessInstance()) {
            g_instanceMutex.reset(CreateMutexW(sa, FALSE, kMutexName));
            mutexErr = GetLastError();
            running = !g_instanceMutex.valid() || mutexErr == ERROR_ALREADY_EXISTS;
        }
    }
    if (running) {
        // NULL + ACCESS_DENIED means the mutex exists but was created by a
        // differently-privileged instance — that still counts as running.
        if (!g_instanceMutex.valid() && mutexErr != ERROR_ACCESS_DENIED &&
            mutexErr != ERROR_ALREADY_EXISTS) {
            Logf(L"single-instance mutex unavailable (%u) — exiting", mutexErr);
            return 1;
        }
        g_instanceMutex.reset();
        if (autostart) return 0;   // relaunch trigger while running: nothing to do
        HWND existing = startHidden ? nullptr : FindWindowW(kWndClass, nullptr);
        if (existing && PostMessageW(existing, ShowWindowMessage(), 0, 0)) {
            Logf(L"NetVigil is already running — opened its window");
            return 0;
        }
        Logf(L"another NetVigil instance is already running — exiting");
        return 1;
    }
    if (!autostart) ClearUserExit(); // started by hand: automatic relaunch applies again

    g_stopEvent = CreateEventW(sa, TRUE, FALSE, kStopEventName);
    DWORD evErr = GetLastError();
    if (!g_stopEvent)
        Logf(L"warning: stop event unavailable (%u) — --stop will not reach "
             L"this instance", evErr);
    else if (evErr == ERROR_ALREADY_EXISTS)
        ResetEvent(g_stopEvent); // clear a stale signal from a previous run

    LoadConfig(intervalArg);
    if (autostart) Logf(L"started by the startup task");
    EnableDpiAwareness();
    int rc = RunGui(hInst, startHidden);

    if (g_stopEvent) {
        HANDLE ev = g_stopEvent;
        g_stopEvent = nullptr; // CtrlHandler must not touch a closed handle
        CloseHandle(ev);
    }
    return rc;
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
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE,
                        quiet ? CREATE_NO_WINDOW : 0, nullptr, nullptr, &si, &pi)) {
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

static bool SignalRunningInstance()
{
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, kStopEventName);
    if (!ev) return false; // GetLastError() says why (ACCESS_DENIED = other privilege level)
    SetEvent(ev);
    CloseHandle(ev);
    Logf(L"stop signal sent to running instance");
    return true;
}

static bool InstanceRunning()
{
    HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
    if (m) {
        CloseHandle(m);
        return true;
    }
    return GetLastError() != ERROR_FILE_NOT_FOUND;
}

// Wait until no instance holds the single-instance mutex any more.
static bool WaitInstanceExit(DWORD ms)
{
    ULONGLONG end = GetTickCount64() + ms;
    for (;;) {
        if (!InstanceRunning()) return true;
        if (GetTickCount64() >= end) return false;
        Sleep(1000);
    }
}

static bool WaitInstanceStart(DWORD ms)
{
    ULONGLONG end = GetTickCount64() + ms;
    for (;;) {
        if (InstanceRunning()) return true;
        if (GetTickCount64() >= end) return false;
        Sleep(500);
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

static std::wstring InstalledExe() { return InstallDirPath() + L"\\NetVigil.exe"; }

static std::wstring AutostartArgs()
{
    return L"--autostart --interval " + std::to_wstring(GetIntervalMin());
}

// Fire-and-forget launch of ourselves (or a helper copy), elevated if asked.
static bool LaunchDetached(const std::wstring& exe, const std::wstring& args, bool elevate)
{
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask  = SEE_MASK_NOASYNC;
    sei.lpVerb = elevate ? L"runas" : L"open";
    sei.lpFile = exe.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow  = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
        Logf(L"could not start '%ls %ls' (%u)", exe.c_str(), args.c_str(), GetLastError());
        return false;
    }
    return true;
}

// This exe IS %ProgramFiles%\NetVigil\NetVigil.exe.
static bool IsRunningInstalledCopy()
{
    return _wcsicmp(ExePath().c_str(), InstalledExe().c_str()) == 0;
}

StartupStatus GetStartupStatus()
{
    StartupStatus st;
    StartupTaskInfo t;
    if (!QueryStartupTask(t, &st.detail)) return st;       // Unknown
    if (!t.exists) {
        st.state = StartupState::NotInstalled;
    } else if (!t.readable) {
        st.state = StartupState::Installed;                // cannot inspect: trust it
    } else if (!t.enabled) {
        st.state = StartupState::Disabled;
    } else if (!t.command.empty() &&
               GetFileAttributesW(t.command.c_str()) == INVALID_FILE_ATTRIBUTES) {
        st.state = StartupState::Broken;
        st.detail = t.command;
    } else if (t.format < nv::kTaskFormat) {
        st.state = StartupState::Outdated;
    } else if (!t.command.empty() && _wcsicmp(ExePath().c_str(), t.command.c_str()) != 0) {
        st.state = StartupState::OtherCopy;
    } else {
        st.state = StartupState::Installed;
    }
    return st;
}

// Both launchers stop THIS instance as part of their job (SignalRunningInstance
// inside CmdInstall/CmdUninstall), so the window closes; after an install the
// task's tray instance takes over.
bool LaunchInstaller()
{
    Logf(L"install at startup requested from the window");
    return LaunchDetached(ExePath(),
                          L"--install --interval " + std::to_wstring(GetIntervalMin()),
                          !g_elevated);
}

bool LaunchUninstaller()
{
    std::wstring helper = ExePath();
    std::wstring args = L"--uninstall";
    if (IsRunningInstalledCopy()) {
        // We ARE the installed copy: a helper copy in %TEMP% does the removal
        // and deletes itself at the next reboot.
        wchar_t tmp[MAX_PATH] = {};
        if (!GetTempPathW(MAX_PATH, tmp)) return false;
        std::wstring tmpExe = std::wstring(tmp) + L"NetVigil-uninstall.exe";
        if (!CopyFileW(helper.c_str(), tmpExe.c_str(), FALSE)) {
            Logf(L"could not create the uninstall helper (%u)", GetLastError());
            return false;
        }
        helper = tmpExe;
        args += L" --helper";
    }
    Logf(L"uninstall requested from the window");
    return LaunchDetached(helper, args, !g_elevated);
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

// Copy via a temporary file and an atomic rename, so an interrupted update
// never leaves a half-written exe for the elevated task to run.
static bool InstallCopy(const std::wstring& dest)
{
    std::wstring tmp = dest + L".new";
    if (!CopyFileW(ExePath().c_str(), tmp.c_str(), FALSE)) return false;
    for (int i = 0; i < 3; ++i) {
        if (MoveFileExW(tmp.c_str(), dest.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return true;
        Sleep(2000); // previous instance may still be releasing the file
    }
    DWORD err = GetLastError();
    DeleteFileW(tmp.c_str());
    SetLastError(err);
    return false;
}

// An --uninstall run from the installed copy scheduled it (and its folder)
// for deletion at the next boot. A reinstall before that reboot must cancel
// it, or the fresh copy vanishes at boot and the startup task breaks.
static void CancelPendingDeletes(const std::vector<std::wstring>& paths)
{
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                      0, KEY_QUERY_VALUE | KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return;
    ScopedRegKey guard(k);
    const wchar_t* value = L"PendingFileRenameOperations";
    DWORD type = 0, bytes = 0;
    if (RegQueryValueExW(k, value, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        type != REG_MULTI_SZ || bytes < sizeof(wchar_t))
        return;
    std::vector<wchar_t> buf(bytes / sizeof(wchar_t) + 2, L'\0');
    if (RegQueryValueExW(k, value, nullptr, &type, (BYTE*)buf.data(), &bytes) != ERROR_SUCCESS)
        return;
    // (source, target) pairs; an empty target means "delete". Empty strings
    // are data here, so split by the byte count rather than at a double null.
    size_t n = bytes / sizeof(wchar_t);
    std::vector<std::wstring> items;
    for (size_t i = 0; i < n;) {
        size_t j = i;
        while (j < n && buf[j]) ++j;
        items.emplace_back(buf.data() + i, j - i);
        i = j + 1;
    }
    if (items.size() % 2 == 1 && items.back().empty()) items.pop_back(); // list terminator
    if (items.size() % 2 != 0) return;   // not the expected layout: leave it alone
    std::vector<std::wstring> kept;
    for (size_t i = 0; i < items.size(); i += 2) {
        bool ours = false;
        for (const auto& p : paths)
            ours = ours || (items[i + 1].empty() &&
                            _wcsicmp(items[i].c_str(), (L"\\?\?\\" + p).c_str()) == 0);
        if (!ours) {
            kept.push_back(items[i]);
            kept.push_back(items[i + 1]);
        }
    }
    if (kept.size() == items.size()) return;
    if (kept.empty()) {
        RegDeleteValueW(k, value);
    } else {
        std::wstring blob;
        for (const auto& item : kept) {
            blob += item;
            blob.push_back(L'\0');
        }
        blob.push_back(L'\0');
        RegSetValueExW(k, value, 0, REG_MULTI_SZ, (const BYTE*)blob.data(),
                       (DWORD)(blob.size() * sizeof(wchar_t)));
    }
    Logf(L"cancelled the pending post-uninstall deletion of the installed copy");
}

// schtasks fallback for when the Task Scheduler API refuses the definition.
static bool LegacyCreateTask(const std::wstring& exe, DWORD intervalMin)
{
    std::wstring tr = L"\\\"" + exe + L"\\\" --autostart --interval " +
                      std::to_wstring(intervalMin);
    std::wstring cmd = L"\"" + Sys32(L"schtasks.exe") +
                       L"\" /Create /F /TN " + kTaskName +
                       L" /SC ONLOGON /DELAY 0000:30 /RL HIGHEST /TR \"" + tr + L"\"";
    DWORD rc = RunProcess(cmd, false);
    if (rc != 0) Logf(L"schtasks /Create failed (exit %u)", rc);
    return rc == 0;
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
    if (!WaitInstanceExit(60000))
        Logf(L"warning: a previous instance is still shutting down — "
             L"the new task instance may exit at startup; re-run "
             L"'schtasks /Run /TN NetVigil' if the monitor is not running");

    std::wstring destDir = InstallDirPath();
    std::wstring destExe = InstalledExe();
    CancelPendingDeletes({ destExe, destDir });
    if (!IsRunningInstalledCopy()) {
        CreateDirectoryW(destDir.c_str(), nullptr);
        if (!InstallCopy(destExe)) {
            Logf(L"failed to copy exe to %ls (%u) — aborting install",
                 destExe.c_str(), GetLastError());
            return 1;
        }
        Logf(L"installed to %ls (admin-only location, so the elevated task "
             L"cannot be pointed at a user-writable binary)", destExe.c_str());
    }

    // The task belongs to whoever is signed in here — not to the admin whose
    // password approved the UAC prompt on a standard account.
    std::wstring account;
    std::wstring user = SessionUserSid(&account);
    std::wstring self = ProcessUserSid();
    if (!user.empty() && !self.empty() && _wcsicmp(user.c_str(), self.c_str()) != 0)
        Logf(L"installing for %ls, the account signed in on this desktop (not the "
             L"administrator who approved the prompt)", account.c_str());

    InterlockedExchange(&g_intervalMin, (LONG)intervalMin);
    std::wstring err;
    bool ok = RegisterStartupTask(destExe, AutostartArgs(), user, &err);
    if (!ok) {
        Logf(L"%ls — falling back to schtasks", err.c_str());
        ok = LegacyCreateTask(destExe, intervalMin);
    }
    if (!ok) return 1;
    Logf(L"startup task '%ls' installed: NetVigil starts at sign-in (elevated, also on "
         L"battery) and is relaunched within %u min if it ever stops", kTaskName, kRelaunchMin);
    SaveSetting(L"interval", std::to_wstring(intervalMin));
    ClearUserExit();

    // Start it now so no re-logon is needed — and make sure it really runs.
    if (!RunStartupTask(&err)) {
        Logf(L"%ls — trying schtasks /Run", err.c_str());
        RunProcess(L"\"" + Sys32(L"schtasks.exe") + L"\" /Run /TN " + kTaskName, false);
    }
    if (WaitInstanceStart(15000))
        Logf(L"monitor started (log: %ls)", g_logPath.c_str());
    else
        Logf(L"warning: the startup task has not started NetVigil yet — check task '%ls' in "
             L"Task Scheduler; it will also start at the next sign-in", kTaskName);
    return 0;
}

static int CmdUninstall()
{
    if (!g_elevated) {
        Logf(L"elevation required to remove the startup task — requesting UAC...");
        if (!RelaunchElevated(g_helper ? L"--uninstall --helper" : L"--uninstall")) {
            Logf(L"elevation was declined or the helper failed — "
                 L"run --uninstall from an elevated terminal (see %ls)",
                 g_logPath.c_str());
            return 1;
        }
        return 0;
    }
    SignalRunningInstance();
    WaitInstanceExit(60000); // a mid-repair instance can take a while to unwind
    DWORD rc = 0;
    StartupTaskInfo t;
    std::wstring err;
    if (QueryStartupTask(t, &err) && !t.exists) {
        Logf(L"startup task was not installed — nothing to remove");
    } else if (DeleteStartupTask(&err)) {
        Logf(L"startup task removed");
    } else {
        Logf(L"%ls — trying schtasks /Delete", err.c_str());
        std::wstring cmd = L"\"" + Sys32(L"schtasks.exe") + L"\" /Delete /F /TN " + kTaskName;
        rc = RunProcess(cmd, false);
        Logf(rc == 0 ? L"startup task removed" : L"schtasks /Delete failed (exit %u)", rc);
    }

    // Remove the installed copy (never the exe the user launched from
    // elsewhere). If we ARE that copy, it cannot delete itself — defer.
    std::wstring destDir = InstallDirPath();
    std::wstring destExe = InstalledExe();
    if (GetFileAttributesW(destExe.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (IsRunningInstalledCopy()) {
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
    if (g_helper) // temp helper copy: gone at the next reboot
        MoveFileExW(ExePath().c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return rc == 0 ? 0 : 1;
}

static int CmdStop()
{
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, kStopEventName);
    if (!ev) {
        Logf(L"no running NetVigil instance found in this session");
        return 1;
    }
    MarkUserExit(); // the startup task's relaunch trigger must not undo this
    SetEvent(ev);
    CloseHandle(ev);
    Logf(L"stop signal sent");
    return 0;
}

// ---------------------------------------------------------------- status/once

static int CmdStatus()
{
    LoadConfig(kDefaultIntervalMin);
    Logf(L"NetVigil status");
    Logf(L"  exe:       %ls", ExePath().c_str());
    Logf(L"  elevated:  %ls", g_elevated ? L"yes" : L"no");
    Logf(L"  log:       %ls", g_logPath.c_str());
    StartupTaskInfo t;
    std::wstring err;
    if (!QueryStartupTask(t, &err))
        Logf(L"  startup:   unknown (%ls)", err.c_str());
    else if (!t.exists)
        Logf(L"  startup:   not installed");
    else if (!t.readable)
        Logf(L"  startup:   installed");
    else
        Logf(L"  startup:   installed%ls, task format %d%ls — %ls %ls",
             t.enabled ? L"" : L" but DISABLED in Task Scheduler", t.format,
             t.format < nv::kTaskFormat ? L" (outdated: --install upgrades it)" : L"",
             t.command.empty() ? L"(command not readable)" : t.command.c_str(),
             t.arguments.c_str());

    ScopedWlan wl(OpenWlan(true));
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

    ProbeResult a = HttpProbe(L"www.msftconnecttest.com", L"/connecttest.txt",
                              false, "Microsoft Connect Test");
    Logf(L"  probe msftconnecttest: %ls", a.ok ? L"ok" : a.gotResponse
         ? L"unexpected response (portal?)" : L"no response");
    ProbeResult b = HttpProbe(L"www.gstatic.com", L"/generate_204", true, nullptr);
    Logf(L"  probe gstatic-204:     %ls", b.ok ? L"ok" : b.gotResponse
         ? L"unexpected response (portal?)" : L"no response");
    Logf(L"  probe ping 1.1.1.1:    %ls", PingProbe("1.1.1.1") ? L"ok" : L"failed");
    Logf(L"  probe ping 8.8.8.8:    %ls", PingProbe("8.8.8.8") ? L"ok" : L"failed");
    Logf(L"  probe tcp 1.1.1.1:443: %ls",
         TcpProbe(Ipv4("1.1.1.1"), 443, 3000) ? L"ok" : L"failed");
    if (a.ok || b.ok) {
        const ProbeResult& good = a.ok ? a : b;
        if (good.dateKnown)
            Logf(L"  clock:     %ls", llabs(good.skewSec) < 60
                 ? L"in step with internet time"
                 : (L"off by " + nv::DurationText(good.skewSec) +
                    (good.skewSec > 0 ? L" (ahead)" : L" (behind)")).c_str());
    }

    Connectivity c = Probe();
    nv::Observation o = Observe(c, 0, true);
    LogObservation(o);
    Logf(L"  verdict:   %ls", NetToStr(c.verdict));
    nv::Diagnosis d = nv::Diagnose(o);
    LogDiagnosis(d, o);
    if (!d.plan.empty()) Logf(L"  (--status only looks; --once would run this plan)");
    std::wstring stats = RepairStats();
    if (!stats.empty()) Logf(L"  repairs that worked here: %ls", stats.c_str());
    return 0;
}

static int CmdOnce()
{
    LoadConfig(kDefaultIntervalMin);
    Connectivity c = Probe();
    Logf(L"connectivity: %ls", NetToStr(c.verdict));
    if (c.verdict == Net::Online) {
        if (c.clockKnown && llabs(c.clockSkew) >= nv::kClockSkewLimitSec) RepairClock(c);
        return 0;
    }
    Net n = c.verdict;
    if (n == Net::Degraded) {
        n = RunRepairs(c, 0, 1);
        Logf(L"after the repair above IP: %ls", NetToStr(n));
        if (n == Net::Online || n == Net::Degraded) return 0;
        c = Probe();
    }
    n = RunRepairs(c, 1, 3);
    Logf(L"final state: %ls", NetToStr(n));
    return n == Net::Online || n == Net::Degraded ? 0 : 1;
}

static void PrintHelp()
{
    fputs(
        "NetVigil - connectivity watchdog\n"
        "\n"
        "  NetVigil.exe                 open the window (starts the watchdog if needed)\n"
        "  NetVigil.exe --tray          start hidden in the tray\n"
        "  NetVigil.exe --autostart     what the startup task runs: like --tray, but quiet\n"
        "                               if already running, and honours a tray Exit until\n"
        "                               the next sign-in\n"
        "  NetVigil.exe --interval N    check every N minutes (persisted in netvigil.ini)\n"
        "  NetVigil.exe --install       register + start the startup task (elevates)\n"
        "  NetVigil.exe --uninstall     stop the monitor and remove the task\n"
        "  NetVigil.exe --stop          signal a running monitor to exit\n"
        "  NetVigil.exe --status        adapters, probes, startup task, and a diagnosis\n"
        "                               with its repair plan (changes nothing)\n"
        "  NetVigil.exe --once          one check; diagnose and repair if needed; exit\n"
        "\n"
        "Closing the window keeps NetVigil running in the tray; exit from the tray\n"
        "menu. On a confirmed loss NetVigil first diagnoses the cause (ISP outage,\n"
        "router, IP config, DNS, proxy, VPN, Wi-Fi radio/association/password, adapter\n"
        "driver, services) and runs only the repairs that fit, cheapest first. Driver\n"
        "resets and service repairs need the elevated task (or an elevated shell).\n",
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
// log instead of the process just vanishing. The startup task's relaunch
// trigger brings the watchdog back.
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    Logf(L"FATAL: unhandled exception 0x%08X at %p — exiting",
         ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0,
         ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr);
    return EXCEPTION_EXECUTE_HANDLER;
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int)
{
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
    InitCore();
    BindConsole();
    InitLog();
    SetUnhandledExceptionFilter(CrashFilter);

    WSADATA wsa;
    int wsaRc = WSAStartup(MAKEWORD(2, 2), &wsa);
    g_wsaOk = (wsaRc == 0);
    if (!g_wsaOk)
        Logf(L"WSAStartup failed (%d) — continuing without the TCP and DNS probes", wsaRc);
    g_queryUnbiased = (PfnQueryUnbiased)(void*)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "QueryUnbiasedInterruptTime");
    g_elevated = IsElevated();
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    enum class Mode { Monitor, Once, Status, Install, Uninstall, Stop, Help };
    Mode mode = Mode::Monitor;
    bool tray = false, autostart = false;
    DWORD interval = kDefaultIntervalMin;

    for (int i = 1; argv && i < argc; ++i) {
        std::wstring a = Lower(argv[i]);
        if      (a == L"--tray")      tray = true;
        else if (a == L"--autostart") tray = autostart = true;
        else if (a == L"--helper")    g_helper = true;
        else if (a == L"--once")      mode = Mode::Once;
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
    default:              rc = StartMonitorGui(hInst, tray, autostart, interval); break;
    }

    if (g_wsaOk) WSACleanup();
    return rc;
}
