// update.cpp — NetVigil's self-updater.
//
// Trust model (the decisions themselves live in updatecore.cpp and are unit
// tested): an update is only ever applied if
//   * its manifest carries a valid ECDSA P-256 signature from the release key
//     compiled into this exe (update_pubkey.h),
//   * its version is strictly newer than the running one (no downgrades), and
//   * the downloaded exe has exactly the signed size and SHA-256.
// The channel (HTTPS, host allow-list, size caps) is defence in depth: even a
// fully hijacked connection cannot make this code run an unsigned binary.
//
// An update is applied only by an ELEVATED process, staged inside the
// admin-only install folder, re-verified from disk, and then installed by the
// staged exe itself through the same --install path a manual install uses
// (stop the old instance, replace the exe atomically, re-register the task,
// start it). A non-elevated window never touches the install folder: it asks
// for elevation and the elevated helper repeats the whole check itself.
#include "core.h"
#include "updatecore.h"

#include <winhttp.h>
#include <shellapi.h>

#include <ctime>
#include <string>
#include <vector>

#ifdef NETVIGIL_PUBKEY_HEADER            // test builds only (tools\test-update.ps1)
#include NETVIGIL_PUBKEY_HEADER
#else
#include "update_pubkey.h"
#endif

#pragma comment(lib, "winhttp.lib")

// ---------------------------------------------------------------- services
// Provided by main.cpp.
bool         CoreElevated();
bool         CoreInstalledCopyRunning();
std::wstring CoreInstallDir();
std::wstring CoreInstalledExe();
bool         CoreStopRequested();
int          CoreReadSettingInt(const wchar_t* key, int fallback);
void         CoreSaveSetting(const wchar_t* key, const std::wstring& value);
void         CoreNotify(UiEvent ev, LPARAM lp);
bool         CoreLaunchStagedInstaller(const std::wstring& exe);
bool         CoreLaunchElevated(const wchar_t* args);

namespace {

// The channel. Test builds (never the shipped one) point at a loopback server.
#ifdef NETVIGIL_UPDATE_TEST
const wchar_t* const kBase = NETVIGIL_UPDATE_TEST_BASE;    // e.g. L"http://127.0.0.1:8765"
#else
const wchar_t* const kBase = L"https://github.com/YurilLAB/NetVigil/releases";
#endif
const wchar_t* const kReleasesPage = L"https://github.com/YurilLAB/NetVigil/releases/latest";

const int kMaxRedirects = 5;

// ---------------------------------------------------------------- HTTP

struct HInet {
    HINTERNET h = nullptr;
    HInet() = default;
    explicit HInet(HINTERNET v) : h(v) {}
    HInet(const HInet&) = delete;
    HInet& operator=(const HInet&) = delete;
    ~HInet() { if (h) WinHttpCloseHandle(h); }
};

struct Url {
    bool https = true;
    std::wstring host, path;
    INTERNET_PORT port = 443;
};

bool CrackUrl(const std::wstring& u, Url& out)
{
    wchar_t host[256], path[2048], extra[2048];
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof uc;
    uc.lpszHostName = host;      uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;       uc.dwUrlPathLength = 2048;
    uc.lpszExtraInfo = extra;    uc.dwExtraInfoLength = 2048;
    if (!WinHttpCrackUrl(u.c_str(), 0, 0, &uc)) return false;
    if (uc.nScheme != INTERNET_SCHEME_HTTPS && uc.nScheme != INTERNET_SCHEME_HTTP) return false;
    out.https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    out.host.assign(host, uc.dwHostNameLength);
    out.path.assign(path, uc.dwUrlPathLength);
    out.path.append(extra, uc.dwExtraInfoLength);
    if (out.path.empty()) out.path = L"/";
    out.port = uc.nPort;
    return !out.host.empty();
}

bool EndsWith(const std::wstring& s, const std::wstring& suffix)
{
    return s.size() >= suffix.size() && _wcsicmp(s.c_str() + s.size() - suffix.size(), suffix.c_str()) == 0;
}

// Where a request — including every redirect — may go.
bool HostAllowed(const Url& u)
{
#ifdef NETVIGIL_UPDATE_TEST
    if (!u.https && _wcsicmp(u.host.c_str(), L"127.0.0.1") == 0) return true;
#endif
    if (!u.https || u.port != 443) return false;                       // TLS on the default port only
    return _wcsicmp(u.host.c_str(), L"github.com") == 0 ||
           EndsWith(u.host, L".githubusercontent.com");                // where release assets are served
}

// GET `url`, following at most kMaxRedirects hops by hand (each re-checked
// against the allow-list). At most `maxBytes` of body; anything else fails.
bool HttpGet(std::wstring url, size_t maxBytes, std::string& body, std::wstring& err)
{
    body.clear();
    HInet session(WinHttpOpen((L"NetVigil/" + nv::VersionToWide(nv::CurrentVersion())).c_str(),
                              WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.h) { err = L"WinHTTP could not start"; return false; }
    WinHttpSetTimeouts(session.h, 10000, 10000, 30000, 30000);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(session.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof protocols);

    for (int hop = 0; hop <= kMaxRedirects; ++hop) {
        Url u;
        if (!CrackUrl(url, u) || !HostAllowed(u)) {
            err = L"refused to contact a host outside the update allow-list";
            return false;
        }
        HInet conn(WinHttpConnect(session.h, u.host.c_str(), u.port, 0));
        if (!conn.h) { err = L"connect failed"; return false; }
        HInet req(WinHttpOpenRequest(conn.h, L"GET", u.path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, u.https ? WINHTTP_FLAG_SECURE : 0));
        if (!req.h) { err = L"request failed"; return false; }
        // No cookies, no credentials, and no automatic redirects. Certificate
        // errors are never overridden (WINHTTP_OPTION_SECURITY_FLAGS stays 0).
        DWORD off = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION;
        WinHttpSetOption(req.h, WINHTTP_OPTION_DISABLE_FEATURE, &off, sizeof off);

        if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(req.h, nullptr)) {
            err = L"no answer from the update server (error " + std::to_wstring(GetLastError()) + L")";
            return false;
        }
        DWORD status = 0, sz = sizeof status;
        WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            wchar_t loc[2048] = {};
            DWORD ln = sizeof loc;
            if (!WinHttpQueryHeaders(req.h, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                     loc, &ln, WINHTTP_NO_HEADER_INDEX)) {
                err = L"redirect without a target";
                return false;
            }
            url = loc;                       // absolute URLs only; a relative one fails CrackUrl
            continue;
        }
        if (status != 200) {
            err = L"the update server answered HTTP " + std::to_wstring(status);
            return false;
        }

        wchar_t lenText[32] = {};
        DWORD lenBytes = sizeof lenText;
        if (WinHttpQueryHeaders(req.h, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
                                lenText, &lenBytes, WINHTTP_NO_HEADER_INDEX) &&
            _wcstoui64(lenText, nullptr, 10) > maxBytes) {
            err = L"the download is larger than allowed";
            return false;
        }
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req.h, &avail)) { err = L"the download was interrupted"; return false; }
            if (avail == 0) return true;
            if (body.size() + avail > maxBytes) { err = L"the download is larger than allowed"; return false; }
            size_t at = body.size();
            body.resize(at + avail);
            DWORD got = 0;
            if (!WinHttpReadData(req.h, &body[at], avail, &got)) { err = L"the download was interrupted"; return false; }
            body.resize(at + got);
        }
    }
    err = L"too many redirects";
    return false;
}

// ---------------------------------------------------------------- check / apply

struct Check {
    enum Result { Failed, UpToDate, Available } result = Failed;
    nv::UpdateManifest manifest;
    std::wstring detail;
};

Check CheckForUpdate()
{
    Check c;
    std::string text;
    std::wstring err;
    if (!HttpGet(std::wstring(kBase) + L"/latest/download/manifest.txt", nv::kMaxManifestBytes + 1, text, err)) {
        c.detail = L"could not reach the update server: " + err;
        return c;
    }
    switch (nv::ParseSignedManifest(text, kUpdatePubKey, c.manifest)) {
    case nv::ManifestResult::Ok:
        break;
    case nv::ManifestResult::BadSignature:
        c.detail = L"the latest release is not signed with NetVigil's release key — ignored";
        return c;
    default:
        c.detail = L"the update information could not be read — ignored";
        return c;
    }
    c.result = nv::CompareVersion(c.manifest.version, nv::CurrentVersion()) > 0 ? Check::Available
                                                                                 : Check::UpToDate;
    return c;
}

bool WriteAll(const std::wstring& path, const std::string& data)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    bool ok = WriteFile(h, data.data(), (DWORD)data.size(), &w, nullptr) && w == data.size() &&
              FlushFileBuffers(h);
    CloseHandle(h);
    return ok;
}

bool ReadAll(const std::wstring& path, std::string& data)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    bool ok = GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && (unsigned long long)sz.QuadPart <= nv::kMaxUpdateExeBytes;
    if (ok) {
        data.resize((size_t)sz.QuadPart);
        DWORD got = 0;
        ok = ReadFile(h, &data[0], (DWORD)data.size(), &got, nullptr) && got == data.size();
    }
    CloseHandle(h);
    return ok;
}

// Where the verified update is staged: the admin-only install folder. (Test
// builds only stage into a scratch folder and never launch anything.)
std::wstring StagingDir()
{
#ifdef NETVIGIL_UPDATE_TEST_STAGEDIR
    return NETVIGIL_UPDATE_TEST_STAGEDIR;
#else
    return CoreInstallDir();
#endif
}

std::wstring StagedPath() { return StagingDir() + L"\\NetVigil-update.exe"; }

// Download, verify, stage in the admin-only install folder, verify AGAIN from
// disk, then let the staged exe install itself. Elevated callers only.
bool StageAndInstall(const nv::UpdateManifest& m, std::wstring& err)
{
    std::string exe;
    std::wstring url = std::wstring(kBase) + L"/download/v" + nv::VersionToWide(m.version) + L"/NetVigil.exe";
    if (!HttpGet(url, (size_t)m.size, exe, err)) return false;
    if (!nv::ExeMatchesManifest(exe.data(), exe.size(), m)) {
        err = L"the downloaded file does not match the signed size and SHA-256 — discarded";
        return false;
    }

    std::wstring dir = StagingDir(), staged = StagedPath();
    CreateDirectoryW(dir.c_str(), nullptr);            // admin-only under Program Files
    DeleteFileW(staged.c_str());
    if (!WriteAll(staged, exe)) {
        err = L"could not write the update into " + dir + L" (" + std::to_wstring(GetLastError()) + L")";
        DeleteFileW(staged.c_str());
        return false;
    }
    std::string back;
    if (!ReadAll(staged, back) || !nv::ExeMatchesManifest(back.data(), back.size(), m)) {
        err = L"the staged update did not verify after writing — discarded";
        DeleteFileW(staged.c_str());
        return false;
    }
#ifdef NETVIGIL_UPDATE_TEST
    Logf(L"TEST BUILD: staged and verified %ls — not launching the installer", staged.c_str());
    return true;
#else
    if (!CoreLaunchStagedInstaller(staged)) {
        err = L"could not start the installer for the update";
        return false;
    }
    return true;
#endif
}

// ---------------------------------------------------------------- state

CRITICAL_SECTION g_cs;
UpdaterState g_state;
volatile LONG g_auto = 1;
volatile LONG g_action = 0;          // 0 none, 1 check now, 2 check + install now
HANDLE g_thread = nullptr;
bool g_inited = false;

int SleepOrWake(DWORD ms);                              // below

bool InstalledCopyExists()
{
    return GetFileAttributesW(CoreInstalledExe().c_str()) != INVALID_FILE_ATTRIBUTES;
}

void Publish(UpdaterState::Phase phase, const std::wstring& latest, const std::wstring& detail,
             bool stamp)
{
    EnterCriticalSection(&g_cs);
    g_state.phase = phase;
    if (!latest.empty()) g_state.latest = latest;
    g_state.detail = detail;
    if (stamp) g_state.checkedAt = (long long)time(nullptr);
    g_state.canInstallHere = InstalledCopyExists();
    g_state.willAutoInstall = g_auto != 0 && CoreElevated() && CoreInstalledCopyRunning();
    LeaveCriticalSection(&g_cs);
    CoreNotify(UiUpdate, 0);
}

// One pass: check, and — when asked or when auto-update applies — install.
// Returns false when the check itself failed (the caller retries sooner).
bool RunOnce(bool installNow)
{
    DeleteFileW(StagedPath().c_str());      // leftover of an earlier update (fails while still running)
    Publish(UpdaterState::Checking, L"", L"", false);
    Check c = CheckForUpdate();
    if (c.result == Check::Failed) {
        Logf(L"update check failed: %ls", c.detail.c_str());
        Publish(UpdaterState::Failed, L"", c.detail, true);
        return false;
    }
    std::wstring latest = nv::VersionToWide(c.manifest.version);
    if (c.result == Check::UpToDate) {
        Logf(L"update check: NetVigil %ls is the latest version", nv::VersionToWide(nv::CurrentVersion()).c_str());
        Publish(UpdaterState::UpToDate, latest, L"", true);
        return true;
    }
    Logf(L"update check: version %ls is available (running %ls)", latest.c_str(),
         nv::VersionToWide(nv::CurrentVersion()).c_str());
    Publish(UpdaterState::Available, latest, L"", true);

    bool auto_ = g_auto != 0 && CoreElevated() && CoreInstalledCopyRunning();
    if (!installNow && !auto_) return true;             // tell the user; they decide
    if (!InstalledCopyExists()) return true;            // portable copy: nothing to update in place

#ifndef NETVIGIL_UPDATE_TEST
    if (!CoreElevated()) {                              // never apply from an unelevated process
        Logf(L"asking for administrator rights to install the update");
        if (CoreLaunchElevated(L"--update")) Publish(UpdaterState::Applying, latest, L"", false);
        else Publish(UpdaterState::Failed, latest, L"the administrator prompt was declined", false);
        return true;
    }
#endif
    Logf(L"installing NetVigil %ls", latest.c_str());
    Publish(UpdaterState::Applying, latest, L"", false);
    std::wstring err;
    if (!StageAndInstall(c.manifest, err)) {
        Logf(L"update failed: %ls", err.c_str());
        Publish(UpdaterState::Failed, latest, err, false);
        return false;
    }
#ifndef NETVIGIL_UPDATE_TEST
    // The installer stops this instance within seconds. Still here after three
    // minutes means it did not — say so instead of showing "installing" forever.
    if (SleepOrWake(180000) < 0) return true;           // stopping, as planned
    Logf(L"the installer did not restart NetVigil within 3 minutes — the update was not applied");
    Publish(UpdaterState::Failed, latest, L"the installer did not finish; it will be retried", false);
    return false;
#else
    return true;
#endif
}

// Sleep in short slices so a stop request or a "check now" is noticed quickly.
// Returns -1 when the process is stopping, else the requested action (0 = the
// timer simply ran out).
int SleepOrWake(DWORD ms)
{
    ULONGLONG end = GetTickCount64() + ms;
    for (;;) {
        if (CoreStopRequested()) return -1;
        LONG a = InterlockedExchange(&g_action, 0);
        if (a) return (int)a;
        if (GetTickCount64() >= end) return 0;
        Sleep(500);
    }
}

DWORD WINAPI UpdaterProc(LPVOID)
{
    DeleteFileW(StagedPath().c_str());                  // leftover of a finished update
    DWORD waitMs = 90 * 1000;                           // let the network settle after sign-in
    for (;;) {
        int action = SleepOrWake(waitMs);
        if (action < 0) return 0;
        if (action == 0) {
            // A scheduled check adds nothing while the connection is down or
            // being repaired — and would fail anyway.
            MonitorState ms = GetMonitorState();
            if (ms.remediating || (ms.haveStatus && ms.status != Net::Online)) {
                waitMs = 5 * 60 * 1000;
                continue;
            }
        }
        bool ok = RunOnce(action == 2);
        waitMs = ok ? 24u * 3600 * 1000 : 3600u * 1000;
    }
}

} // namespace

// ---------------------------------------------------------------- public API

const wchar_t* AppVersion()
{
    static const std::wstring v = nv::VersionToWide(nv::CurrentVersion());
    return v.c_str();
}

UpdaterState GetUpdateState()
{
    if (!g_inited) return UpdaterState{};
    EnterCriticalSection(&g_cs);
    UpdaterState s = g_state;
    LeaveCriticalSection(&g_cs);
    return s;
}

bool GetAutoUpdate() { return g_auto != 0; }

void SetAutoUpdate(bool on)
{
    InterlockedExchange(&g_auto, on ? 1 : 0);
    CoreSaveSetting(L"autoUpdate", on ? L"1" : L"0");
    Logf(on ? L"automatic updates enabled" : L"automatic updates disabled");
    if (!g_inited) return;
    UpdaterState s = GetUpdateState();               // same phase, refreshed flags
    Publish(s.phase, L"", s.detail, false);
}

void RequestUpdateCheck()
{
    InterlockedExchange(&g_action, 1);
}

bool RequestUpdateInstall()
{
    if (!g_inited) return false;
    UpdaterState s = GetUpdateState();
    if (s.phase != UpdaterState::Available || !s.canInstallHere) return false;
    InterlockedExchange(&g_action, 2);
    return true;
}

void OpenReleasesPage()
{
    wchar_t win[MAX_PATH] = {};
    GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring explorer = std::wstring(win) + L"\\explorer.exe";     // browser must not inherit admin rights
    std::wstring arg = std::wstring(L"\"") + kReleasesPage + L"\"";
    ShellExecuteW(nullptr, L"open", explorer.c_str(), arg.c_str(), nullptr, SW_SHOWNORMAL);
}

void StartUpdater()
{
    if (g_inited) return;
    InitializeCriticalSection(&g_cs);
    g_inited = true;
    InterlockedExchange(&g_auto, CoreReadSettingInt(L"autoUpdate", 1) ? 1 : 0);
    g_state.phase = UpdaterState::Idle;
    g_state.canInstallHere = InstalledCopyExists();
    g_state.willAutoInstall = g_auto != 0 && CoreElevated() && CoreInstalledCopyRunning();
    g_thread = CreateThread(nullptr, 0, UpdaterProc, nullptr, 0, nullptr);
    if (g_thread) SetThreadPriority(g_thread, THREAD_PRIORITY_BELOW_NORMAL);
}

void StopUpdater()
{
    if (!g_thread) return;
    // The loop notices the stop request within a second; a download in flight
    // is abandoned at process exit (nothing is launched until a complete,
    // verified file has been staged).
    WaitForSingleObject(g_thread, 3000);
    CloseHandle(g_thread);
    g_thread = nullptr;
}

// --check-update: look, report, change nothing. Exit code 0 = up to date,
// 10 = an update is available, 1 = the check failed.
int CmdCheckUpdate()
{
    Check c = CheckForUpdate();
    Logf(L"running:  %ls", AppVersion());
    if (c.result == Check::Failed) {
        Logf(L"check failed: %ls", c.detail.c_str());
        return 1;
    }
    Logf(L"latest:   %ls (signature verified)", nv::VersionToWide(c.manifest.version).c_str());
    if (c.result == Check::UpToDate) {
        Logf(L"NetVigil is up to date");
        return 0;
    }
    Logf(L"an update is available — run --update (or use Settings) to install it");
    return 10;
}

// --update: the elevated installer of an update. Everything is checked again
// here; nothing the unelevated caller saw is trusted.
int CmdUpdate()
{
#ifndef NETVIGIL_UPDATE_TEST
    if (!CoreElevated()) {
        Logf(L"administrator rights are needed to install an update — requesting UAC...");
        return CoreLaunchElevated(L"--update") ? 0 : 1;
    }
#endif
    Check c = CheckForUpdate();
    if (c.result == Check::Failed) {
        Logf(L"update failed: %ls", c.detail.c_str());
        return 1;
    }
    if (c.result == Check::UpToDate) {
        Logf(L"NetVigil %ls is already the latest version", AppVersion());
        return 0;
    }
    std::wstring err;
    Logf(L"installing NetVigil %ls", nv::VersionToWide(c.manifest.version).c_str());
    if (!StageAndInstall(c.manifest, err)) {
        Logf(L"update failed: %ls", err.c_str());
        return 1;
    }
    return 0;
}
