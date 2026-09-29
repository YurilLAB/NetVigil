// core.h — the surface shared between the watchdog core (main.cpp) and the
// tray/window front end (gui.cpp). Everything here is safe to call from the
// UI thread; the core posts UiEvent notifications back rather than calling in.
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>

enum class Net { Online, Degraded, Portal, Offline };
const wchar_t* NetToStr(Net n);

void Logf(const wchar_t* fmt, ...);
const std::wstring& LogPath();

// Per-network auto-connect policy chosen by the user.
enum class NetMode { Allowed, Preferred, Never };

struct KnownNetwork {
    std::wstring profile;        // WLAN profile name (what we connect by)
    std::wstring ssid;
    NetMode mode = NetMode::Allowed;
    long long lastSeen = 0;      // unix seconds, 0 = never connected
    int connects = 0;
    bool inRange = false;
    bool connected = false;
    ULONG signal = 0;            // 0..100 when in range
};

struct MonitorState {
    bool haveStatus = false;     // false until the first check completes
    Net  status = Net::Offline;
    bool paused = false;
    bool remediating = false;
    bool stopping = false;
    bool elevated = false;
    std::wstring ssid;           // current Wi-Fi network, if any
    std::wstring iface;          // adapter it is on
    std::wstring lastAction;
    ULONGLONG lastCheck = 0;     // GetTickCount64() stamps, 0 = none yet
    ULONGLONG nextCheck = 0;
    ULONGLONG offlineSince = 0;
    int failStreak = 0;
    // Latest diagnosis (nv::Fault as int; 0 = none / healthy).
    int fault = 0;
    bool faultNeedsUser = false; // only the user can finish this fix
    std::wstring diagnosis;      // short fault name, "ISP / router outage"
    std::wstring diagnosisDetail;// one-line explanation
    std::wstring lastRepair;     // what fixed the last outage
    long long lastRepairAt = 0;  // unix seconds
    int windowsLevel = -1;       // Windows' own connectivity hint, -1 = unknown
};

MonitorState GetMonitorState();
void RequestCheckNow();
void NotifyResumed();                     // the machine woke from sleep
void SetPaused(bool paused);
void RequestStop(bool byUser = false);    // byUser: don't auto-relaunch this session

DWORD GetIntervalMin();
void  SetIntervalMin(DWORD minutes);
bool  GetNotifications();
void  SetNotifications(bool on);
bool  GetFailover();                      // may switch Wi-Fi networks in an ISP outage
void  SetFailover(bool on);

std::vector<KnownNetwork> GetKnownNetworks();
void SetNetworkMode(const std::wstring& profile, NetMode mode);
bool ConnectToNetwork(const std::wstring& profile);

// Windows' own captive-portal trigger: opens the network's sign-in page.
extern const wchar_t* const kPortalUrl;

// Startup integration (Settings page). Both launchers hand the work to an
// elevated helper process which stops THIS instance as part of the job.
enum class StartupState {
    NotInstalled,
    Installed,                // this exe is the installed copy the task runs
    OtherCopy,                // task runs a different build than this window
    Disabled,                 // task switched off in Task Scheduler
    Outdated,                 // pre-format-2 task (72 h limit, no battery start)
    Broken,                   // task points at a missing file
    Unknown,                  // Task Scheduler could not be asked
};
struct StartupStatus {
    StartupState state = StartupState::Unknown;
    std::wstring detail;
};
StartupStatus GetStartupStatus();
bool LaunchInstaller();
bool LaunchUninstaller();
const std::wstring& DataDir();            // %LOCALAPPDATA%\NetVigil

// Log lines appended since `seq` (bounded ring); `seq` advances to the newest.
std::vector<std::wstring> GetLogSince(unsigned long long& seq);

// The worker posts `msg` to `hwnd` with one of these in wParam.
// UiAdvice: lParam = nv::Fault the user should hear about (see MonitorState).
enum UiEvent : WPARAM { UiStateChanged = 1, UiLogAppended, UiRestored, UiFailed, UiStopped,
                        UiAdvice, UiUpdate };
void SetUiNotify(HWND hwnd, UINT msg);

// ---- self-update (update.cpp). Everything here is safe to call from the UI thread;
// the network work happens on the updater's own thread and posts UiUpdate.
struct UpdaterState {
    enum Phase { Idle, Checking, UpToDate, Available, Applying, Failed };
    Phase phase = Idle;
    std::wstring latest;             // newest signed version seen, "1.2.3"
    std::wstring detail;             // why the last check/install failed
    long long checkedAt = 0;         // unix seconds of the last completed check, 0 = never
    bool canInstallHere = false;     // an installed copy exists, so it can be updated in place
    bool willAutoInstall = false;    // automatic updates are on AND this process may apply them
};
const wchar_t* AppVersion();         // "1.0.0"
UpdaterState GetUpdateState();
void RequestUpdateCheck();           // check now, in the background
bool RequestUpdateInstall();         // install the available update (UAC if needed)
bool GetAutoUpdate();
void SetAutoUpdate(bool on);
void OpenReleasesPage();             // for copies that cannot be updated in place
void StartUpdater();                 // called by the core once settings are loaded
void StopUpdater();
int  CmdCheckUpdate();               // --check-update
int  CmdUpdate();                    // --update

DWORD WINAPI MonitorThreadProc(LPVOID);

// gui.cpp
extern const wchar_t* const kWndClass;
UINT ShowWindowMessage();                 // registered cross-process "show window" message
int  RunGui(HINSTANCE hInst, bool startHidden);
