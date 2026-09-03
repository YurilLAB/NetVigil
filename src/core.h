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
};

MonitorState GetMonitorState();
void RequestCheckNow();
void SetPaused(bool paused);
void RequestStop();

DWORD GetIntervalMin();
void  SetIntervalMin(DWORD minutes);
bool  GetNotifications();
void  SetNotifications(bool on);

std::vector<KnownNetwork> GetKnownNetworks();
void SetNetworkMode(const std::wstring& profile, NetMode mode);
bool ConnectToNetwork(const std::wstring& profile);

// Log lines appended since `seq` (bounded ring); `seq` advances to the newest.
std::vector<std::wstring> GetLogSince(unsigned long long& seq);

// The worker posts `msg` to `hwnd` with one of these in wParam.
enum UiEvent : WPARAM { UiStateChanged = 1, UiLogAppended, UiRestored, UiFailed, UiStopped };
void SetUiNotify(HWND hwnd, UINT msg);

DWORD WINAPI MonitorThreadProc(LPVOID);

// gui.cpp
extern const wchar_t* const kWndClass;
UINT ShowWindowMessage();                 // registered cross-process "show window" message
int  RunGui(HINSTANCE hInst, bool startHidden);
