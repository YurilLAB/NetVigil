// gui.cpp — NetVigil's small resident window + tray icon.
//
// Plain Win32, no resources: icons are drawn at runtime, controls are created
// by hand. Two tabs — Status (network list, actions, log tail) and a very
// small Settings page. The window is a view over the core's state; the
// watchdog itself runs on a worker thread and the UI thread sleeps in
// GetMessage. Closing the window hides it to the tray — only the tray menu's
// Exit (or Uninstall) stops the watchdog.

#include "core.h"
#include <commctrl.h>
#include <shellapi.h>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

const wchar_t* const kWndClass = L"NetVigil.MainWindow";

UINT ShowWindowMessage()
{
    static UINT m = RegisterWindowMessageW(L"NetVigil.ShowWindow");
    return m;
}

namespace {

const UINT WM_TRAY = WM_APP + 1;
const UINT WM_CORE = WM_APP + 2;   // wParam = UiEvent
const UINT_PTR ID_TIMER_UI = 1, ID_TIMER_RECHECK = 2;

enum : int {
    ID_TABS = 100,
    // Status page
    ID_STATUS, ID_DETAIL, ID_LBL_NETS, ID_LIST, ID_BTN_PREF, ID_BTN_ALLOW, ID_BTN_NEVER,
    ID_BTN_CONNECT, ID_BTN_CHECK, ID_BTN_PAUSE, ID_LBL_LOG, ID_LOG,
    // Settings page
    ID_LBL_INT, ID_EDIT_INTERVAL, ID_LBL_MIN, ID_BTN_APPLY, ID_CHK_NOTIFY,
    ID_LBL_STARTUP, ID_STARTUP_STATE, ID_BTN_INSTALL, ID_LBL_FILES, ID_FILES_PATH,
    ID_BTN_LOGDIR, ID_LBL_UNINST, ID_UNINST_INFO, ID_BTN_UNINSTALL, ID_ABOUT,
    // tray menu
    TC_OPEN = 200, TC_CHECK, TC_PAUSE, TC_EXIT,
};

enum Page { PageStatus = 0, PageSettings = 1 };
enum IconKind { IconOnline, IconOffline, IconWarn, IconPaused, IconCount };

struct Gui {
    HINSTANCE hInst = nullptr;
    HWND hwnd = nullptr, tabs = nullptr, status = nullptr, detail = nullptr,
         list = nullptr, log = nullptr, interval = nullptr, chkNotify = nullptr,
         btnPause = nullptr, startupState = nullptr, btnInstall = nullptr;
    std::vector<HWND> pages[2];
    int page = PageStatus;
    HFONT font = nullptr, fontBold = nullptr, fontBig = nullptr, fontMono = nullptr;
    HICON icons[IconCount] = {};
    IconKind statusIcon = IconWarn;   // colour of the status line
    IconKind trayIcon = IconWarn;     // what the tray currently shows
    NOTIFYICONDATAW nid{};
    std::wstring lastTip, exitNote;
    HANDLE worker = nullptr;
    UINT taskbarCreated = 0;
    unsigned long long logSeq = 0;
    ULONGLONG listedCheck = 0;        // lastCheck the network list was built for
    std::vector<KnownNetwork> rows;
    int dpi = 96;
    bool visible = false, trayAdded = false, hideHintShown = false;
} g;

int S(int v) { return MulDiv(v, g.dpi, 96); }

// SetWindowText repaints even when nothing changed; the status line is
// refreshed every second, so skip the no-op case.
void SetTextIfChanged(HWND h, const std::wstring& text)
{
    wchar_t cur[512];
    int n = GetWindowTextW(h, cur, 512);
    if (n == 0 && text.empty()) return;
    if (n > 0 && n < 511 && text.compare(cur) == 0) return;
    SetWindowTextW(h, text.c_str());
}

// ---------------------------------------------------------------- drawing

HICON MakeDotIcon(COLORREF fill, int size)
{
    HDC screen = GetDC(nullptr);
    HDC dc = CreateCompatibleDC(screen);
    HBITMAP color = CreateCompatibleBitmap(screen, size, size);
    HBITMAP mask  = CreateBitmap(size, size, 1, 1, nullptr);
    ReleaseDC(nullptr, screen);
    if (!dc || !color || !mask) {
        if (dc) DeleteDC(dc);
        if (color) DeleteObject(color);
        if (mask) DeleteObject(mask);
        return LoadIconW(nullptr, IDI_APPLICATION);
    }
    RECT r{ 0, 0, size, size };
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1,
                         RGB(GetRValue(fill) / 2, GetGValue(fill) / 2, GetBValue(fill) / 2));

    HGDIOBJ oldBmp = SelectObject(dc, color);
    FillRect(dc, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    Ellipse(dc, 1, 1, size - 1, size - 1);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);

    SelectObject(dc, mask);                                  // 1 = transparent
    FillRect(dc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));
    SelectObject(dc, GetStockObject(BLACK_BRUSH));
    SelectObject(dc, GetStockObject(BLACK_PEN));
    Ellipse(dc, 1, 1, size - 1, size - 1);
    SelectObject(dc, oldBmp);

    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.hbmMask = mask;
    ii.hbmColor = color;
    HICON icon = CreateIconIndirect(&ii);
    DeleteObject(brush);
    DeleteObject(pen);
    DeleteObject(color);
    DeleteObject(mask);
    DeleteDC(dc);
    return icon ? icon : LoadIconW(nullptr, IDI_APPLICATION);
}

COLORREF StatusColor(IconKind k)
{
    switch (k) {
    case IconOnline:  return RGB(24, 128, 56);
    case IconOffline: return RGB(190, 32, 32);
    case IconWarn:    return RGB(176, 112, 0);
    default:          return RGB(110, 110, 110);
    }
}

void CreateFonts()
{
    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof ncm;
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
    LOGFONTW lf = ncm.lfMessageFont;
    g.font = CreateFontIndirectW(&lf);
    LOGFONTW bold = lf;
    bold.lfWeight = FW_SEMIBOLD;
    g.fontBold = CreateFontIndirectW(&bold);
    LOGFONTW big = lf;
    big.lfHeight = MulDiv(lf.lfHeight, 15, 10);
    big.lfWeight = FW_SEMIBOLD;
    g.fontBig = CreateFontIndirectW(&big);
    LOGFONTW mono = lf;
    wcscpy_s(mono.lfFaceName, L"Consolas");
    mono.lfHeight = MulDiv(lf.lfHeight, 9, 10);
    g.fontMono = CreateFontIndirectW(&mono);
}

// ---------------------------------------------------------------- formatting

std::wstring DurStr(ULONGLONG ms)
{
    ULONGLONG s = ms / 1000;
    wchar_t buf[32];
    if (s < 3600) swprintf_s(buf, L"%llu:%02llu", s / 60, s % 60);
    else          swprintf_s(buf, L"%lluh %02llum", s / 3600, (s % 3600) / 60);
    return buf;
}

std::wstring TimeStr(long long unix)
{
    if (unix <= 0) return L"—";
    __time64_t t = unix;
    tm lt{};
    if (_localtime64_s(&lt, &t) != 0) return L"—";
    wchar_t buf[40];
    wcsftime(buf, 40, L"%Y-%m-%d %H:%M", &lt);
    return buf;
}

const wchar_t* ModeText(NetMode m)
{
    switch (m) {
    case NetMode::Preferred: return L"Preferred ★";
    case NetMode::Never:     return L"Never";
    default:                 return L"Allowed";
    }
}

// ---------------------------------------------------------------- tray

void AddTray()
{
    g.nid = {};
    g.nid.cbSize = sizeof g.nid;
    g.nid.hWnd = g.hwnd;
    g.nid.uID = 1;
    g.nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    g.nid.uCallbackMessage = WM_TRAY;
    g.nid.hIcon = g.icons[g.trayIcon];
    wcscpy_s(g.nid.szTip, L"NetVigil");
    g.trayAdded = Shell_NotifyIconW(NIM_ADD, &g.nid) != FALSE;
    if (!g.trayAdded) {
        Logf(L"tray icon could not be added (%u)", GetLastError());
        return;
    }
    g.nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g.nid);
    g.lastTip.clear(); // force the next SetTray to apply
}

void RemoveTray()
{
    if (!g.trayAdded) return;
    Shell_NotifyIconW(NIM_DELETE, &g.nid);
    g.trayAdded = false;
}

void SetTray(IconKind k, const std::wstring& tip)
{
    if (!g.trayAdded) return;
    if (k == g.trayIcon && tip == g.lastTip) return; // no churn while idle
    g.trayIcon = k;
    g.lastTip = tip;
    g.nid.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    g.nid.hIcon = g.icons[k];
    wcsncpy_s(g.nid.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g.nid);
}

void Balloon(const std::wstring& title, const std::wstring& text, bool force = false)
{
    if (!g.trayAdded || (!force && !GetNotifications())) return;
    g.nid.uFlags = NIF_INFO;
    wcsncpy_s(g.nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(g.nid.szInfo, text.c_str(), _TRUNCATE);
    g.nid.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
    Shell_NotifyIconW(NIM_MODIFY, &g.nid);
}

void TrayMenu()
{
    HMENU m = CreatePopupMenu();
    if (!m) return;
    AppendMenuW(m, MF_STRING, TC_OPEN, L"Open NetVigil");
    AppendMenuW(m, MF_STRING, TC_CHECK, L"Check connection now");
    AppendMenuW(m, MF_STRING, TC_PAUSE,
                GetMonitorState().paused ? L"Resume monitoring" : L"Pause monitoring");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, TC_EXIT, L"Exit (stop the watchdog)");
    SetMenuDefaultItem(m, TC_OPEN, FALSE);
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g.hwnd); // required for the menu to dismiss properly
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g.hwnd, nullptr);
    PostMessageW(g.hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

// ---------------------------------------------------------------- view updates

std::wstring SelectedProfile()
{
    int i = ListView_GetNextItem(g.list, -1, LVNI_SELECTED);
    if (i < 0 || (size_t)i >= g.rows.size()) return L"";
    return g.rows[(size_t)i].profile;
}

void RefreshNetworks()
{
    g.listedCheck = GetMonitorState().lastCheck;
    std::wstring selected = SelectedProfile();
    g.rows = GetKnownNetworks();
    SendMessageW(g.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g.list);
    for (size_t i = 0; i < g.rows.size(); ++i) {
        const KnownNetwork& n = g.rows[i];
        LVITEMW it{};
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = const_cast<LPWSTR>(n.profile.c_str());
        ListView_InsertItem(g.list, &it);
        ListView_SetItemText(g.list, (int)i, 1, const_cast<LPWSTR>(ModeText(n.mode)));
        std::wstring sig = n.connected ? L"connected"
                         : n.inRange   ? std::to_wstring(n.signal) + L"%"
                                       : L"not in range";
        ListView_SetItemText(g.list, (int)i, 2, const_cast<LPWSTR>(sig.c_str()));
        std::wstring last = TimeStr(n.lastSeen);
        if (n.connects > 0) last += L"  (" + std::to_wstring(n.connects) + L"×)";
        ListView_SetItemText(g.list, (int)i, 3, const_cast<LPWSTR>(last.c_str()));
        if (!selected.empty() && n.profile == selected)
            ListView_SetItemState(g.list, (int)i, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
    }
    SendMessageW(g.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.list, nullptr, TRUE);
}

void AppendNewLog()
{
    std::vector<std::wstring> lines = GetLogSince(g.logSeq);
    if (lines.empty()) return;
    std::wstring chunk;
    for (const auto& l : lines) {
        chunk += l;
        chunk += L"\r\n";
    }
    int len = GetWindowTextLengthW(g.log);
    if (len > 60000) {                       // keep the edit control light
        SetWindowTextW(g.log, L"");
        len = 0;
    }
    SendMessageW(g.log, EM_SETSEL, len, len);
    SendMessageW(g.log, EM_REPLACESEL, FALSE, (LPARAM)chunk.c_str());
    SendMessageW(g.log, EM_SCROLLCARET, 0, 0);
}

// The 1 s countdown timer only runs while the Status page is on screen.
void SyncTimer()
{
    if (g.visible && g.page == PageStatus) SetTimer(g.hwnd, ID_TIMER_UI, 1000, nullptr);
    else                                   KillTimer(g.hwnd, ID_TIMER_UI);
}

void SyncSettings()
{
    SetTextIfChanged(g.interval, std::to_wstring(GetIntervalMin()));
    CheckDlgButton(g.hwnd, ID_CHK_NOTIFY, GetNotifications() ? BST_CHECKED : BST_UNCHECKED);
}

// Spawns schtasks, so only called when the Settings page is shown.
void SyncStartupState()
{
    bool installed = IsInstalledAtStartup();
    bool thisCopy  = IsRunningInstalledCopy();
    SetTextIfChanged(g.startupState, installed
        ? (thisCopy
            ? L"Installed — NetVigil starts hidden in the tray at logon, elevated so it "
              L"can reset the Wi-Fi driver."
            : L"Installed — but this window is a different build than the installed "
              L"copy. Update it to run this version at logon.")
        : L"Not installed — NetVigil only runs while you start it yourself, and "
          L"without elevation it cannot reset the driver.");
    SetTextIfChanged(g.btnInstall, !installed ? L"Install at startup…"
                                  : thisCopy  ? L"Installed at startup"
                                              : L"Update installed copy…");
    EnableWindow(g.btnInstall, !installed || !thisCopy);
}

void UpdateStatus(const MonitorState& st)
{
    std::wstring head;
    IconKind ic = IconWarn;
    if (!g.exitNote.empty()) {
        head = g.exitNote;
        ic = IconPaused;
    } else if (st.stopping) {
        head = L"Stopping…";
        ic = IconPaused;
    } else if (st.paused) {
        head = L"Monitoring paused";
        ic = IconPaused;
    } else if (!st.haveStatus) {
        head = L"Checking the connection…";
    } else {
        switch (st.status) {
        case Net::Online:   head = L"Online"; ic = IconOnline; break;
        case Net::Degraded: head = L"Degraded — pings work, HTTP/DNS failing"; break;
        case Net::Portal:   head = L"Captive portal — sign in via your browser"; break;
        default:
            head = st.remediating ? L"Offline — " + st.lastAction : L"Offline";
            ic = IconOffline;
            break;
        }
        if (!st.ssid.empty()) head += L"   ·   " + st.ssid;
    }

    std::wstring det;
    ULONGLONG now = GetTickCount64();
    if (st.paused) {
        det = L"Checks are paused — press Resume to continue.";
    } else {
        if (st.lastCheck)
            det += L"last check " + DurStr(now - st.lastCheck) + L" ago";
        if (st.nextCheck > now && !st.remediating)
            det += (det.empty() ? L"" : L"  ·  ") + std::wstring(L"next in ") +
                   DurStr(st.nextCheck - now);
        if (st.offlineSince)
            det += (det.empty() ? L"" : L"  ·  ") + std::wstring(L"offline for ") +
                   DurStr(now - st.offlineSince);
        if (!st.iface.empty())
            det += (det.empty() ? L"" : L"  ·  ") + st.iface;
        if (!st.elevated)
            det += (det.empty() ? L"" : L"  ·  ") +
                   std::wstring(L"not elevated: driver reset unavailable (see Settings)");
    }
    SetTextIfChanged(g.status, head);
    SetTextIfChanged(g.detail, det);
    SetTextIfChanged(g.btnPause, st.paused ? L"Resume" : L"Pause");
    if (ic != g.statusIcon) {
        g.statusIcon = ic;
        InvalidateRect(g.status, nullptr, TRUE);
    }
    SetTray(ic, L"NetVigil — " + head);
}

void ShowPage(int page)
{
    g.page = page;
    TabCtrl_SetCurSel(g.tabs, page);
    for (int p = 0; p < 2; ++p)
        for (HWND h : g.pages[p]) ShowWindow(h, p == page ? SW_SHOW : SW_HIDE);
    if (page == PageSettings) {
        SyncSettings();
        SyncStartupState();
    } else {
        RefreshNetworks();
        AppendNewLog();
    }
    SyncTimer();
}

void ShowMain()
{
    g.visible = true;
    ShowWindow(g.hwnd, IsIconic(g.hwnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g.hwnd);
    ShowPage(g.page);
    UpdateStatus(GetMonitorState());
}

void HideMain()
{
    g.visible = false;
    SyncTimer();
    ShowWindow(g.hwnd, SW_HIDE);
    if (!g.hideHintShown) {
        g.hideHintShown = true;
        Balloon(L"NetVigil is still running",
                L"The watchdog keeps monitoring in the background. "
                L"Right-click the tray icon to exit.", true);
    }
}

// ---------------------------------------------------------------- controls

HWND Mk(const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h,
        int id, DWORD ex = 0, HFONT font = nullptr)
{
    HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | style,
                             S(x), S(y), S(w), S(h), g.hwnd, (HMENU)(INT_PTR)id,
                             g.hInst, nullptr);
    if (c) SendMessageW(c, WM_SETFONT, (WPARAM)(font ? font : g.font), TRUE);
    return c;
}

HWND Add(int page, HWND h)
{
    g.pages[page].push_back(h);
    return h;
}

void BuildControls()
{
    g.tabs = Mk(WC_TABCONTROLW, L"", WS_TABSTOP, 8, 8, 584, 464, ID_TABS);
    TCITEMW ti{};
    ti.mask = TCIF_TEXT;
    ti.pszText = const_cast<LPWSTR>(L"Status");
    TabCtrl_InsertItem(g.tabs, 0, &ti);
    ti.pszText = const_cast<LPWSTR>(L"Settings");
    TabCtrl_InsertItem(g.tabs, 1, &ti);

    // Page origin and size (96-dpi units) from the tab's display area.
    RECT d{};
    GetClientRect(g.tabs, &d);
    TabCtrl_AdjustRect(g.tabs, FALSE, &d);
    const int ox = 8 + MulDiv(d.left, 96, g.dpi) + 6;
    const int oy = 8 + MulDiv(d.top, 96, g.dpi) + 6;
    const int pw = MulDiv(d.right - d.left, 96, g.dpi) - 12;
    const int ph = MulDiv(d.bottom - d.top, 96, g.dpi) - 12;
    const DWORD btn = BS_PUSHBUTTON | WS_TABSTOP;

    // ---- Status page
    g.status = Add(PageStatus, Mk(L"STATIC", L"Starting…",
                                  SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                                  ox, oy, pw, 26, ID_STATUS, 0, g.fontBig));
    g.detail = Add(PageStatus, Mk(L"STATIC", L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                                  ox, oy + 30, pw, 18, ID_DETAIL));
    Add(PageStatus, Mk(L"STATIC", L"Networks — choose what NetVigil auto-connects to:",
                       SS_LEFT | SS_NOPREFIX, ox, oy + 56, pw, 16, ID_LBL_NETS));
    g.list = Add(PageStatus, Mk(WC_LISTVIEWW, L"",
                                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS |
                                LVS_NOSORTHEADER | WS_TABSTOP,
                                ox, oy + 74, pw, 170, ID_LIST, WS_EX_CLIENTEDGE));
    ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    const struct { const wchar_t* name; int width; } cols[] = {
        { L"Network", 208 }, { L"Auto-connect", 96 }, { L"Signal", 92 }, { L"Last connected", 150 },
    };
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<LPWSTR>(cols[i].name);
        col.cx = S(cols[i].width);
        ListView_InsertColumn(g.list, i, &col);
    }
    const int by = oy + 252;
    Add(PageStatus, Mk(L"BUTTON", L"Set preferred", btn, ox, by, 104, 26, ID_BTN_PREF));
    Add(PageStatus, Mk(L"BUTTON", L"Allow", btn, ox + 110, by, 70, 26, ID_BTN_ALLOW));
    Add(PageStatus, Mk(L"BUTTON", L"Never connect", btn, ox + 186, by, 104, 26, ID_BTN_NEVER));
    Add(PageStatus, Mk(L"BUTTON", L"Connect now", btn, ox + 296, by, 96, 26, ID_BTN_CONNECT));
    Add(PageStatus, Mk(L"BUTTON", L"Check now", btn, ox + pw - 162, by, 84, 26, ID_BTN_CHECK));
    g.btnPause = Add(PageStatus, Mk(L"BUTTON", L"Pause", btn, ox + pw - 72, by, 72, 26,
                                    ID_BTN_PAUSE));
    Add(PageStatus, Mk(L"STATIC", L"Recent activity:", SS_LEFT, ox, oy + 288, 200, 16,
                       ID_LBL_LOG));
    g.log = Add(PageStatus, Mk(L"EDIT", L"",
                               ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                               ox, oy + 306, pw, ph - 306, ID_LOG, WS_EX_CLIENTEDGE,
                               g.fontMono));

    // ---- Settings page (deliberately small)
    int y = oy + 4;
    Add(PageSettings, Mk(L"STATIC", L"Check the connection every", SS_LEFT,
                         ox, y + 4, 170, 18, ID_LBL_INT));
    g.interval = Add(PageSettings, Mk(L"EDIT", L"10", ES_NUMBER | ES_RIGHT | WS_TABSTOP,
                                      ox + 174, y, 44, 24, ID_EDIT_INTERVAL, WS_EX_CLIENTEDGE));
    SendMessageW(g.interval, EM_LIMITTEXT, 4, 0);
    Add(PageSettings, Mk(L"STATIC", L"minutes", SS_LEFT, ox + 224, y + 4, 56, 18, ID_LBL_MIN));
    Add(PageSettings, Mk(L"BUTTON", L"Apply", btn, ox + 286, y - 1, 64, 26, ID_BTN_APPLY));
    y += 40;
    g.chkNotify = Add(PageSettings, Mk(L"BUTTON",
                                       L"Show tray notifications when the connection drops or comes back",
                                       BS_AUTOCHECKBOX | WS_TABSTOP, ox, y, pw, 22, ID_CHK_NOTIFY));
    y += 44;
    Add(PageSettings, Mk(L"STATIC", L"Start with Windows", SS_LEFT, ox, y, pw, 18,
                         ID_LBL_STARTUP, 0, g.fontBold));
    g.startupState = Add(PageSettings, Mk(L"STATIC", L"", SS_LEFT | SS_NOPREFIX,
                                          ox, y + 22, pw, 34, ID_STARTUP_STATE));
    g.btnInstall = Add(PageSettings, Mk(L"BUTTON", L"Install at startup…", btn,
                                        ox, y + 60, 150, 26, ID_BTN_INSTALL));
    y += 104;
    Add(PageSettings, Mk(L"STATIC", L"Settings and log", SS_LEFT, ox, y, pw, 18,
                         ID_LBL_FILES, 0, g.fontBold));
    Add(PageSettings, Mk(L"STATIC", DataDir().c_str(),
                         SS_LEFT | SS_NOPREFIX | SS_PATHELLIPSIS,
                         ox, y + 26, pw - 124, 18, ID_FILES_PATH));
    Add(PageSettings, Mk(L"BUTTON", L"Open folder", btn, ox + pw - 112, y + 21, 112, 26,
                         ID_BTN_LOGDIR));
    y += 66;
    Add(PageSettings, Mk(L"STATIC", L"Uninstall", SS_LEFT, ox, y, pw, 18,
                         ID_LBL_UNINST, 0, g.fontBold));
    Add(PageSettings, Mk(L"STATIC",
                         L"Stops the watchdog, removes the startup task and the installed copy. "
                         L"Your settings and log folder are kept.",
                         SS_LEFT | SS_NOPREFIX, ox, y + 22, pw, 34, ID_UNINST_INFO));
    Add(PageSettings, Mk(L"BUTTON", L"Uninstall NetVigil…", btn, ox, y + 60, 150, 26,
                         ID_BTN_UNINSTALL));
    Add(PageSettings, Mk(L"STATIC",
                         L"NetVigil · plain Win32, no dependencies · closing the window keeps it "
                         L"running in the tray",
                         SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                         ox, oy + ph - 18, pw, 18, ID_ABOUT));

    for (HWND h : g.pages[PageSettings]) ShowWindow(h, SW_HIDE);
    // Children stack beneath earlier siblings, so the tab control (created
    // first) would paint over the pages — send it to the bottom.
    SetWindowPos(g.tabs, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

// ---------------------------------------------------------------- handlers

void OnCoreEvent(UiEvent ev, LPARAM lp)
{
    switch (ev) {
    case UiStateChanged: {
        MonitorState st = GetMonitorState();
        UpdateStatus(st);
        // The network list only needs rebuilding after a completed check,
        // not on every state tick during a repair.
        if (g.visible && g.page == PageStatus && st.lastCheck != g.listedCheck)
            RefreshNetworks();
        break;
    }
    case UiLogAppended:
        if (g.visible && g.page == PageStatus) AppendNewLog();
        break;
    case UiRestored:
        Balloon(L"Connection restored",
                lp ? L"Back online after " + std::to_wstring((unsigned long long)lp) +
                         L" min offline."
                   : L"Back online.");
        break;
    case UiFailed:
        if (lp == 1)
            Balloon(L"Connection is down",
                    L"NetVigil could not restore it yet — retrying every 2 minutes.");
        break;
    case UiStopped:
        DestroyWindow(g.hwnd);
        break;
    }
}

void OnCommand(int id)
{
    switch (id) {
    case ID_BTN_PREF:
    case ID_BTN_ALLOW:
    case ID_BTN_NEVER: {
        std::wstring p = SelectedProfile();
        if (p.empty()) { MessageBeep(MB_ICONWARNING); return; }
        SetNetworkMode(p, id == ID_BTN_PREF ? NetMode::Preferred
                        : id == ID_BTN_NEVER ? NetMode::Never : NetMode::Allowed);
        RefreshNetworks();
        break;
    }
    case ID_BTN_CONNECT: {
        std::wstring p = SelectedProfile();
        if (p.empty()) { MessageBeep(MB_ICONWARNING); return; }
        if (ConnectToNetwork(p))
            SetTimer(g.hwnd, ID_TIMER_RECHECK, 12000, nullptr); // verify once associated
        break;
    }
    case ID_BTN_CHECK:
    case TC_CHECK:
        RequestCheckNow();
        break;
    case ID_BTN_PAUSE:
    case TC_PAUSE:
        SetPaused(!GetMonitorState().paused);
        UpdateStatus(GetMonitorState());
        break;
    case ID_BTN_APPLY: {
        wchar_t buf[16] = {};
        GetWindowTextW(g.interval, buf, 16);
        unsigned long v = wcstoul(buf, nullptr, 10);
        if (v < 1 || v > 1440) {
            MessageBeep(MB_ICONWARNING);
            SyncSettings();
        } else {
            SetIntervalMin((DWORD)v);
        }
        break;
    }
    case ID_CHK_NOTIFY:
        SetNotifications(IsDlgButtonChecked(g.hwnd, ID_CHK_NOTIFY) == BST_CHECKED);
        break;
    case ID_BTN_LOGDIR:
        ShellExecuteW(g.hwnd, L"open", DataDir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        break;
    case ID_BTN_INSTALL:
        if (!LaunchInstaller()) {
            MessageBoxW(g.hwnd,
                        L"The installer could not be started (elevation declined?). "
                        L"See the log for details.",
                        L"NetVigil", MB_ICONERROR | MB_OK);
            break;
        }
        g.exitNote = L"Installing at startup — NetVigil will restart in the tray…";
        UpdateStatus(GetMonitorState());
        break;
    case ID_BTN_UNINSTALL: {
        int r = MessageBoxW(g.hwnd,
                            L"Remove NetVigil from this computer?\n\n"
                            L"This stops the watchdog, removes the startup task and the "
                            L"installed copy. Your settings and log folder are kept.",
                            L"Uninstall NetVigil", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (r != IDYES) break;
        if (!LaunchUninstaller()) {
            MessageBoxW(g.hwnd,
                        L"The uninstall helper could not be started (elevation declined?). "
                        L"See the log for details.",
                        L"NetVigil", MB_ICONERROR | MB_OK);
            break;
        }
        g.exitNote = L"Uninstalling — NetVigil is closing…";
        UpdateStatus(GetMonitorState());
        break;
    }
    case TC_OPEN:
        ShowMain();
        break;
    case TC_EXIT:
        RequestStop();
        UpdateStatus(GetMonitorState());
        break;
    case IDCANCEL: // Escape
        HideMain();
        break;
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == ShowWindowMessage()) {
        ShowMain();
        return 0;
    }
    if (g.taskbarCreated && msg == g.taskbarCreated) { // explorer restarted
        AddTray();
        UpdateStatus(GetMonitorState());
        return 0;
    }
    switch (msg) {
    case WM_CREATE:
        g.hwnd = hwnd;
        BuildControls();
        AddTray();
        return 0;
    case WM_TRAY:
        switch (LOWORD(lp)) {
        case NIN_SELECT:
        case NIN_KEYSELECT:
        case WM_LBUTTONDBLCLK:
            ShowMain();
            break;
        case WM_CONTEXTMENU:
        case WM_RBUTTONUP:
            TrayMenu();
            break;
        }
        return 0;
    case WM_CORE:
        OnCoreEvent((UiEvent)wp, lp);
        return 0;
    case WM_TIMER:
        if (wp == ID_TIMER_UI) {
            UpdateStatus(GetMonitorState());
        } else if (wp == ID_TIMER_RECHECK) {
            KillTimer(hwnd, ID_TIMER_RECHECK);
            RequestCheckNow();
        }
        return 0;
    case WM_COMMAND:
        OnCommand(LOWORD(wp));
        return 0;
    case WM_NOTIFY: {
        const NMHDR* h = (const NMHDR*)lp;
        if (h->idFrom == ID_TABS && h->code == TCN_SELCHANGE)
            ShowPage(TabCtrl_GetCurSel(g.tabs));
        else if (h->idFrom == ID_LIST && h->code == NM_DBLCLK)
            OnCommand(ID_BTN_CONNECT);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        // Pages sit on the themed tab body, which is window-white.
        HDC dc = (HDC)wp;
        if ((HWND)lp == g.status) SetTextColor(dc, StatusColor(g.statusIcon));
        SetBkColor(dc, GetSysColor(COLOR_WINDOW));
        return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
    }
    case WM_CLOSE:
        HideMain();
        return 0;
    case WM_QUERYENDSESSION:
        return TRUE;
    case WM_ENDSESSION:
        if (wp) {
            RequestStop();
            RemoveTray();
        }
        return 0;
    case WM_DESTROY:
        RemoveTray();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

} // namespace

int RunGui(HINSTANCE hInst, bool startHidden)
{
    g.hInst = hInst;
    INITCOMMONCONTROLSEX icc{ sizeof icc, ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES |
                                          ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    HDC dc = GetDC(nullptr);
    g.dpi = GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(nullptr, dc);
    CreateFonts();
    int iconPx = GetSystemMetrics(SM_CXSMICON);
    g.icons[IconOnline]  = MakeDotIcon(RGB(46, 160, 67), iconPx);
    g.icons[IconOffline] = MakeDotIcon(RGB(218, 54, 51), iconPx);
    g.icons[IconWarn]    = MakeDotIcon(RGB(227, 160, 8), iconPx);
    g.icons[IconPaused]  = MakeDotIcon(RGB(140, 140, 140), iconPx);
    g.taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = kWndClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = g.icons[IconOnline];
    wc.hIconSm = g.icons[IconOnline];
    if (!RegisterClassExW(&wc)) {
        Logf(L"RegisterClassEx failed (%u)", GetLastError());
        return 1;
    }

    RECT r{ 0, 0, S(600), S(480) };
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    AdjustWindowRectEx(&r, style, FALSE, 0);
    HWND hwnd = CreateWindowExW(0, kWndClass, L"NetVigil", style,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                r.right - r.left, r.bottom - r.top,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) {
        Logf(L"CreateWindowEx failed (%u)", GetLastError());
        return 1;
    }
    // A non-elevated second launch must be able to ask this (elevated)
    // instance to show itself.
    ChangeWindowMessageFilterEx(hwnd, ShowWindowMessage(), MSGFLT_ALLOW, nullptr);
    SetUiNotify(hwnd, WM_CORE);

    g.worker = CreateThread(nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr);
    if (!g.worker) {
        Logf(L"failed to start the monitor thread (%u)", GetLastError());
        DestroyWindow(hwnd);
        return 1;
    }
    SetThreadPriority(g.worker, THREAD_PRIORITY_BELOW_NORMAL); // never fights the UI

    if (startHidden) UpdateStatus(GetMonitorState());
    else             ShowMain();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    SetUiNotify(nullptr, 0);
    if (WaitForSingleObject(g.worker, 20000) == WAIT_TIMEOUT)
        Logf(L"monitor thread did not finish in time — exiting anyway");
    CloseHandle(g.worker);
    for (HICON& i : g.icons) if (i) DestroyIcon(i);
    DeleteObject(g.font);
    DeleteObject(g.fontBold);
    DeleteObject(g.fontBig);
    DeleteObject(g.fontMono);
    UnregisterClassW(kWndClass, hInst);
    return (int)msg.wParam;
}
