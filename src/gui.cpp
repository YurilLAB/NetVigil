// gui.cpp — NetVigil's small resident window + tray icon.
//
// Plain Win32, no resources: icons are drawn at runtime, controls are created
// by hand. The window is a view over the core's state; the watchdog itself
// runs on a worker thread and the UI thread sleeps in GetMessage. Closing the
// window hides it to the tray — only the tray menu's Exit stops the watchdog.

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
    ID_STATUS = 100, ID_DETAIL, ID_LIST, ID_BTN_PREF, ID_BTN_ALLOW, ID_BTN_NEVER,
    ID_BTN_CONNECT, ID_BTN_CHECK, ID_BTN_PAUSE, ID_EDIT_INTERVAL, ID_BTN_APPLY,
    ID_CHK_NOTIFY, ID_BTN_LOGDIR, ID_LOG, ID_LBL_NETS, ID_LBL_INT, ID_LBL_MIN, ID_LBL_LOG,
    TC_OPEN = 200, TC_CHECK, TC_PAUSE, TC_EXIT,
};

enum IconKind { IconOnline, IconOffline, IconWarn, IconPaused, IconCount };

struct Gui {
    HINSTANCE hInst = nullptr;
    HWND hwnd = nullptr, status = nullptr, detail = nullptr, list = nullptr,
         log = nullptr, interval = nullptr, chkNotify = nullptr, btnPause = nullptr;
    HFONT font = nullptr, fontBig = nullptr, fontMono = nullptr;
    HICON icons[IconCount] = {};
    IconKind statusIcon = IconWarn;
    NOTIFYICONDATAW nid{};
    std::wstring lastTip;
    HANDLE worker = nullptr;
    UINT taskbarCreated = 0;
    unsigned long long logSeq = 0;
    std::vector<KnownNetwork> rows;
    int dpi = 96;
    bool visible = false;
    bool trayAdded = false;
    bool hideHintShown = false;
} g;

int S(int v) { return MulDiv(v, g.dpi, 96); }

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
    g.nid.hIcon = g.icons[g.statusIcon];
    wcscpy_s(g.nid.szTip, L"NetVigil");
    g.trayAdded = Shell_NotifyIconW(NIM_ADD, &g.nid) != FALSE;
    if (!g.trayAdded) {
        Logf(L"tray icon could not be added (%u)", GetLastError());
        return;
    }
    g.nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g.nid);
    g.lastTip.clear();
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
    if (k == g.statusIcon && tip == g.lastTip) return; // no churn while idle
    g.statusIcon = k;
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

void SyncSettings()
{
    SetWindowTextW(g.interval, std::to_wstring(GetIntervalMin()).c_str());
    CheckDlgButton(g.hwnd, ID_CHK_NOTIFY, GetNotifications() ? BST_CHECKED : BST_UNCHECKED);
    SetWindowTextW(g.btnPause, GetMonitorState().paused ? L"Resume" : L"Pause");
}

void UpdateStatus()
{
    MonitorState st = GetMonitorState();
    std::wstring head;
    IconKind ic = IconWarn;
    if (st.stopping) {
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
    }
    if (!st.ssid.empty() && !st.stopping) head += L"   ·   " + st.ssid;

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
                   std::wstring(L"not elevated: driver reset unavailable (run --install)");
    }
    SetWindowTextW(g.status, head.c_str());
    SetWindowTextW(g.detail, det.c_str());
    if (ic != g.statusIcon) InvalidateRect(g.status, nullptr, TRUE);
    SetTray(ic, L"NetVigil — " + head);
}

void ShowMain()
{
    g.visible = true;
    ShowWindow(g.hwnd, IsIconic(g.hwnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g.hwnd);
    SyncSettings();
    RefreshNetworks();
    AppendNewLog();
    UpdateStatus();
    SetTimer(g.hwnd, ID_TIMER_UI, 1000, nullptr);
}

void HideMain()
{
    g.visible = false;
    KillTimer(g.hwnd, ID_TIMER_UI);
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
    HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style,
                             S(x), S(y), S(w), S(h), g.hwnd, (HMENU)(INT_PTR)id,
                             g.hInst, nullptr);
    if (c) SendMessageW(c, WM_SETFONT, (WPARAM)(font ? font : g.font), TRUE);
    return c;
}

void BuildControls()
{
    const DWORD btn = BS_PUSHBUTTON | WS_TABSTOP;
    g.status = Mk(L"STATIC", L"Starting…", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                  12, 10, 576, 26, ID_STATUS, 0, g.fontBig);
    g.detail = Mk(L"STATIC", L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                  12, 40, 576, 18, ID_DETAIL);
    Mk(L"STATIC", L"Networks — choose what NetVigil auto-connects to:",
       SS_LEFT | SS_NOPREFIX, 12, 66, 500, 16, ID_LBL_NETS);
    g.list = Mk(WC_LISTVIEWW, L"",
                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER | WS_TABSTOP,
                12, 84, 576, 180, ID_LIST, WS_EX_CLIENTEDGE);
    ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    const struct { const wchar_t* name; int width; } cols[] = {
        { L"Network", 214 }, { L"Auto-connect", 96 }, { L"Signal", 92 }, { L"Last connected", 150 },
    };
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<LPWSTR>(cols[i].name);
        col.cx = S(cols[i].width);
        ListView_InsertColumn(g.list, i, &col);
    }
    Mk(L"BUTTON", L"Set preferred", btn, 12, 272, 104, 26, ID_BTN_PREF);
    Mk(L"BUTTON", L"Allow", btn, 122, 272, 70, 26, ID_BTN_ALLOW);
    Mk(L"BUTTON", L"Never connect", btn, 198, 272, 104, 26, ID_BTN_NEVER);
    Mk(L"BUTTON", L"Connect now", btn, 308, 272, 96, 26, ID_BTN_CONNECT);
    Mk(L"BUTTON", L"Check now", btn, 426, 272, 84, 26, ID_BTN_CHECK);
    g.btnPause = Mk(L"BUTTON", L"Pause", btn, 516, 272, 72, 26, ID_BTN_PAUSE);

    Mk(L"STATIC", L"Check every", SS_LEFT, 12, 313, 76, 18, ID_LBL_INT);
    g.interval = Mk(L"EDIT", L"10", ES_NUMBER | ES_RIGHT | WS_TABSTOP, 90, 309, 44, 24,
                    ID_EDIT_INTERVAL, WS_EX_CLIENTEDGE);
    SendMessageW(g.interval, EM_LIMITTEXT, 4, 0);
    Mk(L"STATIC", L"min", SS_LEFT, 140, 313, 30, 18, ID_LBL_MIN);
    Mk(L"BUTTON", L"Apply", btn, 172, 308, 64, 26, ID_BTN_APPLY);
    g.chkNotify = Mk(L"BUTTON", L"Show notifications", BS_AUTOCHECKBOX | WS_TABSTOP,
                     254, 310, 150, 22, ID_CHK_NOTIFY);
    Mk(L"BUTTON", L"Open log folder", btn, 466, 308, 122, 26, ID_BTN_LOGDIR);

    Mk(L"STATIC", L"Recent activity:", SS_LEFT, 12, 342, 200, 16, ID_LBL_LOG);
    g.log = Mk(L"EDIT", L"",
               ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
               12, 360, 576, 108, ID_LOG, WS_EX_CLIENTEDGE, g.fontMono);
}

// ---------------------------------------------------------------- handlers

void OnCoreEvent(UiEvent ev, LPARAM lp)
{
    switch (ev) {
    case UiStateChanged:
        UpdateStatus();
        if (g.visible) RefreshNetworks();
        break;
    case UiLogAppended:
        if (g.visible) AppendNewLog();
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
        SyncSettings();
        UpdateStatus();
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
    case ID_BTN_LOGDIR: {
        std::wstring dir = LogPath();
        size_t slash = dir.find_last_of(L'\\');
        if (slash != std::wstring::npos) dir.resize(slash);
        ShellExecuteW(g.hwnd, L"open", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        break;
    }
    case TC_OPEN:
        ShowMain();
        break;
    case TC_EXIT:
        RequestStop();
        UpdateStatus();
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
        UpdateStatus();
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
            UpdateStatus();
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
        if (h->idFrom == ID_LIST && h->code == NM_DBLCLK) OnCommand(ID_BTN_CONNECT);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        if ((HWND)lp == g.status) SetTextColor(dc, StatusColor(g.statusIcon));
        SetBkColor(dc, GetSysColor(COLOR_BTNFACE));
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
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
    INITCOMMONCONTROLSEX icc{ sizeof icc, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
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
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
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

    if (startHidden) UpdateStatus();
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
    DeleteObject(g.fontBig);
    DeleteObject(g.fontMono);
    UnregisterClassW(kWndClass, hInst);
    return (int)msg.wParam;
}
