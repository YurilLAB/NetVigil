// proxy.cpp — the one place NetVigil changes proxy settings. A separate
// translation unit because <wininet.h> and <winhttp.h> cannot be included
// together.

#include "core.h"
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

// Turns off the current user's manual proxy, keeping PAC / auto-detect as
// they were, and reports the server string that was configured. Only called
// for a loopback proxy nothing is listening on — typically a debugging or
// filtering tool that crashed and left every browser pointed at a dead port.
bool DisableManualProxy(std::wstring* previous)
{
    // Read the flags as the Internet Options dialog shows them: the plain
    // INTERNET_PER_CONN_FLAGS drops "automatically detect settings" after a
    // failed WPAD lookup, and writing that back would switch it off for good.
    INTERNET_PER_CONN_OPTIONW opt[2] = {};
    opt[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    opt[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    INTERNET_PER_CONN_OPTION_LISTW list = {};
    list.dwSize = sizeof list;
    list.pszConnection = nullptr;          // the LAN connection's settings
    list.dwOptionCount = 2;
    list.pOptions = opt;
    DWORD size = sizeof list;
    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) {
        opt[0].dwOption = INTERNET_PER_CONN_FLAGS;
        size = sizeof list;
        if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) {
            Logf(L"  cannot read the proxy settings (%u)", GetLastError());
            return false;
        }
    }
    DWORD flags = opt[0].Value.dwValue;
    if (opt[1].Value.pszValue) {
        if (previous) *previous = opt[1].Value.pszValue;
        GlobalFree(opt[1].Value.pszValue);
    }
    if (!(flags & PROXY_TYPE_PROXY)) {
        Logf(L"  the manual proxy is already off");
        return false;
    }
    opt[0].dwOption = INTERNET_PER_CONN_FLAGS;
    opt[0].Value.dwValue = (flags & ~(DWORD)PROXY_TYPE_PROXY) | PROXY_TYPE_DIRECT;
    list.dwOptionCount = 1;
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof list)) {
        Logf(L"  cannot change the proxy settings (%u)", GetLastError());
        return false;
    }
    // Tell running WinINET clients (browsers, Store apps) to re-read them.
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    return true;
}
