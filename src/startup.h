// startup.h — how NetVigil starts with Windows: the logon task (Task
// Scheduler 2.0 COM API, explicit XML definition) and the session facts the
// autostart path needs. Implemented in startup.cpp.
#pragma once
#include <string>

struct StartupTaskInfo {
    bool exists = false;
    bool readable = false;       // definition could be read (false: access denied)
    bool enabled = false;
    int  format = 0;             // nv::TaskFormatOf(description); 1 = pre-format task
    std::wstring command;        // exe path, quotes stripped
    std::wstring arguments;
    std::wstring userId;         // principal the task runs as
    long lastResult = 0;         // HRESULT / exit code of the last run
};

// False only when Task Scheduler itself could not be asked; `out.exists`
// says whether the task is there. `err` receives a readable reason.
bool QueryStartupTask(StartupTaskInfo& out, std::wstring* err);
bool RegisterStartupTask(const std::wstring& exe, const std::wstring& args,
                         const std::wstring& userId, std::wstring* err);
bool DeleteStartupTask(std::wstring* err);
bool RunStartupTask(std::wstring* err);

// The account whose desktop this process runs on, as a SID string — not
// necessarily the token's user: when a standard user approves UAC with an
// administrator's password, the installer runs as that administrator, but
// the task must start NetVigil for the person actually signed in.
std::wstring SessionUserSid(std::wstring* accountName);
std::wstring ProcessUserSid();

// Identifies the current logon session across elevation levels (an elevated
// and a normal token of the same logon share it); 0 if unknown.
long long SessionLogonStamp();
