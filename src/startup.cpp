// startup.cpp — NetVigil's logon task, registered through the Task
// Scheduler 2.0 COM API from an explicit XML definition (nv::BuildTaskXml).
// The schtasks /SC ONLOGON defaults it replaces would not start the task on
// battery power, stopped it when the laptop was unplugged, killed it after
// 72 hours of uptime, and fired at every user's logon.

#include "core.h"
#include "startup.h"
#include "diagnose.h"

#include <objbase.h>
#include <oleauto.h>
#include <taskschd.h>
#include <wtsapi32.h>
#include <sddl.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

const wchar_t* const kTaskName = L"NetVigil";

// COM for the duration of one call. A thread that already chose another
// apartment (the UI thread is STA) keeps it — COM stays usable either way.
struct ComScope {
    HRESULT hr;
    ComScope() : hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComScope() { if (SUCCEEDED(hr)) CoUninitialize(); }
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;
};

template <typename T>
struct Ptr {                               // Release on scope exit
    T* p = nullptr;
    Ptr() = default;
    Ptr(const Ptr&) = delete;
    Ptr& operator=(const Ptr&) = delete;
    ~Ptr() { if (p) p->Release(); }
    T** put() { return &p; }
    T* operator->() const { return p; }
};

struct Bstr {                              // SysFreeString on scope exit
    BSTR b;
    explicit Bstr(const std::wstring& s) : b(SysAllocStringLen(s.data(), (UINT)s.size())) {}
    ~Bstr() { SysFreeString(b); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
};

std::wstring TakeBstr(BSTR b)
{
    std::wstring s = b ? b : L"";
    SysFreeString(b);
    return s;
}

std::wstring HrText(HRESULT hr)
{
    wchar_t buf[16];
    swprintf_s(buf, L"0x%08lX", (unsigned long)hr);
    return buf;
}

std::wstring Unquote(std::wstring s)
{
    if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"') s = s.substr(1, s.size() - 2);
    return s;
}

VARIANT Empty()
{
    VARIANT v;
    VariantInit(&v);
    return v;
}

bool ConnectRoot(Ptr<ITaskService>& svc, Ptr<ITaskFolder>& root, std::wstring* err)
{
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, (void**)svc.put());
    if (FAILED(hr)) {
        if (err) *err = L"Task Scheduler is unavailable (" + HrText(hr) + L")";
        return false;
    }
    hr = svc->Connect(Empty(), Empty(), Empty(), Empty());
    if (FAILED(hr)) {
        if (err) *err = L"cannot connect to Task Scheduler (" + HrText(hr) + L")";
        return false;
    }
    hr = svc->GetFolder(Bstr(L"\\").b, root.put());
    if (FAILED(hr)) {
        if (err) *err = L"cannot open the Task Scheduler root folder (" + HrText(hr) + L")";
        return false;
    }
    return true;
}

bool IsNotFound(HRESULT hr)
{
    return hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
           hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
}

std::wstring SidOfAccount(const std::wstring& account)
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof sid, domSize = 256;
    wchar_t dom[256];
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, account.c_str(), sid, &sidSize, dom, &domSize, &use))
        return L"";
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) return L"";
    std::wstring s = text;
    LocalFree(text);
    return s;
}

} // namespace

bool QueryStartupTask(StartupTaskInfo& out, std::wstring* err)
{
    out = StartupTaskInfo();
    ComScope com;
    Ptr<ITaskService> svc;
    Ptr<ITaskFolder> root;
    if (!ConnectRoot(svc, root, err)) return false;

    Ptr<IRegisteredTask> task;
    HRESULT hr = root->GetTask(Bstr(kTaskName).b, task.put());
    if (IsNotFound(hr)) return true;
    if (hr == E_ACCESSDENIED) {            // there, but not readable by this token
        out.exists = true;
        return true;
    }
    if (FAILED(hr)) {
        if (err) *err = L"cannot read the startup task (" + HrText(hr) + L")";
        return false;
    }
    out.exists = true;
    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (SUCCEEDED(task->get_Enabled(&enabled))) out.enabled = enabled != VARIANT_FALSE;
    LONG last = 0;
    if (SUCCEEDED(task->get_LastTaskResult(&last))) out.lastResult = last;

    Ptr<ITaskDefinition> def;
    if (FAILED(task->get_Definition(def.put()))) return true;
    out.readable = true;
    out.format = 1;
    Ptr<IRegistrationInfo> info;
    BSTR desc = nullptr;
    if (SUCCEEDED(def->get_RegistrationInfo(info.put())) &&
        SUCCEEDED(info->get_Description(&desc)))
        out.format = nv::TaskFormatOf(TakeBstr(desc));

    Ptr<IActionCollection> actions;
    LONG count = 0;
    if (SUCCEEDED(def->get_Actions(actions.put())) &&
        SUCCEEDED(actions->get_Count(&count)) && count >= 1) {
        Ptr<IAction> action;
        Ptr<IExecAction> exec;
        if (SUCCEEDED(actions->get_Item(1, action.put())) &&   // 1-based
            SUCCEEDED(action->QueryInterface(IID_IExecAction, (void**)exec.put()))) {
            BSTR path = nullptr, args = nullptr;
            if (SUCCEEDED(exec->get_Path(&path))) out.command = Unquote(TakeBstr(path));
            if (SUCCEEDED(exec->get_Arguments(&args))) out.arguments = TakeBstr(args);
        }
    }
    Ptr<IPrincipal> principal;
    BSTR user = nullptr;
    if (SUCCEEDED(def->get_Principal(principal.put())) &&
        SUCCEEDED(principal->get_UserId(&user)))
        out.userId = TakeBstr(user);
    return true;
}

bool RegisterStartupTask(const std::wstring& exe, const std::wstring& args,
                         const std::wstring& userId, std::wstring* err)
{
    ComScope com;
    Ptr<ITaskService> svc;
    Ptr<ITaskFolder> root;
    if (!ConnectRoot(svc, root, err)) return false;

    nv::TaskSpec spec;
    spec.userId    = userId;
    spec.command   = L"\"" + exe + L"\"";
    spec.arguments = args;
    size_t slash = exe.find_last_of(L'\\');
    if (slash != std::wstring::npos) spec.workDir = exe.substr(0, slash);

    Ptr<IRegisteredTask> task;
    HRESULT hr = root->RegisterTask(Bstr(kTaskName).b, Bstr(nv::BuildTaskXml(spec)).b,
                                    TASK_CREATE_OR_UPDATE, Empty(), Empty(),
                                    TASK_LOGON_INTERACTIVE_TOKEN, Empty(), task.put());
    if (FAILED(hr)) {
        if (err) *err = L"Task Scheduler rejected the startup task (" + HrText(hr) + L")";
        return false;
    }
    return true;
}

bool DeleteStartupTask(std::wstring* err)
{
    ComScope com;
    Ptr<ITaskService> svc;
    Ptr<ITaskFolder> root;
    if (!ConnectRoot(svc, root, err)) return false;
    HRESULT hr = root->DeleteTask(Bstr(kTaskName).b, 0);
    if (SUCCEEDED(hr) || IsNotFound(hr)) return true;
    if (err) *err = L"cannot delete the startup task (" + HrText(hr) + L")";
    return false;
}

bool RunStartupTask(std::wstring* err)
{
    ComScope com;
    Ptr<ITaskService> svc;
    Ptr<ITaskFolder> root;
    if (!ConnectRoot(svc, root, err)) return false;
    Ptr<IRegisteredTask> task;
    HRESULT hr = root->GetTask(Bstr(kTaskName).b, task.put());
    Ptr<IRunningTask> running;
    if (SUCCEEDED(hr)) hr = task->Run(Empty(), running.put());
    if (FAILED(hr)) {
        if (err) *err = L"cannot start the startup task (" + HrText(hr) + L")";
        return false;
    }
    return true;
}

std::wstring ProcessUserSid()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return L"";
    BYTE buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD n = 0;
    std::wstring s;
    if (GetTokenInformation(tok, TokenUser, buf, sizeof buf, &n)) {
        LPWSTR text = nullptr;
        if (ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &text)) {
            s = text;
            LocalFree(text);
        }
    }
    CloseHandle(tok);
    return s;
}

std::wstring SessionUserSid(std::wstring* accountName)
{
    LPWSTR user = nullptr, domain = nullptr;
    DWORD n = 0;
    std::wstring account;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                    WTSUserName, &user, &n) && user && user[0]) {
        account = user;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                        WTSDomainName, &domain, &n) && domain && domain[0])
            account = std::wstring(domain) + L"\\" + account;
    }
    if (user) WTSFreeMemory(user);
    if (domain) WTSFreeMemory(domain);

    std::wstring sid = account.empty() ? L"" : SidOfAccount(account);
    if (sid.empty()) sid = ProcessUserSid();
    if (accountName) *accountName = account.empty() ? sid : account;
    return sid;
}

long long SessionLogonStamp()
{
    WTSINFOW* info = nullptr;
    DWORD n = 0;
    long long stamp = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                    WTSSessionInfo, (LPWSTR*)&info, &n) && info) {
        if (n >= sizeof(WTSINFOW)) stamp = info->LogonTime.QuadPart;
        WTSFreeMemory(info);
    }
    return stamp;
}
