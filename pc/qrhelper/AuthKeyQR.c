// AuthKeyQR.exe - runs tools\qr_bridge.py in the background with no window,
// under a recognisable name ("AuthKey QR helper" in Task Manager).
//
// Lives in pc\bin; the repo root is two levels up. Python runs in a job
// object that dies with this process, so ending "AuthKey QR helper" in Task
// Manager stops the helper completely. Extra arguments go to qr_bridge.py.
#include <windows.h>
#include <shlobj.h>
#include <wchar.h>

static void parentDir(wchar_t* path) {
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash) *slash = 0;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR args, int show) {
    (void)inst; (void)prev; (void)show;

    wchar_t repo[MAX_PATH];
    GetModuleFileNameW(NULL, repo, MAX_PATH);
    parentDir(repo);    // ...\pc\bin
    parentDir(repo);    // ...\pc
    parentDir(repo);    // repo root

    wchar_t python[MAX_PATH], script[MAX_PATH], logDir[MAX_PATH];
    swprintf(python, MAX_PATH, L"%s\\.venv\\Scripts\\python.exe", repo);
    swprintf(script, MAX_PATH, L"%s\\tools\\qr_bridge.py", repo);
    if (GetFileAttributesW(python) == INVALID_FILE_ATTRIBUTES || GetFileAttributesW(script) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(NULL, L"Can't find .venv\\Scripts\\python.exe or tools\\qr_bridge.py next to pc\\bin.",
                    L"AuthKey QR helper", MB_ICONERROR);
        return 1;
    }

    PWSTR local = NULL;
    if (FAILED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &local))) return 1;
    swprintf(logDir, MAX_PATH, L"%s\\AuthKey", local);
    CoTaskMemFree(local);
    CreateDirectoryW(logDir, NULL);

    static wchar_t cmd[4096];
    swprintf(cmd, 4096, L"\"%s\" \"%s\" --log \"%s\\qr_bridge.log\" %s", python, script, logDir, args ? args : L"");

    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    // CREATE_NO_WINDOW: python.exe (and the child the venv shim starts) get a
    // console with no window, so nothing pops up.
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, repo, &si, &pi)) {
        MessageBoxW(NULL, L"Could not start Python.", L"AuthKey QR helper", MB_ICONERROR);
        return 1;
    }
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    return (int)code;
}
