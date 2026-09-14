/* Hermes Core user-scope launcher. No console. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

#define TITLE L"Hermès Core"

static int join(wchar_t *out, size_t n, const wchar_t *a, const wchar_t *b) {
    if (_snwprintf(out, n, L"%s\\%s", a, b) < 0)
        return 0;
    out[n - 1] = 0;
    return 1;
}

static int self_dir(wchar_t *out, DWORD n) {
    wchar_t self[MAX_PATH];
    DWORD r = GetModuleFileNameW(NULL, self, MAX_PATH);
    if (!r || r >= MAX_PATH)
        return 0;
    wchar_t *slash = wcsrchr(self, L'\\');
    if (!slash)
        return 0;
    *slash = 0;
    wcsncpy(out, self, n - 1);
    out[n - 1] = 0;
    return 1;
}

static int run_hidden(const wchar_t *exe, wchar_t *cmdline, const wchar_t *cwd, DWORD *code) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(exe, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, cwd, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, 120000);
    if (code)
        GetExitCodeProcess(pi.hProcess, code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

static void data_dir(wchar_t *out, DWORD n) {
    wchar_t local[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local)))
        GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    _snwprintf(out, n, L"%s\\HermesCore", local);
    out[n - 1] = 0;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show) {
    (void)inst;
    (void)prev;
    (void)show;
    wchar_t app[MAX_PATH], data[MAX_PATH], pyw[MAX_PATH], py[MAX_PATH], setup[MAX_PATH], bg[MAX_PATH];
    wchar_t cmdline[2048];
    DWORD code = 1;
    int background = 0;
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--background") == 0 || _wcsicmp(argv[i], L"/background") == 0)
            background = 1;
    }
    if (argv)
        LocalFree(argv);
    if (!self_dir(app, MAX_PATH))
        return 1;
    data_dir(data, MAX_PATH);
    SetEnvironmentVariableW(L"HERMES_CORE_HOME", data);
    join(pyw, MAX_PATH, app, L"runtime\\pythonw.exe");
    join(py, MAX_PATH, app, L"runtime\\python.exe");
    join(setup, MAX_PATH, app, L"setup.pyw");
    join(bg, MAX_PATH, app, L"background.pyw");
    {
        wchar_t self[MAX_PATH];
        GetModuleFileNameW(NULL, self, MAX_PATH);
        if (wcsstr(self, L"LynqStartup.exe") != NULL)
            background = 1;
    }
    if (background) {
        _snwprintf(cmdline, 2048, L"\"%s\" \"%s\"", pyw, bg);
        if (!run_hidden(pyw, cmdline, app, &code))
            return 1;
        return (int)code;
    }
    _snwprintf(cmdline, 2048, L"\"%s\" \"%s\"", pyw, setup);
    if (!run_hidden(pyw, cmdline, app, &code)) {
        MessageBoxW(NULL, L"Hermès Core n'a pas pu démarrer.", TITLE, MB_OK | MB_ICONERROR);
        return 1;
    }
    return (int)code;
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    return wWinMain(inst, prev, GetCommandLineW(), show);
}
