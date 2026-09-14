/* Hermes Core Windows installer. User-scope, no console, no VBS.
 * Payload: ZIP appended after PE, trailer magic HCMSETUPZIP + little-endian u64 size.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define APP_VERSION L"0.1.2"
#define TITLE L"Hermès Core"
#define MAGIC "HERMESCOREZIP1.2"
#define MAGIC_LEN 16

static int g_silent = 0;

static void fail(const wchar_t *msg) {
    if (!g_silent)
        MessageBoxW(NULL, msg, TITLE, MB_OK | MB_ICONERROR);
}

static int okinfo(const wchar_t *msg) {
    if (g_silent)
        return IDOK;
    return MessageBoxW(NULL, msg, TITLE, MB_OK | MB_ICONINFORMATION);
}

static int ask(const wchar_t *msg) {
    if (g_silent)
        return IDYES;
    return MessageBoxW(NULL, msg, TITLE, MB_YESNO | MB_ICONQUESTION);
}

static int path_exists(const wchar_t *p) {
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES;
}

static int ensure_dir(const wchar_t *p) {
    wchar_t tmp[MAX_PATH];
    wcsncpy(tmp, p, MAX_PATH - 1);
    tmp[MAX_PATH - 1] = 0;
    for (wchar_t *s = tmp; *s; s++) {
        if (*s == L'\\' && s != tmp) {
            *s = 0;
            CreateDirectoryW(tmp, NULL);
            *s = L'\\';
        }
    }
    return CreateDirectoryW(tmp, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static int join(wchar_t *out, size_t n, const wchar_t *a, const wchar_t *b) {
    if (_snwprintf(out, n, L"%s\\%s", a, b) < 0)
        return 0;
    out[n - 1] = 0;
    return 1;
}

static ULONGLONG free_bytes(const wchar_t *root) {
    ULARGE_INTEGER avail;
    if (!GetDiskFreeSpaceExW(root, &avail, NULL, NULL))
        return 0;
    return avail.QuadPart;
}

static int copy_tree(const wchar_t *src, const wchar_t *dst) {
    wchar_t from[MAX_PATH + 8];
    SHFILEOPSTRUCTW op;
    memset(&op, 0, sizeof(op));
    if (_snwprintf(from, MAX_PATH + 4, L"%s\\*", src) < 0)
        return 0;
    from[wcslen(from) + 1] = 0; /* double-null */
    if (!ensure_dir(dst))
        return 0;
    op.wFunc = FO_COPY;
    op.pFrom = from;
    op.pTo = dst;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_SILENT | FOF_NOERRORUI;
    return SHFileOperationW(&op) == 0;
}

static int remove_tree(const wchar_t *dir) {
    wchar_t from[MAX_PATH + 4];
    SHFILEOPSTRUCTW op;
    memset(&op, 0, sizeof(op));
    wcsncpy(from, dir, MAX_PATH - 1);
    from[wcslen(from) + 1] = 0;
    op.wFunc = FO_DELETE;
    op.pFrom = from;
    op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_NORECURSION;
    op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    return SHFileOperationW(&op) == 0;
}

static int run_hidden(const wchar_t *exe, const wchar_t *cmdline, const wchar_t *cwd, DWORD *code) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[4096];
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    wcsncpy(cmd, cmdline, 4095);
    cmd[4095] = 0;
    if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, cwd, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, 120000);
    if (code)
        GetExitCodeProcess(pi.hProcess, code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

static int write_reg_sz(HKEY root, const wchar_t *sub, const wchar_t *name, const wchar_t *val) {
    HKEY k;
    LONG r = RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (r != ERROR_SUCCESS)
        return 0;
    r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)val, (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

static int delete_reg_value(HKEY root, const wchar_t *sub, const wchar_t *name) {
    HKEY k;
    if (RegOpenKeyExW(root, sub, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return 1;
    RegDeleteValueW(k, name);
    RegCloseKey(k);
    return 1;
}

static int self_path(wchar_t *out, DWORD n) {
    DWORD r = GetModuleFileNameW(NULL, out, n);
    return r > 0 && r < n;
}

static int extract_payload(const wchar_t *self, const wchar_t *zip_out) {
    HANDLE h = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 24) {
        CloseHandle(h);
        return 0;
    }
    LARGE_INTEGER pos;
    pos.QuadPart = sz.QuadPart - 24;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
        CloseHandle(h);
        return 0;
    }
    unsigned char tail[24];
    DWORD rd = 0;
    if (!ReadFile(h, tail, 24, &rd, NULL) || rd != 24) {
        CloseHandle(h);
        return 0;
    }
    if (memcmp(tail + 8, MAGIC, MAGIC_LEN) != 0) {
        CloseHandle(h);
        return 0;
    }
    uint64_t zsz = 0;
    memcpy(&zsz, tail, 8);
    if (zsz < 22 || zsz > (uint64_t)sz.QuadPart - 24) {
        CloseHandle(h);
        return 0;
    }
    pos.QuadPart = sz.QuadPart - 24 - (LONGLONG)zsz;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
        CloseHandle(h);
        return 0;
    }
    HANDLE out = CreateFileW(zip_out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return 0;
    }
    char buf[1 << 16];
    uint64_t left = zsz;
    while (left) {
        DWORD n = (DWORD)(left > sizeof(buf) ? sizeof(buf) : left);
        if (!ReadFile(h, buf, n, &rd, NULL) || rd != n) {
            CloseHandle(out);
            CloseHandle(h);
            return 0;
        }
        DWORD wr = 0;
        if (!WriteFile(out, buf, rd, &wr, NULL) || wr != rd) {
            CloseHandle(out);
            CloseHandle(h);
            return 0;
        }
        left -= rd;
    }
    CloseHandle(out);
    CloseHandle(h);
    return 1;
}

static int find_tar(wchar_t *out, DWORD n) {
    wchar_t sys[MAX_PATH];
    if (!GetSystemDirectoryW(sys, MAX_PATH))
        return 0;
    if (!join(out, n, sys, L"tar.exe"))
        return 0;
    if (path_exists(out))
        return 1;
    if (!GetWindowsDirectoryW(sys, MAX_PATH))
        return 0;
    if (!join(out, n, sys, L"System32\\tar.exe"))
        return 0;
    return path_exists(out);
}

static void app_dir(wchar_t *out, DWORD n) {
    wchar_t local[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local)))
        GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    _snwprintf(out, n, L"%s\\Programs\\HermesCore", local);
    out[n - 1] = 0;
}

static void data_dir(wchar_t *out, DWORD n) {
    wchar_t local[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local)))
        GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    _snwprintf(out, n, L"%s\\HermesCore", local);
    out[n - 1] = 0;
}

static int do_uninstall(int purge_identity) {
    wchar_t app[MAX_PATH], data[MAX_PATH], ident[MAX_PATH], runv[MAX_PATH];
    app_dir(app, MAX_PATH);
    data_dir(data, MAX_PATH);
    join(ident, MAX_PATH, data, L"identity.json");
    join(runv, MAX_PATH, app, L"HermesCore.exe");
    delete_reg_value(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HermesCore");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\HermesCore");
    if (path_exists(app))
        remove_tree(app);
    if (purge_identity && path_exists(ident))
        DeleteFileW(ident);
    okinfo(purge_identity
               ? L"Hermès Core et les données locales ont été retirés."
               : L"Hermès Core a été désinstallé.\nVotre identité privée a été conservée.");
    return 0;
}

static int write_uninstall_info(const wchar_t *app, const wchar_t *setup) {
    wchar_t uninst[MAX_PATH], cmd[MAX_PATH * 2];
    const wchar_t *sub = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\HermesCore";
    _snwprintf(uninst, MAX_PATH, L"%s\\HermesCoreSetup.exe", app);
    CopyFileW(setup, uninst, FALSE);
    _snwprintf(cmd, MAX_PATH * 2, L"\"%s\" /uninstall", uninst);
    write_reg_sz(HKEY_CURRENT_USER, sub, L"DisplayName", L"Hermès Core");
    write_reg_sz(HKEY_CURRENT_USER, sub, L"DisplayVersion", APP_VERSION);
    write_reg_sz(HKEY_CURRENT_USER, sub, L"Publisher", L"Hermès");
    write_reg_sz(HKEY_CURRENT_USER, sub, L"InstallLocation", app);
    write_reg_sz(HKEY_CURRENT_USER, sub, L"UninstallString", cmd);
    write_reg_sz(HKEY_CURRENT_USER, sub, L"DisplayIcon", uninst);
    return 1;
}

static int install(void) {
    wchar_t self[MAX_PATH], app[MAX_PATH], data[MAX_PATH], tmp[MAX_PATH], zip[MAX_PATH], stage[MAX_PATH];
    wchar_t tar[MAX_PATH], cmdline[2048], pyw[MAX_PATH], setup[MAX_PATH], launch[MAX_PATH], ident[MAX_PATH];
    wchar_t logdir[MAX_PATH];
    DWORD code = 1;

    if (!self_path(self, MAX_PATH)) {
        fail(L"Impossible de localiser l'installateur.");
        return 1;
    }
    app_dir(app, MAX_PATH);
    data_dir(data, MAX_PATH);
    join(ident, MAX_PATH, data, L"identity.json");
    if (free_bytes(data[0] ? data : L"C:\\") < 80ull * 1024 * 1024) {
        fail(L"Espace disque insuffisant pour installer Hermès Core.");
        return 1;
    }
    if (path_exists(app)) {
        if (ask(L"Hermès Core est déjà installé.\nMettre à jour sans toucher à votre identité ?") != IDYES)
            return 0;
    } else {
        if (ask(L"Installer Hermès Core sur cet ordinateur ?\nInstallation utilisateur, sans compte administrateur.") != IDYES)
            return 0;
    }
    GetTempPathW(MAX_PATH, tmp);
    _snwprintf(zip, MAX_PATH, L"%sHermesCore-payload-%u.zip", tmp, GetCurrentProcessId());
    _snwprintf(stage, MAX_PATH, L"%sHermesCore-stage-%u", tmp, GetCurrentProcessId());
    if (!extract_payload(self, zip)) {
        fail(L"Paquet d'installation illisible ou incomplet.");
        return 1;
    }
    if (!find_tar(tar, MAX_PATH)) {
        DeleteFileW(zip);
        fail(L"Windows tar.exe est introuvable. Impossible d'installer.");
        return 1;
    }
    ensure_dir(stage);
    _snwprintf(cmdline, 2048, L"\"%s\" -xf \"%s\" -C \"%s\"", tar, zip, stage);
    if (!run_hidden(tar, cmdline, stage, &code) || code != 0) {
        DeleteFileW(zip);
        remove_tree(stage);
        fail(L"Extraction du paquet impossible.");
        return 1;
    }
    DeleteFileW(zip);
    ensure_dir(app);
    ensure_dir(data);
    join(logdir, MAX_PATH, data, L"Logs");
    ensure_dir(logdir);
    if (!copy_tree(stage, app)) {
        remove_tree(stage);
        fail(L"Copie des fichiers impossible.");
        return 1;
    }
    remove_tree(stage);
    join(pyw, MAX_PATH, app, L"runtime\\pythonw.exe");
    join(setup, MAX_PATH, app, L"setup.pyw");
    join(launch, MAX_PATH, app, L"HermesCore.exe");
    if (!path_exists(pyw) || !path_exists(setup)) {
        fail(L"Installation incomplète : runtime manquant.");
        return 1;
    }
    write_uninstall_info(app, self);
    _snwprintf(cmdline, 2048, L"\"%s\" --background", launch);
    write_reg_sz(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HermesCore", cmdline);

    _snwprintf(cmdline, 2048, L"\"%s\" \"%s\"", pyw, setup);
    SetEnvironmentVariableW(L"HERMES_CORE_HOME", data);
    if (g_silent)
        SetEnvironmentVariableW(L"HERMES_SETUP_SILENT", L"1");
    if (!run_hidden(pyw, cmdline, app, &code)) {
        fail(L"Hermès Core n'a pas pu démarrer après l'installation.");
        return 1;
    }
    if (code != 0) {
        fail(L"Installation impossible.\nLa vérification de Hermès Core a échoué.");
        return 1;
    }
    okinfo(L"Hermès Core est prêt.");
    (void)ident;
    return 0;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show) {
    (void)inst;
    (void)prev;
    (void)show;
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int uninstall = 0;
    int purge = 0;
    g_silent = 0;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/uninstall") == 0 || _wcsicmp(argv[i], L"--uninstall") == 0)
            uninstall = 1;
        if (_wcsicmp(argv[i], L"/purge") == 0 || _wcsicmp(argv[i], L"--purge-identity") == 0)
            purge = 1;
        if (_wcsicmp(argv[i], L"/S") == 0 || _wcsicmp(argv[i], L"/silent") == 0 || _wcsicmp(argv[i], L"--silent") == 0)
            g_silent = 1;
    }
    if (argv)
        LocalFree(argv);
    if (uninstall) {
        if (ask(L"Désinstaller Hermès Core ?\nVotre identité privée restera sur cet ordinateur.") != IDYES)
            return 0;
        if (!g_silent && purge == 0 && ask(L"Supprimer aussi l'identité locale ?\nNon recommandé.") == IDYES)
            purge = 1;
        return do_uninstall(purge);
    }
    return install();
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    return wWinMain(inst, prev, GetCommandLineW(), show);
}
