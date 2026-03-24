#include "kutil.h"
#include "driver/IDriverBackend.h"
#include <Psapi.h>
#include <algorithm>

namespace KUtil {

// ─── Kernel export resolution ─────────────────────────────────────────────────

DWORD64 KernelExport(const char* name) {
    // Get kernel base from EnumDeviceDrivers (drivers[0] == ntoskrnl)
    LPVOID d[1024]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) return 0;
    DWORD64 kBase = (DWORD64)d[0];

    // Load ntoskrnl as a user-mode DLL to compute RVA, then apply to kernel base
    HMODULE hNt = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNt) return 0;
    DWORD64 offset = (DWORD64)GetProcAddress(hNt, name) - (DWORD64)hNt;
    FreeLibrary(hNt);
    return kBase + offset;
}

// ─── Driver name cache ────────────────────────────────────────────────────────

static std::vector<DriverInfo> s_drivers;

void BuildDriverCache() {
    s_drivers.clear();
    LPVOID d[1024]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) return;
    int n = (int)(cb / sizeof(LPVOID));
    s_drivers.resize(n);
    for (int i = 0; i < n; i++) {
        s_drivers[i].base = (DWORD64)d[i];
        GetDeviceDriverBaseNameW(d[i], s_drivers[i].name, 64);
        GetDeviceDriverFileNameW(d[i], s_drivers[i].path, MAX_PATH);
    }
}

const std::vector<DriverInfo>& GetDrivers() { return s_drivers; }

DWORD64 FindDriverByAddr(DWORD64 addr, const wchar_t** outName, DWORD64* outOffset) {
    DWORD64 bestDiff = (DWORD64)-1;
    const DriverInfo* best = nullptr;
    for (auto& e : s_drivers) {
        if (addr >= e.base && (addr - e.base) < bestDiff) {
            bestDiff = addr - e.base;
            best     = &e;
        }
    }
    if (best) {
        if (outName)   *outName   = best->name;
        if (outOffset) *outOffset = bestDiff;
        return best->base;
    }
    if (outName)   *outName   = L"<unknown>";
    if (outOffset) *outOffset = 0;
    return 0;
}

// ─── EPROCESS walker ──────────────────────────────────────────────────────────
// Reads kernel memory directly via g_drv — no OpenProcess, no NtQuery API calls.
// This avoids triggering ObRegisterCallbacks on Process object open operations,
// which would deadlock if called while we hold any lock the callback also acquires.

std::vector<ProcessEntry> EnumProcesses() {
    std::vector<ProcessEntry> result;

    // PsInitialSystemProcess: exported PEPROCESS of the System process
    DWORD64 sysProc = g_drv->Rd64(KernelExport("PsInitialSystemProcess"));
    if (!g_drv->IsKernelVA(sysProc)) return result;

    DWORD64 cur = sysProc;
    int guard   = 0;

    do {
        ProcessEntry e{};
        e.eprocess      = cur;
        e.pid           = (DWORD)g_drv->Rd64(cur + EP_UniqueProcessId);
        e.activeThreads = g_drv->Rd32(cur + EP_ActiveThreads);
        e.protection    = g_drv->Rd8 (cur + EP_Protection);

        // ImageFileName: 15-byte ASCII, not null-terminated if full
        for (int i = 0; i < 15; i++)
            e.name[i] = (char)g_drv->Rd8(cur + EP_ImageFileName + i);
        e.name[15] = 0;

        // PPID: read from the parent process field
        // InheritedFromUniqueProcessId is at +0x540 on Win10 22H2
        e.ppid = (DWORD)g_drv->Rd64(cur + 0x540);

        result.push_back(e);

        // Follow ActiveProcessLinks.Flink, then back-calculate EPROCESS base
        DWORD64 flink = g_drv->Rd64(cur + EP_ActiveProcessLinks);
        if (!g_drv->IsKernelVA(flink)) break;
        cur = flink - EP_ActiveProcessLinks;
        guard++;

    } while (cur != sysProc && guard < 2048);

    return result;
}

DWORD64 FindEPROCESS(DWORD pid) {
    DWORD64 sysProc = g_drv->Rd64(KernelExport("PsInitialSystemProcess"));
    if (!g_drv->IsKernelVA(sysProc)) return 0;

    DWORD64 cur = sysProc;
    int guard   = 0;
    do {
        DWORD curPid = (DWORD)g_drv->Rd64(cur + EP_UniqueProcessId);
        if (curPid == pid) return cur;
        DWORD64 flink = g_drv->Rd64(cur + EP_ActiveProcessLinks);
        if (!g_drv->IsKernelVA(flink)) return 0;
        cur = flink - EP_ActiveProcessLinks;
        guard++;
    } while (cur != sysProc && guard < 2048);
    return 0;
}

// _PS_PROTECTION: low 3 bits = Type, high 4 bits = Signer
const char* ProtectionStr(BYTE prot) {
    if (prot == 0) return "None";
    static const char* types[]   = { "", "PPL", "PP", "??" };
    static const char* signers[] = { "None","Auth","CodeGen","AM",
                                     "Lsa","Win","WinTcb","WinSys","App","??" };
    BYTE type   = prot & 0x7;
    BYTE signer = (prot >> 4) & 0xF;
    static char buf[32];
    sprintf_s(buf, "%s/%s",
        types  [type   < 4  ? type   : 3],
        signers[signer < 10 ? signer : 9]);
    return buf;
}

} // namespace KUtil
