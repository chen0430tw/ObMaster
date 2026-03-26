#include "kutil.h"
#include "driver/IDriverBackend.h"
#include <Psapi.h>
#include <algorithm>
#include <map>
#include <vector>

namespace KUtil {

// ─── Kernel export resolution ─────────────────────────────────────────────────
// Windows 10 refuses LoadLibrary on ntoskrnl.exe (error 2, by design).
// Instead: read the PE file from disk, parse the export directory, compute RVA.

static DWORD64 ParseExport(const WCHAR* path, const char* name) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    DWORD sz = GetFileSize(hf, NULL);
    std::vector<BYTE> buf(sz);
    DWORD rd;
    bool ok = ReadFile(hf, buf.data(), sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    WORD  nSec = nt->FileHeader.NumberOfSections;

    // RVA → file offset via section table
    auto rva2foa = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < nSec; i++) {
            DWORD vbeg = sec[i].VirtualAddress;
            DWORD vend = vbeg + sec[i].SizeOfRawData;
            if (rva >= vbeg && rva < vend)
                return sec[i].PointerToRawData + (rva - vbeg);
        }
        return 0;
    };

    auto& ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return 0;
    DWORD efoa = rva2foa(ed.VirtualAddress);
    if (!efoa) return 0;

    auto* exp  = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(buf.data() + efoa);
    auto* nameRVAs = reinterpret_cast<DWORD*>(buf.data() + rva2foa(exp->AddressOfNames));
    auto* ords     = reinterpret_cast<WORD* >(buf.data() + rva2foa(exp->AddressOfNameOrdinals));
    auto* funcRVAs = reinterpret_cast<DWORD*>(buf.data() + rva2foa(exp->AddressOfFunctions));

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD nfoa = rva2foa(nameRVAs[i]);
        if (!nfoa) continue;
        const char* expName = reinterpret_cast<const char*>(buf.data() + nfoa);
        if (strcmp(expName, name) == 0)
            return (DWORD64)funcRVAs[ords[i]];  // return RVA
    }
    return 0;
}

DWORD64 KernelExport(const char* name) {
    static std::map<std::string, DWORD64> s_cache;
    auto it = s_cache.find(name);
    if (it != s_cache.end()) return it->second;

    // Kernel base (ntoskrnl is always drivers[0])
    LPVOID d[1024]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) return 0;
    DWORD64 kBase = (DWORD64)d[0];

    // Get ntoskrnl path via kernel driver enumeration, then convert to user path
    WCHAR drvPath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(d[0], drvPath, MAX_PATH)) return 0;
    // drvPath: \SystemRoot\system32\ntoskrnl.exe or \Device\...
    WCHAR filePath[MAX_PATH];
    if (_wcsnicmp(drvPath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\%s", winDir, drvPath + 12);
    } else {
        // Fall back to known location
        WCHAR winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\System32\\ntoskrnl.exe", winDir);
    }

    DWORD64 rva = ParseExport(filePath, name);
    if (!rva) return 0;

    DWORD64 va = kBase + rva;
    s_cache[name] = va;
    return va;
}

// ─── Driver name cache ────────────────────────────────────────────────────────

static std::vector<DriverInfo> s_drivers;

void BuildDriverCache() {
    static bool s_built = false;
    if (s_built) return;
    s_built = true;
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

        // PPID: InheritedFromUniqueProcessId at +0x540 on Win10 22H2 x64
        e.ppid = (DWORD)g_drv->Rd64(cur + EP_InheritedFromUniqueProcessId);

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
