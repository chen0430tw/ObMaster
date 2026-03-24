#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <vector>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "jutil.h"
#include "ansi.h"

// ── Kernel structures ─────────────────────────────────────────────────────────
//
// PspLoadImageNotifyRoutine[64]    : EX_CALLBACK array (LoadImage)
// PspCreateProcessNotifyRoutine[64]: EX_CALLBACK array (CreateProcess)
// PspCreateThreadNotifyRoutine[64] : EX_CALLBACK array (CreateThread)
//
// EX_CALLBACK (8 bytes):
//   RoutineBlock : EX_FAST_REF  — pointer with low 4 bits = ref count
//   Decode: block = value & ~0xF  ->  EX_CALLBACK_ROUTINE_BLOCK*
//
// EX_CALLBACK_ROUTINE_BLOCK (Windows 10 x64, all modern builds):
//   +0x00  RundownProtect : EX_RUNDOWN_REF  (8 bytes)
//   +0x08  Function       : PEX_CALLBACK_FUNCTION   <- the callback
//   +0x10  Context        : PVOID
//
// The three arrays are NOT exported directly; we locate them by scanning
// the corresponding PsRemove* exported function for the first
// LEA reg, [RIP+disp32] instruction (REX.W 8D /r, mod=00 rm=101).

#define ECRB_FUNCTION   0x08
#define NOTIFY_MAX      64

// ── Helpers ───────────────────────────────────────────────────────────────────

static inline DWORD64 DecodeRef(DWORD64 ref) { return ref & ~(DWORD64)0xF; }

// Return the RVA range of a named PE section in the loaded module.
// Returns false if section not found.
static bool GetSectionRange(HMODULE hNt, const char* secName,
                            DWORD64* outBase, DWORD64* outEnd)
{
    auto* dos = (IMAGE_DOS_HEADER*)hNt;
    auto* nt  = (IMAGE_NT_HEADERS64*)((BYTE*)hNt + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
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

// Locate a Psp*NotifyRoutine array VA by scanning an exported function for
// RIP-relative LEA instructions.
//   skipVA  : skip any kernel VA equal to this (previously found array)
//   dataBase/dataEnd : only accept RVAs inside this range (from .data section)
static DWORD64 FindArrayViaExport(HMODULE hNt, DWORD64 userBase, DWORD64 kernBase,
                                  const char* exportFn,
                                  DWORD64 skipVA   = 0,
                                  DWORD64 dataBase = 0,
                                  DWORD64 dataEnd  = 0,
                                  int scanBytes    = 512)
{
    BYTE* fn = (BYTE*)GetProcAddress(hNt, exportFn);
    if (!fn) { DBG("%s: export not found\n", exportFn); return 0; }

    DBG("%s: scanning %d bytes\n", exportFn, scanBytes);
    for (int i = 0; i < scanBytes - 6; i++) {
        // REX.W (48) or REX.WR (4C) + LEA (8D) + ModRM mod=00 rm=101
        if ((fn[i] == 0x48 || fn[i] == 0x4C) &&
             fn[i+1] == 0x8D &&
            (fn[i+2] & 0xC7) == 0x05)
        {
            INT32 disp      = *(INT32*)(fn + i + 3);
            DWORD64 userTgt = (DWORD64)(fn + i + 7) + (INT64)disp;
            DWORD64 rva     = userTgt - userBase;
            DWORD64 va      = kernBase + rva;
            DBG("  +%03d LEA -> rva=0x%llx va=%p", i, (unsigned long long)rva, (void*)va);
            if (va == skipVA)                                      { printf(" [skip:dup]\n");       continue; }
            if (dataBase != dataEnd && !(rva >= dataBase && rva < dataEnd)) { printf(" [skip:not .data]\n"); continue; }
            printf(" [accept]\n");
            return va;
        }
    }
    DBG("  no valid LEA found\n");
    return 0;
}

// ── Entry scan ────────────────────────────────────────────────────────────────

struct NotifyEntry {
    int     index;
    DWORD64 slotAddr;       // kernel VA of EX_CALLBACK slot in the array
    DWORD64 routineBlock;   // decoded EX_FAST_REF (EX_CALLBACK_ROUTINE_BLOCK*)
    DWORD64 function;       // actual callback function pointer
    const wchar_t* owner;
    DWORD64 ownerOff;
};

static std::vector<NotifyEntry> ScanArray(DWORD64 arrayKVA) {
    std::vector<NotifyEntry> v;
    if (!arrayKVA) return v;

    DBG("ScanArray @ %p\n", (void*)arrayKVA);
    for (int i = 0; i < NOTIFY_MAX; i++) {
        DWORD64 slotAddr = arrayKVA + (DWORD64)i * 8;
        DWORD64 rawRef   = g_drv->Rd64(slotAddr);
        if (!rawRef) continue;

        DWORD64 block = DecodeRef(rawRef);
        DBG("  slot[%d] raw=%p block=%p", i, (void*)rawRef, (void*)block);
        if (!g_drv->IsKernelVA(block)) { printf(" [skip:bad block]\n"); continue; }

        DWORD64 fn = g_drv->Rd64(block + ECRB_FUNCTION);
        if (!fn || !g_drv->IsKernelVA(fn)) { printf(" [skip:bad fn=%p]\n", (void*)fn); continue; }
        DBG("  fn=%p\n", (void*)fn);

        NotifyEntry e{};
        e.index        = i;
        e.slotAddr     = slotAddr;
        e.routineBlock = block;
        e.function     = fn;
        KUtil::FindDriverByAddr(fn, &e.owner, &e.ownerOff);
        v.push_back(e);
    }
    return v;
}

// ── Display ───────────────────────────────────────────────────────────────────

static bool IsSuspicious(const wchar_t* name) {
    if (!name) return true;
    static const wchar_t* ms[] = {
        L"ntoskrnl.exe", L"hal.dll", L"WdFilter.sys", L"CI.dll",
        L"ksecdd.sys",   L"cng.sys", nullptr
    };
    for (int i = 0; ms[i]; i++)
        if (_wcsicmp(name, ms[i]) == 0) return false;
    return true;
}

static void PrintEntry(int idx, const NotifyEntry& e, const char* typeLabel) {
    const char* color = IsSuspicious(e.owner) ? A_RED : A_YELLOW;
    printf("\n  %s[%d]%s %-14s  Slot:%-2d  Block:%p\n",
        A_BOLD, idx, A_RESET, typeLabel, e.index, (void*)e.routineBlock);
    wprintf(L"       Fn  : %hs%p%hs  %hs%ls%hs +0x%llx\n",
        color, (void*)e.function, A_RESET,
        color, e.owner, A_RESET,
        (unsigned long long)e.ownerOff);
}

// ── Public commands ───────────────────────────────────────────────────────────

void CmdNotify(bool doImage, bool doProcess, bool doThread) {
    SetConsoleOutputCP(CP_UTF8);
    KUtil::BuildDriverCache();

    LPVOID drv[1]; DWORD cb;
    EnumDeviceDrivers(drv, sizeof(drv), &cb);
    DWORD64 kernBase = (DWORD64)drv[0];

    HMODULE hNt = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNt) { printf("[!] Cannot load ntoskrnl.exe\n"); return; }
    DWORD64 userBase = (DWORD64)hNt;

    struct { const char* label; const char* exportFn; bool enabled; DWORD64 arrayVA; } sections[] = {
        { "LoadImage",     "PsRemoveLoadImageNotifyRoutine",     doImage,   0 },
        { "CreateProcess", "PsSetCreateProcessNotifyRoutine",   doProcess, 0 },
        { "CreateThread",  "PsRemoveCreateThreadNotifyRoutine",  doThread,  0 },
    };

    DWORD64 dataBase = 0, dataEnd = 0;
    GetSectionRange(hNt, ".data", &dataBase, &dataEnd);
    DBG(".data RVA range: 0x%llx - 0x%llx\n",
        (unsigned long long)dataBase, (unsigned long long)dataEnd);

    // Resolve LoadImage first; pass its VA as skipVA for CreateProcess since
    // PsSetCreateProcessNotifyRoutineEx's first LEA may land on the same array.
    for (auto& s : sections) {
        if (!s.enabled) continue;
        DWORD64 skip = (strcmp(s.exportFn, "PsSetCreateProcessNotifyRoutine") == 0)
                       ? sections[0].arrayVA : 0;
        s.arrayVA = FindArrayViaExport(hNt, userBase, kernBase, s.exportFn,
                                       skip, dataBase, dataEnd);
        // Fallback for CreateProcess
        if (!s.arrayVA && strcmp(s.exportFn, "PsSetCreateProcessNotifyRoutine") == 0) {
            DBG("CreateProcess: primary failed, trying Ex fallback\n");
            s.arrayVA = FindArrayViaExport(hNt, userBase, kernBase,
                                           "PsSetCreateProcessNotifyRoutineEx",
                                           sections[0].arrayVA, dataBase, dataEnd);
        }
        DBG("%s array -> %p\n", s.label, (void*)s.arrayVA);
    }

    FreeLibrary(hNt);

    if (g_jsonMode) {
        printf("{\"command\":\"notify\",\"callbacks\":[\n");
        bool first = true;
        for (auto& s : sections) {
            if (!s.enabled) continue;
            auto v = ScanArray(s.arrayVA);
            for (auto& e : v) {
                if (!first) printf(",\n");
                first = false;
                printf(" {\"type\":%s,\"slot\":%d,\"block\":%s,\"fn\":%s,"
                       "\"owner\":%s,\"offset\":\"0x%llx\"}",
                    JEscape(s.label).c_str(), e.index,
                    JAddr(e.routineBlock).c_str(),
                    JAddr(e.function).c_str(),
                    JEscape(e.owner).c_str(),
                    (unsigned long long)e.ownerOff);
            }
        }
        printf("\n]}\n");
        return;
    }

    int total = 0;
    for (auto& s : sections) {
        if (!s.enabled) continue;
        printf("\n=== %s NotifyRoutines ===\n", s.label);
        if (!s.arrayVA) { printf("  [!] Failed to locate array (export scan failed)\n"); continue; }
        auto v = ScanArray(s.arrayVA);
        if (v.empty()) { printf("  (none)\n"); continue; }
        for (auto& e : v) PrintEntry(total++, e, s.label);
    }
    printf("\n  Total: %d notify entries\n\n", total);
}

void CmdNotifyDisable(unsigned long long targetFn) {
    SetConsoleOutputCP(CP_UTF8);
    KUtil::BuildDriverCache();

    LPVOID drv[1]; DWORD cb;
    EnumDeviceDrivers(drv, sizeof(drv), &cb);
    DWORD64 kernBase = (DWORD64)drv[0];

    HMODULE hNt = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNt) { printf("[!] Cannot load ntoskrnl.exe\n"); return; }
    DWORD64 userBase = (DWORD64)hNt;

    DWORD64 dataBase = 0, dataEnd = 0;
    GetSectionRange(hNt, ".data", &dataBase, &dataEnd);

    const char* exportNames[] = {
        "PsRemoveLoadImageNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsRemoveCreateThreadNotifyRoutine",
        nullptr
    };
    DWORD64 arrays[3]{};
    arrays[0] = FindArrayViaExport(hNt, userBase, kernBase, exportNames[0],
                                   0, dataBase, dataEnd);
    // Try PsSetCreateProcessNotifyRoutine first; fall back to Ex variant
    arrays[1] = FindArrayViaExport(hNt, userBase, kernBase, "PsSetCreateProcessNotifyRoutine",
                                   arrays[0], dataBase, dataEnd);
    if (!arrays[1])
        arrays[1] = FindArrayViaExport(hNt, userBase, kernBase, exportNames[1],
                                       arrays[0], dataBase, dataEnd);
    arrays[2] = FindArrayViaExport(hNt, userBase, kernBase, exportNames[2],
                                   0, dataBase, dataEnd);

    bool found = false;
    for (int t = 0; exportNames[t] && !found; t++) {
        DWORD64 arr = arrays[t];
        if (!arr) continue;

        for (int i = 0; i < NOTIFY_MAX && !found; i++) {
            DWORD64 slotAddr = arr + (DWORD64)i * 8;
            DWORD64 rawRef   = g_drv->Rd64(slotAddr);
            if (!rawRef) continue;

            DWORD64 block = DecodeRef(rawRef);
            if (!g_drv->IsKernelVA(block)) continue;

            DWORD64 fn = g_drv->Rd64(block + ECRB_FUNCTION);
            if (fn != (DWORD64)targetFn) continue;

            const wchar_t* owner; DWORD64 off;
            KUtil::FindDriverByAddr(fn, &owner, &off);
            wprintf(L"  [*] Found: %p  %ls +0x%llx\n", (void*)fn, owner, (unsigned long long)off);
            printf("  [*] Slot[%d] @ %p  Block @ %p\n", i, (void*)slotAddr, (void*)block);

            // Zero the EX_CALLBACK slot — kernel skips NULL entries on iteration
            g_drv->Wr64(slotAddr, 0);
            printf("  [+] Disabled (slot zeroed)\n");
            found = true;
        }
    }

    FreeLibrary(hNt);

    if (!found)
        printf("  [!] No notify entry found with function == %p\n", (void*)(DWORD64)targetFn);
}
