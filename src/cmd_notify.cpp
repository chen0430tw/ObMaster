#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <cstring>
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
    DWORD64 context;        // EX_CALLBACK_ROUTINE_BLOCK + 0x10
    const wchar_t* owner;
    DWORD64 ownerOff;
    const wchar_t* ctxOwner;   // driver owning the context pointer
    DWORD64 ctxOwnerOff;
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
    if (e.context) {
        const char* ccolor = (e.ctxOwner && e.ctxOwner[0] != L'\0') ? A_CYAN : A_DIM;
        wprintf(L"       Ctx : %hs%p%hs  %ls +0x%llx\n",
            ccolor, (void*)e.context, A_RESET,
            e.ctxOwner ? e.ctxOwner : L"<unknown>",
            (unsigned long long)e.ctxOwnerOff);
    }
    // Dump first 16 bytes of Fn to check for trampoline (jmp/call)
    if (e.function && g_drv->IsKernelVA(e.function)) {
        BYTE code[16]{};
        for (int b = 0; b < 16; b += 8) {
            DWORD64 qw = g_drv->Rd64(e.function + b);
            memcpy(code + b, &qw, 8);
        }
        printf("       Code: ");
        for (int b = 0; b < 16; b++) printf("%02X ", code[b]);
        // Check for FF 25 (jmp [rip+disp]) or E9 (jmp rel32)
        if (code[0] == 0xFF && code[1] == 0x25) {
            INT32 disp = *(INT32*)(code + 2);
            DWORD64 tgt = g_drv->Rd64(e.function + 6 + disp);
            const wchar_t* jOwner = nullptr; DWORD64 jOff = 0;
            KUtil::FindDriverByAddr(tgt, &jOwner, &jOff);
            wprintf(L" -> jmp [%p] = %p %ls+0x%llx",
                (void*)(e.function + 6 + disp), (void*)tgt,
                jOwner ? jOwner : L"??", (unsigned long long)jOff);
        } else if (code[0] == 0xE9) {
            INT32 disp = *(INT32*)(code + 1);
            DWORD64 tgt = e.function + 5 + disp;
            const wchar_t* jOwner = nullptr; DWORD64 jOff = 0;
            KUtil::FindDriverByAddr(tgt, &jOwner, &jOff);
            wprintf(L" -> jmp %p %ls+0x%llx",
                (void*)tgt, jOwner ? jOwner : L"??", (unsigned long long)jOff);
        }
        printf("\n");
    }
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
        { "CreateProcess", "PsRemoveCreateProcessNotifyRoutine", doProcess, 0 },
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
        DWORD64 skip = (strcmp(s.exportFn, "PsRemoveCreateProcessNotifyRoutine") == 0)
                       ? sections[0].arrayVA : 0;
        s.arrayVA = FindArrayViaExport(hNt, userBase, kernBase, s.exportFn,
                                       skip, dataBase, dataEnd);
        // Fallback for CreateProcess: try non-Ex Set, then Ex Set
        if (!s.arrayVA && strcmp(s.exportFn, "PsRemoveCreateProcessNotifyRoutine") == 0) {
            DBG("CreateProcess: primary failed, trying non-Ex Set fallback\n");
            s.arrayVA = FindArrayViaExport(hNt, userBase, kernBase,
                                           "PsSetCreateProcessNotifyRoutine",
                                           sections[0].arrayVA, dataBase, dataEnd);
        }
        if (!s.arrayVA && strcmp(s.exportFn, "PsRemoveCreateProcessNotifyRoutine") == 0) {
            DBG("CreateProcess: non-Ex failed, trying Ex fallback\n");
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
    // Try Remove → non-Ex Set → Ex Set
    arrays[1] = FindArrayViaExport(hNt, userBase, kernBase, "PsRemoveCreateProcessNotifyRoutine",
                                   arrays[0], dataBase, dataEnd);
    if (!arrays[1])
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

// ── /notify registry ─────────────────────────────────────────────────────────
//
// CmRegisterCallback stores callbacks in CmpCallBackVector, which on
// Windows 10 x64 is an EX_CALLBACK[100] array — identical layout to
// PspLoadImageNotifyRoutine[64].  Each slot is an EX_FAST_REF:
//
//   slot (8 bytes): raw EX_FAST_REF
//     decode:  block = raw & ~0xF  ->  EX_CALLBACK_ROUTINE_BLOCK*
//     +0x00  RundownProtect : EX_RUNDOWN_REF
//     +0x08  Function       : PEX_CALLBACK_FUNCTION   <- the registry callback
//     +0x10  Context        : PVOID
//
// We locate the array by scanning CmUnRegisterCallback for the first
// RIP-relative LEA pointing into ntoskrnl .data.
//
// To kill an entry: zero the EX_CALLBACK slot — kernel skips NULL on walk.
//
// ⚠️ KNOWN ISSUE (2026-04-10 session_backup):
//   FindCmpCallBackVector() may find the wrong array — the address found via
//   CmUnRegisterCallback LEA scan matched a dispatch table, not the real
//   CmpCallBackVector. Evidence: repeating stride-8 ntoskrnl addresses,
//   UTF-16 strings in slots, fn first-byte not valid x64 prologues.
//   The real CmpCallBackVector may be a CM_CALLBACK_ENTRY linked list,
//   not a flat EX_CALLBACK[100] array.
//
// ppm-engine v0.2.1 cross-verification (2026-04-11):
//   ksafecenter64.sys CmRegisterCallbackEx @ 0x7A47:
//     callback function = 0x7C20 (RegNtPreSetValueKey handler)
//     protects: \Registry\Machine\SOFTWARE\kSafeCenter
//   kboot64.sys also has CmCallback (cm_callback conf=0.85 @ 0x1853F)
//   -> If array scan fails, fallback: search loaded driver address ranges
//      for known CmCallback function offsets from ppm static analysis.

#define CM_ARRAY_MAX  100

// Validate that a kernel VA looks like a CmpCallBackVector (EX_CALLBACK array):
// at least one slot in [0..CM_ARRAY_MAX) must decode to a valid EX_CALLBACK_ROUTINE_BLOCK
// with a kernel-range function pointer that does NOT fall back into the array itself.
// Check if a byte is a valid x64 function prologue start
static bool IsValidPrologue(BYTE b) {
    // Common x64 function prologues:
    //   48 (REX.W prefix for mov/sub/push)
    //   4C (REX.WR prefix)
    //   40-4F (any REX prefix)
    //   55 (push rbp)
    //   53 (push rbx)
    //   56 (push rsi)
    //   57 (push rdi)
    //   41 (REX.B for push r8-r15)
    //   CC (int3 padding before function - skip, check next byte)
    //   E9 (jmp - thunk)
    //   Sub rsp: starts with 48 83 EC
    return (b >= 0x40 && b <= 0x4F) || // REX prefixes
           b == 0x53 || b == 0x55 || b == 0x56 || b == 0x57 || // push regs
           b == 0xE9 || b == 0x33 || b == 0x8B || b == 0x89;   // jmp/xor/mov
}

static bool LooksLikeCmArray(DWORD64 va)
{
    // Require at least one slot that:
    //  1. block is a paged-pool VA (not back in the array)
    //  2. block + 0x00 (RundownProtect) is NOT a kernel VA (should be 0 or tiny ref count)
    //  3. fn = block + 0x08 is a kernel VA not in the array
    //  4. fn resolves to a KNOWN loaded driver (not <unknown>)
    //  5. fn first byte is a valid x64 function prologue (not data/pointer)
    //
    // Also: count valid vs total non-zero slots. If < 50% valid, reject.
    // (dispatch tables have many entries that fail prologue check)
    int totalNonZero = 0, validEntries = 0;

    for (int i = 0; i < CM_ARRAY_MAX; i++) {
        DWORD64 raw = g_drv->Rd64(va + (DWORD64)i * 8);
        if (!raw) continue;
        totalNonZero++;

        DWORD64 block = raw & ~(DWORD64)0xF;
        if (!g_drv->IsKernelVA(block)) continue;
        if (block >= va && block < va + (DWORD64)CM_ARRAY_MAX * 8) continue;

        // RundownProtect at +0x00 must not be a kernel VA
        DWORD64 rundown = g_drv->Rd64(block + 0x00);
        if (g_drv->IsKernelVA(rundown)) continue;

        DWORD64 fn = g_drv->Rd64(block + ECRB_FUNCTION);
        if (!fn || !g_drv->IsKernelVA(fn)) continue;
        if (fn >= va && fn < va + (DWORD64)CM_ARRAY_MAX * 8) continue;

        // Function must resolve to a known loaded driver (non-empty name)
        const wchar_t* owner = nullptr; DWORD64 off = 0;
        KUtil::FindDriverByAddr(fn, &owner, &off);
        if (!owner || owner[0] == L'\0') continue;

        // NEW: fn first byte must be a valid x64 prologue instruction
        // This rejects dispatch table entries where "fn" is actually a data pointer
        BYTE firstByte = g_drv->Rd8(fn);
        if (!IsValidPrologue(firstByte)) {
            DBG("    LooksLikeCmArray: slot[%d] fn=%p firstByte=0x%02X (not prologue) -> skip\n",
                i, (void*)fn, firstByte);
            continue;
        }

        validEntries++;
        DBG("    LooksLikeCmArray: slot[%d] block=%p fn=%p owner=%ls prologue=0x%02X OK\n",
            i, (void*)block, (void*)fn, owner, firstByte);
    }

    // Dispatch tables have many non-zero slots but most fail prologue check.
    // Real CmpCallBackVector: few entries (1-10), all valid.
    // Reject if too many non-zero slots with no valid entries (dispatch table).
    if (validEntries == 0) return false;
    if (totalNonZero > 20 && validEntries < 2) {
        DBG("    LooksLikeCmArray: suspicious ratio %d/%d (too many bad slots)\n",
            validEntries, totalNonZero);
        return false;
    }
    DBG("    LooksLikeCmArray: accepted (%d valid / %d total)\n", validEntries, totalNonZero);
    return true;
}

static DWORD64 FindCmpCallBackVector(HMODULE hNt, DWORD64 userBase, DWORD64 kernBase)
{
    DWORD64 dataBase = 0, dataEnd = 0;
    GetSectionRange(hNt, ".data", &dataBase, &dataEnd);

    // Collect ALL RIP-relative LEA/.data candidates from both exports,
    // then pick the first one that passes the EX_CALLBACK array validation.
    std::vector<DWORD64> candidates;

    const char* probes[] = { "CmUnRegisterCallback", "CmRegisterCallback",
                              "CmRegisterCallbackEx", nullptr };
    for (int p = 0; probes[p]; p++) {
        BYTE* fn = (BYTE*)GetProcAddress(hNt, probes[p]);
        if (!fn) { DBG("%s: not found\n", probes[p]); continue; }
        DBG("FindCmpCallBackVector: scanning %s\n", probes[p]);

        for (int i = 0; i < 512 - 6; i++) {
            if ((fn[i] == 0x48 || fn[i] == 0x4C) &&
                (fn[i+1] == 0x8D || fn[i+1] == 0x8B) &&
                (fn[i+2] & 0xC7) == 0x05)
            {
                INT32 disp      = *(INT32*)(fn + i + 3);
                DWORD64 userTgt = (DWORD64)(fn + i + 7) + (INT64)disp;
                DWORD64 rva     = userTgt - userBase;
                DWORD64 va      = kernBase + rva;
                if (dataBase != dataEnd && !(rva >= dataBase && rva < dataEnd)) {
                    DBG("  +%03d -> rva=0x%llx [skip: not .data]\n", i, (unsigned long long)rva);
                    continue;
                }
                DBG("  +%03d -> rva=0x%llx va=%p [candidate]\n", i, (unsigned long long)rva, (void*)va);
                // Dedup
                bool dup = false;
                for (DWORD64 c : candidates) if (c == va) { dup = true; break; }
                if (!dup) candidates.push_back(va);
            }
        }
    }

    DBG("FindCmpCallBackVector: %zu candidates, validating...\n", candidates.size());
    for (DWORD64 va : candidates) {
        if (LooksLikeCmArray(va)) {
            DBG("  -> validated: %p\n", (void*)va);
            return va;
        }
        DBG("  -> %p failed validation\n", (void*)va);
    }
    DBG("FindCmpCallBackVector: no valid array found\n");
    return 0;
}

void CmdNotifyRegistry(const char* killDriver, DWORD64 killKva, bool killUnknown)
{
    SetConsoleOutputCP(CP_UTF8);
    KUtil::BuildDriverCache();

    LPVOID drv[1]; DWORD cb;
    EnumDeviceDrivers(drv, sizeof(drv), &cb);
    DWORD64 kernBase = (DWORD64)drv[0];

    HMODULE hNt = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNt) { printf("[!] Cannot load ntoskrnl.exe\n"); return; }
    DWORD64 userBase = (DWORD64)hNt;

    DWORD64 arrayVA = FindCmpCallBackVector(hNt, userBase, kernBase);
    FreeLibrary(hNt);

    if (!arrayVA) {
        printf("[!] Failed to locate CmpCallBackVector\n");
        return;
    }
    printf("CmpCallBackVector @ %p\n", (void*)arrayVA);

    // Reuse the same EX_CALLBACK scan logic as Psp* arrays (ScanArray),
    // but with CM_ARRAY_MAX slots instead of NOTIFY_MAX.
    std::vector<NotifyEntry> v;
    for (int i = 0; i < CM_ARRAY_MAX; i++) {
        DWORD64 slotAddr = arrayVA + (DWORD64)i * 8;
        DWORD64 rawRef   = g_drv->Rd64(slotAddr);
        if (!rawRef) continue;

        DWORD64 block = DecodeRef(rawRef);
        DBG("  cm_slot[%d] raw=%p block=%p", i, (void*)rawRef, (void*)block);
        if (!g_drv->IsKernelVA(block)) { DBG(" [skip:bad block]\n"); continue; }

        DWORD64 fn = g_drv->Rd64(block + ECRB_FUNCTION);
        if (!fn || !g_drv->IsKernelVA(fn)) { DBG(" [skip:bad fn=%p]\n", (void*)fn); continue; }
        // Reject self-referential fn (fn points back into the array itself)
        if (fn >= arrayVA && fn < arrayVA + (DWORD64)CM_ARRAY_MAX * 8) {
            DBG(" [skip:fn in array]\n"); continue;
        }
        DBG(" fn=%p\n", (void*)fn);

        // Validate: fn must point to actual code, not data/pointers.
        // Real callback functions start with x64 instructions (sub rsp, push, mov, lea, etc).
        // Stale/garbage entries often have fn pointing to pool LIST_ENTRY nodes where
        // the first QWORD is a kernel VA (Flink pointer), not an instruction.
        {
            DWORD64 fnFirst = g_drv->Rd64(fn);
            // If first 8 bytes at fn look like a kernel VA, it's data, not code
            if (g_drv->IsKernelVA(fnFirst)) {
                DBG("  cm_slot[%d] fn=%p first qword=%p (kernel VA = data, not code) -> skip\n",
                    i, (void*)fn, (void*)fnFirst);
                continue;
            }
            // Also reject if first qword is zero (unmapped/freed)
            if (fnFirst == 0) {
                DBG("  cm_slot[%d] fn=%p first qword=0 -> skip\n", i, (void*)fn);
                continue;
            }
            // If 5+ of the 8 bytes are zero, it's data (small integer/counter), not code.
            // Real x64 instructions are dense — e.g. "48 83 EC 28 48 83 C1 08" has 0 zero bytes.
            BYTE fb[8]; memcpy(fb, &fnFirst, 8);
            int nz = 0;
            for (int b = 0; b < 8; b++) if (fb[b] == 0) nz++;
            if (nz >= 5) {
                DBG("  cm_slot[%d] fn=%p first qword has %d zero bytes (data, not code) -> skip\n",
                    i, (void*)fn, nz);
                continue;
            }
        }

        DWORD64 ctx = g_drv->Rd64(block + 0x10);

        NotifyEntry e{};
        e.index        = i;
        e.slotAddr     = slotAddr;
        e.routineBlock = block;
        e.function     = fn;
        e.context      = ctx;
        e.ctxOwner     = nullptr;
        e.ctxOwnerOff  = 0;
        KUtil::FindDriverByAddr(fn, &e.owner, &e.ownerOff);
        // Sanity: if offset > 64 MB, the match is bogus (pool addr, not in any module)
        if (e.ownerOff > 0x4000000) {
            e.owner    = L"<unknown>";
            e.ownerOff = 0;
        }
        // Resolve context pointer owner too
        if (ctx && g_drv->IsKernelVA(ctx)) {
            KUtil::FindDriverByAddr(ctx, &e.ctxOwner, &e.ctxOwnerOff);
            if (e.ctxOwnerOff > 0x4000000) {
                e.ctxOwner    = nullptr;
                e.ctxOwnerOff = 0;
            }
        }
        v.push_back(e);
    }

    if (g_jsonMode) {
        printf("{\"command\":\"notify_registry\",\"array\":\"%p\",\"callbacks\":[\n",
               (void*)arrayVA);
        bool first = true;
        for (auto& e : v) {
            if (!first) printf(",\n");
            first = false;
            printf(" {\"slot\":%d,\"block\":%s,\"fn\":%s,"
                   "\"owner\":%s,\"offset\":\"0x%llx\"}",
                e.index,
                JAddr(e.routineBlock).c_str(),
                JAddr(e.function).c_str(),
                JEscape(e.owner).c_str(),
                (unsigned long long)e.ownerOff);
        }
        printf("\n]}\n");
        return;
    }

    printf("\n=== CmRegisterCallback Routines ===\n");
    if (v.empty()) {
        printf("  (none)\n\n");
        return;
    }

    // If --kill-kva given, read DriverStart/DriverSize from DriverObject for range matching.
    // DRIVER_OBJECT layout (x64): +0x18 DriverStart (PVOID), +0x20 DriverSize (ULONG)
    DWORD64 killRangeBase = 0, killRangeEnd = 0;
    if (killKva) {
        // Dump first 8 qwords of DriverObject for layout verification
        printf("DriverObject dump @ %p:\n", (void*)killKva);
        for (int q = 0; q < 8; q++) {
            DWORD64 val = g_drv->Rd64(killKva + (DWORD64)q * 8);
            printf("  +0x%02x: %016llX\n", q * 8, (unsigned long long)val);
        }
        killRangeBase = g_drv->Rd64(killKva + 0x18);
        DWORD64 sz    = g_drv->Rd64(killKva + 0x20) & 0xFFFFFFFF; // ULONG
        killRangeEnd  = killRangeBase + sz;
        printf("Kill range: %p -- %p (DriverStart+DriverSize)\n",
               (void*)killRangeBase, (void*)killRangeEnd);
    }

    int killed = 0;
    for (int idx = 0; idx < (int)v.size(); idx++) {
        auto& e = v[idx];
        PrintEntry(idx, e, "Registry");

        bool shouldKill = false;

        // Path 1: name match (when driver is visible in module list)
        if (killDriver && e.owner) {
            char narrow[256]{};
            WideCharToMultiByte(CP_ACP, 0, e.owner, -1, narrow, 255, nullptr, nullptr);
            const char* base = strrchr(narrow, '\\');
            base = base ? base + 1 : narrow;
            shouldKill = (_stricmp(base, killDriver) == 0);
            if (!shouldKill) {
                char killBase[256]; strncpy(killBase, killDriver, 255); killBase[255] = '\0';
                char* dot = strrchr(killBase, '.');
                char narrowBase[256]; strncpy(narrowBase, base, 255); narrowBase[255] = '\0';
                char* dot2 = strrchr(narrowBase, '.');
                if (dot)  *dot  = '\0';
                if (dot2) *dot2 = '\0';
                shouldKill = (_stricmp(narrowBase, killBase) == 0);
            }
        }

        // Path 2: range match via DriverObject KVA (handles DKOM-hidden drivers)
        if (!shouldKill && killRangeBase && killRangeEnd > killRangeBase) {
            shouldKill = (e.function >= killRangeBase && e.function < killRangeEnd);
        }

        // Path 3: kill all entries whose fn doesn't resolve to any known driver
        if (!shouldKill && killUnknown) {
            shouldKill = (!e.owner || wcscmp(e.owner, L"<unknown>") == 0);
        }

        if (shouldKill) {
            g_drv->Wr64(e.slotAddr, 0);
            printf("  %s[+] KILLED -- slot zeroed%s\n", A_GREEN, A_RESET);
            killed++;
        }
    }

    printf("\n  Total: %zu registry callbacks", v.size());
    if (killDriver || killKva || killUnknown) printf("  Killed: %d", killed);
    printf("\n\n");
}
