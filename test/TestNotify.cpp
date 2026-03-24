// TestNotify.cpp
// Validates cmd_notify internals WITHOUT any kernel access.
//
// Tests:
//   1. DecodeRef (EX_FAST_REF low-4-bit mask)
//   2. EX_CALLBACK_ROUTINE_BLOCK layout — mock struct offset check
//   3. FindArrayViaExport LEA scan on real ntoskrnl.exe exports
//      (no kernel read/write — only user-mode DLL load + byte scan)
//
// Safe to run as a normal user-mode process with no driver loaded.
// Compile: build_test_notify.bat

#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <cstdint>
#include <cassert>

// ── Reproduce the same helpers from cmd_notify.cpp ────────────────────────────

static inline uint64_t DecodeRef(uint64_t ref) { return ref & ~(uint64_t)0xF; }

// Returns the RVA of the Psp*NotifyRoutine array found inside exportFn,
// or 0 on failure.  Pure user-mode: loads ntoskrnl.exe as a DLL, byte-scans.
// Get .data section RVA range from PE headers
static bool GetDataSection(HMODULE hNt, uint64_t* base, uint64_t* end) {
    auto* dos = (IMAGE_DOS_HEADER*)hNt;
    auto* nt  = (IMAGE_NT_HEADERS64*)((BYTE*)hNt + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        char name[9]{}; memcpy(name, sec->Name, 8);
        if (_stricmp(name, ".data") == 0) {
            *base = sec->VirtualAddress;
            *end  = sec->VirtualAddress + sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static uint64_t ScanExportForLEA(HMODULE hNt, const char* exportFn,
                                  uint64_t skipRVA  = 0,
                                  uint64_t dataBase = 0,
                                  uint64_t dataEnd  = 0,
                                  int scanBytes     = 512) {
    BYTE* fn = (BYTE*)GetProcAddress(hNt, exportFn);
    if (!fn) return 0;

    for (int i = 0; i < scanBytes - 6; i++) {
        if ((fn[i] == 0x48 || fn[i] == 0x4C) &&
             fn[i+1] == 0x8D &&
            (fn[i+2] & 0xC7) == 0x05)
        {
            INT32 disp       = *(INT32*)(fn + i + 3);
            uint64_t userTgt = (uint64_t)(fn + i + 7) + (int64_t)disp;
            uint64_t rva     = userTgt - (uint64_t)hNt;
            if (rva == skipRVA) continue;
            if (dataBase != dataEnd && !(rva >= dataBase && rva < dataEnd)) continue;
            return rva;
        }
    }
    return 0;
}

// ── Mock EX_CALLBACK_ROUTINE_BLOCK to verify offsets ─────────────────────────

#pragma pack(push, 1)
struct MockECRB {
    uint64_t RundownProtect;  // +0x00
    uint64_t Function;        // +0x08  ← what CmdNotify reads
    uint64_t Context;         // +0x10
};
#pragma pack(pop)

// ── Test runner ───────────────────────────────────────────────────────────────

static int g_pass = 0, g_fail = 0;

#define CHECK(expr, desc) do { \
    if (expr) { printf("  [PASS] %s\n", desc); g_pass++; } \
    else      { printf("  [FAIL] %s\n", desc); g_fail++; } \
} while(0)

int main() {
    SetConsoleOutputCP(CP_UTF8);
    printf("\n=== TestNotify ===\n\n");

    // ── 1. DecodeRef ──────────────────────────────────────────────────────────
    printf("[1] DecodeRef (EX_FAST_REF mask)\n");
    CHECK(DecodeRef(0) == 0,
          "DecodeRef(0) == 0");
    CHECK(DecodeRef(0xFFFFF80012345670ULL) == 0xFFFFF80012345670ULL,
          "already aligned pointer unchanged");
    CHECK(DecodeRef(0xFFFFF80012345677ULL) == 0xFFFFF80012345670ULL,
          "low 4 bits stripped (refcount=7)");
    CHECK(DecodeRef(0xFFFFF8001234567FULL) == 0xFFFFF80012345670ULL,
          "low 4 bits stripped (refcount=0xF)");
    CHECK(DecodeRef(0xFFFFF80012345671ULL) == 0xFFFFF80012345670ULL,
          "low 4 bits stripped (refcount=1)");

    // ── 2. EX_CALLBACK_ROUTINE_BLOCK layout ───────────────────────────────────
    printf("\n[2] EX_CALLBACK_ROUTINE_BLOCK offset check\n");
    MockECRB blk{};
    blk.Function = 0xDEADBEEFCAFEBABEULL;
    BYTE* base = (BYTE*)&blk;
    uint64_t fnFromOffset = *(uint64_t*)(base + 0x08);
    CHECK(fnFromOffset == 0xDEADBEEFCAFEBABEULL,
          "Function field is at offset +0x08");
    CHECK(sizeof(MockECRB) == 0x18,
          "struct is 0x18 bytes (RundownProtect+Function+Context)");
    CHECK(offsetof(MockECRB, Function) == 0x08,
          "offsetof(Function) == 0x08");

    // ── 3. LEA scan on real ntoskrnl.exe exports ──────────────────────────────
    printf("\n[3] LEA scan on ntoskrnl.exe exports\n");

    HMODULE hNt = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNt) {
        printf("  [SKIP] Cannot load ntoskrnl.exe (error %lu)\n", GetLastError());
    } else {
        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), hNt, &mi, sizeof(mi));
        uint64_t imageSize = mi.SizeOfImage;

        uint64_t dataBase = 0, dataEnd = 0;
        GetDataSection(hNt, &dataBase, &dataEnd);
        printf("  [info] .data section RVA: 0x%llx - 0x%llx\n",
               (unsigned long long)dataBase, (unsigned long long)dataEnd);

        uint64_t rvaImage = ScanExportForLEA(hNt, "PsRemoveLoadImageNotifyRoutine",
                                             0, dataBase, dataEnd);
        // Try multiple exports; the Ex version may not have a direct LEA in .data
        uint64_t rvaProc = ScanExportForLEA(hNt, "PsSetCreateProcessNotifyRoutine",
                                            rvaImage, dataBase, dataEnd);
        if (!rvaProc)
            rvaProc = ScanExportForLEA(hNt, "PsSetCreateProcessNotifyRoutineEx",
                                       rvaImage, dataBase, dataEnd);
        uint64_t rvaThr   = ScanExportForLEA(hNt, "PsRemoveCreateThreadNotifyRoutine",
                                             0, dataBase, dataEnd);

        struct { const char* label; uint64_t rva; } scans[] = {
            { "PspLoadImageNotifyRoutine",     rvaImage },
            { "PspCreateProcessNotifyRoutine", rvaProc  },
            { "PspCreateThreadNotifyRoutine",  rvaThr   },
        };

        // Also verify all three RVAs are distinct
        CHECK(rvaImage != rvaProc,  "LoadImage != CreateProcess array");
        CHECK(rvaImage != rvaThr,   "LoadImage != CreateThread array");
        CHECK(rvaProc  != rvaThr,   "CreateProcess != CreateThread array");

        for (auto& s : scans) {
            uint64_t rva = s.rva;
            if (rva == 0) {
                printf("  [FAIL] %s — LEA not found\n", s.label);
                g_fail++;
                continue;
            }
            // The array lives in ntoskrnl's .data section; RVA must be within image
            bool inImage = (rva < imageSize);
            printf("  %s %s — RVA=0x%llx  (%s)\n",
                inImage ? "[PASS]" : "[FAIL]",
                s.label,
                (unsigned long long)rva,
                inImage ? "within image" : "OUT OF IMAGE");
            if (inImage) g_pass++; else g_fail++;
        }

        FreeLibrary(hNt);
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    printf("\n=== Results: %d passed, %d failed ===\n\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
