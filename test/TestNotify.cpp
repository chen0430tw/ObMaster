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
static uint64_t ScanExportForLEA(HMODULE hNt, const char* exportFn, int scanBytes = 256) {
    BYTE* fn = (BYTE*)GetProcAddress(hNt, exportFn);
    if (!fn) return 0;

    for (int i = 0; i < scanBytes - 6; i++) {
        if ((fn[i] == 0x48 || fn[i] == 0x4C) &&
             fn[i+1] == 0x8D &&
            (fn[i+2] & 0xC7) == 0x05)
        {
            INT32 disp      = *(INT32*)(fn + i + 3);
            uint64_t userTgt = (uint64_t)(fn + i + 7) + (int64_t)disp;
            uint64_t rva     = userTgt - (uint64_t)hNt;
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
        struct { const char* fn; const char* label; } scans[] = {
            { "PsRemoveLoadImageNotifyRoutine",     "PspLoadImageNotifyRoutine"    },
            { "PsSetCreateProcessNotifyRoutineEx",  "PspCreateProcessNotifyRoutine"},
            { "PsRemoveCreateThreadNotifyRoutine",  "PspCreateThreadNotifyRoutine" },
        };

        // Get ntoskrnl image size to bound valid RVAs
        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), hNt, &mi, sizeof(mi));
        uint64_t imageSize = mi.SizeOfImage;

        for (auto& s : scans) {
            uint64_t rva = ScanExportForLEA(hNt, s.fn);
            if (rva == 0) {
                printf("  [FAIL] %s — LEA not found in %s\n", s.label, s.fn);
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
