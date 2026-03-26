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
struct NtoskrnlImage {
    std::vector<BYTE> buf;
    DWORD64           kBase   = 0;
    DWORD             textRVA = 0, textFOA = 0, textSz = 0;
    DWORD             dataRVA = 0, dataEnd = 0;
    bool              ok      = false;
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

    auto* sec = IMAGE_FIRST_SECTION(nt); WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; i++) {
        char name[9] = {}; memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            img.textRVA = sec[i].VirtualAddress;
            img.textFOA = sec[i].PointerToRawData;
            img.textSz  = sec[i].SizeOfRawData;
        } else if (strcmp(name, ".data") == 0) {
            img.dataRVA = sec[i].VirtualAddress;
            img.dataEnd = img.dataRVA + sec[i].Misc.VirtualSize; // includes BSS
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

    for (DWORD i = img.textFOA; i + 4 < end; i++) {
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

        // Found anchor.  Scan a window of [-8, +56] bytes around it.
        DWORD wStart = (i > img.textFOA + 8) ? (i - 8) : img.textFOA;
        DWORD wEnd   = ((i + 56 + 7) < end)  ? (i + 56) : (end - 7);

        for (DWORD j = wStart; j < wEnd; j++) {
            // MmPteBase is the base that gets ADDED to the PTE index.
            // Only count ADD r64,[rip+X] (opcode 0x03) to filter out
            // RIP-relative MOVs that load unrelated variables.
            if (j + 6 >= end) continue;
            BYTE rex = buf[j], op = buf[j+1], modrm = buf[j+2];
            if (rex != 0x48 && rex != 0x4C) continue;
            if (op != 0x03) continue; // ADD only
            if ((modrm & 0xC7) != 0x05) continue; // mod=00, r/m=101 (RIP-rel)
            INT32 off32    = *reinterpret_cast<const INT32*>(&buf[j + 3]);
            DWORD instrRVA = (j - img.textFOA) + img.textRVA;
            DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
            if (targetRVA >= img.dataRVA && targetRVA < img.dataEnd)
                hits[targetRVA]++;
        }
    }
    if (hits.empty()) return 0;

    // Sort by hit count descending and validate runtime values.
    std::vector<std::pair<int,DWORD>> ranked;
    for (auto& kv : hits) ranked.push_back({kv.second, kv.first});
    std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b){ return a.first > b.first; });

    static const DWORD64 ALIGN_512G = (1ULL << 39) - 1;
    for (auto& [cnt, rva] : ranked) {
        DWORD64 varVA = img.kBase + rva;
        DWORD64 val   = g_drv->Rd64(varVA);
        if (g_drv->IsKernelVA(val) && (val & ALIGN_512G) == 0) {
            printf("[pte] MiGetPteAddr pattern: RVA=0x%08X hits=%d  MmPteBase=0x%016llX\n",
                   rva, cnt, val);
            return varVA;
        }
        if (g_debug)
            printf("[pte] MiGetPteAddr pattern: RVA=0x%08X hits=%d  val=0x%016llX (skip)\n",
                   rva, cnt, val);
    }
    printf("[pte] MiGetPteAddr pattern: no valid candidate\n");
    return 0;
}

// ── Method 1b: CR3 physical walk via MmPfnDatabase ───────────────────────────
//
// Reads EPROCESS.DirectoryTableBase (CR3 physical) for the System process,
// then follows the PFN database entry for that physical page to recover
// the PteAddress field (_MMPFN+0x18).  PteAddress is always inside the PTE
// self-map, so masking off the low 39 bits directly yields MmPteBase.
//
// This method does not touch ntoskrnl.exe on disk and makes only ~5 kernel
// reads, making it both fast and precise.  It is attempted before the
// heuristic disk-scan methods.
//
// Win10 22H2 x64 offsets used:
//   EPROCESS.Pcb.DirectoryTableBase = +0x28  (_KPROCESS first member)
//   _MMPFN.PteAddress               = +0x18  (stable since Vista)
//   sizeof(_MMPFN)                  = 0x30
//
// Returns the kernel VA of the MmPteBase *variable* (0 on failure).
static DWORD64 FindMmPteBaseByPhysWalk() {
    // 1. System process EPROCESS
    DWORD64 sysEPROCESS = g_drv->Rd64(KUtil::KernelExport("PsInitialSystemProcess"));
    if (!g_drv->IsKernelVA(sysEPROCESS)) return 0;

    // 2. CR3 = DirectoryTableBase at EPROCESS+0x28 (_KPROCESS.DirectoryTableBase)
    DWORD64 cr3 = g_drv->Rd64(sysEPROCESS + 0x28);
    if (!cr3) return 0;
    // Bits[11:0] may hold PCID (if CR4.PCIDE set); physical PFN is always bits[63:12]
    DWORD64 pfn = cr3 >> 12;

    // 3. MmPfnDatabase: exported MMPFN* (points at the start of the PFN array)
    DWORD64 pfnDbVarVA = KUtil::KernelExport("MmPfnDatabase");
    if (!pfnDbVarVA) return 0;
    DWORD64 pfnArray = g_drv->Rd64(pfnDbVarVA);
    if (!g_drv->IsKernelVA(pfnArray)) return 0;

    // 4. _MMPFN entry for the PML4 page: each entry is 0x30 bytes
    DWORD64 pfnEntryVA = pfnArray + pfn * 0x30;
    if (!g_drv->IsKernelVA(pfnEntryVA)) return 0;

    // 5. PteAddress field at _MMPFN+0x18 — points into the PTE self-map
    DWORD64 pteAddr = g_drv->Rd64(pfnEntryVA + 0x18);
    if (!g_drv->IsKernelVA(pteAddr)) return 0;

    // 6. MmPteBase = pteAddr with lower 39 bits cleared (self-map is 512GB-aligned)
    //    pteAddr is inside [MmPteBase, MmPteBase + 2^39), so masking recovers the base.
    DWORD64 candidate = pteAddr & ~((1ULL << 39) - 1);   // clear bits [38:0]
    if (!g_drv->IsKernelVA(candidate)) return 0;
    if (candidate & ((1ULL << 39) - 1)) return 0;        // must be 512 GB-aligned

    if (g_debug)
        printf("[pte] PhysWalk: cr3=0x%016llX pfn=0x%llX pfnEntry=0x%016llX pteAddr=0x%016llX\n",
               cr3, pfn, pfnEntryVA, pteAddr);

    printf("[pte] MmPteBase = 0x%016llX (via CR3/MmPfnDatabase)\n", candidate);
    return candidate;   // returns the VALUE directly (not a varVA); caller stores it
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

    // Count RIP-relative 64-bit loads (MOV r64,[RIP+imm32]) targeting .data
    std::map<DWORD, int> refCnt;
    DWORD end = img.textFOA + img.textSz;
    for (DWORD i = img.textFOA; i + 7 < end; i++) {
        DWORD rva = DecodeRipRelDataRef(buf, i, img.textFOA, img.textRVA, img.dataRVA, img.dataEnd);
        if (rva) refCnt[rva]++;
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
    if (topN[0].first < 50) return 0;  // nothing looks plausible

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

    // ── Method 0: CR3/MmPfnDatabase physical walk (most reliable) ────────────
    // Reads the System process DirectoryTableBase, finds the PFN database entry
    // for the PML4 page, and recovers MmPteBase from the stored PteAddress field.
    // Returns the VALUE directly (not a varVA).
    {
        DWORD64 val = FindMmPteBaseByPhysWalk();
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
        NtoskrnlImage img = LoadNtoskrnl();

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
    // ── Section 0: CR3/MmPfnDatabase physical walk ───────────────────────────
    printf("=== Method 0: CR3 / MmPfnDatabase physical walk ===\n\n");
    {
        DWORD64 sysEP = g_drv->Rd64(KUtil::KernelExport("PsInitialSystemProcess"));
        if (!g_drv->IsKernelVA(sysEP)) {
            printf("  [!] PsInitialSystemProcess unavailable\n\n");
        } else {
            DWORD64 cr3      = g_drv->Rd64(sysEP + 0x28);
            DWORD64 pfn      = cr3 >> 12;
            DWORD64 pfnDbVar = KUtil::KernelExport("MmPfnDatabase");
            DWORD64 pfnArray = pfnDbVar ? g_drv->Rd64(pfnDbVar) : 0;
            DWORD64 pfnEntry = g_drv->IsKernelVA(pfnArray) ? pfnArray + pfn * 0x30 : 0;
            DWORD64 pteAddr  = pfnEntry ? g_drv->Rd64(pfnEntry + 0x18) : 0;
            DWORD64 derived  = pteAddr  ? (pteAddr & ~((1ULL << 39) - 1)) : 0;

            printf("  System EPROCESS:  0x%016llX\n", sysEP);
            printf("  DirectoryTableBase (CR3): 0x%016llX  (PFN = 0x%llX)\n", cr3, pfn);
            printf("  MmPfnDatabase ptr: 0x%016llX  (array @ 0x%016llX)\n", pfnDbVar, pfnArray);
            printf("  PFN entry VA:      0x%016llX\n", pfnEntry);
            printf("  PteAddress field:  0x%016llX\n", pteAddr);
            printf("  Derived MmPteBase: 0x%016llX  %s\n\n", derived,
                   g_drv->IsKernelVA(derived) ? "*** CANDIDATE ***" : "(invalid)");
        }
    }

    NtoskrnlImage img = LoadNtoskrnl();
    if (!img.ok) { printf("[!] Failed to load ntoskrnl.exe\n"); return; }
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
    // Strip sign extension bits (keep low 48 bits for the shift)
    DWORD64 idx = (va & 0x0000FFFFFFFFFFFFULL) >> 9;
    return base + idx;
}

PteInfo ReadPte(DWORD64 va) {
    PteInfo info{};
    info.pte_va = PteVaOf(va);
    if (!info.pte_va || !g_drv->IsKernelVA(info.pte_va)) {
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

    // Attempt a true 8-byte atomic write.
    //
    // On x86-64, an aligned 8-byte store is single-copy atomic (Intel SDM §8.2.3.1).
    // PTEs are 8-byte aligned by construction (PTE array is a contiguous QWORD[]).
    //
    // RTCore64Backend::Wr64Atomic sends IOCTL_WRITE with Size=8.  If the kernel
    // handler does *(QWORD*)addr = *(QWORD*)&op->Value it becomes one MOV QWORD →
    // no window of inconsistency at all.  If the driver rejects Size=8 it falls back
    // to the hi→lo two-write sequence (Present=1 throughout, brief PA inconsistency).
    //
    // Either way the write completes before this function returns.
    bool atomic = g_drv->Wr64Atomic(pteVA, newPteVal);
    printf("[pte] WritePte VA=0x%016llX PTE=0x%016llX (%s)\n",
           va, newPteVal, atomic ? "ATOMIC 8B" : "hi-lo fallback");
    return true;
}
