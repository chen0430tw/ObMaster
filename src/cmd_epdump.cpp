#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include "kutil.h"
#include "driver/IDriverBackend.h"

// ─── /epdump <pid> ────────────────────────────────────────────────────────────
// Diagnostic tool: dumps EPROCESS memory at candidate offsets and compares
// against user-mode PPID (from Toolhelp) to find the correct PPID offset.
// Also shows raw QWORD values at offsets 0x440..0x600 in 8-byte steps.

void CmdEpDump(DWORD pid) {
    // Get user-mode PPID via Toolhelp for comparison
    DWORD umPpid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe{ sizeof(pe) };
        if (Process32First(snap, &pe))
            do {
                if (pe.th32ProcessID == pid) { umPpid = pe.th32ParentProcessID; break; }
            } while (Process32Next(snap, &pe));
        CloseHandle(snap);
    }

    DWORD64 ep = KUtil::FindEPROCESS(pid);
    if (!ep) { printf("[!] EPROCESS not found for pid %u\n", pid); return; }

    printf("\n[*] EPROCESS for pid=%u @ 0x%llx\n", pid, (unsigned long long)ep);
    printf("[*] User-mode PPID (Toolhelp) = %u  (0x%x)\n\n", umPpid, umPpid);
    printf("%-8s  %-18s  %-18s  %s\n", "Offset", "QWORD value", "Lo32 (DWORD)", "Note");
    printf("%s\n", "---------------------------------------------------------------");

    for (DWORD off = 0x430; off <= 0x600; off += 8) {
        DWORD64 val64 = g_drv->Rd64(ep + off);
        DWORD   val32 = (DWORD)(val64 & 0xFFFFFFFF);
        const char* note = "";
        if (off == KUtil::EP_UniqueProcessId)              note = "<-- UniqueProcessId";
        else if (off == KUtil::EP_ActiveProcessLinks)      note = "<-- ActiveProcessLinks.Flink";
        else if (off == KUtil::EP_InheritedFromUniqueProcessId) note = "<-- current PPID offset";
        else if (val32 == umPpid && umPpid != 0)           note = "<<< PPID MATCH (user-mode value)";
        else if (val32 == pid)                             note = "<-- (self PID)";

        printf("+0x%03x   0x%016llx  0x%08x        %s\n",
            off, (unsigned long long)val64, val32, note);
    }
    printf("\n");
}
