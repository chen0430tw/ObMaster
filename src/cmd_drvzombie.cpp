// cmd_drvzombie.cpp — /drv-zombie <drvobj_va>
//
// Diagnose why a driver is stuck in STOP_PENDING (zombie state).
// Reads OBJECT_HEADER, DRIVER_OBJECT, and the full DEVICE_OBJECT chain to
// explain what is holding the PointerCount above zero and blocking unload.
//
// Usage:
//   ObMaster /drv-zombie <drvobj_va>
//   ObMaster /objdir \Driver --kva <dir_va>   ← get drvobj_va first
//
// Typical zombie causes on Win10:
//   • DeviceObjects not yet deleted (each holds +1 ref to DRIVER_OBJECT)
//   • Minifilter / IoRegisterFsRegistrationChange still attached
//   • Open handles to a DeviceObject (DeviceObject.ReferenceCount > 0)
//   • ObRegisterCallbacks registration still live
//   • Pending IRPs keeping a DeviceObject alive

#define NOMINMAX
#include <Windows.h>
#include <cstdio>
#include <vector>
#include <string>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "ansi.h"

// ─── OBJECT_HEADER offsets ────────────────────────────────────────────────────
static const DWORD64 OH_SIZE         = 0x030; // sizeof OBJECT_HEADER
static const DWORD   OH_PointerCount = 0x000; // LONGLONG
static const DWORD   OH_HandleCount  = 0x008; // LONGLONG
static const DWORD   OH_TypeIndex    = 0x018; // BYTE
static const DWORD   OH_InfoMask     = 0x01A; // BYTE
static const DWORD   OH_Flags        = 0x01B; // BYTE  (OB_FLAG_*)

// ─── DRIVER_OBJECT offsets ────────────────────────────────────────────────────
static const DWORD DO_Type           = 0x000; // SHORT  (must be 4)
static const DWORD DO_Size           = 0x002; // SHORT
static const DWORD DO_DeviceObject   = 0x008; // Ptr64  (first DeviceObject or NULL)
static const DWORD DO_Flags          = 0x010; // ULONG
static const DWORD DO_DriverStart    = 0x018; // Ptr64
static const DWORD DO_DriverSize     = 0x020; // ULONG
static const DWORD DO_DriverSection  = 0x028; // Ptr64  (KLDR_DATA_TABLE_ENTRY)
static const DWORD DO_DriverExt      = 0x030; // Ptr64
static const DWORD DO_NameLen        = 0x038; // USHORT  (DriverName.Length)
static const DWORD DO_NameBuf        = 0x040; // Ptr64   (DriverName.Buffer)
static const DWORD DO_DriverInit     = 0x058; // Ptr64
static const DWORD DO_DriverUnload   = 0x068; // Ptr64
static const DWORD DO_MajorFunc      = 0x070; // Ptr64[28]

// DRIVER_OBJECT.Flags bits
static const DWORD DRVO_UNLOAD_INVOKED          = 0x001;
static const DWORD DRVO_LEGACY_DRIVER           = 0x002;
static const DWORD DRVO_BUILT_IN_DRIVER         = 0x004;
static const DWORD DRVO_REINIT_REGISTERED       = 0x008;
static const DWORD DRVO_INITIALIZED             = 0x010;
static const DWORD DRVO_BOOTRESET_REGISTERED    = 0x020;
static const DWORD DRVO_DELETIONS_PENDING       = 0x040;
static const DWORD DRVO_LOAD_IMAGE_NOTIFY       = 0x080;

// ─── DEVICE_OBJECT offsets ────────────────────────────────────────────────────
static const DWORD DEV_Type           = 0x000; // SHORT  (must be 3)
static const DWORD DEV_Size           = 0x002; // USHORT
static const DWORD DEV_ReferenceCount = 0x004; // LONG
static const DWORD DEV_DriverObject   = 0x008; // Ptr64  (back-pointer)
static const DWORD DEV_NextDevice     = 0x010; // Ptr64  (next in DriverObject chain)
static const DWORD DEV_AttachedDevice = 0x018; // Ptr64  (stack attachment)
static const DWORD DEV_CurrentIrp     = 0x020; // Ptr64
static const DWORD DEV_Flags          = 0x030; // ULONG
static const DWORD DEV_Characteristics= 0x034; // ULONG
static const DWORD DEV_Vpb            = 0x038; // Ptr64
static const DWORD DEV_DeviceExtension= 0x040; // Ptr64
static const DWORD DEV_DeviceType     = 0x048; // ULONG
static const DWORD DEV_StackSize      = 0x04C; // CHAR
static const DWORD DEV_SectorSize     = 0x0C0; // USHORT
static const DWORD DEV_DevObjExt      = 0x0C8; // Ptr64  (DEVOBJ_EXTENSION)

// DEVICE_OBJECT.Flags bits (common ones)
static const DWORD DO_BUFFERED_IO       = 0x004;
static const DWORD DO_DIRECT_IO         = 0x010;
static const DWORD DO_DEVICE_INITIALIZING = 0x80000000;

// ─── DEVOBJ_EXTENSION offsets ─────────────────────────────────────────────────
static const DWORD DEVEXT_Type        = 0x000; // SHORT  (must be 13)
static const DWORD DEVEXT_PowerFlags  = 0x010; // ULONG

// ─── helpers ─────────────────────────────────────────────────────────────────

static std::wstring ReadKernelUnicode(DWORD64 bufPtr, WORD lengthBytes) {
    if (!bufPtr || lengthBytes == 0 || lengthBytes > 0x400) return L"";
    WORD chars = lengthBytes / 2;
    std::wstring out(chars, L'\0');
    for (WORD i = 0; i < chars; i++) {
        DWORD64 qw = g_drv->Rd64(bufPtr + i * 2);
        out[i] = (wchar_t)(qw & 0xFFFF);
    }
    return out;
}

static const char* DeviceTypeName(ULONG t) {
    switch (t) {
        case  1: return "BEEP";
        case  2: return "CD_ROM";
        case  3: return "CD_ROM_FILE_SYSTEM";
        case  4: return "CONTROLLER";
        case  5: return "DATALINK";
        case  6: return "DFS";
        case  7: return "DISK";
        case  8: return "DISK_FILE_SYSTEM";
        case  9: return "FILE_SYSTEM";
        case 10: return "INPORT_PORT";
        case 11: return "KEYBOARD";
        case 12: return "MAILSLOT";
        case 13: return "MIDI_IN";
        case 14: return "MIDI_OUT";
        case 15: return "MOUSE";
        case 16: return "MULTI_UNC_PROVIDER";
        case 17: return "NAMED_PIPE";
        case 18: return "NETWORK";
        case 19: return "NETWORK_BROWSER";
        case 20: return "NETWORK_FILE_SYSTEM";
        case 21: return "NULL";
        case 22: return "PARALLEL_PORT";
        case 23: return "PHYSICAL_NETCARD";
        case 24: return "PRINTER";
        case 25: return "SCANNER";
        case 26: return "SERIAL_MOUSE_PORT";
        case 27: return "SERIAL_PORT";
        case 28: return "SCREEN";
        case 29: return "SOUND";
        case 30: return "STREAMS";
        case 31: return "TAPE";
        case 32: return "TAPE_FILE_SYSTEM";
        case 33: return "TRANSPORT";
        case 34: return "UNKNOWN";
        case 35: return "VIDEO";
        case 36: return "VIRTUAL_DISK";
        case 37: return "WAVE_IN";
        case 38: return "WAVE_OUT";
        case 39: return "8042_PORT";
        case 40: return "NETWORK_REDIRECTOR";
        case 41: return "BATTERY";
        case 42: return "BUS_EXTENDER";
        case 43: return "MODEM";
        case 44: return "VDM";
        case 45: return "MASS_STORAGE";
        case 46: return "SMB";
        case 47: return "KS";
        case 48: return "CHANGER";
        case 49: return "SMARTCARD";
        case 50: return "ACPI";
        case 51: return "DVD";
        case 52: return "FULLSCREEN_VIDEO";
        case 53: return "DFS_FILE_SYSTEM";
        case 54: return "DFS_VOLUME";
        case 55: return "SERENUM";
        case 56: return "TERMSRV";
        case 57: return "KSEC";
        case 58: return "FIPS";
        case 59: return "INFINIBAND";
        case 96: return "VMBUS";
        case 97: return "CRYPT_PROVIDER";
        case 98: return "WPD";
        case 99: return "BLUETOOTH";
        case 100:return "MT_COMPOSITE";
        case 101:return "MT_TRANSPORT";
        case 102:return "BIOMETRIC";
        case 103:return "PMI";
        default: return "?";
    }
}

// ─── /drv-zombie <drvobj_va> ──────────────────────────────────────────────────
void CmdDrvZombie(DWORD64 drvObjVA) {
    printf("%s[*]%s /drv-zombie  DRIVER_OBJECT = 0x%016llX\n\n", A_CYAN, A_RESET, drvObjVA);

    // ── 1. Validate DRIVER_OBJECT signature ──────────────────────────────────
    DWORD sig = g_drv->Rd32(drvObjVA + DO_Type);
    if (sig != 0x01500004) {
        printf("%s[!]%s DRIVER_OBJECT signature mismatch: 0x%08X (expected 0x01500004)\n",
               A_RED, A_RESET, sig);
        printf("    Wrong address? Get VA from: ObMaster /objdir \\Driver\n");
        return;
    }

    // ── 2. OBJECT_HEADER ─────────────────────────────────────────────────────
    DWORD64 hdr     = drvObjVA - OH_SIZE;
    LONGLONG ptrCnt = (LONGLONG)g_drv->Rd64(hdr + OH_PointerCount);
    LONGLONG hndCnt = (LONGLONG)g_drv->Rd64(hdr + OH_HandleCount);
    BYTE     typeIdx= (BYTE)(g_drv->Rd64(hdr + OH_TypeIndex) & 0xFF);
    BYTE     infoMsk= (BYTE)(g_drv->Rd64(hdr + OH_InfoMask)  & 0xFF);
    BYTE     objFlgs= (BYTE)(g_drv->Rd64(hdr + OH_Flags)     & 0xFF);

    printf("=== OBJECT_HEADER (0x%016llX) ===\n", hdr);
    printf("    PointerCount : %s%lld%s\n",
           ptrCnt > 1 ? A_YELLOW : A_GREEN, ptrCnt, A_RESET);
    printf("    HandleCount  : %lld\n", hndCnt);
    printf("    TypeIndex    : 0x%02X\n", typeIdx);
    printf("    InfoMask     : 0x%02X\n", infoMsk);
    printf("    ObjectFlags  : 0x%02X\n\n", objFlgs);

    // ── 3. DRIVER_OBJECT core fields ─────────────────────────────────────────
    DWORD   drvFlags  = (DWORD)(g_drv->Rd64(drvObjVA + DO_Flags) & 0xFFFFFFFF);
    DWORD64 devObjPtr = g_drv->Rd64(drvObjVA + DO_DeviceObject);
    DWORD64 drvUnload = g_drv->Rd64(drvObjVA + DO_DriverUnload);
    DWORD64 drvStart  = g_drv->Rd64(drvObjVA + DO_DriverStart);
    DWORD64 drvSect   = g_drv->Rd64(drvObjVA + DO_DriverSection);
    WORD    nameLen   = (WORD)(g_drv->Rd64(drvObjVA + DO_NameLen) & 0xFFFF);
    DWORD64 nameBuf   = g_drv->Rd64(drvObjVA + DO_NameBuf);

    std::wstring drvName = ReadKernelUnicode(nameBuf, nameLen);

    printf("=== DRIVER_OBJECT ===\n");
    printf("    DriverName   : %ls\n", drvName.c_str());
    printf("    DriverStart  : 0x%016llX\n", drvStart);
    printf("    DriverSection: 0x%016llX%s\n", drvSect,
           drvSect ? "" : "  (null — DKOM-unlinked from PsLoadedModuleList)");
    printf("    DriverUnload : 0x%016llX%s\n", drvUnload,
           drvUnload ? "" : "  (NULL — NOT_STOPPABLE)");
    printf("    Flags        : 0x%08X", drvFlags);

    if (drvFlags) {
        printf("  (");
        if (drvFlags & DRVO_UNLOAD_INVOKED)    printf("UNLOAD_INVOKED ");
        if (drvFlags & DRVO_LEGACY_DRIVER)     printf("LEGACY ");
        if (drvFlags & DRVO_BUILT_IN_DRIVER)   printf("BUILTIN ");
        if (drvFlags & DRVO_INITIALIZED)       printf("INITIALIZED ");
        if (drvFlags & DRVO_DELETIONS_PENDING) printf("%sDELETIONS_PENDING%s ", A_YELLOW, A_RESET);
        if (drvFlags & DRVO_REINIT_REGISTERED) printf("REINIT_REG ");
        if (drvFlags & DRVO_LOAD_IMAGE_NOTIFY) printf("IMAGE_NOTIFY ");
        printf(")");
    }
    printf("\n\n");

    // ── 4. Walk DeviceObject chain ────────────────────────────────────────────
    printf("=== DEVICE CHAIN ===\n");
    int devCount = 0;
    DWORD64 devPtr = devObjPtr;
    while (devPtr && devCount < 32) {
        SHORT  devType  = (SHORT)(g_drv->Rd64(devPtr + DEV_Type) & 0xFFFF);
        USHORT devSize  = (USHORT)((g_drv->Rd64(devPtr + DEV_Size) >> 16) & 0xFFFF);
        LONG   refCnt   = (LONG)(g_drv->Rd64(devPtr + DEV_ReferenceCount) & 0xFFFFFFFF);
        DWORD  devFlags = (DWORD)(g_drv->Rd64(devPtr + DEV_Flags) & 0xFFFFFFFF);
        DWORD  devChars = (DWORD)(g_drv->Rd64(devPtr + DEV_Characteristics) & 0xFFFFFFFF);
        DWORD64 attached= g_drv->Rd64(devPtr + DEV_AttachedDevice);
        DWORD64 vpb     = g_drv->Rd64(devPtr + DEV_Vpb);
        DWORD64 curIrp  = g_drv->Rd64(devPtr + DEV_CurrentIrp);
        DWORD   devType2= (DWORD)(g_drv->Rd64(devPtr + DEV_DeviceType) & 0xFFFFFFFF);
        CHAR    stkSz   = (CHAR)(g_drv->Rd64(devPtr + DEV_StackSize) & 0xFF);
        DWORD64 devObjExt = g_drv->Rd64(devPtr + DEV_DevObjExt);
        DWORD64 nextDev = g_drv->Rd64(devPtr + DEV_NextDevice);

        printf("  [%d] DeviceObject 0x%016llX\n", devCount, devPtr);
        if (devType != 3)
            printf("      %s[!] Type = %d (expected 3 = DEVICE_OBJECT)%s\n",
                   A_RED, devType, A_RESET);

        printf("      ReferenceCount  : %s%d%s\n",
               refCnt > 0 ? A_YELLOW : A_GREEN, refCnt, A_RESET);
        printf("      DeviceType      : %u (%s)\n", devType2, DeviceTypeName(devType2));
        printf("      StackSize       : %d\n", (int)stkSz);
        printf("      CurrentIrp      : 0x%016llX%s\n", curIrp,
               curIrp ? "  ← IRP pending!" : "");
        printf("      AttachedDevice  : 0x%016llX%s\n", attached,
               attached ? "  ← filter attached" : " (none)");
        printf("      Vpb             : 0x%016llX%s\n", vpb,
               vpb ? "  ← volume mounted" : "");

        printf("      Flags           : 0x%08X", devFlags);
        if (devFlags) {
            printf("  (");
            if (devFlags & 0x002)  printf("BUFFERED_IO ");
            if (devFlags & 0x010)  printf("DIRECT_IO ");
            if (devFlags & 0x100)  printf("SHUTDOWN_REG ");
            if (devFlags & 0x400)  printf("POWER_PAGABLE ");
            if (devFlags & 0x80000000) printf("%sDEVICE_INITIALIZING%s ", A_YELLOW, A_RESET);
            printf(")");
        }
        printf("\n");

        // DevObj extension (type must be 13)
        if (devObjExt && g_drv->IsKernelVA(devObjExt)) {
            SHORT extType = (SHORT)(g_drv->Rd64(devObjExt + DEVEXT_Type) & 0xFFFF);
            if (extType == 13) {
                DWORD powerFlags = (DWORD)(g_drv->Rd64(devObjExt + DEVEXT_PowerFlags) & 0xFFFFFFFF);
                printf("      DevObjExt @0x%016llX  PowerFlags=0x%08X\n",
                       devObjExt, powerFlags);
            }
        }

        devPtr = nextDev;
        devCount++;
        if (devPtr) printf("\n");
    }
    if (devCount == 0)
        printf("  (no DeviceObjects — chain is empty)\n");
    if (devPtr && devCount == 32)
        printf("  [!] Chain walk limit (32) hit — more devices may exist\n");

    // ── 5. Refcount analysis ──────────────────────────────────────────────────
    printf("\n=== REFCOUNT ANALYSIS ===\n");
    printf("    PointerCount = %lld\n\n", ptrCnt);

    //  Reference sources in a normal kernel:
    //   +1  ObCreateObject (initial, held until IoDeleteDriver / ObfDereferenceObject)
    //   +1  ObInsertObject inserted it into the \Driver directory
    //   +N  one per live DeviceObject (IoCreateDevice calls ObfReferenceObject)
    //   +?  ObRegisterCallbacks list for the driver (if any)
    //   +?  IoRegisterShutdownNotification (if DO_SHUTDOWN_REGISTERED set)
    //   +?  Handles (HandleCount tracks these separately)

    LONGLONG accounted = 1;  // object body always holds 1
    printf("    +1  object body (always)\n");

    if (hndCnt > 0) {
        printf("    +%lld handle(s) (from HandleCount)\n", hndCnt);
        accounted += hndCnt;
    }

    // Each DeviceObject in chain holds one reference
    printf("    +%d  DeviceObject(s) in chain (each holds one ref)\n", devCount);
    accounted += devCount;

    // Directory entry: ObInsertObject adds 1 if object has a name
    if (infoMsk & 0x02) {  // InfoMask bit 1 = has NAME_INFO
        printf("    +1  \\Driver directory entry (object has a name)\n");
        accounted++;
    } else {
        printf("    +0  no name info (already removed from directory or unnamed)\n");
    }

    // Check for shutdown registration
    {
        bool anyShutdown = false;
        DWORD64 dp = devObjPtr;
        int c = 0;
        while (dp && c++ < 32) {
            DWORD df = (DWORD)(g_drv->Rd64(dp + DEV_Flags) & 0xFFFFFFFF);
            if (df & 0x100) { anyShutdown = true; break; }
            dp = g_drv->Rd64(dp + DEV_NextDevice);
        }
        if (anyShutdown) {
            printf("    +1  IoRegisterShutdownNotification (DO_SHUTDOWN_REGISTERED)\n");
            accounted++;
        }
    }

    LONGLONG unaccounted = ptrCnt - accounted;
    printf("\n    Accounted: %lld  |  Unaccounted: %s%lld%s\n",
           accounted,
           unaccounted > 0 ? A_YELLOW : A_GREEN, unaccounted, A_RESET);

    if (unaccounted > 0) {
        printf("\n    %s[?]%s Possible extra ref sources:\n", A_YELLOW, A_RESET);
        printf("        • ObRegisterCallbacks registration still live\n");
        printf("        • IoGetRelatedDeviceObject caller hasn't released\n");
        printf("        • PsLoadedModuleList section reference (kernel image mapping)\n");
        printf("        • IoRegisterLastChanceShutdownNotification\n");
        printf("        • DRIVER_EXTENSION ref (IoAllocateDriverObjectExtension)\n");
    }

    // ── 6. Verdict ────────────────────────────────────────────────────────────
    printf("\n=== VERDICT ===\n");

    bool hasUnloadInvoked = (drvFlags & DRVO_UNLOAD_INVOKED) != 0;
    bool hasDeletions     = (drvFlags & DRVO_DELETIONS_PENDING) != 0;
    bool hasUnload        = (drvUnload != 0);

    if (ptrCnt <= 0) {
        printf("    %s[OK]%s PointerCount already zero — object should be freed shortly.\n",
               A_GREEN, A_RESET);
    } else if (hasUnloadInvoked && hasDeletions && devCount == 0) {
        printf("    %s[STUCK]%s UNLOAD_INVOKED + DELETIONS_PENDING, no DeviceObjects, "
               "but PointerCount=%lld\n", A_YELLOW, A_RESET, ptrCnt);
        printf("    → Something else holds references. Check ObRegisterCallbacks.\n");
    } else if (devCount > 0) {
        printf("    %s[BLOCKED]%s %d DeviceObject(s) are keeping the driver alive.\n",
               A_YELLOW, A_RESET, devCount);
        printf("    → Each DeviceObject must be cleaned up (IoDeleteDevice) for\n"
               "      PointerCount to reach zero and trigger IoDeleteDriver.\n");
        if (devCount <= 4) {
            printf("\n    DeviceObject addresses to investigate:\n");
            DWORD64 dp = devObjPtr;
            int c = 0;
            while (dp && c < devCount) {
                printf("        [%d] 0x%016llX\n", c++, dp);
                dp = g_drv->Rd64(dp + DEV_NextDevice);
            }
        }
    } else if (!hasUnload) {
        printf("    %s[STUCK]%s DriverUnload is NULL — NtUnloadDriver will refuse.\n",
               A_YELLOW, A_RESET);
        printf("    → Use /drv-unload %ls <VA> to patch a ret stub.\n", drvName.c_str());
    } else {
        printf("    %s[?]%s Cause unclear — PointerCount=%lld with no obvious holders.\n",
               A_YELLOW, A_RESET, ptrCnt);
    }

    printf("\n");
}
