#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"

// /patch <addr> <hexbytes>
// Write arbitrary bytes to a kernel address via RTCore64.
// Reads back before/after to verify.
// Example: /patch FFFFF80127ED31B4 33C0C39090
void CmdPatch(unsigned long long addr, const char* hexBytes) {
    // Parse hex string into byte array
    size_t hexLen = strlen(hexBytes);
    if (hexLen == 0 || hexLen % 2 != 0) {
        printf("[!] hex bytes must be even-length (e.g. 33C0C390)\n");
        return;
    }
    size_t byteCount = hexLen / 2;
    BYTE patch[64];
    if (byteCount > 64) { printf("[!] too many bytes (max 64)\n"); return; }

    for (size_t i = 0; i < byteCount; i++) {
        char buf[3] = { hexBytes[i*2], hexBytes[i*2+1], 0 };
        patch[i] = (BYTE)strtoul(buf, nullptr, 16);
    }

    printf("[*] Patching %zu byte(s) @ %016llX\n", byteCount, addr);

    // Read original bytes
    printf("    Before: ");
    for (size_t i = 0; i < byteCount; i++)
        printf("%02X ", g_drv->Rd8(addr + i));
    printf("\n");

    // Write patch bytes
    for (size_t i = 0; i < byteCount; i++)
        g_drv->Wr8(addr + i, patch[i]);

    // Verify readback
    printf("    After:  ");
    bool ok = true;
    for (size_t i = 0; i < byteCount; i++) {
        BYTE got = g_drv->Rd8(addr + i);
        printf("%02X ", got);
        if (got != patch[i]) ok = false;
    }
    printf("\n");

    if (ok)
        printf("  %s[+] Patch applied OK%s\n", A_GREEN, A_RESET);
    else
        printf("  %s[!] Readback mismatch — patch may have failed%s\n", A_RED, A_RESET);
}
