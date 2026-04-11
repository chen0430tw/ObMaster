// cmd_misc.cpp -- /info, /whoami, /acl
//
// Miscellaneous utilities that don't require RTCore64.

#include <Windows.h>
#include <winternl.h>
#include <Sddl.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"
#include "kutil.h"

// ── /info ────────────────────────────────────────────────────────────────────
void CmdInfo() {
    // OS version
    typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    auto RtlGetVer = (RtlGetVersion_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

    RTL_OSVERSIONINFOW ver = {};
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (RtlGetVer) RtlGetVer(&ver);

    printf("  %sSystem%s\n", A_BOLD, A_RESET);
    printf("    OS:       Windows %lu.%lu Build %lu\n",
           ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber);

    // Computer name
    char comp[256] = {};
    DWORD compSz = sizeof(comp);
    GetComputerNameA(comp, &compSz);
    printf("    Host:     %s\n", comp);

    // Architecture
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) arch = "x64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) arch = "x86";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) arch = "ARM64";
    printf("    Arch:     %s (%lu CPUs)\n", arch, si.dwNumberOfProcessors);

    // Memory
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    printf("    RAM:      %.1f GB total, %.1f GB free\n",
           mem.ullTotalPhys / (1024.0*1024*1024),
           mem.ullAvailPhys / (1024.0*1024*1024));

    // Uptime
    ULONGLONG tickMs = GetTickCount64();
    ULONGLONG h = tickMs / 3600000;
    ULONGLONG m = (tickMs % 3600000) / 60000;
    printf("    Uptime:   %lluh %llum\n", h, m);

    // Kernel base
    LPVOID drvs[1]; DWORD cb;
    if (EnumDeviceDrivers(drvs, sizeof(drvs), &cb) && drvs[0]) {
        printf("\n  %sKernel%s\n", A_BOLD, A_RESET);
        printf("    ntoskrnl: 0x%016llX\n", (DWORD64)drvs[0]);
    }

    // RTCore64 status
    printf("\n  %sRTCore64%s\n", A_BOLD, A_RESET);
    HANDLE hDev = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDev != INVALID_HANDLE_VALUE) {
        printf("    Status:   %sLOADED%s (device open OK)\n", A_GREEN, A_RESET);
        CloseHandle(hDev);
    } else {
        DWORD err = GetLastError();
        if (err == 2)
            printf("    Status:   %sNOT LOADED%s (device not found)\n", A_RED, A_RESET);
        else
            printf("    Status:   %sERROR %lu%s\n", A_YELLOW, err, A_RESET);
    }

    // Driver count
    LPVOID allDrvs[2048]; DWORD cb2;
    if (EnumDeviceDrivers(allDrvs, sizeof(allDrvs), &cb2))
        printf("    Drivers:  %u loaded\n", (unsigned)(cb2 / sizeof(LPVOID)));

    printf("\n");
}

// ── /whoami ──────────────────────────────────────────────────────────────────
void CmdWhoami() {
    DWORD pid = GetCurrentProcessId();
    char exeName[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exeName, MAX_PATH);
    const char* basename = strrchr(exeName, '\\');
    basename = basename ? basename + 1 : exeName;

    printf("  %sProcess%s\n", A_BOLD, A_RESET);
    printf("    PID:      %lu\n", pid);
    printf("    Name:     %s\n", basename);

    // Token info
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("    Token:    %s(cannot open)%s\n", A_RED, A_RESET);
        return;
    }

    // User SID
    BYTE userBuf[256];
    DWORD sz = sizeof(userBuf);
    if (GetTokenInformation(hToken, TokenUser, userBuf, sz, &sz)) {
        TOKEN_USER* tu = (TOKEN_USER*)userBuf;
        LPSTR sidStr = nullptr;
        ConvertSidToStringSidA(tu->User.Sid, &sidStr);

        char name[256] = {}, domain[256] = {};
        DWORD nameSz = sizeof(name), domSz = sizeof(domain);
        SID_NAME_USE use;
        LookupAccountSidA(nullptr, tu->User.Sid, name, &nameSz, domain, &domSz, &use);

        printf("\n  %sIdentity%s\n", A_BOLD, A_RESET);
        printf("    User:     %s\\%s\n", domain, name);
        printf("    SID:      %s\n", sidStr ? sidStr : "?");
        if (sidStr) LocalFree(sidStr);
    }

    // Integrity level
    BYTE ilBuf[256];
    sz = sizeof(ilBuf);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, ilBuf, sz, &sz)) {
        TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)ilBuf;
        DWORD* subAuth = GetSidSubAuthority(tml->Label.Sid,
                         *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        const char* level = "Unknown";
        if (*subAuth >= 0x4000) level = "System";
        else if (*subAuth >= 0x3000) level = "High";
        else if (*subAuth >= 0x2000) level = "Medium";
        else if (*subAuth >= 0x1000) level = "Low";
        else level = "Untrusted";
        printf("    Integrity: %s (0x%lX)\n", level, *subAuth);
    }

    // Elevation
    TOKEN_ELEVATION elev = {};
    sz = sizeof(elev);
    if (GetTokenInformation(hToken, TokenElevation, &elev, sz, &sz)) {
        printf("    Elevated: %s\n", elev.TokenIsElevated ? "Yes" : "No");
    }

    // Session
    DWORD session = 0;
    sz = sizeof(session);
    GetTokenInformation(hToken, TokenSessionId, &session, sz, &sz);
    printf("    Session:  %lu\n", session);

    // Privileges
    BYTE privBuf[2048];
    sz = sizeof(privBuf);
    if (GetTokenInformation(hToken, TokenPrivileges, privBuf, sz, &sz)) {
        TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)privBuf;
        int enabled = 0, total = tp->PrivilegeCount;
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) enabled++;
        }
        printf("\n  %sPrivileges%s\n", A_BOLD, A_RESET);
        printf("    Total:    %d (%d enabled)\n", total, enabled);

        // Show key privileges
        const char* key_privs[] = {
            "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
            "SeRestorePrivilege", "SeShutdownPrivilege", "SeTcbPrivilege",
            "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", nullptr
        };
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            char name[128] = {};
            DWORD nameSz = sizeof(name);
            LookupPrivilegeNameA(nullptr, &tp->Privileges[i].Luid, name, &nameSz);
            for (int k = 0; key_privs[k]; k++) {
                if (_stricmp(name, key_privs[k]) == 0) {
                    bool on = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                    printf("    %s%-35s%s %s%s%s\n",
                           on ? A_GREEN : A_DIM, name, A_RESET,
                           on ? A_GREEN : A_DIM, on ? "ENABLED" : "disabled", A_RESET);
                }
            }
        }
    }

    CloseHandle(hToken);
    printf("\n");
}

// ── /acl <target> ────────────────────────────────────────────────────────────
// Detect target type and show security descriptor / DACL.
// Supports: file/directory path, service name (svc:xxx), process PID (pid:NNN)

static void PrintAcl(PACL pAcl, const char* label) {
    if (!pAcl) { printf("    %s: (NULL -- no DACL, full access)\n", label); return; }

    ACL_SIZE_INFORMATION aclInfo = {};
    GetAclInformation(pAcl, &aclInfo, sizeof(aclInfo), AclSizeInformation);
    printf("    %s: %lu ACEs\n", label, aclInfo.AceCount);

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = nullptr;
        if (!GetAce(pAcl, i, &pAce)) continue;

        ACE_HEADER* hdr = (ACE_HEADER*)pAce;
        PSID sid = nullptr;
        DWORD access = 0;
        const char* type = "?";

        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE* ace = (ACCESS_ALLOWED_ACE*)pAce;
            sid = &ace->SidStart;
            access = ace->Mask;
            type = "ALLOW";
        } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE* ace = (ACCESS_DENIED_ACE*)pAce;
            sid = &ace->SidStart;
            access = ace->Mask;
            type = "DENY";
        } else {
            printf("      [%lu] type=%u (unsupported)\n", i, hdr->AceType);
            continue;
        }

        // Resolve SID to name
        char name[256] = {}, domain[256] = {};
        DWORD nameSz = sizeof(name), domSz = sizeof(domain);
        SID_NAME_USE use;
        if (!LookupAccountSidA(nullptr, sid, name, &nameSz, domain, &domSz, &use)) {
            LPSTR sidStr = nullptr;
            ConvertSidToStringSidA(sid, &sidStr);
            snprintf(name, sizeof(name), "%s", sidStr ? sidStr : "?");
            domain[0] = 0;
            if (sidStr) LocalFree(sidStr);
        }

        // Format rwx-style permissions (like Linux ls -l)
        // Generic rights: 0x80000000=READ 0x40000000=WRITE 0x20000000=EXECUTE 0x10000000=ALL
        // File-specific: 0x01=READ_DATA 0x02=WRITE_DATA 0x04=APPEND 0x20=EXECUTE
        //                0x80=READ_ATTR 0x100=WRITE_ATTR 0x10000=DELETE 0x20000=READ_CONTROL
        char rwx[16] = "---";
        if (access & 0x80000001) rwx[0] = 'r';  // GENERIC_READ or FILE_READ_DATA
        if (access & 0x40000006) rwx[1] = 'w';  // GENERIC_WRITE or FILE_WRITE_DATA/APPEND
        if (access & 0x20000020) rwx[2] = 'x';  // GENERIC_EXECUTE or FILE_EXECUTE
        if (access & 0x10000000) { rwx[0]='r'; rwx[1]='w'; rwx[2]='x'; } // GENERIC_ALL
        if (access == 0x1F01FF)  { rwx[0]='r'; rwx[1]='w'; rwx[2]='x'; } // FILE_ALL_ACCESS
        if (access & 0x10000)    strcat(rwx, "+D"); // DELETE

        const char* color = (hdr->AceType == ACCESS_DENIED_ACE_TYPE) ? A_RED : A_GREEN;
        printf("      %s[%s]%s %s%-5s%s  0x%08lX  %s%s%s\n",
               color, type, A_RESET,
               color, rwx, A_RESET,
               access,
               domain[0] ? domain : "", domain[0] ? "\\" : "", name);
    }
}

void CmdAcl(const char* target) {
    if (!target || !target[0]) {
        printf("Usage: /acl <path|svc:name|pid:N>\n"
               "  /acl C:\\Windows\\System32\\cmd.exe    (file/directory)\n"
               "  /acl svc:RTCore64                    (service)\n"
               "  /acl pid:1234                        (process)\n");
        return;
    }

    // ── pid:NNN ──
    if (_strnicmp(target, "pid:", 4) == 0) {
        DWORD pid = atoi(target + 4);
        HANDLE hProc = OpenProcess(READ_CONTROL, FALSE, pid);

        // Fallback: if OpenProcess fails (PPL, System, etc.), try kernel path
        if (!hProc && g_drv) {
            printf("[*] OpenProcess failed (PPL?), trying kernel EPROCESS walk...\n");
            KUtil::BuildDriverCache();
            DWORD64 ep = KUtil::FindEPROCESS(pid);
            if (!ep) {
                printf("%s[!]%s EPROCESS not found for PID %lu\n", A_RED, A_RESET, pid);
                return;
            }

            // Read EPROCESS fields directly
            char imgName[16] = {};
            for (int i = 0; i < 15; i++)
                imgName[i] = (char)g_drv->Rd8(ep + 0x5a8 + i);
            BYTE prot = g_drv->Rd8(ep + 0x87a);

            // Read Token (EX_FAST_REF at +0x4b8)
            DWORD64 tokenRef = g_drv->Rd64(ep + 0x4b8);
            DWORD64 tokenPtr = tokenRef & ~(DWORD64)0xF;

            printf("  Process PID %lu (%s)\n", pid, imgName);
            printf("    EPROCESS:   0x%016llX\n", ep);
            printf("    Protection: 0x%02X (%s)\n", prot, KUtil::ProtectionStr(prot));
            printf("    Token:      0x%016llX\n", tokenPtr);

            // Read SecurityDescriptor from OBJECT_HEADER
            // OBJECT_HEADER is at EPROCESS - 0x30
            // SecurityDescriptor at OBJECT_HEADER + 0x28 (Win10 x64)
            DWORD64 objHdr = ep - 0x30;
            DWORD64 sdAddr = g_drv->Rd64(objHdr + 0x28);

            // SecurityDescriptor is encoded: low 4 bits are flags, mask off
            sdAddr &= ~(DWORD64)0xF;
            if (sdAddr && g_drv->IsKernelVA(sdAddr)) {
                printf("    SecDesc:    0x%016llX\n", sdAddr);
                // Read SECURITY_DESCRIPTOR header from kernel
                // SD.Control at +0x02 (WORD), Owner at +0x04 (DWORD offset),
                // DACL at +0x10 (DWORD offset) in self-relative format
                WORD control = g_drv->Rd16(sdAddr + 0x02);
                bool selfRelative = (control & 0x8000) != 0;
                printf("    SD Control: 0x%04X%s\n", control,
                       selfRelative ? " (self-relative)" : "");

                if (selfRelative) {
                    DWORD ownerOff = g_drv->Rd32(sdAddr + 0x04);
                    DWORD daclOff  = g_drv->Rd32(sdAddr + 0x10);

                    if (ownerOff && ownerOff < 0x1000) {
                        // Read owner SID from kernel (first 8 bytes for basic SID)
                        BYTE sidBuf[68] = {};
                        for (int i = 0; i < 28 && i < 68; i++)
                            sidBuf[i] = g_drv->Rd8(sdAddr + ownerOff + i);
                        PSID pSid = (PSID)sidBuf;
                        if (IsValidSid(pSid)) {
                            char name[256] = {}, domain[256] = {};
                            DWORD n1 = sizeof(name), n2 = sizeof(domain);
                            SID_NAME_USE use;
                            if (LookupAccountSidA(nullptr, pSid, name, &n1, domain, &n2, &use))
                                printf("    Owner:      %s\\%s\n", domain, name);
                            else {
                                LPSTR sidStr = nullptr;
                                ConvertSidToStringSidA(pSid, &sidStr);
                                printf("    Owner:      %s\n", sidStr ? sidStr : "?");
                                if (sidStr) LocalFree(sidStr);
                            }
                        }
                    }

                    if (daclOff && daclOff < 0x1000) {
                        // Read ACL header
                        BYTE aclRev = g_drv->Rd8(sdAddr + daclOff);
                        WORD aclSize = g_drv->Rd16(sdAddr + daclOff + 2);
                        WORD aceCount = g_drv->Rd16(sdAddr + daclOff + 4);
                        printf("    DACL:       %u ACEs (size=%u, rev=%u)\n",
                               aceCount, aclSize, aclRev);

                        // Read individual ACEs
                        DWORD aceOff = daclOff + 8; // ACL header is 8 bytes
                        for (int a = 0; a < aceCount && a < 20; a++) {
                            BYTE aceType = g_drv->Rd8(sdAddr + aceOff);
                            WORD aceSize = g_drv->Rd16(sdAddr + aceOff + 2);
                            DWORD aceMask = g_drv->Rd32(sdAddr + aceOff + 4);

                            const char* aceTypeName = (aceType == 0) ? "ALLOW" :
                                                       (aceType == 1) ? "DENY" : "?";

                            // SID starts at aceOff + 8
                            BYTE sidBuf2[68] = {};
                            int sidLen = aceSize - 8;
                            if (sidLen > 0 && sidLen <= 68) {
                                for (int b = 0; b < sidLen; b++)
                                    sidBuf2[b] = g_drv->Rd8(sdAddr + aceOff + 8 + b);
                            }
                            PSID pSid2 = (PSID)sidBuf2;
                            char name2[256] = {}, domain2[256] = {};
                            DWORD n1 = sizeof(name2), n2 = sizeof(domain2);
                            SID_NAME_USE use2;
                            if (IsValidSid(pSid2) &&
                                LookupAccountSidA(nullptr, pSid2, name2, &n1, domain2, &n2, &use2)) {
                                // fine
                            } else {
                                LPSTR ss = nullptr;
                                if (IsValidSid(pSid2)) ConvertSidToStringSidA(pSid2, &ss);
                                snprintf(name2, sizeof(name2), "%s", ss ? ss : "?");
                                domain2[0] = 0;
                                if (ss) LocalFree(ss);
                            }

                            char rwx[16] = "---";
                            if (aceMask & 0x80000001) rwx[0] = 'r';
                            if (aceMask & 0x40000006) rwx[1] = 'w';
                            if (aceMask & 0x20000020) rwx[2] = 'x';
                            if (aceMask & 0x10000000) { rwx[0]='r'; rwx[1]='w'; rwx[2]='x'; }
                            if (aceMask & 0x10000)    strcat(rwx, "+D");

                            const char* c = (aceType == 1) ? A_RED : A_GREEN;
                            printf("      %s[%s]%s %s%-5s%s  0x%08lX  %s%s%s\n",
                                   c, aceTypeName, A_RESET,
                                   c, rwx, A_RESET, aceMask,
                                   domain2[0] ? domain2 : "", domain2[0] ? "\\" : "", name2);

                            aceOff += aceSize;
                        }
                    }
                }
            } else {
                printf("    SecDesc:    (NULL or invalid)\n");
            }
            printf("\n");
            return;
        }

        if (!hProc) {
            printf("%s[!]%s OpenProcess(%lu): error %lu (try with sudo, or load RTCore64 for kernel path)\n",
                   A_RED, A_RESET, pid, GetLastError());
            return;
        }

        PSECURITY_DESCRIPTOR pSD = nullptr;
        PACL pDacl = nullptr;
        DWORD err = GetSecurityInfo(hProc, SE_KERNEL_OBJECT,
                                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                    nullptr, nullptr, &pDacl, nullptr, &pSD);
        CloseHandle(hProc);

        if (err != ERROR_SUCCESS) {
            printf("%s[!]%s GetSecurityInfo: error %lu\n", A_RED, A_RESET, err);
            return;
        }

        // Owner
        PSID owner = nullptr; BOOL ownerDefault = FALSE;
        GetSecurityDescriptorOwner(pSD, &owner, &ownerDefault);
        if (owner) {
            char name[256] = {}, domain[256] = {};
            DWORD n1 = sizeof(name), n2 = sizeof(domain);
            SID_NAME_USE use;
            LookupAccountSidA(nullptr, owner, name, &n1, domain, &n2, &use);
            printf("  Process PID %lu\n    Owner: %s\\%s\n", pid, domain, name);
        }

        PrintAcl(pDacl, "DACL");
        if (pSD) LocalFree(pSD);
        printf("\n");
        return;
    }

    // ── svc:name ──
    if (_strnicmp(target, "svc:", 4) == 0) {
        const char* svcName = target + 4;
        SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCM) { printf("%s[!]%s OpenSCManager: %lu\n", A_RED, A_RESET, GetLastError()); return; }

        SC_HANDLE hSvc = OpenServiceA(hSCM, svcName, READ_CONTROL);
        if (!hSvc) {
            printf("%s[!]%s OpenService(%s): error %lu\n", A_RED, A_RESET, svcName, GetLastError());
            CloseServiceHandle(hSCM);
            return;
        }

        BYTE sdBuf[4096];
        DWORD needed = 0;
        if (!QueryServiceObjectSecurity(hSvc, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                         (PSECURITY_DESCRIPTOR)sdBuf, sizeof(sdBuf), &needed)) {
            printf("%s[!]%s QueryServiceObjectSecurity: %lu\n", A_RED, A_RESET, GetLastError());
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            return;
        }

        PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sdBuf;
        PSID owner = nullptr; BOOL ownerDefault = FALSE;
        GetSecurityDescriptorOwner(pSD, &owner, &ownerDefault);
        if (owner) {
            char name[256] = {}, domain[256] = {};
            DWORD n1 = sizeof(name), n2 = sizeof(domain);
            SID_NAME_USE use;
            LookupAccountSidA(nullptr, owner, name, &n1, domain, &n2, &use);
            printf("  Service: %s\n    Owner: %s\\%s\n", svcName, domain, name);
        }

        PACL pDacl = nullptr; BOOL daclPresent = FALSE, daclDefault = FALSE;
        GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefault);
        PrintAcl(daclPresent ? pDacl : nullptr, "DACL");

        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        printf("\n");
        return;
    }

    // ── File / Directory path ──
    DWORD attrs = GetFileAttributesA(target);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("%s[!]%s Path not found: %s (error %lu)\n", A_RED, A_RESET, target, GetLastError());
        return;
    }

    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pDacl = nullptr;
    DWORD err = GetNamedSecurityInfoA(target, SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                      nullptr, nullptr, &pDacl, nullptr, &pSD);
    if (err != ERROR_SUCCESS) {
        printf("%s[!]%s GetNamedSecurityInfo: error %lu\n", A_RED, A_RESET, err);
        return;
    }

    const char* typeStr = (attrs & FILE_ATTRIBUTE_DIRECTORY) ? "Directory" : "File";

    PSID owner = nullptr; BOOL ownerDefault = FALSE;
    GetSecurityDescriptorOwner(pSD, &owner, &ownerDefault);
    if (owner) {
        char name[256] = {}, domain[256] = {};
        DWORD n1 = sizeof(name), n2 = sizeof(domain);
        SID_NAME_USE use;
        LookupAccountSidA(nullptr, owner, name, &n1, domain, &n2, &use);
        printf("  %s: %s\n    Owner: %s\\%s\n", typeStr, target, domain, name);
    }

    PrintAcl(pDacl, "DACL");
    if (pSD) LocalFree(pSD);
    printf("\n");
}
