#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "jutil.h"
#include "ansi.h"

// ─── NT internals ─────────────────────────────────────────────────────────────

typedef NTSTATUS (NTAPI* PFN_NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI* PFN_NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOL, BOOL, PULONG, PULONG);
typedef NTSTATUS (NTAPI* PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* PFN_NtClose)(HANDLE);

#define DIRECTORY_QUERY      0x0001
#define DIRECTORY_TRAVERSE   0x0002
#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _OBJ_DIR_INFO {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJ_DIR_INFO;

// OBJECT_DIRECTORY hash bucket count
static const int OD_BUCKETS = 37;

// OBJECT_DIRECTORY_ENTRY offsets
static const DWORD ODE_ChainLink = 0x000;  // OBJECT_DIRECTORY_ENTRY* (next in bucket)
static const DWORD ODE_Object    = 0x008;  // void* (object body address)

// OBJECT_HEADER offsets (Win10 x64, verified on 19045)
static const DWORD OH_SIZE     = 0x030;   // sizeof — body starts here
static const DWORD OH_TypeIndex= 0x018;   // UCHAR (XOR-encoded)
static const DWORD OH_InfoMask = 0x01A;   // UCHAR

// OBJECT_HEADER_NAME_INFO (placed before header, size 0x20)
static const DWORD OHNI_SIZE        = 0x020;
static const DWORD OHNI_NameLen     = 0x008;  // UNICODE_STRING.Length
static const DWORD OHNI_NameBuf     = 0x010;  // UNICODE_STRING.Buffer

static const BYTE  INFO_CREATOR = 0x01;
static const BYTE  INFO_NAME    = 0x02;

// OBJECT_TYPE offsets (Win10 x64)
static const DWORD OT_TypeList_Flink = 0x000;  // LIST_ENTRY.Flink (== next OBJECT_TYPE)
static const DWORD OT_Name_Len       = 0x010;  // UNICODE_STRING.Length
static const DWORD OT_Name_Buf       = 0x018;  // UNICODE_STRING.Buffer
static const DWORD OT_Index          = 0x028;  // UCHAR

// ─── Get kernel address of a handle ──────────────────────────────────────────

static DWORD64 HandleToKernelAddr(HANDLE h) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQSI = (PFN_NtQuerySystemInformation)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    const ULONG SystemExtendedHandleInformation = 0x40;
    DWORD ourPid = GetCurrentProcessId();

    ULONG sz = 1 << 20;
    std::vector<BYTE> buf(sz);
    ULONG ret = 0;
    NTSTATUS st;
    for (int i = 0; i < 4; i++) {
        st = NtQSI(SystemExtendedHandleInformation, buf.data(), sz, &ret);
        if (st != (NTSTATUS)0xC0000004) break;
        sz = ret + 65536;
        buf.resize(sz);
    }
    if (st < 0) return 0;

    // [NumberOfHandles: ULONG_PTR][Reserved: ULONG_PTR][Entries: 0x28 each]
    // Entry: +0x00 Object(PVOID), +0x08 UniqueProcessId, +0x10 HandleValue
    ULONG_PTR count = *(ULONG_PTR*)buf.data();
    BYTE* base = buf.data() + 0x10;
    for (ULONG_PTR i = 0; i < count; i++) {
        BYTE* e = base + i * 0x28;
        if ((DWORD)*(ULONG_PTR*)(e + 0x08) == ourPid &&
            (HANDLE)*(ULONG_PTR*)(e + 0x10) == h)
            return *(DWORD64*)(e + 0x00);
    }
    return 0;
}

// ─── ObHeaderCookie discovery (uses our own process handle) ──────────────────

static BYTE s_cookie     = 0;
static bool s_cookieDone = false;

static BYTE GetObHeaderCookie() {
    if (s_cookieDone) return s_cookie;
    s_cookieDone = true;

    HANDLE hReal = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                    GetCurrentProcess(), &hReal, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (!hReal) return 0;

    DWORD64 objBody = HandleToKernelAddr(hReal);
    CloseHandle(hReal);
    if (!objBody) return 0;

    DWORD64 hdr    = objBody - OH_SIZE;
    BYTE    rawIdx = g_drv->Rd8(hdr + OH_TypeIndex);

    // PsProcessType → OBJECT_TYPE → Index at +0x028
    DWORD64 processType = g_drv->Rd64(KUtil::KernelExport("PsProcessType"));
    if (!g_drv->IsKernelVA(processType)) return 0;
    BYTE realIdx = g_drv->Rd8(processType + OT_Index);

    s_cookie = rawIdx ^ (BYTE)(hdr >> 8) ^ realIdx;
    return s_cookie;
}

static std::wstring ReadKernelName(DWORD64 objBody);  // forward decl

// ─── Build index → type name map via \ObjectTypes directory ──────────────────
// Each object in \ObjectTypes IS an OBJECT_TYPE body.
// OBJECT_TYPE.Index at +0x028 gives the real type index.
// We open root \ (always accessible) → scan buckets for ObjectTypes → walk it.

static std::map<BYTE, std::wstring> BuildTypeIndexMap() {
    std::map<BYTE, std::wstring> result;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtOpenDir = (PFN_NtOpenDirectoryObject)
        GetProcAddress(ntdll, "NtOpenDirectoryObject");
    auto NtClose   = (PFN_NtClose)GetProcAddress(ntdll, "NtClose");
    if (!NtOpenDir || !NtClose) return result;

    wchar_t rootPath[] = L"\\";
    UNICODE_STRING uRoot{ 2, 4, rootPath };
    OBJECT_ATTRIBUTES oaRoot{};
    oaRoot.Length     = sizeof(OBJECT_ATTRIBUTES);
    oaRoot.ObjectName = &uRoot;
    oaRoot.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE hRoot = NULL;
    if (NtOpenDir(&hRoot, DIRECTORY_QUERY, &oaRoot) < 0) return result;
    DWORD64 rootKva = HandleToKernelAddr(hRoot);
    NtClose(hRoot);
    if (!g_drv->IsKernelVA(rootKva)) return result;

    // Scan root buckets for the ObjectTypes directory entry
    DWORD64 objTypesKva = 0;
    for (int b = 0; b < OD_BUCKETS && !objTypesKva; b++) {
        DWORD64 entry = g_drv->Rd64(rootKva + (DWORD64)b * 8);
        for (int g = 0; g_drv->IsKernelVA(entry) && g < 512; g++) {
            DWORD64 objBody = g_drv->Rd64(entry + ODE_Object);
            if (g_drv->IsKernelVA(objBody) &&
                ReadKernelName(objBody) == L"ObjectTypes") {
                objTypesKva = objBody;
                break;
            }
            entry = g_drv->Rd64(entry + ODE_ChainLink);
        }
    }
    if (!objTypesKva) return result;

    // Walk \ObjectTypes hash buckets — each object body IS an OBJECT_TYPE
    for (int b = 0; b < OD_BUCKETS; b++) {
        DWORD64 entry = g_drv->Rd64(objTypesKva + (DWORD64)b * 8);
        for (int g = 0; g_drv->IsKernelVA(entry) && g < 512; g++) {
            DWORD64 typeBody = g_drv->Rd64(entry + ODE_Object);
            if (g_drv->IsKernelVA(typeBody)) {
                BYTE         idx  = g_drv->Rd8(typeBody + OT_Index);
                std::wstring name = ReadKernelName(typeBody);
                if (!name.empty()) result[idx] = name;
            }
            entry = g_drv->Rd64(entry + ODE_ChainLink);
        }
    }
    return result;
}

// ─── Decode type name for an object body address ─────────────────────────────

static std::wstring DecodeTypeName(DWORD64 objBody,
                                   const std::map<BYTE, std::wstring>& typeMap) {
    if (!g_drv->IsKernelVA(objBody)) return L"";
    DWORD64 hdr    = objBody - OH_SIZE;
    BYTE    rawIdx = g_drv->Rd8(hdr + OH_TypeIndex);
    BYTE    cookie = GetObHeaderCookie();
    BYTE    realIdx = rawIdx ^ cookie ^ (BYTE)(hdr >> 8);
    auto it = typeMap.find(realIdx);
    if (it != typeMap.end()) return it->second;
    wchar_t tmp[16];
    swprintf_s(tmp, L"(idx=%u)", realIdx);
    return tmp;
}

// ─── Read object name from OBJECT_HEADER_NAME_INFO ───────────────────────────

static std::wstring ReadKernelName(DWORD64 objBody) {
    if (!g_drv->IsKernelVA(objBody)) return L"";
    DWORD64 hdr      = objBody - OH_SIZE;
    BYTE    infoMask = g_drv->Rd8(hdr + OH_InfoMask);
    if (!(infoMask & INFO_NAME)) return L"";

    DWORD64 nameInfo = hdr - OHNI_SIZE;
    if (infoMask & INFO_CREATOR) nameInfo -= 0x20;

    USHORT  len = g_drv->Rd16(nameInfo + OHNI_NameLen);
    DWORD64 buf = g_drv->Rd64(nameInfo + OHNI_NameBuf);
    if (!len || !g_drv->IsKernelVA(buf)) return L"";

    USHORT nchars = min((USHORT)(len / 2), (USHORT)256);
    std::wstring name(nchars, L'\0');
    for (USHORT i = 0; i < nchars; i++)
        name[i] = (wchar_t)g_drv->Rd16(buf + i * 2);
    return name;
}

// ─── Walk hash buckets at a given kernel directory VA ─────────────────────────

struct ObjRow {
    std::wstring name;
    std::wstring type;
    DWORD64      objAddr;
};

static std::vector<ObjRow> WalkDir(DWORD64 dirKva,
                                   const std::map<BYTE, std::wstring>& typeMap) {
    std::vector<ObjRow> rows;
    for (int b = 0; b < OD_BUCKETS; b++) {
        DWORD64 entry = g_drv->Rd64(dirKva + (DWORD64)b * 8);
        for (int guard = 0; g_drv->IsKernelVA(entry) && guard < 512; guard++) {
            DWORD64 objBody = g_drv->Rd64(entry + ODE_Object);
            if (g_drv->IsKernelVA(objBody)) {
                ObjRow r;
                r.objAddr = objBody;
                r.name    = ReadKernelName(objBody);
                r.type    = DecodeTypeName(objBody, typeMap);
                rows.push_back(r);
            }
            entry = g_drv->Rd64(entry + ODE_ChainLink);
        }
    }
    std::sort(rows.begin(), rows.end(),
        [](auto& a, auto& b){ return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0; });
    return rows;
}

// ─── Print helpers ────────────────────────────────────────────────────────────

static void PrintRows(const std::vector<ObjRow>& rows,
                      const char* label, DWORD64 dirKva)
{
    printf("\n%s[*]%s %s", A_BOLD, A_RESET, label);
    if (g_drv->IsKernelVA(dirKva))
        printf("  (dir @ %s0x%016llx%s)", A_CYAN,
               (unsigned long long)dirKva, A_RESET);
    else
        printf("  %s(dir addr unavailable)%s", A_DIM, A_RESET);
    printf("\n\n");

    printf("  %-44s %-22s %-18s %-18s\n",
        "Name", "Type", "Object Addr", "Header Addr");
    printf("  %-44s %-22s %-18s %-18s\n",
        "────────────────────────────────────────────",
        "──────────────────────",
        "──────────────────", "──────────────────");

    for (auto& r : rows) {
        const char* col = A_RESET;
        if      (r.type == L"Directory")    col = A_CYAN;
        else if (r.type == L"SymbolicLink") col = A_DIM;
        else if (r.type == L"Driver" || r.type == L"Device") col = A_YELLOW;

        if (r.objAddr) {
            wprintf(L"  %hs%-44ls %-22ls%hs 0x%016llx  0x%016llx\n",
                col, r.name.c_str(), r.type.c_str(), A_RESET,
                (unsigned long long)r.objAddr,
                (unsigned long long)(r.objAddr - OH_SIZE));
        } else {
            wprintf(L"  %hs%-44ls %-22ls%hs %hs%-18hs%hs\n",
                col, r.name.c_str(), r.type.c_str(), A_RESET,
                A_DIM, "(no addr)", A_RESET);
        }
    }
    printf("\n  %s%d objects%s\n\n", A_BOLD, (int)rows.size(), A_RESET);
}

static void PrintRowsJson(const std::vector<ObjRow>& rows,
                          const char* label, DWORD64 dirKva)
{
    printf("{\"command\":\"objdir\",\"path\":%s,\"dir_addr\":%s,\"objects\":[\n",
        JEscape(label).c_str(), JAddr(dirKva).c_str());
    bool first = true;
    for (auto& r : rows) {
        if (!first) printf(",\n");
        first = false;
        DWORD64 hdrAddr = r.objAddr ? r.objAddr - OH_SIZE : 0;
        printf(" {\"name\":%s,\"type\":%s,\"object_addr\":%s,\"header_addr\":%s}",
            JEscape(r.name.c_str()).c_str(),
            JEscape(r.type.c_str()).c_str(),
            JAddr(r.objAddr).c_str(),
            hdrAddr ? JAddr(hdrAddr).c_str() : "null");
    }
    printf("\n]}\n");
}

// ─── Main command ─────────────────────────────────────────────────────────────
// path: object manager path (e.g. "\Driver") — used when kvaOverride == 0
// kvaOverride: kernel VA of directory object body — skips NtOpenDirectoryObject

void CmdObjDir(const char* path, DWORD64 kvaOverride) {
    SetConsoleOutputCP(CP_UTF8);

    // Build type index map once (walks OBJECT_TYPE.TypeList chain in kernel)
    auto typeMap = BuildTypeIndexMap();

    // ── KVA-only mode: bypass DACL entirely ──────────────────────────────────
    if (kvaOverride) {
        if (!g_drv->IsKernelVA(kvaOverride)) {
            printf("[!] 0x%llx is not a valid kernel VA\n",
                   (unsigned long long)kvaOverride);
            return;
        }
        auto rows = WalkDir(kvaOverride, typeMap);
        char label[64];
        sprintf_s(label, "kva:0x%llx", (unsigned long long)kvaOverride);
        if (g_jsonMode) PrintRowsJson(rows, label, kvaOverride);
        else            PrintRows    (rows, label, kvaOverride);
        return;
    }

    // ── Normal mode: open via NtOpenDirectoryObject ───────────────────────────
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtOpenDir  = (PFN_NtOpenDirectoryObject) GetProcAddress(ntdll, "NtOpenDirectoryObject");
    auto NtQueryDir = (PFN_NtQueryDirectoryObject)GetProcAddress(ntdll, "NtQueryDirectoryObject");
    auto NtClose    = (PFN_NtClose)               GetProcAddress(ntdll, "NtClose");
    if (!NtOpenDir || !NtQueryDir || !NtClose) {
        printf("[!] Failed to resolve NT APIs\n"); return;
    }

    wchar_t wpath[512]{};
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 511);
    UNICODE_STRING uPath{};
    uPath.Buffer        = wpath;
    uPath.Length        = (USHORT)(wcslen(wpath) * 2);
    uPath.MaximumLength = uPath.Length + 2;

    OBJECT_ATTRIBUTES oa{};
    oa.Length     = sizeof(OBJECT_ATTRIBUTES);
    oa.ObjectName = &uPath;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE hDir = NULL;
    NTSTATUS st = NtOpenDir(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (st < 0)
        st = NtOpenDir(&hDir, DIRECTORY_QUERY, &oa);
    if (st < 0) {
        // Can't open — fall back to kernel walk if user already knows dir addr
        printf("[!] NtOpenDirectoryObject(%s) failed: 0x%08X\n", path, (UINT)st);
        printf("    Hint: get dir addr first with /objdir \\ then use /objdir --kva <addr>\n");
        return;
    }

    DWORD64 dirKva = HandleToKernelAddr(hDir);

    // Get user-mode name+type list via NtQueryDirectoryObject
    std::map<std::wstring, std::wstring> typeMapUser;
    {
        std::vector<BYTE> buf(65536);
        ULONG ctx = 0, retLen = 0;
        bool first = true;
        while (true) {
            NTSTATUS qs = NtQueryDir(hDir, buf.data(), (ULONG)buf.size(),
                                     FALSE, first, &ctx, &retLen);
            if (qs == (NTSTATUS)0x80000006) break;  // STATUS_NO_MORE_ENTRIES
            if (qs < 0 && qs != (NTSTATUS)0x00000105) break;
            for (auto* info = (OBJ_DIR_INFO*)buf.data();
                 info->Name.Buffer != nullptr; info++) {
                typeMapUser[std::wstring(info->Name.Buffer, info->Name.Length / 2)]
                    = std::wstring(info->TypeName.Buffer, info->TypeName.Length / 2);
            }
            if (qs != (NTSTATUS)0x00000105) break;
            first = false;
        }
    }
    NtClose(hDir);

    // Walk kernel hash buckets and build addr map
    std::map<std::wstring, DWORD64> addrMap;
    if (g_drv->IsKernelVA(dirKva)) {
        for (int b = 0; b < OD_BUCKETS; b++) {
            DWORD64 entry = g_drv->Rd64(dirKva + (DWORD64)b * 8);
            for (int guard = 0; g_drv->IsKernelVA(entry) && guard < 512; guard++) {
                DWORD64 objBody = g_drv->Rd64(entry + ODE_Object);
                if (g_drv->IsKernelVA(objBody)) {
                    std::wstring name = ReadKernelName(objBody);
                    if (!name.empty()) addrMap[name] = objBody;
                }
                entry = g_drv->Rd64(entry + ODE_ChainLink);
            }
        }
    }

    // Merge: user-mode gives type names, kernel gives addresses
    std::vector<ObjRow> rows;
    for (auto& [name, type] : typeMapUser) {
        ObjRow r;
        r.name    = name;
        r.type    = type;
        r.objAddr = 0;
        auto it = addrMap.find(name);
        if (it != addrMap.end()) r.objAddr = it->second;
        rows.push_back(r);
    }
    std::sort(rows.begin(), rows.end(),
        [](auto& a, auto& b){ return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0; });

    if (g_jsonMode) PrintRowsJson(rows, path, dirKva);
    else            PrintRows    (rows, path, dirKva);
}
