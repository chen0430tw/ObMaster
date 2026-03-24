// winsock2 must come before windows.h to avoid redefinition conflicts
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <cstdio>
#include <vector>
#include <map>
#include <string>
#include <TlHelp32.h>
#include "globals.h"
#include "jutil.h"

// ─── /net ─────────────────────────────────────────────────────────────────────
// Lists TCP (IPv4+IPv6) and UDP (IPv4+IPv6) connections with owning process name.
// Uses GetExtendedTcpTable/GetExtendedUdpTable — no kernel reads needed here.

static const char* TcpStateStr(DWORD s) {
    static const char* t[] = {
        "","CLOSED","LISTEN","SYN_SENT","SYN_RCVD",
        "ESTAB","FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT",
        "CLOSING","LAST_ACK","TIME_WAIT","DELETE_TCB"
    };
    return (s > 0 && s <= 12) ? t[s] : "UNKNOWN";
}

static void FmtIPv4(DWORD ip, USHORT port, char* buf, size_t sz) {
    auto* b = (BYTE*)&ip;
    sprintf_s(buf, sz, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], ntohs(port));
}

static void FmtIPv6(BYTE* ip, USHORT port, char* buf, size_t sz) {
    char tmp[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, ip, tmp, sizeof(tmp));
    sprintf_s(buf, sz, "[%s]:%u", tmp, ntohs(port));
}

// Build pid -> process name map via Toolhelp (display only, no kernel needed)
static std::map<DWORD, std::string> BuildPidMap() {
    std::map<DWORD, std::string> m;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe))
        do { m[(DWORD)pe.th32ProcessID] = pe.szExeFile; } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return m;
}

// JSON helper — emits one connection record; caller manages commas
static void EmitConnJson(const char* proto, const char* state,
                         const char* loc, const char* rem,
                         DWORD pid, const char* proc, bool& first) {
    if (!first) printf(",\n");
    first = false;
    printf(" {\"proto\":%s,\"state\":%s,\"local\":%s,\"remote\":%s,\"pid\":%u,\"process\":%s}",
        JEscape(proto).c_str(), JEscape(state).c_str(),
        JEscape(loc).c_str(),   JEscape(rem).c_str(),
        pid, JEscape(proc).c_str());
}

void CmdNet() {
    SetConsoleOutputCP(CP_UTF8);

    auto pidMap = BuildPidMap();

    if (g_jsonMode) printf("{\"command\":\"net\",\"connections\":[\n");
    bool jsonFirst = true;

    if (!g_jsonMode) {
        printf("\n%-6s %-13s %-42s %-42s %s\n",
            "Proto", "State", "Local", "Remote", "PID / Process");
        printf("%s\n", std::string(130, '-').c_str());
    }

    // ── TCP IPv4 ──────────────────────────────────────────────────────────────
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> tcp4buf(size);
    if (GetExtendedTcpTable(tcp4buf.data(), &size, TRUE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        auto* t = (MIB_TCPTABLE_OWNER_PID*)tcp4buf.data();
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            auto& r = t->table[i];
            char loc[48], rem[48];
            FmtIPv4(r.dwLocalAddr,  (USHORT)r.dwLocalPort,  loc, sizeof(loc));
            FmtIPv4(r.dwRemoteAddr, (USHORT)r.dwRemotePort, rem, sizeof(rem));
            auto it = pidMap.find(r.dwOwningPid);
            const char* proc = it != pidMap.end() ? it->second.c_str() : "?";
            if (g_jsonMode)
                EmitConnJson("TCP4", TcpStateStr(r.dwState), loc, rem, r.dwOwningPid, proc, jsonFirst);
            else
                printf("%-6s %-13s %-42s %-42s %u / %s\n",
                    "TCP4", TcpStateStr(r.dwState), loc, rem, r.dwOwningPid, proc);
        }
    }

    // ── TCP IPv6 ──────────────────────────────────────────────────────────────
    size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> tcp6buf(size);
    if (GetExtendedTcpTable(tcp6buf.data(), &size, TRUE, AF_INET6,
        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        auto* t = (MIB_TCP6TABLE_OWNER_PID*)tcp6buf.data();
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            auto& r = t->table[i];
            char loc[72], rem[72];
            FmtIPv6(r.ucLocalAddr,  (USHORT)r.dwLocalPort,  loc, sizeof(loc));
            FmtIPv6(r.ucRemoteAddr, (USHORT)r.dwRemotePort, rem, sizeof(rem));
            auto it = pidMap.find(r.dwOwningPid);
            const char* proc = it != pidMap.end() ? it->second.c_str() : "?";
            if (g_jsonMode)
                EmitConnJson("TCP6", TcpStateStr(r.dwState), loc, rem, r.dwOwningPid, proc, jsonFirst);
            else
                printf("%-6s %-13s %-42s %-42s %u / %s\n",
                    "TCP6", TcpStateStr(r.dwState), loc, rem, r.dwOwningPid, proc);
        }
    }

    // ── UDP IPv4 ──────────────────────────────────────────────────────────────
    size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> udp4buf(size);
    if (GetExtendedUdpTable(udp4buf.data(), &size, TRUE, AF_INET,
        UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        auto* t = (MIB_UDPTABLE_OWNER_PID*)udp4buf.data();
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            auto& r = t->table[i];
            char loc[48];
            FmtIPv4(r.dwLocalAddr, (USHORT)r.dwLocalPort, loc, sizeof(loc));
            auto it = pidMap.find(r.dwOwningPid);
            const char* proc = it != pidMap.end() ? it->second.c_str() : "?";
            if (g_jsonMode)
                EmitConnJson("UDP4", "*", loc, "*:*", r.dwOwningPid, proc, jsonFirst);
            else
                printf("%-6s %-13s %-42s %-42s %u / %s\n",
                    "UDP4", "*", loc, "*:*", r.dwOwningPid, proc);
        }
    }

    // ── UDP IPv6 ──────────────────────────────────────────────────────────────
    size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> udp6buf(size);
    if (GetExtendedUdpTable(udp6buf.data(), &size, TRUE, AF_INET6,
        UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        auto* t = (MIB_UDP6TABLE_OWNER_PID*)udp6buf.data();
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            auto& r = t->table[i];
            char loc[72];
            FmtIPv6(r.ucLocalAddr, (USHORT)r.dwLocalPort, loc, sizeof(loc));
            auto it = pidMap.find(r.dwOwningPid);
            const char* proc = it != pidMap.end() ? it->second.c_str() : "?";
            if (g_jsonMode)
                EmitConnJson("UDP6", "*", loc, "*:*", r.dwOwningPid, proc, jsonFirst);
            else
                printf("%-6s %-13s %-42s %-42s %u / %s\n",
                    "UDP6", "*", loc, "*:*", r.dwOwningPid, proc);
        }
    }

    if (g_jsonMode) printf("\n]}\n");
    else printf("\n");
}
