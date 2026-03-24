#pragma once

// ─── Command declarations ─────────────────────────────────────────────────────

void CmdProc();                             // /proc
void CmdKill(DWORD pid);                    // /kill <pid>
void CmdDrivers();                          // /drivers
void CmdServices(bool allStates);           // /services [all]
void CmdNet();                              // /net
void CmdObcb(bool doProcess, bool doThread);// /obcb [process|thread]
void CmdDisable(unsigned long long addr);   // /disable <addr>
void CmdEnable (unsigned long long addr);   // /enable  <addr>
void CmdRunAs(const char* level, const char* cmdline); // /runas system|ti <cmd>
void CmdEpDump(DWORD pid);                  // /epdump <pid>  (offset probe)
void CmdNotify(bool doImage, bool doProcess, bool doThread); // /notify [image|process|thread]
void CmdNotifyDisable(unsigned long long fn);                // /ndisable <addr>
void CmdMemScan(DWORD pid, bool showAll = false);            // /memscan <pid> [all]
void CmdMemRestore(DWORD pid, const char* dll);              // /memrestore <pid> <dll>
