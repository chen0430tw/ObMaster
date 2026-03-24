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
