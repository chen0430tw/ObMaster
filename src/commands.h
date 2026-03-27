#pragma once
#include <string>
#include <vector>

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
void CmdMemRestore(DWORD pid, const char* dll,
                   const char* section = nullptr);           // /memrestore <pid> <dll> [section]
struct WatchTarget { std::string dll; std::string section; };
void CmdWatchFix(const char* proc,
                 const std::vector<WatchTarget>& targets);  // /watchfix <proc> <dll>[:<sec>] ...
void CmdHandles(const char* filter);                        // /handles [drive]
void CmdFlt(const char* volume);                            // /flt [drive]
void CmdFltDetach(const char* filter, const char* volume);  // /flt-detach <f> <v>
void CmdUnmount(char drive);                                // /unmount <drive>
void CmdPatch(unsigned long long addr, const char* hexBytes); // /patch <addr> <hexbytes>  (legacy, unsafe)
void CmdSafePatch(DWORD64 addr, const char* hexStr);         // /safepatch <addr> <hex>   (shadow page)
void CmdSafePatchRestore(DWORD64 addr);                      // /restore <addr>
void CmdTimeDelta(DWORD targetPid, int durationMs);          // /timedelta <pid> [ms]
void CmdGuardAdd(DWORD64 addr);                              // /guard-add <addr>
void CmdGuardStart(int intervalMs);                          // /guard-start [ms]
void CmdGuardStop();                                         // /guard-stop
void CmdGuardList();                                         // /guard-list
void CmdPte(DWORD64 va, bool setWrite = false,               // /pte <addr> [--set-write]
            bool clearNx = false,                           //              [--clear-nx]
            DWORD64 restoreVal = 0);                        //              [--restore <val>]
void CmdForceUnload(const char* drvName, DWORD64 drvObjVA); // /drv-unload <name> <drvobj_va>
void CmdForceStop(const char* svcName);                    // /force-stop <name>
void CmdElevatePid(DWORD targetPid);                        // /elevate-pid <pid>
void CmdElevateSelf(const char* extraCmd);                  // /elevate-self [cmd]
void CmdEnablePriv(const char* privName);                   // /enable-priv <privilege>
void CmdDrvLoad(const char* sysPath);                       // /drv-load <path.sys>
void CmdHandleClose(DWORD pid, DWORD64 handleVal);          // /handle-close <pid> <handle_hex>
