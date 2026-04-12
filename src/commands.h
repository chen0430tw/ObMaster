#pragma once
#include <string>
#include <vector>

// ─── Command declarations ─────────────────────────────────────────────────────

void CmdProc();                             // /proc
void CmdProcToken(DWORD pid);               // /proc-token <pid>
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
void CmdNotifyRegistry(const char* killDriver = nullptr,
                       DWORD64 killKva = 0,
                       bool killUnknown = false);           // /notify registry [--kill <drv>] [--kill-kva <dobj_va>] [--kill-unknown]
void CmdMemScan(DWORD pid, bool showAll = false);            // /memscan <pid> [all]
void CmdMemRestore(DWORD pid, const char* dll,
                   const char* section = nullptr);           // /memrestore <pid> <dll> [section]
struct WatchTarget { std::string dll; std::string section; };
void CmdWatchFix(const char* proc,
                 const std::vector<WatchTarget>& targets);  // /watchfix <proc> <dll>[:<sec>] ...
void CmdHandles(const char* filter, bool doClose = false);  // /handles [drive|path] [--close]
void CmdFlt(const char* volume);                            // /flt [drive]
void CmdFltDetach(const char* filter, const char* volume);  // /flt-detach <f> <v>
void CmdUnmount(char drive);                                // /unmount <drive>
void CmdPatch(unsigned long long addr, const char* hexBytes); // /patch <addr> <hexbytes>  (legacy, unsafe)
void CmdSafePatch(DWORD64 addr, const char* hexStr);         // /safepatch <addr> <hex>   (shadow page)
void CmdSafePatchRestore(DWORD64 addr);                      // /restore <addr>
void CmdSpTest(DWORD64 addr);                                // /sp-test <addr>
void CmdTimeDelta(DWORD targetPid, int durationMs);          // /timedelta <pid> [ms]
void CmdGuardAdd(DWORD64 addr);                              // /guard-add <addr>
void CmdGuardStart(int intervalMs);                          // /guard-start [ms]
void CmdGuardStop();                                         // /guard-stop
void CmdGuardList();                                         // /guard-list
void CmdPte(DWORD64 va, bool setWrite = false,               // /pte <addr> [--set-write]
            bool clearNx = false,                           //              [--clear-nx]
            DWORD64 restoreVal = 0);                        //              [--restore <val>]
void CmdForceUnload(const char* drvName, DWORD64 drvObjVA); // /drv-unload <name> <drvobj_va>
void CmdForceStop(const char* svcName, bool force = false); // /force-stop <name> [--force]
void CmdNukeDriver(const char* svcName, DWORD64 drvObjVA);      // /nuke-driver <svc> <drvobj_va>
void CmdElevatePid(DWORD targetPid);                        // /elevate-pid <pid>
void CmdElevateSelf(const char* extraCmd);                  // /elevate-self [cmd]
void CmdEnablePriv(const char* privName);                   // /enable-priv <privilege>
void CmdDrvLoad(const char* sysPath);                       // /drv-load <path.sys>
void CmdHandleClose(DWORD pid, DWORD64 handleVal);          // /handle-close <pid> <handle_hex>
int  CmdHandleScan(DWORD pid, DWORD64 accessMask, DWORD targetPid, bool doClose,
                   bool quiet = false, DWORD64 cachedHT = 0); // /handle-scan
void CmdDrvZombie(DWORD64 drvObjVA);                            // /drv-zombie <drvobj_va>
void CmdObjDir(const char* path, DWORD64 kvaOverride = 0);  // /objdir [path] [--kva <addr>]
void CmdWlMon(int intervalMs);                              // /wlmon [ms]
void CmdWlInject(const char* dllPath);                      // /wlinject <dll>
void CmdWlUninject(const char* dllName);                    // /wluninject <dll-name>
void CmdWnd(bool showAll, bool allDesktops);                 // /wnd [--all] [--all-desktops]
void CmdWndClose(DWORD64 hwnd);                             // /wnd-close <hwnd>
void CmdWlSas();                                            // /wl-sas
void CmdWlPersist(const char* dllPath);                     // /wl-persist <dll>
void CmdWlUnpersist(const char* dllName);                   // /wl-unpersist <dll>
void CmdWlUnloadAll(const char* dllName, bool forceKill);   // /wluninject-all <dll> [--force]
void CmdDllList(const char* filter);                        // /dll-list <name>
void CmdInjScan(DWORD pid);                                 // /inj-scan [pid]
void CmdKillPpl(DWORD pid);                                 // /kill-ppl <pid>
void CmdMakePpl(DWORD pid, BYTE level);                     // /make-ppl <pid> [level]
void CmdObcbInstall(const char* sysPath);                   // /obcb-install [path]
void CmdBsod(const char* dumpPath = nullptr,
             const char* afterSpec = nullptr,
             const char* beforeSpec = nullptr);              // /bsod [path|--list|--all] [--after 3d] [--before yd]
void CmdInfo();                                             // /info
void CmdWhoami();                                           // /whoami
void CmdAcl(const char* target);                            // /acl <path|svc:name|pid:N>
void CmdV2P(DWORD64 va);                                    // /v2p <va>
void CmdP2V(DWORD64 pa);                                    // /p2v <pa>
