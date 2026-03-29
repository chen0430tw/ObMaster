@echo off
setlocal

set MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207
set SDK=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0

set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDK%\Lib\%SDKVER%\ucrt\x64;%SDK%\Lib\%SDKVER%\um\x64

set SRC=..\src
set OUT=ObMaster.exe

cd /d "%~dp0"

echo [*] Building ObMaster...

cl.exe /nologo /O2 /MT /EHsc /std:c++17 /utf-8 ^
    /I"%SRC%" ^
    "%SRC%\main.cpp" ^
    "%SRC%\kutil.cpp" ^
    "%SRC%\driver\RTCore64Backend.cpp" ^
    "%SRC%\cmd_proc.cpp" ^
    "%SRC%\cmd_drivers.cpp" ^
    "%SRC%\cmd_services.cpp" ^
    "%SRC%\cmd_net.cpp" ^
    "%SRC%\cmd_obcb.cpp" ^
    "%SRC%\cmd_runas.cpp" ^
    "%SRC%\cmd_epdump.cpp" ^
    "%SRC%\cmd_notify.cpp" ^
    "%SRC%\cmd_memscan.cpp" ^
    "%SRC%\cmd_handles.cpp" ^
    "%SRC%\cmd_flt.cpp" ^
    "%SRC%\cmd_patch.cpp" ^
    "%SRC%\pte.cpp" ^
    "%SRC%\patch_store.cpp" ^
    "%SRC%\cmd_safepatch.cpp" ^
    "%SRC%\cmd_timedelta.cpp" ^
    "%SRC%\cmd_guard.cpp" ^
    "%SRC%\cmd_pte.cpp" ^
    "%SRC%\cmd_unload.cpp" ^
    "%SRC%\cmd_elevate.cpp" ^
    "%SRC%\cmd_handle_close.cpp" ^
    "%SRC%\cmd_objdir.cpp" ^
    /Fe:"%OUT%" ^
    /link advapi32.lib psapi.lib iphlpapi.lib ws2_32.lib fltlib.lib setupapi.lib cfgmgr32.lib ole32.lib ntdll.lib 2>build_err.txt

if %ERRORLEVEL% == 0 (
    echo [+] Build OK: %~dp0%OUT%
) else (
    echo [!] Build FAILED, errorlevel=%ERRORLEVEL%
)
endlocal
