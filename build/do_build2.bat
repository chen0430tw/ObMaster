@echo off
chcp 65001 >nul

set MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207
set SDK=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0
set SRC=C:\Users\Administrator\ObMaster\src
set OUT=C:\Users\Administrator\ObMaster\build\ObMaster.exe

set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDK%\Lib\%SDKVER%\ucrt\x64;%SDK%\Lib\%SDKVER%\um\x64

echo [*] Building...
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
    /Fe:"%OUT%" ^
    /link advapi32.lib psapi.lib iphlpapi.lib ws2_32.lib

if %ERRORLEVEL% == 0 (
    echo [+] Build OK: %OUT%
) else (
    echo [!] Build FAILED, errorlevel=%ERRORLEVEL%
)
