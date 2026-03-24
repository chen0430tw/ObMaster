@echo off
setlocal

set MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207
set SDK=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0

set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDK%\Lib\%SDKVER%\ucrt\x64;%SDK%\Lib\%SDKVER%\um\x64

cd /d "%~dp0"

echo [*] Building TestTarget...
cl.exe /nologo /O2 /MT /EHsc /std:c++17 /utf-8 TestTarget.cpp /Fe:TestTarget.exe /link advapi32.lib

if %ERRORLEVEL% == 0 (
    echo [+] Build OK: %~dp0TestTarget.exe
) else (
    echo [!] Build FAILED
)
endlocal
