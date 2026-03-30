@echo off
chcp 65001 >nul

set MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207
set SDK=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0
set HERE=%~dp0

set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDK%\Lib\%SDKVER%\ucrt\x64;%SDK%\Lib\%SDKVER%\um\x64

echo [*] Building SimVBox.exe...
cl.exe /nologo /O2 /MT /EHsc /std:c++17 /utf-8 ^
    "%HERE%SimVBox.cpp" ^
    /Fe:"%HERE%SimVBox.exe" ^
    /link advapi32.lib

echo [*] Building SimKsafe.exe...
cl.exe /nologo /O2 /MT /EHsc /std:c++17 /utf-8 ^
    "%HERE%SimKsafe.cpp" ^
    /Fe:"%HERE%SimKsafe.exe" ^
    /link advapi32.lib

echo [*] Building SimKshutdown.exe...
cl.exe /nologo /O2 /MT /EHsc /std:c++17 /utf-8 ^
    "%HERE%SimKshutdown.cpp" ^
    /Fe:"%HERE%SimKshutdown.exe" ^
    /link advapi32.lib

if exist "%HERE%SimVBox.exe" if exist "%HERE%SimKsafe.exe" if exist "%HERE%SimKshutdown.exe" (
    echo [+] Build OK: SimVBox.exe SimKsafe.exe SimKshutdown.exe
) else (
    echo [!] Build FAILED
)

:: clean up object files
del /q "%HERE%*.obj" 2>nul
