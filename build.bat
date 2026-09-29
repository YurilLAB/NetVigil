@echo off
setlocal
rem build.bat        builds build\NetVigil.exe
rem build.bat test   builds and runs the decision-logic unit tests
set "TARGET=app"
if /i "%~1"=="test" set "TARGET=test"
if /i "%~1"=="updatetest" set "TARGET=updatetest"

where cl >nul 2>nul
if %errorlevel%==0 goto :have_cl

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo vswhere.exe not found - install Visual Studio Build Tools.
    exit /b 1
)
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\netvigil_vsdir.txt"
set /p VSDIR=<"%TEMP%\netvigil_vsdir.txt"
del "%TEMP%\netvigil_vsdir.txt" >nul 2>nul
if not defined VSDIR (
    echo No Visual C++ toolset found.
    exit /b 1
)
call "%VSDIR%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 -no_logo
if errorlevel 1 exit /b 1

:have_cl
if not exist build mkdir build
if "%TARGET%"=="test" goto :test
if "%TARGET%"=="updatetest" goto :updatetest

rem Hardening: /GS (default) + /guard:cf (control-flow guard) + /sdl (extra runtime checks);
rem at link time ASLR (high entropy), DEP, CET shadow stacks, and System32-only loading of
rem every DLL the exe imports (DEPENDENTLOADFLAG 0x800 = LOAD_LIBRARY_SEARCH_SYSTEM32).
cl /nologo /utf-8 /W4 /O2 /GL /EHsc /std:c++17 /GS /guard:cf /sdl /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 src\main.cpp src\gui.cpp src\diagnose.cpp src\startup.cpp src\proxy.cpp src\update.cpp src\updatecore.cpp /Fo:build\ /Fe:build\NetVigil.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /LTCG /OPT:REF /OPT:ICF /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT /DEPENDENTLOADFLAG:0x800
if errorlevel 1 exit /b 1
echo.
echo Built build\NetVigil.exe
exit /b 0

:test
cl /nologo /utf-8 /W4 /EHsc /std:c++17 /Isrc tests\diagnose_tests.cpp src\diagnose.cpp /Fo:build\ /Fe:build\diagnose_tests.exe
if errorlevel 1 exit /b 1
build\diagnose_tests.exe
if errorlevel 1 exit /b 1
cl /nologo /utf-8 /W4 /EHsc /std:c++17 /Isrc tests\update_tests.cpp src\updatecore.cpp /Fo:build\ /Fe:build\update_tests.exe
if errorlevel 1 exit /b 1
build\update_tests.exe
exit /b %errorlevel%

:updatetest
rem TEST-ONLY build for tools\test-update.ps1 — never shipped (tools\release.ps1 refuses an exe
rem that contains these settings): update channel = a loopback server, trust anchor = a throwaway
rem key, staging = a scratch folder, and the installer is never launched.
rem Needs NV_TEST_BASE (http://127.0.0.1:PORT), NV_TEST_STAGE, NV_TEST_PUBKEY (header) and NV_TEST_OUT.
if not defined NV_TEST_OUT (echo NV_TEST_OUT is not set & exit /b 1)
if not exist "%NV_TEST_OUT%" mkdir "%NV_TEST_OUT%"
cl /nologo /utf-8 /W4 /O2 /EHsc /std:c++17 /GS /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DNETVIGIL_UPDATE_TEST "/DNETVIGIL_UPDATE_TEST_BASE=L\"%NV_TEST_BASE%\"" "/DNETVIGIL_UPDATE_TEST_STAGEDIR=L\"%NV_TEST_STAGE%\"" "/DNETVIGIL_PUBKEY_HEADER=\"%NV_TEST_PUBKEY%\"" src\main.cpp src\gui.cpp src\diagnose.cpp src\startup.cpp src\proxy.cpp src\update.cpp src\updatecore.cpp /Fo:"%NV_TEST_OUT%\\" /Fe:"%NV_TEST_OUT%\NetVigilTest.exe" /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED
if errorlevel 1 exit /b 1
echo Built %NV_TEST_OUT%\NetVigilTest.exe
exit /b 0
