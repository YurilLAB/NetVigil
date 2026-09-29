@echo off
setlocal
rem build.bat        builds build\NetVigil.exe
rem build.bat test   builds and runs the decision-logic unit tests
set "TARGET=app"
if /i "%~1"=="test" set "TARGET=test"

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

rem Hardening: /GS (default) + /guard:cf (control-flow guard) + /sdl (extra runtime checks);
rem at link time ASLR (high entropy), DEP, CET shadow stacks, and System32-only loading of
rem every DLL the exe imports (DEPENDENTLOADFLAG 0x800 = LOAD_LIBRARY_SEARCH_SYSTEM32).
cl /nologo /utf-8 /W4 /O2 /GL /EHsc /std:c++17 /GS /guard:cf /sdl /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 src\main.cpp src\gui.cpp src\diagnose.cpp src\startup.cpp src\proxy.cpp /Fo:build\ /Fe:build\NetVigil.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /LTCG /OPT:REF /OPT:ICF /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT /DEPENDENTLOADFLAG:0x800
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
