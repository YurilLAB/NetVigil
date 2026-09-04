@echo off
setlocal
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
cl /nologo /utf-8 /W4 /O2 /GL /EHsc /std:c++17 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 src\main.cpp src\gui.cpp /Fo:build\ /Fe:build\NetVigil.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /LTCG /OPT:REF /OPT:ICF
if errorlevel 1 exit /b 1
echo.
echo Built build\NetVigil.exe
