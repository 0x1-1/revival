@echo off
REM Build revival_tool.exe -- 32-bit console application.
REM
REM Why 32-bit: dump-threads reads CONTEXT from Goley_'s (32-bit) threads.
REM A 64-bit tool would need Wow64GetThreadContext; staying x86 keeps the
REM code identical to Goley_'s register layout.

set "VC_VARS="
for %%e in (BuildTools Community Professional Enterprise) do if not defined VC_VARS if exist "C:\Program Files\Microsoft Visual Studio\2022\%%e\VC\Auxiliary\Build\vcvars32.bat" set "VC_VARS=C:\Program Files\Microsoft Visual Studio\2022\%%e\VC\Auxiliary\Build\vcvars32.bat"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not defined VC_VARS if exist "%VSWHERE%" for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VC_VARS=%%i\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VC_VARS%" (
    echo ERROR: vcvars32.bat not found. Install VS 2022 Build Tools with the
    echo "MSVC v143 C++ x86/x64" component, or fix VC_VARS in this script.
    exit /b 1
)

call "%VC_VARS%"
cd /d "%~dp0"

cl.exe /nologo /EHsc /O2 /MT /W3 ^
    main.cpp ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X86 ^
    user32.lib advapi32.lib shell32.lib psapi.lib ^
    /OUT:revival_tool.exe

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === revival_tool.exe built ===
dir revival_tool.exe
