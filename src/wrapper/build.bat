@echo off
REM Build revival_wrapper.exe (32-bit so it matches Goley_.exe arch).
REM IFEO Debugger key will invoke this binary in front of Goley_.exe.

set "VC_VARS="
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat" set "VC_VARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
if not defined VC_VARS if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat" set "VC_VARS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
if not defined VC_VARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" set "VC_VARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"

if not exist "%VC_VARS%" (
    echo ERROR: vcvars32.bat not found. Install VS 2022 Build Tools MSVC v143 x86 x64.
    exit /b 1
)

call "%VC_VARS%"
cd /d "%~dp0"

REM /MT = static CRT so the wrapper has zero install deps.
REM /EHsc = standard C++ exception model for std::wstring.
cl.exe /nologo /O2 /MT /EHsc ^
    wrapper.cpp ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X86 ^
    user32.lib kernel32.lib ^
    /OUT:revival_wrapper.exe

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === revival_wrapper.exe built ===
dir revival_wrapper.exe
