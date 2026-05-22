@echo off
REM Build revival_patcher.dll (32-bit, Goley_.exe matches)
REM Requires Visual Studio 2022 Build Tools

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

REM Compile MinHook C sources + our patcher.cpp into one DLL.
REM MinHook gives us a safe trampoline-based API hook framework
REM (used to intercept kernel32!CreateProcessA so we can inject
REM our DLL into the GameMon.des child that nProtect spawns).
cl.exe /nologo /LD /O2 /MT ^
    /Iminhook/include /Iminhook /Iminhook/hde ^
    patcher.cpp ^
    minhook/hook.c ^
    minhook/buffer.c ^
    minhook/trampoline.c ^
    minhook/hde/hde32.c ^
    /link /SUBSYSTEM:WINDOWS /MACHINE:X86 ^
    user32.lib kernel32.lib ^
    /OUT:revival_patcher.dll

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === revival_patcher.dll built ===
dir revival_patcher.dll
