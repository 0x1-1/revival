@echo off
REM Tek seferlik client build helper -- vcvars yolu hardcoded (dogrulandi),
REM parantezli if-blogu yok (cmd'nin (x86) paren-sayim bug'ini onler).
set "VC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VC%" echo ERROR: vcvars yok: %VC% & exit /b 1
call "%VC%"

echo === [1/3] revival_tool.exe ===
cd /d "C:\Joygame\revival\src\tool"
cl.exe /nologo /EHsc /O2 /MT /W3 main.cpp /link /SUBSYSTEM:CONSOLE /MACHINE:X86 user32.lib advapi32.lib shell32.lib psapi.lib /OUT:revival_tool.exe
if errorlevel 1 echo TOOL BUILD FAILED & exit /b 1

echo === [2/3] revival_patcher.dll ===
cd /d "C:\Joygame\revival\src\patcher"
cl.exe /nologo /LD /O2 /MT /Iminhook/include /Iminhook /Iminhook/hde patcher.cpp minhook/hook.c minhook/buffer.c minhook/trampoline.c minhook/hde/hde32.c /link /SUBSYSTEM:WINDOWS /MACHINE:X86 user32.lib kernel32.lib /OUT:revival_patcher.dll
if errorlevel 1 echo PATCHER BUILD FAILED & exit /b 1

echo === [3/3] revival_wrapper.exe ===
cd /d "C:\Joygame\revival\src\wrapper"
cl.exe /nologo /O2 /MT /EHsc wrapper.cpp /link /SUBSYSTEM:CONSOLE /MACHINE:X86 user32.lib kernel32.lib /OUT:revival_wrapper.exe
if errorlevel 1 echo WRAPPER BUILD FAILED & exit /b 1

echo === ALL CLIENT BUILDS OK ===
