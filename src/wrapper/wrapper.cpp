// revival_wrapper.exe
//
// Goley_.exe icin IFEO (Image File Execution Options) debugger wrapper.
// Su registry kaydina yerlestiriliyor:
//
//   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
//     Image File Execution Options\Goley_.exe :: Debugger = <bu .exe>
//
// Kayit yapildiktan sonra her CreateProcess(Goley_.exe) cagrisini Windows
// soyle ceviriyor:
//
//     wrapper.exe <Goley_.exe yolu> <orijinal arg'lar>
//
// Wrapper sirayla: Goley_'i CREATE_SUSPENDED ile spawn et, patcher DLL'i
// inject et, ResumeThread cagir. Goley_ ilk instruction'ini calistirmadan
// once DLL yuklenmis olur, nProtect'in child-side anti-debug'i daha
// silahlanmamis olur, bu yuzden CreateRemoteThread(LoadLibraryA) basarili
// olur. Asil oyun runtime DllMain icinde basliyor.

#include <windows.h>
#include <stdio.h>
#include <string>

// DLL ve log dosyasinin yollari wmain'de exe'nin kendi konumundan
// hesaplaniyor. Hardcoded path kullanmiyoruz; repo nereye tasinirsa
// dogru yollar otomatik buluyor.
static wchar_t DLL_PATH[MAX_PATH] = {0};
static wchar_t LOG_PATH[MAX_PATH] = {0};

static void Log(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    HANDLE h = CreateFileW(LOG_PATH, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t timed[2200];
        int n = swprintf_s(timed, _countof(timed),
            L"[%02d:%02d:%02d.%03d] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
        DWORD written;
        // Convert to UTF-8 for log file
        char utf8[4400];
        int sz = WideCharToMultiByte(CP_UTF8, 0, timed, n, utf8, _countof(utf8), NULL, NULL);
        if (sz > 0) WriteFile(h, utf8, sz, &written, NULL);
        CloseHandle(h);
    }
}

// Inject DLL into the given (suspended) child process.
// Uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW).
// Child is CREATE_SUSPENDED so its address space is fully initialized AND
// its main thread is paused -- CreateRemoteThread succeeds reliably here.
static bool InjectDll(HANDLE hProcess, const wchar_t* dllPath) {
    SIZE_T pathBytes = (lstrlenW(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, pathBytes,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!pRemote) {
        Log(L"InjectDll: VirtualAllocEx FAILED err=%lu", GetLastError());
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemote, dllPath, pathBytes, &written)) {
        Log(L"InjectDll: WriteProcessMemory FAILED err=%lu", GetLastError());
        return false;
    }
    HMODULE hKern = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibW =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKern, "LoadLibraryW");
    if (!pLoadLibW) {
        Log(L"InjectDll: GetProcAddress(LoadLibraryW) FAILED");
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        pLoadLibW, pRemote, 0, NULL);
    if (!hThread) {
        Log(L"InjectDll: CreateRemoteThread FAILED err=%lu", GetLastError());
        return false;
    }
    Log(L"InjectDll: remote LoadLibraryW thread launched, waiting...");
    WaitForSingleObject(hThread, 15000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    Log(L"InjectDll: LoadLibraryW returned 0x%08lX (HMODULE)", exitCode);
    return exitCode != 0;
}

// DLL ve log dosyasi yollarini exe'nin kendi konumuna gore hesaplar.
// wrapper.exe su yapida bulunuyor: <repo>/src/wrapper/revival_wrapper.exe
//   DLL_PATH = <repo>/src/patcher/revival_patcher.dll
//   LOG_PATH = <repo>/wrapper.log
static void ResolvePaths(void) {
    wchar_t exePath[MAX_PATH] = {0};
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return;
    // exePath'i parcala: <repo>\src\wrapper\revival_wrapper.exe
    // Bir seviye yukari -> <repo>\src\wrapper
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (!slash) return;
    *slash = 0;
    // Wrapper'in bulundugu klasor: <repo>\src\wrapper
    wsprintfW(DLL_PATH, L"%s\\..\\patcher\\revival_patcher.dll", exePath);
    // Log: <repo>\wrapper.log (iki seviye yukari)
    wchar_t* up1 = wcsrchr(exePath, L'\\');     // <repo>\src
    if (up1) {
        *up1 = 0;
        wchar_t* up2 = wcsrchr(exePath, L'\\'); // <repo>
        if (up2) { *up2 = 0; }
    }
    wsprintfW(LOG_PATH, L"%s\\wrapper.log", exePath);
}

int wmain(int argc, wchar_t* argv[]) {
    ResolvePaths();
    Log(L"===== wrapper.exe started, argc=%d =====", argc);
    for (int i = 0; i < argc; i++) {
        Log(L"  argv[%d] = %s", i, argv[i]);
    }

    if (argc < 2) {
        Log(L"Usage: wrapper.exe <exe_path> [args...]");
        return 1;
    }

    // ===== Anti-recursion guard =====
    // IFEO Debugger redirection applies to EVERY CreateProcess(Goley_.exe),
    // including the one we make below. Without a guard, our spawn of
    // Goley_.exe gets re-redirected to wrapper.exe (us again) -> fork bomb.
    //
    // We set GLY_NO_WRAPPER=1 in our environment before calling
    // CreateProcessW. The new wrapper instance (which IFEO will spawn)
    // inherits the env, sees the flag, and uses DEBUG_PROCESS to bypass
    // IFEO for its own spawn -- Windows skips IFEO when the parent is
    // already attached as a debugger.
    DWORD chainLen = GetEnvironmentVariableW(L"GLY_NO_WRAPPER", NULL, 0);
    DWORD creationFlags = CREATE_SUSPENDED;
    if (chainLen > 0) {
        // We are a re-invocation. Use DEBUG_PROCESS to bypass IFEO check
        // when WE spawn the real Goley_.exe (Windows treats us as the
        // debugger; doesn't apply Debugger key again).
        Log(L"Recursion detected (env GLY_NO_WRAPPER set) -- using DEBUG_PROCESS");
        creationFlags |= DEBUG_PROCESS;
    } else {
        // First invocation. Set env so children skip the IFEO bounce.
        SetEnvironmentVariableW(L"GLY_NO_WRAPPER", L"1");
        Log(L"First wrapper instance -- env GLY_NO_WRAPPER=1 set");
    }

    // IFEO passes the target exe path as argv[1], any original args follow.
    std::wstring exePath = argv[1];

    std::wstring cmdLine;
    cmdLine += L"\"";
    cmdLine += exePath;
    cmdLine += L"\"";
    for (int i = 2; i < argc; i++) {
        cmdLine += L" ";
        cmdLine += argv[i];
    }

    Log(L"Spawning: exe='%s' creationFlags=0x%X", exePath.c_str(), creationFlags);
    Log(L"Cmdline:  %s", cmdLine.c_str());

    std::wstring cmdBuf = cmdLine;

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(
        exePath.c_str(),
        &cmdBuf[0],
        NULL, NULL, FALSE,
        creationFlags,
        NULL, NULL,
        &si, &pi);

    // If DEBUG_PROCESS was used, detach RIGHT NOW (before InjectDll).
    // Without detach, the child's threads are throttled waiting for our
    // (nonexistent) debugger event loop, so CreateRemoteThread(LoadLibraryW)
    // never executes. After DebugActiveProcessStop the child is a normal
    // CREATE_SUSPENDED process and our injection succeeds.
    if (ok && (creationFlags & DEBUG_PROCESS)) {
        DebugSetProcessKillOnExit(FALSE);
        BOOL detached = DebugActiveProcessStop(pi.dwProcessId);
        Log(L"DebugActiveProcessStop (early detach) returned %d", detached);
    }
    if (!ok) {
        Log(L"CreateProcessW FAILED err=%lu", GetLastError());
        return 1;
    }
    Log(L"CreateProcess OK PID=%lu (suspended)", pi.dwProcessId);

    // Inject our patcher DLL while the child is suspended. At this point
    // the child's main thread is created but paused -- nProtect's child-
    // side self-protect code hasn't run yet, so CreateRemoteThread works.
    bool injected = InjectDll(pi.hProcess, DLL_PATH);
    Log(L"InjectDll returned %s", injected ? L"OK" : L"FAIL");

    // If we attached as debugger (recursive call), detach now so child
    // runs free. Without detach, the OS expects us to pump debug events,
    // which we don't.
    if (creationFlags & DEBUG_PROCESS) {
        BOOL detached = DebugActiveProcessStop(pi.dwProcessId);
        Log(L"DebugActiveProcessStop returned %d (detached debugger)", detached);
    }

    // No Sleep between inject and Resume -- the dnight 22:46 baseline
    // (which actually produced a visible splash and a stable PID for 80+s)
    // had no sleep here. Both Sleep(300) and Sleep(80) broke Themida's
    // internal unpack timer; the unpacker hung at val=0 forever.
    DWORD resumed = ResumeThread(pi.hThread);
    Log(L"ResumeThread returned %lu (prev suspend count)", resumed);

    // Wait for child to exit, then return its exit code (Windows debugger
    // protocol: the debugger should wait on the debuggee).
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    Log(L"Child exited with code %lu", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)exitCode;
}
