// revival_patcher.dll
//
// Goley_.exe'ye inject edilen ana DLL. Themida packer'ini ve nProtect
// anti-cheat'i atlatmaktan sorumlu.
//
// Strateji ozeti:
//   - Themida hafiza uzerinde patch yapilmasini hash check ile yakaliyor.
//     Bu yuzden binary'e hicbir zaman dokunmuyoruz. Onun yerine donanim
//     breakpoint (DR0) ile validation branch'ini yakalayip VEH icinde
//     EIP'yi yeniden yaziyoruz. Memory degismedi, hash check gecer.
//   - Process'i olduren API'leri (TerminateProcess, ExitProcess, ntdll
//     muadilleri) DllMain icinde inline patch'liyoruz. Boylece Themida
//     unpack basladiginda zaten silah'lanmis durumdayiz, yarisi mimari
//     olarak kaybetmemis oluyoruz. Detay: docs/THEMIDA_BYPASS.md
//   - nProtect'in MessageBox dialog'larini IAT hijack + HW BP ile
//     bastiriyoruz.

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

// MinHook: kernel32!CreateProcessA ve CreateProcessW hook'lari icin.
// nProtect "trusted re-launch" pattern'i ile Goley_'i tekrar spawn
// edebiliyor; bu hook'lar sayesinde child process'lere de DLL inject
// edebiliyoruz. MinHook (BSD) build.bat icinde bu DLL'e statik olarak
// dahil ediliyor (hde32 + trampoline + buffer modulleri).
#include "MinHook.h"

// DLL'in disk uzerindeki yolu. DllMain icinde GetModuleFileNameA ile
// hesaplaniyor. Child process'lere kendimizi inject ederken bu yolu
// kullaniyoruz (LoadLibraryA target process'te bizim DLL'i bulsun diye).
static char SELF_DLL_PATH[MAX_PATH] = {0};

// Validation function entry point (image base 0x400000 + RVA 0x93dc4d = 0xD3DC4D)
// This is `cmp byte [esp+13h], 0`:entry of the validation fail path.
// We want to skip this entire path, jumping to success_path = 0xD3DCF2.
//
// Pattern at 0xD3DC4D: 80 7C 24 13 00 0F 85 94 00 00 00 ...
// Instead of patching, we break before execution and rewrite EIP.

static const DWORD VALIDATION_RVA = 0x93DC4D;
static const DWORD SUCCESS_RVA    = 0x93DCF2;  // target jmp destination

// GameGuard CHECK result handler. Originally we tried to skip `call 0x8e3550`
// entirely (PRIMARY_RVA = 0x935374), but the function has side effects --
// internal GG state flags that downstream code relies on. Skipping it
// triggered an immediate (~1 sec) suicide.
//
// New strategy: let the call EXECUTE (preserves side effects), then HW BP
// at the instruction RIGHT AFTER the call (`mov esi, eax` at 0xD35379).
// We force EAX = 0x755 just before the move, so esi gets the magic
// "all clear" value -- the je at 0xD35381 then routes into success path.
static const DWORD GG_RESULT_PATCH_RVA = 0x935379;  // 0xD35379 (mov esi, eax)
static const DWORD GG_OK_STATUS        = 0x755;

// Parent's CreateProcessA call site that spawns the "trusted" child Goley_.
// At 0xD35586/etc. happens; THIS specific site is the re-exec call.
// Static disasm showed call [0x199854C] sites at 0x8DE91A/0x8E5015/0x8E5A19/0x8EA21B.
// 0x8E5A19 is the most likely re-exec (pushes 0x12b1d48 = exe path).
//
// On HW BP hit at the CALL: read dwCreationFlags from stack (6th __stdcall arg),
// OR-in CREATE_SUSPENDED (0x4) so the child spawns frozen. PowerShell watcher
// then injects + resumes -- this is the only way to beat Themida's anti-inject
// timing window in the child.
static const DWORD GG_CREATEPROC_CALL_RVA = 0x4E5A19;  // 0x8E5A19 - 0x400000

// Old MessageBoxW CALL skip (kept as fallback / additional intercept)
static const DWORD GG_MBW_CALL_RVA      = 0x935586;
static const DWORD GG_MBW_CALL_NEXT_RVA = 0x93558B;

// IAT slot kept for diagnostics (it's MEM_FREE at runtime due to Themida obfuscation)
static const DWORD GOLEY_MBW_IAT_VA = 0x019984D4;

// GameGuard error 153 dialog comes from nProtect's own DLL (decrypted from
// npggNT.des at runtime) calling user32!MessageBoxW directly -- NOT from
// Goley_'s ShowGameGuardError function (which we found earlier handles
// error codes 1001-1018 only). So we hook MessageBoxW/MessageBoxA at the
// user32 export entry. On HW BP hit at the FIRST instruction of these
// functions: return IDOK (1) without showing any dialog.
//
// __stdcall MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT) -- 4 args, 16 bytes
// On entry: [esp] = return addr, [esp+4..esp+16] = args
// We restore ESP and EIP as if "ret 16" had executed.
static BYTE* g_imageBase = NULL;
static PVOID g_vehHandle = NULL;
static DWORD g_msgBoxAVA = 0;                   // resolved at PatchThread start
static DWORD g_msgBoxWVA = 0;
static volatile LONG g_valHit = 0;             // validation bypass hit
static volatile LONG g_mbaHit = 0;             // MessageBoxA suppression hit count
static volatile LONG g_mbwHit = 0;             // MessageBoxW suppression hit count
static volatile LONG g_ggrHit = 0;             // GG result patch hit (one-shot)
static volatile LONG g_cpHit  = 0;             // CreateProcess call patched flag (one-shot)
static DWORD g_createProcessWVA = 0;            // resolved at PatchThread start

// Log dosyasinin yolu. DllMain'de hesaplanir: bu DLL'in bulundugu
// klasor + "..\\..\\patcher.log" (yani repo'nun kokune).
static char g_logPath[MAX_PATH] = {0};

static void Log(const char* msg) {
    // Eger Log() DllMain'den once cagrilirsa, fallback olarak
    // %TEMP%\patcher.log'a yaz.
    const char* path = g_logPath[0] ? g_logPath : "patcher.log";
    HANDLE h = CreateFileA(path,
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD written;
        char timed[1100];
        SYSTEMTIME st;
        GetLocalTime(&st);
        int n = wsprintfA(timed, "[%02d:%02d:%02d.%03d P=%lu] %s\r\n",
                          st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                          GetCurrentProcessId(), msg);
        WriteFile(h, timed, n, &written, NULL);
        CloseHandle(h);
    }
}

// VEH handler:gets called whenever ANY exception fires in the process.
static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS exc) {
    DWORD code = exc->ExceptionRecord->ExceptionCode;
    DWORD eip = exc->ContextRecord->Eip;

    // Themida anti-debug fingerprint: ntdll-level INT3 (0xCC) sprinkled
    // through unpacker. With a debugger attached, the debugger consumes
    // these and Themida sees "debugger present -> abort". With NO
    // debugger and NO VEH, they go to OS UnhandledExceptionFilter -> die.
    // We swallow them: skip past the 0xCC byte (EIP+1) and continue --
    // same effect as a debugger that quietly absorbs them.
    if (code == EXCEPTION_BREAKPOINT &&
        eip >= 0x77000000 && eip < 0x78000000) {  // ntdll range (32-bit ASLR)
        exc->ContextRecord->Eip = eip + 1;
        // No log here -- can fire hundreds of times; would flood the log.
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // We installed DR0 hardware breakpoint on validation branch entry.
    // When EIP hits it, Windows fires EXCEPTION_SINGLE_STEP.
    //
    // IMPORTANT: 0xD3DC4D is NOT a function entry -- it is an inline
    // conditional branch INSIDE a larger function. Original code:
    //   D3DC4D: 80 7C 24 13 00       cmp byte [esp+13h], 0
    //   D3DC52: 0F 85 9A 00 00 00    jne 0xD3DCF2     (success_path)
    //   D3DC58: ... fail path ...
    // So we must NOT pop the stack or fake-return. We jump directly to
    // the success branch (EIP = SUCCESS_RVA). Stack stays intact, EAX
    // untouched. Semantically identical to "patch jne -> jmp" but
    // without modifying memory (Themida hash check stays happy).
    if (code == EXCEPTION_SINGLE_STEP) {
        DWORD valVA  = (DWORD)(g_imageBase + VALIDATION_RVA);
        DWORD ggrVA  = (DWORD)(g_imageBase + GG_RESULT_PATCH_RVA);
        DWORD mbwVA  = (DWORD)(g_imageBase + GG_MBW_CALL_RVA);
        DWORD mbwNx  = (DWORD)(g_imageBase + GG_MBW_CALL_NEXT_RVA);

        // -- ntdll!NtCreateUserProcess entry point hook
        //    Lowest-level user-mode syscall stub for process creation. Args:
        //      [esp+0x00] = return addr
        //      [esp+0x04] = ProcessHandle (out)
        //      [esp+0x08] = ThreadHandle (out)
        //      [esp+0x0C] = ProcessDesiredAccess
        //      [esp+0x10] = ThreadDesiredAccess
        //      [esp+0x14] = ProcessObjectAttributes
        //      [esp+0x18] = ThreadObjectAttributes
        //      [esp+0x1C] = ProcessFlags
        //      [esp+0x20] = ThreadFlags     <-- set bit 0 (CREATE_SUSPENDED) here
        //      [esp+0x24] = ProcessParameters
        //      [esp+0x28] = CreateInfo
        //      [esp+0x2C] = AttributeList
        if (g_createProcessWVA && eip == g_createProcessWVA) {
            DWORD* esp = (DWORD*)exc->ContextRecord->Esp;
            DWORD origThreadFlags = esp[8];          // [esp+0x20]
            DWORD newThreadFlags  = origThreadFlags | 0x1;  // THREAD_CREATE_FLAGS_CREATE_SUSPENDED
            esp[8] = newThreadFlags;
            char buf[200];
            wsprintfA(buf, "NtCreateUserProcess hooked @ 0x%X: ThreadFlags 0x%X -> 0x%X caller=0x%X",
                      eip, origThreadFlags, newThreadFlags, esp[0]);
            Log(buf);
            exc->ContextRecord->Dr3  = 0;
            exc->ContextRecord->Dr7 &= ~0x40;
            InterlockedExchange(&g_cpHit, 1);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- GameGuard CHECK RESULT @ 0xD35379 (PRIMARY bypass)
        //    The check function 0x8e3550 has already executed (preserving
        //    side effects). We're now at `mov esi, eax`. Force EAX=0x755
        //    BEFORE the move so esi gets the magic, then cmp/je routes
        //    naturally into the success path.
        if (eip == ggrVA) {
            char buf[160];
            DWORD origEax = exc->ContextRecord->Eax;
            wsprintfA(buf, "GG RESULT patched @ 0x%X: EAX 0x%X -> 0x755",
                      eip, origEax);
            Log(buf);
            exc->ContextRecord->Eax = GG_OK_STATUS;
            exc->ContextRecord->Dr2  = 0;
            exc->ContextRecord->Dr7 &= ~0x10;        // disarm L2
            InterlockedExchange(&g_ggrHit, 1);       // tell refresh loop to stop re-arming DR2
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- MessageBoxW CALL site (GameGuard error 150 dialog)
        // Runtime bytes here: E8 FA B1 11 06 (rel32 call into Themida VM
        // that forwards to user32!MessageBoxW). We skip the entire 5-byte
        // CALL by setting EIP to the next instruction. EAX = IDOK so any
        // caller that expects "user clicked OK" semantics keeps flowing.
        if (eip == mbwVA) {
            char buf[160];
            wsprintfA(buf, "MessageBoxW CALL skipped @ 0x%X -> EIP=0x%X EAX=1 (IDOK)",
                      eip, mbwNx);
            Log(buf);
            exc->ContextRecord->Eax = 1;             // IDOK
            exc->ContextRecord->Eip = mbwNx;         // skip the CALL
            exc->ContextRecord->Dr1  = 0;
            exc->ContextRecord->Dr7 &= ~0x4;         // disarm L1
            InterlockedIncrement(&g_mbwHit);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- Themida validation branch (0xD3DC4D)
        if (eip == valVA) {
            // STRATEGY: Do NOT jump to success_path -- that path expects
            // validation code to have initialized certain registers/memory
            // first, so jumping in mid-stride causes NULL deref @ 0xD3DCF4.
            //
            // Instead, RIG THE INPUT: poke [esp+0x13] = 1 so when
            //   cmp byte [esp+13h], 0   (at this address)
            //   jne 0xD3DCF2            (at +5)
            // executes naturally, cmp sees nonzero, jne is TAKEN, and
            // validation flows into success path with ALL side-effects
            // (register init, etc.) properly performed.
            //
            // Then self-disarm DRx so the cmp itself doesn't re-trigger
            // the breakpoint after we return EXCEPTION_CONTINUE_EXECUTION.
            BYTE* stackByte = (BYTE*)(exc->ContextRecord->Esp + 0x13);
            BYTE  oldVal = *stackByte;
            *stackByte = 1;

            char buf[256];
            wsprintfA(buf, "VEH hit! EIP=0x%X  [esp+13h]: 0x%02X -> 0x01  (let cmp/jne run natural)",
                      eip, oldVal);
            Log(buf);

            // Disarm DR0/L0 in THIS thread so the same instruction doesn't
            // re-fire the BP on every retry. The refresh loop will see
            // g_valHit=1 and stop arming new threads.
            exc->ContextRecord->Dr0  = 0;
            exc->ContextRecord->Dr7 &= ~0x1;         // clear L0 only (keep L1/L2)

            // Don't touch EIP -- let the cmp/jne execute normally.
            InterlockedExchange(&g_valHit, 1);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Themida's VM dispatcher fires THOUSANDS of STATUS_PRIVILEGED_INSTRUCTION
    // (0xC0000096) exceptions per second emulating cpuid/rdtsc/etc. Logging
    // each one is so slow that Themida's own VEH chain gets starved and the
    // process can't finish unpacking. So filter to "interesting" codes only:
    //   - ACCESS_VIOLATION  (0xC0000005) -- could indicate Themida's tamper kill
    //   - INVALID_HANDLE    (0xC0000008)
    //   - STACK_OVERFLOW    (0xC00000FD)
    //   - INTEGER_DIVIDE    (0xC0000094)
    //   - BREAKPOINT        (0x80000003)
    //   - ILLEGAL_INSTRUCTION(0xC000001D)
    if (code == EXCEPTION_ACCESS_VIOLATION   ||
        code == 0xC0000008 /* INVALID_HANDLE */ ||
        code == EXCEPTION_STACK_OVERFLOW     ||
        code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
        code == EXCEPTION_BREAKPOINT         ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        // Filter out our OWN IAT probe -- when Themida hasn't mapped the
        // import page yet, our `*(DWORD*)GOLEY_MBW_IAT_VA` read access-faults.
        // VirtualQuery pre-check is in place but defense-in-depth: also ignore
        // the AV when fault address matches our IAT slot exactly.
        DWORD faultAddr = exc->ExceptionRecord->NumberParameters > 1
                          ? (DWORD)exc->ExceptionRecord->ExceptionInformation[1] : 0;
        if (code == EXCEPTION_ACCESS_VIOLATION && faultAddr == GOLEY_MBW_IAT_VA) {
            return EXCEPTION_CONTINUE_SEARCH;  // silent
        }

        // AV-rescue RE-ENABLED for the IFEO-wrapper setup. Previously
        // this triggered a self-re-exec path that hid the window, but
        // now wrapper.exe catches the re-exec via IFEO and injects our
        // DLL into the child too -- so going down the re-exec branch
        // is fine, the child carries our bypass.
        static const wchar_t g_emptyWStr[2] = { 0, 0 };
        if (code == EXCEPTION_ACCESS_VIOLATION &&
            eip == 0xD30313 && faultAddr == 0) {
            exc->ContextRecord->Edx = (DWORD)(ULONG_PTR)&g_emptyWStr[0];
            char buf[160];
            wsprintfA(buf, "AV @ 0xD30313 [edx]=NULL -> EDX=0x%p (empty wstring)",
                      &g_emptyWStr[0]);
            Log(buf);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        char buf[256];
        wsprintfA(buf, "INTERESTING EXC: code=0x%X EIP=0x%X flags=0x%X p0=0x%X p1=0x%X",
                  code, eip, exc->ExceptionRecord->ExceptionFlags,
                  exc->ExceptionRecord->NumberParameters > 0
                      ? (DWORD)exc->ExceptionRecord->ExceptionInformation[0] : 0,
                  faultAddr);
        Log(buf);

        // NOTE: tried 2026-05-21 evening to swallow ntdll/image-range AVs
        // with EXCEPTION_CONTINUE_EXECUTION + EIP+0 -- produced 54000+ exception
        // log entries in 3 seconds (infinite loop). Removed. The correct fix
        // is HDE32 instruction-length advance, deferred to next session.
        // See CHECKPOINT_2026-05-21.md.
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Inline-patch a __stdcall(N args) function to: mov eax, 1; ret <retBytes>
// Used to neutralize select user32/kernel32 APIs so the game/anti-cheat
// either fakes-success or silently no-ops. Memory write is on system DLLs,
// NOT on Themida-protected game code, so Themida's hash check stays happy.
//
// 8 bytes overwritten at function entry:
//   B8 01 00 00 00      mov eax, 1     ; success / IDOK / TRUE
//   C2 RR 00 / 90...    ret <retBytes> ; stdcall cleanup
//
// For functions that take N args (4 bytes each), retBytes = N * 4.
// Special case ExitProcess: it normally never returns, but we override that
// by returning (with EAX=0 and ret 4) so the caller continues execution.
static BOOL PatchStdcallStub(DWORD funcVA, int retBytes, const char* name) {
    if (!funcVA) {
        char buf[128];
        wsprintfA(buf, "PatchStdcallStub: %s VA is NULL, skipped", name);
        Log(buf);
        return FALSE;
    }
    BYTE patch[8] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,         // mov eax, 1
        0xC2, (BYTE)(retBytes & 0xFF), 0x00   // ret <retBytes>
    };
    DWORD oldProt = 0;
    LPVOID target = (LPVOID)(ULONG_PTR)funcVA;
    if (!VirtualProtect(target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt)) {
        char buf[128];
        wsprintfA(buf, "PatchStdcallStub: VirtualProtect failed for %s (err=%lu)",
                  name, GetLastError());
        Log(buf);
        return FALSE;
    }
    BYTE orig[8];
    memcpy(orig, target, sizeof(orig));
    memcpy(target, patch, sizeof(patch));

    DWORD dummy;
    VirtualProtect(target, sizeof(patch), oldProt, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(patch));

    char buf[256];
    wsprintfA(buf, "Patched %s @ 0x%X  orig=%02X%02X%02X%02X%02X%02X%02X%02X -> mov eax,1 / ret %d",
              name, funcVA,
              orig[0], orig[1], orig[2], orig[3], orig[4], orig[5], orig[6], orig[7],
              retBytes);
    Log(buf);
    return TRUE;
}

// Backward-compat shim for the existing call sites
static BOOL PatchMessageBoxStub(DWORD funcVA, const char* name) {
    return PatchStdcallStub(funcVA, 16, name);  // 4 args
}

// Fake MessageBoxW that Goley_'s IAT will point at after we hijack the slot.
// Returns IDOK without showing any dialog.
static int WINAPI FakeMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    char tbuf[256] = {0};
    char cbuf[256] = {0};
    // Best-effort log: convert wide -> ANSI for log file (truncate at 255).
    if (lpText) {
        for (int i = 0; i < 255 && lpText[i]; i++) {
            tbuf[i] = (lpText[i] < 0x80) ? (char)lpText[i] : '?';
        }
    }
    if (lpCaption) {
        for (int i = 0; i < 255 && lpCaption[i]; i++) {
            cbuf[i] = (lpCaption[i] < 0x80) ? (char)lpCaption[i] : '?';
        }
    }
    char buf[1024];
    wsprintfA(buf, "FakeMessageBoxW INTERCEPT: caption='%s' text='%s' type=0x%X -> IDOK",
              cbuf, tbuf, uType);
    Log(buf);
    return 1;  // IDOK
}

// Scan process memory for all 4-byte aligned DWORDs that equal `target`,
// optionally overwriting them with `replacement`. Returns count of slots
// found/patched. Themida obfuscates the original IAT, so the only reliable
// way to find function-pointer slots is to scan runtime memory for the
// resolved API address itself.
//
// We deliberately SKIP our own DLL's memory range to avoid breaking our
// own MessageBoxW import (could cause infinite recursion if we ever call
// it from our code).
static int ScanAndReplaceFnPointer(DWORD target, DWORD replacement, const char* name,
                                   BOOL dryRun) {
    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = (BYTE*)0x00010000;
    BYTE* endAddr = (BYTE*)0x7FFE0000;  // user-mode upper limit (x86)

    // Compute our own DLL's memory range so we can exclude it
    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&ScanAndReplaceFnPointer, &hSelf);
    DWORD selfBase = (DWORD)(ULONG_PTR)hSelf;
    DWORD selfEnd  = selfBase + 0x100000;  // assume <=1MB DLL
    while (addr < endAddr) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += 0x10000;
            continue;
        }
        // Skip free / guard / no-access pages, and skip executable code
        // sections (we only want data sections where IAT slots live).
        BOOL skip = (mbi.State != MEM_COMMIT)
                 || (mbi.Protect & PAGE_NOACCESS)
                 || (mbi.Protect & PAGE_GUARD)
                 // skip pure-executable pages (no read => unlikely IAT)
                 || (mbi.Protect == PAGE_EXECUTE);

        // Also skip our own DLL's memory
        DWORD regionStart = (DWORD)(ULONG_PTR)mbi.BaseAddress;
        if (regionStart >= selfBase && regionStart < selfEnd) {
            skip = TRUE;
        }

        if (!skip) {
            DWORD scanStart = (DWORD)(ULONG_PTR)mbi.BaseAddress;
            DWORD scanEnd   = scanStart + (DWORD)mbi.RegionSize;
            // Align to 4 bytes
            scanStart = (scanStart + 3) & ~3;
            for (DWORD p = scanStart; p + 4 <= scanEnd; p += 4) {
                __try {
                    if (*(DWORD*)(ULONG_PTR)p == target) {
                        found++;
                        if (!dryRun) {
                            DWORD oldProt;
                            if (VirtualProtect((LPVOID)(ULONG_PTR)p, 4, PAGE_READWRITE, &oldProt)) {
                                *(DWORD*)(ULONG_PTR)p = replacement;
                                DWORD dummy;
                                VirtualProtect((LPVOID)(ULONG_PTR)p, 4, oldProt, &dummy);
                                char buf[160];
                                wsprintfA(buf, "  patched %s slot at 0x%X  prot=0x%X",
                                          name, p, mbi.Protect);
                                Log(buf);
                            }
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    // Page changed mid-scan, skip
                    break;
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    char buf[160];
    wsprintfA(buf, "Memory scan for %s (target=0x%X) found %d slot(s) %s",
              name, target, found, dryRun ? "[dry-run]" : "[patched]");
    Log(buf);
    return found;
}

// Overwrite a DWORD at the given VA. Used to rewrite Goley_'s IAT slot.
static BOOL PatchIATSlot(DWORD slotVA, DWORD newValue, const char* name) {
    DWORD oldProt = 0;
    LPVOID slot = (LPVOID)(ULONG_PTR)slotVA;
    if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &oldProt)) {
        char buf[160];
        wsprintfA(buf, "PatchIATSlot: VirtualProtect failed for %s @ 0x%X (err=%lu)",
                  name, slotVA, GetLastError());
        Log(buf);
        return FALSE;
    }
    DWORD oldVal = *(DWORD*)slot;
    *(DWORD*)slot = newValue;
    DWORD dummy;
    VirtualProtect(slot, sizeof(DWORD), oldProt, &dummy);

    char buf[160];
    wsprintfA(buf, "IAT slot %s @ 0x%X: 0x%X -> 0x%X", name, slotVA, oldVal, newValue);
    Log(buf);
    return TRUE;
}

// Hook ExitProcess + TerminateProcess so we know who's killing us.
// We can't easily call original (which would require trampoline);
// instead we just LOG the call stack and then ABORT the kill by
// suspending the current thread forever -- this keeps the process alive
// long enough to inspect with a debugger.
typedef VOID(WINAPI *ExitProcess_t)(UINT);
typedef BOOL(WINAPI *TerminateProcess_t)(HANDLE, UINT);
static ExitProcess_t g_origExitProcess = NULL;
static TerminateProcess_t g_origTerminateProcess = NULL;

static VOID WINAPI HookedExitProcess(UINT uExitCode) {
    DWORD retAddr = (DWORD)(ULONG_PTR)_ReturnAddress();
    char buf[256];
    wsprintfA(buf, "*** ExitProcess(0x%X) called from caller=0x%X -- SUSPENDING thread ***",
              uExitCode, retAddr);
    Log(buf);
    // Suspend forever -- gives us time to attach debugger / take screenshot
    while (1) { Sleep(60000); }
}

static BOOL WINAPI HookedTerminateProcess(HANDLE hProc, UINT uExitCode) {
    DWORD retAddr = (DWORD)(ULONG_PTR)_ReturnAddress();
    char buf[256];
    wsprintfA(buf, "*** TerminateProcess(hProc=0x%p, code=0x%X) called from caller=0x%X -- BLOCKED ***",
              hProc, uExitCode, retAddr);
    Log(buf);
    // If target is OUR process, block it. If external, allow.
    if (hProc == GetCurrentProcess() || (DWORD)(ULONG_PTR)hProc == (DWORD)-1) {
        while (1) { Sleep(60000); }
    }
    return g_origTerminateProcess ? g_origTerminateProcess(hProc, uExitCode) : FALSE;
}

// Patch IAT of main module to redirect ExitProcess + TerminateProcess.
// Returns count of redirected slots.
static int HookKillApis() {
    int hooks = 0;
    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 0;

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) return 0;

    FARPROC origExit  = GetProcAddress(hKernel, "ExitProcess");
    FARPROC origTerm  = GetProcAddress(hKernel, "TerminateProcess");
    g_origExitProcess      = (ExitProcess_t)origExit;
    g_origTerminateProcess = (TerminateProcess_t)origTerm;

    BYTE* base = (BYTE*)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD impDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impDirRva) return 0;
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + impDirRva);

    for (; imp->Name; imp++) {
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
        for (; iat->u1.Function; iat++) {
            FARPROC* slot = (FARPROC*)&iat->u1.Function;
            DWORD oldProt;
            if (*slot == origExit) {
                VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &oldProt);
                *slot = (FARPROC)HookedExitProcess;
                VirtualProtect(slot, sizeof(FARPROC), oldProt, &oldProt);
                Log("Hooked ExitProcess IAT slot");
                hooks++;
            } else if (*slot == origTerm) {
                VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &oldProt);
                *slot = (FARPROC)HookedTerminateProcess;
                VirtualProtect(slot, sizeof(FARPROC), oldProt, &oldProt);
                Log("Hooked TerminateProcess IAT slot");
                hooks++;
            }
        }
    }
    return hooks;
}

// Enumerate threads in current process and set HW BP on all of them.
// Sets up to 4 simultaneous breakpoints in DR0/DR1/DR2/DR3 (only re-arms
// slots whose corresponding hit-flag is still 0). Pass 0 to skip a slot.
static int SetHardwareBreakpointAllThreads(DWORD t0, DWORD t1, DWORD t2, DWORD t3 = 0) {
    int success = 0;
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("CreateToolhelp32Snapshot failed");
        return 0;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;
            if (te.th32ThreadID == currentTid) continue;  // skip our own thread

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                // Build a clean Dr7 with execute-mode 1-byte BPs in DR0/DR1/DR2.
                // Each enabled slot uses RW=00 (execute) LEN=00 (1 byte), so
                // the upper 16 bits of Dr7 stay all-zero. The lower 8 bits
                // hold the L0/G0..L3/G3 enable flags. We enable only Lx for
                // slots whose target is non-zero AND not yet hit.
                DWORD dr7 = 0x00000000;
                if (t0) { ctx.Dr0 = t0; dr7 |= 0x1;  /* L0 */ }
                if (t1) { ctx.Dr1 = t1; dr7 |= 0x4;  /* L1 */ }
                if (t2) { ctx.Dr2 = t2; dr7 |= 0x10; /* L2 */ }
                if (t3) { ctx.Dr3 = t3; dr7 |= 0x40; /* L3 */ }
                else    { ctx.Dr3 = 0; }
                ctx.Dr7 = dr7;
                if (SetThreadContext(hThread, &ctx)) {
                    // Only log every 50th thread set to avoid log spam --
                    // 30+ threads * 20Hz = enormous log volume otherwise.
                    success++;
                }
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return success;
}

// Sweep-clear DR0..DR7 on every thread so Themida's GetThreadContext
// anti-debug probe sees a clean context. Called once after VEH self-disarm.
static int ClearHardwareBreakpointAllThreads() {
    int cleared = 0;
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;
            if (te.th32ThreadID == currentTid) continue;

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                ctx.Dr0 = 0;
                ctx.Dr1 = 0;
                ctx.Dr2 = 0;
                ctx.Dr3 = 0;
                ctx.Dr6 = 0;
                ctx.Dr7 = 0;
                if (SetThreadContext(hThread, &ctx)) cleared++;
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return cleared;
}

// ===========================================================================
// Passive thread-EIP polling -- finds the "wait point" without any hooks
// ===========================================================================
//
// Enumerate every thread in this process, SuspendThread + GetThreadContext
// (FULL) + read [ESP] = return address, ResumeThread. Log:
//   - tid
//   - EIP and a hint at which module it's in (kernel32 / kernelbase / ntdll
//     / user32 / image base for Goley_ itself)
//   - ESP and the first DWORD it points at (the wait's return address into
//     the caller's frame).
//
// If a thread is parked in ntdll!NtWaitForSingleObject or kernelbase!
// WaitForSingleObjectEx, its [ESP+0] is the return address we need to
// look up in IDA -- the next instruction after the WaitFor* call inside
// Goley_'s init code. That tells us EXACTLY which wait we have to
// satisfy (by SetEvent on the right handle, or by short-circuiting the
// caller).
//
// This is read-only -- no code is patched, no DRx is touched, no hook is
// installed. nProtect's anti-hook fingerprint check is not tripped.
static DWORD g_lastThreadDumpTick = 0;

static const char* ClassifyEip(DWORD eip) {
    static char buf[64];
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hKernelB = GetModuleHandleA("kernelbase.dll");
    HMODULE hNtdll  = GetModuleHandleA("ntdll.dll");
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    HMODULE hWs2    = GetModuleHandleA("ws2_32.dll");
    HMODULE hImage  = GetModuleHandleA(NULL);

    struct { HMODULE h; const char* tag; DWORD size; } mods[] = {
        { hImage,   "image",     0x02000000 },
        { hNtdll,   "ntdll",     0x00200000 },
        { hKernel,  "kernel32",  0x00200000 },
        { hKernelB, "kernelbase",0x00400000 },
        { hUser32,  "user32",    0x00200000 },
        { hWs2,     "ws2_32",    0x00100000 },
    };
    for (int i = 0; i < (int)(sizeof(mods)/sizeof(mods[0])); i++) {
        if (!mods[i].h) continue;
        DWORD base = (DWORD)(ULONG_PTR)mods[i].h;
        if (eip >= base && eip < base + mods[i].size) {
            wsprintfA(buf, "%s+0x%X", mods[i].tag, eip - base);
            return buf;
        }
    }
    wsprintfA(buf, "?(0x%X)", eip);
    return buf;
}

static void DumpThreadEips(void) {
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("DumpThreadEips: snapshot FAILED");
        return;
    }

    Log("--- thread EIP dump start ---");

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int total = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;
            if (te.th32ThreadID == currentTid) continue;
            total++;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!hThread) continue;

            DWORD suspendCount = SuspendThread(hThread);

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;
            BOOL ok = GetThreadContext(hThread, &ctx);

            DWORD retAddr = 0;
            if (ok && ctx.Esp) {
                // Read [ESP+0] = return address (the address right after
                // the call that parked us here, i.e. the next instruction
                // inside the caller -- typically Goley_ code).
                __try {
                    retAddr = *(volatile DWORD*)(ULONG_PTR)ctx.Esp;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    retAddr = 0xDEADBEEF;
                }
            }

            if (ok) {
                char buf[512];
                char eipClass[80]; lstrcpynA(eipClass, ClassifyEip(ctx.Eip), 79); eipClass[79] = 0;
                char retClass[80]; lstrcpynA(retClass, ClassifyEip(retAddr),   79); retClass[79] = 0;
                wsprintfA(buf,
                    "  tid=%lu EIP=0x%08X (%s) ESP=0x%08X [ESP]=0x%08X (%s)",
                    te.th32ThreadID, ctx.Eip, eipClass,
                    ctx.Esp, retAddr, retClass);
                Log(buf);
            } else {
                char buf[160];
                wsprintfA(buf, "  tid=%lu GetThreadContext FAILED err=%lu",
                          te.th32ThreadID, GetLastError());
                Log(buf);
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    char tail[80];
    wsprintfA(tail, "--- thread EIP dump end (%d threads) ---", total);
    Log(tail);
}

// Window dismissal thread: scans for any modal dialog whose caption
// contains "GameGuard" and PostMessages WM_CLOSE to dismiss it without
// touching code memory. nProtect's error dialog is rendered by its own
// decrypted DLL (not Goley_'s code), so neither code-patches nor IAT
// hooks reach it -- only the visible window itself can be intercepted.
typedef struct {
    HWND foundHwnd;
    DWORD ownerPid;
} FindData;

static BOOL CALLBACK FindGGDialogProc(HWND hWnd, LPARAM lParam) {
    FindData* fd = (FindData*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid != fd->ownerPid) return TRUE;

    char title[256] = {0};
    GetWindowTextA(hWnd, title, sizeof(title) - 1);
    if (title[0] == '\0') return TRUE;

    // GameGuard error dialogs use captions like:
    //   "GameGuard Error : 150"
    //   "nProtect GameGuard"
    //   "nProtect GameGuard Error Report"
    // Strict filter: only true GameGuard error dialogs by caption.
    // Goley_ main window has title "ChaguChagu V31927 " so we never touch it.
    if (strstr(title, "GameGuard") != NULL ||
        strstr(title, "nProtect")  != NULL) {
        fd->foundHwnd = hWnd;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI DialogKillerThread(LPVOID) {
    DWORD myPid = GetCurrentProcessId();
    int killed = 0;
    while (1) {
        FindData fd = { NULL, myPid };
        EnumWindows(FindGGDialogProc, (LPARAM)&fd);
        if (fd.foundHwnd) {
            char title[256] = {0};
            GetWindowTextA(fd.foundHwnd, title, sizeof(title) - 1);
            char buf[512];
            wsprintfA(buf, "DialogKiller: dismissing hWnd=0x%p title='%s'",
                      fd.foundHwnd, title);
            Log(buf);
            // PostMessage WM_CLOSE is the gentlest dismissal -- equivalent
            // to clicking the X button. Most modal dialogs return IDCANCEL.
            PostMessageA(fd.foundHwnd, WM_CLOSE, 0, 0);
            killed++;
            if (killed > 50) {
                // Safety: if we've killed 50 dialogs, the loop is probably
                // misbehaving (catching the main game window). Stop.
                Log("DialogKiller: too many dismissals, stopping");
                break;
            }
        }
        Sleep(150);  // poll 6-7 Hz
    }
    return 0;
}

// ============================================================================
// MinHook: kernel32!CreateProcessA hook + child APC injection
// ============================================================================
//
// nProtect's NPGameLib.c (reversed source from fatrolls/nProtect-GameGuard)
// shows the parent process calls:
//   CreateProcessA(szGameMon, CommandLine, ..., CREATE_SUSPENDED, ...)
//   <pipe setup>
//   ResumeThread(ProcessInformation.hThread)
//
// To inject our DLL into the child WITHOUT the
// STATUS_PROCESS_IS_TERMINATING race that CreateRemoteThread suffered,
// we hook CreateProcessA inside the parent and queue an APC (asynchronous
// procedure call) on the child's main thread *while it is suspended*.
// When the parent later calls ResumeThread, the very first user-mode code
// the child executes is `LoadLibraryA(<our_dll>)` queued by us.

typedef BOOL (WINAPI *CreateProcessA_t)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CreateProcessW_t)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static CreateProcessA_t g_origCreateProcessA = NULL;
static CreateProcessW_t g_origCreateProcessW = NULL;

// Inject SELF_DLL_PATH into the child via APC. The child's main thread is
// expected to be in suspended state (created with CREATE_SUSPENDED or
// equivalent). Returns TRUE if QueueUserAPC succeeded.
static BOOL ApcInjectChild(HANDLE hProcess, HANDLE hThread, DWORD childPid) {
    SIZE_T pathLen = lstrlenA(SELF_DLL_PATH) + 1;
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, pathLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        char buf[160];
        wsprintfA(buf, "  child[%lu] VirtualAllocEx FAILED err=%lu",
                  childPid, GetLastError());
        Log(buf);
        return FALSE;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemote, SELF_DLL_PATH, pathLen, &written)) {
        char buf[160];
        wsprintfA(buf, "  child[%lu] WriteProcessMemory FAILED err=%lu",
                  childPid, GetLastError());
        Log(buf);
        return FALSE;
    }
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    PVOID pLoadLib = GetProcAddress(hKernel, "LoadLibraryA");
    if (!pLoadLib) {
        Log("  ApcInjectChild: GetProcAddress(LoadLibraryA) FAILED");
        return FALSE;
    }
    DWORD r = QueueUserAPC((PAPCFUNC)pLoadLib, hThread, (ULONG_PTR)pRemote);
    char buf[256];
    wsprintfA(buf, "  child[%lu] APC queued at 0x%p (LoadLibraryA path 0x%p) -> %s",
              childPid, pLoadLib, pRemote, r ? "OK" : "FAIL");
    Log(buf);
    return r != 0;
}

static BOOL WINAPI HookedCreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    char buf[1024];
    wsprintfA(buf, "[HOOK] CreateProcessA: app='%s' cmd='%.200s' flags=0x%X",
              lpApplicationName ? lpApplicationName : "(null)",
              lpCommandLine     ? lpCommandLine     : "(null)",
              dwCreationFlags);
    Log(buf);

    // Force CREATE_SUSPENDED so the child can't run before we APC-inject.
    BOOL addedSuspend = !(dwCreationFlags & CREATE_SUSPENDED);
    DWORD effectiveFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL ok = g_origCreateProcessA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, effectiveFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (!ok) {
        wsprintfA(buf, "  -> CreateProcessA FAILED err=%lu", GetLastError());
        Log(buf);
        return ok;
    }

    HANDLE hProcess = lpProcessInformation->hProcess;
    HANDLE hThread  = lpProcessInformation->hThread;
    DWORD  childPid = lpProcessInformation->dwProcessId;
    wsprintfA(buf, "  -> CHILD spawned PID=%lu hProc=0x%p hThread=0x%p addedSuspend=%d",
              childPid, hProcess, hThread, addedSuspend);
    Log(buf);

    ApcInjectChild(hProcess, hThread, childPid);

    // If WE added CREATE_SUSPENDED (caller didn't ask for it), we must
    // resume the thread ourselves so the caller's expectation holds.
    // The APC we queued will fire on the very first user-mode dispatch.
    if (addedSuspend) {
        DWORD prev = ResumeThread(hThread);
        wsprintfA(buf, "  -> manual ResumeThread (prev suspend count=%lu)", prev);
        Log(buf);
    }
    // Else: caller will resume the thread themselves -- APC still fires.
    return ok;
}

// Wide-char variant. nProtect uses A, but other DLLs in the same process
// (e.g. CRT spawn helpers, system services) may use W. Hook both for safety.
static BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR  lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    char buf[1024];
    char appA[260] = {0};
    char cmdA[260] = {0};
    if (lpApplicationName) {
        for (int i = 0; i < 259 && lpApplicationName[i]; i++)
            appA[i] = (lpApplicationName[i] < 0x80) ? (char)lpApplicationName[i] : '?';
    }
    if (lpCommandLine) {
        for (int i = 0; i < 259 && lpCommandLine[i]; i++)
            cmdA[i] = (lpCommandLine[i] < 0x80) ? (char)lpCommandLine[i] : '?';
    }
    wsprintfA(buf, "[HOOK] CreateProcessW: app='%s' cmd='%s' flags=0x%X",
              appA, cmdA, dwCreationFlags);
    Log(buf);

    BOOL addedSuspend = !(dwCreationFlags & CREATE_SUSPENDED);
    DWORD effectiveFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL ok = g_origCreateProcessW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, effectiveFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (!ok) {
        wsprintfA(buf, "  -> CreateProcessW FAILED err=%lu", GetLastError());
        Log(buf);
        return ok;
    }

    HANDLE hProcess = lpProcessInformation->hProcess;
    HANDLE hThread  = lpProcessInformation->hThread;
    DWORD  childPid = lpProcessInformation->dwProcessId;
    wsprintfA(buf, "  -> CHILD-W spawned PID=%lu hProc=0x%p hThread=0x%p addedSuspend=%d",
              childPid, hProcess, hThread, addedSuspend);
    Log(buf);

    ApcInjectChild(hProcess, hThread, childPid);

    if (addedSuspend) {
        DWORD prev = ResumeThread(hThread);
        wsprintfA(buf, "  -> manual ResumeThread (prev suspend count=%lu)", prev);
        Log(buf);
    }
    return ok;
}

// ============================================================================
// Wait API hooks:diagnose what handle Goley_'s init thread is blocked on
// ============================================================================
//
// After Themida unpack + GG bypass, Goley_ hangs on "초기화중" (Initializing).
// nProtect normally fires a named event (e.g. "Global\NPGGuard_xxx") when
// GameMon is ready, but we blocked GameMon spawn so the event is never set.
//
// We hook the wait APIs and log -- via NtQueryObject -- the Object Manager
// name of any handle Goley_ blocks on for >= 5 seconds or INFINITE. From
// that we identify the "GameMon ready" event and can `SetEvent` it ourselves.

typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef DWORD (WINAPI *WaitForSingleObjectEx_t)(HANDLE, DWORD, BOOL);
typedef DWORD (WINAPI *WaitForMultipleObjects_t)(DWORD, const HANDLE*, BOOL, DWORD);
typedef LONG  (NTAPI  *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef LONG  (NTAPI  *NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static WaitForSingleObject_t      g_origWFSO   = NULL;
static WaitForSingleObjectEx_t    g_origWFSOEx = NULL;
static WaitForMultipleObjects_t   g_origWFMO   = NULL;
static NtWaitForSingleObject_t    g_origNtWFSO = NULL;
static NtQueryObject_t            g_pNtQueryObject = NULL;

// Recursion guard so Log()'s internal CreateFile/WriteFile (which may use
// kernel mutexes -> WaitForSingleObject) doesn't re-enter our wait hooks.
// __declspec(thread) was tried but caused early Themida-process death,
// likely due to static TLS section conflicting with packer assumptions.
// We use a single process-wide flag plus InterlockedCompareExchange so
// only one thread logs a wait at a time; the cost is missing a few
// concurrent waits, which is fine for diagnostics.
static volatile LONG g_inHook = 0;
static inline BOOL EnterHook(void) {
    return InterlockedCompareExchange(&g_inHook, 1, 0) == 0;
}
static inline void LeaveHook(void) {
    InterlockedExchange(&g_inHook, 0);
}

// UNICODE_STRING + OBJECT_NAME_INFORMATION layout (private to ntdll headers,
// redeclared here so we don't drag in winternl.h).
typedef struct {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING_local;
typedef struct {
    UNICODE_STRING_local Name;
} OBJECT_NAME_INFORMATION_local;

// Convert kernel handle -> human-readable Object Manager name into `buf`.
// Examples seen in the wild: "\BaseNamedObjects\NPGGuard_xxx",
// "\KernelObjects\HighMemoryCondition", "" (anonymous), etc.
static void DescribeHandle(HANDLE h, char* buf, int bufSize) {
    if (!g_pNtQueryObject || bufSize < 4) {
        if (bufSize >= 4) lstrcpyA(buf, "?");
        return;
    }
    BYTE tmp[1024] = {0};
    ULONG retLen = 0;
    LONG status = g_pNtQueryObject(h, 1 /*ObjectNameInformation*/,
                                   tmp, sizeof(tmp), &retLen);
    if (status < 0) {
        wsprintfA(buf, "name?(0x%lX)", status);
        return;
    }
    OBJECT_NAME_INFORMATION_local* info = (OBJECT_NAME_INFORMATION_local*)tmp;
    if (info->Name.Length == 0 || info->Name.Buffer == NULL) {
        lstrcpyA(buf, "<unnamed>");
        return;
    }
    int chars = info->Name.Length / (int)sizeof(wchar_t);
    if (chars > bufSize - 4) chars = bufSize - 4;
    for (int i = 0; i < chars; i++) {
        wchar_t c = info->Name.Buffer[i];
        buf[i] = (c >= 0x20 && c < 0x80) ? (char)c : '?';
    }
    buf[chars] = 0;
}

static DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout) {
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 5000);
    if (longWait && EnterHook()) {
        char name[300];
        DescribeHandle(hObj, name, sizeof(name));
        char buf[600];
        wsprintfA(buf, "[WFSO] TID=%lu h=0x%p timeout=%lu name='%s' caller=0x%p",
                  GetCurrentThreadId(), hObj, dwTimeout, name, _ReturnAddress());
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFSO(hObj, dwTimeout);
    if (longWait && EnterHook()) {
        char buf[200];
        wsprintfA(buf, "  [WFSO] TID=%lu h=0x%p -> %lu",
                  GetCurrentThreadId(), hObj, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

static DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE hObj, DWORD dwTimeout,
                                                BOOL bAlertable) {
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 5000);
    if (longWait && EnterHook()) {
        char name[300];
        DescribeHandle(hObj, name, sizeof(name));
        char buf[600];
        wsprintfA(buf, "[WFSOEx] TID=%lu h=0x%p timeout=%lu alertable=%d name='%s' caller=0x%p",
                  GetCurrentThreadId(), hObj, dwTimeout, bAlertable, name,
                  _ReturnAddress());
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFSOEx(hObj, dwTimeout, bAlertable);
    if (longWait && EnterHook()) {
        char buf[200];
        wsprintfA(buf, "  [WFSOEx] TID=%lu h=0x%p -> %lu",
                  GetCurrentThreadId(), hObj, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

static DWORD WINAPI HookedWaitForMultipleObjects(DWORD nCount,
                                                  const HANDLE* pHandles,
                                                  BOOL bWaitAll,
                                                  DWORD dwTimeout) {
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 5000);
    if (longWait && pHandles && EnterHook()) {
        char buf[2048];
        int off = wsprintfA(buf, "[WFMO] TID=%lu n=%lu waitAll=%d timeout=%lu",
                            GetCurrentThreadId(), nCount, bWaitAll, dwTimeout);
        for (DWORD i = 0; i < nCount && i < 8 && off < 1900; i++) {
            char name[280];
            DescribeHandle(pHandles[i], name, sizeof(name));
            off += wsprintfA(buf + off, "; h%lu=0x%p '%.200s'",
                             i, pHandles[i], name);
        }
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFMO(nCount, pHandles, bWaitAll, dwTimeout);
    if (longWait && EnterHook()) {
        char buf[160];
        wsprintfA(buf, "  [WFMO] TID=%lu -> %lu", GetCurrentThreadId(), r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

// NtWaitForSingleObject hook removed -- ntdll syscall stubs are too small
// for HDE32 to trampoline reliably. kernel32 wrappers cover what we need.

// Install Wait* hooks. Called once from PatchThread after MinHook init.
static void InitWaitHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll  = GetModuleHandleA("ntdll.dll");
    if (!hKernel || !hNtdll) {
        Log("InitWaitHooks: kernel32/ntdll not loaded");
        return;
    }
    g_pNtQueryObject = (NtQueryObject_t)GetProcAddress(hNtdll, "NtQueryObject");
    if (!g_pNtQueryObject) Log("InitWaitHooks: NtQueryObject not found (names unavailable)");

    // NOTE: ntdll!NtWaitForSingleObject is DELIBERATELY NOT hooked.
    // Its prologue is a tiny syscall stub (mov eax,N / sysenter / ret 0xC)
    // that MinHook's HDE32 disassembler can't reliably trampoline. Hooking
    // it tore down Goley_ before InitWaitHooks finished. kernel32 wrappers
    // are enough to catch every long wait Goley_/nProtect does at user-mode.
    struct WaitHookSpec { HMODULE mod; const char* name; LPVOID detour; LPVOID* orig; };
    WaitHookSpec specs[] = {
        { hKernel, "WaitForSingleObject",    (LPVOID)&HookedWaitForSingleObject,   (LPVOID*)&g_origWFSO   },
        { hKernel, "WaitForSingleObjectEx",  (LPVOID)&HookedWaitForSingleObjectEx, (LPVOID*)&g_origWFSOEx },
        { hKernel, "WaitForMultipleObjects", (LPVOID)&HookedWaitForMultipleObjects,(LPVOID*)&g_origWFMO   },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        PVOID p = GetProcAddress(specs[i].mod, specs[i].name);
        char buf[200];
        if (!p) {
            wsprintfA(buf, "InitWaitHooks: GetProcAddress(%s) FAILED", specs[i].name);
            Log(buf);
            continue;
        }
        MH_STATUS s = MH_CreateHook(p, specs[i].detour, specs[i].orig);
        if (s != MH_OK) {
            wsprintfA(buf, "InitWaitHooks: MH_CreateHook(%s) status=%d", specs[i].name, s);
            Log(buf);
            continue;
        }
        s = MH_EnableHook(p);
        if (s != MH_OK) {
            wsprintfA(buf, "InitWaitHooks: MH_EnableHook(%s) status=%d", specs[i].name, s);
            Log(buf);
            continue;
        }
        wsprintfA(buf, "InitWaitHooks: %s hooked at 0x%p", specs[i].name, p);
        Log(buf);
    }
}

// One-shot MinHook init + enable both CreateProcessA/W hooks. Returns TRUE
// only if both hooks were successfully created+enabled.
static BOOL InitCreateProcessHooks() {
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        char buf[128];
        wsprintfA(buf, "MH_Initialize FAILED status=%d", s);
        Log(buf);
        return FALSE;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) {
        Log("InitCreateProcessHooks: kernel32 not loaded");
        return FALSE;
    }
    PVOID pCPA = GetProcAddress(hKernel, "CreateProcessA");
    PVOID pCPW = GetProcAddress(hKernel, "CreateProcessW");

    char buf[256];
    wsprintfA(buf, "Hook targets: CreateProcessA=0x%p CreateProcessW=0x%p", pCPA, pCPW);
    Log(buf);

    BOOL allOk = TRUE;
    if (pCPA) {
        s = MH_CreateHook(pCPA, (LPVOID)&HookedCreateProcessA,
                          (LPVOID*)&g_origCreateProcessA);
        if (s != MH_OK) {
            wsprintfA(buf, "MH_CreateHook(CreateProcessA) status=%d", s); Log(buf);
            allOk = FALSE;
        }
    } else { allOk = FALSE; }

    if (pCPW) {
        s = MH_CreateHook(pCPW, (LPVOID)&HookedCreateProcessW,
                          (LPVOID*)&g_origCreateProcessW);
        if (s != MH_OK) {
            wsprintfA(buf, "MH_CreateHook(CreateProcessW) status=%d", s); Log(buf);
            allOk = FALSE;
        }
    } else { allOk = FALSE; }

    s = MH_EnableHook(MH_ALL_HOOKS);
    if (s != MH_OK) {
        wsprintfA(buf, "MH_EnableHook(ALL) status=%d", s); Log(buf);
        return FALSE;
    }
    Log(allOk ? "MinHook: CreateProcessA/W hooks ACTIVE"
              : "MinHook: hooks partially installed (see warnings above)");
    return allOk;
}

DWORD WINAPI PatchThread(LPVOID lpParam) {
    Log("PatchThread starting (VEH+HWBP+MinHook refresh-loop mode)");

    // Install kernel32!CreateProcessA/W hooks FIRST so the very first
    // child spawn (typically nProtect's GameMon.des) gets our DLL APC-injected.
    InitCreateProcessHooks();

    // Wait hooks DISABLED -- they were tripping nProtect's anti-hook
    // fingerprint check. We now use thread enumeration + GetThreadContext
    // to read each thread's EIP every 5 seconds (see DumpThreadEips()
    // below). That tells us which thread is parked in
    // kernelbase!WaitForSingleObjectEx / ntdll!ZwWaitForSingleObject and
    // what the return address into Goley_'s code is -- enough to find
    // the wait site in IDA without ever installing a wait hook.
    Log("Wait hooks DISABLED -- using thread-EIP polling instead");

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) { Log("GetModuleHandle NULL"); return 1; }
    g_imageBase = (BYTE*)hMod;

    char buf[256];
    wsprintfA(buf, "Image base: 0x%p", g_imageBase);
    Log(buf);

    // VEH already installed inline from DllMain ATTACH (race fix).
    if (g_vehHandle) {
        Log("VEH already installed (inline from DllMain)");
    } else {
        g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
        if (!g_vehHandle) {
            Log("AddVectoredExceptionHandler FAILED");
            return 1;
        }
        Log("VEH installed by PatchThread (fallback)");
    }

    // Hook ExitProcess + TerminateProcess so we can capture the call site
    // that's killing us ~8 seconds after VEH-bypass.
    int killHooks = HookKillApis();
    char hbuf[64];
    wsprintfA(hbuf, "Kill API hooks installed: %d slot(s)", killHooks);
    Log(hbuf);

    DWORD valVA = (DWORD)(g_imageBase + VALIDATION_RVA);

    // PLAN: IAT slot hijack for Goley_'s MessageBoxW call site.
    // Disasm of the unpacked binary at 0xD35585 showed:
    //   call [0x019984D4]   ; user32!MessageBoxW via IAT
    // We rewrite the slot to point at our FakeMessageBoxW which returns IDOK
    // without showing any dialog. This is the cleanest bypass:
    //   - No write on user32 (anti-tamper friendly)
    //   - No HW BP (anti-debug friendly)
    //   - No DR registers (Themida-friendly)
    //
    // Note: at DLL_PROCESS_ATTACH time, Goley_'s IAT may not yet contain the
    // real MessageBoxW pointer (Themida fills it after unpack). So we retry
    // every refresh iteration below until the slot value looks "real".

    wsprintfA(buf, "Targets: validation=0x%X  MessageBoxW-IAT=0x%X (will hijack after unpack)",
              valVA, GOLEY_MBW_IAT_VA);
    Log(buf);

    // Inline-stub kernel32!ExitProcess + TerminateProcess so any "init
    // failed -> suicide" cleanup can't actually kill the process. nProtect
    // doesn't hash-check kernel32 (only user32 in the tests above).
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel) {
        DWORD termVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "TerminateProcess");
        DWORD exitVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "ExitProcess");
        PatchStdcallStub(termVA, 8, "kernel32!TerminateProcess");
        PatchStdcallStub(exitVA, 4, "kernel32!ExitProcess");
    }

    // ALSO patch the ntdll-level process kill APIs. Themida-packed code
    // often bypasses kernel32 wrappers and calls these syscall stubs
    // directly. Without patching them too, Goley_ can exit despite our
    // kernel32 patches.
    //
    //   NtTerminateProcess(HANDLE, NTSTATUS) -- 2 args -> ret 8
    //   RtlExitUserProcess(UINT)             -- 1 arg  -> ret 4
    //   NtTerminateThread (HANDLE, NTSTATUS) -- 2 args -> ret 8  (defensive)
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (hNt) {
        DWORD ntTermProc = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateProcess");
        DWORD rtlExit    = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "RtlExitUserProcess");
        DWORD ntTermThr  = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateThread");
        PatchStdcallStub(ntTermProc, 8, "ntdll!NtTerminateProcess");
        PatchStdcallStub(rtlExit,    4, "ntdll!RtlExitUserProcess");
        PatchStdcallStub(ntTermThr,  8, "ntdll!NtTerminateThread");
        // ntdll!NtCreateUserProcess is the REAL syscall that creates a process
        // on modern Windows. kernel32!CreateProcessA/W and internal variants
        // all funnel through it. Goley_'s Themida bypass goes straight here.
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            g_createProcessWVA = (DWORD)(ULONG_PTR)GetProcAddress(hNtdll, "NtCreateUserProcess");
            wsprintfA(buf, "ntdll!NtCreateUserProcess resolved at 0x%X", g_createProcessWVA);
            Log(buf);
        }
        // BLOCK CreateProcess: any call returns FALSE without spawning a child.
        // This prevents Goley_'s "trusted re-launch" pattern. Parent process
        // already has all our bypasses applied, so it can continue solo.
        // ret 40 = stdcall cleanup for 10 args (HWND, ..., lpProcessInformation)
        // CreateProcess block disabled -- Goley_ bypasses kernel32 entirely
        // via direct NtCreateUserProcess syscall, so blocking these doesn't
        // prevent the child spawn. Child inject is handled by the PowerShell
        // watcher using NtCreateThreadEx (less restrictive than CRT).
    }

    // Refresh loop: ONLY DR0 is used, for the Themida validation branch
    // (one-shot). After val hits, we ALSO try to hijack the MessageBoxW
    // IAT slot at GOLEY_MBW_IAT_VA. The slot may be empty/0xFFFFFFFF at
    // DLL_PROCESS_ATTACH time (Themida hasn't filled imports yet); we
    // retry on every iteration until we see a real pointer there.
    int iterations = 0;
    int totalHWBPSets = 0;
    DWORD startTick = GetTickCount();
    BOOL valSweepDone = FALSE;
    BOOL iatHijacked = FALSE;
    BOOL ggrSweepDone = FALSE;
    BOOL waitHooksInstalled = FALSE;
    while (GetTickCount() - startTick < 600000) {  // 10 minute upper bound
        // (1) Once val hits, sweep-clear DRx (Themida anti-debug friendliness)
        if (g_valHit && !valSweepDone) {
            Log("Validation hit -- one final DRx sweep clear");
            int c = ClearHardwareBreakpointAllThreads();
            wsprintfA(buf, "DRx cleared on %d threads", c);
            Log(buf);
            valSweepDone = TRUE;
        }

        // (1b) Thread-EIP polling -- every 5 sec, enumerate every thread
        //      in this process, suspend, read EIP+ESP, resume. Log lines
        //      whose EIP is inside ntdll!Zw* / kernelbase!Wait* / a few
        //      well-known wait stubs. The return address read from [ESP+0]
        //      tells us which Goley_ code site is parked on a wait.
        //
        //      Triggered:
        //        - first dump:  ~10s after PatchThread start
        //        - then:        every 15s
        //      Avoids overlap with HW BP refresh (which already runs every
        //      ~100 ms) by checking elapsed since last dump.
        DWORD nowTick = GetTickCount();
        if ((nowTick - startTick) > 10000 &&
            (nowTick - g_lastThreadDumpTick) > 15000) {
            g_lastThreadDumpTick = nowTick;
            DumpThreadEips();
        }

        // (1b) Once GG result hits, sweep-clear DRx again (critical: Themida
        //      anti-debug probe kills us in ~2 sec if any DR1/DR2 stay set)
        if (g_ggrHit && !ggrSweepDone) {
            Log("GG result hit -- second DRx sweep clear");
            int c = ClearHardwareBreakpointAllThreads();
            wsprintfA(buf, "DRx cleared on %d threads (after GG result)", c);
            Log(buf);
            ggrSweepDone = TRUE;
        }

        // (2) After val hit, Themida has resolved imports. Scan the entire
        //     process memory for the resolved MessageBoxW address and
        //     replace EVERY occurrence with our FakeMessageBoxW. This
        //     handles Themida's obfuscated IAT (the original IAT VA is
        //     MEM_FREE at runtime; the real function pointers live in
        //     Themida-allocated regions).
        //     Done ONCE, ~1 second after val hit (gives nProtect DLL
        //     time to also resolve its imports).
        // (2) GameGuard daemon kill defensive. Apply ONCE, 1.5s after val
        //     hit. We DROPPED the memory-write patches at 0xD39A11/0xD35585
        //     because the runtime bytes at 0xD35585 are NOT the static-
        //     disasm bytes -- Themida replaced the original `call [IAT]`
        //     with a relative `call ThemidaVMStub` at unpack time. Memory
        //     writes there trigger Themida's runtime tamper check and
        //     suicide within seconds.
        //
        //     The MessageBoxW CALL is now intercepted via HW BP DR1 in the
        //     VEH handler (see mbwVA check above), which doesn't write to
        //     code memory and bypasses tamper detection.
        if (g_valHit && !iatHijacked && iterations >= 30) {
            // Multiple patch sites to neutralize GameGuard error dialog and
            // the cmp/jne chain that routes to it. Apply all in one pass.
            // Memory writes intentionally omitted -- MessageBoxW CALL is
            // handled via HW BP DR1 (see VEH handler).

            // Defensive: kill GameMon.des / GameMon64.des daemons even though
            // they don't currently spawn for Goley_ (driver init failed before
            // daemon launch). In case nProtect retries the spawn later.
            const char* daemons[] = { "GameMon.des", "GameMon64.des", NULL };
            for (int i = 0; daemons[i]; i++) {
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap == INVALID_HANDLE_VALUE) continue;
                PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        if (lstrcmpiA(pe.szExeFile, daemons[i]) == 0) {
                            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hProc) {
                                TerminateProcess(hProc, 9);
                                CloseHandle(hProc);
                                wsprintfA(buf, "Killed daemon %s pid=%lu", daemons[i], pe.th32ProcessID);
                                Log(buf);
                            }
                        }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }

            iatHijacked = TRUE;
        }

        // (3) HW BP layout:
        //   DR0 = val bypass (0xD3DC4D) -- one-shot, disarmed after first hit
        //   DR1 = MessageBoxW CALL (0xD35586) -- catches the dialog if the
        //         primary bypass somehow misses
        //   DR2 = GG CHECK CALL (0xD35374) -- PRIMARY bypass, structural
        //         skip of the entire GG status check
        DWORD t0 = g_valHit ? 0 : valVA;
        // MessageBoxW: keep persistent until GG result hits (after that the
        // dialog path is structurally bypassed, no need to catch MBW).
        DWORD t1 = g_ggrHit ? 0 : (DWORD)(g_imageBase + GG_MBW_CALL_RVA);
        // GG result: one-shot. Once hit, NEVER re-arm (Themida anti-debug
        // probes DRx periodically and persistent set kills us in ~2 sec).
        DWORD t2 = g_ggrHit ? 0 : (DWORD)(g_imageBase + GG_RESULT_PATCH_RVA);
        // CreateProcessW hook: one-shot. Fires when parent re-execs the
        // child Goley_, adds CREATE_SUSPENDED so we can inject before run.
        // Uses kernel32!CreateProcessW entry point so ANY caller is caught.
        DWORD t3 = g_cpHit ? 0 : g_createProcessWVA;
        int n = SetHardwareBreakpointAllThreads(t0, t1, t2, t3);
        totalHWBPSets += n;
        iterations++;

        if (iterations % 40 == 0) {
            wsprintfA(buf, "iter %d total_set=%d hits[val=%d] iat=%d",
                      iterations, totalHWBPSets, g_valHit, iatHijacked);
            Log(buf);
        }

        // If both done and a few seconds have passed, slow the loop.
        if (g_valHit && iatHijacked && iterations > 200) {
            Sleep(500);
        } else {
            Sleep(50);  // 20Hz refresh
        }
    }

    Log("PatchThread loop exit");
    return 0;
}

// DLL'in disk uzerindeki yolundan log dosyasinin yolunu hesaplar.
// Patcher su yapida bulunuyor: <repo>/src/patcher/revival_patcher.dll
// Log dosyasini repo'nun kokune koyariz: <repo>/patcher.log
static void ResolveLogPath(HMODULE hModule) {
    if (!GetModuleFileNameA(hModule, SELF_DLL_PATH, MAX_PATH)) return;
    // Once SELF_DLL_PATH'i kendi path'ine kopyaladik. Simdi log icin
    // ondan turetiyoruz: dirname -> dirname -> dirname + "\\patcher.log".
    char tmp[MAX_PATH];
    lstrcpynA(tmp, SELF_DLL_PATH, MAX_PATH);
    for (int up = 0; up < 3; up++) {
        char* slash = (char*)strrchr(tmp, '\\');
        if (!slash) break;
        *slash = 0;
    }
    if (tmp[0]) {
        wsprintfA(g_logPath, "%s\\patcher.log", tmp);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        ResolveLogPath(hModule);
        Log("DLL_PROCESS_ATTACH (VEH+HWBP+DialogKiller)");

        // ============================================================
        // INLINE early armor -- runs in DllMain BEFORE any async thread.
        // ============================================================
        // Race issue: wrapper.exe calls LoadLibraryW(us) and ResumeThread()
        // back-to-back. As soon as ResumeThread fires, Themida starts
        // unpacking. On a warm system that takes ~7 ms to reach
        // ExitProcess/TerminateProcess for any of its anti-debug paths.
        // Our async PatchThread doesn't finish MinHook + kill-API
        // patching for ~40 ms, so the race is lost and the child exits
        // before we install anything.
        //
        // Solution: install kill-API stubs INLINE here, in the loader
        // lock context. VirtualProtect + memcpy are kernel32 ops, very
        // fast (sub-millisecond) and safe under loader lock. After
        // DllMain returns, the wrapper's ResumeThread proceeds and
        // Themida unpack starts -- by then TerminateProcess/ExitProcess
        // /Nt{Terminate,Exit}* all return success without doing anything.
        {
            HMODULE hKernel = GetModuleHandleA("kernel32.dll");
            HMODULE hNt     = GetModuleHandleA("ntdll.dll");
            if (hKernel) {
                DWORD termVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "TerminateProcess");
                DWORD exitVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "ExitProcess");
                PatchStdcallStub(termVA, 8, "[inline] kernel32!TerminateProcess");
                PatchStdcallStub(exitVA, 4, "[inline] kernel32!ExitProcess");
            }
            if (hNt) {
                DWORD ntTermProc = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateProcess");
                DWORD rtlExit    = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "RtlExitUserProcess");
                DWORD ntTermThr  = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateThread");
                PatchStdcallStub(ntTermProc, 8, "[inline] ntdll!NtTerminateProcess");
                PatchStdcallStub(rtlExit,    4, "[inline] ntdll!RtlExitUserProcess");
                PatchStdcallStub(ntTermThr,  8, "[inline] ntdll!NtTerminateThread");
            }
            // Install VEH inline too -- HW BP needs it ready before the
            // first DR0 hit. AddVectoredExceptionHandler is just a
            // linked-list insertion, doesn't take loader lock.
            g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
            Log(g_vehHandle ? "[inline] VEH installed" : "[inline] VEH FAILED");
        }

        HANDLE h = CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
        // Background dialog dismisser -- catches any "GameGuard"/"nProtect"
        // titled modal regardless of which DLL renders it.
        HANDLE hDk = CreateThread(NULL, 0, DialogKillerThread, NULL, 0, NULL);
        if (hDk) CloseHandle(hDk);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        Log("DLL_PROCESS_DETACH");
        if (g_vehHandle) RemoveVectoredExceptionHandler(g_vehHandle);
    }
    return TRUE;
}
