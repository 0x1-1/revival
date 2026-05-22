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

// Hacker Disassembler Engine 32 -- instruction-length decoder. Used in the
// VEH to advance EIP past a faulting instruction by its REAL length instead
// of a fixed +1 (Themida raises breakpoint-status from varied instructions;
// a wrong advance lands mid-instruction and loops/crashes). hde32.c is built
// into this DLL (see build_client_fixed.bat) and -Iminhook/hde is on the
// include path. hde32_disasm is declared extern "C" inside the header.
#include "hde32.h"

// WoW64 breakpoint status. Not always pulled in via winnt.h, so define it
// explicitly. This is the code that actually killed Goley_ right after the
// splash (STATUS_WX86_BREAKPOINT @ ntdll), distinct from the native
// EXCEPTION_BREAKPOINT (0x80000003).
#ifndef STATUS_WX86_BREAKPOINT
#define STATUS_WX86_BREAKPOINT 0x4000001FL
#endif

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
static const DWORD DEFAULT_TR_IP_RVA   = 0xB84554;  // VA 0xF84554, "213.74.179.19"

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

// FAZ77: forced LobbyPane reaches TeamManager_Roster without the real
// login-ok/profile/team model. The Roster init path dereferences
// [this+0x48]+0xF1 when [this+0x48] is still NULL and crashes only on the
// Team tab. Skip that optional roster prefill loop so the pane can continue
// far enough to expose the next missing session/team state.
static const DWORD TEAM_ROSTER_NULL_RVA      = 0x80B2D7; // 0xC0B2D7
static const DWORD TEAM_ROSTER_CONTINUE_RVA  = 0x80B424; // after prefill loop

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
static DWORD g_mainThreadId = 0;                // DllMain runs on hijacked main thread
// FAZ21: set to 1 by the WFMO shim the instant GG-ready is auto-signaled.
// Gates LoadLibrary/GetProcAddress capture so we only log the POST-ready
// integrity-check loads (0x8E8740) instead of drowning in normal-init noise.
static volatile LONG g_ggReadySignaled = 0;

// FAZ21: master toggle for the loader-level capture hooks (LoadLibrary*,
// GetProcAddress, ntdll!LdrLoadDll, ntdll!LdrGetProcedureAddress, UEF).
// DISABLED by default: faz21 dump analysis suggests hooking the loader CORE
// crashes a parallel-loader worker once D3D9 render init triggers heavy DLL
// loading. The diagnostic data is already captured; flip to TRUE only to
// re-capture. (InitWaitHooks/SHIM auto-signal is NOT gated by this.)
static const BOOL CAPTURE_HOOKS_ENABLED = FALSE;

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

// Forward decl: ClassifyEip is defined further down (thread-EIP poller helper)
// but the FAZ21 post-ready broad logger in VehHandler needs it earlier.
static const char* ClassifyEip(DWORD eip);

// FAZ36: copy an MSVC std::string (object at `obj`) into out[outsz], NUL-term.
// Layout (VS2010/2012): _Bx union char[16]/char* at +0, _Mysize at +0x10,
// _Myres (capacity) at +0x14. SSO when _Myres < 16. MUST be called inside a
// __try -- it dereferences possibly-wild pointers.
static void CopyStdStr(DWORD obj, char* out, int outsz) {
    out[0] = 0;
    DWORD cap = *(DWORD*)(obj + 0x14);
    DWORD sz  = *(DWORD*)(obj + 0x10);
    const char* src = (cap >= 0x10) ? *(const char**)obj : (const char*)obj;
    if (!src) return;
    int n = (int)sz; if (n < 0) n = 0; if (n > outsz - 1) n = outsz - 1;
    int i = 0; for (; i < n; ++i) out[i] = src[i];
    out[i] = 0;
}

// VEH handler:gets called whenever ANY exception fires in the process.
static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS exc) {
    DWORD code = exc->ExceptionRecord->ExceptionCode;
    DWORD eip = exc->ContextRecord->Eip;

    // Themida + nProtect anti-debug fingerprint: software breakpoints
    // sprinkled through the unpacker and the nProtect init path. With a real
    // debugger attached the debugger consumes them (so Themida sees "debugger
    // present -> abort"); with NO debugger and NO swallow they reach the OS
    // UnhandledExceptionFilter -> process dies. We emulate "a debugger quietly
    // absorbed it" by advancing EIP past the faulting instruction.
    //
    // Handle BOTH codes:
    //   0x80000003 EXCEPTION_BREAKPOINT      (native INT3)
    //   0x4000001F STATUS_WX86_BREAKPOINT    (WoW64 layer) <- this is what
    //                                         actually killed us after splash.
    //
    // The previous build hardcoded the ntdll range 0x77000000-0x78000000 and a
    // fixed EIP+1. That missed 0x4000001F entirely and broke whenever ASLR put
    // ntdll elsewhere -> the breakpoint reached the OS -> crash. We now swallow
    // regardless of module (there are no legitimate INT3s we want to keep; the
    // HW-breakpoint hooks come through as EXCEPTION_SINGLE_STEP, handled below)
    // and advance by the instruction's REAL length via HDE32 so we never land
    // mid-instruction. A blind EIP+0 looped 54000x/3s last time; a blind EIP+1
    // is wrong for any breakpoint-status raised from a >1-byte instruction.
    if (code == EXCEPTION_BREAKPOINT || code == STATUS_WX86_BREAKPOINT) {
        DWORD len = 1;
        __try {
            BYTE* p  = (BYTE*)eip;
            BYTE  op = p[0];
            if (op == 0xCC || op == 0xF1) {       // INT3 / ICEBP -- 1 byte
                len = 1;
            } else if (op == 0xCD) {              // INT n        -- 2 bytes
                len = 2;
            } else {                              // decode real length
                hde32s hs;
                len = hde32_disasm(p, &hs);
                if ((hs.flags & F_ERROR) || len == 0) len = 1;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            len = 1;  // EIP unreadable -> best-effort single-byte advance
        }
        exc->ContextRecord->Eip = eip + len;
        // No log here -- can fire hundreds of times; would flood the log.
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // FAZ27 NOTE: the post-GG-ready "be passive" early-return is placed AFTER
    // the SINGLE_STEP block below (NOT here) -- our own HW breakpoints (esp. the
    // GG-result DR2 @ 0xD35379) can RE-FIRE during loading and MUST still be
    // handled (force EAX=0x755), or the unhandled single-step crashes the
    // process. Only the IO-heavy INTERESTING/broad logging is skipped post-ready.

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
            static volatile LONG s_ggrHits = 0;
            DWORD origEax = exc->ContextRecord->Eax;
            exc->ContextRecord->Eax = GG_OK_STATUS;  // force success on EVERY call
            LONG h = InterlockedIncrement(&s_ggrHits);
            if (h <= 15) {
                char buf[160];
                wsprintfA(buf, "GG RESULT patched @ 0x%X #%d: EAX 0x%X -> 0x755",
                          eip, (int)h, origEax);
                Log(buf);
            }
            InterlockedExchange(&g_ggrHit, 1);       // mbw no longer needed (dialog path avoided)
            // FAZ46: the GG result check (0xD35360) is PERIODIC (~15s). The old
            // one-shot disarm let the 2nd+ checks read the real 0x78 -> esi!=0x755
            // -> "GameGuard Error" MessageBox (0xd35557) -> exit. So KEEP DR2 armed
            // and RF past the insn instead of disarming. Forces 0x755 every time
            // -> esi==0x755 -> je 0xd3559c success branch -> dialog never opens.
            exc->ContextRecord->EFlags |= 0x10000;   // RF: keep BP armed
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

        // -- FAZ49 DIAGNOSTIC: UI-loader reachability. The GG teardowns are solved
        //    (faz45/48 data-poke), the game is stable, but the screen is flat gray
        //    and FILELOG=0 -> the login/UI never loads. Codex asked to log whether
        //    the login-UI loader sites are reached: 0xD75A40 (entry), and inner
        //    points 0xD75D47/0xD75D6D/0xD75D99/0xD75D9E (the login-UI call region).
        //    If NONE hit -> the state transition that should trigger the login UI
        //    never fires (look upstream). Read-only diag; RF keeps BPs armed. This
        //    replaces the unused FAZ46 store-BP (GG fix is the [ctx+0x10]/[ctx+1]
        //    data-poke; the store-BP never fired) -> no behavior change.
        {
            static volatile LONG s_uiHits[5] = { 0, 0, 0, 0, 0 };
            const DWORD uiRva[5] = { 0x975A40, 0x975D47, 0x975D6D, 0x975D99, 0x975D9E };
            const char* uiTag[5] = { "0xD75A40(entry)", "0xD75D47", "0xD75D6D", "0xD75D99", "0xD75D9E" };
            for (int i = 0; i < 5; ++i) {
                if (eip == (DWORD)(g_imageBase + uiRva[i])) {
                    LONG h = InterlockedIncrement(&s_uiHits[i]);
                    if (h <= 8) {
                        char buf[240];
                        wsprintfA(buf, "FAZ53: UI-loader HIT %s #%d (eax=%X al=%02X ecx=%X esi=%X edi=%X esp=%X)",
                                  uiTag[i], (int)h,
                                  exc->ContextRecord->Eax,
                                  exc->ContextRecord->Eax & 0xFF,
                                  exc->ContextRecord->Ecx,
                                  exc->ContextRecord->Esi,
                                  exc->ContextRecord->Edi,
                                  exc->ContextRecord->Esp);
                        Log(buf);
                    }
                    exc->ContextRecord->EFlags |= 0x10000;  // RF: keep armed
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }

    // FAZ27: post-GG-ready we keep the FUNCTIONAL handlers below (IAT-probe
    // filter, the 0xD30313 EDX=NULL game-AV rescue) -- those are required for
    // the game to survive loading -- but SKIP the IO-heavy diagnostic LOGGING
    // (the "INTERESTING EXC" line + regs/stack dump + the broad logger). File IO
    // at exception time perturbs the NVIDIA/WinTrust adapter-init path. So the
    // logging is gated on !g_ggReadySignaled; the rescues always run.

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

        // FAZ77: Team tab / TeamManager_Roster with no real profile/team model.
        // Faulting instruction:
        //   0xC0B2D7 mov ecx, [esi + eax + 0xF1]
        // Here EAX is [this+0x48]. Forced lobby has not received NotifyLoginOk
        // / team payloads, so that model pointer is NULL. Continuing at
        // 0xC0B424 skips only the roster prefill loop and lets the UI handler
        // finish instead of taking the process down.
        if (code == EXCEPTION_ACCESS_VIOLATION && g_imageBase &&
            eip == (DWORD)(g_imageBase + TEAM_ROSTER_NULL_RVA) &&
            faultAddr == 0xF1 &&
            exc->ContextRecord->Eax == 0 &&
            exc->ContextRecord->Esi == 0) {
            static volatile LONG s_teamNullHits = 0;
            LONG h = InterlockedIncrement(&s_teamNullHits);
            if (h <= 8) {
                char tbuf[240];
                wsprintfA(tbuf,
                          "FAZ77: TeamManager_Roster null team/profile model at 0x%X; skip prefill loop -> 0x%X (hit=%ld ebx=0x%08X)",
                          eip, (DWORD)(g_imageBase + TEAM_ROSTER_CONTINUE_RVA),
                          h, exc->ContextRecord->Ebx);
                Log(tbuf);
            }
            exc->ContextRecord->Eip = (DWORD)(g_imageBase + TEAM_ROSTER_CONTINUE_RVA);
            return EXCEPTION_CONTINUE_EXECUTION;
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
            if (!g_ggReadySignaled) {   // FAZ27: rescue always; log only pre-ready
                char buf[160];
                wsprintfA(buf, "AV @ 0xD30313 [edx]=NULL -> EDX=0x%p (empty wstring)",
                          &g_emptyWStr[0]);
                Log(buf);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // FAZ27: skip ALL diagnostic logging post-GG-ready (IO perturbs NVIDIA
        // adapter init). The rescues above already ran.
        if (g_ggReadySignaled) return EXCEPTION_CONTINUE_SEARCH;
        char buf[256];
        wsprintfA(buf, "INTERESTING EXC: code=0x%X EIP=0x%X flags=0x%X p0=0x%X p1=0x%X",
                  code, eip, exc->ExceptionRecord->ExceptionFlags,
                  exc->ExceptionRecord->NumberParameters > 0
                      ? (DWORD)exc->ExceptionRecord->ExceptionInformation[0] : 0,
                  faultAddr);
        Log(buf);

        // FAZ19: dump regs + stack return-addrs so we can identify which GAME
        // function (0x4xxxxx-0x14xxxxx image range) drove this fault/exit after
        // GG-ready. The ntdll EIP alone doesn't tell us the caller.
        {
            CONTEXT* c = exc->ContextRecord;
            char rbuf[400];
            wsprintfA(rbuf, "  regs: EAX=%08X ECX=%08X EDX=%08X EBX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X",
                      c->Eax, c->Ecx, c->Edx, c->Ebx, c->Esi, c->Edi, c->Ebp, c->Esp);
            Log(rbuf);
            __try {
                DWORD* sp = (DWORD*)c->Esp;
                char sbuf[400];
                int n = wsprintfA(sbuf, "  stack[esp..+0x20]:");
                for (int i = 0; i < 9; i++)
                    n += wsprintfA(sbuf + n, " %08X", sp[i]);
                Log(sbuf);
                if (c->Ebp) {
                    DWORD* bp = (DWORD*)c->Ebp;
                    char bbuf[160];
                    wsprintfA(bbuf, "  [ebp]=%08X [ebp+4]=retaddr=%08X", bp[0], bp[1]);
                    Log(bbuf);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Log("  (stack unreadable)");
            }
        }

        // NOTE: tried 2026-05-21 evening to swallow ntdll/image-range AVs
        // with EXCEPTION_CONTINUE_EXECUTION + EIP+0 -- produced 54000+ exception
        // log entries in 3 seconds (infinite loop). Removed. The correct fix
        // is HDE32 instruction-length advance, deferred to next session.
        // See CHECKPOINT_2026-05-21.md.
    }

    // FAZ21/27: post-GG-ready BROAD exception logger -- DISABLED (the `&& 0`).
    // It served its diagnostic purpose (proved the death was nvldumd fastfail
    // from our NtTerminateThread stub). Its file IO at exception time perturbs
    // the NVIDIA/WinTrust adapter-init path, so it stays off during loading.
    if (0 && g_ggReadySignaled &&
        code != EXCEPTION_BREAKPOINT      && code != STATUS_WX86_BREAKPOINT &&
        code != EXCEPTION_SINGLE_STEP     && code != 0xC0000096 /*priv-insn spam*/ &&
        code != EXCEPTION_ACCESS_VIOLATION&& code != 0xC0000008 /*invalid handle*/ &&
        code != EXCEPTION_STACK_OVERFLOW  && code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION) {
        char cls[80]; lstrcpynA(cls, ClassifyEip(eip), 79); cls[79] = 0;
        char buf[260];
        DWORD p0 = exc->ExceptionRecord->NumberParameters > 0
                       ? (DWORD)exc->ExceptionRecord->ExceptionInformation[0] : 0;
        wsprintfA(buf, "POST-READY EXC: code=0x%X EIP=0x%X (%s) flags=0x%X nParam=%lu p0=0x%X",
                  code, eip, cls, exc->ExceptionRecord->ExceptionFlags,
                  exc->ExceptionRecord->NumberParameters, p0);
        Log(buf);
        // For a __fastfail the EIP/regs are the failing site; dump regs once.
        CONTEXT* c = exc->ContextRecord;
        char rbuf[400];
        wsprintfA(rbuf, "  regs: EAX=%08X ECX=%08X EDX=%08X EBX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X",
                  c->Eax, c->Ecx, c->Edx, c->Ebx, c->Esi, c->Edi, c->Ebp, c->Esp);
        Log(rbuf);
        __try {
            DWORD* sp = (DWORD*)c->Esp;
            char sbuf[400];
            int n = wsprintfA(sbuf, "  stack[esp..+0x20]:");
            for (int i = 0; i < 9; i++) n += wsprintfA(sbuf + n, " %08X", sp[i]);
            Log(sbuf);
        } __except (EXCEPTION_EXECUTE_HANDLER) { Log("  (stack unreadable)"); }
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

static BOOL IsGameProcess() {
    char exePath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        const char* filename = strrchr(exePath, '\\');
        if (filename) {
            filename++; // skip backslash
        } else {
            filename = exePath;
        }
        if (lstrcmpiA(filename, "Goley_.exe") == 0 || lstrcmpiA(filename, "BinaryTr.bin") == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// IAT Hooking Helper
static BOOL HookIatSlot(HMODULE hMod, const char* dllName, const char* funcName, FARPROC detour, FARPROC* orig) {
    if (!hMod) return FALSE;
    BYTE* base = (BYTE*)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD impDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impDirRva) return FALSE;
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + impDirRva);

    HMODULE hTargetDll = GetModuleHandleA(dllName);
    if (!hTargetDll) return FALSE;
    FARPROC origFunc = GetProcAddress(hTargetDll, funcName);
    if (!origFunc) return FALSE;

    for (; imp->Name; imp++) {
        const char* name = (const char*)(base + imp->Name);
        if (lstrcmpiA(name, dllName) == 0) {
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
            for (; iat->u1.Function; iat++) {
                FARPROC* slot = (FARPROC*)&iat->u1.Function;
                if (*slot == origFunc) {
                    DWORD oldProt;
                    if (VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &oldProt)) {
                        if (orig && !*orig) {
                            *orig = *slot;
                        }
                        *slot = detour;
                        VirtualProtect(slot, sizeof(FARPROC), oldProt, &oldProt);
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

// GameGuard.des Hook Definitions
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
static GetProcAddress_t g_origGetProcAddress = NULL;
static ExitProcess_t g_origExitProcess_GG = NULL;

typedef LONG (NTAPI *NtTerminateProcess_t)(HANDLE, LONG);
static NtTerminateProcess_t g_origNtTerminateProcess_GG = NULL;

typedef VOID (NTAPI *RtlExitUserProcess_t)(UINT);
static RtlExitUserProcess_t g_origRtlExitUserProcess_GG = NULL;

typedef LONG (NTAPI *NtTerminateThread_t)(HANDLE, LONG);
static NtTerminateThread_t g_origNtTerminateThread_GG = NULL;

static DWORD g_parentPid = 0;

static DWORD GetParentProcessId() {
    DWORD parentPid = 0;
    DWORD myPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == myPid) {
                    parentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return parentPid;
}

static BOOL WINAPI HookedTerminateProcess_GG(HANDLE hProcess, UINT uExitCode) {
    DWORD targetPid = GetProcessId(hProcess);
    char buf[256];
    wsprintfA(buf, "[GG-HOOK] TerminateProcess: targetPid=%lu (parent=%lu) exitCode=%u", targetPid, g_parentPid, uExitCode);
    Log(buf);

    if (targetPid == g_parentPid && g_parentPid != 0) {
        Log("  [GG-HOOK] Blocking TerminateProcess on parent game process!");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return TerminateProcess(hProcess, uExitCode);
}

static LONG NTAPI HookedNtTerminateProcess_GG(HANDLE hProcess, LONG exitStatus) {
    DWORD targetPid = 0;
    if (hProcess == GetCurrentProcess() || (DWORD)(ULONG_PTR)hProcess == (DWORD)-1) {
        targetPid = GetCurrentProcessId();
    } else {
        targetPid = GetProcessId(hProcess);
    }

    char buf[256];
    wsprintfA(buf, "[GG-HOOK] NtTerminateProcess: targetPid=%lu (parent=%lu) status=0x%X", targetPid, g_parentPid, exitStatus);
    Log(buf);

    if (targetPid == g_parentPid && g_parentPid != 0) {
        Log("  [GG-HOOK] Blocking NtTerminateProcess on parent game process!");
        return 0; // STATUS_SUCCESS
    }

    if (g_origNtTerminateProcess_GG) {
        return g_origNtTerminateProcess_GG(hProcess, exitStatus);
    }
    
    static NtTerminateProcess_t pReal = NULL;
    if (!pReal) {
        HMODULE hNt = GetModuleHandleA("ntdll.dll");
        if (hNt) pReal = (NtTerminateProcess_t)GetProcAddress(hNt, "NtTerminateProcess");
    }
    if (pReal) return pReal(hProcess, exitStatus);
    return 0;
}

static VOID WINAPI HookedExitProcess_GG(UINT uExitCode) {
    char buf[256];
    wsprintfA(buf, "[GG-HOOK] ExitProcess(%u) called. Allowing self-exit.", uExitCode);
    Log(buf);
    if (g_origExitProcess_GG) {
        g_origExitProcess_GG(uExitCode);
    } else {
        ExitProcess(uExitCode);
    }
}

static VOID NTAPI HookedRtlExitUserProcess_GG(UINT status) {
    char buf[256];
    wsprintfA(buf, "[GG-HOOK] RtlExitUserProcess(%u) called. Allowing self-exit.", status);
    Log(buf);
    if (g_origRtlExitUserProcess_GG) {
        g_origRtlExitUserProcess_GG(status);
    } else {
        static RtlExitUserProcess_t pReal = NULL;
        if (!pReal) {
            HMODULE hNt = GetModuleHandleA("ntdll.dll");
            if (hNt) pReal = (RtlExitUserProcess_t)GetProcAddress(hNt, "RtlExitUserProcess");
        }
        if (pReal) pReal(status);
    }
}

static LONG NTAPI HookedNtTerminateThread_GG(HANDLE hThread, LONG status) {
    char buf[256];
    wsprintfA(buf, "[GG-HOOK] NtTerminateThread called. Allowing.");
    Log(buf);
    if (g_origNtTerminateThread_GG) {
        return g_origNtTerminateThread_GG(hThread, status);
    }
    static NtTerminateThread_t pReal = NULL;
    if (!pReal) {
        HMODULE hNt = GetModuleHandleA("ntdll.dll");
        if (hNt) pReal = (NtTerminateThread_t)GetProcAddress(hNt, "NtTerminateThread");
    }
    if (pReal) return pReal(hThread, status);
    return 0;
}

static FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    if (lpProcName && ((ULONG_PTR)lpProcName > 0xFFFF)) {
        if (lstrcmpiA(lpProcName, "TerminateProcess") == 0) {
            Log("[GG-HOOK] Intercepted GetProcAddress(TerminateProcess)");
            return (FARPROC)HookedTerminateProcess_GG;
        }
        if (lstrcmpiA(lpProcName, "ExitProcess") == 0) {
            Log("[GG-HOOK] Intercepted GetProcAddress(ExitProcess)");
            return (FARPROC)HookedExitProcess_GG;
        }
        if (lstrcmpiA(lpProcName, "NtTerminateProcess") == 0) {
            Log("[GG-HOOK] Intercepted GetProcAddress(NtTerminateProcess)");
            return (FARPROC)HookedNtTerminateProcess_GG;
        }
        if (lstrcmpiA(lpProcName, "RtlExitUserProcess") == 0) {
            Log("[GG-HOOK] Intercepted GetProcAddress(RtlExitUserProcess)");
            return (FARPROC)HookedRtlExitUserProcess_GG;
        }
        if (lstrcmpiA(lpProcName, "NtTerminateThread") == 0) {
            Log("[GG-HOOK] Intercepted GetProcAddress(NtTerminateThread)");
            return (FARPROC)HookedNtTerminateThread_GG;
        }
    }
    return g_origGetProcAddress(hModule, lpProcName);
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
            DWORD goleyFrame = 0;   // FAZ49: first Goley_ .text return addr on the stack
            if (ok && ctx.Esp) {
                // Read [ESP+0] = return address (the address right after
                // the call that parked us here, i.e. the next instruction
                // inside the caller -- typically Goley_ code).
                __try {
                    retAddr = *(volatile DWORD*)(ULONG_PTR)ctx.Esp;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    retAddr = 0xDEADBEEF;
                }
                // FAZ49: scan up the stack for the first Goley_ code return
                // address (image .text ~0x401000..0x1000000). When a thread is
                // parked in ntdll/kernelbase waiting, this reveals the Goley_
                // call site that issued the wait -> WHERE the game is stuck.
                __try {
                    DWORD* sp = (DWORD*)(ULONG_PTR)ctx.Esp;
                    for (int k = 0; k < 768; ++k) {
                        DWORD v = sp[k];
                        if (v >= 0x401000 && v < 0x1000000) { goleyFrame = v; break; }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            if (ok) {
                char buf[512];
                char eipClass[80]; lstrcpynA(eipClass, ClassifyEip(ctx.Eip), 79); eipClass[79] = 0;
                char retClass[80]; lstrcpynA(retClass, ClassifyEip(retAddr),   79); retClass[79] = 0;
                wsprintfA(buf,
                    "  tid=%lu EIP=0x%08X (%s) ESP=0x%08X [ESP]=0x%08X (%s) goley=0x%08X",
                    te.th32ThreadID, ctx.Eip, eipClass,
                    ctx.Esp, retAddr, retClass, goleyFrame);
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

// FAZ16 DENEY: GameGuard.des'i spawn et ama SUSPENDED birak (inject/resume yok)
// ----------------------------------------------------------------------------
// Kok neden: GG kendi init'ini error 150 ile reddedip ExitProcess(150) yapiyor;
// GG olunce oyun da olur. Bu deneyde GG child'ini CREATE_SUSPENDED dogurup HIC
// resume etmiyoruz -> GG init kodunu hic calistiramaz -> error 150 veremez,
// olemez. Oyunun gecerli process/thread handle'lari olur ama "GG hazir" sinyali
// gelmez -> oyun muhtemelen "초기화중"de hang eder (crash yerine). Hang ederse
// harici nprotect_probe.py ile beklenen event'i bulup SetEvent ederiz.
// Toggle: false yapinca eski davranis (inject+resume) geri gelir.
// PATH A (faz19-B teshisi sonrasi varsayilan): GG'yi suspended birak. Pure GG
// teshisi gosterdi ki islevsel GG tampere oyunu <1sn'de oldurUyor (B yolu kendini
// yeniyor) -> GG'yi hic calistirmayip oyunun kontrollerini taklit edecegiz.
static const BOOL GG_LEAVE_SUSPENDED = TRUE;

// FAZ19-B teshis modu (sadece GG_LEAVE_SUSPENDED FALSE iken): GG'yi PURE calistir
// (inject YOK, resume VAR) -> native davranis + ag capture. TESHIS BITTI: pure GG
// ag DENEMEDI (0 TCP/DNS) ve oyun <1sn'de oldu -> error 150 lokal/anti-tamper,
// server degil. Varsayilan kapali.
static const BOOL GG_RUN_CLEAN = FALSE;

static BOOL IsGameGuardSpawn(const char* app, const char* cmd) {
    char low[1024];
    int n = 0;
    if (app) { for (int i = 0; app[i] && n < 1022; i++) low[n++] = (char)(app[i] | 0x20); }
    if (cmd) { for (int i = 0; cmd[i] && n < 1022; i++) low[n++] = (char)(cmd[i] | 0x20); }
    low[n] = 0;
    // "gameguard" veya ".des" gecen herhangi bir spawn'i GG say.
    for (int i = 0; i + 8 < n; i++) {
        if (low[i]=='g'&&low[i+1]=='a'&&low[i+2]=='m'&&low[i+3]=='e'&&
            low[i+4]=='g'&&low[i+5]=='u'&&low[i+6]=='a'&&low[i+7]=='r'&&low[i+8]=='d')
            return TRUE;
    }
    for (int i = 0; i + 3 < n; i++) {
        if (low[i]=='.'&&low[i+1]=='d'&&low[i+2]=='e'&&low[i+3]=='s') return TRUE;
    }
    return FALSE;
}

static BOOL IsGGErrorSpawn(const char* app, const char* cmd) {
    char low[1024];
    int n = 0;
    if (app) { for (int i = 0; app[i] && n < 1022; i++) low[n++] = (char)(app[i] | 0x20); }
    if (cmd) { for (int i = 0; cmd[i] && n < 1022; i++) low[n++] = (char)(cmd[i] | 0x20); }
    low[n] = 0;
    for (int i = 0; i + 10 < n; i++) {
        if (low[i]=='g'&&low[i+1]=='g'&&low[i+2]=='e'&&low[i+3]=='r'&&
            low[i+4]=='r'&&low[i+5]=='o'&&low[i+6]=='r'&&low[i+7]=='.'&&
            low[i+8]=='d'&&low[i+9]=='e'&&low[i+10]=='s') {
            return TRUE;
        }
    }
    return FALSE;
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
    DWORD caller = (DWORD)(ULONG_PTR)_ReturnAddress();
    wsprintfA(buf, "[HOOK] CreateProcessA: app='%s' cmd='%.200s' flags=0x%X caller=0x%X",
              lpApplicationName ? lpApplicationName : "(null)",
              lpCommandLine     ? lpCommandLine     : "(null)",
              dwCreationFlags,
              caller);
    Log(buf);

    if (IsGGErrorSpawn(lpApplicationName, lpCommandLine)) {
        __try {
            DWORD* raSlot = (DWORD*)_AddressOfReturnAddress();
            wsprintfA(buf,
                "[GGERROR-DIAG] spawn caller=0x%X currentDir='%s' stack: ret=%08X s1=%08X s2=%08X s3=%08X s4=%08X",
                caller,
                lpCurrentDirectory ? lpCurrentDirectory : "(null)",
                raSlot[0], raSlot[1], raSlot[2], raSlot[3], raSlot[4]);
            Log(buf);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[GGERROR-DIAG] stack unreadable");
        }
    }

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

    // FAZ16/19 DENEY: GameGuard child'i icin ozel modlar.
    if (IsGameGuardSpawn(lpApplicationName, lpCommandLine)) {
        if (GG_LEAVE_SUSPENDED) {
            wsprintfA(buf, "  -> [DENEY] GameGuard PID=%lu SUSPENDED (inject/resume YOK)", childPid);
            Log(buf);
            return ok;  // GG donmus halde
        }
        if (GG_RUN_CLEAN) {
            wsprintfA(buf, "  -> [DENEY-B] GameGuard PID=%lu PURE calisiyor (inject YOK, resume VAR) "
                           "-> native error-150 + ag denemeleri izlenecek", childPid);
            Log(buf);
            if (addedSuspend) ResumeThread(hThread);
            return ok;  // GG kendi DLL'imiz olmadan calisir
        }
    }

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

    // FAZ16/19 DENEY: GameGuard child (CreateProcessW yolu).
    if (IsGameGuardSpawn(appA, cmdA)) {
        if (GG_LEAVE_SUSPENDED) {
            wsprintfA(buf, "  -> [DENEY] GameGuard-W PID=%lu SUSPENDED (inject/resume YOK)", childPid);
            Log(buf);
            return ok;
        }
        if (GG_RUN_CLEAN) {
            wsprintfA(buf, "  -> [DENEY-B] GameGuard-W PID=%lu PURE (inject YOK, resume VAR)", childPid);
            Log(buf);
            if (addedSuspend) ResumeThread(hThread);
            return ok;
        }
    }

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

static void DescribeHandleType(HANDLE h, char* buf, int bufSize) {
    if (!g_pNtQueryObject || bufSize < 4) {
        if (bufSize >= 4) lstrcpyA(buf, "?");
        return;
    }
    BYTE tmp[1024] = {0};
    ULONG retLen = 0;
    LONG status = g_pNtQueryObject(h, 2 /*ObjectTypeInformation*/,
                                   tmp, sizeof(tmp), &retLen);
    if (status < 0) {
        wsprintfA(buf, "type?(0x%lX)", status);
        return;
    }
    OBJECT_NAME_INFORMATION_local* info = (OBJECT_NAME_INFORMATION_local*)tmp;
    if (info->Name.Length == 0 || info->Name.Buffer == NULL) {
        lstrcpyA(buf, "<type-unnamed>");
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

static __forceinline BOOL IsPostReadyGfxWaitCaller(void* ra) {
    DWORD a = (DWORD)(ULONG_PTR)ra;
    // FAZ49: main thread is blocked after the GFx/IME virtual call path:
    // 0x630770 -> call 0x717570 -> WaitForSingleObjectEx return near 0x6307F4.
    // Keep post-ready wait diagnostics narrow so render init is not disturbed.
    return (a >= 0x00630700 && a < 0x00630880);
}

static __forceinline BOOL IsMainThreadWait(void) {
    return g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId;
}

static const char* WaitLogSuffix(void* ra) {
    if (!g_ggReadySignaled) return "";
    if (IsPostReadyGfxWaitCaller(ra)) return "/POST-GFX";
    if (IsMainThreadWait()) return "/POST-MAIN";
    return "/POST";
}

// FAZ18: the Gamebryo task pool hammers WaitForSingleObject from a tight code
// range (callers ~0x0181F000..0x01831000, seen in faz17 thread dumps) and
// floods the log. We want the INIT thread's GG-ready wait (a non-pool caller,
// possibly a short-timeout poll loop that the old longWait>=5s filter missed).
// So: log a wait if it is long OR its caller is outside the engine task pool.
static __forceinline BOOL InterestingWait(DWORD timeout, void* ra) {
    // FAZ27: go silent post-GG-ready. The WFSO/WFMO logging does NtQueryObject +
    // file IO; doing that during NVIDIA/render init perturbs driver init. The
    // SHIM auto-signal logic runs independently of this gate.
    // FAZ53: post-ready wait logging already proved the main-thread wait is a
    // normal per-frame mutex/DWM path. Keep the hook functional for the GG-ready
    // shim, but stop logging post-ready waits so UI-loader diagnostics are not
    // buried under tens of MB of frame-loop noise.
    if (g_ggReadySignaled) return FALSE;
    if (timeout == INFINITE || timeout >= 5000) return TRUE;
    DWORD a = (DWORD)(ULONG_PTR)ra;
    if (a >= 0x0181F000 && a < 0x01831000) return FALSE;  // engine task pool
    if (a >= 0x77000000) return FALSE;                    // ntdll/kernel internal
    return TRUE;
}

static DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout) {
    void* ra = _ReturnAddress();
    BOOL logit = InterestingWait(dwTimeout, ra);
    if (logit && EnterHook()) {
        char name[300];
        char type[80];
        DescribeHandle(hObj, name, sizeof(name));
        DescribeHandleType(hObj, type, sizeof(type));
        char buf[600];
        wsprintfA(buf, "[WFSO%s] TID=%lu h=0x%p type='%s' timeout=%lu name='%s' caller=0x%p",
                  WaitLogSuffix(ra),
                  GetCurrentThreadId(), hObj, type, dwTimeout, name, ra);
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFSO(hObj, dwTimeout);
    if (logit && r != WAIT_TIMEOUT && EnterHook()) {
        char buf[200];
        wsprintfA(buf, "  [WFSO] TID=%lu h=0x%p caller=0x%p -> %lu",
                  GetCurrentThreadId(), hObj, ra, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

static DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE hObj, DWORD dwTimeout,
                                                BOOL bAlertable) {
    void* ra = _ReturnAddress();
    BOOL logit = InterestingWait(dwTimeout, ra);
    if (logit && EnterHook()) {
        char name[300];
        char type[80];
        DescribeHandle(hObj, name, sizeof(name));
        DescribeHandleType(hObj, type, sizeof(type));
        char buf[600];
        wsprintfA(buf, "[WFSOEx%s] TID=%lu h=0x%p type='%s' timeout=%lu alertable=%d name='%s' caller=0x%p",
                  WaitLogSuffix(ra),
                  GetCurrentThreadId(), hObj, type, dwTimeout, bAlertable, name, ra);
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFSOEx(hObj, dwTimeout, bAlertable);
    if (logit && r != WAIT_TIMEOUT && EnterHook()) {
        char buf[200];
        wsprintfA(buf, "  [WFSOEx] TID=%lu h=0x%p caller=0x%p -> %lu",
                  GetCurrentThreadId(), hObj, ra, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

// ============================================================================
// FAZ24: timed self-minidump -- capture the LIVE failing render-init state
// ============================================================================
//
// WER LocalDumps only ever snapshots the messy TEARDOWN (ntdll int3 + GPU UMD
// FreeLibraryAndExitThread), never the root cause of the post-GG-ready death
// (~130ms after GG-ready). The death is silent (no VEH-caught exception), so
// we can't trigger a dump on a fault. Instead: when GG-ready fires, a thread
// writes self-minidumps at a few short delays to bracket the death and capture
// what every thread (esp. the main/render thread) is REALLY doing just before
// the process dies. dbghelp!MiniDumpWriteDump; MiniDumpWithThreadInfo includes
// thread stacks for walking. Output: C:\Joygame\goley-rev\dumps\self\.
typedef BOOL (WINAPI *MiniDumpWriteDump_t)(HANDLE, DWORD, HANDLE, ULONG,
                                           PVOID, PVOID, PVOID);
static volatile LONG g_selfDumpStarted = 0;
// FAZ27: self-dump suspends all threads mid-NVIDIA-init -> disruptive. Off.
static const BOOL SELFDUMP_ENABLED = FALSE;

static void WriteSelfDump(int idx, DWORD sinceMs) {
    // Load the SYSTEM dbghelp by FULL PATH -- the game has an OLD dbghelp.dll
    // loaded (BugTrap, base ~0x58DE0000) where MiniDumpWithThreadInfo is
    // unsupported (INVALID_PARAMETER). The system one is modern.
    HMODULE hDbg = LoadLibraryA("C:\\Windows\\System32\\dbghelp.dll");
    if (!hDbg) hDbg = LoadLibraryA("dbghelp.dll");
    if (!hDbg) { Log("[SELFDUMP] dbghelp.dll load FAILED"); return; }
    MiniDumpWriteDump_t pMDWD = (MiniDumpWriteDump_t)GetProcAddress(hDbg, "MiniDumpWriteDump");
    if (!pMDWD) { Log("[SELFDUMP] MiniDumpWriteDump not found"); return; }
    char path[MAX_PATH];
    wsprintfA(path, "C:\\Joygame\\goley-rev\\dumps\\self\\selfdump_%d_%lums.dmp", idx, sinceMs);
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char b[200]; wsprintfA(b, "[SELFDUMP] CreateFile FAILED err=%lu path=%s", GetLastError(), path); Log(b);
        return;
    }
    // MiniDumpNormal (0): thread list + module list + thread STACK memory --
    // enough to walk every thread. Supported by every dbghelp version.
    BOOL ok = pMDWD(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                    0 /*MiniDumpNormal*/, NULL, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hFile);
    char b[260];
    wsprintfA(b, "[SELFDUMP] #%d @+%lums -> %s (ok=%d err=0x%lX)", idx, sinceMs, path, ok, err);
    Log(b);
}

static DWORD WINAPI SelfDumpThread(LPVOID) {
    // Death is ~127-168ms after GG-ready. Bracket it with snapshots BEFORE
    // teardown so we see the real failing state (not the WER teardown int3).
    // MiniDumpWriteDump SUSPENDS all threads while writing (~90ms for 36
    // threads), so the process is frozen during the write and CANNOT die
    // mid-dump. That lets us start ONE dump late (+110ms, just before the
    // ~127ms death) and reliably capture the live render-init/crash state.
    // (+62ms was too early -- d3d9 not loaded yet.)
    DWORD t0 = GetTickCount();
    const DWORD delays[] = { 60 };
    for (int i = 0; i < (int)(sizeof(delays)/sizeof(delays[0])); i++) {
        DWORD now = GetTickCount();
        DWORD target = t0 + delays[i];
        if (now < target) Sleep(target - now);
        WriteSelfDump(i, GetTickCount() - t0);
    }
    return 0;
}

static DWORD WINAPI HookedWaitForMultipleObjects(DWORD nCount,
                                                  const HANDLE* pHandles,
                                                  BOOL bWaitAll,
                                                  DWORD dwTimeout) {
    void* ra = _ReturnAddress();
    BOOL logit = InterestingWait(dwTimeout, ra);
    if (logit && pHandles && EnterHook()) {
        char buf[2048];
        int off = wsprintfA(buf, "[WFMO] TID=%lu n=%lu waitAll=%d timeout=%lu caller=0x%p",
                            GetCurrentThreadId(), nCount, bWaitAll, dwTimeout, ra);
        for (DWORD i = 0; i < nCount && i < 8 && off < 1900; i++) {
            char name[280];
            char type[80];
            DescribeHandle(pHandles[i], name, sizeof(name));
            DescribeHandleType(pHandles[i], type, sizeof(type));
            off += wsprintfA(buf + off, "; h%lu=0x%p type='%s' '%.200s'",
                             i, pHandles[i], type, name);
        }
        Log(buf);
        LeaveHook();
    }
    // FAZ19 SHIM: the init thread blocks here on
    //   WaitForMultipleObjects([ready=h0, fail=h1], waitAll=FALSE, INFINITE)
    // at the GG launch fn (~0x008E5080). GG is suspended so it never signals
    // the ready event; we signal index 0 (the ready event, confirmed by
    // WFMO->0 across runs) ourselves so the game advances without the external
    // probe. Match by signature + caller RANGE: the exact return address and
    // handle values shift slightly run-to-run (observed 0x8E5081 / 0x8E5082).
    {
        DWORD raddr = (DWORD)(ULONG_PTR)ra;
        if (nCount == 2 && !bWaitAll && dwTimeout == INFINITE &&
            raddr >= 0x008E5000 && raddr < 0x008E5100 && pHandles) {
            SetEvent(pHandles[0]);
            // FAZ21: arm LoadLibrary/GetProcAddress capture. The very next
            // thing the success path does is call 0x8E8740, which decrypts +
            // LoadLibrary's the GG SDK DLL and GetProcAddress's 2 integrity fns.
            LONG was = InterlockedExchange(&g_ggReadySignaled, 1);
            // FAZ24/27: timed self-dump DISABLED -- MiniDumpWriteDump SUSPENDS
            // ALL threads at +60ms, i.e. RIGHT during nvldumd!OpenAdapter
            // (~+63ms), which itself can fastfail the NVIDIA init. Diagnostic
            // only; off for the "patcher passive post-ready" test.
            if (SELFDUMP_ENABLED && !was && InterlockedExchange(&g_selfDumpStarted, 1) == 0) {
                HANDLE hSD = CreateThread(NULL, 0, SelfDumpThread, NULL, 0, NULL);
                if (hSD) CloseHandle(hSD);
            }
            if (EnterHook()) {
                char b2[200];
                wsprintfA(b2, "[SHIM] auto-SetEvent GG-ready h0=0x%p @ WFMO caller=0x%X "
                              "(capture %s)",
                          pHandles[0], raddr, was ? "already-armed" : "ARMED");
                Log(b2);
                LeaveHook();
            }
        }
    }
    DWORD r = g_origWFMO(nCount, pHandles, bWaitAll, dwTimeout);
    if (logit && r != WAIT_TIMEOUT && EnterHook()) {
        char buf[160];
        wsprintfA(buf, "  [WFMO] TID=%lu caller=0x%p -> %lu", GetCurrentThreadId(), ra, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

// NtWaitForSingleObject hook removed -- ntdll syscall stubs are too small
// for HDE32 to trampoline reliably. kernel32 wrappers cover what we need.

// ============================================================================
// FAZ21: LoadLibrary + GetProcAddress capture (GAME process, log-only)
// ============================================================================
//
// faz20 statik analizi: GG-ready WFMO success path'i (0x8E50EF) -> call 0x8E8740,
// bir GG SDK modulunu RUNTIME decrypt edip LoadLibrary ile yukluyor + ondan 2
// fonksiyon GetProcAddress'liyor (oyun image'ini 0x400000 + 0x40B buffer ile
// cagrilan bellek-butunluk callback'leri). DLL adi + fn isimleri SIFRELI
// (0x103f64c/0x103f62c/0x103f614, 0x8EC410 runtime decrypt) -> sadece
// LoadLibrary/GetProcAddress argumaninda PLAINTEXT olarak gorunuyor.
//
// LoadLibrary* her zaman loglanir (dusuk hacim, init'te ~onlarca yuklenir).
// GetProcAddress SADECE GG-ready oto-signal'den sonra (g_ggReadySignaled)
// loglanir -- aksi halde normal init binlerce GetProcAddress ile log'u bogar.
// Boylece WFMO->0'dan hemen sonraki 0x8E8740 yuklemeleri net yakalanir.
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef HMODULE (WINAPI *LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef FARPROC (WINAPI *GetProcAddressGame_t)(HMODULE, LPCSTR);

static LoadLibraryA_t       g_origLoadLibraryA       = NULL;
static LoadLibraryW_t       g_origLoadLibraryW       = NULL;
static LoadLibraryExA_t     g_origLoadLibraryExA     = NULL;
static LoadLibraryExW_t     g_origLoadLibraryExW     = NULL;
static GetProcAddressGame_t g_origGetProcAddressGame = NULL;

// Best-effort wide->ANSI for logging a DLL path (truncate at cap-1).
static void WideToAnsiLog(LPCWSTR w, char* out, int cap) {
    int i = 0;
    if (w) for (; i < cap - 1 && w[i]; i++) out[i] = (w[i] < 0x80) ? (char)w[i] : '?';
    out[i] = 0;
}

static HMODULE WINAPI HookedLoadLibraryA(LPCSTR name) {
    void* ra = _ReturnAddress();
    HMODULE h = g_origLoadLibraryA(name);
    if (EnterHook()) {
        char buf[600];
        wsprintfA(buf, "[LL-A%s] '%s' -> hMod=0x%p caller=0x%p",
                  g_ggReadySignaled ? "/POST" : "", name ? name : "(null)", h, ra);
        Log(buf);
        LeaveHook();
    }
    return h;
}

static HMODULE WINAPI HookedLoadLibraryW(LPCWSTR name) {
    void* ra = _ReturnAddress();
    HMODULE h = g_origLoadLibraryW(name);
    if (EnterHook()) {
        char a[400]; WideToAnsiLog(name, a, sizeof(a));
        char buf[600];
        wsprintfA(buf, "[LL-W%s] '%s' -> hMod=0x%p caller=0x%p",
                  g_ggReadySignaled ? "/POST" : "", a, h, ra);
        Log(buf);
        LeaveHook();
    }
    return h;
}

static HMODULE WINAPI HookedLoadLibraryExA(LPCSTR name, HANDLE hFile, DWORD flags) {
    void* ra = _ReturnAddress();
    HMODULE h = g_origLoadLibraryExA(name, hFile, flags);
    if (EnterHook()) {
        char buf[600];
        wsprintfA(buf, "[LLEx-A%s] '%s' flags=0x%X -> hMod=0x%p caller=0x%p",
                  g_ggReadySignaled ? "/POST" : "", name ? name : "(null)", flags, h, ra);
        Log(buf);
        LeaveHook();
    }
    return h;
}

static HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR name, HANDLE hFile, DWORD flags) {
    void* ra = _ReturnAddress();
    HMODULE h = g_origLoadLibraryExW(name, hFile, flags);
    if (EnterHook()) {
        char a[400]; WideToAnsiLog(name, a, sizeof(a));
        char buf[600];
        wsprintfA(buf, "[LLEx-W%s] '%s' flags=0x%X -> hMod=0x%p caller=0x%p",
                  g_ggReadySignaled ? "/POST" : "", a, flags, h, ra);
        Log(buf);
        LeaveHook();
    }
    return h;
}

// kernel32!UnhandledExceptionFilter: the last-chance filter the CRT/BugTrap
// route a fault through before the process is torn down. Logging it captures
// the REAL faulting exception record + address even when our VEH returned
// CONTINUE_SEARCH (e.g. a C++ exception or a fault inside render init).
typedef LONG (WINAPI *UnhandledExceptionFilter_t)(struct _EXCEPTION_POINTERS*);
static UnhandledExceptionFilter_t g_origUEF = NULL;

static LONG WINAPI HookedUEF(struct _EXCEPTION_POINTERS* ep) {
    void* ra = _ReturnAddress();
    if (EnterHook()) {
        if (ep && ep->ExceptionRecord) {
            char buf[300];
            wsprintfA(buf, "[UEF] code=0x%X addr=0x%p flags=0x%X p0=0x%p caller=0x%p",
                      ep->ExceptionRecord->ExceptionCode,
                      ep->ExceptionRecord->ExceptionAddress,
                      ep->ExceptionRecord->ExceptionFlags,
                      ep->ExceptionRecord->NumberParameters > 0
                          ? (void*)ep->ExceptionRecord->ExceptionInformation[0] : NULL,
                      ra);
            Log(buf);
        } else {
            Log("[UEF] called with NULL ExceptionPointers");
        }
        LeaveHook();
    }
    return g_origUEF ? g_origUEF(ep) : EXCEPTION_CONTINUE_SEARCH;
}

static FARPROC WINAPI HookedGetProcAddressGame(HMODULE hModule, LPCSTR lpProcName) {
    void* ra = _ReturnAddress();
    FARPROC p = g_origGetProcAddressGame(hModule, lpProcName);
    // Only log POST GG-ready (else normal init floods us). The integrity
    // callbacks 0x8E8740 resolves are the 2 fn names we want.
    if (g_ggReadySignaled && EnterHook()) {
        char buf[600];
        if ((ULONG_PTR)lpProcName > 0xFFFF) {
            wsprintfA(buf, "[GPA/POST] hMod=0x%p '%s' -> 0x%p caller=0x%p",
                      hModule, lpProcName, p, ra);
        } else {
            wsprintfA(buf, "[GPA/POST] hMod=0x%p ordinal#%u -> 0x%p caller=0x%p",
                      hModule, (unsigned)(ULONG_PTR)lpProcName, p, ra);
        }
        Log(buf);
        LeaveHook();
    }
    return p;
}

// -- NT API structure definitions for low-level hooks
typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_NT, *PUNICODE_STRING_NT;

typedef struct _STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING_NT, *PSTRING_NT, ANSI_STRING_NT, *PANSI_STRING_NT;

typedef NTSTATUS (NTAPI *LdrLoadDll_t)(
    PWSTR SearchPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING_NT DllName,
    PVOID *BaseAddress
);
static LdrLoadDll_t g_origLdrLoadDll = NULL;

typedef NTSTATUS (NTAPI *LdrGetProcedureAddress_t)(
    PVOID BaseAddress,
    PANSI_STRING_NT Name,
    ULONG Ordinal,
    PVOID *ProcedureAddress
);
static LdrGetProcedureAddress_t g_origLdrGetProcedureAddress = NULL;

static NTSTATUS NTAPI HookedLdrLoadDll(
    PWSTR SearchPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING_NT DllName,
    PVOID *BaseAddress
) {
    NTSTATUS status = g_origLdrLoadDll(SearchPath, DllCharacteristics, DllName, BaseAddress);
    if (DllName && DllName->Buffer && EnterHook()) {
        char nameA[512] = {0};
        int len = DllName->Length / sizeof(wchar_t);
        if (len > 511) len = 511;
        for (int i = 0; i < len; i++) {
            nameA[i] = (DllName->Buffer[i] < 0x80) ? (char)DllName->Buffer[i] : '?';
        }
        nameA[len] = '\0';

        char buf[1024];
        wsprintfA(buf, "[LdrLoadDll%s] '%s' -> BaseAddress=0x%p status=0x%X caller=0x%p",
                  g_ggReadySignaled ? "/POST" : "", nameA, BaseAddress ? *BaseAddress : NULL, status, _ReturnAddress());
        Log(buf);
        LeaveHook();
    }
    return status;
}

static NTSTATUS NTAPI HookedLdrGetProcedureAddress(
    PVOID BaseAddress,
    PANSI_STRING_NT Name,
    ULONG Ordinal,
    PVOID *ProcedureAddress
) {
    NTSTATUS status = g_origLdrGetProcedureAddress(BaseAddress, Name, Ordinal, ProcedureAddress);
    if (g_ggReadySignaled && EnterHook()) {
        char buf[1024];
        if (Name && Name->Buffer) {
            wsprintfA(buf, "[LdrGPA/POST] hMod=0x%p '%s' -> 0x%p status=0x%X caller=0x%p",
                      BaseAddress, Name->Buffer, ProcedureAddress ? *ProcedureAddress : NULL, status, _ReturnAddress());
        } else {
            wsprintfA(buf, "[LdrGPA/POST] hMod=0x%p ordinal#%u -> 0x%p status=0x%X caller=0x%p",
                      BaseAddress, Ordinal, ProcedureAddress ? *ProcedureAddress : NULL, status, _ReturnAddress());
        }
        Log(buf);
        LeaveHook();
    }
    return status;
}

static void InitNtdllHooks() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { Log("InitNtdllHooks: ntdll not loaded"); return; }

    struct Spec { const char* name; LPVOID detour; LPVOID* orig; };
    Spec specs[] = {
        { "LdrLoadDll",             (LPVOID)&HookedLdrLoadDll,             (LPVOID*)&g_origLdrLoadDll             },
        { "LdrGetProcedureAddress", (LPVOID)&HookedLdrGetProcedureAddress, (LPVOID*)&g_origLdrGetProcedureAddress },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        PVOID fn = GetProcAddress(hNtdll, specs[i].name);
        char buf[200];
        if (!fn) { wsprintfA(buf, "InitNtdllHooks: GetProcAddress(%s) FAILED", specs[i].name); Log(buf); continue; }
        MH_STATUS s = MH_CreateHook(fn, specs[i].detour, specs[i].orig);
        if (s != MH_OK) { wsprintfA(buf, "InitNtdllHooks: MH_CreateHook(%s) status=%d", specs[i].name, s); Log(buf); continue; }
        s = MH_EnableHook(fn);
        if (s != MH_OK) { wsprintfA(buf, "InitNtdllHooks: MH_EnableHook(%s) status=%d", specs[i].name, s); Log(buf); continue; }
        wsprintfA(buf, "InitNtdllHooks: %s hooked at 0x%p", specs[i].name, fn);
        Log(buf);
    }
}

// ============================================================================
// FAZ23: d3d9 uninitialized-critical-section FIX
// ============================================================================
//
// faz22 (WinDbg): the post-GG-ready death is an AV in
// ntdll!RtlpWaitOnCriticalSection -- d3d9 enters one of its OWN global
// critical sections (d3d9+0x178480) during Direct3DCreate9 ->
// InternalDirectDrawCreate -> GetDisplayModeList, but that critsec is ZEROED
// (DebugInfo=0, OwningThread=0, never InitializeCriticalSection'd). A zeroed
// LockCount(0) reads as "locked" -> contended path -> inc DebugInfo->
// ContentionCount with DebugInfo=NULL -> write to 0x14 -> AV -> process dies.
// Not caused by our hooks/thread-suspension (verified: persists with both off).
//
// FIX: hook ntdll!RtlEnterCriticalSection. A VALID critsec always has DebugInfo
// = a real pointer OR 0xFFFFFFFF (-1, the no-debug-info sentinel) -- NEVER 0.
// So DebugInfo==0 uniquely identifies a zeroed/uninitialized critsec. When we
// see one, RtlInitializeCriticalSection it FIRST, then enter normally. Targeted
// and offset-independent: only touches the broken case, leaves all valid
// critsecs untouched.
typedef LONG (NTAPI *RtlEnterCriticalSection_t)(PVOID);
typedef LONG (NTAPI *RtlInitializeCriticalSection_t)(PVOID);
static RtlEnterCriticalSection_t      g_origRtlEnterCriticalSection = NULL;
static RtlInitializeCriticalSection_t g_pRtlInitializeCriticalSection = NULL;
static volatile LONG g_critsecFixCount = 0;

static LONG NTAPI HookedRtlEnterCriticalSection(PVOID cs) {
    // DebugInfo is the first pointer-sized field of RTL_CRITICAL_SECTION.
    if (cs && g_pRtlInitializeCriticalSection) {
        PVOID dbg = *(PVOID*)cs;            // cs->DebugInfo
        if (dbg == NULL) {                  // zeroed / uninitialized -> fix it
            g_pRtlInitializeCriticalSection(cs);
            LONG n = InterlockedIncrement(&g_critsecFixCount);
            // FAZ27: do NOT log post-GG-ready -- file IO on a hot critsec path
            // during NVIDIA/render init is exactly the interference we're
            // eliminating. Init silently; only log pre-ready occurrences.
            if (n <= 20 && !g_ggReadySignaled && EnterHook()) {
                char buf[160];
                wsprintfA(buf, "[CSFIX] uninitialized critsec 0x%p (DebugInfo=NULL) -> InitializeCriticalSection (#%ld) caller=0x%p",
                          cs, n, _ReturnAddress());
                Log(buf);
                LeaveHook();
            }
        }
    }
    return g_origRtlEnterCriticalSection(cs);
}

static void InitCritsecFix() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { Log("InitCritsecFix: ntdll not loaded"); return; }
    g_pRtlInitializeCriticalSection =
        (RtlInitializeCriticalSection_t)GetProcAddress(hNtdll, "RtlInitializeCriticalSection");
    PVOID pEnter = GetProcAddress(hNtdll, "RtlEnterCriticalSection");
    char buf[200];
    if (!pEnter || !g_pRtlInitializeCriticalSection) {
        Log("InitCritsecFix: RtlEnterCriticalSection/RtlInitializeCriticalSection NOT found");
        return;
    }
    MH_STATUS s = MH_CreateHook(pEnter, (LPVOID)&HookedRtlEnterCriticalSection,
                                (LPVOID*)&g_origRtlEnterCriticalSection);
    if (s != MH_OK) { wsprintfA(buf, "InitCritsecFix: MH_CreateHook status=%d", s); Log(buf); return; }
    s = MH_EnableHook(pEnter);
    if (s != MH_OK) { wsprintfA(buf, "InitCritsecFix: MH_EnableHook status=%d", s); Log(buf); return; }
    wsprintfA(buf, "InitCritsecFix: RtlEnterCriticalSection hooked at 0x%p (auto-init zeroed critsecs)", pEnter);
    Log(buf);
}

// ============================================================================
// FAZ31: file-open LOGGING (diagnostic only). Goal: determine whether the game
// ever tries to open the Translations package / UIString files during loading,
// and with what name / success. The localization map<int,wstring> at
// [[0x12baa04]+0x20]+0x528 is empty (size 0) in every loading-phase crash dump,
// so the UIString translation is never loaded. This hook tells us if the game
// even ATTEMPTS the open. CreateFileA forwards to CreateFileW inside kernel32,
// so hooking W catches both. No game code is touched.
// ============================================================================
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileW_t g_origCreateFileW = NULL;

// case-insensitive: does wide haystack contain ascii needle (lowercase)?
static bool WideContainsAsciiI(LPCWSTR hay, const char* needle) {
    if (!hay) return false;
    for (const wchar_t* p = hay; *p; ++p) {
        const wchar_t* h = p; const char* n = needle;
        while (*n) {
            wchar_t a = *h;
            if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
            if (a != (wchar_t)(unsigned char)*n) break;
            ++h; ++n;
        }
        if (!*n) return true;
    }
    return false;
}

static HANDLE WINAPI HookedCreateFileW(LPCWSTR name, DWORD access, DWORD share,
        LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    HANDLE h = g_origCreateFileW(name, access, share, sa, disp, flags, tmpl);
    __try {
        if (name && (WideContainsAsciiI(name, "translation") ||
                     WideContainsAsciiI(name, ".vl") ||
                     WideContainsAsciiI(name, "uistring") ||
                     WideContainsAsciiI(name, "binarycache") ||
                     WideContainsAsciiI(name, "\\ui\\") ||
                     WideContainsAsciiI(name, "/ui/") ||
                     WideContainsAsciiI(name, ".swf") ||
                     WideContainsAsciiI(name, "ui_common") ||
                     WideContainsAsciiI(name, "ui_local") ||
                     WideContainsAsciiI(name, "fonts_tr") ||
                     WideContainsAsciiI(name, "messenger") ||
                     WideContainsAsciiI(name, "login.swf"))) {
            char buf[600]; char ascii[512]; int i = 0;
            for (; name[i] && i < 511; ++i) ascii[i] = (name[i] < 128) ? (char)name[i] : '?';
            ascii[i] = 0;
            wsprintfA(buf, "[FILELOG] CreateFileW(%s) -> %s", ascii,
                      (h == INVALID_HANDLE_VALUE) ? "FAIL(INVALID_HANDLE)" : "OK");
            Log(buf);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return h;
}

// Install the file-open logging hook. Called from PatchThread.
static void InitFileLogHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) { Log("InitFileLogHooks: kernel32 not loaded"); return; }
    PVOID fn = GetProcAddress(hKernel, "CreateFileW");
    char buf[200];
    if (!fn) { Log("InitFileLogHooks: GetProcAddress(CreateFileW) FAILED"); return; }
    MH_STATUS s = MH_CreateHook(fn, (LPVOID)&HookedCreateFileW, (LPVOID*)&g_origCreateFileW);
    if (s != MH_OK) { wsprintfA(buf, "InitFileLogHooks: MH_CreateHook status=%d", s); Log(buf); return; }
    s = MH_EnableHook(fn);
    if (s != MH_OK) { wsprintfA(buf, "InitFileLogHooks: MH_EnableHook status=%d", s); Log(buf); return; }
    wsprintfA(buf, "InitFileLogHooks: CreateFileW hooked at 0x%p", fn);
    Log(buf);
}

// ============================================================================
// FAZ47: global MessageBoxW/A hook (thread-INDEPENDENT, unlike the CALL-site
// HW-BP which is per-thread). The "GameGuard Error" dialog (0xd35557) is raised
// from a PERIODIC GG watchdog ~15s in, on a thread whose DR regs are not armed,
// so the ggr-force at 0xD35379 misses it. We intercept the MessageBox itself:
// log the LIVE GG status (ctx=*[0x12b22c8], [ctx+0x10]) + caption/text to learn
// why 0x8e3550 returned !=0x755 despite faz45, then suppress the (modal) dialog
// and return IDOK so the caller is not blocked.
// ============================================================================
typedef int (WINAPI *MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
static MessageBoxW_t g_origMessageBoxW = NULL;
static MessageBoxA_t g_origMessageBoxA = NULL;

static void LogMbGGStatus(const char* api, const char* cap, const char* txt) {
    DWORD ctx = 0, status = 0xDEADBEEF;
    __try {
        ctx = *(volatile DWORD*)0x12B22C8;
        if (ctx) status = *(DWORD*)(ctx + 0x10);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    char buf[420];
    wsprintfA(buf, "FAZ47: %s SUPPRESSED caption='%s' text='%s' ctx=0x%X [ctx+0x10]=0x%X -> IDOK",
              api, cap, txt, ctx, status);
    Log(buf);
}

static int WINAPI HookedMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    __try {
        if (WideContainsAsciiI(lpCaption, "gameguard") || WideContainsAsciiI(lpText, "gameguard")) {
            char cap[128]; int i = 0;
            if (lpCaption) for (; lpCaption[i] && i < 127; ++i) cap[i] = (lpCaption[i] < 128) ? (char)lpCaption[i] : '?';
            cap[i] = 0;
            char txt[160]; int j = 0;
            if (lpText) for (; lpText[j] && j < 159; ++j) txt[j] = (lpText[j] < 128) ? (char)lpText[j] : '?';
            txt[j] = 0;
            LogMbGGStatus("MessageBoxW", cap, txt);
            return 1;  // IDOK, do not show
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return g_origMessageBoxW(hWnd, lpText, lpCaption, uType);
}

// case-insensitive: does ascii haystack contain ascii needle (lowercase)?
static bool AsciiContainsI(const char* hay, const char* needle) {
    if (!hay) return false;
    for (const char* p = hay; *p; ++p) {
        const char* h = p; const char* n = needle;
        while (*n) {
            char a = *h; if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (a != *n) break;
            ++h; ++n;
        }
        if (!*n) return true;
    }
    return false;
}

static int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    __try {
        if (AsciiContainsI(lpCaption, "gameguard") || AsciiContainsI(lpText, "gameguard")) {
            LogMbGGStatus("MessageBoxA", lpCaption ? lpCaption : "", lpText ? lpText : "");
            return 1;  // IDOK
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return g_origMessageBoxA(hWnd, lpText, lpCaption, uType);
}

static void InitMessageBoxHook() {
    HMODULE hUser = LoadLibraryA("user32.dll");
    char buf[200];
    if (!hUser) { Log("InitMessageBoxHook: user32 not loaded"); return; }
    PVOID fnW = GetProcAddress(hUser, "MessageBoxW");
    PVOID fnA = GetProcAddress(hUser, "MessageBoxA");
    if (fnW) {
        MH_STATUS s = MH_CreateHook(fnW, (LPVOID)&HookedMessageBoxW, (LPVOID*)&g_origMessageBoxW);
        if (s == MH_OK) s = MH_EnableHook(fnW);
        wsprintfA(buf, "InitMessageBoxHook: MessageBoxW @0x%p status=%d", fnW, s); Log(buf);
    }
    if (fnA) {
        MH_STATUS s = MH_CreateHook(fnA, (LPVOID)&HookedMessageBoxA, (LPVOID*)&g_origMessageBoxA);
        if (s == MH_OK) s = MH_EnableHook(fnA);
        wsprintfA(buf, "InitMessageBoxHook: MessageBoxA @0x%p status=%d", fnA, s); Log(buf);
    }
}

// ============================================================================
// FAZ58: Winsock send trace (log-only)
// ============================================================================
//
// Login click now reaches the correct Goley login screen, connects to our local
// TCP8000 logger, and sends a stable 28-byte packet before Error 93. Server-side
// ProudNet/WebGL startup probes did not match native TCP framing, so stop
// guessing the response and identify the exact native call site that emits the
// 28-byte packet. This hook does not alter network behavior; it only logs the
// caller return address + first bytes for small outbound sends.
typedef UINT_PTR SOCKET_COMPAT;
typedef struct _WSABUF_COMPAT {
    ULONG len;
    CHAR* buf;
} WSABUF_COMPAT, *LPWSABUF_COMPAT;
typedef OVERLAPPED* LPWSAOVERLAPPED_COMPAT;
typedef void (CALLBACK *LPWSAOVERLAPPED_COMPLETION_ROUTINE_COMPAT)(
    DWORD, DWORD, LPWSAOVERLAPPED_COMPAT, DWORD);

typedef int (WINAPI *send_t)(SOCKET_COMPAT, const char*, int, int);
typedef int (WINAPI *WSASend_t)(SOCKET_COMPAT, LPWSABUF_COMPAT, DWORD, LPDWORD,
                                DWORD, LPWSAOVERLAPPED_COMPAT,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE_COMPAT);
typedef int (WINAPI *recv_t)(SOCKET_COMPAT, char*, int, int);
typedef int (WINAPI *WSARecv_t)(SOCKET_COMPAT, LPWSABUF_COMPAT, DWORD, LPDWORD,
                                LPDWORD, LPWSAOVERLAPPED_COMPAT,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE_COMPAT);
static send_t    g_origSend    = NULL;
static WSASend_t g_origWSASend = NULL;
static recv_t    g_origRecv    = NULL;
static WSARecv_t g_origWSARecv = NULL;
static volatile LONG g_netLogCount = 0;

static void BuildTinyBacktrace(char* out, int cap) {
    out[0] = 0;
    DWORD* fp = NULL;
#if defined(_M_IX86)
    __asm { mov fp, ebp }
#endif
    int pos = 0;
    for (int i = 0; i < 10 && fp && pos < cap - 24; ++i) {
        DWORD next = 0, ret = 0;
        __try {
            next = fp[0];
            ret = fp[1];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        if (!ret) break;

        DWORD rva = 0;
        if (g_imageBase && ret >= (DWORD)(ULONG_PTR)g_imageBase) {
            rva = ret - (DWORD)(ULONG_PTR)g_imageBase;
        }
        char item[36];
        wsprintfA(item, "%s0x%X", (i == 0) ? "" : ">", rva ? rva : ret);
        lstrcpynA(out + pos, item, cap - pos);
        pos += lstrlenA(out + pos);

        if (next <= (DWORD)(ULONG_PTR)fp || next - (DWORD)(ULONG_PTR)fp > 0x100000) break;
        fp = (DWORD*)next;
    }
}

static void LogNetBytes(const char* api, void* ra, const BYTE* data, int len) {
    if (!data || len <= 0) return;
    BOOL magic28 = FALSE;
    __try {
        magic28 = (len == 28) ||
                  (len >= 4 && data[0] == 0x32 && data[1] == 0x18 &&
                   data[2] == 0x00 && data[3] == 0x00);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    LONG n = InterlockedIncrement(&g_netLogCount);
    if (!magic28 && (n > 80 || len > 512)) return;
    if (!EnterHook()) return;

    __try {
        char hex[3 * 80 + 1];
        int max = len;
        if (max > 80) max = 80;
        int pos = 0;
        static const char* digs = "0123456789abcdef";
        for (int i = 0; i < max && pos < (int)sizeof(hex) - 4; ++i) {
            BYTE b = data[i];
            hex[pos++] = digs[(b >> 4) & 0xF];
            hex[pos++] = digs[b & 0xF];
            hex[pos++] = ' ';
        }
        hex[pos] = 0;

        DWORD rva = 0;
        if (g_imageBase && (DWORD)(ULONG_PTR)ra >= (DWORD)(ULONG_PTR)g_imageBase) {
            rva = (DWORD)(ULONG_PTR)ra - (DWORD)(ULONG_PTR)g_imageBase;
        }

        char bt[260];
        BuildTinyBacktrace(bt, sizeof(bt));

        char buf[900];
        wsprintfA(buf, "[NETLOG%s] %s len=%d caller=0x%p rva=0x%X bt=%s bytes=%s",
                  magic28 ? "/LOGIN28" : "", api, len, ra, rva, bt, hex);
        Log(buf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[NETLOG] exception while formatting bytes");
    }
    LeaveHook();
}

static int WINAPI HookedSend(SOCKET_COMPAT s, const char* buf, int len, int flags) {
    LogNetBytes("send", _ReturnAddress(), (const BYTE*)buf, len);
    return g_origSend(s, buf, len, flags);
}

static int WINAPI HookedWSASend(SOCKET_COMPAT s, LPWSABUF_COMPAT bufs, DWORD count,
                                LPDWORD sent, DWORD flags,
                                LPWSAOVERLAPPED_COMPAT ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE_COMPAT cb) {
    DWORD cap = count;
    if (cap > 8) cap = 8;
    __try {
        for (DWORD i = 0; bufs && i < cap; ++i) {
            char api[32];
            wsprintfA(api, "WSASend[%lu]", i);
            LogNetBytes(api, _ReturnAddress(), (const BYTE*)bufs[i].buf, (int)bufs[i].len);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return g_origWSASend(s, bufs, count, sent, flags, ov, cb);
}

static int WINAPI HookedRecv(SOCKET_COMPAT s, char* buf, int len, int flags) {
    int r = g_origRecv(s, buf, len, flags);
    if (r > 0) LogNetBytes("recv", _ReturnAddress(), (const BYTE*)buf, r);
    return r;
}

static int WINAPI HookedWSARecv(SOCKET_COMPAT s, LPWSABUF_COMPAT bufs, DWORD count,
                                LPDWORD recvd, LPDWORD flags,
                                LPWSAOVERLAPPED_COMPAT ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE_COMPAT cb) {
    int r = g_origWSARecv(s, bufs, count, recvd, flags, ov, cb);
    DWORD got = recvd ? *recvd : 0;
    if (r == 0 && got > 0 && bufs && count > 0) {
        DWORD left = got;
        DWORD cap = count;
        if (cap > 8) cap = 8;
        for (DWORD i = 0; i < cap && left > 0; ++i) {
            DWORD n = bufs[i].len;
            if (n > left) n = left;
            char api[32];
            wsprintfA(api, "WSARecv[%lu]", i);
            LogNetBytes(api, _ReturnAddress(), (const BYTE*)bufs[i].buf, (int)n);
            left -= n;
        }
    }
    return r;
}

static void InitWinsockLogHooks() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");
    char buf[220];
    if (!hWs2) { Log("InitWinsockLogHooks: ws2_32 not loaded"); return; }

    PVOID pSend = GetProcAddress(hWs2, "send");
    if (pSend) {
        MH_STATUS s = MH_CreateHook(pSend, (LPVOID)&HookedSend, (LPVOID*)&g_origSend);
        if (s == MH_OK) s = MH_EnableHook(pSend);
        wsprintfA(buf, "InitWinsockLogHooks: send @0x%p status=%d", pSend, s);
        Log(buf);
    } else {
        Log("InitWinsockLogHooks: GetProcAddress(send) FAILED");
    }

    PVOID pWSASend = GetProcAddress(hWs2, "WSASend");
    if (pWSASend) {
        MH_STATUS s = MH_CreateHook(pWSASend, (LPVOID)&HookedWSASend, (LPVOID*)&g_origWSASend);
        if (s == MH_OK) s = MH_EnableHook(pWSASend);
        wsprintfA(buf, "InitWinsockLogHooks: WSASend @0x%p status=%d", pWSASend, s);
        Log(buf);
    } else {
        Log("InitWinsockLogHooks: GetProcAddress(WSASend) FAILED");
    }

    PVOID pRecv = GetProcAddress(hWs2, "recv");
    if (pRecv) {
        MH_STATUS s = MH_CreateHook(pRecv, (LPVOID)&HookedRecv, (LPVOID*)&g_origRecv);
        if (s == MH_OK) s = MH_EnableHook(pRecv);
        wsprintfA(buf, "InitWinsockLogHooks: recv @0x%p status=%d", pRecv, s);
        Log(buf);
    } else {
        Log("InitWinsockLogHooks: GetProcAddress(recv) FAILED");
    }

    PVOID pWSARecv = GetProcAddress(hWs2, "WSARecv");
    if (pWSARecv) {
        MH_STATUS s = MH_CreateHook(pWSARecv, (LPVOID)&HookedWSARecv, (LPVOID*)&g_origWSARecv);
        if (s == MH_OK) s = MH_EnableHook(pWSARecv);
        wsprintfA(buf, "InitWinsockLogHooks: WSARecv @0x%p status=%d", pWSARecv, s);
        Log(buf);
    } else {
        Log("InitWinsockLogHooks: GetProcAddress(WSARecv) FAILED");
    }
}

// ============================================================================
// FAZ59: ProudNet native outbound codec trace (log-only)
// ============================================================================
//
// The 28-byte login packet is not plaintext. Static disassembly shows the send
// wrapper calls 0xA69F20 before emitting the final [0x32][u16 len][ch][payload]
// frame:
//   __stdcall Encode(keyCtx, channel, outBuf, outCap, plainPtr, plainLen)
//
// Hooking here gives us the payload before the old ProudNet obfuscation layer.
typedef BOOL (__stdcall *ProudEncode_t)(void* keyCtx, BYTE channel, BYTE* outBuf,
                                        int outCap, const BYTE* plain, int plainLen);
static ProudEncode_t g_origProudEncode = NULL;
static volatile LONG g_codecLogCount = 0;
typedef int (__stdcall *ProudRawSendEntry_t)(const BYTE* payload, int len);
static ProudRawSendEntry_t g_origProudRawSendEntry = NULL;
typedef int (__stdcall *ProudSendWrapper_t)(void* netObj, int slot, const BYTE* payload, int len);
static ProudSendWrapper_t g_origProudSendWrapper = NULL;
static volatile LONG g_rawEntryLogCount = 0;
static volatile LONG g_sendWrapperLogCount = 0;
static volatile LONG g_forcedConnectSuccess = 0;
static volatile LONG g_requestLoginObserved = 0;
static volatile DWORD g_requestLoginTick = 0;
static volatile LONG g_forcedLobbyPane = 0;
static volatile LONG g_error93LatchLogged = 0;
static volatile DWORD g_lastLobbyNetStateLog = 0;
static const BOOL FORCE_LOCAL_CONNECT_SUCCESS = TRUE;
static const BOOL ENABLE_PROUD_CODEC_DIAG = FALSE;
static const BOOL FORCE_ERROR93_ONCE_LATCH = TRUE;
static const BOOL ENABLE_POSTREADY_THREAD_DUMPS = FALSE;
// FAZ70: keep the stable FAZ66 login path clean. The FAZ67-69 Viz hooks/scanner
// were useful diagnostics, but one run lost the PNRAW path and crashed before
// RequestLogin. Disable them while we work from the known-good capture point.
static const BOOL ENABLE_VIZ_LOGIN_DIAG = FALSE;
static volatile LONG g_vizCtorLogCount = 0;
static volatile LONG g_vizDispatcherLogCount = 0;
static void* g_lastVizClientObj = NULL;
static void ScanVizClientObjects();

static void FormatHexPrefix(const BYTE* data, int len, char* out, int outCap) {
    out[0] = 0;
    if (!data || len <= 0 || outCap <= 4) return;
    int max = len;
    if (max > 96) max = 96;
    int pos = 0;
    static const char* digs = "0123456789abcdef";
    __try {
        for (int i = 0; i < max && pos < outCap - 4; ++i) {
            BYTE b = data[i];
            out[pos++] = digs[(b >> 4) & 0xF];
            out[pos++] = digs[b & 0xF];
            out[pos++] = ' ';
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        return;
    }
    out[pos] = 0;
}

static void LogCodecBytes(const char* tag, void* keyCtx, BYTE channel,
                          const BYTE* data, int len, int capOrLen) {
    if (!data || len <= 0) return;
    LONG n = InterlockedIncrement(&g_codecLogCount);
    if (n > 120 || len > 512) return;
    if (!EnterHook()) return;
    __try {
        char hex[3 * 96 + 1];
        FormatHexPrefix(data, len, hex, sizeof(hex));
        char buf[700];
        wsprintfA(buf, "[PNCODEC/%s] key=0x%p ch=%u len=%d cap=%d bytes=%s",
                  tag, keyCtx, (unsigned)channel, len, capOrLen, hex);
        Log(buf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[PNCODEC] exception while formatting bytes");
    }
    LeaveHook();
}

static BOOL __stdcall HookedProudEncode(void* keyCtx, BYTE channel, BYTE* outBuf,
                                        int outCap, const BYTE* plain, int plainLen) {
    LogCodecBytes("IN", keyCtx, channel, plain, plainLen, outCap);
    BOOL ok = g_origProudEncode(keyCtx, channel, outBuf, outCap, plain, plainLen);
    if (ok) {
        LogCodecBytes("OUT", keyCtx, channel, outBuf, outCap, outCap);
    } else if (EnterHook()) {
        Log("[PNCODEC/OUT] encode returned FALSE");
        LeaveHook();
    }
    return ok;
}

static void InitProudNetCodecHooks() {
    if (!g_imageBase) { Log("InitProudNetCodecHooks: image base missing"); return; }
    PVOID pEncode = (PVOID)(g_imageBase + 0x669F20); // VA 0xA69F20 in unpacked BinaryTr
    MH_STATUS s = MH_CreateHook(pEncode, (LPVOID)&HookedProudEncode,
                                (LPVOID*)&g_origProudEncode);
    if (s == MH_OK) s = MH_EnableHook(pEncode);
    char buf[220];
    wsprintfA(buf, "InitProudNetCodecHooks: encode 0xA69F20 @0x%p status=%d", pEncode, s);
    Log(buf);
}

static void __stdcall ProudRawSendEntryProbe(const BYTE* payload, int len,
                                             DWORD esiVal, DWORD ediVal, void* ra) {
    LONG n = InterlockedIncrement(&g_rawEntryLogCount);
    if (n <= 80 && payload && len > 0 && len <= 512 && EnterHook()) {
        __try {
            char hex[3 * 96 + 1];
            FormatHexPrefix(payload, len, hex, sizeof(hex));
            DWORD rva = 0;
            if (g_imageBase && (DWORD)(ULONG_PTR)ra >= (DWORD)(ULONG_PTR)g_imageBase) {
                rva = (DWORD)(ULONG_PTR)ra - (DWORD)(ULONG_PTR)g_imageBase;
            }
            char buf[760];
            wsprintfA(buf, "[PNRAW] caller=0x%p rva=0x%X esi=0x%08X edi=0x%08X len=%d bytes=%s",
                      ra, rva, esiVal, ediVal, len, hex);
            Log(buf);
            if (len == 246 && InterlockedCompareExchange(&g_requestLoginObserved, 1, 0) == 0) {
                g_requestLoginTick = GetTickCount();
                Log("FAZ73: observed RequestLogin raw payload; lobby shortcut timer armed");
            }
            if (len >= 16) {
                char path[MAX_PATH];
                wsprintfA(path, "C:\\Joygame\\goley-rev\\dumps\\pnraw_%lu_%03ld_rva_%X_len_%d.bin",
                          GetCurrentProcessId(), n, rva, len);
                HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD wrote = 0;
                    WriteFile(h, payload, (DWORD)len, &wrote, NULL);
                    CloseHandle(h);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[PNRAW] exception while formatting bytes");
        }
        LeaveHook();
    }

}

struct SmallStdStringA {
    char text[16];
    DWORD size;
    DWORD cap;
};

static BOOL ForceLoadPaneByName(const char* paneName, const char* tag) {
    DWORD app = 0;
    DWORD uiRoot = 0;
    DWORD fn = (DWORD)(g_imageBase + 0x85EB00); // 0xC5EB00 pane load helper
    DWORD zBits = *(DWORD*)(g_imageBase + 0xC47AA8); // 0x1047AA8, common z/order float
    DWORD ret = 0;
    SmallStdStringA s;
    ZeroMemory(&s, sizeof(s));
    lstrcpynA(s.text, paneName, sizeof(s.text));
    s.size = lstrlenA(s.text);
    s.cap = 0x0F;

    __try {
        app = *(volatile DWORD*)0x12BAA04;
        if (!app) return FALSE;
        uiRoot = *(volatile DWORD*)(app + 0x08);
        if (!uiRoot) return FALSE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (EnterHook()) {
        char buf[220];
        wsprintfA(buf, "FAZ73: force-load pane '%s' via 0xC5EB00 appUI=0x%08X tag=%s",
                  paneName, uiRoot, tag ? tag : "");
        Log(buf);
        LeaveHook();
    }

#if defined(_M_IX86)
    __try {
        __asm {
            push edi
            lea edi, s
            push zBits
            push uiRoot
            call fn
            movzx eax, al
            mov ret, eax
            pop edi
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (EnterHook()) { Log("FAZ73: exception while force-loading pane"); LeaveHook(); }
        return FALSE;
    }
#endif

    if (EnterHook()) {
        char buf[160];
        wsprintfA(buf, "FAZ73: force-load pane result=%lu", ret);
        Log(buf);
        LeaveHook();
    }
    return ret != 0;
}

static DWORD QueryProudConnectionState(DWORD proudClientObj) {
    DWORD fn = (DWORD)(g_imageBase + 0x668460); // 0xA68460, returns current ProudNet state-ish value
    DWORD ret = 0xFFFFFFFF;
    if (!proudClientObj || !g_imageBase) return ret;
#if defined(_M_IX86)
    __try {
        __asm {
            mov eax, proudClientObj
            call fn
            mov ret, eax
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ret = 0xFFFFFFFE;
    }
#endif
    return ret;
}

static void LogLobbyNetStateIfDue(const char* tag) {
    DWORD now = GetTickCount();
    if (g_lastLobbyNetStateLog && (now - g_lastLobbyNetStateLog) < 3000) return;
    g_lastLobbyNetStateLog = now;

    DWORD app = 0, netObj = 0, proudClient = 0, netIface = 0;
    DWORD state = 0xFFFFFFFF;
    BYTE b200c = 0, b200d = 0, b2111 = 0, b211d = 0, iface71 = 0xFF;
    __try {
        app = *(volatile DWORD*)0x12BAA04;
        if (app) netObj = *(volatile DWORD*)(app + 0x28);
        if (netObj) {
            proudClient = *(volatile DWORD*)netObj;
            netIface = *(volatile DWORD*)(netObj + 4);
            b200c = *(volatile BYTE*)(netObj + 0x200C);
            b200d = *(volatile BYTE*)(netObj + 0x200D);
            b2111 = *(volatile BYTE*)(netObj + 0x2111);
            b211d = *(volatile BYTE*)(netObj + 0x211D);
            if (netIface) iface71 = *(volatile BYTE*)(netIface + 0x71);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
    state = QueryProudConnectionState(proudClient);

    if (EnterHook()) {
        char buf[320];
        wsprintfA(buf,
                  "FAZ74: lobby net state tag=%s app=0x%08X net=0x%08X proud=0x%08X iface=0x%08X state=%lu b200c=%u b200d=%u b2111=%u b211d=%u iface+71=%u err93Latch=%u",
                  tag ? tag : "", app, netObj, proudClient, netIface, state,
                  b200c, b200d, b2111, b211d, iface71, *(volatile BYTE*)0x12BF14C);
        Log(buf);
        LeaveHook();
    }
}

static void PinError93LatchAfterLogin() {
    if (!FORCE_ERROR93_ONCE_LATCH || !g_requestLoginObserved) return;
    __try {
        volatile BYTE* pShown = (volatile BYTE*)0x12BF14C;
        if (*pShown == 0) {
            *pShown = 1;
            if (InterlockedCompareExchange(&g_error93LatchLogged, 1, 0) == 0 && EnterHook()) {
                Log("FAZ74: pre-armed Error93 once-latch [0x12bf14c]=1 after RequestLogin");
                LeaveHook();
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    LogLobbyNetStateIfDue("post-requestlogin");
}

static void __stdcall ProudRawSendEntryForceAfterOriginal(const BYTE* payload, int len,
                                                          DWORD esiVal, DWORD ediVal) {
    BOOL looksLikeConnectRequest = FALSE;
    __try {
        looksLikeConnectRequest =
            (len == 16 && payload &&
             ((DWORD*)payload)[0] == 0 &&
             ((DWORD*)payload)[1] == 3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (FORCE_LOCAL_CONNECT_SUCCESS && looksLikeConnectRequest &&
        InterlockedCompareExchange(&g_forcedConnectSuccess, 1, 0) == 0) {
        BYTE pkt[32];
        ZeroMemory(pkt, sizeof(pkt));
        pkt[5] = 0; // key table index used by 0xA68560
        CopyMemory(pkt + 0x0C, "0123456789", 10); // accepted by 0xA684C0
        DWORD fn = (DWORD)(g_imageBase + 0x673CA0); // 0xA73CA0 post-connect handler
        DWORD wrapper = ediVal;
        DWORD pktPtr = (DWORD)(ULONG_PTR)pkt;
        if (EnterHook()) {
            char buf[220];
            wsprintfA(buf, "[PNRAW/FORCE2] invoking local connect-success handler AFTER original hello wrapper=0x%08X esi=0x%08X",
                      wrapper, esiVal);
            Log(buf);
            LeaveHook();
        }
#if defined(_M_IX86)
        __try {
            __asm {
                mov eax, pktPtr
                push wrapper
                call fn
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (EnterHook()) { Log("[PNRAW/FORCE2] exception while invoking 0xA73CA0"); LeaveHook(); }
        }
#endif
    }
}

#if defined(_M_IX86)
static __declspec(naked) int HookedProudRawSendEntryNaked() {
    __asm {
        pushfd
        pushad

        mov eax, [esp+40]   // original arg1: payload
        mov ecx, [esp+44]   // original arg2: len
        mov edx, [esp+4]    // saved original ESI
        mov ebx, [esp]      // saved original EDI
        mov ebp, [esp+36]   // original return address

        push ebp
        push ebx
        push edx
        push ecx
        push eax
        call ProudRawSendEntryProbe

        popad
        popfd

        mov eax, [esp+4]        // payload
        mov ecx, [esp+8]        // len
        push ecx
        push eax
        call dword ptr [g_origProudRawSendEntry]

        push eax                // preserve original return value
        pushfd
        pushad

        mov eax, [esp+44]       // original arg1: payload
        mov ecx, [esp+48]       // original arg2: len
        mov edx, [esp+4]        // saved ESI after original
        mov ebx, [esp]          // saved EDI after original (wrapper; callee-preserved)

        push ebx
        push edx
        push ecx
        push eax
        call ProudRawSendEntryForceAfterOriginal

        popad
        popfd
        pop eax
        ret 8
    }
}
#endif

static int __stdcall HookedProudRawSendEntry(const BYTE* payload, int len) {
    DWORD esiVal = 0;
    DWORD ediVal = 0;
#if defined(_M_IX86)
    __asm { mov esiVal, esi }
    __asm { mov ediVal, edi }
#endif
    LONG n = InterlockedIncrement(&g_rawEntryLogCount);
    if (n <= 80 && payload && len > 0 && len <= 512 && EnterHook()) {
        __try {
            char hex[3 * 96 + 1];
            FormatHexPrefix(payload, len, hex, sizeof(hex));
            void* ra = _ReturnAddress();
            DWORD rva = 0;
            if (g_imageBase && (DWORD)(ULONG_PTR)ra >= (DWORD)(ULONG_PTR)g_imageBase) {
                rva = (DWORD)(ULONG_PTR)ra - (DWORD)(ULONG_PTR)g_imageBase;
            }
            char buf[760];
            wsprintfA(buf, "[PNRAW] caller=0x%p rva=0x%X esi=0x%08X edi=0x%08X len=%d bytes=%s",
                      ra, rva, esiVal, ediVal, len, hex);
            Log(buf);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[PNRAW] exception while formatting bytes");
        }
        LeaveHook();
    }

#if defined(_M_IX86)
    __asm { mov esi, esiVal }
    __asm { mov edi, ediVal }
#endif
    int ret = g_origProudRawSendEntry(payload, len);

    BOOL looksLikeConnectRequest = FALSE;
    __try {
        looksLikeConnectRequest =
            (len == 16 && payload &&
             ((DWORD*)payload)[0] == 0 &&
             ((DWORD*)payload)[1] == 3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (FORCE_LOCAL_CONNECT_SUCCESS && looksLikeConnectRequest &&
        InterlockedCompareExchange(&g_forcedConnectSuccess, 1, 0) == 0) {
        BYTE pkt[32];
        ZeroMemory(pkt, sizeof(pkt));
        pkt[5] = 0; // key table index used by 0xA68560
        CopyMemory(pkt + 0x0C, "0123456789", 10); // accepted by 0xA684C0
        DWORD fn = (DWORD)(g_imageBase + 0x673CA0); // 0xA73CA0 post-connect handler
        DWORD wrapper = ediVal;
        DWORD pktPtr = (DWORD)(ULONG_PTR)pkt;
        if (EnterHook()) {
            char buf[220];
            wsprintfA(buf, "[PNRAW/FORCE] invoking local connect-success handler 0xA73CA0 wrapper=0x%08X", wrapper);
            Log(buf);
            LeaveHook();
        }
#if defined(_M_IX86)
        __try {
            __asm {
                mov eax, pktPtr
                push wrapper
                call fn
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (EnterHook()) { Log("[PNRAW/FORCE] exception while invoking 0xA73CA0"); LeaveHook(); }
        }
#endif
    }

    return ret;
}

static int __stdcall HookedProudSendWrapper(void* netObj, int slot, const BYTE* payload, int len) {
    LONG n = InterlockedIncrement(&g_sendWrapperLogCount);
    if (n <= 120 && payload && len > 0 && len <= 512 && EnterHook()) {
        __try {
            char hex[3 * 96 + 1];
            FormatHexPrefix(payload, len, hex, sizeof(hex));
            void* ra = _ReturnAddress();
            DWORD rva = 0;
            if (g_imageBase && (DWORD)(ULONG_PTR)ra >= (DWORD)(ULONG_PTR)g_imageBase) {
                rva = (DWORD)(ULONG_PTR)ra - (DWORD)(ULONG_PTR)g_imageBase;
            }
            DWORD esiVal = 0;
            DWORD ediVal = 0;
#if defined(_M_IX86)
            __asm { mov esiVal, esi }
            __asm { mov ediVal, edi }
#endif
            char buf[760];
            wsprintfA(buf, "[PNSENDWRAP] caller=0x%p rva=0x%X net=0x%p slot=%d esi=0x%08X edi=0x%08X len=%d bytes=%s",
                      ra, rva, netObj, slot, esiVal, ediVal, len, hex);
            Log(buf);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[PNSENDWRAP] exception while formatting bytes");
        }
        LeaveHook();
    }
    return g_origProudSendWrapper(netObj, slot, payload, len);
}

static void InitProudNetRawSendHook() {
    if (!g_imageBase) { Log("InitProudNetRawSendHook: image base missing"); return; }
    PVOID pRaw = (PVOID)(g_imageBase + 0x669940); // VA 0xA69940 common generated-RMI send entry
#if defined(_M_IX86)
    MH_STATUS s = MH_CreateHook(pRaw, (LPVOID)&HookedProudRawSendEntryNaked,
                                (LPVOID*)&g_origProudRawSendEntry);
#else
    MH_STATUS s = MH_CreateHook(pRaw, (LPVOID)&HookedProudRawSendEntry,
                                (LPVOID*)&g_origProudRawSendEntry);
#endif
    if (s == MH_OK) s = MH_EnableHook(pRaw);
    char buf[220];
    wsprintfA(buf, "InitProudNetRawSendHook: raw-entry 0xA69940 @0x%p status=%d", pRaw, s);
    Log(buf);

    PVOID pSendWrapper = (PVOID)(g_imageBase + 0x669790); // VA 0xA69790 lower outbound send wrapper
    s = MH_CreateHook(pSendWrapper, (LPVOID)&HookedProudSendWrapper,
                      (LPVOID*)&g_origProudSendWrapper);
    if (s == MH_OK) s = MH_EnableHook(pSendWrapper);
    wsprintfA(buf, "InitProudNetRawSendHook: send-wrapper 0xA69790 @0x%p status=%d", pSendWrapper, s);
    Log(buf);
}

// ============================================================================
// FAZ67: capture Goley Viz/S2C dispatcher object for NotifyLoginOk experiments
// ============================================================================
typedef void* (__thiscall *VizClientCtor_t)(void* self, void* a1, void* a2, void* a3, void* a4);
static VizClientCtor_t g_origVizClientCtor = NULL;
typedef BOOL (__thiscall *VizS2CDispatcher_t)(void* self, void* msg, int hostOrContext);
static VizS2CDispatcher_t g_origVizS2CDispatcher = NULL;

static void LogVizObj(const char* tag, void* self) {
    if (!self || !EnterHook()) return;
    __try {
        DWORD* p = (DWORD*)self;
        char buf[520];
        wsprintfA(buf, "[VIZ/%s] self=0x%p vt=0x%08X field8=0x%08X f18=0x%08X f20=0x%08X f24=0x%08X f28=0x%08X f2c=0x%08X f30=0x%08X",
                  tag, self, p[0], p[2], p[6], p[8], p[9], p[10], p[11], p[12]);
        Log(buf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[VIZ] exception while logging object");
    }
    LeaveHook();
}

static void* __fastcall HookedVizClientCtor(void* self, void* edx, void* a1, void* a2, void* a3, void* a4) {
    void* ret = g_origVizClientCtor(self, a1, a2, a3, a4);
    g_lastVizClientObj = self;
    LONG n = InterlockedIncrement(&g_vizCtorLogCount);
    if (n <= 8) {
        if (EnterHook()) {
            char buf[260];
            wsprintfA(buf, "[VIZ/CTOR] self=0x%p ret=0x%p a1=0x%p a2=0x%p a3=0x%p a4=0x%p", self, ret, a1, a2, a3, a4);
            Log(buf);
            LeaveHook();
        }
        LogVizObj("CTOROBJ", self);
    }
    return ret;
}

static BOOL __fastcall HookedVizS2CDispatcher(void* self, void* edx, void* msg, int hostOrContext) {
    LONG n = InterlockedIncrement(&g_vizDispatcherLogCount);
    if (n <= 20 && EnterHook()) {
        __try {
            char buf[360];
            wsprintfA(buf, "[VIZ/DISPATCH] self=0x%p msg=0x%p host=0x%08X lastObj=0x%p", self, msg, hostOrContext, g_lastVizClientObj);
            Log(buf);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[VIZ/DISPATCH] exception while logging");
        }
        LeaveHook();
    }
    return g_origVizS2CDispatcher(self, msg, hostOrContext);
}

static void InitVizLoginHooks() {
    if (!g_imageBase) { Log("InitVizLoginHooks: image base missing"); return; }
    char buf[240];

    PVOID pCtor = (PVOID)(g_imageBase + 0x178500); // VA 0x578500 Viz client ctor, ret 0x10
    MH_STATUS s = MH_CreateHook(pCtor, (LPVOID)&HookedVizClientCtor,
                                (LPVOID*)&g_origVizClientCtor);
    if (s == MH_OK) s = MH_EnableHook(pCtor);
    wsprintfA(buf, "InitVizLoginHooks: ctor 0x578500 @0x%p status=%d", pCtor, s);
    Log(buf);

    PVOID pDisp = (PVOID)(g_imageBase + 0x177ED0); // VA 0x577ED0 S2C dispatcher, ret 8
    s = MH_CreateHook(pDisp, (LPVOID)&HookedVizS2CDispatcher,
                      (LPVOID*)&g_origVizS2CDispatcher);
    if (s == MH_OK) s = MH_EnableHook(pDisp);
    wsprintfA(buf, "InitVizLoginHooks: dispatcher 0x577ED0 @0x%p status=%d", pDisp, s);
    Log(buf);
}

static void ScanVizClientObjects() {
    if (!EnterHook()) return;
    __try {
        const DWORD needle = 0x00EC9C04;
        BYTE* addr = (BYTE*)0x00010000;
        int hits = 0;
        while ((DWORD)(ULONG_PTR)addr < 0x70000000 && hits < 32) {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T q = VirtualQuery(addr, &mbi, sizeof(mbi));
            if (!q) {
                addr += 0x10000;
                continue;
            }
            DWORD protect = mbi.Protect & 0xff;
            BOOL readable = (mbi.State == MEM_COMMIT) &&
                            !(mbi.Protect & PAGE_GUARD) &&
                            protect != PAGE_NOACCESS;
            if (readable && mbi.RegionSize <= (16 * 1024 * 1024)) {
                BYTE* start = (BYTE*)mbi.BaseAddress;
                BYTE* end = start + mbi.RegionSize - sizeof(DWORD);
                for (BYTE* p = start; p < end && hits < 32; p += 4) {
                    __try {
                        if (*(DWORD*)p == needle) {
                            DWORD* obj = (DWORD*)p;
                            char buf[620];
                            wsprintfA(buf, "[VIZ/SCAN] hit=%d self=0x%p vt=0x%08X field8=0x%08X f18=0x%08X f20=0x%08X f24=0x%08X f28=0x%08X f2c=0x%08X f30=0x%08X",
                                      hits + 1, obj, obj[0], obj[2], obj[6], obj[8], obj[9], obj[10], obj[11], obj[12]);
                            Log(buf);
                            if (!g_lastVizClientObj) g_lastVizClientObj = obj;
                            hits++;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        break;
                    }
                }
            }
            BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            addr = next > addr ? next : addr + 0x1000;
        }
        char buf[120];
        wsprintfA(buf, "[VIZ/SCAN] done hits=%d lastObj=0x%p", hits, g_lastVizClientObj);
        Log(buf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[VIZ/SCAN] exception");
    }
    LeaveHook();
}

// Install LoadLibrary*/GetProcAddress capture hooks. Called once from
// PatchThread (game process only) after MinHook init. MinHook is already
// initialized by InitCreateProcessHooks.
static void InitLoadLibraryHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) { Log("InitLoadLibraryHooks: kernel32 not loaded"); return; }
    struct Spec { const char* name; LPVOID detour; LPVOID* orig; };
    Spec specs[] = {
        { "LoadLibraryA",   (LPVOID)&HookedLoadLibraryA,   (LPVOID*)&g_origLoadLibraryA   },
        { "LoadLibraryW",   (LPVOID)&HookedLoadLibraryW,   (LPVOID*)&g_origLoadLibraryW   },
        { "LoadLibraryExA", (LPVOID)&HookedLoadLibraryExA, (LPVOID*)&g_origLoadLibraryExA },
        { "LoadLibraryExW", (LPVOID)&HookedLoadLibraryExW, (LPVOID*)&g_origLoadLibraryExW },
        { "GetProcAddress", (LPVOID)&HookedGetProcAddressGame, (LPVOID*)&g_origGetProcAddressGame },
        { "UnhandledExceptionFilter", (LPVOID)&HookedUEF, (LPVOID*)&g_origUEF },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        PVOID fn = GetProcAddress(hKernel, specs[i].name);
        char buf[200];
        if (!fn) { wsprintfA(buf, "InitLoadLibraryHooks: GetProcAddress(%s) FAILED", specs[i].name); Log(buf); continue; }
        MH_STATUS s = MH_CreateHook(fn, specs[i].detour, specs[i].orig);
        if (s != MH_OK) { wsprintfA(buf, "InitLoadLibraryHooks: MH_CreateHook(%s) status=%d", specs[i].name, s); Log(buf); continue; }
        s = MH_EnableHook(fn);
        if (s != MH_OK) { wsprintfA(buf, "InitLoadLibraryHooks: MH_EnableHook(%s) status=%d", specs[i].name, s); Log(buf); continue; }
        wsprintfA(buf, "InitLoadLibraryHooks: %s hooked at 0x%p", specs[i].name, fn);
        Log(buf);
    }
}

// Install Wait* hooks. Called once from PatchThread after MinHook init.
static void InitWaitHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
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
    // it tore down Goley_ before InitWaitHooks finished. Hook both kernel32
    // and kernelbase wrappers because Win10 often forwards user-mode waits
    // through kernelbase before entering the ntdll syscall stub.
    struct WaitHookSpec { HMODULE mod; const char* modName; const char* name; LPVOID detour; LPVOID* orig; };
    WaitHookSpec specs[] = {
        { hKernel,     "kernel32",   "WaitForSingleObject",    (LPVOID)&HookedWaitForSingleObject,   (LPVOID*)&g_origWFSO   },
        { hKernel,     "kernel32",   "WaitForSingleObjectEx",  (LPVOID)&HookedWaitForSingleObjectEx, (LPVOID*)&g_origWFSOEx },
        { hKernel,     "kernel32",   "WaitForMultipleObjects", (LPVOID)&HookedWaitForMultipleObjects,(LPVOID*)&g_origWFMO   },
        { hKernelBase, "kernelbase", "WaitForSingleObject",    (LPVOID)&HookedWaitForSingleObject,   (LPVOID*)&g_origWFSO   },
        { hKernelBase, "kernelbase", "WaitForSingleObjectEx",  (LPVOID)&HookedWaitForSingleObjectEx, (LPVOID*)&g_origWFSOEx },
        { hKernelBase, "kernelbase", "WaitForMultipleObjects", (LPVOID)&HookedWaitForMultipleObjects,(LPVOID*)&g_origWFMO   },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        if (!specs[i].mod) continue;
        PVOID p = GetProcAddress(specs[i].mod, specs[i].name);
        char buf[200];
        if (!p) {
            wsprintfA(buf, "InitWaitHooks: GetProcAddress(%s!%s) FAILED", specs[i].modName, specs[i].name);
            Log(buf);
            continue;
        }
        MH_STATUS s = MH_CreateHook(p, specs[i].detour, specs[i].orig);
        if (s != MH_OK) {
            wsprintfA(buf, "InitWaitHooks: MH_CreateHook(%s!%s) status=%d", specs[i].modName, specs[i].name, s);
            Log(buf);
            continue;
        }
        s = MH_EnableHook(p);
        if (s != MH_OK) {
            wsprintfA(buf, "InitWaitHooks: MH_EnableHook(%s!%s) status=%d", specs[i].modName, specs[i].name, s);
            Log(buf);
            continue;
        }
        wsprintfA(buf, "InitWaitHooks: %s!%s hooked at 0x%p", specs[i].modName, specs[i].name, p);
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

    // FAZ31: log the command line the game was launched with. The Netmarble
    // launcher normally passes region/locale/auth params; thread-hijack inject
    // launches with NONE. If translation-load is gated on a missing param,
    // this is where we'd see it.
    {
        LPWSTR cl = GetCommandLineW();
        if (cl) {
            char a[700]; int i = 0;
            for (; cl[i] && i < 699; ++i) a[i] = (cl[i] < 128) ? (char)cl[i] : '?';
            a[i] = 0;
            char b[760]; wsprintfA(b, "[CMDLINE] %s", a); Log(b);
        } else { Log("[CMDLINE] (null)"); }
    }

    // Install kernel32!CreateProcessA/W hooks FIRST so the very first
    // child spawn (typically nProtect's GameMon.des) gets our DLL APC-injected.
    InitCreateProcessHooks();

    // FAZ16: Wait hooks RE-ENABLED. Onceki not "nProtect anti-hook'u
    // tetikliyor" diyordu -- ama o GG (GameMon/npggNT) CALISIRKEN gecerliydi.
    // Artik GG child'i SUSPENDED birakiyoruz (GG_LEAVE_SUSPENDED), yani
    // npggNT anti-hook hic aktiflesmemis durumda. Bu pencerede wait hook'lari
    // guvenli olmali. Amac: init thread'in "초기화중"de bekledigi GG-ready
    // event'inin handle + caller'ini loglamak -> harici probe ile SADECE o
    // handle'a SetEvent (signal-all oyunu cikisa/AV'ye surukledi).
    if (GG_LEAVE_SUSPENDED) {
        Log("Wait hooks ENABLED (GG suspended -> anti-hook dormant)");
        InitWaitHooks();  // REQUIRED: WFMO SHIM auto-signals GG-ready + sets g_ggReadySignaled
        InitCritsecFix(); // FAZ23: auto-init d3d9's zeroed critsec (the post-ready death, faz22)
        InitFileLogHooks(); // FAZ31: log Translation/.VL/UIString file opens (diagnostic)
        InitMessageBoxHook(); // FAZ47: suppress "GameGuard Error" dialog + log live GG status
        InitWinsockLogHooks(); // FAZ58: trace login TCP send callsite (log-only)
        // FAZ21 capture hooks (LoadLibrary*/GetProcAddress + ntdll LdrLoadDll/
        // LdrGetProcedureAddress). HYPOTHESIS: hooking the loader CORE
        // (LdrLoadDll/LdrGetProcedureAddress) destabilizes the PARALLEL loader
        // (LdrpDrainWorkQueue) once render init (D3D9 device enum) triggers
        // heavy DLL loading -> a loader worker thread faults -> unhandled exc ->
        // WER teardown (faz21 dump: main thread healthy in LdrLoadDll via OUR
        // hooks; TID 9320 unhandled-exc -> UnhandledExceptionFilter). We already
        // captured the data we needed (0x8E8740 = fail-safe), so DISABLE these
        // by default to test if the game survives render init without them.
        // Flip to TRUE only to re-capture loader-level activity.
        if (CAPTURE_HOOKS_ENABLED) {
            InitLoadLibraryHooks();
            InitNtdllHooks();
        } else {
            Log("FAZ21: capture hooks (LoadLibrary/LdrLoadDll) DISABLED -- testing loader stability");
        }
    } else {
        Log("Wait hooks DISABLED -- using thread-EIP polling instead");
    }

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) { Log("GetModuleHandle NULL"); return 1; }
    g_imageBase = (BYTE*)hMod;

    char buf[256];
    wsprintfA(buf, "Image base: 0x%p", g_imageBase);
    Log(buf);
    if (ENABLE_PROUD_CODEC_DIAG) {
        InitProudNetCodecHooks(); // FAZ59: log pre/post outbound ProudNet codec payloads
    } else {
        Log("FAZ72: ProudNet codec hook disabled; raw/send-wrapper/netlog only");
    }
    InitProudNetRawSendHook(); // FAZ59: log generated-RMI caller + raw payload
    if (ENABLE_VIZ_LOGIN_DIAG) {
        InitVizLoginHooks(); // FAZ67: capture Viz/S2C object and NotifyLoginOk dispatcher calls
        ScanVizClientObjects();
    } else {
        Log("FAZ70: Viz login diagnostics disabled; preserving stable PNRAW/RequestLogin path");
    }

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
        // FAZ27: NtTerminateThread stub REMOVED -- it was THE root cause of the
        // post-GG-ready death. The NVIDIA UMD (nvd3dum/nvldumd) spawns worker
        // threads during OpenAdapter that exit normally via
        // FreeLibraryAndExitThread -> RtlExitUserThread -> NtTerminateThread.
        // Our no-op stub made NtTerminateThread RETURN instead of terminating,
        // so RtlExitUserThread fell through to its `int3` guard (ntdll+0xa72f4)
        // -> unhandled breakpoint -> WER -> process death. NtTerminateThread
        // MUST work for normal thread lifecycle. (void)ntTermThr;
        (void)ntTermThr;
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
    BOOL threadsFrozen = FALSE;
    DWORD ggReadyTick = 0;     // FAZ35: set on first post-ready iteration
    BOOL  diagArmed = FALSE;   // FAZ35: translation-OPEN diag BP armed once
    // FAZ55: TR/Goley launch-state diagnostic. Region (0x12bbc88) is empty (no
    // launcher SSO login) -> locale-mode global [0x12bac14] defaults to 2 (EN);
    // the UIString loader then builds "Translation_3_UIString_EN.txt" which is
    // NOT in the VLPH patch package (only CF/DE/ID) -> localization map empty
    // -> loading crash (0xd30313/0x8bce5a). FAZ53 proved service 3 + locale 4
    // reaches ChaguChaguId login. FAZ55 tries the natural TR/Goley pair:
    // locale-mode 3 (TR) + service 2 (Goley label at 0xD3F1F0).
    // This is a DATA write to game globals (NOT code), so Themida's code-hash
    // anti-tamper is unaffected. Set FALSE to disable.
    const BOOL FORCE_LOCALE_TR = TRUE;
    // FAZ36: pin the BINARY-CACHE root (transMgr+0x12c) to "../DataTr/". See the
    // block below for the full rationale (BinaryCache lives only in DataTr/).
    const BOOL FORCE_DATATR_ROOT = TRUE;
    // FAZ52/55 diagnostic: launcher/NMRunParam normally sets the service/region
    // state used by the pane selector at 0xD3EA12. In our direct launch both
    // [0x12bbc40] and [app+0x54]->state remain 0, so the selector never chooses
    // "LoginPane" and the login.swf loader is never reached. Data-only test:
    // FAZ55 uses service=2 (Goley) and pane-state=2, because 0xD3EA12 routes
    // that combination to "LoginPane" without selecting the ChaguChaguId label.
    const BOOL FORCE_LOGIN_PANE_STATE = TRUE;
    // FAZ56: 8277 fallback/report path copies the built-in TR default IP
    // ("213.74.179.19") before the external redirect helper can patch it.
    // Keep the source string pinned to localhost inside the injected DLL so
    // both SERVER_IP:8000 and default-report 8277 paths stay local.
    const BOOL FORCE_DEFAULT_TR_IP_LOCAL = TRUE;
    // FAZ45: pin the persistent GameGuard status field [ctx+0x10] to 0x755.
    // faz44 root cause: GG-ctx init (0x8E36A0) stores 0x8E3E80's result (0x78,
    // "fail"/error 120) into [ctx+0x10] (store @0x8E36AB). The existing 0xD35379
    // patch only fixes a transient EAX downstream, never this PERSISTENT field.
    // ~16s later a periodic GG-status reporter (0x8E685A: cmp [ctx+0x10],0x755 /
    // jne) sees 0x78 != 0x755 and spawns ggerror.des 120 (120x), tearing the game
    // down BEFORE the Flash UI loads (faz43 gray screen). [ctx+0x10] has a single
    // writer (the init store); the reporter only READS it, and the secondary
    // error flag [0x12b1e8c] is never written by game code (GG DLL is suspended)
    // -> stays 0. So pinning [ctx+0x10]=0x755 makes the reporter take its skip
    // branch (no spawn). ctx = *[0x12b22c8]. DATA write only (Themida-safe).
    const BOOL FORCE_GG_STATUS = TRUE;
    while (GetTickCount() - startTick < 600000) {  // 10 minute upper bound
        if (FORCE_DEFAULT_TR_IP_LOCAL) {
            __try {
                BYTE* pDefaultIp = g_imageBase + DEFAULT_TR_IP_RVA;
                static const char localIpPatch[14] = "127.0.0.1";
                if (memcmp(pDefaultIp, localIpPatch, sizeof(localIpPatch)) != 0) {
                    DWORD oldProt = 0;
                    if (VirtualProtect(pDefaultIp, sizeof(localIpPatch), PAGE_EXECUTE_READWRITE, &oldProt)) {
                        memcpy(pDefaultIp, localIpPatch, sizeof(localIpPatch));
                        DWORD dummy = 0;
                        VirtualProtect(pDefaultIp, sizeof(localIpPatch), oldProt, &dummy);
                        static BOOL loggedIP = FALSE;
                        if (!loggedIP) { Log("FAZ56: forced default TR IP string 213.74.179.19 -> 127.0.0.1"); loggedIP = TRUE; }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // FAZ55: keep locale-mode pinned to 3 (TR) every iteration so the
        // locale getter 0xd2e140 reads/caches "TR" before the translation
        // loader runs (loader runs after GG-ready, during loading).
        if (FORCE_LOCALE_TR) {
            __try {
                volatile DWORD* pLocaleMode = (volatile DWORD*)0x12BAC14;
                if (*pLocaleMode != 3) {
                    *pLocaleMode = 3;
                    static BOOL loggedLF = FALSE;
                    if (!loggedLF) { Log("FAZ55: forced locale-mode [0x12bac14] = 3 (TR)"); loggedLF = TRUE; }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (FORCE_LOGIN_PANE_STATE && !g_requestLoginObserved) {
            __try {
                volatile DWORD* pServiceRegion = (volatile DWORD*)0x12BBC40;
                if (*pServiceRegion != 2) {
                    *pServiceRegion = 2;
                    static BOOL loggedRegion = FALSE;
                    if (!loggedRegion) { Log("FAZ55: forced service/region [0x12bbc40] = 2 (Goley)"); loggedRegion = TRUE; }
                }
                DWORD app = *(volatile DWORD*)0x12BAA04;
                if (app) {
                    DWORD stateObj = *(volatile DWORD*)(app + 0x54);
                    if (stateObj) {
                        volatile DWORD* pPaneState = (volatile DWORD*)stateObj;
                        if (*pPaneState != 2) {
                            DWORD oldPane = *pPaneState;
                            *pPaneState = 2;
                            static BOOL loggedPane = FALSE;
                            if (!loggedPane) {
                                char b[160];
                                wsprintfA(b, "FAZ55: forced [app+0x54]->state %lu -> 2 (Goley LoginPane)", oldPane);
                                Log(b);
                                loggedPane = TRUE;
                            }
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // FAZ73: after a real RequestLogin is sent, stop pinning the app back to
        // LoginPane and try the game's own pane loader for LobbyPane once. This
        // is intentionally a data/control-flow shortcut, not a network codec
        // solution; it answers whether lobby UI can stand up without a valid
        // NotifyLoginOk session object.
        if (g_requestLoginObserved && !g_forcedLobbyPane &&
            g_requestLoginTick && (GetTickCount() - g_requestLoginTick) > 1500) {
            if (InterlockedCompareExchange(&g_forcedLobbyPane, 1, 0) == 0) {
                ForceLoadPaneByName("LobbyPane", "after RequestLogin");
            }
        }
        PinError93LatchAfterLogin();

        // FAZ45: pin GG persistent status [ctx+0x10] = 0x755 every iteration so
        // the periodic ggerror.des reporter never sees a "fail" status. ctx is
        // the global GG context pointer at [0x12b22c8] (NULL until GG-ctx init).
        if (FORCE_GG_STATUS) {
            __try {
                DWORD ggCtx = *(volatile DWORD*)0x12B22C8;
                if (ggCtx) {
                    volatile DWORD* pStatus = (volatile DWORD*)(ggCtx + 0x10);
                    if (*pStatus != GG_OK_STATUS) {
                        *pStatus = GG_OK_STATUS;
                        static BOOL loggedGS = FALSE;
                        if (!loggedGS) { Log("FAZ45: forced GG status [ctx+0x10] = 0x755"); loggedGS = TRUE; }
                    }
                    // FAZ48: pin [ctx+1] (byte GG-OK flag) = 1. The SECOND GG-check
                    // 0x8E6350 (via 0x8E3710, gating "Error99") returns 0x755 (OK)
                    // immediately when [ctx+1]!=0; otherwise after a 3-call grace
                    // period (~15s) it returns 0x262/0x28a -> "Gameguard Error99" ->
                    // CRT exit path -> ExitProcess(patched/non-returning) -> crash.
                    // Forcing [ctx+1]=1 makes Error99 NEVER fire at the source.
                    volatile BYTE* pFlag = (volatile BYTE*)(ggCtx + 1);
                    if (*pFlag == 0) {
                        *pFlag = 1;
                        static BOOL loggedF = FALSE;
                        if (!loggedF) { Log("FAZ48: forced GG-OK flag [ctx+1] = 1 (Error99 gate)"); loggedF = TRUE; }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // FAZ22/23: once GG-ready is signaled, the game proceeds into render
        // init (Direct3DCreate9). STOP all thread suspension here -- both
        // SetHardwareBreakpointAllThreads AND DumpThreadEips SuspendThread()
        // every thread at 2-20Hz. faz22 dump proved the death is an AV in
        // ntdll!RtlpWaitOnCriticalSection: a d3d9 GLOBAL critsec has
        // DebugInfo=NULL (zeroed/uninitialized) -> contended-enter NULL-deref.
        // Hypothesis: suspending a thread mid-d3d9-InitializeCriticalSection
        // leaves that critsec half-initialized. All Themida/GG HW-BP bypasses
        // (val/ggr) fire long BEFORE GG-ready, so we no longer need the loop.
        if (g_ggReadySignaled) {
            // FAZ53: FAZ52 proved the LoginPane gate opens and reaches the
            // loader. Now spend the limited DR slots on the return/branch points:
            //   0xD75D6D = right after call 0xD75A40, AL is loader success flag
            //   0xD75D99 = failure side
            //   0xD75D9E = success side
            // Keep the GG result patch (DR2, ggr) so GG stability is unchanged.
            DWORD uiRetVA   = (DWORD)(g_imageBase + 0x975D6D);  // after loader call, AL=result
            DWORD uiFailVA  = (DWORD)(g_imageBase + 0x975D99);  // loader fail path
            DWORD uiOkVA    = (DWORD)(g_imageBase + 0x975D9E);  // loader success path
            DWORD ggrVA     = (DWORD)(g_imageBase + GG_RESULT_PATCH_RVA);
            if (!threadsFrozen) {
                Log("FAZ23: GG-ready -> ceasing ALL thread suspension (let d3d9 init run clean)");
                threadsFrozen = TRUE;
                ggReadyTick = GetTickCount();
                int n = SetHardwareBreakpointAllThreads(uiRetVA, uiFailVA, ggrVA, uiOkVA);
                wsprintfA(buf, "FAZ53: armed UI-loader result BPs ret=0x%X fail=0x%X ok=0x%X (+ggr DR2) on %d threads",
                          uiRetVA, uiFailVA, uiOkVA, n);
                Log(buf);
                diagArmed = TRUE;
            }
            // Re-arm continuously (after 1500ms, past d3d9 init) so threads spawned
            // after the initial arming also get the BPs (DR regs aren't inherited).
            if ((GetTickCount() - ggReadyTick) > 1500) {
                SetHardwareBreakpointAllThreads(uiRetVA, uiFailVA, ggrVA, uiOkVA);
            }
            // FAZ49: periodic thread-EIP/ESP/retaddr dump on the gray screen to see
            // WHERE main/render threads are parked (message loop / network wait /
            // init / state transition). First dump ~4s after GG-ready (d3d9 device
            // init done -> SuspendThread is safe), then every 6s. Diagnostic only.
            static DWORD s_lastDump = 0;
            if (ENABLE_POSTREADY_THREAD_DUMPS &&
                (GetTickCount() - ggReadyTick) > 4000 &&
                (s_lastDump == 0 || (GetTickCount() - s_lastDump) > 6000)) {
                s_lastDump = GetTickCount();
                Log("FAZ49: --- periodic gray-screen thread dump ---");
                DumpThreadEips();
            }
            Sleep(200);
            continue;
        }

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
        // FAZ46: GG result check is PERIODIC -> keep armed permanently (was
        // g_ggrHit ? 0 : ggrVA, a one-shot that let later checks fail).
        DWORD t2 = (DWORD)(g_imageBase + GG_RESULT_PATCH_RVA);
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
        g_mainThreadId = GetCurrentThreadId();
        Log("DLL_PROCESS_ATTACH (VEH+HWBP+DialogKiller)");

        if (IsGameProcess()) {
            Log("Running in Game Process");
            // ============================================================
            // INLINE early armor -- runs in DllMain BEFORE any async thread.
            // ============================================================
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
                    // FAZ27: NtTerminateThread stub REMOVED (root cause of the
                    // post-GG-ready death -- broke NVIDIA UMD worker-thread exit
                    // -> int3 fall-through in RtlExitUserThread). See PatchThread.
                    (void)ntTermThr;
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
        } else {
            Log("Running in non-game Process (GameGuard.des/etc)");
            g_parentPid = GetParentProcessId();
            char buf[256];
            wsprintfA(buf, "Parent Process ID: %lu", g_parentPid);
            Log(buf);

            HMODULE hMain = GetModuleHandleA(NULL);
            BOOL ok1 = HookIatSlot(hMain, "KERNEL32.DLL", "GetProcAddress", (FARPROC)HookedGetProcAddress, (FARPROC*)&g_origGetProcAddress);
            BOOL ok2 = HookIatSlot(hMain, "KERNEL32.DLL", "ExitProcess", (FARPROC)HookedExitProcess_GG, (FARPROC*)&g_origExitProcess_GG);
            wsprintfA(buf, "IAT Hooks inside GameGuard.des: GetProcAddress=%d, ExitProcess=%d", ok1, ok2);
            Log(buf);
        }
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        Log("DLL_PROCESS_DETACH");
        if (g_vehHandle) RemoveVectoredExceptionHandler(g_vehHandle);
    }
    return TRUE;
}
