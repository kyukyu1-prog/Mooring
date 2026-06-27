// hardware_breakpoint: enumerate threads and check each thread's
// debug-register state. Non-zero Dr0-Dr3 on any thread other than
// the caller is a strong indicator of either a hardware-breakpoint
// debugger or a hook library that uses DR-based interception.
//
// We skip the calling thread because applications that integrate
// mooring may legitimately use DRs in the same thread (some
// instrumentation libraries do); checking it would create
// self-noise.
//
// Future work: also surface Dr7 enable bits. Populated Dr0-Dr3
// without enables in Dr7 is suspicious but won't actually trip; a
// fully wired-up Dr7 is the real signal. Treating any non-zero DR
// address as critical is fine in practice — nobody bothers to
// populate DR0-Dr3 without intending to flip Dr7.

#include "mooring/detectors.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <string>

namespace mooring::detectors {

namespace {

void check_thread(DWORD tid, scan_result& out) {
    HANDLE h = ::OpenThread(
        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!h) return;

    // CONTEXT must be requested with the right flag set or
    // GetThreadContext leaves the relevant fields untouched.
    // Forgetting CONTEXT_DEBUG_REGISTERS is a classic silent bug.
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (::GetThreadContext(h, &ctx)) {
        bool const has_breakpoint =
            ctx.Dr0 != 0 || ctx.Dr1 != 0 ||
            ctx.Dr2 != 0 || ctx.Dr3 != 0;

        if (has_breakpoint) {
            finding f;
            f.cat      = category::hardware_breakpoint;
            f.sev      = severity::critical;
            f.detector = "hardware_breakpoint";
            f.subject  = "thread " + std::to_string(tid);
            f.description =
                "Non-zero hardware debug register (Dr0-Dr3) detected "
                "on thread. Common signal of a hardware-breakpoint "
                "debugger or a hook library using DR-based "
                "interception.";

            // Report the first populated DR as the relevant
            // address so the user has a concrete pointer to chase,
            // not just "something somewhere on this thread".
            f.address = static_cast<std::uintptr_t>(
                ctx.Dr0 ? ctx.Dr0 :
                ctx.Dr1 ? ctx.Dr1 :
                ctx.Dr2 ? ctx.Dr2 : ctx.Dr3);
            out.add(std::move(f));
        }
    }

    ::CloseHandle(h);
}

}  // namespace

void scan_hardware_breakpoints(scan_result& out) {
    DWORD const pid      = ::GetCurrentProcessId();
    DWORD const self_tid = ::GetCurrentThreadId();

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (::Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid)      continue;
            if (te.th32ThreadID       == self_tid) continue;
            check_thread(te.th32ThreadID, out);
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
}

}  // namespace mooring::detectors
