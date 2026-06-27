// thread_origin: every thread has a "start address" attribute
// recorded by the kernel at thread creation. Mooring asks for it
// via NtQueryInformationThread and checks that the address lives
// inside some module the loader knows about.
//
// Shellcode, manually mapped payloads invoked through
// CreateRemoteThread, and RWX-region trampolines all light up
// here because their start address isn't part of any module.
//
// Caveat: some debuggers, profilers, and instrumentation tools
// spawn worker threads whose start address sits outside the
// original module set. We report them as findings; the embedding
// app is expected to allow-list specific tools when their false
// positives are known.

#include "mooring/detectors.h"
#include "mooring/internal/module_inventory.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <string>

namespace mooring::detectors {

namespace {

// ThreadQuerySetWin32StartAddress: NtQueryInformationThread info
// class 9. Not declared in winternl.h, but the value has been
// stable across every Windows version mooring targets and is
// widely used by debugging tools.
constexpr ULONG ThreadQuerySetWin32StartAddress = 9;

using NtQueryInformationThread_t = NTSTATUS (NTAPI*)(
    HANDLE ThreadHandle,
    ULONG  ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength,
    PULONG ReturnLength);

NtQueryInformationThread_t resolve_NtQIT() {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    // The double-cast through void* silences clang's
    // -Wcast-function-type without changing semantics.
    return reinterpret_cast<NtQueryInformationThread_t>(
        reinterpret_cast<void*>(
            ::GetProcAddress(ntdll, "NtQueryInformationThread")));
}

std::uintptr_t thread_start_address(HANDLE th) {
    static auto const fn = resolve_NtQIT();
    if (!fn) return 0;
    std::uintptr_t addr = 0;
    NTSTATUS const s = fn(
        th, ThreadQuerySetWin32StartAddress,
        &addr, sizeof(addr), nullptr);
    // NT_SUCCESS is `(NTSTATUS)(s) >= 0`. Same idea.
    return (s >= 0) ? addr : 0;
}

}  // namespace

void scan_thread_origins(scan_result& out) {
    auto const  modules = enumerate_loaded_modules();
    DWORD const pid     = ::GetCurrentProcessId();

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (::Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE th = ::OpenThread(
                THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) continue;

            std::uintptr_t const start = thread_start_address(th);
            ::CloseHandle(th);

            if (start == 0) continue;
            if (module_containing(modules, start)) continue;

            finding f;
            f.cat         = category::thread_origin;
            f.sev         = severity::critical;
            f.detector    = "thread_origin";
            f.subject     = "thread " + std::to_string(te.th32ThreadID);
            f.description =
                "Thread start address lies outside every loaded "
                "module (suggests shellcode, an RWX-region "
                "trampoline, or a manually mapped payload).";
            f.address = start;
            out.add(std::move(f));
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
}

}  // namespace mooring::detectors
