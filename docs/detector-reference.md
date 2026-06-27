# Detector reference

Each detector below documents what it catches, the technique it
relies on, and the false-positive surface developers should know
about before treating a finding as actionable.

---

## `inline_hook`

**What it catches.** Inline hooks installed at the prologue of
exported functions. Covers the common patterns: `JMP rel32`,
short jumps, `MOV reg, imm64; JMP reg`, indirect jumps through a
memory operand (`JMP [rip+disp32]`), `PUSH imm32; RET`
trampolines.

**Technique.** For every loaded module, the detector reads the
on-disk PE image, walks the export table of the in-memory image,
and compares the first bytes of each non-forwarded exported
function between disk and memory. If the bytes differ AND the
in-memory bytes match a known hook prologue pattern, the export
is flagged.

**Severity.**

- `critical` — in-memory bytes match a hook prologue and differ
  from disk.
- The detector currently does not emit `suspicious` for inline
  hooks; a future iteration will lower severity for ambiguous
  differences.

**False-positive surface.**

- The Windows loader patches a handful of `ntdll` syscall stubs at
  process start to wire up correct syscall numbers for the running
  build. Differences in those stubs are real and not malicious;
  the detector's narrow byte-pattern check avoids most of them
  because the patched stubs do not look like jumps.
- Control Flow Guard (CFG) and Indirect Call Speculation
  mitigations may rewrite small portions of code at load time;
  these should not produce jump-shaped prologues but they may
  show up if the byte-pattern set is broadened.

---

## `iat_hook`

**What it catches.** Import Address Table entries whose runtime
resolution does not land inside the module declared in the import
descriptor. Catches naive IAT redirection used by injected DLLs to
intercept calls from the host into Windows APIs.

**Technique.** For every loaded module, the detector walks the
import directory. For each resolved entry, it checks which module
contains the resolved address; if no module contains it the import
is flagged `critical`. If a module contains it but its name
disagrees with the import descriptor, the import is flagged
`suspicious` (the address may belong to a legitimate forwarded
export).

**Severity.**

- `critical` — resolved address lies outside every loaded module.
- `suspicious` — resolved address lies inside a different module
  than the import descriptor names.

**False-positive surface.**

- Forwarded exports legitimately resolve to a different module
  than the one named in the import descriptor (e.g., a forwarder
  in `kernel32` to `kernelbase`). The detector reports these as
  `suspicious` for this reason.
- API set redirection (`api-ms-win-*`) is resolved early by the
  loader; the import descriptor names the apiset and the resolved
  address lives in the implementing DLL. This will currently
  surface as `suspicious`.

---

## `thread_origin`

**What it catches.** Threads whose `Win32StartAddress` (as reported
by `NtQueryInformationThread`) is not contained by any module the
loader knows about. Common signal of shellcode execution, manually
mapped payloads invoked via `CreateRemoteThread`, or RWX-region
trampolines.

**Technique.** Snapshots all threads owned by the current process
via Tool Help, queries each thread's start address via
`NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`, and
verifies that the address falls inside some loaded module.

**Severity.**

- `critical` — start address outside every loaded module.

**False-positive surface.**

- Threads whose start address has been overwritten by Windows to
  point at thread-pool dispatcher routines remain inside `ntdll`
  and are not flagged.
- Some runtime systems (debuggers, profilers, sandboxes) inject
  worker threads whose start address is outside the original
  module set. Mooring will report these as findings; runtime
  allow-listing of known tools is left to the embedding
  application.

---

## `hidden_module`

**What it catches.** `MEM_IMAGE` memory regions that are present
in the process address space but not reachable through the PEB
module list. The classic signature of manually mapped DLLs that
bypass `LdrLoadDll` to avoid notification callbacks and the
loader's module list.

**Technique.** Walks the address space via `VirtualQuery`; for
each committed `MEM_IMAGE` region, checks that its base address is
contained inside some loaded module. Regions whose base is outside
every loaded module are reported; presence of an `MZ` header lifts
severity from `suspicious` to `critical`.

**Severity.**

- `critical` — orphan `MEM_IMAGE` region with intact `MZ` header.
- `suspicious` — orphan `MEM_IMAGE` region with stripped or
  missing `MZ` header.

**False-positive surface.**

- A module mid-load (between `NtMapViewOfSection` and the link
  insert into the loader list) may appear hidden for a few cycles.
  Repeat the scan after a short delay before treating a single
  finding as conclusive.

---

## `hardware_breakpoint`

**What it catches.** Hardware breakpoints (debug registers
`Dr0`–`Dr3` non-zero) on any thread of the current process other
than the calling thread. Used by reverse engineers as a low-trace
alternative to software (`INT 3`) breakpoints, and by some
hooking libraries to install hooks without modifying code bytes.

**Technique.** Enumerates threads via Tool Help, opens each thread
with `THREAD_GET_CONTEXT`, calls `GetThreadContext` with
`CONTEXT_DEBUG_REGISTERS`, and reports any thread with a non-zero
`Dr0`–`Dr3`.

**Severity.**

- `critical` — any non-zero `Dr0`–`Dr3` on any other thread.

**False-positive surface.**

- A small number of legitimate runtimes (some JITs, some
  performance profilers, certain instrumentation frameworks) set
  hardware breakpoints for their own use. These will be reported;
  the embedding application decides whether to allow-list a
  specific profiler context.

---

## Planned detectors

The list below is what is in the queue but not yet implemented:

- `eat_hook` — Export Address Table tampering.
- `veh_abuse` — vectored exception handler chain enumeration.
- `syscall_stub` — ntdll syscall-stub byte-pattern verification
  with awareness of legitimate per-build loader patches.
- `debugger_present` — multi-method debugger detection (PEB flag,
  `NtQueryInformationProcess`, timing, hardware probes).
- `suspicious_memory` — committed RWX regions outside any loaded
  module.
