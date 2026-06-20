# Mooring

[![build](https://github.com/kyukyu1-prog/Mooring/actions/workflows/build.yml/badge.svg)](https://github.com/kyukyu1-prog/Mooring/actions/workflows/build.yml)
[![CodeQL](https://github.com/kyukyu1-prog/Mooring/actions/workflows/codeql.yml/badge.svg)](https://github.com/kyukyu1-prog/Mooring/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6.svg)](#build)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)](#build)

Process integrity and anti-injection detection toolkit for Windows
applications. Mooring is a small library of detectors that an
application can call against its own process to surface signs of code
tampering, unauthorized injection, or runtime debugging.

> Status: early development (`v0.1.x`). Public API is not yet stable.

## What it detects

| Detector              | Catches                                                                    |
|-----------------------|----------------------------------------------------------------------------|
| `inline_hook`         | Prologue patches on exported functions (`JMP rel32`, `MOV r64,imm64;JMP r`, indirect jumps) |
| `iat_hook`            | Import Address Table entries redirected outside the originating module     |
| `thread_origin`       | Threads whose `Win32StartAddress` lies outside every loaded module         |
| `hidden_module`       | `MEM_IMAGE` regions present in the address space but absent from the loader list |
| `hardware_breakpoint` | Non-zero `Dr0`–`Dr3` on any thread other than the caller                   |

See [`docs/detector-reference.md`](docs/detector-reference.md) for
what each detector measures, the technique behind it, and where it
can produce false positives.

## Why

Commercial runtime application self-protection (RASP) and anti-cheat
products are well out of reach for the audience Mooring targets: indie
game developers, modding communities, and small ISVs that face the
same threat surface (DLL injection, inline hooking, memory tamper,
debugger-assisted reverse engineering) without the budget or licensing
posture for EAC-class products. Mooring is the small, embeddable,
permissively-licensed alternative for the floor of that stack.

It is intentionally narrow. It does not ship offensive tooling. It
does not try to *prevent* anything by itself — it gives the host
application enough signal to react.

## Quickstart

```cpp
#include <mooring/mooring.h>

int main() {
    auto result = mooring::detectors::scan_self();
    for (auto const& f : result.findings) {
        // ... report, log, react ...
    }
    return result.count(mooring::severity::critical) ? 1 : 0;
}
```

A more complete sample is in [`examples/scan_self.cpp`](examples/scan_self.cpp).

## Build

Requirements: Windows 10 or newer, CMake 3.20+, MSVC 2019+ or
clang-cl 13+. x64 only for now.

```pwsh
cmake -S . -B build -A x64
cmake --build build --config Release
.\build\examples\Release\scan_self.exe
```

The static library lives in `build\Release\mooring.lib`. The example
exe lives in `build\examples\Release\scan_self.exe`.

## Layout

```
include/mooring/        public API headers
src/core/               shared utilities (PEB walk, PE parser)
src/detectors/          one .cpp per detector
examples/               sample programs
docs/                   architecture and detector reference
```

## Notes for embedders

A few things worth knowing before wiring mooring into a real app:

- **Run on a background thread.** A full `scan_self()` reads every
  loaded module's on-disk image to compare prologue bytes; on a
  large process this is a noticeable amount of I/O. Don't block
  your UI thread on it.
- **Re-scan rather than scan once.** Some signals (a module
  mid-load, a worker thread mid-creation) can momentarily look
  like findings. A finding that survives two scans separated by a
  short delay is far more likely to be real.
- **You decide what to do with a finding.** Mooring reports;
  reaction policy belongs to the host. A common starting point:
  `critical` → fail closed (exit, disable sensitive features,
  refuse network handshake), `suspicious` → log and watch,
  `info` → telemetry only.
- **Allow-lists are your problem.** Mooring does not ship a
  bundled allow-list for known profilers, debuggers, or
  legitimate hookers. The set of "tools my users run" is
  application-specific; each `finding` carries enough address /
  module / name detail for you to filter as you see fit.

## Scope and non-goals

Mooring is a *defensive* toolkit. It studies offensive techniques to
build detection and hardening primitives, and ships none of them as
end-user weapons. See [`SCOPE.md`](SCOPE.md) for the explicit
boundary and the disclosure policy for findings against third-party
defensive products.

## License

MIT. See [`LICENSE`](LICENSE).
