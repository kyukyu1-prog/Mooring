# Architecture

Mooring is structured as a small core plus a set of independent
detector modules. The core knows nothing about specific detection
techniques; detectors share no state and can be invoked in any
order or subset.

## Layout

```
include/mooring/         public API
  mooring.h              umbrella header
  result.h               finding / scan_result types
  detectors.h            detector function signatures
  internal/              implementation headers, not part of the
                         supported public surface
    module_inventory.h   loaded module enumeration
    pe_image.h           PE header / section / export walking
    strings.h            small string conversions

src/
  core/                  shared utilities
    result.cpp           finding aggregation helpers
    module_inventory.cpp PEB walk + module table
    pe_image.cpp         PE parsing on loaded or on-disk images
    strings.cpp          wide<->utf8, ascii lowercasing
  detectors/             one .cpp per detector
    inline_hook.cpp
    iat_hook.cpp
    thread_origin.cpp
    hidden_module.cpp
    hardware_breakpoint.cpp

examples/
  scan_self.cpp          command-line driver that runs every
                         detector against the host process
```

## Detector contract

Each detector exposes one function with the signature

```cpp
void scan_X(mooring::scan_result& out);
```

A detector reads process state, never mutates it, and appends zero
or more `finding`s to `out`. Detectors are independent: adding a
new one is a matter of dropping a `.cpp` into `src/detectors/`,
exposing the function in `detectors.h`, and adding the file to
`CMakeLists.txt`.

## Result model

A `finding` carries:

- `severity` — `info` / `suspicious` / `critical`
- `category` — the kind of anomaly
- `detector` — the name of the detector that produced the finding
- `subject` — a short identifier of the thing the finding is about
  (a thread id, a module name, a function name)
- `description` — human-readable summary
- `address` — optional address relevant to the finding

Severity is the detector's own confidence:

- `critical` — strong, near-unambiguous evidence of tampering or
  injection.
- `suspicious` — anomaly consistent with an attack but capable of
  occurring legitimately (e.g., a forwarded export resolving to a
  different module than the import descriptor names).
- `info` — baseline observation included for context; never an
  alert on its own.

## Why module enumeration is centralized

Several detectors need an up-to-date snapshot of the loader module
list. `enumerate_loaded_modules()` walks the
`PEB->Ldr->InMemoryOrderModuleList` directly rather than going
through `EnumProcessModules`, so the detector sees exactly what the
Windows loader believes is loaded. The `hidden_module` detector
then compares that view against a `VirtualQuery` walk of the
address space; any divergence between the two views is the entire
point of the comparison, and going through `psapi.dll` would
collapse both views into the same set.

## Threading

The current detectors snapshot process state without taking locks
or suspending threads. Findings reflect the state observed at the
moment of the scan; concurrent injection may complete after a
detector has already moved past the relevant region. Running the
scan periodically (rather than once at startup) is the intended
usage pattern.

## What lives outside this repository

The adversary-emulation harness used to validate detectors against
known injection and hooking techniques is maintained separately and
is not shipped here. See [`../SCOPE.md`](../SCOPE.md) for the
project's posture on offensive code distribution.
