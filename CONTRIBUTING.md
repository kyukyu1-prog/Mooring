# Contributing

Mooring is small and intentionally narrow. Patches are welcome,
especially:

- New detectors. See `docs/detector-reference.md` for the queue
  and `src/detectors/hardware_breakpoint.cpp` for the smallest
  reference implementation.
- Allow-list / configuration knobs for the existing detectors.
- Documentation — especially false-positive notes if you've hit
  one in the wild.

Out of scope is documented in [`SCOPE.md`](SCOPE.md). Please read
it before sending anything substantial.

## Style

- C++17, no fancy features. We compile cleanly under `/W4` on
  MSVC and `-Wall -Wextra -Wpedantic` on clang-cl.
- Public API lives under `include/mooring/`. Anything in
  `include/mooring/internal/` is fair game to break across
  minor versions.
- `.clang-format` is checked in; please run it before sending a
  PR (`clang-format -i` over the files you touched is enough).
- Comments explain *why*, not *what*. The code already says what.

## Adding a detector

1. Drop `src/detectors/your_detector.cpp` exposing one function:

    ```cpp
    void scan_your_thing(scan_result& out);
    ```

2. Add its signature to `include/mooring/detectors.h`.
3. Add it to `scan_self()` if it makes sense to run by default.
4. Add the source to `CMakeLists.txt`.
5. Document it in `docs/detector-reference.md`. The detector
   docs *are* the spec — what it catches, the technique, the
   severity grading, and the known false-positive surface.

## Reporting findings against third-party defensive products

See the disclosure section in [`SCOPE.md`](SCOPE.md). The short
version: vendor first, 90-day embargo, no PoC in public
write-ups that aids exploitation against unpatched populations.

## Commits

Conventional one-liner subject (`fix:`, `feat:`, `docs:` …) is
fine, just keep them imperative and under ~70 chars. Body is
optional but useful for non-obvious changes.
