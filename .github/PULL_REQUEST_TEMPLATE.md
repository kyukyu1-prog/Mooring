## Summary

<!-- One line: what this PR changes and why. -->

## Type

- [ ] Bug fix
- [ ] New detector
- [ ] Detector tuning (false-positive reduction, severity grading, allow-list)
- [ ] Documentation
- [ ] Build / tooling

## Checklist

- [ ] Compiles cleanly under `/W4` on MSVC (or `-Wall -Wextra -Wpedantic` on clang-cl)
- [ ] If a new detector: added to `docs/detector-reference.md` with technique + false-positive surface
- [ ] If a new detector: added to `CMakeLists.txt` source list and to `detectors.h`
- [ ] `clang-format` ran over touched files
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Notes

<!-- Anything reviewers should know — design tradeoffs, follow-ups,
     references, before/after measurements, etc. -->
