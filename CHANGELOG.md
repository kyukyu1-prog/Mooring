# Changelog

All notable changes to this project will be documented in this file.
Format roughly follows [Keep a Changelog][keepachangelog]; this
project does not yet promise SemVer.

[keepachangelog]: https://keepachangelog.com/en/1.1.0/

## [Unreleased]

### Added
- GitHub Actions CI: Windows MSVC build on every push and pull request.
- Dependabot configuration for monthly GitHub Actions updates.
- Issue templates: bug report, false-positive report, detector proposal.
- Pull request template with detector-author checklist.
- `CODEOWNERS`, `SECURITY.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- README status badges (build, license, platform, C++ standard).

## [0.1.0] - 2026-06

Initial public release.

### Added
- Static library `mooring::mooring` with five detectors:
  - `inline_hook` — exported-function prologue tampering
  - `iat_hook` — Import Address Table redirection
  - `thread_origin` — threads started outside any loaded module
  - `hidden_module` — `MEM_IMAGE` regions absent from the loader list
  - `hardware_breakpoint` — non-zero `Dr0`–`Dr3` on any other thread
- `scan_self` example program that runs every detector against the
  host process.
- Architecture and per-detector reference documentation.
- `.clang-format` and `.editorconfig` for consistent formatting.

### Known issues
- `inline_hook` does not yet allow-list legitimate loader-time
  patches outside of the existing jump-pattern filter; very
  occasional false positives possible after Windows feature
  updates.
- `thread_origin` will surface profiler / debugger worker threads;
  no built-in allow-list.
