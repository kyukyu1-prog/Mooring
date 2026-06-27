# Scope

This document is the canonical statement of what Mooring is and is
not, and what kinds of work happen under its name.

## In scope

- Detection primitives for unauthorized code injection, inline and
  IAT/EAT hooking, hidden modules, debugger presence, hardware
  breakpoint abuse, and similar process-integrity violations on
  Windows.
- Hardening primitives that raise the cost of the techniques above:
  self-integrity verification, anti-debug layers (configurable and
  opt-in by the embedding application), tamper-resistant storage of
  integrity baselines.
- Research, internal red-team validation harnesses, and adversary
  emulation explicitly used to measure and improve detector quality.
- Coordinated disclosure of bypasses found in third-party RASP or
  anti-cheat products studied as part of detector quality work.

## Out of scope

- Shipping offensive tooling as an end-user product. Adversary
  emulation used to validate detectors lives inside the project's
  test harness and is not packaged for distribution as a
  ready-to-run injector, hook installer, or anti-anti-cheat bypass.
- Malware family development, ransomware components, credential
  theft primitives, mass scanning, persistence frameworks, or any
  capability whose primary purpose is offense rather than defense.
- Detection circumvention work targeted at any specific commercial
  product outside of a coordinated-disclosure engagement.

## Coordinated disclosure

Bypasses found in third-party defensive products during detector
research are reported to the affected vendor through their published
security contact prior to any public discussion. Embargo windows
follow industry norms (typically 90 days, extendable on vendor
request). Public write-ups remove or sanitize anything that would
aid exploitation against unpatched populations.

## Authorization

All artifacts studied by this project are either:

- Owned by the project,
- Public CTF or research artifacts,
- Or commercial software studied under coordinated-disclosure terms
  agreed to with the vendor.

No work is performed against systems the project does not have
explicit authorization to study.

## Contributions

Contributions that extend detection or hardening capability are
welcome. Contributions whose primary effect is to make offensive use
of Mooring easier are not.
