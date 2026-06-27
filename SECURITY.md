# Security policy

## Reporting a vulnerability in Mooring

If you've found a vulnerability or a bypass in mooring itself —
the kind of thing that lets injected code defeat detection it
should have caught — please report it privately.

**Preferred channel:** GitHub Private Vulnerability Reporting

  https://github.com/kyukyu1-prog/Mooring/security/advisories/new

Private reports go straight to the maintainers and stay sealed
until coordinated disclosure is ready.

## In scope

- Bypasses that let a known injection / hooking technique escape
  the relevant detector without modification to user-mode code.
- Detector outputs that are demonstrably wrong (false negatives
  with a clean reproducer).
- Memory-safety bugs in the detector implementations themselves.

## Out of scope (use a public issue instead)

- False *positives*. These aren't security-sensitive — please use
  the public `false_positive` issue template.
- Detector enhancements that broaden coverage without addressing
  a concrete bypass — use the `detector_proposal` template.

## Findings against third-party defensive products

When mooring's research touches third-party RASP / anti-cheat
products and we find a bypass in them, those findings are
reported to the affected vendor first under a 90-day embargo.
See [`SCOPE.md`](SCOPE.md) for the project's full disclosure
policy.

## Response time

I aim to acknowledge a private report within 5 business days.
Fix timelines depend on complexity; you'll be kept in the loop
once the report lands.
