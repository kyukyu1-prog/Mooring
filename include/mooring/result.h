#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mooring {

// Detector's own confidence in a finding. Not a recommendation
// for action — the embedding application decides what to do at
// each level (see README.md "Notes for embedders").
enum class severity {
    info,        // baseline observation, not necessarily anomalous
    suspicious,  // worth attention, could occur legitimately
    critical     // strong evidence of tampering or injection
};

// What kind of anomaly was detected. Append-only — new detectors
// add a new value at the end so external code switching over the
// enum keeps compiling.
enum class category {
    inline_hook,
    iat_hook,
    eat_hook,
    thread_origin,
    hidden_module,
    hardware_breakpoint,
    debugger_present,
    veh_abuse,
    suspicious_memory
};

// Stable string labels. Handy for logs, JSON, or anything else
// where you'd otherwise reimplement a switch yourself.
char const* to_string(severity s) noexcept;
char const* to_string(category c) noexcept;

struct finding {
    category       cat = category::suspicious_memory;
    severity       sev = severity::info;
    std::string    detector;     // name of the detector that produced this
    std::string    subject;      // module / thread / region identifier
    std::string    description;  // human-readable summary
    std::uintptr_t address = 0;  // address relevant to the finding (0 if N/A)
};

struct scan_result {
    std::vector<finding> findings;

    void add(finding f) { findings.push_back(std::move(f)); }

    bool        empty() const noexcept { return findings.empty(); }
    std::size_t size()  const noexcept { return findings.size(); }

    // Count by severity or category. Linear in findings.size() —
    // call once and cache if you're sorting a UI by these.
    std::size_t count(severity s) const noexcept;
    std::size_t count(category c) const noexcept;
};

}  // namespace mooring
