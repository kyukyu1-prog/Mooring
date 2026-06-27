// scan_self - command-line driver that runs every mooring detector
// against the current process and prints a human-readable report.
//
// Exit code is non-zero on any critical finding so the binary can
// be plugged into a CI / smoke-test rig.

#include <mooring/mooring.h>

#include <iomanip>
#include <iostream>

namespace {

// Shorter labels for the console output than the API's full
// strings; matches the table headers people are used to.
char const* short_severity(mooring::severity s) noexcept {
    switch (s) {
        case mooring::severity::info:       return "INFO";
        case mooring::severity::suspicious: return "WARN";
        case mooring::severity::critical:   return "CRIT";
    }
    return "????";
}

void print_header() {
    std::cout <<
        "mooring scan_self v0.1\n"
        "  scanning current process for injection / tamper signatures\n\n";
}

void print_summary(mooring::scan_result const& r) {
    std::cout
        << "Summary: " << r.size() << " finding(s)\n"
        << "  critical:    " << r.count(mooring::severity::critical)   << "\n"
        << "  suspicious:  " << r.count(mooring::severity::suspicious) << "\n"
        << "  info:        " << r.count(mooring::severity::info)       << "\n\n";
}

void print_finding(mooring::finding const& f) {
    std::cout
        << "[" << short_severity(f.sev) << "] "
        << mooring::to_string(f.cat) << "  "
        << f.subject << "\n"
        << "    " << f.description << "\n";

    if (f.address) {
        std::cout
            << "    address:  0x"
            << std::hex << f.address << std::dec << "\n";
    }
    std::cout << "    detector: " << f.detector << "\n\n";
}

}  // namespace

int main() {
    print_header();

    auto const result = mooring::detectors::scan_self();

    print_summary(result);

    if (result.empty()) {
        std::cout << "No findings. Process looks clean to mooring.\n";
        return 0;
    }

    for (auto const& f : result.findings) {
        print_finding(f);
    }

    return result.count(mooring::severity::critical) > 0 ? 1 : 0;
}
