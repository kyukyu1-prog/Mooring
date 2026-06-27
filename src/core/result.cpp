#include "mooring/result.h"

namespace mooring {

std::size_t scan_result::count(severity s) const noexcept {
    std::size_t n = 0;
    for (auto const& f : findings) {
        if (f.sev == s) ++n;
    }
    return n;
}

std::size_t scan_result::count(category c) const noexcept {
    std::size_t n = 0;
    for (auto const& f : findings) {
        if (f.cat == c) ++n;
    }
    return n;
}

char const* to_string(severity s) noexcept {
    switch (s) {
        case severity::info:       return "info";
        case severity::suspicious: return "suspicious";
        case severity::critical:   return "critical";
    }
    return "unknown";
}

char const* to_string(category c) noexcept {
    switch (c) {
        case category::inline_hook:         return "inline_hook";
        case category::iat_hook:            return "iat_hook";
        case category::eat_hook:            return "eat_hook";
        case category::thread_origin:       return "thread_origin";
        case category::hidden_module:       return "hidden_module";
        case category::hardware_breakpoint: return "hardware_breakpoint";
        case category::debugger_present:    return "debugger_present";
        case category::veh_abuse:           return "veh_abuse";
        case category::suspicious_memory:   return "suspicious_memory";
    }
    return "unknown";
}

}  // namespace mooring
