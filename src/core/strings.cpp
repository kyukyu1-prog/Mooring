#include "mooring/internal/strings.h"

#include <Windows.h>

#include <cctype>

namespace mooring {

std::string wide_to_utf8(std::wstring const& w) {
    if (w.empty()) return {};

    int const required = ::WideCharToMultiByte(
        CP_UTF8, 0,
        w.data(), static_cast<int>(w.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};

    std::string out(static_cast<std::size_t>(required), '\0');
    int const written = ::WideCharToMultiByte(
        CP_UTF8, 0,
        w.data(), static_cast<int>(w.size()),
        out.data(), required, nullptr, nullptr);
    if (written != required) return {};
    return out;
}

std::string ascii_lower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

}  // namespace mooring
