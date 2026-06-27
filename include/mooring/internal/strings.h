#pragma once

#include <string>

namespace mooring {

// UTF-16 -> UTF-8 via WideCharToMultiByte. Empty result on failure.
std::string wide_to_utf8(std::wstring const& w);

// In-place ASCII lowercasing (non-ASCII bytes are left untouched).
std::string ascii_lower(std::string s);

}  // namespace mooring
