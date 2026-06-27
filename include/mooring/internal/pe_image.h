#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mooring {

struct pe_section {
    std::string name;             // up to 8 chars, null-trimmed
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size    = 0;
    std::uint32_t raw_address     = 0;
    std::uint32_t raw_size        = 0;
};

struct pe_export {
    std::string   name;           // empty for ordinal-only exports
    std::uint16_t ordinal   = 0;
    std::uint32_t rva       = 0;
    bool          forwarded = false;
};

// A non-owning view over a PE image, either as the Windows loader
// has mapped it into memory or as it sits on disk.
class pe_view {
public:
    pe_view(std::byte const* base, std::size_t size, bool is_loaded_image) noexcept
        : base_(base), size_(size), loaded_(is_loaded_image) {}

    bool valid() const noexcept;

    std::byte const* base() const noexcept { return base_; }
    std::size_t      size() const noexcept { return size_; }
    bool             is_loaded_image() const noexcept { return loaded_; }

    std::vector<pe_section> sections() const;
    std::vector<pe_export>  exports() const;

    // Translate an RVA into a pointer inside this view, taking into
    // account whether the image is on-disk (sections must be walked)
    // or already in memory (RVA == VA - base).
    std::byte const* rva_to_ptr(std::uint32_t rva) const noexcept;

private:
    std::byte const* base_;
    std::size_t      size_;
    bool             loaded_;
};

// Read an entire file into memory. Returned vector is empty on
// failure or for files larger than the internal sanity cap.
std::vector<std::byte> read_file_bytes(std::wstring const& path);

}  // namespace mooring
