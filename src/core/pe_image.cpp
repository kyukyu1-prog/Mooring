// Minimal PE walker.
//
// Supports two address conventions:
//   * loaded image — sections expanded to their virtual layout
//     (as the Windows loader maps them). RVA == offset from base.
//   * on-disk image — sections packed per FileAlignment. RVA must
//     be translated through the section table to find the file
//     offset.
//
// The pe_view's is_loaded_image flag picks which RVA-translation
// path applies. Mixing them up returns garbage; the rva_to_ptr
// edge cases below exist to catch the common slipups.

#include "mooring/internal/pe_image.h"

#include <Windows.h>

#include <cstring>

namespace mooring {

namespace {

IMAGE_NT_HEADERS const* nt_headers(std::byte const* base) noexcept {
    if (!base) return nullptr;
    auto const* dos = reinterpret_cast<IMAGE_DOS_HEADER const*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS const*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

// IMAGE_FIRST_SECTION takes a non-const pointer in <winnt.h>.
// We don't mutate the section table, so the cast is safe and the
// alternative (inlining the offset arithmetic) is uglier.
IMAGE_SECTION_HEADER const* section_headers(IMAGE_NT_HEADERS const* nt) noexcept {
    return IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(nt));
}

}  // namespace

bool pe_view::valid() const noexcept {
    if (!base_ || size_ < sizeof(IMAGE_DOS_HEADER)) return false;
    return nt_headers(base_) != nullptr;
}

std::vector<pe_section> pe_view::sections() const {
    std::vector<pe_section> out;
    auto const* nt = nt_headers(base_);
    if (!nt) return out;
    auto const* secs = section_headers(nt);

    out.reserve(nt->FileHeader.NumberOfSections);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto const& s = secs[i];

        pe_section ps;
        // Name is 8 bytes, NUL-terminated only if shorter than 8.
        // strnlen handles both cases without overrunning the field.
        auto const* name_bytes = reinterpret_cast<char const*>(s.Name);
        ps.name.assign(name_bytes,
                       ::strnlen(name_bytes, sizeof(s.Name)));
        ps.virtual_address = s.VirtualAddress;
        ps.virtual_size    = s.Misc.VirtualSize;
        ps.raw_address     = s.PointerToRawData;
        ps.raw_size        = s.SizeOfRawData;
        out.push_back(std::move(ps));
    }
    return out;
}

std::byte const* pe_view::rva_to_ptr(std::uint32_t rva) const noexcept {
    // RVA 0 means "no entry" in every context we use this from
    // (export slots, import descriptor lists). Returning a
    // pointer to the DOS header would be a footgun for callers.
    if (rva == 0) return nullptr;

    if (loaded_) {
        // Loaded image: virtual layout. RVA == offset from base.
        if (static_cast<std::size_t>(rva) >= size_) return nullptr;
        return base_ + rva;
    }

    // On-disk image: walk sections to translate RVA -> file offset.
    auto const* nt = nt_headers(base_);
    if (!nt) return nullptr;
    auto const* secs = section_headers(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto const& s = secs[i];
        std::uint32_t const v_end = s.VirtualAddress + s.Misc.VirtualSize;
        if (rva >= s.VirtualAddress && rva < v_end) {
            std::uint32_t const offset = rva - s.VirtualAddress;
            // If VirtualSize > SizeOfRawData (uninitialized BSS-like
            // tail), the tail of the section doesn't exist on disk.
            // Caller's problem; null is the right answer.
            if (offset >= s.SizeOfRawData) return nullptr;
            std::uint32_t const file_offset = s.PointerToRawData + offset;
            if (file_offset >= size_) return nullptr;
            return base_ + file_offset;
        }
    }
    return nullptr;
}

std::vector<pe_export> pe_view::exports() const {
    std::vector<pe_export> out;
    auto const* nt = nt_headers(base_);
    if (!nt) return out;

    auto const& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return out;

    auto const* dir_ptr = rva_to_ptr(dir.VirtualAddress);
    if (!dir_ptr) return out;
    auto const* exp_dir =
        reinterpret_cast<IMAGE_EXPORT_DIRECTORY const*>(dir_ptr);

    auto const* functions_ptr = rva_to_ptr(exp_dir->AddressOfFunctions);
    auto const* names_ptr     = rva_to_ptr(exp_dir->AddressOfNames);
    auto const* ordinals_ptr  = rva_to_ptr(exp_dir->AddressOfNameOrdinals);
    if (!functions_ptr) return out;

    auto const* functions = reinterpret_cast<std::uint32_t const*>(functions_ptr);
    auto const* names     = reinterpret_cast<std::uint32_t const*>(names_ptr);
    auto const* ordinals  = reinterpret_cast<std::uint16_t const*>(ordinals_ptr);

    // Build ordinal-index -> name map first. The on-disk export
    // table has names in a separate array indexed by name ordinal;
    // doing this in one pre-pass keeps the main loop simple.
    std::vector<std::string> ordinal_names(exp_dir->NumberOfFunctions);
    if (names && ordinals) {
        for (std::uint32_t i = 0; i < exp_dir->NumberOfNames; ++i) {
            std::uint16_t const ord = ordinals[i];
            if (ord >= exp_dir->NumberOfFunctions) continue;
            auto const* name_ptr = rva_to_ptr(names[i]);
            if (!name_ptr) continue;
            ordinal_names[ord] = reinterpret_cast<char const*>(name_ptr);
        }
    }

    out.reserve(exp_dir->NumberOfFunctions);
    for (std::uint32_t i = 0; i < exp_dir->NumberOfFunctions; ++i) {
        std::uint32_t const rva = functions[i];
        if (rva == 0) continue;  // empty slot

        pe_export e;
        e.ordinal = static_cast<std::uint16_t>(i + exp_dir->Base);
        e.rva     = rva;
        e.name    = ordinal_names[i];

        // Forwarders: the RVA points back into the export
        // directory itself, where the bytes are an ASCII
        // "TargetDll.Function" string rather than executable
        // code. Skip these in prologue checks.
        e.forwarded = (rva >= dir.VirtualAddress &&
                       rva <  dir.VirtualAddress + dir.Size);
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<std::byte> read_file_bytes(std::wstring const& path) {
    std::vector<std::byte> data;

    // FILE_SHARE_READ|WRITE|DELETE because:
    //   - the loader has the file mapped as an image section,
    //   - some installers / updaters hold the file open for
    //     writing while patching modules in place.
    // We want to read regardless of who else has it open.
    HANDLE h = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) return data;

    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart <= 0) {
        ::CloseHandle(h);
        return data;
    }

    // Sanity cap. No legitimate Windows module is this large;
    // refusing to allocate hundreds of megabytes is the safer
    // default if we ever encounter a hostile loader entry pointing
    // at a giant file.
    constexpr long long kMaxBytes = 256ll << 20;
    if (size.QuadPart > kMaxBytes) {
        ::CloseHandle(h);
        return data;
    }

    data.resize(static_cast<std::size_t>(size.QuadPart));

    DWORD read = 0;
    BOOL const ok = ::ReadFile(
        h, data.data(),
        static_cast<DWORD>(data.size()), &read, nullptr);
    ::CloseHandle(h);

    if (!ok || read != data.size()) {
        data.clear();
    }
    return data;
}

}  // namespace mooring
