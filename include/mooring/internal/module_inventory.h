#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mooring {

// Snapshot of a single module known to the Windows loader at scan
// time. Populated by walking PEB->Ldr->InMemoryOrderModuleList.
struct loaded_module {
    void*       base      = nullptr;  // image base in the host process
    std::size_t size      = 0;        // SizeOfImage from PE header
    std::wstring name;                // BaseDllName, e.g. L"kernel32.dll"
    std::wstring full_path;           // FullDllName

    std::uintptr_t base_addr() const noexcept {
        return reinterpret_cast<std::uintptr_t>(base);
    }
    std::uintptr_t end_addr() const noexcept {
        return base_addr() + size;
    }
    bool contains(std::uintptr_t addr) const noexcept {
        return addr >= base_addr() && addr < end_addr();
    }
};

// Walk the loader module list of the current process.
std::vector<loaded_module> enumerate_loaded_modules();

// Linear search for the module containing `addr`. Returns nullptr if
// no module contains the address.
loaded_module const* module_containing(
    std::vector<loaded_module> const& modules,
    std::uintptr_t addr) noexcept;

}  // namespace mooring
