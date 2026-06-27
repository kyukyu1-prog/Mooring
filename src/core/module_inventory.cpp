// Module enumeration via the in-process PEB.
//
// We deliberately do not use psapi's EnumProcessModules here. The
// hidden_module detector compares the loader's view of "what's
// mapped" against a raw address-space walk; if both views go
// through psapi they collapse into the same set and the
// comparison stops being useful. Reading the loader list directly
// via PEB->Ldr->InMemoryOrderModuleList gives us exactly the set
// the loader believes in.

#include "mooring/internal/module_inventory.h"

#include <Windows.h>
#include <winternl.h>

namespace mooring {

namespace {

// On x64 the PEB lives at gs:[0x60]; NtCurrentTeb()->ProcessEnvironmentBlock
// gives us the same pointer through the (documented-ish) winternl
// path without needing the intrinsic directly.
PEB* current_peb() noexcept {
    return reinterpret_cast<PEB*>(NtCurrentTeb()->ProcessEnvironmentBlock);
}

// Read SizeOfImage out of the PE header at DllBase. We can't take
// SizeOfImage from LDR_DATA_TABLE_ENTRY because the field isn't
// part of the public winternl layout — winternl truncates the
// struct and pads with Reserved fields.
std::size_t pe_image_size(void* base) noexcept {
    if (!base) return 0;
    auto const* bytes = static_cast<std::byte const*>(base);
    auto const* dos   = reinterpret_cast<IMAGE_DOS_HEADER const*>(bytes);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS const*>(
        bytes + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

std::wstring unicode_string_to_wstring(UNICODE_STRING const& us) {
    if (!us.Buffer || us.Length == 0) return {};
    return std::wstring(us.Buffer, us.Length / sizeof(wchar_t));
}

}  // namespace

std::vector<loaded_module> enumerate_loaded_modules() {
    std::vector<loaded_module> result;

    PEB* peb = current_peb();
    if (!peb || !peb->Ldr) return result;

    // NOTE: this walk is racy by design. The loader can be
    // mid-update on another thread (LdrLoadDll inserting an entry,
    // LdrUnloadDll removing one). We don't take the loader lock —
    // it isn't exposed by the public API and grabbing it from a
    // detector would be a much worse idea than the occasional
    // missed module. Callers are expected to tolerate transient
    // discrepancies and re-scan; see README.
    LIST_ENTRY const* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY const* it = head->Flink;
         it && it != head;
         it = it->Flink)
    {
        // CONTAINING_RECORD: given a pointer to InMemoryOrderLinks
        // inside an LDR_DATA_TABLE_ENTRY, recover the enclosing
        // struct. Standard pattern for walking Windows-style
        // intrusive lists.
        auto const* entry = CONTAINING_RECORD(
            it, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!entry->DllBase) continue;

        loaded_module m;
        m.base      = entry->DllBase;
        m.size      = pe_image_size(entry->DllBase);
        m.full_path = unicode_string_to_wstring(entry->FullDllName);

        // BaseDllName isn't in the public winternl layout, so
        // derive it from FullDllName. Good enough for the
        // case-insensitive name comparisons we do downstream.
        if (auto const sep = m.full_path.find_last_of(L"\\/");
            sep != std::wstring::npos)
        {
            m.name = m.full_path.substr(sep + 1);
        } else {
            m.name = m.full_path;
        }

        result.push_back(std::move(m));
    }

    return result;
}

loaded_module const* module_containing(
    std::vector<loaded_module> const& modules,
    std::uintptr_t addr) noexcept
{
    // Linear scan. For the module counts we see in practice (a few
    // dozen up to a couple hundred) this beats hashing on cost,
    // and keeps the function trivially noexcept.
    for (auto const& m : modules) {
        if (m.contains(addr)) return &m;
    }
    return nullptr;
}

}  // namespace mooring
