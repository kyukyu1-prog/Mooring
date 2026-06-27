// hidden_module: walk the process address space with VirtualQuery
// and look for MEM_IMAGE allocations the loader doesn't know
// about.
//
// The signature this catches: a manually mapped PE that bypassed
// LdrLoadDll. The mapping is still flagged MEM_IMAGE by the
// memory manager (because it backs an image section), but the
// loader never linked it into PEB->Ldr, so PEB enumeration misses
// it entirely.
//
// We key on AllocationBase, not BaseAddress: a single mapped
// image produces multiple MEMORY_BASIC_INFORMATION regions (one
// per section, since they have different protections), but they
// all share an AllocationBase equal to the image's DllBase.
// Deduping on AllocationBase reports each hidden mapping once.

#include "mooring/detectors.h"
#include "mooring/internal/module_inventory.h"

#include <Windows.h>

#include <sstream>
#include <string>
#include <unordered_set>

namespace mooring::detectors {

namespace {

std::string addr_to_hex(std::uintptr_t a) {
    std::ostringstream oss;
    oss << "0x" << std::hex << a;
    return oss.str();
}

}  // namespace

void scan_hidden_modules(scan_result& out) {
    auto const known = enumerate_loaded_modules();

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);

    auto       address = reinterpret_cast<std::byte*>(si.lpMinimumApplicationAddress);
    auto const end     = reinterpret_cast<std::byte*>(si.lpMaximumApplicationAddress);

    std::unordered_set<std::uintptr_t> seen;

    while (address < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(address, &mbi, sizeof(mbi)) == 0) break;

        auto         region_base = reinterpret_cast<std::byte*>(mbi.BaseAddress);
        SIZE_T const region_size = mbi.RegionSize;

        bool const is_image = (mbi.Type  == MEM_IMAGE) &&
                              (mbi.State == MEM_COMMIT);

        if (is_image) {
            auto const alloc_base =
                reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);

            // First time we see this image. Subsequent sections of
            // the same image will share AllocationBase and skip.
            if (seen.insert(alloc_base).second &&
                !module_containing(known, alloc_base))
            {
                // Sniff the first two bytes to grade severity. An
                // intact 'MZ' header lifts the finding to
                // critical; a stripped header is suspicious (could
                // be a manually mapped image with the DOS stub
                // erased, or a quirky mapping the detector doesn't
                // model yet).
                bool has_mz = false;
                if (auto const* mz_base =
                        reinterpret_cast<std::byte const*>(mbi.AllocationBase);
                    mz_base && region_size >= 2)
                {
                    has_mz = mz_base[0] == std::byte{'M'} &&
                             mz_base[1] == std::byte{'Z'};
                }

                finding f;
                f.cat      = category::hidden_module;
                f.sev      = has_mz ? severity::critical
                                    : severity::suspicious;
                f.detector = "hidden_module";
                f.subject  = addr_to_hex(alloc_base);
                f.description = has_mz
                    ? "MEM_IMAGE region with PE header not "
                      "present in the loader module list "
                      "(manual mapping signature)."
                    : "MEM_IMAGE region not represented in the "
                      "loader module list; PE header stripped "
                      "or missing.";
                f.address = alloc_base;
                out.add(std::move(f));
            }
        }

        // Advance to the next region. Guard against zero-size
        // loops just in case VirtualQuery ever returns one — it
        // shouldn't, but a hung loop here is much worse than a
        // missed region.
        auto next = region_base + region_size;
        if (next <= address) break;
        address = next;
    }
}

}  // namespace mooring::detectors
