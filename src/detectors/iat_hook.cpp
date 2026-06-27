// iat_hook: walk every loaded module's import table and check
// where each resolved IAT entry actually points.
//
// Two findings shapes:
//   critical    — the resolved address belongs to no loaded module
//                 at all. Classic injected-DLL signature: the
//                 injector points the IAT slot at its own code.
//   suspicious  — the resolved address belongs to a module other
//                 than the one the import descriptor names. Same
//                 shape as a hook, but legitimate forwarded
//                 exports and api-ms-win-* apiset redirection
//                 also produce it, so it gets the lower grade.
//
// Bound binaries (OriginalFirstThunk == 0) lose their import
// names. We still verify addresses for those, but the import
// name shown in the finding is the placeholder "(bound, name
// unavailable)" rather than something invented.

#include "mooring/detectors.h"
#include "mooring/internal/module_inventory.h"
#include "mooring/internal/strings.h"

#include <Windows.h>

#include <cstdint>
#include <sstream>
#include <string>

namespace mooring::detectors {

namespace {

std::string format_import_name(
    IMAGE_THUNK_DATA const* orig_thunk,
    std::byte const*        module_base,
    bool                    has_oft)
{
    if (!has_oft) {
        return "(bound, name unavailable)";
    }
    if ((orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0) {
        std::ostringstream oss;
        oss << "ordinal " << (orig_thunk->u1.Ordinal & 0xFFFF);
        return oss.str();
    }
    auto const* by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME const*>(
        module_base + orig_thunk->u1.AddressOfData);
    return reinterpret_cast<char const*>(by_name->Name);
}

void scan_module(
    loaded_module const&              target,
    std::vector<loaded_module> const& all,
    scan_result&                      out)
{
    if (!target.base || target.size == 0) return;

    auto const* base = static_cast<std::byte const*>(target.base);
    auto const* dos  = reinterpret_cast<IMAGE_DOS_HEADER const*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS const*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto const& imp_dir = nt->OptionalHeader
                              .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) return;

    auto const* descs = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR const*>(
        base + imp_dir.VirtualAddress);

    std::string const target_name_utf8 = wide_to_utf8(target.name);

    for (; descs->Name != 0; ++descs) {
        auto const* dll_name = reinterpret_cast<char const*>(
            base + descs->Name);
        std::string const expected_dll(dll_name);

        // OriginalFirstThunk holds the original import-by-name /
        // import-by-ordinal entries; FirstThunk is the IAT itself
        // (resolved addresses at runtime). When the binary is
        // bound, OFT is zeroed and only FT is meaningful.
        bool  const has_oft         = (descs->OriginalFirstThunk != 0);
        DWORD const first_thunk_rva = descs->FirstThunk;
        DWORD const orig_thunk_rva  = has_oft ? descs->OriginalFirstThunk
                                              : descs->FirstThunk;
        if (first_thunk_rva == 0 || orig_thunk_rva == 0) continue;

        auto const* thunk = reinterpret_cast<IMAGE_THUNK_DATA const*>(
            base + first_thunk_rva);
        auto const* orig_thunk = reinterpret_cast<IMAGE_THUNK_DATA const*>(
            base + orig_thunk_rva);

        for (; thunk->u1.Function != 0; ++thunk, ++orig_thunk) {
            auto const resolved =
                static_cast<std::uintptr_t>(thunk->u1.Function);

            auto const* containing = module_containing(all, resolved);
            std::string const import_name =
                format_import_name(orig_thunk, base, has_oft);

            // Case 1: outside every module. Definite redirection,
            // either to a hidden module's code or to a stand-alone
            // RWX region used as a hook trampoline.
            if (!containing) {
                finding f;
                f.cat      = category::iat_hook;
                f.sev      = severity::critical;
                f.detector = "iat_hook";

                std::ostringstream subj;
                subj << target_name_utf8 << " -> "
                     << expected_dll << "!" << import_name;
                f.subject = subj.str();
                f.description =
                    "IAT entry resolves to an address outside every "
                    "loaded module.";
                f.address = resolved;
                out.add(std::move(f));
                continue;
            }

            // Case 2: inside *some* module but the wrong one.
            // Most common cause is a forwarded export legitimately
            // resolving into the implementing DLL (kernel32 ->
            // kernelbase forwarders are everywhere). Hence
            // severity::suspicious.
            std::string const containing_name_utf8 =
                wide_to_utf8(containing->name);
            if (ascii_lower(containing_name_utf8) !=
                ascii_lower(expected_dll))
            {
                finding f;
                f.cat      = category::iat_hook;
                f.sev      = severity::suspicious;
                f.detector = "iat_hook";

                std::ostringstream subj;
                subj << target_name_utf8 << " -> "
                     << expected_dll << "!" << import_name;
                f.subject = subj.str();

                std::ostringstream desc;
                desc << "IAT entry resolves into "
                     << containing_name_utf8
                     << " rather than the descriptor's "
                     << expected_dll
                     << "; could be a forwarded export or an IAT hook.";
                f.description = desc.str();
                f.address = resolved;
                out.add(std::move(f));
            }
        }
    }
}

}  // namespace

void scan_iat_hooks(scan_result& out) {
    auto const modules = enumerate_loaded_modules();
    for (auto const& m : modules) {
        scan_module(m, modules, out);
    }
}

}  // namespace mooring::detectors
