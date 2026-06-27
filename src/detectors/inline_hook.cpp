// inline_hook: compare the prologue of every exported function in
// every loaded module against the on-disk PE image. Differences
// that match a known hook prologue pattern are reported.
//
// Why "looks like a jump" instead of "any difference":
//   - Windows patches a few ntdll syscall stubs at load time to
//     wire up the right syscall numbers for the running build.
//     The patched bytes are ordinary instructions, not jumps, so
//     the jump filter naturally excludes them.
//   - CFG and similar mitigations can rewrite small portions of
//     code at load time. Same story.
//   - A real hook installer (Detours, minHook, EasyHook, hand-
//     rolled) almost always lands on one of the patterns
//     enumerated in looks_like_jump below.
//
// Future work: stricter mode that reports any prologue diff at
// `suspicious` severity, for callers willing to triage the noise.

#include "mooring/detectors.h"
#include "mooring/internal/module_inventory.h"
#include "mooring/internal/pe_image.h"
#include "mooring/internal/strings.h"

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

namespace mooring::detectors {

namespace {

// Compare the first 5 bytes — enough to catch the canonical
// `JMP rel32` hook (E9 + 4 byte disp), which is the overwhelming
// majority of hooks seen in the wild. Larger windows catch more
// patterns but also pick up benign in-function differences that
// the jump filter would have to chase.
constexpr std::size_t kPrologueCompare = 5;

bool looks_like_jump(std::byte const* bytes, std::size_t len) noexcept {
    if (len < 1) return false;
    auto const b0 = static_cast<std::uint8_t>(bytes[0]);

    if (b0 == 0xE9) return true;                  // JMP rel32
    if (b0 == 0xEB) return true;                  // JMP rel8

    if (b0 == 0xFF && len >= 2) {
        auto const b1 = static_cast<std::uint8_t>(bytes[1]);
        if (b1 == 0x25) return true;              // JMP  [rip+disp32]
        if (b1 == 0x15) return true;              // CALL [rip+disp32]
        if ((b1 & 0xF8) == 0xE0) return true;     // JMP  r/m64 (reg form)
        if ((b1 & 0xF8) == 0xD0) return true;     // CALL r/m64 (reg form)
    }

    // PUSH imm32 (often followed by RET) — 6-byte absolute jump
    // trampoline. Showed up in classic Win32 hooking libraries.
    if (b0 == 0x68 && len >= 5) return true;

    // 64-bit absolute trampoline:
    //   48 B8 <imm64>          ; MOV RAX, imm64
    //   FF E0                  ; JMP RAX
    // 12 bytes total. Common in modern hookers because it doesn't
    // require a nearby code cave for a relative jump.
    if (len >= 12 && b0 == 0x48) {
        auto const b1  = static_cast<std::uint8_t>(bytes[1]);
        auto const b10 = static_cast<std::uint8_t>(bytes[10]);
        auto const b11 = static_cast<std::uint8_t>(bytes[11]);
        if (b1 == 0xB8 && b10 == 0xFF && b11 == 0xE0) return true;
    }

    return false;
}

void scan_module(loaded_module const& m, scan_result& out) {
    // Pull the on-disk image. Modules whose path we can't open
    // (KnownDlls mapped without a backing file we can CreateFile,
    // MOTW-blocked paths, weird unicode normalization) silently
    // skip; the detector falls back to checking only what it can.
    auto const disk_bytes = read_file_bytes(m.full_path);
    if (disk_bytes.empty()) return;

    pe_view disk(disk_bytes.data(), disk_bytes.size(),
                 /*is_loaded_image=*/false);
    pe_view loaded(reinterpret_cast<std::byte const*>(m.base), m.size,
                   /*is_loaded_image=*/true);

    if (!disk.valid() || !loaded.valid()) return;

    // Walk the in-memory export table — the authoritative list of
    // "things callers can land on first".
    auto const exports = loaded.exports();
    for (auto const& e : exports) {
        if (e.forwarded) continue;
        if (e.rva == 0)  continue;

        auto const* disk_ptr = disk  .rva_to_ptr(e.rva);
        auto const* mem_ptr  = loaded.rva_to_ptr(e.rva);
        if (!disk_ptr || !mem_ptr) continue;

        if (std::memcmp(disk_ptr, mem_ptr, kPrologueCompare) == 0) continue;
        if (!looks_like_jump(mem_ptr, 16)) continue;

        finding f;
        f.cat      = category::inline_hook;
        f.sev      = severity::critical;
        f.detector = "inline_hook";

        std::ostringstream subj;
        subj << wide_to_utf8(m.name) << "!";
        if (!e.name.empty()) {
            subj << e.name;
        } else {
            subj << "ord " << e.ordinal;
        }
        f.subject = subj.str();

        f.description =
            "In-memory prologue of export differs from on-disk image "
            "and matches a known hook prologue pattern.";
        f.address = reinterpret_cast<std::uintptr_t>(mem_ptr);
        out.add(std::move(f));
    }
}

}  // namespace

void scan_inline_hooks(scan_result& out) {
    auto const modules = enumerate_loaded_modules();
    for (auto const& m : modules) {
        scan_module(m, out);
    }
}

}  // namespace mooring::detectors
