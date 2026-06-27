#pragma once

#include "result.h"

namespace mooring::detectors {

// Detect inline hooks by comparing in-memory prologues of exported
// functions against the on-disk PE image.
void scan_inline_hooks(scan_result& out);

// Detect IAT entries whose resolved address falls outside the
// exporting module's address range (classic IAT hook signature).
void scan_iat_hooks(scan_result& out);

// Detect threads whose start address does not lie within any module
// known to the loader.
void scan_thread_origins(scan_result& out);

// Detect MEM_IMAGE regions in the process address space that are
// not represented in the loader module list.
void scan_hidden_modules(scan_result& out);

// Detect non-zero hardware debug registers across all process threads
// other than the calling thread.
void scan_hardware_breakpoints(scan_result& out);

// Convenience: run every detector against the current process.
inline scan_result scan_self() {
    scan_result out;
    scan_inline_hooks(out);
    scan_iat_hooks(out);
    scan_thread_origins(out);
    scan_hidden_modules(out);
    scan_hardware_breakpoints(out);
    return out;
}

}  // namespace mooring::detectors
