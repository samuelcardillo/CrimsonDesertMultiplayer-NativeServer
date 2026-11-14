#pragma once
// The rule of pivot_guard (pivot_guard.h), with no game access (tests: tests/optd_pivot_guard_tests.cpp).
//
// Builds 1.0.0.3527 and 1.0.0.3549 (the same code here; capstone on the PE, and the crash dump of 2026-11-05):
//   0x2205570  the handler of pa::StageChart_Function_ChangePivot, a virtual call from 0x2202C5E
//   0x22055F1  call 0x22038F0 (jmp 0xC80A6B0): fills its out argument, [rsp+0x70] the array of targets and [rsp+0x78] their
//              count, and returns 1 when the event's parameter is valid, however many targets it found
//   0x22055FC  mov r14,[rsp+0x70] ; test al,al ; jne 0x2205734
//   0x2205734  mov rax,[r14+8]    <- the element 0, with no look at the count: a read of 0x8 when there are none
//   0x22059FF  test r14,r14 ; je 0x2205ADA ; then frees the [rsp+0x78] elements of r14: the way out every other path of the
//              function takes, already correct for an empty result.
// Build 1.0.0.3576: the same function at +0xC40 (kSites3576 below); 1.0.0.3663 at +0x6FDE0 (kSites3663).

#include <cstddef>
#include <cstdint>

namespace cdmp::session2::pvg {

inline constexpr uintptr_t kPoint = 0x2205734, kLookupResult = 0x22055FC, kExit = 0x22059FF, kEntry = 0x2205570;
inline constexpr size_t kCountAtRsp = 0x78;
inline constexpr uint32_t kPatch = 8;
// mov rax,[r14+8] ; lea rdx,[rax+8]: two whole instructions, and no branch lands inside them: the function's only branch
// to this area is the jne to their start, and no rel32 of the code section lands in 0x2205735..0x220573F.
inline constexpr uint8_t kPointBytes[kPatch] = {0x49, 0x8B, 0x46, 0x08, 0x48, 0x8D, 0x50, 0x08};
inline constexpr uint8_t kLookupBytes[] = {0x4C, 0x8B, 0x74, 0x24, 0x70, 0x84, 0xC0, 0x0F, 0x85, 0x2B, 0x01, 0x00, 0x00};
inline constexpr uint8_t kExitBytes[] = {0x4D, 0x85, 0xF6, 0x0F, 0x84, 0xD2, 0x00, 0x00, 0x00};
inline constexpr uint8_t kEntryBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41};

// The four sites per build; the bytes above hold on both.
struct Sites {
    uintptr_t entry, lookup, point, exit;
};
inline constexpr Sites kSites3527{kEntry, kLookupResult, kPoint, kExit};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the whole handler moved by +0xC40 with the same bytes at the four
// sites. 0x22061B0 begins a .pdata entry (to 0x220674C); 0x2206231 calls 0x2204530 (3527's 0x22038F0 + 0xC40, a jmp into
// the protected section, as on 3527) right before the lookup's test; the virtual caller is 0x220389E (3527's 0x2202C5E +
// 0xC40, call [rax+0x40]). The function's only branch to the point is the jne at 0x2206243 to its start, and no rel32
// of the exe's executable sections lands in 0x2206375..0x220637B.
inline constexpr Sites kSites3576{0x22061B0, 0x220623C, 0x2206374, 0x220663F};
static_assert(kSites3576.lookup - kSites3576.entry == kLookupResult - kEntry &&
                  kSites3576.point - kSites3576.entry == kPoint - kEntry &&
                  kSites3576.exit - kSites3576.entry == kExit - kEntry,
              "3576: the same function, moved whole");
// Build 1.0.0.3663 (static, 2026-11-13; never run): the whole handler moved by +0x6F1A0 from 3576 (3527 + 0x6FDE0) with
// the same bytes at the four sites; the lookup's 13 bytes are unique near the shift. 0x2275350 begins a .pdata entry (to
// 0x22758EC, 0x59C bytes as on 3576); 0x22753D1 calls 0x22736D0 (a jmp into the protected section, as on 3527) right
// before the lookup's test; the virtual caller is 0x2272A3E (call [rax+0x40], in 0x2272840). The function's only rel32
// branch to the point is the jne at 0x22753E3 to its start, and no rel32 of the exe's executable sections lands in
// 0x2275515..0x227551B.
inline constexpr Sites kSites3663{0x2275350, 0x22753DC, 0x2275514, 0x22757DF};
static_assert(kSites3663.lookup - kSites3663.entry == kLookupResult - kEntry &&
                  kSites3663.point - kSites3663.entry == kPoint - kEntry &&
                  kSites3663.exit - kSites3663.entry == kExit - kEntry,
              "3663: the same function, moved whole");

// No target: the function's own way out (`exit_rva`: the build's), instead of reading the element 0 of nothing.
// Otherwise the native path, untouched.
template <class Context>
bool skip_no_targets(Context& ctx, uintptr_t base, uint32_t count, uintptr_t exit_rva = kExit) noexcept {
    if (ctx.r14 && count) return false;
    ctx.rip = base + exit_rva;
    return true;
}

}  // namespace cdmp::session2::pvg
