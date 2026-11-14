#include "mod/game/game_errors.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>

#include <safetyhook.hpp>

#include "mod/game/build_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/game/seq_ring.h"
#include "mod/log.h"

namespace cdmp::game {
namespace {
namespace off = build_2976;

// Entry of the logger: arguments 10-13 on the stack ([rsp] = return address).
// Seen at a call site (0x35AED1..0x35AF10): arg10 dword = code, arg11 dword =
// severity, arg12 = const char* message (printf format), arg13 = first value.
constexpr uintptr_t kErrorLogger = 0x35D8D0;
constexpr uint8_t kErrorLoggerHead[] = {0xE9};  // starts with a jmp into .xtls
// 1.0.0.3527: a plain function, no Denuvo jmp, 2640 call sites with the same arguments
// (0x2427710..0x2427753: [rsp+48] code, [rsp+50] severity, [rsp+58] text at the call).
constexpr uintptr_t kErrorLogger3527 = 0x3A7380;
constexpr uint8_t kErrorLoggerHead3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x20};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): moved by +0x2E0 with the same head (a .pdata function start, the
// only match near), and again exactly 2640 call sites passing [rsp+48] code, [rsp+50] severity, [rsp+58] text
// (e.g. 0xC754E4..0xC75524).
constexpr uintptr_t kErrorLogger3576 = 0x3A7660;
// Build 1.0.0.3663 (static, 2026-11-13; never run): 0x3AACB0 = 3576's +0x3650 (the shift of the client's network code
// next to it, profile_s2.h), with the same 15-byte head, a .pdata function start (0x3AACB0..0x3AADEA) and 2634 call
// sites (3576: 2640); 38 of 40 sampled callers store [rsp+48] code, [rsp+50] severity, [rsp+58] text before the call.
constexpr uintptr_t kErrorLogger3663 = 0x3AACB0;
constexpr uint32_t kArgCode = 0x50, kArgSeverity = 0x58, kArgText = 0x60, kArgValue = 0x68;
constexpr int kExtraValues = 3;  // arguments 14-16 (more format values, if any)

struct Entry {
    uintptr_t caller;
    uint32_t code;
    uint32_t severity;
    uint64_t value;
    uint64_t extra[kExtraValues];
    char text[160];
};
SafetyHookMid g_hook;
safetyhook::Allocation g_stub;  // our own copy of the logger's leading jmp, hooked instead
SRWLOCK g_lock = SRWLOCK_INIT;
Entry g_ring[32];
uint32_t g_count = 0;
uint64_t g_lost = 0;
uintptr_t g_base = 0;

bool copy_entry(uint64_t rsp, Entry& e) {
    __try {
        e.caller = *reinterpret_cast<const uintptr_t*>(rsp);
        e.code = *reinterpret_cast<const uint32_t*>(rsp + kArgCode);
        e.severity = *reinterpret_cast<const uint32_t*>(rsp + kArgSeverity);
        e.value = *reinterpret_cast<const uint64_t*>(rsp + kArgValue);
        for (int k = 0; k < kExtraValues; ++k) {
            e.extra[k] = *reinterpret_cast<const uint64_t*>(rsp + kArgValue + 8 + 8 * k);
        }
        const char* text = *reinterpret_cast<const char* const*>(rsp + kArgText);
        size_t i = 0;
        if (text) {
            for (; i + 1 < sizeof e.text && text[i]; ++i) e.text[i] = text[i];
        }
        e.text[i] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// P8 session 8 pets: CreateOwnedActor 0x8AF580 failed (0x8BD530's branch 0x8BDC4A, its report call
// 0x8BDF77 returns to 0x8BDF7C). Counted here, lock-free: the drained line is deduplicated after 10.
constexpr uintptr_t kActorCreateFailedFrom = 0x8BDF7C;
std::atomic<uint64_t> g_create_failed_value{0};
// P8 session 9 (child_reannounce): every failure's value in order (0 when none had the owner/actor form); its
// count is the failure count.
SeqRing<16> g_fail_ring;
std::atomic<bool> g_installed{false};

void on_error(safetyhook::Context& ctx) {
    Entry e;
    if (!copy_entry(ctx.rsp, e)) return;
    // 2976's return address only (never ported to 3527 / 3576 / 3663).
    if (g_base && current_build() == Build::v2976 && e.caller == g_base + kActorCreateFailedFrom) {
        uint64_t found = 0;
        const uint64_t vals[] = {e.value, e.extra[0], e.extra[1], e.extra[2]};
        for (const uint64_t v : vals) {
            if ((v >> 60) == 0x9 && ((v >> 28) & 0xF) == 0xB) {
                g_create_failed_value.store(v, std::memory_order_relaxed);
                found = v;
                break;
            }
        }
        g_fail_ring.push(found);  // its index from its own fetch_add (seq_ring.h)
    }
    if (!TryAcquireSRWLockExclusive(&g_lock)) {
        ++g_lost;
        return;
    }
    if (g_count < 32) g_ring[g_count++] = e;
    else ++g_lost;
    ReleaseSRWLockExclusive(&g_lock);
}

}  // namespace

bool game_errors_install() {
    if (g_hook) return true;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (current_build() == Build::v3527 || current_build() == Build::v3576 || current_build() == Build::v3663) {
        // The same plain function on all three (3576: kErrorLogger3576, 3663: kErrorLogger3663).
        const bool is3576 = current_build() == Build::v3576;
        const bool is3663 = current_build() == Build::v3663;
        const uintptr_t logger = is3663 ? kErrorLogger3663 : is3576 ? kErrorLogger3576 : kErrorLogger3527;
        const char* const name = is3663 ? "3663" : is3576 ? "3576" : "3527";
        uint8_t head3527[sizeof kErrorLoggerHead3527]{};
        if (!safe_read(g_base + logger, head3527, sizeof head3527) ||
            std::memcmp(head3527, kErrorLoggerHead3527, sizeof head3527) != 0) {
            log::warn("Game errors: {} logger not recognised; not hooked", name);
            return false;
        }
        auto hooked = safetyhook::MidHook::create(reinterpret_cast<void*>(g_base + logger), on_error);
        if (!hooked) {
            log::warn("Game errors: could not hook the {} logger", name);
            return false;
        }
        g_hook = std::move(*hooked);
        g_installed.store(true, std::memory_order_release);
        log::info("Game errors: hook installed at {} logger exe+0x{:X} (the game's internal errors go to this log)", name,
                  logger);
        return true;
    }
    // Only 2976 reaches the jmp-stub path below; any other build is refused (its byte at kErrorLogger means nothing).
    if (current_build() != Build::v2976) {
        log::warn("Game errors: unsupported game build; not hooked");
        return false;
    }
    uint8_t head[1];
    if (g_base != off::kImageBase || !safe_read(g_base + kErrorLogger, head, 1) || head[0] != kErrorLoggerHead[0]) {
        log::warn("Game errors: logger not recognised; not hooked");
        return false;
    }
    auto* target = reinterpret_cast<uint8_t*>(g_base + kErrorLogger);
    auto direct = safetyhook::MidHook::create(target, on_error);
    if (direct) {
        g_hook = std::move(*direct);
        g_installed.store(true, std::memory_order_release);
        log::info("Game errors: hook installed (the game's internal errors go to this log)");
        return true;
    }
    log::info("Game errors: direct hook not possible (safetyhook error {}, inline {}); using a stub",
              static_cast<int>(direct.error().type),
              direct.error().type == safetyhook::MidHook::Error::BAD_INLINE_HOOK
                  ? static_cast<int>(direct.error().inline_hook_error.type)
                  : -1);

    // The logger is a lone `jmp rel32` into Denuvo's .xtls. Copy that jmp into
    // memory of ours near it, hook the copy (clean bytes), then point the
    // original jmp at the copy. Only 4 bytes of the game change.
    int32_t rel = 0;
    std::memcpy(&rel, target + 1, 4);
    uint8_t* const dest = target + 5 + rel;
    auto alloc = safetyhook::Allocator::global()->allocate_near({target}, 32);
    if (!alloc) {
        log::warn("Game errors: no memory near the logger; not hooked");
        return false;
    }
    g_stub = std::move(*alloc);
    uint8_t* stub = g_stub.data();
    const int64_t to_dest = dest - (stub + 5);
    const int64_t to_stub = stub - (target + 5);
    if (to_dest != static_cast<int32_t>(to_dest) || to_stub != static_cast<int32_t>(to_stub)) {
        log::warn("Game errors: stub out of jmp range; not hooked");
        return false;
    }
    std::memset(stub, 0xCC, 32);
    stub[0] = 0xE9;
    const int32_t r1 = static_cast<int32_t>(to_dest);
    std::memcpy(stub + 1, &r1, 4);
    auto hooked = safetyhook::MidHook::create(stub, on_error);
    if (!hooked) {
        log::warn("Game errors: could not hook the stub either; not hooked");
        return false;
    }
    g_hook = std::move(*hooked);
    // The game is running: rewrite the jmp's rel32 with every other thread
    // suspended (safetyhook's own freeze), so none can fetch a torn target.
    bool written = false;
    safetyhook::trap_threads(target, target, 5, [&] {
        DWORD old = 0;
        if (!VirtualProtect(target + 1, 4, PAGE_EXECUTE_READWRITE, &old)) return;
        const int32_t r2 = static_cast<int32_t>(to_stub);
        std::memcpy(target + 1, &r2, 4);
        VirtualProtect(target + 1, 4, old, &old);
        FlushInstructionCache(GetCurrentProcess(), target, 5);
        written = true;
    });
    if (!written) {
        log::warn("Game errors: cannot write the logger's jmp; not hooked");
        return false;
    }
    g_installed.store(true, std::memory_order_release);
    log::info("Game errors: hook installed through a stub (the game's internal errors go to this log)");
    return true;
}

uint64_t game_errors_actor_create_failures(uint64_t* last_value) {
    if (last_value) *last_value = g_create_failed_value.load(std::memory_order_relaxed);
    return g_fail_ring.count();
}

size_t game_errors_actor_create_failures_since(uint64_t& cursor, uint64_t* values, size_t max, uint64_t* lost) {
    return g_fail_ring.read(cursor, values, max, lost);
}

bool game_errors_installed() { return g_installed.load(std::memory_order_acquire); }

void game_errors_drain() {
    if (!g_hook) return;
    Entry local[32];
    uint32_t n = 0;
    uint64_t lost = 0;
    AcquireSRWLockExclusive(&g_lock);
    n = g_count;
    std::memcpy(local, g_ring, sizeof(Entry) * n);
    g_count = 0;
    lost = g_lost;
    ReleaseSRWLockExclusive(&g_lock);

    static std::map<std::string, int> seen;
    static uint64_t logged = 0, reported_lost = 0;
    for (uint32_t i = 0; i < n; ++i) {
        const Entry& e = local[i];
        const uintptr_t rva = e.caller >= g_base ? e.caller - g_base : e.caller;
        const std::string id = std::to_string(rva) + "|" + e.text;
        if (logged >= 400 || ++seen[id] > 10) continue;  // each distinct error up to 10 times
        ++logged;
        log::info("Game error: \"{}\" (values 0x{:X} 0x{:X} 0x{:X} 0x{:X}, code {}, severity {}, from exe+0x{:X})",
                  e.text, e.value, e.extra[0], e.extra[1], e.extra[2], e.code, e.severity, rva);
    }
    if (lost != reported_lost) {
        log::info("Game errors: {} not copied (busy)", lost);
        reported_lost = lost;
    }
}

}  // namespace cdmp::game
