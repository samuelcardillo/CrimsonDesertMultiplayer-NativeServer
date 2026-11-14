#include "mod/session2/report_guard.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstring>
#include <format>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"

namespace cdmp::session2 {
namespace {

// 0x1317D40: mov [rsp+10],rbx; push rbp/rsi/rdi/r12/r13/r14/r15
// (docs/research/data/rpt0-estatico.md, checked by hand).
constexpr uintptr_t kReporter = 0x1317D40;
constexpr uint8_t kReporterHead[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57,
                                     0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
// Build 1.0.0.3527. The complete 32-byte entry is unique in the executable;
// the stack frame and first three argument moves preserve reporter_detour's ABI.
constexpr uintptr_t kReporter3527 = 0x14F75E0;
constexpr uint8_t kReporter3527Head[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41,
    0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00,
    0x00, 0x4D, 0x8B, 0xF0, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xD9};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the same 32 bytes moved by +0x820, still unique in the
// executable and a .pdata entry (0x14F7E00..0x14F7FD0); the body is the same Sentry reporter (its "Project" /
// "app_build" tags, the attachment loop, the same [rcx] "Sentry up" check first).
constexpr uintptr_t kReporter3576 = 0x14F7E00;
// Build 1.0.0.3663 (static, 2026-11-13; never run): the same 32 bytes, unique in the code section, at 0x1536D20
// (3576 +0x3EF20), a .pdata entry of the same 0x1D0 bytes (0x1536D20..0x1536EF0); the same Sentry reporter: the
// [rcx] "Sentry up" check first, the "Project" and "Message" tags, "[Pentry] sendMessageEvent".
constexpr uintptr_t kReporter3663 = 0x1536D20;
constexpr uint32_t kMaxPaths = 8;
constexpr size_t kMaxText = 260;
constexpr uint64_t kMaxLogged = 16;  // a broken loop must not flood the log

SafetyHookInline g_hook;
std::atomic<bool> g_active{false};
std::atomic<uint64_t> g_dropped{0};
std::atomic<uint64_t> g_dropped_live{0};

struct ReporterProfile {
    uintptr_t rva;
    const uint8_t* head;
    size_t head_size;
};

ReporterProfile reporter_profile() noexcept {
    switch (game::current_build()) {
        case game::Build::v2976: return {kReporter, kReporterHead, sizeof kReporterHead};
        case game::Build::v3527: return {kReporter3527, kReporter3527Head, sizeof kReporter3527Head};
        case game::Build::v3576: return {kReporter3576, kReporter3527Head, sizeof kReporter3527Head};
        case game::Build::v3663: return {kReporter3663, kReporter3527Head, sizeof kReporter3527Head};
        default: return {};
    }
}

// A NUL-terminated string at p, up to kMaxText bytes, page by page.
std::string read_text(uintptr_t p) {
    if (!p) return "(null)";
    std::string s;
    char c = 0;
    while (s.size() < kMaxText) {
        if (!game::safe_read(p + s.size(), &c, 1)) return s + "(unreadable)";
        if (!c) return s;
        s += c;
    }
    return s + "...";
}

void __fastcall reporter_detour(uint8_t* active, const char* reason, const ReportFiles* files) noexcept {
    // Never calls the original: nothing reaches Sentry while this is on. The
    // game's own first check (0x1317D60) is whether Sentry is up.
    uint8_t live = 0;
    const bool known = active && game::safe_read(reinterpret_cast<uintptr_t>(active), &live, 1);
    const uint64_t n = g_dropped.fetch_add(1) + 1;
    if (live) g_dropped_live.fetch_add(1);
    if (n > kMaxLogged) return;
    try {
        log::warn("Session2 report guard: the game asked for an error report (#{}, {}); NOT sent: {}", n,
                  !known  ? "Sentry state unreadable"
                  : live ? "Sentry was ON: it would have gone to Pearl Abyss"
                         : "Sentry was off: the game would not have sent it either",
                  report_describe(reason, files));
    } catch (...) {
    }
}

}  // namespace

std::string report_describe(const char* reason, const ReportFiles* files) {
    std::string s = std::format("reason '{}'", read_text(reinterpret_cast<uintptr_t>(reason)));
    ReportFiles v{};
    if (!files || !game::safe_read(reinterpret_cast<uintptr_t>(files), &v, sizeof v)) return s + ", files unreadable";
    s += std::format(", {} file{}", v.count, v.count == 1 ? "" : "s");
    for (uint32_t i = 0; i < v.count && i < kMaxPaths; ++i) {
        // element -> object -> char* path
        auto obj = game::read<uintptr_t>(reinterpret_cast<uintptr_t>(v.data) + i * sizeof(void*));
        auto path = obj && *obj ? game::read<uintptr_t>(*obj) : std::nullopt;
        s += i ? " | " : ": ";
        s += path ? read_text(*path) : "(unreadable)";
    }
    if (v.count > kMaxPaths) s += " | ...";
    return s;
}

bool report_guard_install_at(void* target, const uint8_t* head, size_t head_size) {
    if (g_active.load()) return true;  // the head is ours now: no second check
    uint8_t actual[32] = {};
    if (!target || head_size > sizeof actual ||
        !game::safe_read(reinterpret_cast<uintptr_t>(target), actual, head_size) ||
        std::memcmp(actual, head, head_size) != 0) {
        return false;
    }
    g_hook = safetyhook::create_inline(target, reinterpret_cast<void*>(&reporter_detour),
                                       SafetyHookInline::StartDisabled);
    if (!g_hook || !g_hook.enable()) {
        g_hook = {};
        return false;
    }
    g_active.store(true);
    return true;
}

bool report_guard_try_install() {
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto p = reporter_profile();
    return p.rva && report_guard_install_at(reinterpret_cast<void*>(base + p.rva), p.head, p.head_size);
}

uintptr_t report_guard_target_rva() { return reporter_profile().rva; }

bool report_guard_install() {
    if (g_active.load()) return true;
    if (!report_guard_try_install()) {
        log::error("Session2 report guard: the game's error reporter (exe+0x{:X}) is not the expected code or "
                   "cannot be hooked; option D stays off",
                   report_guard_target_rva());
        return false;
    }
    log::info("Session2 report guard ON: the game's error reports with files (failed saves) are not sent "
              "until the game closes (exe+0x{:X})",
              report_guard_target_rva());
    return true;
}

bool report_guard_active() { return g_active.load(); }
uint64_t report_guard_dropped() { return g_dropped.load(); }
uint64_t report_guard_dropped_live() { return g_dropped_live.load(); }

}  // namespace cdmp::session2
