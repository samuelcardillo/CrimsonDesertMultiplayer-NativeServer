#include "mod/session2/pivot_guard.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/pivot_guard_logic.h"

namespace cdmp::session2 {
namespace {

constexpr uint64_t kLoggedTimes = 8;
constexpr uint32_t kStage = 0x10, kStageIdAndOwner = 0x30;  // processor -> stage -> u32 stage id, u32 owner's actor key

SafetyHookMid g_hook;
uintptr_t g_base = 0;
bool g_guest = false;
const pvg::Sites* g_sites = &pvg::kSites3527;  // set before the hook goes in
std::atomic<uint64_t> g_fired{0};

void on_point(safetyhook::Context& ctx) noexcept {
    uint32_t count = 0;
    if (!game::safe_read(ctx.rsp + pvg::kCountAtRsp, &count, sizeof count)) return;  // never decide on an unread count
    if (!pvg::skip_no_targets(ctx, g_base, count, g_sites->exit)) return;
    if (g_fired.fetch_add(1, std::memory_order_relaxed) >= kLoggedTimes) return;
    uintptr_t stage = 0;
    uint32_t id[2] = {};
    const bool known = game::safe_read(ctx.rbx + kStage, &stage, sizeof stage) && stage &&
                       game::safe_read(stage + kStageIdAndOwner, id, sizeof id);
    log::warn("PivotGuard: a ChangePivot with no target on this client (stage 0x{:X} of actor 0x{:08X}{}): skipped, this "
              "would have closed the game",
              id[0], id[1], known ? "" : ", unreadable");
}

bool code_is(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

DWORD WINAPI install_thread(void*) {
    const bool b3576 = game::current_build() == game::Build::v3576;
    const bool b3663 = game::current_build() == game::Build::v3663;
    const auto* profile = game::reader_profile();
    if (!b3576 && !b3663 && (!profile || game::current_build() != game::Build::v3527)) {
        log::info("PivotGuard: only for builds 3527, 3549, 3576 and 3663, off");
        return 0;
    }
    // 3576: the world slot 0x71C0100 (core_globals_3576.json; reader_profile() may have no 3576 entry yet).
    // Build 1.0.0.3663 (static, 2026-11-13; never run): the world slot 0x72451C0 (core_globals_3663.json, two AOB
    // patterns; 3195 RIP references in code).
    const uintptr_t world_slot = b3663 ? 0x72451C0 : b3576 ? 0x71C0100 : profile->world_system;
    g_sites = b3663 ? &pvg::kSites3663 : b3576 ? &pvg::kSites3576 : &pvg::kSites3527;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uintptr_t world = 0;
    while (!game::safe_read(g_base + world_slot, &world, sizeof world) || !world) Sleep(500);
    if (!code_is(g_sites->entry, pvg::kEntryBytes) || !code_is(g_sites->lookup, pvg::kLookupBytes) ||
        !code_is(g_sites->exit, pvg::kExitBytes)) {
        log::error("PivotGuard: the code around exe+0x{:X} is not the expected one; REFUSED, not hooked", g_sites->point);
        return 0;
    }
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("PivotGuard: the exe's sections are unreadable; REFUSED, not hooked");
        return 0;
    }
    if (p8_install_mid(g_base, secs, g_sites->point, pvg::kPatch, pvg::kPointBytes, &on_point, g_hook, "PivotGuard",
                       "ChangePivot's first read of its targets")) {
        log::info("PivotGuard ON ({}): a ChangePivot with no target leaves by its own way out (exe+0x{:X})",
                  g_guest ? "guest" : "host", g_sites->point);
    }
    return 0;
}

}  // namespace

void pivot_guard_start(bool enabled, bool guest) {
    if (!enabled) {
        log::info("PivotGuard: off in cdmp.ini (change_pivot_guard=0)");
        return;
    }
    g_guest = guest;
    if (const HANDLE t = CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr)) {
        CloseHandle(t);
    } else {
        log::error("PivotGuard: no thread ({}); not hooked", GetLastError());
    }
}

}  // namespace cdmp::session2
