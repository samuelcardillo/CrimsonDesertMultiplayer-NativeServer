#include "mod/session2/achievement_guard.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/achievement_guard_logic.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

constexpr uint64_t kLoggedTimes = 12;
constexpr size_t kNameMax = 64;

// The build's addresses (achievement_guard_logic.h): 3527/3549, 3576 and 3663.
struct Addrs {
    uintptr_t world_system, vt_steam_manager, unlock, point, way_out;
    std::span<const uint8_t> way_out_bytes;
};
// 3576: the world slot from core_globals_3576.json (reader_profile() is null on 3576).
constexpr Addrs k3576{0x71C0100, agd::kVtSteamManager3576, agd::kUnlock3576, agd::kPoint3576, agd::kWayOut3576,
                      agd::kWayOutBytes3576};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the world slot 0x72451C0 (profile_s2.h; two AOB patterns).
constexpr Addrs k3663{0x72451C0, agd::kVtSteamManager3663, agd::kUnlock3663, agd::kPoint3663, agd::kWayOut3663,
                      agd::kWayOutBytes3663};

SafetyHookMid g_hook;
uintptr_t g_base = 0;
uintptr_t g_way_out = agd::kWayOut;  // written before the hook goes in, then read only
std::atomic<bool> g_blocked{false};
std::atomic<uint64_t> g_skipped{0};

// The achievement's name, [[r8]] (a C string), for the log only.
std::string name_of(uintptr_t key) noexcept {
    uintptr_t holder = 0, text = 0;
    char buf[kNameMax + 1] = {};
    if (!key || !game::safe_read(key, &holder, sizeof holder) || !holder ||
        !game::safe_read(holder, &text, sizeof text) || !text) {
        return "?";
    }
    for (size_t i = 0; i < kNameMax; ++i) {
        if (!game::safe_read(text + i, &buf[i], 1) || buf[i] == 0) break;
        if (buf[i] < 0x20 || buf[i] > 0x7E) buf[i] = '?';
    }
    return buf;
}

void on_point(safetyhook::Context& ctx) noexcept {
    // Sticky: once remote, for the rest of this process (agd::Gate, written with an atomic here).
    if (!g_blocked.load(std::memory_order_relaxed) && guest_remote_live()) g_blocked.store(true, std::memory_order_relaxed);
    const uintptr_t key = ctx.r8;
    if (!agd::skip_unlock(ctx, g_base, g_blocked.load(std::memory_order_relaxed), g_way_out)) return;
    if (g_skipped.fetch_add(1, std::memory_order_relaxed) >= kLoggedTimes) return;
    try {
        log::info("AchievementGuard: Steam achievement '{}' NOT unlocked: this game has played in the host's world, whose "
                  "progress is not this player's (until the game is restarted)",
                  name_of(key));
    } catch (...) {
    }
}

bool code_is(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

DWORD WINAPI install_thread(void*) {
    const auto* profile = game::reader_profile();
    Addrs a{};
    if (game::current_build() == game::Build::v3663) {
        a = k3663;
    } else if (game::current_build() == game::Build::v3576) {
        a = k3576;
    } else if (profile && game::current_build() == game::Build::v3527) {
        a = {profile->world_system, agd::kVtSteamManager, agd::kUnlock, agd::kPoint, agd::kWayOut, agd::kWayOutBytes};
    } else {
        log::info("AchievementGuard: only for builds 3527, 3549, 3576 and 3663, off");
        return 0;
    }
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uintptr_t world = 0;
    while (!game::safe_read(g_base + a.world_system, &world, sizeof world) || !world) Sleep(500);
    uintptr_t vt_slot = 0;
    if (!game::safe_read(g_base + a.vt_steam_manager + 2 * sizeof(uintptr_t), &vt_slot, sizeof vt_slot) ||
        vt_slot != g_base + a.unlock || !code_is(a.unlock, agd::kUnlockBytes) || !code_is(a.way_out, a.way_out_bytes)) {
        log::error("AchievementGuard: the achievement code is not the expected one; REFUSED, not hooked. The guest may get "
                   "the host's Steam achievements");
        return 0;
    }
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("AchievementGuard: the exe's sections are unreadable; REFUSED, not hooked");
        return 0;
    }
    g_way_out = a.way_out;  // before the hook can run
    // At the title screen at the latest: long before the guest can join a host.
    if (p8_install_mid(g_base, secs, a.point, agd::kPatch, agd::kPointBytes, &on_point, g_hook, "AchievementGuard",
                       "PlatformAchievementManager_Steam::vf2 after its prologue")) {
        log::info("AchievementGuard ON (guest): once this game plays in a host's world, no Steam achievement is unlocked "
                  "until it is restarted (exe+0x{:X})",
                  a.point);
    }
    return 0;
}

}  // namespace

void achievement_guard_start(bool enabled) {
    if (!enabled) {
        log::warn("AchievementGuard: off in cdmp.ini (achievement_guard=0): joining a host can unlock the host's Steam "
                  "achievements on this account");
        return;
    }
    if (const HANDLE t = CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr)) {
        CloseHandle(t);
    } else {
        log::error("AchievementGuard: no thread ({}); not hooked", GetLastError());
    }
}

}  // namespace cdmp::session2
