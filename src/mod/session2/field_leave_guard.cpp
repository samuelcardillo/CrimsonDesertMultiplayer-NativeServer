#include "mod/session2/field_leave_guard.h"

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
#include "mod/session2/field_leave_guard_logic.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

constexpr uint64_t kLoggedTimes = 16;
constexpr uintptr_t kVtServerComponent = 0x5EF4E50;

// The build's addresses (field_leave_guard_logic.h): 3527/3549, 3576 and 3663.
struct Addrs {
    uintptr_t world_system, entry, point, own_call, vt_server_component;
};
// 3576: the world slot from core_globals_3576.json (reader_profile() is null on 3576).
constexpr Addrs k3576{0x71C0100, flg::kEntry3576, flg::kPoint3576, flg::kOwnCall3576, flg::kVtServerComponent3576};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the world slot 0x72451C0 (profile_s2.h; two AOB patterns).
constexpr Addrs k3663{0x72451C0, flg::kEntry3663, flg::kPoint3663, flg::kOwnCall3663, flg::kVtServerComponent3663};

SafetyHookMid g_hook;
uintptr_t g_base = 0;
uintptr_t g_own_call = flg::kOwnCall, g_vt_server_component = kVtServerComponent;  // set before the hook goes in
bool g_guest = false;
std::atomic<uint64_t> g_fired{0};

template <class T>
T read_or_zero(uintptr_t address) noexcept {
    T value{};
    if (!address || !game::safe_read(address, &value, sizeof value)) return T{};
    return value;
}

void on_point(safetyhook::Context& ctx) noexcept {
    const uintptr_t own = read_or_zero<uintptr_t>(ctx.rdi + flg::kComponentOwnManager);
    const uintptr_t actor = read_or_zero<uintptr_t>(ctx.rdi + flg::kComponentActor);
    const uintptr_t user = actor ? read_or_zero<uintptr_t>(actor + flg::kActorUser) : 0;
    const uint32_t leaver_user = user ? read_or_zero<uint32_t>(user + flg::kUserKey) : 0;
    const uint32_t field_owner = read_or_zero<uint32_t>(ctx.rbx + flg::kFieldOwnerKey);
    const uintptr_t owner_manager = ctx.rax;
    if (!flg::skip_owner_unload(ctx, g_base, own, leaver_user, field_owner, g_own_call)) return;
    if (g_fired.fetch_add(1, std::memory_order_relaxed) >= kLoggedTimes) return;
    const uint32_t key = actor ? read_or_zero<uint32_t>(actor + flg::kActorKey) : 0;
    const uintptr_t vt = read_or_zero<uintptr_t>(ctx.rdi);
    log::info("FieldLeaveGuard: 0x{:08X} of user 0x{:08X} leaves a field of user 0x{:08X} ({}): manager 0x{:X} of the field's owner "
              "stays loaded, only its own 0x{:X} unloads",
              key, leaver_user, field_owner, vt == g_base + g_vt_server_component ? "server" : "client", owner_manager, own);
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
        a = {profile->world_system, flg::kEntry, flg::kPoint, flg::kOwnCall, kVtServerComponent};
    } else {
        log::info("FieldLeaveGuard: only for builds 3527, 3549, 3576 and 3663, off");
        return 0;
    }
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uintptr_t world = 0;
    while (!game::safe_read(g_base + a.world_system, &world, sizeof world) || !world) Sleep(500);
    if (!code_is(a.entry, flg::kEntryBytes) || !code_is(a.own_call, flg::kOwnCallBytes)) {
        log::error("FieldLeaveGuard: the code around exe+0x{:X} is not the expected one; REFUSED, not hooked", a.point);
        return 0;
    }
    g_own_call = a.own_call;  // before the hook can run
    g_vt_server_component = a.vt_server_component;
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("FieldLeaveGuard: the exe's sections are unreadable; REFUSED, not hooked");
        return 0;
    }
    if (p8_install_mid(g_base, secs, a.point, flg::kPatch, flg::kPointBytes, &on_point, g_hook, "FieldLeaveGuard",
                       "the sequencer component's call to the field owner's manager")) {
        log::info("FieldLeaveGuard ON ({}): another user's character leaving a field does not unload its owner's manager (exe+0x{:X})",
                  g_guest ? "guest" : "host", a.point);
    }
    return 0;
}

}  // namespace

void field_leave_guard_start(bool enabled, bool guest) {
    if (!enabled) {
        log::info("FieldLeaveGuard: off in cdmp.ini (field_leave_guard=0)");
        return;
    }
    g_guest = guest;
    if (const HANDLE t = CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr)) {
        CloseHandle(t);
    } else {
        log::error("FieldLeaveGuard: no thread ({}); not hooked", GetLastError());
    }
}

}  // namespace cdmp::session2
