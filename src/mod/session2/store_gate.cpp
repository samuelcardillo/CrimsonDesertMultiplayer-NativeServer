#include "mod/session2/store_gate.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/gimmick_interact_logic.h"
#include "mod/session2/guest.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

// Build 3549 (capstone on the installed PE, 2026-11-06); see store_gate.h. 3576 (static, 2026-11-06 evening, not yet
// run): the same function 0x23C7350 (+0xD50), its points at the same offsets (+0x16B, +0x437) with the same bytes; the
// world slot 0x71C0100.
struct Pts {
    uintptr_t fn, has_scene, same_scene, world_slot;
};
constexpr Pts k3549{0x23C6600, 0x23C676B, 0x23C6A37, 0};
constexpr Pts k3576{0x23C7350, 0x23C74BB, 0x23C7787, 0x71C0100};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the two points' arrays (kHasSceneBytes, kSameSceneBytes, the je's
// rel32 included) are each unique in the code section, at +0x173 / +0x43F (3527 +0x16B / +0x437) of 0x2438BE0 (.pdata
// 0x2438BE0-0x24392E3, head kFnHead); r13 = rcx the store component ([r13+8] the actor, [actor+0xA0] its user at
// 0x2438D94 / 0x2438D9C), r12 = the requester's current scene ([rbx+0xA0] or [rbx+0x90] at 0x2438D18 / 0x2438D21) and
// reloaded at 0x2438D94 right after the test, [rbp-0x31] its scene id (0x2438D3D), rbx the shopkeeper's (0x243900F),
// rsi = r8 the shopkeeper actor (0x2438FF1); the world slot 0x72451C0.
constexpr Pts k3663{0x2438BE0, 0x2438D53, 0x243901F, 0x72451C0};
const Pts* g_p = &k3549;  // written once by store_gate_start

constexpr uint8_t kFnHead[10] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18};
constexpr uint8_t kHasSceneBytes[7] = {0x41, 0xF7, 0xC4, 0xFF, 0xFF, 0xFF, 0x1F};
constexpr uint32_t kHasScenePatch = 7;
constexpr uint8_t kSameSceneBytes[10] = {0x48, 0x39, 0x5D, 0xCF, 0x0F, 0x84, 0xBF, 0x00, 0x00, 0x00};
constexpr uint32_t kSameScenePatch = 10;
constexpr int32_t kRbpCurrent = -0x31;
constexpr uint32_t kComp_Actor = 0x08, kActor_User = 0xA0, kUser_Key = 0x60, kActor_Key = 0x60;
constexpr uint32_t kWorld_Mgr = 0x30, kMgr_User = 0x58;
constexpr uint32_t kUserMask = 0xFFF00000, kUserTag = 0x90100000;

uintptr_t g_base = 0, g_world_slot = 0;
std::atomic<bool> g_started{false}, g_guest{false}, g_hooked{false};
std::atomic<uint8_t> g_mode{0};  // gil::Mode (Trace = probe)
SafetyHookMid g_has_hook, g_same_hook;
std::atomic<uint64_t> g_has_calls{0}, g_has_let{0}, g_same_calls{0}, g_same_let{0}, g_would{0};
std::atomic<uint32_t> g_last_requester{0}, g_last_npc{0};

template <class T>
T rd(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return game::safe_read(a, &v, sizeof v) ? v : fallback;
}
bool write_u64(uintptr_t a, uint64_t v) noexcept {
    if (a < 0x10000) return false;
    __try {
        *reinterpret_cast<volatile uint64_t*>(a) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
uint32_t own_user() noexcept {
    const uintptr_t world = g_world_slot ? rd<uintptr_t>(g_base + g_world_slot) : 0;
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    const uintptr_t user = mgr ? rd<uintptr_t>(mgr + kMgr_User) : 0;
    return user ? rd<uint32_t>(user + kUser_Key) : 0;
}
// The requester of this check (r13 = its store component) and whether the check is the other player's to pass.
bool other_players(uintptr_t store_comp, uint32_t* who) noexcept {
    const uintptr_t actor = store_comp ? rd<uintptr_t>(store_comp + kComp_Actor) : 0;
    const uintptr_t user = actor ? rd<uintptr_t>(actor + kActor_User) : 0;
    const uint32_t req = user ? rd<uint32_t>(user + kUser_Key) : 0;
    *who = actor ? rd<uint32_t>(actor + kActor_Key) : 0;
    const uint32_t mine = own_user();
    if (!req || !mine || (req & kUserMask) != kUserTag || (mine & kUserMask) != kUserTag) return false;
    if (g_guest.load(std::memory_order_relaxed)) return req == mine && guest_remote_live();
    return req != mine;  // the host: a request of user 2 at its server
}
bool on() noexcept { return static_cast<gil::Mode>(g_mode.load(std::memory_order_relaxed)) == gil::Mode::On; }

void has_scene_mid(safetyhook::Context& ctx) {
    g_has_calls.fetch_add(1, std::memory_order_relaxed);
    if ((ctx.r12 & 0x1FFFFFFFull) != 0) return;
    uint32_t who = 0;
    if (!other_players(ctx.r13, &who)) return;
    g_last_requester.store(who, std::memory_order_relaxed);
    if (!on()) {
        g_would.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    ctx.r12 = 1;  // only tested here; the function reloads r12 at 0x23C67AC
    g_has_let.fetch_add(1, std::memory_order_relaxed);
}
void same_scene_mid(safetyhook::Context& ctx) {
    g_same_calls.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t slot = ctx.rbp + kRbpCurrent;
    if (rd<uint64_t>(slot) == ctx.rbx) return;
    uint32_t who = 0;
    if (!other_players(ctx.r13, &who)) return;
    g_last_requester.store(who, std::memory_order_relaxed);
    g_last_npc.store(ctx.rsi ? rd<uint32_t>(ctx.rsi + kActor_Key) : 0, std::memory_order_relaxed);
    if (!on()) {
        g_would.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (write_u64(slot, ctx.rbx)) g_same_let.fetch_add(1, std::memory_order_relaxed);
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), actual.size()) == 0;
}

DWORD WINAPI worker(LPVOID) {
    try {
        for (int i = 0; i < 2400 && g_world_slot; ++i) {
            uintptr_t world = 0;
            if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
            Sleep(500);
        }
        std::vector<gad::Section> secs;
        if (!p8_exe_sections(g_base, secs) || !bytes_at(g_p->fn, kFnHead)) {
            log::error("StoreGate: the store check 0x23C6600 is not build 3549's expected code; not installed");
            return 0;
        }
        const bool a = p8_install_mid(g_base, secs, g_p->has_scene, kHasScenePatch, kHasSceneBytes, &has_scene_mid, g_has_hook,
                                      "StoreGate", "the store check's 'current scene' test 0x23C676B");
        const bool b = a && p8_install_mid(g_base, secs, g_p->same_scene, kSameScenePatch, kSameSceneBytes, &same_scene_mid,
                                           g_same_hook, "StoreGate", "the store check's scene compare 0x23C6A37");
        if (!a || !b) {
            g_has_hook = {};
            g_same_hook = {};
            log::error("StoreGate: not both points could be hooked; nothing installed");
            return 0;
        }
        g_hooked.store(true);
        log::info("StoreGate ({}, store_gate={}): hooked exe+0x{:X} / exe+0x{:X} | {}", g_guest.load() ? "guest" : "host",
                  gil::mode_name(static_cast<gil::Mode>(g_mode.load())), g_p->has_scene, g_p->same_scene,
                  g_guest.load() ? "this client's own buy/sell checks pass the shopkeeper-scene test while it plays on a host"
                                 : "user 2's buy/sell requests at this server pass the shopkeeper-scene test");
        uint64_t last = 0;
        for (;;) {
            Sleep(60000);
            const uint64_t now = g_has_let.load() + g_same_let.load() + g_would.load();
            if (now == last) continue;
            last = now;
            log::info("StoreGate summary ({}, store_gate={}): 'current scene' tests {} (let {}) | scene compares {} (let {}) | "
                      "would (probe) {} | last requester 0x{:08X}, shopkeeper 0x{:08X}",
                      g_guest.load() ? "guest" : "host", gil::mode_name(static_cast<gil::Mode>(g_mode.load())),
                      g_has_calls.load(), g_has_let.load(), g_same_calls.load(), g_same_let.load(), g_would.load(),
                      g_last_requester.load(), g_last_npc.load());
        }
    } catch (...) {
        log::error("StoreGate: the worker stopped (exception)");
    }
    return 0;
}

}  // namespace

void store_gate_start(const std::string& mode, bool guest) {
    const auto m = gil::parse_mode(mode);
    if (!m) {
        log::warn("StoreGate: store_gate '{}' is not 0 | probe | 1; it stays off", mode);
        return;
    }
    if (*m == gil::Mode::Off) return;
    if (!game::is_3549() && !game::is_3576() && !game::is_3663()) {
        log::warn("StoreGate: store_gate is for builds 3549, 3576 and 3663 only; off");
        return;
    }
    if (g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_p = game::is_3663() ? &k3663 : game::is_3576() ? &k3576 : &k3549;
    if (g_p->world_slot) {
        g_world_slot = g_p->world_slot;
    } else if (const auto* profile = game::reader_profile()) {
        g_world_slot = profile->world_system;
    }
    g_guest.store(guest);
    g_mode.store(static_cast<uint8_t>(*m));
    log::info("StoreGate ON ({}, store_gate={}): hooked once the world is up", guest ? "guest" : "host",
              gil::mode_name(*m));
    CloseHandle(CreateThread(nullptr, 0, worker, nullptr, 0, nullptr));
}

}  // namespace cdmp::session2
