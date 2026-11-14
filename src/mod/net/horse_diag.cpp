#include "mod/net/horse_diag.h"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <format>

#include <safetyhook.hpp>

#include "mod/game/offsets.h"
#include "mod/game/character_profile.h"
#include "mod/game/character_phase_ready.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/net/enemy_relay.h"
#include "mod/session2/guest_actor_diag_logic.h"

namespace cdmp::net {
namespace {
namespace off = game::build_2976;
namespace gad = session2::gad;

constexpr uint32_t kCopyHorse = 0xB010F002;

// 3527's object layout and phase logic (game::layout_3527(): 3527, 3549, 3576) or 3663, whose offsets this module reads
// were checked in its 3663 code (kPhase3663 below): the CC's +0x08 / +0x30 / +0x88 and the selector's +0x1B in the
// verified apply arrays, the layer chart +0x118 (character_profile.h), the actor's +0x68 in listeners_entry.
bool layout_ok() noexcept {
    return game::layout_3527() || game::current_build() == game::Build::v3663;
}

struct Site {
    uintptr_t rva;
    uint8_t head[16];
    const char* name;
};
constexpr Site kCcUpdate = {0x85FBA0, {0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
                                       0x41, 0x56, 0x41, 0x57}, "CC update"};
constexpr Site kCcPost = {0x860D30, {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57,
                                     0x41, 0x56, 0x48, 0x83}, "CC post-update"};
constexpr Site kRestore = {0x8646D0, {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x20, 0x48, 0x89, 0x50, 0x10, 0x55,
                                      0x56, 0x57, 0x41, 0x54}, "restore actions"};
constexpr Site kPending = {0x2329D70, {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89,
                                       0x74, 0x24, 0x20, 0x57}, "pending actions"};

SafetyHookMid g_cc_hook, g_post_hook, g_restore_hook, g_pending_hook, g_phase_hook, g_action_query_hook,
              g_apply_hook, g_apply_secondary_hook, g_ai_flag_hook, g_listeners_hook;
uint8_t* g_ret = nullptr;
uintptr_t g_apply_resume = 0;
uintptr_t g_apply_secondary_resume = 0;
uintptr_t g_ai_flag_resume = 0;
uintptr_t g_listeners_exit = 0;
std::atomic<uint64_t> g_selector_repaired{0}, g_ai_flag_skipped{0}, g_listeners_skipped{0};
bool g_contain = false;
std::atomic<uint32_t> g_watch_real{0};
std::atomic<int> g_lines{0};
constexpr int kMaxLines = 400;
std::atomic<uint64_t> g_skipped{0}, g_skipped_post{0};
std::atomic<uint64_t> g_phase_skipped{0}, g_query_skipped{0};
std::atomic<uint64_t> g_apply_empty{0};
std::atomic<uint32_t> g_extra_copy{0};  // option D: user 2's character
std::atomic<uint32_t> g_owner{0};       // option D: everything user 2 owns (pet, horse...)
uint64_t g_t0 = 0;

// P8 guest, guest_remote_update_guard (horse_diag_install_remote). Set before
// its hooks go in, never changed after: in this mode only the remote check runs.
bool g_remote_mode = false;
std::atomic<uint32_t> g_remote_local{0};  // the guest's user key; 0 = not known (nothing contained)
std::atomic<uint64_t> g_remote_skipped{0}, g_remote_skipped_post{0};
std::atomic<uint32_t> g_remote_last_key{0};
gad::KeySet<1024> g_remote_keys;       // distinct contained keys (only touched on a skip)
gad::FirstPairs<32> g_remote_first;    // the first 32: key, controller (logged by the reporter)
std::atomic<uint64_t> g_remote_first_dropped{0};  // keys beyond the 1024 of the set

uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

struct Layer {
    uintptr_t a0, a8, a10, a18, chart;
};
struct State {
    uint32_t key = 0;
    Layer layer[2]{};
    uint8_t pending = 0;     // CC+0xA8
    uintptr_t pending_list = 0;  // CC+0x80
    uint8_t restore = 0xFF;  // [[CC+0x40]+0x30]
};

bool read_key(uintptr_t cc, uint32_t& key) {
    __try {
        const auto actor = *reinterpret_cast<const uintptr_t*>(cc + 0x08);
        if (!actor) return false;
        key = *reinterpret_cast<const uint32_t*>(actor + off::kActor_Key);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool read_state(uintptr_t cc, State& s) {
    __try {
        for (int i = 0; i < 2; ++i) {
            const auto l = *reinterpret_cast<const uintptr_t*>(cc + 0x88 + 8 * i);
            if (!l) continue;
            s.layer[i] = {*reinterpret_cast<const uintptr_t*>(l + 0x00), *reinterpret_cast<const uintptr_t*>(l + 0x08),
                          *reinterpret_cast<const uintptr_t*>(l + 0x10), *reinterpret_cast<const uintptr_t*>(l + 0x18),
                          *reinterpret_cast<const uintptr_t*>(l + game::character_profile::layer_chart_offset())};
        }
        s.pending = *reinterpret_cast<const uint8_t*>(cc + 0xA8);
        s.pending_list = *reinterpret_cast<const uintptr_t*>(cc + 0x80);
        const auto st = *reinterpret_cast<const uintptr_t*>(cc + 0x40);
        s.restore = st ? *reinterpret_cast<const uint8_t*>(st + 0x30) : 0xFE;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void read_restore_data(uintptr_t cc, uint8_t (&raw)[0x10], uint64_t& f8) {
    __try {
        const auto st = *reinterpret_cast<const uintptr_t*>(cc + 0x40);
        if (st) {
            std::memcpy(raw, reinterpret_cast<const void*>(st + 0x30), sizeof raw);
            f8 = *reinterpret_cast<const uint64_t*>(st + 0xF8);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// An actor of the CC owned by the option D user (its character and children).
bool owned_by_guest(uintptr_t cc) {
    const uint32_t owner = g_owner.load(std::memory_order_relaxed);
    if (!owner) return false;
    __try {
        const auto actor = *reinterpret_cast<const uintptr_t*>(cc + 0x08);
        return actor && *reinterpret_cast<const uint32_t*>(actor + off::kActor_OwnerUser) == owner;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool is_copy(uint32_t key) {
    const uint32_t extra = g_extra_copy.load(std::memory_order_relaxed);
    return key == kCopyHorse || is_enemy_copy_key(key) || (extra && key == extra);
}

bool watched(uint32_t key) {
    return is_copy(key) || (key && key == g_watch_real.load(std::memory_order_relaxed));
}

const char* who(uint32_t key) {
    if (const uint32_t extra = g_extra_copy.load(std::memory_order_relaxed); extra && key == extra) return "USER 2";
    return key == kCopyHorse ? "COPY" : is_enemy_copy_key(key) ? "ENEMY COPY" : "real";
}

// Same "shape" = same nullness of every field (pointers themselves change).
uint32_t shape(const State& s) {
    uint32_t v = 0;
    for (int i = 0; i < 2; ++i) {
        const Layer& l = s.layer[i];
        v = v << 5 | (l.a0 != 0) | (l.a8 != 0) << 1 | (l.a10 != 0) << 2 | (l.a18 != 0) << 3 | (l.chart != 0) << 4;
    }
    return v << 10 | (s.pending != 0) << 9 | (s.pending_list != 0) << 8 | s.restore;
}

bool take_line() { return g_lines.fetch_add(1, std::memory_order_relaxed) < kMaxLines; }

void log_state(const char* where, const State& s) {
    if (!take_line()) return;
    log::info("HorseDiag +{} ms {} {} 0x{:08X}: L0 a0={} a8={} cur(+10)={} play(+18)={} chart={} | "
              "L1 cur={} play={} chart={} | pending(+A8)={} list(+80)={} restoreByte={}",
              now_ms() - g_t0, where, who(s.key), s.key, s.layer[0].a0 != 0, s.layer[0].a8 != 0,
              s.layer[0].a10 != 0, s.layer[0].a18 != 0, s.layer[0].chart != 0, s.layer[1].a10 != 0,
              s.layer[1].a18 != 0, s.layer[1].chart != 0, s.pending, s.pending_list != 0, s.restore);
}

// A layer with its own chart but nothing playing: the update crashes on it.
// Both layers: an enemy copy ("Wolf Tracker") got its layer-0 action and
// crashed on layer 1 (live test 2026-10-04).
bool layer_without_action(const State& s) {
    for (const Layer& l : s.layer) {
        if (l.chart && (!l.a10 || !l.a18)) return true;
    }
    return false;
}

// Last shape seen per watched actor (2 slots: copy, real).
std::atomic<uint32_t> g_last_shape[3] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

// P8 guest (S34): the CC's actor is controlled by another user and a layer has
// a chart and no action. Runs for every character every frame: the local key
// first, then the controller (most actors stop there), the layers last.
// Guarded reads of scalars only (no struct copy: no CRT memcpy in a mid hook).
uint32_t remote_local_key() {
    uint32_t local = g_remote_local.load(std::memory_order_relaxed);
    if (local || !layout_ok()) return local;
    const auto* profile = game::reader_profile();
    if (!profile) return 0;
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto read = []<class T>(uintptr_t address, T& value) noexcept {
        return address && game::fast_read(address, &value, sizeof value);
    };
    uintptr_t world = 0, manager = 0, vt = 0, actor = 0;
    if (read(base + profile->world_system, world) && world &&
        read(world + off::kWorldSystem_ActorManager, manager) && manager &&
        read(manager, vt) && vt == base + profile->vt_actor_manager &&
        read(manager + off::kActorManager_ControlledActor, actor) && actor &&
        read(actor + off::kActor_OwnerUser, local) && (local >> 28) == 9) {
        g_remote_local.store(local, std::memory_order_relaxed);
        return local;
    }
    return 0;
}

bool remote_without_action(uintptr_t cc, uint32_t local, uint32_t& key, uint32_t& ctrl) {
    __try {
        const auto actor = *reinterpret_cast<const uintptr_t*>(cc + 0x08);
        if (!actor) return false;
        ctrl = *reinterpret_cast<const uint32_t*>(actor + off::kActor_OwnerUser);
        const bool scoped = layout_ok()
            ? game::phase3527::user_requires_readiness(ctrl, local) : gad::remote_user_controlled(ctrl, local);
        if (!scoped) return false;
        bool lacks0 = false, lacks1 = false;
        const auto l0 = *reinterpret_cast<const uintptr_t*>(cc + off::kControl_Layer0);
        if (l0) {
            lacks0 = gad::layer_lacks_action(*reinterpret_cast<const uintptr_t*>(l0 + game::character_profile::layer_chart_offset()),
                                             *reinterpret_cast<const uintptr_t*>(l0 + 0x10),
                                             *reinterpret_cast<const uintptr_t*>(l0 + off::kLayer_Playback));
        }
        const auto l1 = *reinterpret_cast<const uintptr_t*>(cc + off::kControl_Layer0 + 8);
        if (l1 && !lacks0) {
            lacks1 = gad::layer_lacks_action(*reinterpret_cast<const uintptr_t*>(l1 + game::character_profile::layer_chart_offset()),
                                             *reinterpret_cast<const uintptr_t*>(l1 + 0x10),
                                             *reinterpret_cast<const uintptr_t*>(l1 + off::kLayer_Playback));
        }
        if (!lacks0 && !lacks1) return false;
        key = *reinterpret_cast<const uint32_t*>(actor + off::kActor_Key);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The remote mode's whole hook body (update and post-update): true = return at once.
bool contain_remote(uintptr_t cc, std::atomic<uint64_t>& skipped) {
    const uint32_t local = remote_local_key();
    if (!local && !layout_ok()) return false;
    uint32_t key = 0, ctrl = 0;
    if (!remote_without_action(cc, local, key, ctrl)) return false;
    skipped.fetch_add(1, std::memory_order_relaxed);
    g_remote_last_key.store(key, std::memory_order_relaxed);
    const auto ins = g_remote_keys.insert(key);
    if (ins == gad::KeySet<1024>::Insert::Added) {
        g_remote_first.add(key, ctrl);
    } else if (ins == gad::KeySet<1024>::Insert::Full) {
        g_remote_first_dropped.fetch_add(1, std::memory_order_relaxed);
    }
    return true;
}

// 3527 has an independent movement job (99B380 -> 94F7F0) and an action
// query used by a sibling job. Neither passes through Update/PostUpdate.
// Scope stays identical to containment: remote user copies only. Pending
// action application and Restore run independently; neither may be withheld
// while waiting for the first action that they are responsible for installing.
// The actors these guards are for: copies this client does not control.
bool phase_guarded_actor(uintptr_t cc) {
    const auto read = []<class T>(uintptr_t address, T& value) noexcept {
        return address && game::fast_read(address, &value, sizeof value);
    };
    uintptr_t actor = 0;
    uint32_t controller = 0, key = 0;
    if (!read(cc + 8, actor) || !actor || !read(actor + off::kActor_OwnerUser, controller)) return false;
    if (g_remote_mode) return game::phase3527::user_requires_readiness(controller, remote_local_key());
    if (!g_contain || !read(actor + off::kActor_Key, key)) return false;
    const uint32_t owner = g_owner.load(std::memory_order_relaxed);
    return is_copy(key) || (owner && controller == owner);
}

bool phase_unready(uintptr_t cc, bool needs_playback) {
    // Per character, per frame, on the job threads: SEH reads only (VirtualQuery costs 0.2-0.5 ms here).
    const auto read = []<class T>(uintptr_t address, T& value) noexcept {
        return address && game::fast_read(address, &value, sizeof value);
    };
    if (!phase_guarded_actor(cc)) return false;
    return game::phase3527::must_wait(game::phase3527::selected_action(cc, read), needs_playback);
}

void on_movement_phase(safetyhook::Context& ctx) {
    if (!phase_unready(ctx.rcx, true)) return;
    g_phase_skipped.fetch_add(1, std::memory_order_relaxed);
    // At the true entry, before any phase side effects. The caller ignores
    // the return value, then performs its other work and actor-reference release.
    ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
}

void on_action_query(safetyhook::Context& ctx) {
    uintptr_t actor = 0, components = 0, cc = 0;
    if (!game::fast_read(ctx.rcx + 8, &actor, sizeof actor) || !actor ||
        !game::fast_read(actor + 0x68, &components, sizeof components) || !components ||
        !game::fast_read(components + 0x40, &cc, sizeof cc) || !cc || !phase_unready(cc, false)) return;
    g_query_skipped.fetch_add(1, std::memory_order_relaxed);
    // The query's native missing-current branch returns false (B0B60E).
    // Match that result instead of suppressing the surrounding actor job.
    ctx.rax = 0;
    ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
}

bool guarded_store8(uintptr_t address, uint8_t value) noexcept {
    __try {
        *reinterpret_cast<volatile uint8_t*>(address) = value;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// See repaired_selector: after this, every native reader of the selected action
// finds one. The next application writes the selector from its message again.
void repair_selector(uintptr_t cc) noexcept {
    const auto read = []<class T>(uintptr_t address, T& value) noexcept {
        return address && game::fast_read(address, &value, sizeof value);
    };
    const int index = game::phase3527::repaired_selector(cc, read);
    uintptr_t selector = 0;
    if (index < 0 || !read(cc + 0x30, selector) || !selector) return;
    if (guarded_store8(selector + 0x1B, static_cast<uint8_t>(index))) {
        g_selector_repaired.fetch_add(1, std::memory_order_relaxed);
    }
}

// Rax holds the selected layer at both application sites.
bool selected_layer_empty(uintptr_t layer, uintptr_t playback) noexcept {
    if (!playback) return true;
    uintptr_t current = 0;
    return game::fast_read(layer + 0x10, &current, sizeof current) && !current;
}

void on_apply_playback_flag(safetyhook::Context& ctx) {
    if (!selected_layer_empty(ctx.rax, ctx.rcx) || !phase_unready(ctx.r15, true)) return;
    repair_selector(ctx.r15);
    // Run8: Pending -> 9463E0 -> 2517A80 installed layer1 while selected
    // layer0 still had no playback. Only this preliminary flag read lacked
    // a null check. The following loop checks each layer's current/playback
    // before using DIL, and uses DIL only for the selected layer. Therefore
    // the flag is dead when that layer has no playback. Continue the native
    // application, other layer's blend updates, unlocks and cleanup intact.
    if (!game::phase3527::skip_null_playback_flag(ctx, g_apply_resume, true)) return;
    g_apply_empty.fetch_add(1, std::memory_order_relaxed);
}

void on_apply_secondary_flag(safetyhook::Context& ctx) {
    if (!selected_layer_empty(ctx.rax, ctx.rdx) || !phase_unready(ctx.r14, true)) return;
    repair_selector(ctx.r14);
    if (!game::phase3527::skip_null_playback_secondary(ctx, g_apply_secondary_resume, true)) return;
    g_apply_empty.fetch_add(1, std::memory_order_relaxed);
}

// The listener block of the application (listeners_unsafe). Its exit 25197B3 only
// uses the stack frame, so nothing else of the function is affected.
void on_apply_listeners(safetyhook::Context& ctx) {
    const auto read = []<class T>(uintptr_t address, T& value) noexcept {
        return address && game::fast_read(address, &value, sizeof value);
    };
    uintptr_t layer0 = 0, current0 = 0;
    const bool layer0_readable = read(ctx.r15 + 0x88, layer0) && layer0 && read(layer0 + 0x10, current0);
    const auto selected = game::phase3527::selected_action(ctx.r15, read);
    if (!game::phase3527::listeners_unsafe(layer0_readable, current0, selected) || !phase_guarded_actor(ctx.r15)) return;
    g_listeners_skipped.fetch_add(1, std::memory_order_relaxed);
    ctx.rip = g_listeners_exit;
}

// Actor type 1's AI component, called from the status update after an application.
// Both layers empty leaves nothing for the repair to point at (run 10, 22485D5):
// the native "action has no such flag" branch, for this call only.
void on_ai_action_flag(safetyhook::Context& ctx) {
    uintptr_t current = 0;
    if (!game::fast_read(ctx.rcx + 0x10, &current, sizeof current) || current) return;
    g_ai_flag_skipped.fetch_add(1, std::memory_order_relaxed);
    ctx.rip = g_ai_flag_resume;
}

// Where the phase guards go, per build (the byte arrays below are the same on both).
struct PhaseSites {
    uintptr_t phase, query, query_false, apply_read, apply_gate, secondary_read, secondary_gate, secondary_flag, ai_flag,
        selector_write, listeners_entry, listeners_exit;
    uintptr_t apply_hook, apply_resume, secondary_hook, secondary_resume, ai_resume;
};
constexpr PhaseSites kPhase3527{0x94F7F0, 0xB0B230, 0xB0B60E, 0x25191E0, 0x2519248, 0x251A199, 0x251A1F6, 0x251A20D,
                                0x22485D1, 0x25185FB, 0x25194C1, 0x25197B3,
                                0x25191F4, 0x25191FC, 0x251A1AD, 0x251A1B5, 0x22485DB};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): every array is byte for byte 3527's at old + the shift of its
// function, the only match near: the movement phase 0x94FB60 (+0x370), the action query 0xB0B650 and its false return
// 0xB0BA2E (+0x420), the application 2517A80 -> 0x2518850 and 251A170 -> 0x251AF40 (+0xDD0, both .pdata starts),
// the AI component's read 0x2249211 (+0xC40, in 0x22491D0). Hook points and resumes are inside the verified arrays.
constexpr PhaseSites kPhase3576{0x94FB60, 0xB0B650, 0xB0BA2E, 0x2519FB0, 0x251A018, 0x251AF69, 0x251AFC6, 0x251AFDD,
                                0x2249211, 0x25193CB, 0x251A291, 0x251A583,
                                0x2519FC4, 0x2519FCC, 0x251AF7D, 0x251AF85, 0x224921B};

// Build 1.0.0.3663 (static, 2026-11-13; never run). 3663 is a recompile (frames and some struct offsets changed), so
// each site was found again:
// - the movement phase 0x97D6D0 (.pdata start, phase_head): the movement job 0x9CA6D0 (3527's 0x99B380 + 0x2F350, the
//   same 65 instructions but for three struct displacements) calls it at the same +0x8A and ignores its result (the
//   next instruction reloads rcx). Its body is recompiled (frame 0x180, [r13+0x5C8] -> +0x5E0), the entry is what is
//   hooked;
// - the action query 0xB42220 (.pdata start; 3527's body, guest_phase_3527.txt, found by its own bytes at +0xA0 /
//   +0x110 / +0x170 -> +0xA7 / +0x119 / +0x179): it gained a third byte argument (r8b; the callers 0x800662,
//   0x973626, 0x997756, 0x9A9C05 pass 0, 0xB4294D a byte) and pushes r12/r14/r15, so its head and false return differ
//   (query_head3663; query_false3663 at 0xB426BC, `xor al,al; mov rbx,[rsp+0x70]`). It still reads [rcx+8] -> +0x68
//   -> +0x20 / +0x40 as 3527's. The hook returns false at its entry, before any push, as in 3527;
// - the application 0x258A230 (3527 2517A80): every array byte for byte, the only match near: selector_write
//   0x258ADAB (+0xB7B as in 3576), apply_read 0x258B930 / apply_gate 0x258B998 / listeners 0x258BC11..0x258BF03 (the
//   function is 0x60 bytes shorter between +0xB7B and +0x1700; the listener block is 0x2F2 bytes as in 3527/3576);
// - 251A170 -> 0x258C8C0 (.pdata start; the three arrays at its +0x29 / +0x86 / +0x9D as in 3527);
// - the AI component's read 0x22BA541 (+0x41 in 0x22BA500, as 3576's in 0x22491D0).
// Hook points and resumes are inside the verified arrays at 3527's distances.
constexpr PhaseSites kPhase3663{0x97D6D0, 0xB42220, 0xB426BC, 0x258B930, 0x258B998, 0x258C8E9, 0x258C946, 0x258C95D,
                                0x22BA541, 0x258ADAB, 0x258BC11, 0x258BF03,
                                0x258B944, 0x258B94C, 0x258C8FD, 0x258C905, 0x22BA54B};

bool install_phase_guards() {
    if (game::current_build() == game::Build::v2976) return true;
    if (!layout_ok()) return false;
    const bool b3663 = game::current_build() == game::Build::v3663;
    const PhaseSites& s = b3663 ? kPhase3663 : game::current_build() == game::Build::v3576 ? kPhase3576 : kPhase3527;
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    constexpr uint8_t phase_head[]{0x48,0x89,0x5C,0x24,0x10,0x55,0x56,0x57,
                                   0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57};
    constexpr uint8_t query_head3527[]{0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,
                                       0x24,0x10,0x56,0x57,0x41,0x56,0x48,0x83};
    constexpr uint8_t query_false3527[]{0x32,0xC0,0x48,0x8B,0x5C,0x24,0x60};
    // 3663: push r12 / r14 / r15 (the new third argument), so a larger save area.
    constexpr uint8_t query_head3663[]{0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,
                                       0x24,0x10,0x56,0x57,0x41,0x54,0x41,0x56};
    constexpr uint8_t query_false3663[]{0x32,0xC0,0x48,0x8B,0x5C,0x24,0x70};
    constexpr uint8_t apply_read[]{0x49,0x8B,0x47,0x30,0x0F,0xB6,0x58,0x1B,
        0x49,0x8B,0x84,0xDF,0x88,0,0,0,0x48,0x8B,0x48,0x18,
        0x48,0x8B,0x41,0x28,0x0F,0xB6,0x78,0x7E,0x49,0x8B,0x4F,0x08};
    constexpr uint8_t apply_gate[]{0x48,0x83,0x79,0x18,0,0x74,0x35,0x3A,0xD3,
        0x75,0x1E,0x40,0x84,0xFF,0x74,0x19};
    constexpr uint8_t secondary_read[]{0x4C,0x8B,0xF1,0x44,0x0F,0xB6,0x60,0x1B,
        0x4A,0x8B,0x84,0xE1,0x88,0,0,0,0x48,0x8B,0x50,0x18,
        0x48,0x8B,0x42,0x28,0x0F,0xB6,0x68,0x7E,0x48,0x8B,0x41,0x08};
    constexpr uint8_t secondary_gate[]{0x48,0x83,0x7B,0x18,0,0x74,0x40};
    constexpr uint8_t secondary_flag[]{0x41,0x3A,0xFC,0x75,0x19,0x40,0x84,0xED,0x74,0x14};
    constexpr uint8_t ai_flag[]{0x48,0x8B,0x51,0x10,0xF6,0x42,0x0E,0x18,0x75,0x04,0x32,0xC9};
    constexpr uint8_t selector_write[]{0x49,0x8B,0x47,0x30,0x0F,0xB6,0x8C,0x24,0xD0,0x04,0,0,0x88,0x48,0x1B};
    constexpr uint8_t listeners_entry[]{0x49,0x8B,0x47,0x08,0x48,0x8B,0x48,0x68,0x48,0x8B,0x49,0x38};
    constexpr uint8_t listeners_exit[]{0x48,0x8D,0x44,0x24,0x60,0xBE,0xFE,0x01,0,0,0x48,0x8B,0x5C,0x24,0x50};
    const auto matches = [base]<size_t N>(uintptr_t rva, const uint8_t (&bytes)[N]) {
        uint8_t actual[N]{};
        return game::safe_read(base + rva, actual, N) && std::memcmp(actual, bytes, N) == 0;
    };
    const bool query_ok = b3663 ? matches(s.query, query_head3663) && matches(s.query_false, query_false3663)
                                : matches(s.query, query_head3527) && matches(s.query_false, query_false3527);
    if (!game::validate_native_catalog() || !matches(s.phase, phase_head) || !query_ok ||
        !matches(s.apply_read, apply_read) || !matches(s.apply_gate, apply_gate) ||
        !matches(s.secondary_read, secondary_read) || !matches(s.secondary_gate, secondary_gate) ||
        !matches(s.secondary_flag, secondary_flag) || !matches(s.ai_flag, ai_flag) ||
        !matches(s.selector_write, selector_write) || !matches(s.listeners_entry, listeners_entry) ||
        !matches(s.listeners_exit, listeners_exit)) {
        log::error("Character phase guards: {} signatures do not match",
                   b3663 ? "3663" : game::current_build() == game::Build::v3576 ? "3576" : "3527");
        return false;
    }
    g_phase_hook = safetyhook::create_mid(reinterpret_cast<void*>(base + s.phase), &on_movement_phase);
    if (g_phase_hook) {
        g_action_query_hook = safetyhook::create_mid(reinterpret_cast<void*>(base + s.query), &on_action_query);
    }
    if (g_action_query_hook) {
        g_apply_resume = base + s.apply_resume;
        g_apply_hook = safetyhook::create_mid(reinterpret_cast<void*>(base + s.apply_hook), &on_apply_playback_flag);
    }
    if (g_apply_hook) {
        g_apply_secondary_resume = base + s.secondary_resume;
        g_apply_secondary_hook = safetyhook::create_mid(reinterpret_cast<void*>(base + s.secondary_hook),
                                                       &on_apply_secondary_flag);
    }
    if (g_apply_secondary_hook) {
        g_ai_flag_resume = base + s.ai_resume;
        g_ai_flag_hook = safetyhook::create_mid(reinterpret_cast<void*>(base + s.ai_flag), &on_ai_action_flag);
    }
    if (g_ai_flag_hook) {
        g_listeners_exit = base + s.listeners_exit;
        g_listeners_hook = safetyhook::create_mid(reinterpret_cast<void*>(base + s.listeners_entry), &on_apply_listeners);
    }
    if (!g_phase_hook || !g_action_query_hook || !g_apply_hook || !g_apply_secondary_hook || !g_ai_flag_hook ||
        !g_listeners_hook) {
        g_phase_hook = {};
        g_action_query_hook = {};
        g_apply_hook = {};
        g_apply_secondary_hook = {};
        g_ai_flag_hook = {};
        g_listeners_hook = {};
        return false;
    }
    log::info("Character phase guards ON: movement phase exe+0x{:X} waits for the selected action/playback; "
              "query exe+0x{:X} uses its native false result without an action; user copies wait for readiness "
              "until local identity is known, then only remote copies are guarded; action application "
              "exe+0x{:X} and exe+0x{:X} skip only the unused blend flag reads when selected playback is null",
              s.phase, s.query, s.apply_hook, s.secondary_hook);
    return true;
}

void on_cc_update(safetyhook::Context& ctx) {
    if (g_remote_mode) {
        if (contain_remote(ctx.rcx, g_remote_skipped)) ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
        return;
    }
    uint32_t key = 0;
    // User 2's children too (pet, horse...): before this they returned here,
    // above the containment (live test 2026-10-09, crash 0x232D5FF via 0x85FC94).
    if (!read_key(ctx.rcx, key) || !(watched(key) || owned_by_guest(ctx.rcx))) return;
    State s;
    s.key = key;
    if (!read_state(ctx.rcx, s)) return;
    const uint32_t sh = shape(s);
    auto& last = g_last_shape[key == kCopyHorse ? 0 : is_enemy_copy_key(key) ? 2 : 1];
    if (last.exchange(sh, std::memory_order_relaxed) != sh) log_state("update", s);
    // Containment: a copy whose main layer has a chart but no current action
    // crashed three different functions of this update (INFORME §5).
    if (g_contain && (is_copy(key) || owned_by_guest(ctx.rcx)) && layer_without_action(s)) {
        g_skipped.fetch_add(1, std::memory_order_relaxed);
        ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
    }
}

void on_cc_post(safetyhook::Context& ctx) {
    if (g_remote_mode) {
        if (contain_remote(ctx.rcx, g_remote_skipped_post)) ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
        return;
    }
    if (!g_contain) return;
    uint32_t key = 0;
    if (!read_key(ctx.rcx, key) || !(is_copy(key) || owned_by_guest(ctx.rcx))) return;
    State s;
    if (!read_state(ctx.rcx, s)) return;
    if (layer_without_action(s)) {
        g_skipped_post.fetch_add(1, std::memory_order_relaxed);
        ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
    }
}

void on_restore(safetyhook::Context& ctx) {
    uint32_t key = 0;
    if (!read_key(ctx.rcx, key) || !watched(key)) return;
    State s;
    s.key = key;
    if (!read_state(ctx.rcx, s)) return;
    log_state("RESTORE(0x8646D0)", s);
    // The restore data: bytes +0x30..+0x40 and the u64 at +0xF8 of [CC+0x40].
    uint8_t raw[0x10] = {};
    uint64_t f8 = 0;
    read_restore_data(ctx.rcx, raw, f8);
    if (take_line()) {
        log::info("HorseDiag   restore data [CC+0x40]+0x30: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
                  "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} | +0xF8 0x{:X}",
                  raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10],
                  raw[11], raw[12], raw[13], raw[14], raw[15], f8);
    }
}

void on_pending(safetyhook::Context& ctx) {
    uint32_t key = 0;
    if (!read_key(ctx.rcx, key) || !watched(key)) return;
    State s;
    s.key = key;
    if (!read_state(ctx.rcx, s)) return;
    if (s.pending) log_state("PENDING(0x2329D70)", s);
}

bool hook(const Site& site, SafetyHookMid& out, safetyhook::MidHookFn fn) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!game::validate_native_catalog() || !game::character_profile::matches(base, site.rva, site.head)) {
        log::warn("HorseDiag: {} (exe+0x{:X}) not recognised", site.name, site.rva);
        return false;
    }
    auto h = safetyhook::MidHook::create(reinterpret_cast<void*>(base + game::character_profile::rva(site.rva)), fn);
    if (!h) {
        log::warn("HorseDiag: {} hook failed", site.name);
        return false;
    }
    out = std::move(*h);
    return true;
}

// The lone `ret` the containment resumes at (once per process).
bool make_ret() {
    if (g_ret) return true;
    g_ret = static_cast<uint8_t*>(VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!g_ret) return false;
    g_ret[0] = 0xC3;
    DWORD old = 0;
    VirtualProtect(g_ret, 16, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), g_ret, 16);
    return true;
}

}  // namespace

bool horse_diag_install(bool contain) {
    if (g_cc_hook) return true;
    g_t0 = now_ms();
    if (!make_ret()) return false;
    const bool ok = hook(kCcUpdate, g_cc_hook, on_cc_update) && hook(kRestore, g_restore_hook, on_restore) &&
                    hook(kPending, g_pending_hook, on_pending);
    if (!ok) {
        g_cc_hook = {};
        g_restore_hook = {};
        g_pending_hook = {};
        return false;
    }
    g_contain = contain;
    if (contain && (!hook(kCcPost, g_post_hook, on_cc_post) || !install_phase_guards())) {
        g_cc_hook = {};
        g_post_hook = {};
        g_restore_hook = {};
        g_pending_hook = {};
        g_contain = false;
        return false;
    }
    log::info("HorseDiag: installed (containment {})", g_contain ? "on" : "off");
    return true;
}

void horse_diag_watch(uint32_t key) {
    g_watch_real = key;
    log::info("HorseDiag: watching the copy 0x{:08X} and the real horse 0x{:08X}", kCopyHorse, key);
}

void horse_diag_also_key(uint32_t key) { g_extra_copy.store(key, std::memory_order_relaxed); }

void horse_diag_owner(uint32_t user_key) { g_owner.store(user_key, std::memory_order_relaxed); }

std::string horse_diag_describe() {
    return std::format("character update skipped {} (post-update {}, movement phase {}, action query {}) while without action; empty apply playback {}, selector repaired {}, AI flag read skipped {}, apply listeners skipped {}",
                       g_skipped.load(std::memory_order_relaxed), g_skipped_post.load(std::memory_order_relaxed),
                       g_phase_skipped.load(std::memory_order_relaxed), g_query_skipped.load(std::memory_order_relaxed),
                       g_apply_empty.load(std::memory_order_relaxed), g_selector_repaired.load(std::memory_order_relaxed),
                       g_ai_flag_skipped.load(std::memory_order_relaxed), g_listeners_skipped.load(std::memory_order_relaxed));
}

bool horse_diag_install_remote() {
    if (g_cc_hook) return false;  // the co-op's / host's install owns the two hooks
    g_t0 = now_ms();
    if (!make_ret()) return false;
    g_remote_mode = true;  // before the hooks: they read it
    if (!hook(kCcUpdate, g_cc_hook, on_cc_update)) {
        g_remote_mode = false;
        return false;
    }
    if (!hook(kCcPost, g_post_hook, on_cc_post) || !install_phase_guards()) {
        g_cc_hook = {};
        g_post_hook = {};
        g_remote_mode = false;
        return false;
    }
    g_contain = true;
    return true;
}

void horse_diag_contain_remote(uint32_t local_user_key) {
    g_remote_local.store(local_user_key, std::memory_order_relaxed);
}

void horse_diag_remote_report() {
    if (!g_remote_mode) return;
    const uint32_t local = g_remote_local.load(std::memory_order_relaxed);
    g_remote_first.drain([local](uint32_t key, uint32_t ctrl, size_t i) {
        log::info("RemoteUpdateGuard: holding actor 0x{:08X} (control 0x{:08X}, not the local user 0x{:08X}): a "
                  "layer has a chart and no action; CharacterControl::Update 0x85FBA0 and PostUpdate 0x860D30 "
                  "return at once until it has one (key {} of the first 32 logged)",
                  key, ctrl, local, i + 1);
    });
}

std::string horse_diag_remote_describe() {
    if (!g_remote_mode) return {};
    const uint64_t uncounted = g_remote_first_dropped.load(std::memory_order_relaxed);
    return std::format(" | remote update guard: update skipped {} post-update {} movement phase {} action query {} empty apply playback {} selector repaired {} AI flag read skipped {} apply listeners skipped {} | actors held {}{} (last 0x{:08X})",
                       g_remote_skipped.load(std::memory_order_relaxed),
                       g_remote_skipped_post.load(std::memory_order_relaxed),
                       g_phase_skipped.load(std::memory_order_relaxed), g_query_skipped.load(std::memory_order_relaxed),
                       g_apply_empty.load(std::memory_order_relaxed),
                       g_selector_repaired.load(std::memory_order_relaxed),
                       g_ai_flag_skipped.load(std::memory_order_relaxed),
                       g_listeners_skipped.load(std::memory_order_relaxed),
                       g_remote_keys.size(),
                       uncounted ? std::format(" (key set full: {} skips of uncounted keys)", uncounted) : std::string(),
                       g_remote_last_key.load(std::memory_order_relaxed));
}

void horse_diag_tick() {
    static uint64_t logged = 0, logged_post = 0, last = 0;
    const uint64_t a = g_skipped.load(std::memory_order_relaxed), b = g_skipped_post.load(std::memory_order_relaxed);
    const uint64_t t = now_ms();
    if ((a != logged || b != logged_post) && t - last >= 2000) {
        log::info("HorseDiag: copy's update skipped {} times (post-update {}) while it has no action", a, b);
        logged = a;
        logged_post = b;
        last = t;
    }
}

}  // namespace cdmp::net
