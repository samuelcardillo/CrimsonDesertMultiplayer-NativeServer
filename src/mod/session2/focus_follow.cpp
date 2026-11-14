#include "mod/session2/focus_follow.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <mutex>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/focus_follow_logic.h"
#include "mod/session2/mount_sync.h"
#include "mod/session2/remote_visible.h"

namespace cdmp::session2 {
namespace {

// Builds 3527 and 3549 (real code and vtables unchanged between them; read live on 3549).
constexpr uintptr_t kVtClan = 0x594D250;  // ClientMercenaryClanActorComponent: its vf23 0x23143D0 is slot 23
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the clan vtable 0x594D250 -> 0x594F340 by RTTI (slot 23 =
// 0x2315120, the old vf23 + 0xD50), Status 0x591A710 -> 0x591C7C0 (RTTI), world slot 0x71C0100 (reader_profile() may
// be null on 3576). Offsets unchanged: the focus routine 0x23144B0 -> 0x2315200 still stores clan+0x118 (0x23154AC)
// and tests Status+0x369; Status' setter 0x18CD090 keeps +0x3B8 / +0x3C0.
constexpr uintptr_t kVtClan3576 = 0x594F340, kVtStatus3576 = 0x591C7C0, kWorldSlot3576 = 0x71C0100;
// Build 1.0.0.3663 (static, 2026-11-13; never run): the clan vtable 0x594F340 -> 0x59CAFB8 by RTTI (slot 23 =
// 0x2385E20, 3527's vf23 + 0x71A50), Status 0x591C7C0 -> 0x5998B60 (RTTI), world slot 0x72451C0. The focus routine
// 0x23144B0 -> 0x2385F00 (+0x71A50) still stores clan+0x118 (0x23861AC), tests Status+0x369 (0x2385F3C) and reads
// +0x3B8 / +0x3C0 (0x23860F7 / 0x23860F1); Status' setter 0x1932980 keeps the +0x3B8 store (remote_visible.cpp). The
// clan component is still at components +0x110: the client component factory 0x9C3100 builds it (vtable store at
// 0x9C33A0) and registers it with index 0x22 (0x9C33FB), stored at table + index * 8 (0x2297192).
constexpr uintptr_t kVtClan3663 = 0x59CAFB8, kVtStatus3663 = 0x5998B60, kWorldSlot3663 = 0x72451C0;
constexpr uint32_t kWorldManager = 0x30, kManagerUser = 0x58, kUserMain = 0xD0;
constexpr uint32_t kActorKey = 0x60, kActorComps = 0x68, kActorInfo = 0x88, kInfoType = 0x01, kActorUser = 0xA0;
constexpr uint32_t kCompsStatus = 0x20, kCompsClan = 0x110, kClanFocus = 0x118;
constexpr uint32_t kStatusActor = 0x08, kStatusBusy = 0x369, kStatusFlags = 0x3B8, kStatusPending = 0x3C0;
constexpr uint64_t kHiddenBit = 0x100000;
constexpr uint16_t kOpMoveAck = 2697, kOpStartActionAck = 2991, kOpLoad = 2005;
constexpr int kLogLines = 24;

std::atomic<bool> g_on{false};
std::atomic<bool> g_installed{false};
bool g_guest = false;
uintptr_t g_base = 0, g_world_slot = 0, g_vt_status = 0, g_vt_clan = 0;

std::atomic<uint64_t> g_outbound{0};     // the frame to send, packed; 0 = none
std::atomic<uint64_t> g_local{0};        // what this client's user is playing, packed
std::atomic<uint64_t> g_remote{0};       // what the other player said, packed

std::mutex g_mu;                         // the follower: the network thread stores, the main thread applies
ffl::Follower g_follower;
uint64_t g_epoch = 0;
std::atomic<bool> g_work{false};

std::atomic<uint64_t> g_last_pass_ms{0};
std::atomic<uint64_t> c_shown{0}, c_hidden{0}, c_failed{0};
std::atomic<uint64_t> c_out_move{0}, c_out_action{0}, c_out_load{0}, c_in_move{0}, c_in_action{0}, c_in_load{0};
std::atomic<int> g_lines{0};

template <class T>
bool read_at(uintptr_t address, T& value) noexcept {
    return address && game::safe_read(address, &value, sizeof value);
}

uintptr_t local_user() noexcept {
    uintptr_t world = 0, manager = 0, user = 0;
    if (!read_at(g_world_slot, world) || !read_at(world + kWorldManager, manager) || !read_at(manager + kManagerUser, user)) {
        return 0;
    }
    return user;
}

// This client's user: what it is playing now. False while there is no world.
bool read_local(ffl::Focus& out) noexcept {
    const uintptr_t user = local_user();
    uintptr_t main_actor = 0, comps = 0, clan = 0, vt = 0;
    uint32_t main_key = 0, focus = 0;
    if (!user || !read_at(user + kUserMain, main_actor) || !read_at(main_actor + kActorKey, main_key) ||
        !read_at(main_actor + kActorComps, comps) || !read_at(comps + kCompsClan, clan) || !read_at(clan, vt) ||
        vt != g_vt_clan || !read_at(clan + kClanFocus, focus)) {
        return false;
    }
    out = ffl::from_clan(focus, main_key);
    return ffl::valid(out);
}

struct Copy {
    uintptr_t status = 0;
    ffl::Seen seen;
    uint64_t flags = 0, pending = 0;
};

Copy read_copy(uint32_t key, uintptr_t user) noexcept {
    Copy c;
    const uintptr_t actor = mount_sync_find_actor(key);
    if (!actor) return c;
    uintptr_t comps = 0, status = 0, back = 0, vt = 0, owner = 0, info = 0;
    uint8_t type = 0, busy = 0;
    if (!read_at(actor + kActorComps, comps) || !read_at(comps + kCompsStatus, status) ||
        !read_at(status + kStatusActor, back) || back != actor || !read_at(status, vt) || vt != g_vt_status ||
        !read_at(actor + kActorUser, owner) || !read_at(actor + kActorInfo, info) || !read_at(info + kInfoType, type) ||
        !read_at(status + kStatusBusy, busy) || !read_at(status + kStatusFlags, c.flags) ||
        !read_at(status + kStatusPending, c.pending)) {
        return c;
    }
    c.status = status;
    c.seen.exists = true;
    c.seen.other_user = owner != 0 && user != 0 && owner != user;
    c.seen.hidden = ((c.flags | c.pending) & kHiddenBit) != 0;
    c.seen.busy = busy != 0;
    c.seen.type = type;
    return c;
}

void note(const char* what, uint32_t key, const Copy& before, bool ok) noexcept {
    (ok ? (what[0] == 's' ? c_shown : c_hidden) : c_failed).fetch_add(1, std::memory_order_relaxed);
    if (g_lines.fetch_add(1, std::memory_order_relaxed) >= kLogLines) return;
    uint64_t after = 0;
    if (before.status) read_at(before.status + kStatusFlags, after);
    if (ok) {
        log::info("FocusFollow: {} 0x{:08X} (flags 0x{:X} -> 0x{:X})", what, key, before.flags, after);
    } else {
        log::warn("FocusFollow: could not change 0x{:08X} ({}): the game's setter faulted", key, what);
    }
}

DWORD WINAPI sender_thread(void*) {
    uintptr_t world = 0;
    while (!read_at(g_world_slot, world) || !world) Sleep(500);
    // Waits for remote_visible's hook: it is what checks the setter's code and calls it.
    for (int i = 0; i < 1200 && !remote_visible_ready(); ++i) Sleep(500);
    if (!remote_visible_ready()) {
        log::warn("FocusFollow: remote_visible is not installed: this PC only tells the other which character it plays");
    }
    if (!mount_sync_active()) {
        log::warn("FocusFollow: mount_sync is off, and its dispatch hook is where the change is made: this PC will not "
                  "follow the other player's character");
    }
    g_installed.store(true, std::memory_order_release);
    log::info("FocusFollow ON ({}): the character in control is told to the other PC and its copy is shown there",
              g_guest ? "guest" : "host");
    ffl::Publisher publisher;
    ffl::Focus last{};
    uint64_t last_remote = 0, last_summary = GetTickCount64();
    for (;;) {
        Sleep(100);
        const uint64_t now = GetTickCount64();
        ffl::Focus focus;
        if (read_local(focus)) {
            g_local.store(ffl::pack(focus), std::memory_order_relaxed);
            if (publisher.due(focus, now)) g_outbound.store(ffl::pack(focus), std::memory_order_release);
            if (focus != last) {
                log::info("FocusFollow: this player now controls 0x{:08X} (main 0x{:08X})", focus.focus, focus.main);
                last = focus;
            }
        }
        const uint64_t remote = g_remote.load(std::memory_order_relaxed);
        if (remote != last_remote) {
            const ffl::Focus r = ffl::unpack(remote);
            log::info("FocusFollow: the other player now controls 0x{:08X} (main 0x{:08X})", r.focus, r.main);
            last_remote = remote;
        }
        if (now - last_summary >= 60000 && (remote || c_out_move.load(std::memory_order_relaxed))) {
            last_summary = now;
            const ffl::Focus r = ffl::unpack(remote);
            const ffl::Focus l = ffl::unpack(g_local.load(std::memory_order_relaxed));
            log::info("FocusFollow summary: this player 0x{:08X} | the other 0x{:08X} | shown {} hidden {} failed {} | about the "
                      "character in control, to user 2: Move {} action {} load {}; from the host: Move {} action {} load {}",
                      l.focus, r.focus, c_shown.load(), c_hidden.load(), c_failed.load(), c_out_move.load(),
                      c_out_action.load(), c_out_load.load(), c_in_move.load(), c_in_action.load(), c_in_load.load());
        }
    }
}

void count(uint16_t opcode, std::span<const uint8_t> payload, uint32_t focus, std::atomic<uint64_t>& move,
           std::atomic<uint64_t>& action, std::atomic<uint64_t>& load) noexcept {
    if (!focus || (focus >> 28) != 0xB) return;  // the main character's are not the question
    if (opcode == kOpLoad) {
        // A record names the actor past its header: its count is enough to see whether any went out.
        if (payload.size() < 18) return;
        for (size_t i = 0; i + 4 <= 40 && i + 4 <= payload.size(); ++i) {
            if (payload[i] == (focus & 0xFF) && payload[i + 1] == ((focus >> 8) & 0xFF) && payload[i + 2] == ((focus >> 16) & 0xFF) &&
                payload[i + 3] == (focus >> 24)) {
                load.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        return;
    }
    if (opcode != kOpMoveAck && opcode != kOpStartActionAck) return;
    if (payload.size() < 4) return;
    const uint32_t key = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (static_cast<uint32_t>(payload[3]) << 24);
    if (key != focus) return;
    (opcode == kOpMoveAck ? move : action).fetch_add(1, std::memory_order_relaxed);
}

}  // namespace

void focus_follow_start(bool enabled, bool guest) {
    if (!enabled) {
        log::info("FocusFollow: off (focus_follow=0)");
        return;
    }
    const bool b3576 = game::current_build() == game::Build::v3576;
    const bool b3663 = game::current_build() == game::Build::v3663;
    if (game::current_build() != game::Build::v3527 && !b3576 && !b3663) {
        log::info("FocusFollow: only for builds 3527, 3549, 3576 and 3663, off");
        return;
    }
    const auto* profile = game::reader_profile();
    if (!profile && !b3576 && !b3663) return;
    g_guest = guest;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_world_slot = g_base + (b3663 ? kWorldSlot3663 : b3576 ? kWorldSlot3576 : profile->world_system);
    g_vt_status = g_base + (b3663 ? kVtStatus3663 : b3576 ? kVtStatus3576 : profile->vt_status);
    g_vt_clan = g_base + (b3663 ? kVtClan3663 : b3576 ? kVtClan3576 : kVtClan);
    g_on.store(true, std::memory_order_release);
    if (const HANDLE t = CreateThread(nullptr, 0, sender_thread, nullptr, 0, nullptr)) {
        CloseHandle(t);
    } else {
        log::error("FocusFollow: no thread ({})", GetLastError());
    }
}

bool focus_follow_pop_outbound(std::vector<uint8_t>& frame) noexcept {
    const uint64_t v = g_outbound.exchange(0, std::memory_order_acq_rel);
    if (!v) return false;
    try {
        frame = ffl::frame(ffl::unpack(v));
    } catch (...) {
        return false;
    }
    return true;
}

void focus_follow_discard_outbound() noexcept { g_outbound.store(0, std::memory_order_relaxed); }

bool focus_follow_on_frame(std::span<const uint8_t> frame, uint64_t epoch) noexcept {
    if (!ffl::is_frame(frame)) return false;
    if (!g_on.load(std::memory_order_acquire)) return true;  // ours, ignored
    const auto want = ffl::decode(frame);
    if (!want) return true;
    const uint64_t now = GetTickCount64();
    try {
        const std::lock_guard lock(g_mu);
        const bool reset = epoch != g_epoch;
        g_epoch = epoch;
        g_follower.on_want(*want, now, reset);
    } catch (...) {
        return true;
    }
    g_remote.store(ffl::pack(*want), std::memory_order_release);
    g_work.store(true, std::memory_order_release);
    return true;
}

void focus_follow_on_dispatch() noexcept {
    if (!g_work.load(std::memory_order_acquire) || !g_installed.load(std::memory_order_acquire)) return;
    const uint64_t now = GetTickCount64();
    const uint64_t last = g_last_pass_ms.load(std::memory_order_relaxed);
    if (now - last < ffl::kApplyEveryMs) return;
    g_last_pass_ms.store(now, std::memory_order_relaxed);
    if (!remote_visible_ready()) return;
    const uintptr_t user = local_user();
    if (!user) return;

    // The decisions under the lock (a frame may be arriving); the game's setter outside it.
    ffl::Focus want{};
    std::array<uint32_t, ffl::Follower::kSlots> to_hide{};
    std::array<Copy, ffl::Follower::kSlots> hide_copy{};
    try {
        const std::unique_lock lock(g_mu, std::try_to_lock);
        if (!lock.owns_lock() || !g_follower.known()) return;
        want = g_follower.want();
        const auto left = g_follower.left();
        for (size_t i = 0; i < left.size(); ++i) {
            const uint32_t key = left[i].key;
            if (!key) continue;
            const Copy c = read_copy(key, user);
            if (g_follower.act_on_left(i, c.seen, now) == ffl::Act::Hide) {
                to_hide[i] = key;
                hide_copy[i] = c;
            }
        }
    } catch (...) {
        return;
    }

    const Copy focus = read_copy(want.focus, user);
    if (ffl::act_on_focus(focus.seen) == ffl::Act::Show) {
        const bool ok = remote_visible_set_hidden(focus.status, false, (focus.pending & kHiddenBit) != 0,
                                                  (focus.flags & kHiddenBit) != 0);
        note("shown", want.focus, focus, ok);
    }
    for (size_t i = 0; i < to_hide.size(); ++i) {
        if (!to_hide[i]) continue;
        const bool ok = remote_visible_set_hidden(hide_copy[i].status, true, false, true);
        note("hidden", to_hide[i], hide_copy[i], ok);
    }
}

uint64_t focus_follow_remote() noexcept { return g_remote.load(std::memory_order_acquire); }

void focus_follow_count_out(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    count(opcode, payload, ffl::unpack(g_local.load(std::memory_order_relaxed)).focus, c_out_move, c_out_action, c_out_load);
}

void focus_follow_count_in(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    count(opcode, payload, ffl::unpack(g_remote.load(std::memory_order_relaxed)).focus, c_in_move, c_in_action, c_in_load);
}

}  // namespace cdmp::session2
