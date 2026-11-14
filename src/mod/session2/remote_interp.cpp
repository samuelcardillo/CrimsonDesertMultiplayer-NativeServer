#include "mod/session2/remote_interp.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/attach_follow.h"
#include "mod/session2/combat_follow_logic.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/horse_follow.h"
#include "mod/session2/p8_probes.h"
#include "mod/game/build_profile.h"
#include "mod/session2/remote_interp_logic.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using rip::KeyClass;
using rip::Mode;
using rip::Site;

// ---------------------------------------------------------------- the sites (build 2976, .rsrc)
//
// Verified with capstone on the exe (p8-impl-interp-remota.md §2): each is one whole 7-byte
// instruction, so no branch can land inside the 5-byte patch; the mid hook relocates exactly it.
//   0x11B200E movsxd r10,[rip+0x5B07533] (-> 0x6CB9548)  then lea r9,[rax+rbx] (now)
//   0x11B2730 movsxd r11,[rip+0x5B06E11]                 rax+rbx = now
//   0x11B249A movsxd rax,[rip+0x5B070A7]                 rcx = now (0x11B2496 lea rcx,[rax+rbx])
//   0x11B2B62 movsxd rax,[rip+0x5B069DF]                 rcx = now (0x11B2B5E)
struct HookSite {
    uintptr_t rva;
    uint8_t bytes[7];
    Site site;
    uint32_t off;  // buffer - mc
    const char* what;
};
constexpr HookSite kHooks2976[rip::kSites] = {
    {0x11B200E, {0x4C, 0x63, 0x15, 0x33, 0x75, 0xB0, 0x05}, Site::SetPos, rip::kPosBuffer,
     "the delay read of setInterpolatePositionData 0x11B1FD0"},
    {0x11B2730, {0x4C, 0x63, 0x1D, 0x11, 0x6E, 0xB0, 0x05}, Site::SetRot, rip::kRotBuffer,
     "the delay read of setInterpolateRotateData 0x11B26E0"},
    {0x11B249A, {0x48, 0x63, 0x05, 0xA7, 0x70, 0xB0, 0x05}, Site::UpdPos, rip::kPosBuffer,
     "the delay read of updateInterpolatePositionData 0x11B2420"},
    {0x11B2B62, {0x48, 0x63, 0x05, 0xDF, 0x69, 0xB0, 0x05}, Site::UpdRot, rip::kRotBuffer,
     "the delay read of updateInterpolateRotateData 0x11B2AF0"},
};
// 1.0.0.3527 [V capstone on the PE; buffers read live on 2026-11-05]: the same four readers of the delay, same registers
// (rdi buffer, set: now = rax+rbx, update: now = rcx). The movement controller grew 0x60 before its buffers.
constexpr HookSite kHooks3527[rip::kSites] = {
    {0x1386C3E, {0x4C, 0x63, 0x15, 0x83, 0x15, 0xD8, 0x05}, Site::SetPos, 0x430,
     "the delay read of setInterpolatePositionData 0x1386C00"},
    {0x1387360, {0x4C, 0x63, 0x1D, 0x61, 0x0E, 0xD8, 0x05}, Site::SetRot, 0x4E8,
     "the delay read of setInterpolateRotateData 0x1387310"},
    {0x13870CA, {0x48, 0x63, 0x05, 0xF7, 0x10, 0xD8, 0x05}, Site::UpdPos, 0x430,
     "the delay read of updateInterpolatePositionData 0x1387050"},
    {0x1387792, {0x48, 0x63, 0x05, 0x2F, 0x0A, 0xD8, 0x05}, Site::UpdRot, 0x4E8,
     "the delay read of updateInterpolateRotateData 0x1387720"},
};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the four functions moved whole by +0x7B0 (each a .pdata start at
// old + 0x7B0: 0x13873B0, 0x1387AC0, 0x1387800, 0x1387ED0); the four reads are the same instructions at the same offsets
// (only the RIP displacement differs) and all four resolve to the delay 0x710A2D8 (3527's 0x71081C8 + 0x2110, the block's
// move). Both emptying thresholds `cmp r8,0x3E8` are at old + 0x7B0 too. The buffer offsets (mc+0x430 / +0x4E8) are
// 3527's: not re-derived (no caller in the normal code); resolve() checks cc's back pointer, so a wrong one only fails.
constexpr HookSite kHooks3576[rip::kSites] = {
    {0x13873EE, {0x4C, 0x63, 0x15, 0xE3, 0x2E, 0xD8, 0x05}, Site::SetPos, 0x430,
     "the delay read of setInterpolatePositionData 0x1386C00 (3576 0x13873B0)"},
    {0x1387B10, {0x4C, 0x63, 0x1D, 0xC1, 0x27, 0xD8, 0x05}, Site::SetRot, 0x4E8,
     "the delay read of setInterpolateRotateData 0x1387310 (3576 0x1387AC0)"},
    {0x138787A, {0x48, 0x63, 0x05, 0x57, 0x2A, 0xD8, 0x05}, Site::UpdPos, 0x430,
     "the delay read of updateInterpolatePositionData 0x1387050 (3576 0x1387800)"},
    {0x1387F42, {0x48, 0x63, 0x05, 0x8F, 0x23, 0xD8, 0x05}, Site::UpdRot, 0x4E8,
     "the delay read of updateInterpolateRotateData 0x1387720 (3576 0x1387ED0)"},
};
// Build 1.0.0.3663 (static, 2026-11-13; never run): in 0x13A6C00..0x13E6C00 only one global is read by four
// `movsxd r64,[rip+X]`: 3527's four sites + 0x3EE50, at the same distances (0x48C / 0x722 / 0xB54), each at the same
// offset in its function (0x13C5A50, 0x13C6160, 0x13C5EA0, 0x13C6570; .pdata starts), with the same registers (rdi the
// buffer; set: now = rax+rbx after it, update: rcx = now before it) and the same instruction (only the RIP displacement
// differs); all four read the delay 0x718EA48. Both thresholds `cmp r8,0x3E8` are at 3527's + 0x3EE50. The buffer
// offsets: the CC's constructor 0x96FB30 (vptr 0x59C1660) builds the controller with 0x98CD80(mc, cc) and stores it at
// CC+0xC8 (0x96FEA7); 0x98CD80 stores the CC at mc+0x60 (0x98D556) and initializes mc+0x430 and mc+0x4E8 with the same
// call (0x98D1DA / 0x98D20A). The four functions read the buffer's +0x08 array, +0x10 count, 0xA0-byte samples, ts +0x98.
constexpr HookSite kHooks3663[rip::kSites] = {
    {0x13C5A8E, {0x4C, 0x63, 0x15, 0xB3, 0x8F, 0xDC, 0x05}, Site::SetPos, 0x430,
     "the delay read of setInterpolatePositionData 0x1386C00 (3663 0x13C5A50)"},
    {0x13C61B0, {0x4C, 0x63, 0x1D, 0x91, 0x88, 0xDC, 0x05}, Site::SetRot, 0x4E8,
     "the delay read of setInterpolateRotateData 0x1387310 (3663 0x13C6160)"},
    {0x13C5F1A, {0x48, 0x63, 0x05, 0x27, 0x8B, 0xDC, 0x05}, Site::UpdPos, 0x430,
     "the delay read of updateInterpolatePositionData 0x1387050 (3663 0x13C5EA0)"},
    {0x13C65E2, {0x48, 0x63, 0x05, 0x5F, 0x84, 0xDC, 0x05}, Site::UpdRot, 0x4E8,
     "the delay read of updateInterpolateRotateData 0x1387720 (3663 0x13C6570)"},
};
const HookSite* g_sites = kHooks2976;
constexpr uint32_t kHookLen = 7;
uintptr_t g_delay_global = 0x6CB9548;  // GlobalVariableInt value (2976 object 0x6CB9510; 3527 0x71081C8), default 200

// The emptying threshold: cmp r8,0x3E8 right before `jbe` (0x11B207A / 0x11B277C).
uintptr_t g_threshold_sites[2] = {0x11B2073, 0x11B2775};  // 3527: 0x1386CA3, 0x13873A5
constexpr uint8_t kThresholdOrig[7] = {0x49, 0x81, 0xF8, 0xE8, 0x03, 0x00, 0x00};
constexpr uint8_t kThresholdNew[7] = {0x49, 0x81, 0xF8, 0xC4, 0x09, 0x00, 0x00};  // 2500
static_assert(rip::kPatchedThreshold == 0x9C4);

// The rule of the task: hooks and patches only inside [0x1000, 0x51EB000) (never .xtls).
constexpr uintptr_t kCodeBegin = 0x1000;
uintptr_t g_code_end = 0x51EB000;  // 3527: 0x5595000

constexpr uint64_t kSummaryMs = 60000;

// ---------------------------------------------------------------- state

std::atomic<bool> g_started{false}, g_on{false};
std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_applying{false};  // mode 1 and the four hooks in
std::atomic<uint32_t> g_threshold{rip::kOrigThreshold};
// [session2] remote_interp_owned_cap_ms (P8 session 8 pets; 0 = as before): the cap of an owned actor's delay.
std::atomic<uint32_t> g_owned_cap{0};
std::atomic<uint64_t> g_owned_slots{0}, g_skipped_attached{0}, g_owner_unreadable{0};
std::atomic<int> g_patch_state{0};  // 0 not asked, 1 patched, -1 refused/failed
bool g_guest = false;
uintptr_t g_base = 0, g_delay_addr = 0;
uintptr_t g_resume[rip::kSites] = {};
std::vector<gad::Section> g_secs;
SafetyHookMid g_hooks[rip::kSites];

rip::SlotTable<8192> g_table;

struct SiteCounters {
    std::atomic<uint64_t> calls{0}, resolved{0}, replaced{0}, no_slot{0};
    std::atomic<uint64_t> cls[rip::kClasses] = {};
    std::atomic<uint64_t> fail[5] = {};  // rip::ResolveFail
    rip::TidSet<8> tids;
};
SiteCounters g_site[rip::kSites];

std::atomic<uint64_t> g_resets[rip::kClasses] = {}, g_resets_1000[rip::kClasses] = {}, g_older[rip::kClasses] = {};
std::atomic<uint64_t> g_recorded[rip::kClasses] = {}, g_unreadable_buf{0};
rip::Histogram<7> g_gaps[rip::kClasses] = {rip::Histogram<7>(rip::kGapBounds), rip::Histogram<7>(rip::kGapBounds),
                                             rip::Histogram<7>(rip::kGapBounds)};
rip::Histogram<6> g_delays{rip::kDelayBounds};  // 0xB, per update-position frame (the value mode 1 uses)
// The latest game clock a hook saw (the slots' "touched" is on that clock, not GetTickCount64).
std::atomic<uint64_t> g_last_now{0};

// P8 mount ride ([session2] remote_interp_pair, remote_interp_logic.h "one clock for a rider and its horse"): the
// rider -> horse pairs the client's OnRecvPacket observer notes (horse_follow.cpp), and what the pair did.
std::atomic<bool> g_pair_on{false};
rip::RidePairs g_pairs;
std::atomic<uint64_t> g_pair_frames{0}, g_pair_dense{0}, g_pair_sparse{0}, g_pair_clamped{0};
rip::Histogram<7> g_pair_diff{rip::kPairDiffBounds};  // |D horse - D rider| per paired update frame (ms)
std::atomic<uint32_t> g_pair_last_horse{0}, g_pair_last_d{0};

// P8 session 25 ([session2] remote_interp_combat, guest; remote_interp_logic.h "the combat class"): (b)'s table, fed
// by the mod's network thread (remote_interp_on_host_packet), and what the class did per update-position frame.
std::atomic<uint8_t> g_combat{0};     // 0 | probe | 1
// 2026-11-05, remote_interp_players (remote_interp_logic.h "the players' class"): 0 | probe | 1.
std::atomic<uint8_t> g_players{0};
std::atomic<uint32_t> g_player_delay{0};  // the other player's delay after its last step (ms; 0 = none yet)
std::atomic<uint64_t> g_pl_frames{0}, g_pl_samples{0};
rip::Histogram<6> g_pl_hitch_today{rip::kHitchBounds};  // hitches with the delay in force (ms the character stood)
rip::Histogram<6> g_pl_hitch_would{rip::kHitchBounds};  // the same samples with the players' delay
rip::Histogram<8> g_pl_late{rip::kPlayerBounds};   // how late each sample arrived (ms)
rip::Histogram<8> g_pl_delay{rip::kPlayerBounds};  // the delay it would use / uses, per frame (ms)
std::atomic<uint32_t> g_own_char{0};  // this client's character (its MainPlayerDataStartAck 2756)
rip::EngageTable g_engage;
std::atomic<uint64_t> g_cb_packets{0}, g_cb_no_own{0};
std::atomic<uint64_t> g_cb_frames{0}, g_cb_dense_only{0}, g_cb_engaged_only{0}, g_cb_both{0}, g_cb_starved{0},
    g_cb_past_buffer{0};
rip::Histogram<8> g_cb_would{rip::kCombatDelayBounds};  // the class's D per frame (with probe: the shadow's)
rip::Histogram<8> g_cb_today{rip::kCombatDelayBounds};  // probe: the D in force in the same frames

// ---------------------------------------------------------------- reads on the game's threads

struct FastMem {
    bool u32(uintptr_t a, uint32_t& v) const noexcept { return game::fast_read(a, &v, sizeof v); }
    bool u64(uintptr_t a, uint64_t& v) const noexcept { return game::fast_read(a, &v, sizeof v); }
    bool vec3(uintptr_t a, float* v) const noexcept { return game::fast_read(a, v, 3 * sizeof(float)); }
    bool ptr(uintptr_t a, uintptr_t& v) const noexcept {
        uintptr_t p = 0;
        if (!game::fast_read(a, &p, sizeof p)) return false;
        if (p && (p < 0x10000 || p > 0x00007FFFFFFFFFFFull)) return false;
        v = p;
        return true;
    }
};

uint32_t game_delay() noexcept {
    int32_t raw = 0;
    return game::fast_read(g_delay_addr, &raw, sizeof raw) ? rip::sane_game_delay(raw) : rip::kMinDelay;
}

// Is this slot's actor owned by a user ([actor+0xA0] a pointer whose +0x60 is a 0x9 user key: a user's
// pet, horse or companion)? Kept in the slot: Yes stays (another actor behind the controller resets it),
// No is asked again every second (an owner set after the first sample), Unknown every time. Only with the
// owned cap on. Two SEH reads at most.
uint8_t owned_of(rip::Slot& slot, uintptr_t actor, uint64_t now) noexcept {
    uint8_t owned = slot.owned.load(std::memory_order_relaxed);
    if (!rip::owned_recheck_due(owned, slot.owned_at.load(std::memory_order_relaxed), now)) return owned;
    uint64_t raw = 0;
    uint32_t key = 0;
    const bool owner_read = game::fast_read(actor + rip::kOwnerOffset, &raw, sizeof raw);
    const bool ptr_ok = owner_read && raw >= 0x10000 && raw <= 0x00007FFFFFFFFFFFull;
    const bool key_read = ptr_ok && game::fast_read(static_cast<uintptr_t>(raw) + rip::kOwnerKey, &key, sizeof key);
    const uint8_t now_owned = rip::classify_owner(owner_read, raw, key_read, key);
    if (now_owned == rip::kOwnedUnknown) {
        g_owner_unreadable.fetch_add(1, std::memory_order_relaxed);
        return owned == rip::kOwnedNo ? rip::kOwnedNo : rip::kOwnedUnknown;
    }
    slot.owned_at.store(now, std::memory_order_relaxed);
    if (now_owned != owned) {
        slot.owned.store(now_owned, std::memory_order_relaxed);
        if (now_owned == rip::kOwnedYes) g_owned_slots.fetch_add(1, std::memory_order_relaxed);
    }
    return now_owned;
}

// set position only: what the game is about to do with the new sample (resets, cadence). arrivals: the combat
// class is on (its arrival gaps are kept for every newer sample, moved or not).
void observe_insert(const safetyhook::Context& c, uintptr_t buf, KeyClass cls, rip::Slot* slot, uint32_t key,
                    uint8_t owned, uint32_t owned_cap, bool arrivals, uint64_t now) noexcept {
    const FastMem m;
    const rip::LastSample last = rip::last_sample(m, buf, true);
    uint64_t ts_new = 0;
    float pos_new[3] = {};
    if (!last.ok || !m.u64(c.rbp + rip::kSampleTs, ts_new) || !m.vec3(c.rbp, pos_new)) {
        g_unreadable_buf.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (arrivals && slot && cls == KeyClass::Npc) slot->note_arrival(ts_new);
    // The players' class: every newer sample of the other player's character, and how late it is here.
    const auto pmode = static_cast<Mode>(g_players.load(std::memory_order_relaxed));
    if (slot && cls == KeyClass::Character && pmode != Mode::Off) {
        const uint64_t prev = slot->arr_last.load(std::memory_order_relaxed);
        if (slot->note_arrival(ts_new) && now > ts_new) {
            const uint64_t late = now - ts_new;
            g_pl_samples.fetch_add(1, std::memory_order_relaxed);
            g_pl_late.add(late);
            const uint32_t would = rip::from_fix(slot->d_fix.load(std::memory_order_relaxed));
            const uint32_t gd = game_delay();
            const uint32_t today = pmode == Mode::On && g_applying.load(std::memory_order_relaxed) && would ? would : gd;
            if (const uint32_t h = rip::player_hitch(now, today, prev, ts_new)) g_pl_hitch_today.add(h);
            if (const uint32_t h = rip::player_hitch(now, would ? would : gd, prev, ts_new)) g_pl_hitch_would.add(h);
            rip::note_lateness(*slot, now, static_cast<uint32_t>(std::min<uint64_t>(late, rip::kMaxLateness + 1)));
        }
    }
    rip::SetIn in;
    in.count = last.count;
    in.ts_last = last.ts;
    in.ts_new = ts_new;
    in.moved = last.count == 0 || rip::moved(pos_new, last.pos);
    in.threshold = g_threshold.load(std::memory_order_relaxed);
    const rip::SetOut o = rip::observe_set(in);
    const size_t k = static_cast<size_t>(cls);
    if (o.older) g_older[k].fetch_add(1, std::memory_order_relaxed);
    if (o.reset) g_resets[k].fetch_add(1, std::memory_order_relaxed);
    if (o.reset_1000) g_resets_1000[k].fetch_add(1, std::memory_order_relaxed);
    if (o.gap && in.moved) g_gaps[k].add(o.gap);
    if (o.record && slot) {
        // An owned actor riding a parent (the pet on its owner's shoulder): its gaps are not its cadence.
        if (owned == rip::kOwnedYes && owned_cap &&
            rip::skip_gap_attached(owned, owned_cap, attach_registry_attached(key, GetTickCount64()))) {
            g_skipped_attached.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        slot->record_gap(static_cast<uint32_t>(o.gap));
        g_recorded[k].fetch_add(1, std::memory_order_relaxed);
    }
}

// update position, an 0xB controller in the combat class this frame: its counters (relaxed atomics, a few SEH
// reads of the buffer's last sample).
void note_combat_frame(const rip::Slot& slot, uintptr_t buf, uint64_t now, const rip::CombatStep& cs) noexcept {
    g_cb_frames.fetch_add(1, std::memory_order_relaxed);
    (cs.cls.dense && cs.cls.engaged ? g_cb_both
     : cs.cls.dense                 ? g_cb_dense_only
                                    : g_cb_engaged_only)
        .fetch_add(1, std::memory_order_relaxed);
    g_cb_would.add(cs.would);
    if (cs.mode == Mode::Probe) g_cb_today.add(cs.today);
    // With the class's D (applied with 1, the shadow's with probe): nothing arrived for T = now - D yet.
    if (rip::no_sample_ahead(now, cs.would, slot.arr_last.load(std::memory_order_relaxed))) {
        g_cb_starved.fetch_add(1, std::memory_order_relaxed);
    }
    // ... or T is past the buffer's last INSERTED sample (a still actor's keepalives are not inserted).
    const rip::LastSample last = rip::last_sample(FastMem{}, buf, false);
    if (last.ok && last.count && rip::no_sample_ahead(now, cs.would, last.ts)) {
        g_cb_past_buffer.fetch_add(1, std::memory_order_relaxed);
    }
}

void set_dest(safetyhook::Context& c, Site s, uint32_t v) noexcept {
    switch (s) {
        case Site::SetPos: c.r10 = v; break;
        case Site::SetRot: c.r11 = v; break;
        case Site::UpdPos:
        case Site::UpdRot: c.rax = v; break;
    }
}

template <size_t I>
void on_delay_read(safetyhook::Context& c) noexcept {
    const HookSite& hs = g_sites[I];
    SiteCounters& sc = g_site[I];
    sc.calls.fetch_add(1, std::memory_order_relaxed);
    sc.tids.add(GetCurrentThreadId());
    const auto mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    const uintptr_t buf = c.rdi;
    // The game's clock as the function itself has it at this point (0x1416B80 + bias).
    const uint64_t now = hs.site == Site::SetPos || hs.site == Site::SetRot ? c.rax + c.rbx : c.rcx;
    if (now > g_last_now.load(std::memory_order_relaxed)) g_last_now.store(now, std::memory_order_relaxed);
    rip::ResolveFail why = rip::ResolveFail::None;
    const rip::Resolved r = rip::resolve(FastMem{}, buf, hs.off, &why);
    if (!r.ok) {
        sc.fail[static_cast<size_t>(why)].fetch_add(1, std::memory_order_relaxed);
        return;  // the game's own read runs
    }
    sc.resolved.fetch_add(1, std::memory_order_relaxed);
    const KeyClass cls = rip::key_class(r.key);
    sc.cls[static_cast<size_t>(cls)].fetch_add(1, std::memory_order_relaxed);
    // Only the position sites make a slot (the rotation ones use the controller's).
    const bool create = hs.site == Site::SetPos || hs.site == Site::UpdPos;
    rip::Slot* slot = g_table.get(r.mc, r.key, now, create).slot;
    if (!slot) sc.no_slot.fetch_add(1, std::memory_order_relaxed);
    const uint32_t gd = game_delay();
    const uint32_t owned_cap = g_owned_cap.load(std::memory_order_relaxed);
    const auto cmode = static_cast<Mode>(g_combat.load(std::memory_order_relaxed));
    // The combat class also needs it (an owned actor follows its owner: never in the class).
    const uint8_t owned = (owned_cap || cmode != Mode::Off) && slot && cls == KeyClass::Npc
                              ? owned_of(*slot, r.actor, now)
                              : rip::kOwnedUnknown;
    if (hs.site == Site::SetPos) observe_insert(c, buf, cls, slot, r.key, owned, owned_cap, cmode != Mode::Off, now);
    if (hs.site == Site::UpdPos && slot) {
        // P8 mount ride: a horse its rider (0xA, which always reads the game's value) rides now targets gd.
        uint32_t pair_delay = 0;
        if (cls == KeyClass::Npc && g_pair_on.load(std::memory_order_relaxed) &&
            g_pairs.rider_of(r.key, GetTickCount64())) {
            // The rider's delay: the game's, or with remote_interp_players=1 the one the rider has now.
            const uint32_t pd = g_player_delay.load(std::memory_order_relaxed);
            pair_delay = static_cast<Mode>(g_players.load(std::memory_order_relaxed)) == Mode::On && pd ? pd : gd;
        }
        bool dense = false;
        // P8 session 25: the combat class ((b): this client's engagement table, on the mod's clock).
        rip::CombatStep cs;
        rip::CombatStep* csp = nullptr;
        if (cmode != Mode::Off && cls == KeyClass::Npc) {
            cs.mode = cmode;
            cs.engaged = g_engage.engaged(r.key, GetTickCount64());
            cs.excluded = owned == rip::kOwnedYes;
            csp = &cs;
        }
        rip::update_step(*slot, cls, now, gd, rip::delay_cap(owned, owned_cap), pair_delay, &dense, csp);
        if (csp && cs.cls.in) note_combat_frame(*slot, buf, now, cs);
        const auto pmode = static_cast<Mode>(g_players.load(std::memory_order_relaxed));
        if (cls == KeyClass::Character && pmode != Mode::Off) {
            const uint32_t would = rip::update_player(*slot, now, gd);
            g_pl_frames.fetch_add(1, std::memory_order_relaxed);
            g_pl_delay.add(would);
            g_player_delay.store(would, std::memory_order_relaxed);
        }
        if (pair_delay) {
            g_pair_frames.fetch_add(1, std::memory_order_relaxed);
            (dense ? g_pair_dense : g_pair_sparse).fetch_add(1, std::memory_order_relaxed);
            // A full buffer of dense samples: never a delay older than its first sample (it would stand frozen).
            uint32_t count = 0;
            uint64_t ts0 = 0;
            if (rip::first_sample_ts(FastMem{}, buf, count, ts0)) {
                const uint32_t d_now = rip::from_fix(slot->d_fix.load(std::memory_order_relaxed));
                bool clamped = false;
                const uint32_t d_new =
                    rip::clamp_to_buffer(d_now, count, ts0, now, gd, &clamped, rip::buffer_margin(slot->gaps()));
                if (clamped) {
                    slot->d_fix.store(rip::to_fix(d_new), std::memory_order_relaxed);
                    g_pair_clamped.fetch_add(1, std::memory_order_relaxed);
                }
            }
            const uint32_t dh = rip::from_fix(slot->d_fix.load(std::memory_order_relaxed));
            g_pair_diff.add(dh > gd ? dh - gd : gd - dh);
            g_pair_last_horse.store(r.key, std::memory_order_relaxed);
            g_pair_last_d.store(dh, std::memory_order_relaxed);
        }
    }
    rip::DelayIn in;
    in.mode = mode;
    in.applying = g_applying.load(std::memory_order_relaxed);
    in.players = static_cast<Mode>(g_players.load(std::memory_order_relaxed)) == Mode::On;
    in.cls = cls;
    in.have_slot = slot != nullptr;
    in.updated = slot && slot->updated.load(std::memory_order_relaxed);
    in.d_fix = slot ? slot->d_fix.load(std::memory_order_relaxed) : 0;
    in.game_delay = gd;
    const rip::DelayOut d = rip::decide_delay(in);
    if (hs.site == Site::UpdPos && cls == KeyClass::Npc && in.updated) g_delays.add(d.would);
    if (d.replaced) {
        set_dest(c, hs.site, d.value);
        c.rip = g_resume[I];  // past the 7-byte movsxd: the register keeps our value
        sc.replaced.fetch_add(1, std::memory_order_relaxed);
    }
}

constexpr safetyhook::MidHookFn kFns[rip::kSites] = {&on_delay_read<0>, &on_delay_read<1>, &on_delay_read<2>,
                                                     &on_delay_read<3>};

// ---------------------------------------------------------------- install (its own thread)

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

bool in_allowed_range(uintptr_t rva, size_t len) { return rva >= kCodeBegin && rva + len <= g_code_end; }

bool code_ready() {
    for (size_t i = 0; i < rip::kSites; ++i) {
        if (!bytes_at(g_sites[i].rva, g_sites[i].bytes)) return false;
    }
    return bytes_at(g_threshold_sites[0], kThresholdOrig) && bytes_at(g_threshold_sites[1], kThresholdOrig);
}

// Writes `len` bytes at exe+rva with every thread kept out of the page (user2_funnels' write_code).
bool write_code(uintptr_t rva, const uint8_t* bytes, size_t len) {
    auto* target = reinterpret_cast<uint8_t*>(g_base + rva);
    bool written = false;
    safetyhook::trap_threads(target, target, len, [&] {
        DWORD old = 0;
        if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old)) return;
        std::memcpy(target, bytes, len);
        VirtualProtect(target, len, old, &old);
        FlushInstructionCache(GetCurrentProcess(), target, len);
        written = true;
    });
    if (!written) return false;
    std::vector<uint8_t> back(len);
    return game::safe_read(g_base + rva, back.data(), len) && std::memcmp(back.data(), bytes, len) == 0;
}

bool install_hooks() {
    for (size_t i = 0; i < rip::kSites; ++i) {
        const HookSite& h = g_sites[i];
        if (!in_allowed_range(h.rva, kHookLen)) {
            log::error("RemoteInterp: {} (exe+0x{:X}) is outside the game's code; REFUSED, nothing hooked", h.what,
                       h.rva);
            return false;
        }
        if (!bytes_at(h.rva, h.bytes)) {
            log::error("RemoteInterp: {} (exe+0x{:X}) is not the expected code of this build; REFUSED, nothing "
                       "hooked",
                       h.what, h.rva);
            return false;
        }
    }
    for (size_t i = 0; i < rip::kSites; ++i) g_resume[i] = g_base + g_sites[i].rva + kHookLen;
    for (size_t i = 0; i < rip::kSites; ++i) {
        const HookSite& h = g_sites[i];
        if (!p8_install_mid(g_base, g_secs, h.rva, kHookLen, h.bytes, kFns[i], g_hooks[i], "RemoteInterp", h.what)) {
            // The ones already in stay as probes (they change nothing without g_applying).
            log::error("RemoteInterp: hook {} of 4 refused; the delay stays the game's (the others only count)",
                       i + 1);
            return false;
        }
    }
    return true;
}

// Both sites verified, then written; the first put back if the second cannot be written.
bool patch_threshold() {
    for (uintptr_t rva : g_threshold_sites) {
        if (!in_allowed_range(rva, sizeof kThresholdOrig) ||
            !gad::in_real_code(g_secs, static_cast<uint32_t>(rva), sizeof kThresholdOrig)) {
            log::error("RemoteInterp: the emptying threshold exe+0x{:X} is not inside .rsrc/[0x1000, 0x51EB000); "
                       "REFUSED (threshold stays 1000 ms)",
                       rva);
            return false;
        }
        if (!bytes_at(rva, kThresholdOrig)) {
            log::error("RemoteInterp: the emptying threshold exe+0x{:X} is not `cmp r8,0x3E8` (49 81 F8 E8 03 00 00); "
                       "REFUSED (threshold stays 1000 ms)",
                       rva);
            return false;
        }
    }
    // A failed write may still have changed the bytes (it reads them back): put back every site already touched.
    for (size_t i = 0; i < 2; ++i) {
        if (write_code(g_threshold_sites[i], kThresholdNew, sizeof kThresholdNew)) continue;
        bool back = true;
        for (size_t j = 0; j <= i; ++j) {
            if (!bytes_at(g_threshold_sites[j], kThresholdOrig)) {
                back = write_code(g_threshold_sites[j], kThresholdOrig, sizeof kThresholdOrig) && back;
            }
        }
        log::error("RemoteInterp: exe+0x{:X} could not be written; threshold stays 1000 ms ({})", g_threshold_sites[i],
                   back ? "sites restored" : "a site COULD NOT BE RESTORED");
        return false;
    }
    return true;
}

// The local player's controlled actor exists (ui_pause's check): the world is up.
bool player_in_world() {
    uintptr_t world = 0, mgr = 0, vt = 0, actor = 0, avt = 0;
    if (const auto* profile = game::reader_profile();
        profile && (game::layout_3527() || game::current_build() == game::Build::v3663)) {
        return peek(g_base + profile->world_system, world) && world &&
               peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
               vt == g_base + profile->vt_actor_manager && peek(mgr + g2976::kActorManager_ControlledActor, actor) && actor &&
               peek(actor, avt) && avt;
    }
    return peek(g_base + g2976::kWorldSystemSlot, world) && world &&
           peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
           vt == g_base + g2976::kVtClientActorManager &&
           peek(mgr + g2976::kActorManager_ControlledActor, actor) && actor && peek(actor, avt) &&
           avt == g_base + g2976::kVtControlledActor;
}

void wait_for_world() {
    const uint64_t t0 = GetTickCount64();
    uint64_t last_line = t0;
    log::info("RemoteInterp: waiting for the local player in the world before hooking (never at start-up or on the "
              "title screen)");
    for (int stable = 0; stable < 6;) {
        Sleep(500);
        stable = player_in_world() ? stable + 1 : 0;
        const uint64_t now = GetTickCount64();
        if (now - last_line >= 60000) {
            log::info("RemoteInterp start-up: still waiting for the world after {} s", (now - t0) / 1000);
            last_line = now;
        }
    }
}

// ---------------------------------------------------------------- the summary (its thread)

template <size_t B>
std::string hist_text(const rip::Histogram<B>& h) {
    std::string s;
    for (size_t i = 0; i <= B; ++i) {
        const uint64_t n = h.n[i].load(std::memory_order_relaxed);
        s += std::format("{}{}{} {}", s.empty() ? "" : ", ", i < B ? "<=" : ">", i < B ? h.bounds[i] : h.bounds[B - 1],
                         n);
    }
    return s;
}

std::string tids_text(const rip::TidSet<8>& t) {
    std::string s;
    for (const auto& x : t.tid) {
        if (const uint32_t v = x.load(std::memory_order_relaxed)) s += std::format("{}{}", s.empty() ? "" : ",", v);
    }
    if (const uint64_t o = t.overflow.load(std::memory_order_relaxed)) s += std::format(" (+{} calls from more)", o);
    return s.empty() ? std::string("none") : s;
}

// M5: are the four sites on one thread? (the ids seen, and whether the sets intersect)
std::string threads_verdict() {
    std::vector<uint32_t> all[rip::kSites];
    for (size_t i = 0; i < rip::kSites; ++i) {
        for (const auto& x : g_site[i].tids.tid) {
            if (const uint32_t v = x.load(std::memory_order_relaxed)) all[i].push_back(v);
        }
    }
    bool any = false, single = true;
    uint32_t first = 0;
    for (const auto& v : all) {
        for (uint32_t t : v) {
            if (!any) {
                any = true;
                first = t;
            } else if (t != first) {
                single = false;
            }
        }
    }
    if (!any) return "no call yet";
    return single ? std::format("ONE thread ({}) for every site seen", first)
                  : std::string("SEVERAL threads (the table is atomic: no assumption)");
}

std::string top_slots() {
    // The 0xB controllers touched in the last minute: how many, and the 6 with the largest delay.
    struct Row {
        uint32_t key, d;
        std::array<uint32_t, 3> gaps;
        bool owned;
    };
    const uint64_t now = g_last_now.load(std::memory_order_relaxed);
    const uint64_t since = now > kSummaryMs ? now - kSummaryMs : 0;
    std::vector<Row> rows;
    size_t live = 0, live_npc = 0, live_updated = 0;
    g_table.for_each([&](const rip::Slot& s) {
        if (s.touched.load(std::memory_order_relaxed) < since) return;
        ++live;
        const uint32_t key = s.key.load(std::memory_order_relaxed);
        if (rip::key_class(key) != KeyClass::Npc) return;
        ++live_npc;
        if (!s.updated.load(std::memory_order_relaxed)) return;
        ++live_updated;
        if (const uint32_t d = s.d_fix.load(std::memory_order_relaxed)) {
            rows.push_back({key, rip::from_fix(d), s.gaps(), s.owned.load(std::memory_order_relaxed) == rip::kOwnedYes});
        }
    });
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.d > b.d; });
    std::string s = std::format(" | controllers seen in the last minute {} (0xB {}, of them read by the mode-2 update {})",
                                live, live_npc, live_updated);
    for (size_t i = 0; i < rows.size() && i < 6; ++i) {
        s += std::format("{}0x{:08X}{} {} ms (gaps {}/{}/{})", i ? ", " : " | largest delays: ", rows[i].key,
                         rows[i].owned ? " (owned)" : "", rows[i].d, rows[i].gaps[0], rows[i].gaps[1], rows[i].gaps[2]);
    }
    return s;
}

// P8 mount ride: the pairs riding now, D of the rider (the game's value: 0xA keeps it) vs D of its horse.
std::string pairs_text() {
    const uint64_t tick = GetTickCount64();
    const uint64_t now = g_last_now.load(std::memory_order_relaxed);
    const uint64_t since = now > 2000 ? now - 2000 : 0;
    const uint32_t gd = game_delay();
    std::string live;
    g_pairs.for_each_live(tick, [&](uint32_t rider, uint32_t horse) {
        std::string d = "horse not updated by mode 2";
        g_table.for_each([&](const rip::Slot& s) {
            if (s.key.load(std::memory_order_relaxed) != horse || s.touched.load(std::memory_order_relaxed) < since) {
                return;
            }
            const auto g = s.gaps();
            d = std::format("D horse {} ms (gaps {}/{}/{})", rip::from_fix(s.d_fix.load(std::memory_order_relaxed)),
                            g[0], g[1], g[2]);
        });
        live += std::format("{}0x{:08X} on 0x{:08X}: D rider {} ms, {}", live.empty() ? "" : "; ", rider, horse, gd, d);
    });
    return std::format("RemoteInterp summary pairs (remote_interp_pair=1): riding now [{}] | began {} ended {} | paired "
                       "horse frames {} (rider's delay taken {}, own target kept: its samples not dense enough {}; D "
                       "cut to its full buffer's first sample {}) | |D horse - D rider| per paired frame (ms) [{}] | "
                       "last 0x{:08X} at {} ms",
                       live.empty() ? std::string("none") : live, g_pairs.began.load(), g_pairs.ended.load(),
                       g_pair_frames.load(), g_pair_dense.load(), g_pair_sparse.load(), g_pair_clamped.load(),
                       hist_text(g_pair_diff), g_pair_last_horse.load(), g_pair_last_d.load());
}

// P8 session 25: the combat class over the summary's minute (counters since start; controllers from the slots).
std::string combat_text() {
    const auto cmode = static_cast<Mode>(g_combat.load());
    const uint64_t now = g_last_now.load(std::memory_order_relaxed);
    const uint64_t minute = now > kSummaryMs ? now - kSummaryMs : 0, recent = now > 2000 ? now - 2000 : 0;
    struct Row {
        uint32_t key, d;
        std::array<uint32_t, rip::kArrivals> arr;
    };
    std::vector<Row> rows;
    size_t in_minute = 0, in_now = 0;
    g_table.for_each([&](const rip::Slot& s) {
        const uint64_t at = s.combat_at.load(std::memory_order_relaxed);
        if (!at || at < minute) return;
        ++in_minute;
        if (at < recent) return;
        ++in_now;
        const uint32_t f = (cmode == Mode::Probe ? s.d2_fix : s.d_fix).load(std::memory_order_relaxed);
        rows.push_back({s.key.load(std::memory_order_relaxed), rip::from_fix(f), s.arrivals()});
    });
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.d > b.d; });
    std::string now_list;
    for (size_t i = 0; i < rows.size() && i < 6; ++i) {
        now_list += std::format("{}0x{:08X} {} ms (arrivals {}/{}/{}/{})", i ? ", " : " | in the class now: ",
                                rows[i].key, rows[i].d, rows[i].arr[0], rows[i].arr[1], rows[i].arr[2], rows[i].arr[3]);
    }
    const uint64_t frames = g_cb_frames.load();
    const uint64_t starved = g_cb_starved.load();
    return std::format(
        "RemoteInterp summary combat (remote_interp_combat={}): own character 0x{:08X} | engaging packets {} (own "
        "character unknown {}), engaged now {}, table evictions {} | class frames {} (dense only {}, engaged only {}, "
        "both {}) | D per class frame ({}) [{}]{} | frames with no sample ahead {} ({:.1f}%), past the buffer's last "
        "inserted sample {} | controllers in the class: last minute {}, last 2 s {}{}",
        rip::mode_name(cmode), g_own_char.load(), g_cb_packets.load(), g_cb_no_own.load(),
        g_engage.live(GetTickCount64()), g_engage.evicted.load(), frames, g_cb_dense_only.load(),
        g_cb_engaged_only.load(), g_cb_both.load(), cmode == Mode::On ? "applied with remote_interp=1" : "would be",
        hist_text(g_cb_would),
        cmode == Mode::Probe ? std::format(" | D in force in the same frames [{}]", hist_text(g_cb_today))
                             : std::string(),
        starved, frames ? 100.0 * static_cast<double>(starved) / static_cast<double>(frames) : 0.0,
        g_cb_past_buffer.load(), in_minute, in_now, now_list);
}

void summary() {
    const auto mode = static_cast<Mode>(g_mode.load());
    std::string sites;
    for (size_t i = 0; i < rip::kSites; ++i) {
        const SiteCounters& s = g_site[i];
        sites += std::format(" | {}: calls {} resolved {} (0xA {}, 0xB {}, other {}) unresolved [no CC {}, CC not its "
                             "mc {}, no actor {}, no key {}] no slot {} replaced {} threads [{}]",
                             rip::site_name(g_sites[i].site), s.calls.load(), s.resolved.load(), s.cls[0].load(),
                             s.cls[1].load(), s.cls[2].load(), s.fail[1].load(), s.fail[2].load(), s.fail[3].load(),
                             s.fail[4].load(), s.no_slot.load(), s.replaced.load(), tids_text(s.tids));
    }
    log::info("RemoteInterp summary [{}] ({}): hooks {} | delay {} | threshold {} ms ({}) | game delay {} ms | "
              "threads (M5): {}{}",
              rip::mode_name(mode), g_guest ? "guest" : "host", g_on.load() ? "on" : "OFF",
              g_applying.load() ? "per actor (0xB)" : "the game's (not changed)", g_threshold.load(),
              g_patch_state.load() == 1    ? "patched"
              : g_patch_state.load() == -1 ? "patch REFUSED"
                                           : "not patched",
              game_delay(), threads_verdict(), sites);
    std::string cls;
    for (size_t k = 0; k < rip::kClasses; ++k) {
        cls += std::format(" | {}: buffer emptied {} (with the game's 1000 ms: {}), older samples {}, cadence gaps "
                           "recorded {} | gaps [{}]",
                           rip::class_name(static_cast<KeyClass>(k)), g_resets[k].load(), g_resets_1000[k].load(),
                           g_older[k].load(), g_recorded[k].load(), hist_text(g_gaps[k]));
    }
    log::info("RemoteInterp summary inserts (set pos):{} | unreadable buffers {}", cls, g_unreadable_buf.load());
    const std::string owned =
        g_owned_cap.load()
            ? std::format(" | owned actors (cap {} ms): controllers {}, gaps not recorded while attached to a parent {} "
                          "(attached now {}), owner unreadable {}",
                          rip::delay_cap(rip::kOwnedYes, g_owned_cap.load()), g_owned_slots.load(),
                          g_skipped_attached.load(), attach_registry_count(GetTickCount64()), g_owner_unreadable.load())
            : std::string();
    log::info("RemoteInterp summary delays: 0xB per frame ({} 1) [{}] | controllers: table used {}, reclaimed {}, "
              "another actor {}, full {}{}{}",
              mode == Mode::On ? "applied with" : "would be, with", hist_text(g_delays), g_table.used(),
              g_table.reclaimed(), g_table.rekeyed(), g_table.full(), owned, top_slots());
    if (g_pair_on.load()) log::info("{}", pairs_text());
    if (g_combat.load()) log::info("{}", combat_text());
    if (g_players.load()) {
        log::info("RemoteInterp summary players [{}]: the other player's character, frames {} | hitches (it stood still "
                  "while moving; ms) with the delay in force {} [{}], with the players' delay {} [{}] | samples {}, "
                  "lateness [{}] | players' delay per frame [{}] | now {} ms",
                  rip::mode_name(static_cast<Mode>(g_players.load())), g_pl_frames.load(), g_pl_hitch_today.total(),
                  hist_text(g_pl_hitch_today), g_pl_hitch_would.total(), hist_text(g_pl_hitch_would), g_pl_samples.load(),
                  hist_text(g_pl_late), hist_text(g_pl_delay), g_player_delay.load());
    }
}

DWORD WINAPI interp_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto build = game::current_build();
    if (build == game::Build::unsupported ||
        (!game::legacy_layout() && build != game::Build::v3576 && build != game::Build::v3663)) {
        log::error("RemoteInterp: unsupported game build; remote_interp stays off");
        return 0;
    }
    if (build == game::Build::v3527) {
        g_sites = kHooks3527;
        g_delay_global = 0x71081C8;
        g_threshold_sites[0] = 0x1386CA3;
        g_threshold_sites[1] = 0x13873A5;
        g_code_end = 0x5595000;
    } else if (build == game::Build::v3576) {
        // kHooks3576; the thresholds at 3527's + 0x7B0; the real code section .text1 ends at 0x5597000 (0x1000 +
        // 0x5596000, its flags: execute, not write).
        g_sites = kHooks3576;
        g_delay_global = 0x710A2D8;
        g_threshold_sites[0] = 0x1387453;
        g_threshold_sites[1] = 0x1387B55;
        g_code_end = 0x5597000;
    } else if (build == game::Build::v3663) {
        // kHooks3663; the thresholds at 3527's + 0x3EE50 (0x13C5AF3, 0x13C61F5); the real code section is the first one,
        // [0x1000, 0x5613000) (its flags: execute, not write).
        g_sites = kHooks3663;
        g_delay_global = 0x718EA48;
        g_threshold_sites[0] = 0x13C5AF3;
        g_threshold_sites[1] = 0x13C61F5;
        g_code_end = 0x5613000;
    }
    if (!p8_exe_sections(g_base, g_secs)) {
        log::error("RemoteInterp: the game's section table is unreadable; remote_interp stays off");
        return 0;
    }
    g_delay_addr = g_base + g_delay_global;
    bool ready = false;
    for (int i = 0; i < 24000 && !(ready = code_ready()); ++i) Sleep(5);
    if (!ready) log::warn("RemoteInterp: the game's code is not the expected one after 2 minutes; checking once more");
    wait_for_world();
    const auto mode = static_cast<Mode>(g_mode.load());
    if (!install_hooks()) return 0;
    g_on.store(true);
    if (mode == Mode::On) {
        if (patch_threshold()) {
            g_patch_state.store(1);
            g_threshold.store(rip::kPatchedThreshold);
            // Delays above the game's 1000 ms emptying threshold only work with it raised: per-actor delays apply
            // only when both threshold sites are patched.
            g_applying.store(true);
        } else {
            g_patch_state.store(-1);
        }
    }
    if (g_pair_on.load()) {
        // The pairs come from the client's OnRecvPacket (the sniffer's hook, in by now: late_init installs it once
        // WorldSystem exists, before the local player is in the world).
        horse_follow_set_pair_notes(true);
        bool attached = false;
        for (int i = 0; i < 60 && !(attached = horse_follow_client_attach("remote_interp_pair")); ++i) Sleep(1000);
        if (!attached) {
            g_pair_on.store(false);
            horse_follow_set_pair_notes(false);
            log::warn("RemoteInterp: remote_interp_pair needs the sniffer's OnRecvPacket hook ([sniffer] enabled=1); "
                      "pairs off (every horse keeps its own delay)");
        }
    }
    log::info("RemoteInterp ON ({}, {}): 4 mid hooks at the delay reads exe+0x{:X} / 0x{:X} / 0x{:X} / 0x{:X} (7 "
              "verified bytes each, inside .rsrc) | {} | emptying threshold {} ms{}",
              rip::mode_name(mode), g_guest ? "guest" : "host", g_sites[0].rva, g_sites[1].rva, g_sites[2].rva,
              g_sites[3].rva,
              mode == Mode::On ? "0xB actors in mode 2: their own delay = clamp(max(last 3 gaps) + 150, 200, 1800), "
                                 "approached at <= +0.5 / -0.25 ms per ms; 0xA and the rest: the game's"
                               : "probe: counts and the delay it WOULD use, nothing changed",
              g_threshold.load(),
              mode == Mode::On ? (g_patch_state.load() == 1 ? " (both sites patched)" : " (patch REFUSED)")
                               : "");
    if (const auto cmode = static_cast<Mode>(g_combat.load()); cmode != Mode::Off) {
        log::info("RemoteInterp combat class ON ({}): an 0xB controller whose last {} arrival gaps are <= {} ms, or "
                  "engaged with this client's character (2922 / 2991 within {} s), targets clamp(max(last 3 arrival "
                  "gaps) + {}, {}, {}) (engaged but not dense yet: the moved gaps capped at {} ms), up 0.5 / down 1.0 "
                  "ms per ms; owned actors and paired horses never{}",
                  rip::mode_name(cmode), rip::kArrivals, rip::kDenseGapMs, rip::kEngageMs / 1000, rip::kCombatMargin,
                  rip::kCombatFloor, rip::kCombatCap, rip::kCombatMovedCap,
                  cmode == Mode::Probe ? " | probe: on a shadow controller, counted, never applied" : "");
    }
    uint64_t last = GetTickCount64();
    for (;;) {
        Sleep(1000);
        const uint64_t now = GetTickCount64();
        if (now - last >= kSummaryMs) {
            last = now;
            summary();
        }
    }
}

}  // namespace

void remote_interp_start(const std::string& raw, bool guest, uint32_t owned_cap_ms, bool pair,
                         const std::string& combat_raw, const std::string& players_raw) {
    const auto p = rip::parse_mode(raw);
    if (!p.known) {
        log::warn("RemoteInterp: remote_interp='{}' is not 0, probe or 1; it stays off", raw);
        return;
    }
    auto pc = rip::parse_mode(combat_raw);
    if (!pc.known) {
        log::warn("RemoteInterp: remote_interp_combat='{}' is not 0, probe or 1; it stays off", combat_raw);
        pc.mode = Mode::Off;
    }
    if (p.mode == Mode::Off) {
        if (owned_cap_ms) log::warn("RemoteInterp: remote_interp_owned_cap_ms={} needs remote_interp; off", owned_cap_ms);
        if (pair) log::warn("RemoteInterp: remote_interp_pair=1 needs remote_interp; off");
        if (pc.mode != Mode::Off) log::warn("RemoteInterp: remote_interp_combat needs remote_interp; off");
        return;
    }
    if (pc.mode != Mode::Off && !guest) {
        log::warn("RemoteInterp: remote_interp_combat is the guest's half (the host's is combat_follow_v2); off here");
        pc.mode = Mode::Off;
    }
    auto pp = rip::parse_mode(players_raw);
    if (!pp.known) {
        log::warn("RemoteInterp: remote_interp_players='{}' is not 0, probe or 1; it stays off", players_raw);
        pp.mode = Mode::Off;
    }
    if (g_started.exchange(true)) return;
    g_players.store(static_cast<uint8_t>(pp.mode));
    if (pp.mode != Mode::Off) {
        log::info("RemoteInterp: remote_interp_players={}: the other player's character (0xA) {} a delay that follows how "
                  "late its samples arrive (peak + {} ms, {}..{} ms, the peak falling 1 ms per {} ms)",
                  rip::mode_name(pp.mode), pp.mode == Mode::On ? "gets" : "is measured for", rip::kPlayerMargin,
                  rip::kMinDelay, rip::kPlayerMax, 16 * rip::kLateDecayDiv);
    }
    g_mode.store(static_cast<uint8_t>(p.mode));
    g_combat.store(static_cast<uint8_t>(pc.mode));  // before any host packet can reach remote_interp_on_host_packet
    g_guest = guest;
    if (owned_cap_ms) {
        g_owned_cap.store(owned_cap_ms);
        attach_registry_enable(true);  // the network side notes which owned actors ride a parent
        log::info("RemoteInterp: actors with an owner ([actor+0xA0] != 0: pets, horses, companions) get a delay of at "
                  "most {} ms (remote_interp_owned_cap_ms={}); their sample gaps are not recorded while a StartAction "
                  "seen on the network attaches them to a character (0xA) parent",
                  rip::delay_cap(rip::kOwnedYes, owned_cap_ms), owned_cap_ms);
    }
    if (pair) {
        g_pair_on.store(true);
        log::info("RemoteInterp: remote_interp_pair=1: a horse (0xB) whose rider (0xA) names it as Path parent in its "
                  "latest Move Ack targets the rider's delay (the game's, {} ms by default) while each of its last 3 "
                  "sample gaps is within it, reached through the same no-jump approach (<= +0.5 / -0.25 ms per ms); "
                  "every other actor keeps its own",
                  rip::kMinDelay);
    }
    CloseHandle(CreateThread(nullptr, 0, interp_thread, nullptr, 0, nullptr));
}

void remote_interp_note_ride(uint32_t rider, uint32_t horse) noexcept {
    if (!g_pair_on.load(std::memory_order_relaxed)) return;
    g_pairs.note(rider, horse, GetTickCount64());
}

// P8 re-entry (s25/reentrada.md §1.4): a new remote conversation starts every table from scratch. The mod's network
// thread, at the conversation's first host packet (before its 2756 sets this client's character again); the hooks see
// the slot table's new generation (lock-free: a slot of the old one starts again at its next lookup).
static std::atomic<uint32_t> g_conv_seen{0};
static void conversation_check() noexcept {
    const uint32_t conv = guest_conversation_id();
    if (conv == g_conv_seen.load(std::memory_order_relaxed) || g_conv_seen.exchange(conv) == conv) return;
    if (conv < 2) return;  // the first remote conversation: nothing of an earlier one
    g_table.new_generation();
    g_engage.forget();
    g_pairs.forget();
    g_own_char.store(0, std::memory_order_relaxed);
    try {
        log::info("RemoteInterp: remote conversation {} (re-entry): slot table generation {}, engaged enemies and ride "
                  "pairs forgotten, own character unknown until its 2756",
                  conv, g_table.generation());
    } catch (...) {
    }
}

void remote_interp_on_host_packet(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    if (g_on.load(std::memory_order_relaxed) && g_guest) conversation_check();
    if (!g_combat.load(std::memory_order_relaxed)) return;
    if (opcode == 2756) {  // MainPlayerDataStartAck: this client's character, u32 at +0 (guest.cpp, mount_sync)
        if (payload.size() >= 4) {
            const uint32_t key = cfl::rd32(payload, 0);
            if (cfl::is_a(key)) g_own_char.store(key, std::memory_order_relaxed);
        }
        return;
    }
    if (opcode != cfl::kOpAttackTargetAck && opcode != cfl::kOpStartActionAck) return;
    const uint32_t own = g_own_char.load(std::memory_order_relaxed);
    if (!own) {
        g_cb_no_own.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // combat_follow's own rule (the host's side of session 9), with this client's character as "user 2".
    if (const uint32_t k = cfl::read_out(opcode, payload, own).engage) {
        g_engage.note(k, GetTickCount64());
        g_cb_packets.fetch_add(1, std::memory_order_relaxed);
    }
}

bool remote_interp_active() { return g_on.load(); }

std::string remote_interp_describe() {
    if (!g_started.load()) return {};
    uint64_t replaced = 0;
    for (const auto& s : g_site) replaced += s.replaced.load();
    return std::format("remote_interp {} (hooks {}, threshold {} ms{}{}{}) | delays replaced {}",
                       rip::mode_name(static_cast<Mode>(g_mode.load())), g_on.load() ? "on" : "OFF",
                       g_threshold.load(),
                       g_owned_cap.load() ? std::format(", owned actors capped at {} ms",
                                                        rip::delay_cap(rip::kOwnedYes, g_owned_cap.load()))
                                          : std::string(),
                       g_pair_on.load() ? std::format(", rider/horse pairs: frames {}", g_pair_frames.load())
                                        : std::string(),
                       g_combat.load() ? std::format(", combat class {}: frames {}",
                                                     rip::mode_name(static_cast<Mode>(g_combat.load())),
                                                     g_cb_frames.load())
                                       : std::string(),
                       replaced);
}

}  // namespace cdmp::session2
