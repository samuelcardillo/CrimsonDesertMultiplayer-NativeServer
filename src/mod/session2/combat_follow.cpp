#include "mod/game/build_profile.h"
#include "mod/session2/combat_follow.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <cmath>
#include <format>
#include <string>

#include "mod/game/actor_lookup.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/combat_follow_logic.h"
#include "mod/session2/horse_follow_logic.h"
#include "mod/session2/observer_hold_acks.h"
#include "mod/session2/server.h"

// Windows 10 1803+; older SDK headers lack the name (the call then fails and a plain timer is used).
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using cfl::Mode;
using cfl::Skip;

// The host client's game clock as its threads read it (remote_motion.cpp, divergence_probe): frame ms + us/1000
// + the client->server bias. Only differences of it are used (the anchor), so the bias cancels out.
// 3527 [V capstone 0x15F9B20, 0x1386C1C]: 0x70D9E60, 0x70D9E70, 0x71BE198.
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the frame clock 0x15FA340 reads 0x70DBF68 / 0x70DBF78 (0x15FA360,
// 0x15FA36C), setInterpolatePositionData 0x13873B0 the bias 0x71C03A8 (0x13873CC): 3527's + 0x2108 / + 0x2210.
// Build 1.0.0.3663 (static, 2026-11-13; never run): the frame clock 0x163B030 (called right before the delay read of
// setInterpolatePositionData 0x13C5A50) reads ms 0x71600E8 at +0x20 and us 0x71600F0 at +0x2C (as 3576's; now 8 bytes
// apart), setInterpolatePositionData reads the bias 0x7245468 at +0x1C (0x13C5A6C). The actor / TransformSync offsets
// below are 3527's: comps +0x68 and TransformSync comps+0x1A0 are in 3663's code (the action query 0xB42220 is called on
// [comps+0x1A0]; TransformSync's load reader 0x23DCEA0 is 3527's 0x236BF20 instruction for instruction; 0x146C2C7..
// 0x146C315 still adds [+0xB4/+0xB8/+0xBC] to the sector shorts [+0xC0/+0xC2] * 1000), but the quaternion +0xA4, the
// control byte +0xC8 and the actor manager's table are not re-derived.
uintptr_t kClockBase = 0x6C8CD68;
uintptr_t kClockFrac = 0x6C8CD70;
uintptr_t kClockBias = 0x6D69438;
// Client actor -> components (+0x68) -> TransformSync (+0x1A0): quat +0xA4, pos +0xB4 (sector-local), sector
// i16 x/z +0xC0 (actor_lookup.cpp); the control state byte [actor+0xC8] (mirror-ack-formats.md §5: 1/2 =
// simulated by this client, 0 = remote).
constexpr uint32_t kActorComps = 0x68, kCompsTs = 0x1A0, kTsQuat = 0xA4, kTsPos = 0xB4, kTsSector = 0xC0;
constexpr uint32_t kActorControl = 0xC8;
constexpr uint32_t kActorKey = 0x60;  // u32, checked again in the same read pass (review 2026-10-10)
constexpr float kSectorSize = 1000.0f;
constexpr uint64_t kSummaryMs = 60000;
// v2: the client actor manager's hash table (actor_lookup.cpp, remote_motion.cpp's find_actor_fast), read with
// fast_read (SEH only, no VirtualQuery per read).
constexpr uint32_t kMgrTable = 0x08, kTableBucketCount = 0x88, kTableBuckets = 0x98, kTableNodes = 0xA0;
constexpr uint32_t kBucketStride = 0x100, kBucketMaxEntries = (kBucketStride - 8) / 8;
constexpr uint32_t kNodeKey = 0x04, kNodeActor = 0x08;
constexpr size_t kTableSize = 32;

std::atomic<uint8_t> g_mode{0};
// combat_follow_v2: 0 | probe | 1. Stored with release after g_qpc_freq; take_frame loads it with acquire.
std::atomic<uint8_t> g_v2{0};
std::atomic<bool> g_started{false}, g_hires{false};
uintptr_t g_base = 0;
// v2's clock is QueryPerformanceCounter (the 100 ms keepalive at 33 ms ticks needs better than GetTickCount64's
// 15.6 ms steps); v1 keeps GetTickCount64.
std::atomic<uint64_t> g_qpc_freq{0};

// v1 (session 9): its table, its lock (take_frame's threads try, its thread acquires) and its clock, exactly as
// before. v2 has its own three: with combat_follow_v2=probe nothing of v2 reaches what v1 sees, decides or sends.
SRWLOCK g_lock = SRWLOCK_INIT;
cfl::Table<kTableSize> g_table;
SRWLOCK g_lock2 = SRWLOCK_INIT;
cfl::Table<kTableSize> g_table2;

std::atomic<uint64_t> c_engage_pk{0}, c_fight_pk{0}, c_samples{0}, c_busy{0}, c_busy2{0}, c_clock_unread{0},
    c_removed{0}, c_resets{0}, c_late_ticks{0};
std::atomic<bool> g_reset_pending{false}, g_reset_pending2{false};
std::atomic<uint32_t> g_engaged_now{0}, g_engaged2_now{0}, g_engaged_v2_now{0};
hfl::CadenceHist h_real;  // gaps of the real samples of followed enemies (the table of the path that sends)
// |real ts - the host client's game clock when take_frame saw it| (ms): the anchor's sanity.
std::array<std::atomic<uint64_t>, 6> h_offset{};
constexpr std::array<uint64_t, 5> kOffsetBounds = {20, 50, 100, 250, 1000};
std::atomic<int64_t> g_offset_last{0};

// The counters of one path: v1 (session 9) and v2 (the combat stream; with probe, decided and never sent).
struct PathStats {
    std::atomic<uint64_t> ticks{0}, candidates{0}, gone{0}, unreadable{0}, key_mismatch{0}, not_local{0}, beyond{0},
        held{0}, user2_unread{0}, beyond_cap{0}, made{0}, refused{0}, would{0}, keepalives{0};
    std::atomic<uint64_t> skip[cfl::kSkips] = {};
    std::atomic<uint64_t> control[4] = {};  // [actor+0xC8] = 0, 1, 2, other
    std::atomic<uint32_t> last_key{0}, max_dist_cm{0};
    hfl::CadenceHist h_synth;  // gaps of our samples (or would-be)
};
PathStats g_v1s, g_v2s;

// The performance counter in 1/unit s, without overflowing the product (10 MHz x 1e6 would after ~3 weeks of uptime).
// Only once g_v2 is set (g_qpc_freq is non-zero then).
uint64_t qpc_in(uint64_t unit) {
    const uint64_t f = g_qpc_freq.load(std::memory_order_relaxed);
    if (!f) return 0;
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    const auto q = static_cast<uint64_t>(c.QuadPart);
    return q / f * unit + q % f * unit / f;
}
uint64_t v2_ms() { return qpc_in(1000); }
uint64_t qpc_us() { return qpc_in(1000000); }

bool game_now(uint64_t& now) noexcept {
    uint64_t base = 0, frac = 0;
    int64_t bias = 0;
    if (!game::fast_read(g_base + kClockBase, &base, sizeof base) ||
        !game::fast_read(g_base + kClockFrac, &frac, sizeof frac) ||
        !game::fast_read(g_base + kClockBias, &bias, sizeof bias)) {
        return false;
    }
    now = base + frac / 1000 + static_cast<uint64_t>(bias);
    return now != 0;
}

void add_offset(int64_t d) {
    const uint64_t a = static_cast<uint64_t>(d < 0 ? -d : d);
    size_t i = 0;
    while (i < kOffsetBounds.size() && a > kOffsetBounds[i]) ++i;
    h_offset[i].fetch_add(1, std::memory_order_relaxed);
}

// The actor's pose and control byte in the host client (SEH reads, no VirtualQuery).
// The actor must still carry `key` ([actor+0x60]) when its pose is read: a slot reused by another actor
// between the lookup and the reads is refused (key_mismatch).
bool read_pose(uintptr_t actor, uint32_t key, float (&pos)[3], float (&quat)[4], uint8_t& control,
               bool& key_mismatch) noexcept {
    uintptr_t comps = 0, ts = 0;
    int16_t sector[2] = {};
    float p[3] = {};
    uint32_t k1 = 0, k2 = 0;
    key_mismatch = false;
    if (!game::fast_read(actor + kActorKey, &k1, sizeof k1)) return false;
    if (k1 != key) {
        key_mismatch = true;
        return false;
    }
    if (!game::fast_read(actor + kActorControl, &control, 1)) return false;
    if (!game::fast_read(actor + kActorComps, &comps, sizeof comps) || !comps ||
        !game::fast_read(comps + kCompsTs, &ts, sizeof ts) || !ts ||
        !game::fast_read(ts + kTsQuat, quat, sizeof quat) || !game::fast_read(ts + kTsPos, p, sizeof p) ||
        !game::fast_read(ts + kTsSector, sector, sizeof sector)) {
        return false;
    }
    if (!game::fast_read(actor + kActorKey, &k2, sizeof k2) || k2 != key) {
        key_mismatch = true;
        return false;
    }
    pos[0] = p[0] + sector[0] * kSectorSize;
    pos[1] = p[1];
    pos[2] = p[2] + sector[1] * kSectorSize;
    return cfl::sane_pose(pos, quat);
}

std::string hist(const hfl::CadenceHist& h) {
    std::string s;
    for (size_t i = 0; i < h.n.size(); ++i) {
        s += std::format("{}{}{} {}", s.empty() ? "" : ", ", i < hfl::kCadenceBounds.size() ? "<=" : ">",
                         i < hfl::kCadenceBounds.size() ? hfl::kCadenceBounds[i] : hfl::kCadenceBounds.back(),
                         h.n[i].load(std::memory_order_relaxed));
    }
    return s;
}

// One enemy that passed the reads: decided, and sent (send) or counted; noted in its path's table.
void decide_one(const cfl::Enemy& e, const float (&rpos)[3], const float (&rquat)[4], uint64_t gnow, uint64_t now,
                const cfl::Policy& pol, PathStats& st, bool send, cfl::Table<kTableSize>& table, SRWLOCK& lock) {
    uint64_t ts = 0;
    bool keepalive = false;
    const Skip s = cfl::decide(e, gnow, now, rpos, rquat, ts, pol, &keepalive);
    st.skip[static_cast<size_t>(s)].fetch_add(1, std::memory_order_relaxed);
    if (s != Skip::None) return;
    // A v2 keepalive repeats the last pose sent bit for bit (the game does not insert it: no gap in the buffer).
    const bool same = keepalive && pol.keepalive_same_pose;
    float pos[3], quat[4];
    std::copy(same ? e.pos : rpos, (same ? e.pos : rpos) + 3, pos);
    std::copy(same ? e.quat : rquat, (same ? e.quat : rquat) + 4, quat);
    float vel[3] = {};
    cfl::velocity(e, pos, gnow, vel);
    if (e.have_sent && ts > e.sent_ts) st.h_synth.add(ts - e.sent_ts);
    if (keepalive && pol.keepalive_same_pose) st.keepalives.fetch_add(1, std::memory_order_relaxed);
    st.last_key.store(e.key, std::memory_order_relaxed);
    if (send) {
        // 3576's and 3663's MoveActorAck are 3527's (game::wire_build()).
        const bool sent = game::wire_build() == game::Build::v3527
                              ? server_push_extra(cfl::make_move_ack_3527(e.key, pos, quat, vel, ts))
                              : server_push_extra(cfl::make_move_ack(e.key, pos, quat, vel, ts));
        if (!sent) {
            st.refused.fetch_add(1, std::memory_order_relaxed);
            return;  // not noted as sent: the next tick tries again
        }
        st.made.fetch_add(1, std::memory_order_relaxed);
    } else {
        st.would.fetch_add(1, std::memory_order_relaxed);
    }
    AcquireSRWLockExclusive(&lock);
    table.sent(e.key, ts, gnow, now, pos, quat);
    ReleaseSRWLockExclusive(&lock);
}

// ---------------------------------------------------------------- v1 (session 9), as before

void tick_v1() {
    PathStats& st = g_v1s;
    st.ticks.fetch_add(1, std::memory_order_relaxed);
    // A new guest epoch asked for a reset (combat_follow_on_epoch never waits for the lock itself).
    if (g_reset_pending.exchange(false, std::memory_order_acq_rel)) {
        AcquireSRWLockExclusive(&g_lock);
        g_table.reset();
        ReleaseSRWLockExclusive(&g_lock);
        c_resets.fetch_add(1, std::memory_order_relaxed);
    }
    const auto mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    const uint32_t u2 = server_user2_player_key();
    if (!u2 || !server_live_session2()) return;
    const uint64_t now = GetTickCount64();
    std::array<cfl::Enemy, cfl::kMaxFollowed> list{};
    size_t n = 0;
    AcquireSRWLockExclusive(&g_lock);
    n = g_table.followed(now, list);
    g_engaged_now.store(static_cast<uint32_t>(g_table.engaged(now)), std::memory_order_relaxed);
    ReleaseSRWLockExclusive(&g_lock);
    if (!n) return;
    st.candidates.fetch_add(n, std::memory_order_relaxed);
    const auto u2pos = game::actor_world_position(u2);
    if (!u2pos) {
        st.user2_unread.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const float up[3] = {u2pos->x, u2pos->y, u2pos->z};
    uint64_t gnow = 0;
    if (!game_now(gnow)) {
        c_clock_unread.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    for (size_t i = 0; i < n; ++i) {
        const cfl::Enemy& e = list[i];
        const auto actor = game::find_actor(e.key);
        if (!actor || !*actor) {
            st.gone.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        float pos[3] = {}, quat[4] = {};
        uint8_t control = 0xFF;
        bool mismatch = false;
        if (!read_pose(*actor, e.key, pos, quat, control, mismatch)) {
            (mismatch ? st.key_mismatch : st.unreadable).fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        st.control[control <= 2 ? control : 3].fetch_add(1, std::memory_order_relaxed);
        if (control != 1 && control != 2) {
            st.not_local.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const float d = cfl::distance(pos, up);
        if (d > cfl::kRangeM) {
            st.beyond.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (const auto cm = static_cast<uint32_t>(d * 100.0f); cm > st.max_dist_cm.load(std::memory_order_relaxed)) {
            st.max_dist_cm.store(cm, std::memory_order_relaxed);
        }
        if (observer_hold_acks_holding(e.key)) {
            st.held.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        decide_one(e, pos, quat, gnow, now, cfl::kPolicyV1, st, mode == Mode::On, g_table, g_lock);
    }
}

// ---------------------------------------------------------------- v2 (the combat stream): its lookup with fast_read

template <class T>
bool fr(uintptr_t a, T& v) noexcept {
    return game::fast_read(a, &v, sizeof v);
}
bool fp(uintptr_t a, uintptr_t& v) noexcept {
    const auto p = game::fast_ptr(a);
    if (!p) return false;
    v = *p;
    return true;
}

struct ActorTable {
    uint32_t buckets = 0;
    uintptr_t bucket_base = 0, nodes = 0;
};

// The client actor manager (its vtable checked) and its hash table, once per tick.
bool actor_table(ActorTable& t) noexcept {
    uintptr_t world = 0, mgr = 0, vt = 0, table = 0;
    const auto* profile = game::reader_profile();
    if (!profile) return false;
    return fp(g_base + profile->world_system, world) && fp(world + g2976::kWorldSystem_ActorManager, mgr) &&
           fr(mgr, vt) && vt == g_base + profile->vt_actor_manager && fp(mgr + kMgrTable, table) &&
           fr(table + kTableBucketCount, t.buckets) && t.buckets && t.buckets <= (1u << 24) &&
           fp(table + kTableBuckets, t.bucket_base) && fp(table + kTableNodes, t.nodes);
}

uintptr_t find_actor_fast(const ActorTable& t, uint32_t key) noexcept {
    const uintptr_t bucket = t.bucket_base + static_cast<uintptr_t>(key % t.buckets) * kBucketStride;
    uint32_t n = 0;
    if (!fr(bucket, n)) return 0;
    for (uint32_t i = 0; i < n && i < kBucketMaxEntries; ++i) {
        uint32_t k = 0, idx = 0;
        if (!fr(bucket + 8 + i * 8, k) || k != key || !fr(bucket + 0xC + i * 8, idx)) continue;
        uintptr_t node = 0, actor = 0;
        uint32_t nk = 0;
        if (!fp(t.nodes + static_cast<uintptr_t>(idx) * 8, node) || !fr(node + kNodeKey, nk) || nk != key ||
            !fp(node + kNodeActor, actor)) {
            return 0;
        }
        return actor;
    }
    return 0;
}

// One actor as read this tick.
struct Read {
    enum State : uint8_t { Ok, Gone, Unreadable, Mismatch };
    State state = Gone;
    uint8_t control = 0xFF;
    float pos[3] = {};
    float quat[4] = {0, 0, 0, 1};
};

Read read_actor(const ActorTable& t, uint32_t key) noexcept {
    Read r;
    const uintptr_t actor = find_actor_fast(t, key);
    if (!actor) return r;
    bool mismatch = false;
    r.state = read_pose(actor, key, r.pos, r.quat, r.control, mismatch) ? Read::Ok
              : mismatch                                                ? Read::Mismatch
                                                                        : Read::Unreadable;
    return r;
}

void tick_v2() {
    PathStats& st = g_v2s;
    const auto mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    const auto v2 = static_cast<Mode>(g_v2.load(std::memory_order_relaxed));
    st.ticks.fetch_add(1, std::memory_order_relaxed);
    if (g_reset_pending2.exchange(false, std::memory_order_acq_rel)) {
        AcquireSRWLockExclusive(&g_lock2);
        g_table2.reset();
        ReleaseSRWLockExclusive(&g_lock2);
        if (v2 == Mode::On) c_resets.fetch_add(1, std::memory_order_relaxed);
    }
    const uint32_t u2 = server_user2_player_key();
    if (!u2 || !server_live_session2()) return;
    const uint64_t now = v2_ms();
    std::array<cfl::Enemy, kTableSize> list{};
    size_t n = 0;
    AcquireSRWLockExclusive(&g_lock2);
    n = g_table2.followed_v2(now, list);
    g_engaged2_now.store(static_cast<uint32_t>(g_table2.engaged(now)), std::memory_order_relaxed);
    ReleaseSRWLockExclusive(&g_lock2);
    g_engaged_v2_now.store(static_cast<uint32_t>(n), std::memory_order_relaxed);
    if (!n) return;
    st.candidates.fetch_add(n, std::memory_order_relaxed);
    ActorTable at;
    const Read me = actor_table(at) ? read_actor(at, u2) : Read{};
    if (me.state != Read::Ok) {  // user 2's character (or the actor table itself) unreadable
        st.user2_unread.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    uint64_t gnow = 0;
    if (!game_now(gnow)) {
        c_clock_unread.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // The filters, then the kMaxFollowedV2 nearest.
    std::array<Read, kTableSize> reads{};
    std::array<cfl::Near, kTableSize> pass{};
    size_t np = 0;
    for (size_t i = 0; i < n; ++i) {
        const cfl::Enemy& e = list[i];
        const Read& r = reads[i] = read_actor(at, e.key);
        if (r.state != Read::Ok) {
            (r.state == Read::Gone       ? st.gone
             : r.state == Read::Mismatch ? st.key_mismatch
                                         : st.unreadable)
                .fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        st.control[r.control <= 2 ? r.control : 3].fetch_add(1, std::memory_order_relaxed);
        if (r.control != 1 && r.control != 2) {
            st.not_local.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const float d = cfl::distance(r.pos, me.pos);
        if (d > cfl::kRangeV2M) {
            st.beyond.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (observer_hold_acks_holding(e.key)) {
            st.held.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        pass[np++] = cfl::Near{i, d};
    }
    const size_t keep = cfl::nearest_first(pass, np, cfl::kMaxFollowedV2);
    st.beyond_cap.fetch_add(np - keep, std::memory_order_relaxed);
    const bool send = mode == Mode::On && v2 == Mode::On;
    for (size_t j = 0; j < keep; ++j) {
        if (const auto cm = static_cast<uint32_t>(pass[j].dist * 100.0f);
            cm > st.max_dist_cm.load(std::memory_order_relaxed)) {
            st.max_dist_cm.store(cm, std::memory_order_relaxed);
        }
        const Read& r = reads[pass[j].index];
        decide_one(list[pass[j].index], r.pos, r.quat, gnow, now, cfl::kPolicyV2, st, send, g_table2, g_lock2);
    }
}

// ---------------------------------------------------------------- threads and summary

std::string path_text(const PathStats& st, bool v2) {
    std::string skips;
    for (size_t i = 0; i < cfl::kSkips; ++i) {
        skips += std::format("{}{} {}", i ? ", " : "", cfl::skip_name(static_cast<Skip>(i)), st.skip[i].load());
    }
    return std::format(
        "ticks {}, candidates {} (gone {}, unreadable {}, key changed under the read {}, not simulated here {}, beyond "
        "{:.0f} m {}, withheld from user 2 {}, user 2 unreadable {}{}) | control byte 0/1/2/other {}/{}/{}/{} | "
        "decisions [{}]{} | last 0x{:08X}, farthest {:.1f} m | our cadence [{}]",
        st.ticks.load(), st.candidates.load(), st.gone.load(), st.unreadable.load(), st.key_mismatch.load(),
        st.not_local.load(), v2 ? cfl::kRangeV2M : cfl::kRangeM, st.beyond.load(), st.held.load(),
        st.user2_unread.load(),
        v2 ? std::format(", past the {} nearest {}", cfl::kMaxFollowedV2, st.beyond_cap.load()) : std::string(),
        st.control[0].load(), st.control[1].load(), st.control[2].load(), st.control[3].load(), skips,
        v2 ? std::format(" | keepalives (same pose) {}", st.keepalives.load()) : std::string(), st.last_key.load(),
        static_cast<double>(st.max_dist_cm.load()) / 100.0, hist(st.h_synth));
}

void summary_if_due(uint64_t& last_summary) {
    if (const uint64_t now = GetTickCount64(); now - last_summary >= kSummaryMs) {
        last_summary = now;
        log::info("{}", combat_follow_describe());
        if (static_cast<Mode>(g_v2.load()) == Mode::Probe) {
            log::info("CombatFollow v2 probe (its own table and thread, decided beside v1, nothing of it sent): engaged "
                      "now {} (with the fights near user 2: {}) | {} | would make {} | table busy {}",
                      g_engaged2_now.load(), g_engaged_v2_now.load(), path_text(g_v2s, true), g_v2s.would.load(),
                      c_busy2.load());
        }
    }
}

// v1's thread (combat_follow_v2 0 / probe): session 9's loop, unchanged. It writes the minute summary.
DWORD WINAPI v1_thread(LPVOID) {
    uint64_t last_summary = GetTickCount64();
    for (;;) {
        Sleep(cfl::kTickMs);
        try {
            tick_v1();
            summary_if_due(last_summary);
        } catch (...) {
        }
    }
}

// Waits until the QPC microsecond `due`: the waitable timer (high resolution when the system has it), or Sleep.
void wait_until_us(HANDLE timer, uint64_t due) {
    const uint64_t now = qpc_us();
    if (due <= now) return;
    const uint64_t left = due - now;
    if (timer) {
        LARGE_INTEGER rel;
        rel.QuadPart = -static_cast<LONGLONG>(left * 10);  // relative, 100 ns units
        if (SetWaitableTimer(timer, &rel, 0, nullptr, nullptr, FALSE) &&
            WaitForSingleObject(timer, 1000) == WAIT_OBJECT_0) {
            return;
        }
    }
    Sleep(static_cast<DWORD>((left + 999) / 1000));
}

// v2's thread (combat_follow_v2 probe / 1): a tick every kTickV2Ms on a drift-free schedule. With 1 it writes the
// minute summary (v1 does not run).
DWORD WINAPI v2_thread(LPVOID) {
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    g_hires.store(timer != nullptr);
    if (!timer) timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS);
    if (!g_hires.load()) {
        log::warn("CombatFollow v2: no high-resolution waitable timer on this system; {} ({} ms ticks may run late)",
                  timer ? "a plain one" : "Sleep", cfl::kTickV2Ms);
    }
    const bool summaries = static_cast<Mode>(g_v2.load()) == Mode::On;
    uint64_t last_summary = GetTickCount64();
    constexpr uint64_t kPeriodUs = cfl::kTickV2Ms * 1000ull;
    uint64_t due = qpc_us() + kPeriodUs;
    for (;;) {
        wait_until_us(timer, due);
        try {
            tick_v2();
            if (summaries) summary_if_due(last_summary);
        } catch (...) {
        }
        bool late = false;
        due = cfl::next_deadline(due, qpc_us(), kPeriodUs, &late);
        if (late) c_late_ticks.fetch_add(1, std::memory_order_relaxed);
    }
}

bool start_thread(LPTHREAD_START_ROUTINE fn) {
    HANDLE t = CreateThread(nullptr, 0, fn, nullptr, 0, nullptr);
    if (!t) return false;
    CloseHandle(t);
    return true;
}

// take_frame: one packet into one path's table (a try-lock: never waits). False: the table was busy.
bool note_out(cfl::Table<kTableSize>& table, SRWLOCK& lock, const cfl::Seen& s, uint32_t fight, uint64_t now,
              uint64_t gnow, bool& removed, bool& tracked, uint64_t& prev_real) noexcept {
    if (!TryAcquireSRWLockExclusive(&lock)) return false;
    removed = s.gone && table.remove(s.gone);  // died / despawned: forgotten
    if (s.engage) table.engage(s.engage, now);
    if (fight) table.fight(fight, now);
    if (s.sample) {
        if (cfl::Enemy* e = table.find(s.sample)) {
            tracked = true;
            prev_real = e->anchor_ts;
            table.sample(s.sample, s.ts, gnow, s.parent, now);
        }
    }
    ReleaseSRWLockExclusive(&lock);
    return true;
}

}  // namespace

bool combat_follow_start(const std::string& raw, const std::string& raw_v2) {
    const auto p = cfl::parse_mode(raw);
    if (!p.known) {
        log::warn("CombatFollow: combat_follow='{}' is not 0, probe or 1; it stays off", raw);
        return false;
    }
    auto pv2 = cfl::parse_mode(raw_v2);
    if (!pv2.known) {
        log::warn("CombatFollow: combat_follow_v2='{}' is not 0, probe or 1; v2 stays off", raw_v2);
        pv2.mode = Mode::Off;
    }
    if (p.mode == Mode::Off) {
        if (pv2.mode != Mode::Off) log::warn("CombatFollow: combat_follow_v2 needs combat_follow; off");
        return false;
    }
    if (g_started.exchange(true)) return false;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (g_base != g2976::kImageBase || (!game::legacy_layout() && game::current_build() != game::Build::v3576 &&
                                        game::current_build() != game::Build::v3663)) {
        log::warn("CombatFollow: unexpected image base or build; off");
        return false;
    }
    if (game::current_build() == game::Build::v3527) {
        kClockBase = 0x70D9E60;
        kClockFrac = 0x70D9E70;
        kClockBias = 0x71BE198;
    } else if (game::current_build() == game::Build::v3576) {
        kClockBase = 0x70DBF68;
        kClockFrac = 0x70DBF78;
        kClockBias = 0x71C03A8;
    } else if (game::current_build() == game::Build::v3663) {
        kClockBase = 0x71600E8;
        kClockFrac = 0x71600F0;
        kClockBias = 0x7245468;
    }
    if (pv2.mode != Mode::Off) {
        LARGE_INTEGER f;
        if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
            log::warn("CombatFollow: no performance counter; combat_follow_v2 stays off");
            pv2.mode = Mode::Off;
        } else {
            g_qpc_freq.store(static_cast<uint64_t>(f.QuadPart), std::memory_order_relaxed);
        }
    }
    g_mode.store(static_cast<uint8_t>(p.mode));
    g_v2.store(static_cast<uint8_t>(pv2.mode), std::memory_order_release);  // after g_qpc_freq
    // v1's thread unless v2 replaces it (1); v2's thread with probe or 1.
    if (pv2.mode != Mode::Off && !start_thread(v2_thread)) {
        log::error("CombatFollow: v2's thread could not be created; combat_follow_v2 off (v1 as before)");
        pv2.mode = Mode::Off;
        g_v2.store(0, std::memory_order_release);
    }
    if (pv2.mode != Mode::On && !start_thread(v1_thread)) {
        g_mode.store(0);
        g_v2.store(0, std::memory_order_release);
        log::error("CombatFollow: the thread could not be created; off");
        return false;
    }
    if (pv2.mode != Mode::On) {
        log::info("CombatFollow ON ({}): the host client's enemies engaged with user 2 (AttackTargetAck 2922 with its "
                  "character, or a StartActionAck 2991 aimed at it, within {} ms) that this client simulates "
                  "([actor+0xC8] 1/2), within {:.0f} m of user 2 and without a parent {} every {} ms (at most {} at a "
                  "time; ts = the enemy's last real ts + the host client's game clock since then)",
                  cfl::mode_name(p.mode), cfl::kEngageMs, cfl::kRangeM,
                  p.mode == Mode::On ? "get a synthetic MoveActorAck 2697 to user 2 (server_push_extra)"
                                     : "are measured as if a synthetic 2697 went (probe: nothing sent)",
                  cfl::kTickMs, cfl::kMaxFollowed);
    }
    if (pv2.mode != Mode::Off) {
        log::info("CombatFollow v2 ({}{}): the combat stream (noche/combate-retardo.md §6.1): also every 0xB fighting "
                  "ANY character (2922 / 2991 to session 2) within {:.0f} m of user 2, the {} nearest, every {} ms "
                  "(high-resolution timer, drift-free); sent when moved > 1e-4 m or rotated > 1.19e-7 rad, a {} ms "
                  "keepalive repeating the last pose bit for bit, no cutoff without real samples (clock gate {} ms and "
                  "anchor age {} s kept); actors read with fast_read; its own table, thread and clock",
                  cfl::mode_name(pv2.mode),
                  pv2.mode == Mode::Probe ? ": decided and counted beside v1, which sends exactly as before" : "",
                  cfl::kRangeV2M, cfl::kMaxFollowedV2, cfl::kTickV2Ms, cfl::kKeepaliveV2Ms, cfl::kMaxOffsetMs,
                  cfl::kAnchorMaxAgeMs / 1000);
    }
    return true;
}

bool combat_follow_active() { return g_mode.load(std::memory_order_relaxed) != 0; }

void combat_follow_on_out(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    if (!combat_follow_active()) return;
    if (opcode != cfl::kOpMoveActorAck && opcode != cfl::kOpStartActionAck && opcode != cfl::kOpAttackTargetAck &&
        opcode != cfl::kOpNotifyHandleDeadAck && opcode != cfl::kOpRemoveActorAck) {
        return;
    }
    const auto v2 = static_cast<Mode>(g_v2.load(std::memory_order_acquire));
    const cfl::Seen s = cfl::read_out(opcode, payload, server_user2_player_key(), game::wire_build());
    // v2 (probe or 1), in its own table: an enemy fighting any character is a candidate too (the tick checks how
    // near user 2 it is). v1's table never sees a fight.
    const uint32_t fight = v2 != Mode::Off ? s.fight : 0;
    if (!s.engage && !fight && !s.sample && !s.gone) return;
    uint64_t gnow = 0;
    const bool clock = s.sample && game_now(gnow);
    if (s.sample && !clock) c_clock_unread.fetch_add(1, std::memory_order_relaxed);
    // The path that sends gives the counters (v1, or v2 with 1).
    bool removed = false, tracked = false, main_ok = false;
    uint64_t prev_real = 0;
    if (v2 != Mode::On && (s.engage || s.sample || s.gone)) {
        main_ok = note_out(g_table, g_lock, s, 0, GetTickCount64(), clock ? gnow : 0, removed, tracked, prev_real);
        if (!main_ok) c_busy.fetch_add(1, std::memory_order_relaxed);
    }
    if (v2 != Mode::Off) {
        bool removed2 = false, tracked2 = false;
        uint64_t prev2 = 0;
        const bool ok2 = note_out(g_table2, g_lock2, s, fight, v2_ms(), clock ? gnow : 0, removed2, tracked2, prev2);
        if (!ok2) c_busy2.fetch_add(1, std::memory_order_relaxed);
        if (v2 == Mode::On) {
            main_ok = ok2;
            removed = removed2;
            tracked = tracked2;
            prev_real = prev2;
        }
        if (ok2 && fight) c_fight_pk.fetch_add(1, std::memory_order_relaxed);
    }
    if (!main_ok) return;
    if (removed) c_removed.fetch_add(1, std::memory_order_relaxed);
    if (s.engage) c_engage_pk.fetch_add(1, std::memory_order_relaxed);
    if (tracked) {
        c_samples.fetch_add(1, std::memory_order_relaxed);
        if (prev_real && s.ts > prev_real) h_real.add(s.ts - prev_real);
        if (clock) {
            const int64_t d = static_cast<int64_t>(s.ts) - static_cast<int64_t>(gnow);
            g_offset_last.store(d, std::memory_order_relaxed);
            add_offset(d);
        }
    }
}

void combat_follow_on_epoch() noexcept {
    // Never a blocking acquire here: each path's tick (the mod's threads) empties its table on its next turn.
    if (!combat_follow_active()) return;
    g_reset_pending.store(true, std::memory_order_release);
    g_reset_pending2.store(true, std::memory_order_release);
}

std::string combat_follow_describe() {
    const auto mode = static_cast<Mode>(g_mode.load());
    if (mode == Mode::Off) return {};
    const auto v2 = static_cast<Mode>(g_v2.load());
    const bool on2 = v2 == Mode::On;
    const PathStats& st = on2 ? g_v2s : g_v1s;
    std::string off;
    for (size_t i = 0; i < h_offset.size(); ++i) {
        off += std::format("{}{}{} {}", i ? ", " : "", i < kOffsetBounds.size() ? "<=" : ">",
                           i < kOffsetBounds.size() ? kOffsetBounds[i] : kOffsetBounds.back(), h_offset[i].load());
    }
    std::string s = std::format(
        "CombatFollow summary [{}{}]: engaging packets {}{} | engaged now {}{} | real samples of followed enemies {} "
        "(cadence [{}]) | {} | {} {} (refused by the queue {}) | real ts - game clock at take_frame (ms) [{}] (last "
        "{}; beyond {} ms: not followed) | died/removed {} | epoch resets {} | table busy {} | clock unreadable {}",
        cfl::mode_name(mode), on2 ? ", v2" : "", c_engage_pk.load(),
        v2 != Mode::Off ? std::format(", fighting a character {}", c_fight_pk.load()) : std::string(),
        on2 ? g_engaged2_now.load() : g_engaged_now.load(),
        on2 ? std::format(" (with the fights near user 2: {})", g_engaged_v2_now.load()) : std::string(),
        c_samples.load(), hist(h_real), path_text(st, on2), mode == Mode::On ? "made" : "would make",
        mode == Mode::On ? st.made.load() : st.would.load(), st.refused.load(), off, g_offset_last.load(),
        cfl::kMaxOffsetMs, c_removed.load(), c_resets.load(), on2 ? c_busy2.load() : c_busy.load(),
        c_clock_unread.load());
    if (v2 != Mode::Off) {
        s += std::format(" | v2 timer: every {} ms, high resolution {}, late ticks {}", cfl::kTickV2Ms,
                         g_hires.load() ? "yes" : "NO", c_late_ticks.load());
    }
    return s;
}

}  // namespace cdmp::session2
