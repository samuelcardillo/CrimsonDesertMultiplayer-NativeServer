#include "mod/session2/horse_follow.h"
#include "mod/game/build_profile.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <format>
#include <string>
#include <vector>

#include "mod/game/actor_lookup.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/net/troc_sniffer.h"
#include "mod/session2/child_hold.h"
#include "mod/session2/horse_follow_logic.h"
#include "mod/session2/remote_interp.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

using hfl::Mode;
using hfl::Shape;
using hfl::Verdict;

std::atomic<uint8_t> g_mode{0};

// Riders and horses seen in the Acks to user 2 (keys -> last ts) and user 2's own Reqs.
hfl::Cadence<16> g_rider_ack, g_horse_ack, g_parent_ack, g_rider_req, g_horse_req, g_parent_req;
hfl::KeyRing<64> g_user2_keys;  // keys user 2 sent a MoveActorReq for (it controls them)

hfl::CadenceHist h_rider_ack, h_horse_ack, h_rider_req, h_horse_req;
std::atomic<uint64_t> c_acks{0}, c_bad_size{0}, c_ridden{0}, c_other_parent{0}, c_horse_own{0};
// Riders whose 0xB parent is a gimmick (type 7), not a horse: the helmsman at a ship's wheel (parent = the wheel mount)
// or a character standing on a ship (parent = the hull). Never followed (both directions).
std::atomic<uint64_t> c_gimmick_parent{0}, c_rev_gimmick_parent{0};

// The parent's actor type on this PC's client (actor +0x88 -> info, +1 the type): 7 a gimmick, 5 a vehicle actor (a horse,
// a mount, a ship's vehicle); 0 unknown (not loaded, unreadable, or a build where this layout was not checked).
// Why: 2026-11-13 (build 3663, two copies), the host at its ship's wheel is a "rider on an 0xB parent" whose parent is the
// wheel mount 0xB0100E5C; the synthetic 2697 of that "horse" (the rider's WORLD pose, parent -1, ~13 a second) reached
// the guest, whose wheel 0xB0100E5D was then drawn 2.9 m up and 1.9 m back (its offset to the mount counted twice). The
// same synthetic Acks of the wheel piece were seen on 3576 (docs/ESTADO-3527.md, "13-nov: BARCO", 224,000 in a night).
constexpr uint32_t kActor_Info = 0x88;
constexpr uint8_t kTypeGimmick = 7;
std::atomic<uint64_t> g_type_cache{0};  // (key << 8) | type of the last parent looked up
uint8_t parent_type(uint32_t key) noexcept {
    if (!game::is_3576() && !game::is_3663()) return 0;  // actor +0x88 / info +1 checked on these (vehicle_follow)
    const uint64_t c = g_type_cache.load(std::memory_order_relaxed);
    if (c && static_cast<uint32_t>(c >> 8) == key) return static_cast<uint8_t>(c);
    uint8_t type = 0;
    if (const auto actor = game::find_actor(key)) {
        if (const auto info = game::read_ptr(*actor + kActor_Info)) {
            if (const auto t = game::read<uint8_t>(*info + 1)) type = *t;
        }
    }
    if (type) g_type_cache.store(static_cast<uint64_t>(key) << 8 | type, std::memory_order_relaxed);
    return type;
}
std::atomic<uint64_t> c_verdict[hfl::kVerdicts] = {};
std::atomic<uint64_t> c_made{0}, c_push_failed{0}, c_build_failed{0};
std::atomic<uint64_t> c_reqs{0}, c_req_ridden{0}, c_req_horse_own{0};
std::atomic<uint32_t> g_last_rider{0}, g_last_horse{0}, g_last_req_rider{0}, g_last_req_horse{0};

// P8 mount ride, the measures of the H->G direction (take_frame, to user 2): the horse's samples user 2 gets while
// ridden, all of them (derived + its own) and its own only; the ones not newer than the last (dropped by user 2's
// buffer: counted, nothing changed in this direction).
hfl::MonoTs<8> g_fwd_all, g_fwd_real;
hfl::Intervals iv_fwd_all, iv_fwd_real;
std::atomic<uint64_t> c_fwd_derived{0}, c_fwd_real{0}, c_fwd_derived_stale{0}, c_fwd_real_stale{0};

std::string iv_text(const hfl::Intervals& v) {
    return std::format("n {} p50 {} p90 {} max {} (pauses > {} ms: {})", v.count(), v.quantile(0.5), v.quantile(0.9),
                       v.max.load(std::memory_order_relaxed), hfl::kIvPauseMs, v.pauses.load(std::memory_order_relaxed));
}

// A horse sample in a direction's streams: `all` gets every one, `real` only the horse's own.
void stream_note(hfl::MonoTs<8>& all, hfl::MonoTs<8>& real, hfl::Intervals& iv_all, hfl::Intervals& iv_real,
                 uint32_t horse, uint64_t ts, bool derived, std::atomic<uint64_t>& stale) noexcept {
    const hfl::SeqNote a = all.note(horse, ts);
    if (a.seq == hfl::Seq::Newer) iv_all.add(a.gap);
    if (a.seq == hfl::Seq::Same || a.seq == hfl::Seq::Older) stale.fetch_add(1, std::memory_order_relaxed);
    if (derived) return;
    const hfl::SeqNote r = real.note(horse, ts);
    if (r.seq == hfl::Seq::Newer) iv_real.add(r.gap);
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

}  // namespace

bool horse_follow_configure(const std::string& raw) {
    const auto p = hfl::parse_mode(raw);
    if (!p.known) {
        log::warn("HorseFollow: horse_follow='{}' is not 0, probe or 1; it stays off", raw);
        return false;
    }
    g_mode.store(static_cast<uint8_t>(p.mode));
    if (p.mode == Mode::Off) return false;
    log::info("HorseFollow ON ({}): {}", hfl::mode_name(p.mode),
              p.mode == Mode::On
                  ? "every rider's MoveActorAck 2697 to user 2 (parent +0x8C an 0xB key, world transform +0x94) is "
                    "followed by a synthetic 2697 of that horse (pos/quat from the rider's Path, parent -1, the same ts), "
                    "never for a horse user 2 controls; user 2's own riding (the other direction) is only measured"
                  : "probe: riders' Acks to user 2, their horses' own Acks and user 2's riding Reqs counted, nothing "
                    "made");
    return true;
}

bool horse_follow_active() { return g_mode.load(std::memory_order_relaxed) != 0; }

void horse_follow_on_out(uint16_t opcode, std::span<const uint8_t> packet, HorsePushFn push) noexcept {
    const auto mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    if (mode == Mode::Off || opcode != hfl::kOpMoveActorAck || packet.size() < hfl::kHeader) return;
    c_acks.fetch_add(1, std::memory_order_relaxed);
    const std::span<const uint8_t> payload = packet.subspan(hfl::kHeader);
    const hfl::Move m = hfl::read_move(payload, hfl::kAckSize, game::current_build());
    switch (m.shape) {
        case Shape::NotMove: c_bad_size.fetch_add(1, std::memory_order_relaxed); return;
        case Shape::OtherParent: c_other_parent.fetch_add(1, std::memory_order_relaxed); return;
        case Shape::OnFoot:
            // A horse's own Ack while a rider names it (its ~1 Hz Move).
            if (hfl::while_ridden(g_parent_ack.last(m.key), m.ts)) {
                c_horse_own.fetch_add(1, std::memory_order_relaxed);
                if (const uint64_t g = g_horse_ack.gap(m.key, m.ts)) h_horse_ack.add(g);
                c_fwd_real.fetch_add(1, std::memory_order_relaxed);
                stream_note(g_fwd_all, g_fwd_real, iv_fwd_all, iv_fwd_real, m.key, m.ts, false, c_fwd_real_stale);
            }
            return;
        case Shape::Ridden: break;
    }
    if (parent_type(m.parent) == kTypeGimmick) {
        c_gimmick_parent.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    c_ridden.fetch_add(1, std::memory_order_relaxed);
    if (const uint64_t g = g_rider_ack.gap(m.key, m.ts)) h_rider_ack.add(g);
    g_parent_ack.gap(m.parent, m.ts);
    // No log line here (a game thread): the pair and the counts go to the minute's summary.
    g_last_rider.store(m.key, std::memory_order_relaxed);
    g_last_horse.store(m.parent, std::memory_order_relaxed);
    // User 2's own rider or horse (its Reqs taught us the keys): never a synthetic Ack of a horse it controls.
    const Verdict v = hfl::decide(mode, m, g_user2_keys.contains(m.parent) || g_user2_keys.contains(m.key));
    c_verdict[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    if (v == Verdict::Probe) {
        c_fwd_derived.fetch_add(1, std::memory_order_relaxed);
        stream_note(g_fwd_all, g_fwd_real, iv_fwd_all, iv_fwd_real, m.parent, m.ts, true, c_fwd_derived_stale);
    }
    if (v != Verdict::Make || !push) return;
    try {  // the mod's heap (never the game's); a failed allocation must not end the game from noexcept
        std::vector<uint8_t> horse;
        if (!hfl::make_horse_ack(packet, horse, game::current_build())) {
            c_build_failed.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (push(horse)) {
            c_made.fetch_add(1, std::memory_order_relaxed);
            c_fwd_derived.fetch_add(1, std::memory_order_relaxed);
            stream_note(g_fwd_all, g_fwd_real, iv_fwd_all, iv_fwd_real, m.parent, m.ts, true, c_fwd_derived_stale);
        } else {
            c_push_failed.fetch_add(1, std::memory_order_relaxed);
        }
    } catch (...) {
        c_build_failed.fetch_add(1, std::memory_order_relaxed);
    }
}

namespace {

// P8 session 9, M1 (guest_horse_probe): user 2's riding measured and the horse's 2556 built, never sent. The
// mod's network thread only (inject); describe() reads the atomics.
std::atomic<bool> g_guest_probe{false};
struct RiderNote {
    uint32_t horse = 0;
    uint64_t ts = 0;
    float world[3] = {};
};
std::array<RiderNote, 4> g_rider_notes{};  // network thread only
std::atomic<uint64_t> c_gp_reqs{0}, c_gp_built{0}, c_gp_build_failed{0}, c_gp_own{0}, c_gp_compared{0},
    c_gp_own_older{0}, c_gp_no_rider{0};
std::atomic<uint64_t> g_gp_last_synth_ts{0};
hfl::ErrHistMm h_gp_err;
std::atomic<uint32_t> g_gp_err_max_mm{0};

void guest_probe(const hfl::Move& m, std::span<const uint8_t> payload) {
    c_gp_reqs.fetch_add(1, std::memory_order_relaxed);
    if (m.shape == Shape::Ridden) {
        try {
            std::vector<uint8_t> req;  // the mod's heap, freed at once: only to prove it can be built
            const bool ok = hfl::make_horse_req(payload, req, game::current_build());
            (ok ? c_gp_built : c_gp_build_failed).fetch_add(1, std::memory_order_relaxed);
        } catch (...) {
            c_gp_build_failed.fetch_add(1, std::memory_order_relaxed);
        }
        RiderNote* slot = &g_rider_notes[0];
        for (RiderNote& r : g_rider_notes) {
            if (r.horse == m.parent || !r.horse) {
                slot = &r;
                break;
            }
        }
        slot->horse = m.parent;
        slot->ts = m.ts;
        std::memcpy(slot->world, payload.data() + movement::layout(game::current_build())->world_pos, 12);
        g_gp_last_synth_ts.store(m.ts, std::memory_order_relaxed);
        return;
    }
    if (m.shape != Shape::OnFoot) return;
    for (const RiderNote& r : g_rider_notes) {
        if (r.horse != m.key || !r.horse) continue;
        if (!hfl::while_ridden(r.ts, m.ts)) return;
        c_gp_own.fetch_add(1, std::memory_order_relaxed);
        // A would-be synthetic carries the rider's ts: the horse's own sample with an older ts would be
        // dropped by the client's buffer (its action still applies).
        if (m.ts <= r.ts) c_gp_own_older.fetch_add(1, std::memory_order_relaxed);
        const uint64_t d = m.ts > r.ts ? m.ts - r.ts : r.ts - m.ts;
        if (d > 100) return;
        float own[3] = {};
        std::memcpy(own, payload.data() + movement::layout(game::current_build())->pos, 12);
        const float dx = own[0] - r.world[0], dy = own[1] - r.world[1], dz = own[2] - r.world[2];
        const float e = std::sqrt(dx * dx + dy * dy + dz * dz);
        if (!std::isfinite(e)) return;
        const auto mm = static_cast<uint32_t>(std::min(e * 1000.0f, 1.0e9f));
        c_gp_compared.fetch_add(1, std::memory_order_relaxed);
        h_gp_err.add(mm);
        if (mm > g_gp_err_max_mm.load(std::memory_order_relaxed)) g_gp_err_max_mm.store(mm, std::memory_order_relaxed);
        return;
    }
    // Not a ridden horse's (or its rider not seen yet).
}

std::string guest_probe_describe() {
    std::string err;
    for (size_t i = 0; i < h_gp_err.n.size(); ++i) {
        err += std::format("{}{}{} {}", i ? ", " : "", i < hfl::kErrBoundsMm.size() ? "<=" : ">",
                           i < hfl::kErrBoundsMm.size() ? hfl::kErrBoundsMm[i] : hfl::kErrBoundsMm.back(),
                           h_gp_err.n[i].load());
    }
    return std::format(
        "GuestHorseProbe [probe, nothing sent]: user 2's Move Reqs {} | riding: synthetic 2556 of its horse built "
        "{} (failed {}), cadence = the rider's Req cadence [{}] | the horse's own Reqs while ridden {} (older than "
        "the rider's last ts {}) | own pos vs the rider's Path world at <= 100 ms (mm) [{}] (compared {}, max {} "
        "mm)",
        c_gp_reqs.load(), c_gp_built.load(), c_gp_build_failed.load(), hist(h_rider_req), c_gp_own.load(),
        c_gp_own_older.load(), err, c_gp_compared.load(), g_gp_err_max_mm.load());
}

}  // namespace

bool horse_follow_configure_guest_probe(const std::string& raw) {
    const auto p = hfl::parse_mode(raw);
    if (!p.known || p.mode == Mode::Off) {
        if (!p.known) log::warn("GuestHorseProbe: guest_horse_probe='{}' is not 0 or probe; it stays off", raw);
        return false;
    }
    if (p.mode == Mode::On) {
        log::warn("GuestHorseProbe: guest_horse_probe=1 is not implemented (nothing is ever sent): runs as probe");
    }
    g_guest_probe.store(true);
    log::info("GuestHorseProbe ON (probe): user 2's riding Reqs and its horse's own Reqs measured; the synthetic "
              "MoveActorReq 2556 of the horse (the rider's Path world pose, parent -1, the rider's ts, history zeroed) "
              "built for every riding Req and NEVER sent (pendientes/p8-impl-s9-movimiento.md §4)");
    return true;
}

bool horse_follow_guest_probe_active() { return g_guest_probe.load(std::memory_order_relaxed); }

void horse_follow_on_guest_req(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    const bool gp = g_guest_probe.load(std::memory_order_relaxed);
    if ((!horse_follow_active() && !gp) || opcode != hfl::kOpMoveActorReq) return;
    const hfl::Move m = hfl::read_move(payload, hfl::kReqSize, game::current_build());
    if (m.shape == Shape::NotMove) return;
    if (gp) guest_probe(m, payload);
    c_reqs.fetch_add(1, std::memory_order_relaxed);
    g_user2_keys.add(m.key);
    if (m.shape == Shape::Ridden) {
        c_req_ridden.fetch_add(1, std::memory_order_relaxed);
        if (const uint64_t g = g_rider_req.gap(m.key, m.ts)) h_rider_req.add(g);
        g_parent_req.gap(m.parent, m.ts);
        g_last_req_rider.store(m.key, std::memory_order_relaxed);
        g_last_req_horse.store(m.parent, std::memory_order_relaxed);
    } else if (m.shape == Shape::OnFoot && hfl::while_ridden(g_parent_req.last(m.key), m.ts)) {
        c_req_horse_own.fetch_add(1, std::memory_order_relaxed);
        if (const uint64_t g = g_horse_req.gap(m.key, m.ts)) h_horse_req.add(g);
    }
}

// ================================================================ P8 mount ride: the client-side observer
namespace {

std::atomic<uint8_t> g_rev_mode{0};
std::atomic<bool> g_pair_notes{false}, g_client_attached{false};
// G->H: the horse samples the host's client gets while user 2 rides (all: derived [or would-be, probe] + its own;
// real: its own only), the last rider ts naming each horse, the pair checks.
hfl::MonoTs<8> g_rev_all, g_rev_real, g_rev_named;
hfl::PairCache<8> g_rev_pair;
hfl::Intervals iv_rev_all, iv_rev_real;
std::atomic<uint64_t> c_rev[hfl::kRevs] = {};
std::atomic<uint64_t> c_rev_acks{0}, c_rev_unreadable{0}, c_rev_build_failed{0}, c_rev_handed{0}, c_rev_real{0},
    c_rev_real_stale{0}, c_rev_derived_stale{0}, c_rev_checks{0}, c_rev_ctrl_seen{0}, c_rev_exceptions{0};
std::atomic<uint32_t> g_rev_last_rider{0}, g_rev_last_horse{0};
std::atomic<uint64_t> c_pair_notes{0};

// The packet as the client got it (the game's receive buffer): one SEH-guarded copy (no C++ objects here).
bool guarded_read(void* dst, const void* src, size_t n) noexcept {
    __try {
        std::memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Is `horse` owned by user 2 (its server actor's [actor+0xA0] == user 2's ServerUserActor)? child_hold's SEH reads
// of the server's actor table; cached kPairRecheckMs per horse (Unknown too: no table walk per Ack).
hfl::PairCheck pair_check(uint32_t horse, uint64_t now) {
    if (const auto c = g_rev_pair.get(horse, now)) return *c;
    c_rev_checks.fetch_add(1, std::memory_order_relaxed);
    hfl::PairCheck r = hfl::PairCheck::Unknown;
    uintptr_t user2 = 0;
    const auto owner = hold_actor_owner(horse);
    if (owner && server_user2(user2) && user2) r = *owner == user2 ? hfl::PairCheck::Ok : hfl::PairCheck::NotOwned;
    g_rev_pair.put(horse, r, now);
    return r;
}

// The reverse direction for one 2697 (a copy of the whole packet). Returns the extra packet's size (0: none).
size_t reverse(Mode mode, const hfl::Move& m, std::span<const uint8_t> copy, uint8_t* extra, size_t cap) {
    if (m.shape == Shape::OnFoot) {
        // The horse's own sample, while user 2's rider names it: in the streams (stale = not newer than the last
        // the client got; its buffer drops it, nothing is changed).
        if (!hfl::while_ridden(g_rev_named.last(m.key), m.ts)) return 0;
        c_rev_real.fetch_add(1, std::memory_order_relaxed);
        stream_note(g_rev_all, g_rev_real, iv_rev_all, iv_rev_real, m.key, m.ts, false, c_rev_real_stale);
        return 0;
    }
    if (m.shape != Shape::Ridden) return 0;
    if (parent_type(m.parent) == kTypeGimmick) {
        c_rev_gimmick_parent.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    c_rev_acks.fetch_add(1, std::memory_order_relaxed);
    const uint32_t u2 = server_user2_player_key();
    const uint64_t now = GetTickCount64();
    const hfl::PairCheck pc =
        u2 && m.key == u2 && !m.world_zero ? pair_check(m.parent, now) : hfl::PairCheck::Unknown;
    const hfl::Rev v = hfl::decide_reverse(mode, m, u2, pc, g_rev_all.last(m.parent));
    c_rev[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    if (v != hfl::Rev::Same && v != hfl::Rev::Older && v != hfl::Rev::Probe && v != hfl::Rev::Derive) return 0;
    // A validated pair: the horse is ridden by user 2's rider up to this ts.
    g_rev_named.note(m.parent, m.ts);
    g_rev_last_rider.store(m.key, std::memory_order_relaxed);
    g_rev_last_horse.store(m.parent, std::memory_order_relaxed);
    if (g_user2_keys.contains(m.parent)) c_rev_ctrl_seen.fetch_add(1, std::memory_order_relaxed);
    if (v == hfl::Rev::Probe) {
        stream_note(g_rev_all, g_rev_real, iv_rev_all, iv_rev_real, m.parent, m.ts, true, c_rev_derived_stale);
        return 0;
    }
    if (v != hfl::Rev::Derive) return 0;
    if (!hfl::make_horse_ack_into(copy, extra, cap, game::current_build())) {
        c_rev_build_failed.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    stream_note(g_rev_all, g_rev_real, iv_rev_all, iv_rev_real, m.parent, m.ts, true, c_rev_derived_stale);
    c_rev_handed.fetch_add(1, std::memory_order_relaxed);
    return hfl::kHeader + movement::payload_size(game::current_build(), 2697);
}

// The sniffer's recv-extra callback (the client's NetworkThread, inside OnRecvPacket): no allocation, no lock, no
// log. Both PCs: the rider -> horse pairs for remote_interp_pair; the host: the reverse direction.
size_t client_recv(const uint8_t* packet, uint16_t size, uint8_t* extra, size_t cap) noexcept {
    const size_t kWhole = hfl::kHeader + movement::payload_size(game::current_build(), 2697);
    if (!packet || size != kWhole) return 0;
    uint8_t copy[hfl::kHeader + movement::k3527.move_ack];
    if (!guarded_read(copy, packet, kWhole)) {
        c_rev_unreadable.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    const uint16_t op = static_cast<uint16_t>(copy[0] | (copy[1] << 8));
    const uint16_t len = static_cast<uint16_t>(copy[3] | (copy[4] << 8));
    if (op != hfl::kOpMoveActorAck || len != kWhole - hfl::kHeader) return 0;
    const std::span<const uint8_t> whole(copy, kWhole);
    const hfl::Move m = hfl::read_move(whole.subspan(hfl::kHeader), hfl::kAckSize, game::current_build());
    if (m.shape == Shape::NotMove) return 0;
    if (g_pair_notes.load(std::memory_order_relaxed) && (m.key >> 28) == 0xA) {
        remote_interp_note_ride(m.key, m.shape == Shape::Ridden ? m.parent : 0);
        c_pair_notes.fetch_add(1, std::memory_order_relaxed);
    }
    const auto mode = static_cast<Mode>(g_rev_mode.load(std::memory_order_relaxed));
    if (mode == Mode::Off) return 0;
    try {
        return reverse(mode, m, whole, extra, cap);
    } catch (...) {
        c_rev_exceptions.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

std::string reverse_describe() {
    const auto mode = static_cast<Mode>(g_rev_mode.load());
    const net::RecvExtraStats st = net::sniffer_recv_extra_stats();
    const auto rv = [](hfl::Rev v) { return c_rev[static_cast<size_t>(v)].load(); };
    return std::format(
        "HorseFollowReverse [{}] (G->H, the host's client only{}): riders' Move Acks {} | user 2's rider on its own "
        "horse: {} {} (handed {}, delivered by OnRecvPacket {}, refused: the sniffer's injection off {}, FAULTED {}{}, build failed {}) | same tick {}, older "
        "than the horse's last {} | not user 2's rider {}, no world {}, owner unreadable {} (checks {}), horse not "
        "user 2's {} | its Reqs name the horse {} | last pair 0x{:08X} on 0x{:08X} || the horse's own Acks while "
        "ridden {} (stale: not newer than the last derived, dropped by the client's buffer {}) | intervals of the "
        "horse samples (ms) all [{}] own only [{}] | derived not newer {} | packet unreadable {} exceptions {} | "
        "riders' Acks noted for remote_interp_pair {}",
        hfl::mode_name(mode), g_client_attached.load() ? "" : ", NOT attached to the sniffer", c_rev_acks.load(),
        mode == Mode::On ? "derived" : "would derive", mode == Mode::On ? rv(hfl::Rev::Derive) : rv(hfl::Rev::Probe),
        c_rev_handed.load(), st.delivered, st.refused, st.faulted, st.faulted ? " -> the path is OFF" : "",
        c_rev_build_failed.load(), rv(hfl::Rev::Same), rv(hfl::Rev::Older), rv(hfl::Rev::NotUser2),
        rv(hfl::Rev::NoWorld), rv(hfl::Rev::Unverified), c_rev_checks.load(), rv(hfl::Rev::NotOwned),
        c_rev_ctrl_seen.load(), g_rev_last_rider.load(), g_rev_last_horse.load(), c_rev_real.load(),
        c_rev_real_stale.load(), iv_text(iv_rev_all), iv_text(iv_rev_real), c_rev_derived_stale.load(),
        c_rev_unreadable.load(), c_rev_exceptions.load(), c_pair_notes.load());
}

std::string forward_describe() {
    return std::format(
        "HorseRide H->G (to user 2): horse samples while ridden: derived {} (not newer than the last {}), its own {} "
        "(not newer than the last: dropped by user 2's buffer {}) | intervals (ms) all [{}] own only [{}]",
        c_fwd_derived.load(), c_fwd_derived_stale.load(), c_fwd_real.load(), c_fwd_real_stale.load(),
        iv_text(iv_fwd_all), iv_text(iv_fwd_real));
}

}  // namespace

bool horse_follow_client_attach(const char* who) {
    if (g_client_attached.load()) return true;
    if (!net::sniffer_set_recv_extra(&client_recv)) return false;
    g_client_attached.store(true);
    log::info("HorseFollow: client-side observer attached to the sniffer's OnRecvPacket hook ({}): every MoveActorAck "
              "2697 this client gets is read (an SEH copy){}{}",
              who, g_pair_notes.load() ? ", rider -> horse pairs for remote_interp_pair" : "",
              g_rev_mode.load() ? ", user 2's horse samples derived from its rider (horse_follow_reverse)" : "");
    return true;
}

void horse_follow_set_pair_notes(bool on) { g_pair_notes.store(on); }

bool horse_follow_reverse_configure(const std::string& raw) {
    const auto p = hfl::parse_mode(raw);
    if (!p.known) {
        log::warn("HorseFollowReverse: horse_follow_reverse='{}' is not 0, probe or 1; it stays off", raw);
        return false;
    }
    if (p.mode == Mode::Off) return false;
    g_rev_mode.store(static_cast<uint8_t>(p.mode));
    if (!horse_follow_client_attach("horse_follow_reverse")) {
        g_rev_mode.store(0);
        log::warn("HorseFollowReverse: needs the sniffer's OnRecvPacket hook ([sniffer] enabled=1); it stays off");
        return false;
    }
    log::info("HorseFollowReverse ON ({}): user 2's main character riding a horse OWNED by user 2 (its server actor's "
              "owner): every MoveActorAck 2697 of it reaching THIS client {} a 2697 of the horse (the rider's Path "
              "world pose, parent -1, the rider's ts), only if newer than the last horse sample this client got; "
              "never to the server nor to user 2{}",
              hfl::mode_name(p.mode),
              p.mode == Mode::On ? "is preceded (same OnRecvPacket call, same thread) by"
                                 : "is measured as if preceded by (probe: nothing delivered)",
              child_hold_active() ? ""
                                  : " | WARNING: child_hold's hooks are not in (observer_hold / child_settle_ms): the "
                                    "horse's owner is unreadable, nothing will be derived");
    return true;
}

bool horse_follow_reverse_active() { return g_rev_mode.load(std::memory_order_relaxed) != 0; }

void horse_follow_on_epoch() noexcept {
    g_user2_keys.clear();
    // P8 mount ride: user 2's keys of the old epoch name nothing now.
    g_rev_named.clear();
    g_rev_pair.clear();
    g_rev_all.clear();
    g_rev_real.clear();
}

std::string horse_follow_describe() {
    const auto mode = static_cast<Mode>(g_mode.load());
    const std::string rev = g_rev_mode.load() ? reverse_describe() : std::string();
    if (mode == Mode::Off) {
        std::string s = g_guest_probe.load() ? guest_probe_describe() : std::string();
        if (!rev.empty()) s += (s.empty() ? "" : " || ") + rev;
        return s;
    }
    const std::string gp = (g_guest_probe.load() ? " || " + guest_probe_describe() : std::string()) +
                           (rev.empty() ? std::string() : " || " + rev) + " || " + forward_describe();
    return std::format(
        "HorseFollow [{}]: to user 2: Move Acks {} (bad size {}, rider on an 0xB parent {}, other parents {}, on a gimmick "
        "{} and from user 2 {}: not horses, skipped) | "
        "made {} (push refused {}, build failed {}) | verdicts: no world {}, user 2's horse {}, would make {} | "
        "last pair 0x{:08X} on 0x{:08X} | rider Ack cadence [{}] | its horse's own Acks {} [{}] || user 2's Move Reqs "
        "{} (riding {}, last 0x{:08X} on 0x{:08X}) | rider Req cadence [{}] | its horse's own Reqs {} [{}] (this "
        "direction reaches the host's client natively: NOT followed)",
        hfl::mode_name(mode), c_acks.load(), c_bad_size.load(), c_ridden.load(), c_other_parent.load(),
        c_gimmick_parent.load(), c_rev_gimmick_parent.load(), c_made.load(),
        c_push_failed.load(), c_build_failed.load(), c_verdict[static_cast<size_t>(Verdict::NoWorld)].load(),
        c_verdict[static_cast<size_t>(Verdict::OwnHorse)].load(), c_verdict[static_cast<size_t>(Verdict::Probe)].load(),
        g_last_rider.load(), g_last_horse.load(), hist(h_rider_ack), c_horse_own.load(), hist(h_horse_ack),
        c_reqs.load(), c_req_ridden.load(), g_last_req_rider.load(), g_last_req_horse.load(), hist(h_rider_req),
        c_req_horse_own.load(), hist(h_horse_req)) +
           gp;
}

}  // namespace cdmp::session2
