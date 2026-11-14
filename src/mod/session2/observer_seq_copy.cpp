#include "mod/session2/observer_seq_copy.h"

#include <windows.h>

#include <atomic>
#include <format>
#include <mutex>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/log.h"
#include "mod/session2/observer_seq_copy_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

std::atomic<osq::Mode> g_mode{osq::Mode::Off};
std::mutex g_mu;  // leaf lock: under it only the outgoing queue's own lock is taken (server_push_extra)
osq::Ledger g_ledger;  // under g_mu
// The 2661's prefix on this build (set by observer_seq_copy_configure, before the tap and take_frame's calls).
std::atomic<size_t> g_prepare_prefix{osq::kPreparePrefix};
osq::Copier g_copier;  // under g_mu
uint32_t g_trip_epoch = 0;  // under g_mu: the guest epoch of the current trip
std::atomic<uint64_t> g_milestone_hold_ms{0};  // review M2: the host's 2322 hold after user 2's 2762 (0 = off)
// observer_sched_copy (p8-impl-horarios-snapshot.md): the host's schedule stages. Fixed size (no allocation),
// under g_mu; set before the sniffer's tap (configure), read relaxed.
std::atomic<bool> g_sched{false};
osq::SchedLedger g_sched_ledger;  // under g_mu
osq::SchedTrip g_sched_trip;      // under g_mu
bool sched_on() { return g_sched.load(std::memory_order_relaxed); }

constexpr size_t kReqKinds = static_cast<size_t>(osq::Copier::Req::Count);
std::atomic<uint64_t> g_sniffed{0}, g_out_seen{0}, g_filter_drop[kReqKinds]{}, g_filter_would[kReqKinds]{}, g_push_refused{0},
    g_deletes_copied{0}, g_cancelled{0}, g_bound_removed{0}, g_faults{0};
// User 2's 2276 / 2105 that PASS (guest_seq_play, p8-impl-escenas-play.md §5): [0] 2276, [1] 2105; own = about one of
// user 2's own sequencers, other = an id the host's client was never given (or a short payload).
std::atomic<uint64_t> g_pass_own[2]{}, g_pass_other[2]{};
// Review 7: of the 2276 / 2105 dropped (or would be), how many came while user 2 was NOT in an observer trip of
// the host's field ([0] 2276, [1] 2105). Natively user 2's client never holds a host sequencer (the 2661 goes
// ToTarget the host's character only), so any 2276 / 2105 about one comes from its copy in X (guest_seq_play).
std::atomic<uint64_t> g_drop_outside[2]{};

// ---------------------------------------------------------------- events (any thread) -> lines (network thread)

enum Note : uint16_t {
    kNLedger,     // v0 seq, v1 seen | nbind<<8 | required<<24, v2 actor|owner<<32, v3..v6 bindings (node|actor<<32)
    kNTrip,       // v0 observer, v1 owner|user2 user<<32, v2 snapshot, v3 ledger live, v4 epoch
    kNPending,    // v0 seq, v1 required, v2..v5 waiting keys, v6 origin
    kNCopy,       // v0 seq, v1 kind, v2 with_branch, v3 waited_us, v4 origin, v5 bytes, v6 pushed, v7 probe, v8 required
    kNDelete,     // v0 seq, v1 fate, v2 pushed, v3 probe
    kNGate,       // v0 by_timeout, v1 pending, v2 announced
    kNBound,      // v0 seq, v1 key
    kNFilter,     // v0 op, v1 seq/0, v2 dropped (1) / would (0)
    kNClear,      // v0 why
    kNBranch,     // v0 seq, v1 pushed, v2 probe
    kNPass,       // v0 op (2276 / 2105), v1 seq (0: short), v2 own
    // observer_sched_copy
    kNSchedLedger,  // v0 op, v1 seen, v2 key, v3 actor|resource<<32, v4 bytes, v5 ledger live, v6 kind, v7 2411 id
    kNSchedTrip,    // v0 pending, v1 ledger live, v2 excluded (user 2's own), v3 epoch
    kNSchedCopy,    // v0 Sent kind, v1 key, v2 actor|resource<<32, v3 follow-ups, v4 bytes, v5 waited_us, v6 probe,
                    // v7 follow_lost | follow_wait<<1 | live<<2, v8 same_bytes, v9 NPC 2005 records before it
    kNSchedLive,    // v0 op, v1 Live fate, v2 key, v3 probe, v4 kind
    kNSchedNative,  // v0 SchedNative, v1 key, v2 NPC 2005 records so far
    kNSchedGate,    // v0 signal (1 its 2549, 2 its 2144), v1 NPC 2005 records so far, v2 pending
    kNoteCount
};
constexpr uint64_t kNoteCap[kNoteCount] = {400, 64, 400, 600, 200, 64, 64, 64, 32, 200, 32, 400, 64, 400, 400, 200, 64};
p8p::EventRing<2048> g_ring;
std::atomic<uint64_t> g_note_count[kNoteCount]{};
std::atomic<uint64_t> g_ring_lost{0};

void note(Note kind, std::initializer_list<uint64_t> v, bool force = false) {
    if (g_note_count[kind].fetch_add(1, std::memory_order_relaxed) >= kNoteCap[kind] && !force) return;
    p8p::Event e;
    e.kind = kind;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    size_t i = 0;
    for (const uint64_t x : v) {
        if (i < 12) e.v[i++] = x;
    }
    if (!g_ring.push(e)) g_ring_lost.fetch_add(1, std::memory_order_relaxed);
}

enum class ClearWhy : uint8_t { Epoch, UserGone, Logout, Server };
const char* clear_name(ClearWhy w) {
    switch (w) {
        case ClearWhy::Epoch: return "a new guest epoch or a new server";
        case ClearWhy::UserGone: return "user 2 gone";
        case ClearWhy::Logout: return "user 2's logout was asked for";
        case ClearWhy::Server: return "a new server instance (the ledger and the known ids too)";
        default: return "?";
    }
}

// ---------------------------------------------------------------- pushing (under g_mu)

bool probe() { return g_mode.load(std::memory_order_relaxed) == osq::Mode::Probe; }

// The real push (on) or nothing (probe: reported as sent).
bool push_copy(std::span<const uint8_t> bytes) {
    if (probe()) return true;
    if (server_epoch() != g_trip_epoch || server_logout_requested()) return false;
    const bool ok = server_push_extra(bytes);
    if (!ok) g_push_refused.fetch_add(1, std::memory_order_relaxed);
    return ok;
}

void note_released(const std::vector<osq::Released>& rel) {
    for (const osq::Released& r : rel) {
        note(kNCopy, {r.seq, static_cast<uint64_t>(r.kind), r.with_branch ? 1u : 0u, r.waited_us,
                      static_cast<uint64_t>(r.origin), r.bytes, r.pushed ? 1u : 0u, probe() ? 1u : 0u, r.required,
                      r.after_milestone ? 1u : 0u});
    }
}

// Under g_mu. The schedule copies first, with their own gate (user 2 finished loading + the 2335's actor
// announced: osq::SchedTripT), so that they go right behind the 2005 of the host's character, before the later NPC
// 2005s: an NPC binds to its stage only when its 2005 is unpacked (p8-impl-horarios-x.md §4.1).
void sched_release_locked(uint64_t now) {
    if (!sched_on() || !g_sched_trip.pending()) return;
    const uint64_t pr = probe() ? 1u : 0u;
    g_sched_trip.release(
        now, g_sched_ledger, [](uint32_t actor) { return g_copier.announced(actor); }, push_copy,
        [pr](const osq::SchedSent& s) {
            note(kNSchedCopy,
                 {static_cast<uint64_t>(s.kind), s.key, s.actor | static_cast<uint64_t>(s.resource) << 32, s.follow,
                  s.bytes, s.waited_us, pr,
                  (s.follow_lost ? 1u : 0u) | (s.follow_wait ? 2u : 0u) | (s.live ? 4u : 0u), s.same_bytes ? 1u : 0u,
                  s.npc_before},
                 s.kind == osq::SchedSent::Refused || s.follow_wait);
        });
}

void release_locked() {
    const uint64_t now = p8_now_us();
    sched_release_locked(now);
    std::vector<osq::Released> rel;
    g_copier.release(now, g_ledger, push_copy, &rel);
    note_released(rel);
}

// ---------------------------------------------------------------- lines

std::string head(const char* what, const p8p::Event& e) {
    return std::format("ObserverSeqCopy [{}] {}{} |", what, p8_when(e.qpc_us), e.tid ? std::format(" T{}", e.tid) : "");
}

std::string keys_text(const uint64_t* v, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        if (v[i]) s += std::format(" 0x{:08X}", static_cast<uint32_t>(v[i]));
    }
    return s.empty() ? " none" : s;
}

std::string line_of(const p8p::Event& e) {
    const uint64_t* v = e.v;
    switch (e.kind) {
        case kNLedger: {
            const auto seen = static_cast<osq::HostSeen>(v[1] & 0xFF);
            std::string b;
            for (size_t i = 3; i < 7; ++i) {
                if (v[i]) b += std::format(" 0x{:08X}->0x{:08X}", static_cast<uint32_t>(v[i]), static_cast<uint32_t>(v[i] >> 32));
            }
            const auto n = static_cast<uint32_t>((v[1] >> 8) & 0xFFFF);
            if (seen == osq::HostSeen::NewField) {
                return std::format("{} the host's client got its own MoveFieldAck 2174: {} | ledger live {}",
                                   head("ledger", e), osq::host_seen_name(seen), v[7]);
            }
            return std::format("{} the host's client: {} {} of sequencer 0x{:X} (actor 0x{:08X}, owner 0x{:08X}) | "
                               "bindings {}:{}{} | required actors {} | ledger live {}",
                               head("ledger", e), seen == osq::HostSeen::Deleted || seen == osq::HostSeen::DeleteUnknown ? 2810 : 2661,
                               osq::host_seen_name(seen), v[0], static_cast<uint32_t>(v[2]), static_cast<uint32_t>(v[2] >> 32), n,
                               b.empty() ? " -" : b, n > 4 ? " ..." : "", (v[1] >> 24) & 0xFFFF, v[7]);
        }
        case kNTrip: {
            const auto owner = static_cast<uint32_t>(v[1]), user = static_cast<uint32_t>(v[1] >> 32);
            if (!v[0]) {
                return std::format("{} user 2's MoveFieldAck 2174 (owner as the server wrote it 0x{:08X}, user 2's user "
                                   "0x{:08X}): NOT an observer trip (its own field, or a key unknown) -> nothing to copy | "
                                   "epoch {}",
                                   head("trip", e), owner, user, v[4]);
            }
            return std::format("{} user 2's MoveFieldAck 2174 into a field owned by 0x{:08X} (user 2 is 0x{:08X}): "
                               "OBSERVER trip | snapshot: {} of the ledger's {} live sequencer(s) wait for the 2005 of "
                               "their bound actors and for user 2's own 2322 (S2) | epoch {}",
                               head("trip", e), owner, user, v[2], v[3], v[4]);
        }
        case kNPending:
            return std::format("{} sequencer 0x{:X} ({}) pending: {} required actor(s), not yet announced to user 2:{}",
                               head("pending", e), v[0], v[6] ? "live 2661 of the host" : "snapshot", v[1],
                               keys_text(&v[2], 4));
        case kNCopy: {
            const bool sent = v[6] != 0, pr = v[7] != 0;
            const char* verb = pr ? "WOULD SEND (probe)" : sent ? "SENT to user 2's queue" : "REFUSED by the queue (stays pending)";
            if (v[1] == osq::Released::Milestone) {
                return std::format("{} the host's 2322 (its character's PlayAllPreLoadSequencerAck, {} bytes): {} | on the "
                                   "guest: GuestSeqRoute [2322 ...] ROUTED, X+0x231 1 -> 2",
                                   head("2322", e), v[5], verb);
            }
            return std::format("{} sequencer 0x{:X} ({}): {} {}2661 ({} bytes) after the 2005 of its {} bound actor(s), "
                               "{:.3f} s after it became pending | on the guest: GuestSeqRoute [2661 ...] ROUTED and "
                               "GuestStage [2661 result 0xC061C1] created in X{}",
                               head("copy", e), v[0], v[4] ? "live" : "snapshot", verb, v[2] ? "2981 + " : "", v[5], v[8],
                               static_cast<double>(v[3]) / 1e6,
                               v[9] ? " | AFTER the host's 2322 (its actors reached user 2 after its load: "
                                      "observer_load_defer)"
                                    : "");
        }
        case kNDelete: {
            const auto fate = static_cast<osq::Copier::DeleteFate>(v[1]);
            if (fate == osq::Copier::DeleteFate::Cancelled) {
                return std::format("{} the host's 2810 of sequencer 0x{:X}: its pending copy is CANCELLED (never sent)",
                                   head("2810", e), v[0]);
            }
            return std::format("{} the host's 2810 of sequencer 0x{:X} (its copy reached user 2): {}", head("2810", e), v[0],
                               v[3] ? "WOULD SEND (probe)" : v[2] ? "SENT to user 2's queue" : "REFUSED by the queue (LOST)");
        }
        case kNGate:
            return std::format("{} the copies may go now ({}) | pending {}, actors announced to user 2 {}", head("gate", e),
                               v[0] ? "30 s after user 2's 2144 without its own 2322" : "user 2's own 2322 went to its queue",
                               v[1], v[2]);
        case kNBound:
            return std::format("{} actor 0x{:08X} left user 2's view (2516) while sequencer 0x{:X}, copied to it, still "
                               "binds it on the host: no 2810 for user 2 alone [E: watch the guest]",
                               head("bound actor removed", e), static_cast<uint32_t>(v[1]), v[0]);
        case kNFilter: {
            const char* what = v[0] == osq::kOpDeleteSeqReq ? " DeleteSequencerReq"
                               : v[0] == osq::kOpDelayEndReq ? " StageBranchStateDelayEndReq"
                               : v[0] == osq::kOpPivotReq    ? " ChangeSequencerPivotReq"
                                                             : "";
            const char* why = v[0] == osq::kOpDeleteSeqReq || v[0] == osq::kOpDelayEndReq || v[0] == osq::kOpPivotReq
                                  ? " (sent by the guest's tick / live update of the host character's manager X: "
                                    "guest_seq_play; it must never reach the server's copy of the host's sequencer)"
                                  : "";
            return std::format("{} user 2's Req {}{} {}{}{}", head("filter", e), v[0], what,
                               v[2] ? "DROPPED" : "WOULD BE DROPPED (probe)",
                               v[0] == osq::kOpCandidatePos
                                   ? std::string(": SyncStageCandidatePostionReq while user 2 observes the host's field "
                                                 "(the server applies it to the field's manager, the host's)")
                                   : std::format(": sequencer 0x{:X} is the host's (its 2661 went to the host's client)", v[1]),
                               why);
        }
        case kNPass:
            return std::format("{} user 2's Req {} {} about sequencer 0x{:X} PASSES: {}", head("filter", e), v[0],
                               v[0] == osq::kOpDeleteSeqReq ? "DeleteSequencerReq" : "StageBranchStateDelayEndReq", v[1],
                               v[2] ? "one of user 2's own sequencers (never dropped)"
                                    : "not an id the host's client was given (or a short payload) [if user 2 observes the "
                                      "host and this id is near the host's ids: check the 2105 field layout]");
        case kNClear:
            return std::format("{} the trip's copies end: {}", head("clear", e), clear_name(static_cast<ClearWhy>(v[0])));
        case kNBranch:
            return std::format("{} the host's 2981 of sequencer 0x{:X} (copied to user 2) did not reach user 2 natively: {}",
                               head("2981", e), v[0],
                               v[2] ? "WOULD SEND (probe)" : v[1] ? "SENT to user 2's queue" : "REFUSED by the queue");
        case kNSchedLedger: {
            const auto seen = static_cast<osq::SchedSeen>(v[1]);
            if (seen == osq::SchedSeen::NewField) {
                return std::format("{} the host's client got its own MoveFieldAck 2174: schedule ledger emptied",
                                   head("sched ledger", e));
            }
            if (v[0] == osq::kOpSchedClosed) {
                return std::format("{} the host's client: 2411 actor 0x{:08X} id 0x{:08X}: {} | ledger live {}",
                                   head("sched ledger", e), static_cast<uint32_t>(v[3]), v[7], osq::sched_seen_name(seen),
                                   v[5]);
            }
            return std::format("{} the host's client: {}{} of stage 0x{:X} (actor 0x{:08X}, resource 0x{:08X}, {} bytes): "
                               "{} | ledger live {}",
                               head("sched ledger", e), v[0], v[0] == osq::kOpSchedCreate || v[0] == osq::kOpSchedChange ||
                                                                       v[0] == osq::kOpSchedEvade
                                                                   ? std::format(" kind {}", v[6])
                                                                   : std::string(),
                               v[2], static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[3] >> 32), v[4],
                               osq::sched_seen_name(seen), v[5]);
        }
        case kNSchedTrip:
            return std::format("{} user 2's observer trip: {} of the ledger's {} live schedule stage(s) wait for user 2 "
                               "to finish loading (its 2549 or 2144) and the 2005 of their actor{} | epoch {}",
                               head("sched trip", e), v[0], v[1],
                               v[2] ? std::format(" ({} of user 2's own character left out)", v[2]) : std::string(), v[3]);
        case kNSchedGate:
            return std::format("{} user 2 finished loading the field ({}): the schedule copies may go behind the 2005 of "
                               "their actor | NPC 2005 records already queued to user 2: {} | pending {}",
                               head("sched gate", e),
                               v[0] == 1 ? "its 2549 MoveFieldCompleteReq reached the server path"
                                         : "its 2144 went to its queue",
                               v[1], v[2]);
        case kNSchedCopy: {
            using S = osq::SchedSent;
            const auto kind = static_cast<S::Kind>(v[0]);
            const auto actor = static_cast<uint32_t>(v[2]), res = static_cast<uint32_t>(v[2] >> 32);
            const char* verb = v[6] ? "WOULD SEND (probe)" : "SENT to user 2's queue";
            const std::string npc = std::format(" | NPC 2005 records already queued to user 2: {}", v[9]);
            const std::string notes =
                std::string((v[7] & 1) ? " | NOTE: follow-ups the ledger dropped never went: the copy may lag the host" : "") +
                ((v[7] & 2) ? " | the queue REFUSED a follow-up: the rest goes from it next time" : "");
            const char* origin = (v[7] & 4) ? "live 2335 of the host" : "snapshot";
            switch (kind) {
                case S::Vanished:
                    return std::format("{} stage 0x{:X} ({}): left the ledger before it went (its 2126/2411, or the "
                                       "host's new field): nothing sent",
                                       head("sched copy", e), v[1], origin);
                case S::Duplicate:
                    return std::format("{} stage 0x{:X} (actor 0x{:08X}, resource 0x{:08X}): its 2335 reached user 2 "
                                       "natively first ({}): the 2335 NOT repeated; {} {} follow-up(s), {} bytes{}{}",
                                       head("sched copy", e), v[1], actor, res,
                                       v[8] ? "the same bytes" : "OTHER bytes than the ledger's", verb, v[3], v[4], notes,
                                       npc);
                case S::Refused:
                    return std::format("{} stage 0x{:X} ({}): 2335 REFUSED by the queue (stays pending){}",
                                       head("sched copy", e), v[1], origin, npc);
                case S::FollowUps:
                    return std::format("{} stage 0x{:X} (actor 0x{:08X}, resource 0x{:08X}): {} {} more follow-up(s) "
                                       "after its 2335, {} bytes{}",
                                       head("sched copy", e), v[1], actor, res, verb, v[3], v[4], notes);
                default:
                    return std::format("{} stage 0x{:X} ({}, actor 0x{:08X}, resource 0x{:08X}): {} its 2335 + {} "
                                       "follow-up(s), {} bytes, {:.3f} s after it became pending{}{} | on the guest: "
                                       "GuestSchedLoad [load] of the resource before it, then the 2335's handler",
                                       head("sched copy", e), v[1], origin, actor, res, verb, v[3], v[4],
                                       static_cast<double>(v[5]) / 1e6, npc, notes);
            }
        }
        case kNSchedNative: {
            const auto r = static_cast<osq::SchedNative>(v[0]);
            const char* what = r == osq::SchedNative::DuplicateSame
                                   ? "its copy had not gone yet; the same bytes: the native one stands in for it (its "
                                     "follow-ups still go)"
                               : r == osq::SchedNative::DuplicateOther
                                   ? "its copy had not gone yet; OTHER bytes than the ledger's: the copy is dropped"
                                   : "NATIVE AFTER COPY: our copy of this stage already reached user 2 (counted, not "
                                     "merged; the guest refuses a second create for a key it has)";
            return std::format("{} user 2 got the 2335 of stage 0x{:X} natively: {} | NPC 2005 records so far {}",
                               head("sched native", e), v[1], what, v[2]);
        }
        case kNSchedLive: {
            using L = osq::SchedLive;
            const auto fate = static_cast<L>(v[1]);
            const char* what = "?";
            switch (fate) {
                case L::Forwarded: what = v[3] ? "WOULD SEND (probe)" : "SENT to user 2's queue"; break;
                case L::Refused: what = "REFUSED by the queue (LOST)"; break;
                case L::NativeAlready: what = "the same payload already went to user 2 natively: not repeated"; break;
                case L::NotUser2: what = "not a stage user 2 has (native or copied): not copied"; break;
                case L::CancelledPending: what = "its 2335 copy had not gone yet: CANCELLED (never sent)"; break;
                case L::KeptInPending: what = "its stage is pending: it goes with that copy, in order"; break;
                case L::Native2335: what = "user 2 got it natively too"; break;
                case L::Queued2335: what = "user 2 did NOT get it natively: PENDING, copied behind its actor's 2005"; break;
                case L::Requeued2335:
                    what = "created again while user 2 has it only by our copy: PENDING again (the new bytes)";
                    break;
                case L::PendingFull: what = "user 2 did NOT get it natively, and the pending table is FULL: not copied"; break;
                default: break;
            }
            return std::format("{} the host's {}{} of stage 0x{:X}: {}", head("sched live", e), v[0],
                               v[0] == osq::kOpSchedCreate ? std::format(" kind {}", v[4]) : std::string(), v[2], what);
        }
        default:
            return std::format("ObserverSeqCopy: note {}?", e.kind);
    }
}

void clear_trip(ClearWhy why) {
    bool had = false;
    {
        std::lock_guard lock(g_mu);
        had = g_copier.trip_active() || g_sched_trip.active();
        g_copier.clear();
        g_sched_trip.clear();
    }
    if (had) note(kNClear, {static_cast<uint64_t>(why)});
}

void sched_summary() {
    osq::SchedTrip::Counters c;
    size_t live = 0, pending = 0, has = 0;
    uint64_t created = 0, followed = 0, fdrop = 0, funknown = 0, deleted = 0, closed = 0, closed_other = 0, full = 0,
             big = 0, bad = 0, fields = 0, first = 0;
    bool observer = false, loaded = false;
    uint8_t signal = 0;
    uint64_t npcs = 0;
    {
        std::lock_guard lock(g_mu);
        c = g_sched_trip.counters();
        loaded = g_sched_trip.loaded();
        signal = g_sched_trip.load_signal();
        npcs = g_sched_trip.npc_announced();
        live = g_sched_ledger.live();
        created = g_sched_ledger.created();
        followed = g_sched_ledger.followed();
        fdrop = g_sched_ledger.follow_dropped();
        funknown = g_sched_ledger.follow_unknown();
        deleted = g_sched_ledger.deleted();
        closed = g_sched_ledger.closed();
        closed_other = g_sched_ledger.closed_other_actor();
        full = g_sched_ledger.full();
        big = g_sched_ledger.too_big();
        bad = g_sched_ledger.bad();
        fields = g_sched_ledger.fields();
        pending = g_sched_trip.pending();
        first = g_sched_trip.first_pending();
        has = g_sched_trip.has_count();
        observer = g_sched_trip.observer();
    }
    std::string live_txt;
    for (size_t i = 0; i < osq::kSchedLiveOps; ++i) {
        live_txt += std::format(" | {}{}: copied {}, already native {}, not user 2's {}, went with a pending copy {}, refused {}",
                                osq::kSchedLiveOp[i], i == 3 ? " (not creating)" : "", c.live_fwd[i], c.live_native[i],
                                c.live_not_user2[i], c.live_kept[i], c.live_refused[i]);
    }
    log::info("ObserverSchedCopy summary ({}) | ledger (the host's client): live {} of {}, created {}, follow-ups kept {} "
              "(dropped {}, of unknown keys {}), deleted {}, closed by 2411 {} (id matched, other actor {}), full {}, too "
              "big {}, malformed {}, fields {} | snapshots {} ({} keys, user 2's own left out {}), {} now, gate {}, NPC "
              "2005 records queued to user 2 this trip {}, pending {}{} (table full {}) | SENT 2335 {} (+{} follow-ups, "
              "follow-ups refused and resumed {}), duplicates suppressed (its 2335 reached user 2 natively first) {} same "
              "bytes / {} other bytes, NATIVE AFTER COPY {}, vanished {}, cancelled by their 2126 {}, refused {} | live{} "
              "| host 2335 in the trip: user 2 got it natively {}, did NOT (copied) {}, created again over our copy "
              "(copied again) {} | native to user 2 in its trips: 2126 {}, 2958 {}, 2909 {}, 2335 {}, 2411 {} | stages "
              "user 2 has {} (table full {}), native hashes overwritten {}",
              probe() ? "PROBE" : "ON", live, osq::kSchedLedgerEntries, created, followed, fdrop, funknown, deleted, closed,
              closed_other, full, big, bad, fields, c.snapshots, c.snapshot_keys, c.excluded,
              observer ? "OBSERVER" : "not observing",
              !loaded ? "closed (user 2 still loading)" : signal == 1 ? "open (its 2549)" : "open (its 2144)", npcs,
              pending, first ? std::format(" (first 0x{:X})", first) : "", c.pending_full, c.copied, c.follow_copied,
              c.follow_refused, c.dup_same, c.dup_other, c.native_after_copy, c.vanished, c.cancelled, c.refused, live_txt,
              c.live_2335_native, c.live_2335_queued, c.live_2335_requeued, c.native[0], c.native[1], c.native[2],
              c.native[3], c.native_closed, has, c.has_full, c.ring_overwritten);
}

uint64_t g_last_summary_ms = 0;  // network thread only

void summary() {
    std::string pend;
    osq::Copier::Counters c;
    size_t live = 0, pending = 0, announced = 0, delivered = 0, early = 0;
    uint64_t prepared = 0, deleted = 0, full = 0, not_own = 0, fields = 0, known_full = 0;
    bool observer = false, gate = false, ms = false, have_ms = false;
    uint32_t host_char = 0;
    {
        std::lock_guard lock(g_mu);
        c = g_copier.counters();
        live = g_ledger.live();
        early = g_ledger.early();
        prepared = g_ledger.prepared();
        deleted = g_ledger.deleted();
        full = g_ledger.full();
        not_own = g_ledger.not_own();
        fields = g_ledger.fields();
        known_full = g_ledger.known_full();
        host_char = g_ledger.host_char();
        have_ms = !g_ledger.milestone().empty();
        pending = g_copier.pending();
        announced = g_copier.announced_count();
        delivered = g_copier.delivered_count();
        observer = g_copier.observer();
        gate = g_copier.gate_is_open();
        ms = g_copier.milestone_sent();
        size_t shown = 0;
        for (uint64_t seq : g_copier.pending_seqs()) {
            if (shown++ >= 8) {
                pend += " ...";
                break;
            }
            std::string w;
            for (uint32_t k : g_copier.waiting_for(seq, g_ledger)) w += std::format(" 0x{:08X}", k);
            pend += std::format(" 0x{:X}(waits for{})", seq, w.empty() ? " the gate" : w);
        }
    }
    log::info("ObserverSeqCopy summary ({}) | ledger (the host's client): live {} (2981 waiting for their 2661 {}), "
              "prepared {}, deleted {}, not own {}, full {}, fields {}, host character 0x{:08X}, its 2322 {} | trips {} "
              "(observer {}), now {} | gate {} | pending {}{} | copied {} (with their 2981 {}), 2322 {} ({}), 2810 copied "
              "{}, cancelled {}, vanished {}, filtered out by observer_seq_copy_only {}, pending table full {} (purged {}), "
              "delivered marks evicted {}, known ids over the bound {}, queue refused {} | announced to user 2 {} (overflow {}), delivered now {}, bound actor removed {} | C>S dropped: "
              "host sequencer {}, 2100 {}, 2276 {}, 2105 {}, 2888 {} | would drop (probe): {}, {}, {}, {}, {} | of the 2276/2105 dropped or "
              "would be, outside an observer trip {}/{} | 2276 passed: own {}, "
              "not the host's {} | 2105 passed: own {}, not the host's {} | sniffed {} | ring lost {}",
              osq::mode_name(g_mode.load()), live, early, prepared, deleted, not_own, full, fields, host_char,
              have_ms ? "kept" : "none yet", c.trips, c.observer_trips, observer ? "OBSERVER" : "not observing",
              gate ? "open" : "closed", pending, pend.empty() ? "" : ":" + pend, c.copied, c.copied_branches, c.milestones,
              ms ? "sent this trip" : "not this trip", g_deletes_copied.load(), c.cancelled, c.vanished, c.filtered,
              c.pending_full, c.purged, c.delivered_evicted, known_full, c.refused, announced, c.announced_overflow, delivered, c.bound_removed,
              g_filter_drop[1].load(), g_filter_drop[2].load(), g_filter_drop[3].load(), g_filter_drop[4].load(),
              g_filter_drop[5].load(), g_filter_would[1].load(), g_filter_would[2].load(), g_filter_would[3].load(),
              g_filter_would[4].load(), g_filter_would[5].load(), g_drop_outside[0].load(), g_drop_outside[1].load(), g_pass_own[0].load(), g_pass_other[0].load(), g_pass_own[1].load(), g_pass_other[1].load(), g_sniffed.load(),
              g_ring_lost.load());
    // Review M2 (observer_load_defer): the host's 2322 waiting for snapshot copies.
    if (const uint64_t hold_ms = g_milestone_hold_ms.load()) {
        log::info("ObserverSeqCopy 2322 hold (observer_load_defer): while a snapshot copy waits for its actors, the "
                  "host's 2322 waits until user 2's 2762 + {} ms (at most {} s after the trip) | trips held {}, ran out "
                  "with a snapshot copy still pending {} | snapshot copies sent AFTER the 2322 {}",
                  hold_ms, osq::Copier::kMilestoneHoldMaxUs / 1000000, c.milestone_holds, c.milestone_hold_expired,
                  c.snapshot_after_milestone);
    }
}

}  // namespace

void observer_seq_copy_configure(const std::string& mode, const std::string& only, bool copy_2322, bool filter_2100) {
    bool bad = false;
    const osq::Mode m = osq::parse_mode(mode, &bad);
    if (bad) log::warn("ObserverSeqCopy: observer_seq_copy={} is not 0, probe or 1: off", mode);
    osq::OnlyFilter f = osq::OnlyFilter::parse(only);
    if (!f.bad.empty()) log::warn("ObserverSeqCopy: observer_seq_copy_only: '{}' is not hex: ignored", f.bad);
    std::string list;
    for (uint64_t s : f.seqs) list += std::format(" seq 0x{:X}", s);
    for (uint32_t k : f.keys) list += std::format(" actor 0x{:08X}", k);
    {
        // 3576: the Troc catalogue did not change (troc_mapping_3549_3576.json: 0 size changes), so 3527's prefix.
        // Build 1.0.0.3663 (static, 2026-11-13; never run): renumbered catalogue, same layout of what this reads:
        // the 2661 serializer 0x2D41C70 (writes 0x934 = 2356) emits u8 4 | u32 actor | the play data 0x26B31E0 (87
        // bytes: 21 writes, the owner u32 first, then the u64 id) | per binding u32 | u32 | u8 | u8 | u8 (11): 3527's
        // 92 + 11 n; the 2810 (0x2D42250, 0xA63): 17 bytes, the u64 id at +4; the 2981 (0x2D43070, 0xAC0): u8 | u32
        // actor | u64 id | ...; the 2322 (0x2C7A9A0, 0xB7D): u32 actor; the 2174 (0x2C7A2B0, 0x93C): 17 + 0x30 n
        // (0x26AB510). The 2005 / 2516 and the C>S Reqs' u64 @0 were not re-read (the session core's payloads).
        const game::Build b = game::current_build();
        const size_t prefix = b == game::Build::v3527 || b == game::Build::v3576 || b == game::Build::v3663
                                  ? osq::kPreparePrefix3527
                                  : osq::kPreparePrefix;
        g_prepare_prefix.store(prefix);
        std::lock_guard lock(g_mu);
        g_ledger.set_prepare_prefix(prefix);
        g_copier.set_filter(std::move(f));
        g_copier.set_milestone(copy_2322);
        g_copier.set_filter_2100(filter_2100);
    }
    g_mode.store(m);
    if (m == osq::Mode::Off) return;
    log::info("ObserverSeqCopy {} (observer_seq_copy={}): the host client's 2661/2981/2810/2322 (sniffer) -> ledger; "
              "user 2's observer trip (its MoveFieldAck, the server's owner) -> each live sequencer goes to user 2 as "
              "[its 2981 if user 2 has none] + its 2661, byte for byte, once every actor it binds was announced to user "
              "2 (2005) and user 2's own 2322 went (or 30 s after its 2144); live 2661s too; a delivered one's 2810 | "
              "only:{} | the host's 2322 once per observer trip: {} | user 2's 2767/2591/2436/2138/2173/2276/2105/2888 about the "
              "host's sequencers{}: {} | needs the guest's guest_seq_route=1 (without it the guest's client drops these "
              "copies)",
              osq::mode_name(m), mode, list.empty() ? " every sequencer" : list, copy_2322 ? "yes" : "no",
              filter_2100 ? " and its 2100 while it observes" : " (its 2100 passes: observer_seq_copy_2100=0)",
              m == osq::Mode::On ? "DROPPED" : "counted only");
}

void observer_seq_copy_set_milestone_hold(uint32_t ms) {
    {
        std::lock_guard lock(g_mu);
        g_copier.set_milestone_hold(static_cast<uint64_t>(ms) * 1000);
    }
    g_milestone_hold_ms.store(ms);
    if (ms && observer_seq_copy_wanted()) {
        log::info("ObserverSeqCopy: observer_load_defer is on: the host's 2322 copy waits while a snapshot copy waits "
                  "for its actors (withheld from user 2 during its load), until user 2's 2762 + {} ms (at most {} s "
                  "after the trip)",
                  ms, osq::Copier::kMilestoneHoldMaxUs / 1000000);
    }
}

bool observer_seq_copy_wanted() { return g_mode.load(std::memory_order_relaxed) != osq::Mode::Off; }
bool observer_seq_copy_sends() { return g_mode.load(std::memory_order_relaxed) == osq::Mode::On; }

void observer_sched_copy_configure(bool on) {
    if (!on) return;
    if (!observer_seq_copy_wanted()) {
        log::warn("ObserverSchedCopy: observer_sched_copy=1 needs observer_seq_copy=probe or 1 (its sniffer ledger, "
                  "trips and gate): off");
        return;
    }
    g_sched.store(true);
    log::info("ObserverSchedCopy {} (observer_sched_copy=1, on observer_seq_copy's path): the host client's "
              "2335/2126/2411/2958/2909 (sniffer) -> a ledger of its live schedule stages ({} at most: the creating "
              "2335 + up to {} follow-ups each); user 2's observer trip -> each stage goes to user 2 byte for byte (2335 "
              "then its 2958/2909) once user 2 finished loading (its 2549 or 2144) right behind the 2005 of its actor, "
              "before the later NPC 2005s, unless its 2335 reached user 2 natively first; a creating 2335 of the "
              "trip user 2 did not get natively, the same way; the 2661s keep their own gate "
              "| live: the 2126/2958/2909 of a stage user 2 has, unless the same payload just reached it "
              "natively | on the guest: guest_schedule_load=1 loads the file before the 2335",
              probe() ? "PROBE (decided and logged, nothing sent)" : "ON", osq::kSchedLedgerEntries,
              osq::SchedEntry::kFollow);
}
bool observer_sched_copy_wanted() { return sched_on(); }

namespace {

// The sniffer's writer thread, under g_mu: one schedule Ack of the host's own client (or its own 2174).
void sched_sniffed_locked(std::span<const uint8_t> raw, uint64_t t_us) {
    osq::SchedMsg m;
    m.op = static_cast<uint16_t>(raw[0] | raw[1] << 8);  // kept when the payload does not parse (Bad)
    const osq::SchedSeen seen = g_sched_ledger.on_host_packet(raw, t_us, &m);
    if (seen == osq::SchedSeen::Other) return;
    note(kNSchedLedger, {m.op, static_cast<uint64_t>(seen), m.key, m.actor | static_cast<uint64_t>(m.resource) << 32,
                         raw.size(), g_sched_ledger.live(), m.kind, m.closed_id},
         seen == osq::SchedSeen::Full || seen == osq::SchedSeen::TooBig);
    // A 2335 the ledger could not keep (full / too big) cannot be copied either: it is not queued.
    if (seen == osq::SchedSeen::Bad || seen == osq::SchedSeen::NewField || seen == osq::SchedSeen::Full ||
        seen == osq::SchedSeen::TooBig || m.op == osq::kOpSchedClosed) {
        return;
    }
    const osq::SchedTrip::Live fate = g_sched_trip.on_host_live(m, raw, p8_now_us(), push_copy);
    // Every fate but the routine one (a host 2335 user 2 also got natively: counted in the summary).
    if (fate != osq::SchedTrip::Live::None && fate != osq::SchedTrip::Live::Native2335) {
        note(kNSchedLive, {m.op, static_cast<uint64_t>(fate), m.key, probe() ? 1u : 0u, m.kind},
             fate == osq::SchedTrip::Live::Refused || fate == osq::SchedTrip::Live::PendingFull);
    }
}

}  // namespace

void observer_seq_copy_sniffed(const uint8_t* packet, size_t size, uint64_t t_us, bool server_to_client) noexcept {
    if (!observer_seq_copy_wanted() || !server_to_client || size < osq::kHeader) return;
    const uint16_t op = static_cast<uint16_t>(packet[0] | packet[1] << 8);
    const bool sched = sched_on() && osq::sched_op(op);
    if (op != osq::kOpPrepare && op != osq::kOpBranch && op != osq::kOpDelete && op != osq::kOpMilestone &&
        op != osq::kOpMoveField && !sched) {
        return;
    }
    try {
        g_sniffed.fetch_add(1, std::memory_order_relaxed);
        const std::span<const uint8_t> raw(packet, size);
        uint64_t seq = 0;
        std::lock_guard lock(g_mu);
        if (sched || (op == osq::kOpMoveField && sched_on())) {
            sched_sniffed_locked(raw, t_us);
            if (sched) {
                release_locked();
                return;
            }
        }
        const osq::HostSeen seen = g_ledger.on_host_packet(raw, t_us, &seq);
        if (seen == osq::HostSeen::Prepared || seen == osq::HostSeen::Replaced || seen == osq::HostSeen::NotOwn ||
            seen == osq::HostSeen::Full || seen == osq::HostSeen::Deleted || seen == osq::HostSeen::NewField) {
            uint64_t b[4] = {};
            uint64_t req = 0, nb = 0, ao = 0;
            if (const osq::SeqRec* r = g_ledger.find(seq); r && seen != osq::HostSeen::Deleted) {
                for (size_t i = 0; i < 4 && i < r->bindings.size(); ++i) {
                    b[i] = r->bindings[i].node | static_cast<uint64_t>(r->bindings[i].actor) << 32;
                }
                req = r->required.size();
                nb = r->bindings.size();
                ao = r->actor | static_cast<uint64_t>(r->owner) << 32;
            }
            note(kNLedger, {seq, static_cast<uint64_t>(seen) | nb << 8 | req << 24, ao, b[0], b[1], b[2], b[3],
                            g_ledger.live()});
        }
        if (seen == osq::HostSeen::Prepared || seen == osq::HostSeen::Replaced) {
            if (const osq::SeqRec* r = g_ledger.find(seq); r && g_copier.on_host_prepared(*r, p8_now_us(), g_ledger)) {
                const std::vector<uint32_t> w = g_copier.waiting_for(seq, g_ledger);
                note(kNPending, {seq, r->required.size(), w.size() > 0 ? w[0] : 0u, w.size() > 1 ? w[1] : 0u,
                                 w.size() > 2 ? w[2] : 0u, w.size() > 3 ? w[3] : 0u, 1});
            }
        } else if (seen == osq::HostSeen::Branch) {
            // A 2981 of a sequencer copied in this trip that did not reach user 2 natively (another state
            // than the last one it got): copied. take_frame saw the native one first, when there was one
            // (the server sends to session 2 inside the same emission; the host's client reads it later).
            const uint64_t h = osq::packet_payload_hash(raw);
            if (g_copier.host_branch_needs_copy(seq, h)) {
                const bool ok = push_copy(raw);
                if (ok) g_copier.on_user2_branch(seq, h);
                note(kNBranch, {seq, ok ? 1u : 0u, probe() ? 1u : 0u});
            }
        } else if (seen == osq::HostSeen::Deleted || seen == osq::HostSeen::DeleteUnknown) {
            const auto fate = g_copier.on_host_deleted(seq);
            if (fate == osq::Copier::DeleteFate::Cancelled) {
                g_cancelled.fetch_add(1, std::memory_order_relaxed);
                note(kNDelete, {seq, static_cast<uint64_t>(fate), 0, probe() ? 1u : 0u});
            } else if (fate == osq::Copier::DeleteFate::Copy) {
                const bool ok = push_copy(raw);
                if (ok) g_deletes_copied.fetch_add(1, std::memory_order_relaxed);
                note(kNDelete, {seq, static_cast<uint64_t>(fate), ok ? 1u : 0u, probe() ? 1u : 0u}, true);
            }
        }
        release_locked();
    } catch (...) {
        g_faults.fetch_add(1, std::memory_order_relaxed);
    }
}

void observer_seq_copy_on_out(uint16_t opcode, std::span<const uint8_t> payload, bool pushed,
                              uint32_t server_owner) noexcept {
    if (!observer_seq_copy_wanted() || !pushed) return;
    const bool sched = sched_on() && osq::sched_op(opcode);
    if (opcode != osq::kOpMoveField && opcode != osq::kOpAnnounce && opcode != osq::kOpRemove &&
        opcode != osq::kOpBranch && opcode != osq::kOpMilestone && opcode != osq::kOpComplete &&
        opcode != osq::kOpPrepare && opcode != osq::kOpLoaded && !sched) {
        return;
    }
    try {
        g_out_seen.fetch_add(1, std::memory_order_relaxed);
        const uint64_t now = p8_now_us();
        if (sched) {  // a schedule Ack that reached user 2 natively (ToNear, or 2126's ToNear site) in its trip
            std::lock_guard lock(g_mu);
            const osq::SchedNative r = g_sched_trip.on_user2_native(opcode, payload, now, g_sched_ledger);
            if (r == osq::SchedNative::DuplicateSame || r == osq::SchedNative::DuplicateOther ||
                r == osq::SchedNative::NativeAfterCopy) {
                const auto m = osq::parse_sched(opcode, payload);
                note(kNSchedNative, {static_cast<uint64_t>(r), m ? m->key : 0u, g_sched_trip.npc_announced()},
                     r == osq::SchedNative::NativeAfterCopy);
                if (r == osq::SchedNative::DuplicateSame) release_locked();  // its follow-ups, right behind it
            }
            return;
        }
        switch (opcode) {
            case osq::kOpMoveField: {
                const uint32_t user = server_user2_user_key();
                const bool observer = user && (server_owner >> 28) == osq::kUserClass && server_owner != user;
                size_t snap = 0, live = 0, sched_snap = 0, sched_live = 0;
                uint64_t sched_excluded = 0;
                {
                    std::lock_guard lock(g_mu);
                    g_trip_epoch = server_epoch();
                    snap = g_copier.on_user2_move(observer, now, g_ledger);
                    live = g_ledger.live();
                    if (sched_on()) {
                        const uint64_t before = g_sched_trip.counters().excluded;
                        sched_snap = g_sched_trip.on_trip(observer, now, g_sched_ledger, server_user2_player_key());
                        sched_live = g_sched_ledger.live();
                        sched_excluded = g_sched_trip.counters().excluded - before;
                    }
                    if (observer) {
                        for (uint64_t seq : g_copier.pending_seqs()) {
                            const osq::SeqRec* r = g_ledger.find(seq);
                            const std::vector<uint32_t> w = g_copier.waiting_for(seq, g_ledger);
                            note(kNPending, {seq, r ? r->required.size() : 0u, w.size() > 0 ? w[0] : 0u,
                                             w.size() > 1 ? w[1] : 0u, w.size() > 2 ? w[2] : 0u, w.size() > 3 ? w[3] : 0u, 0});
                        }
                    }
                }
                note(kNTrip, {observer ? 1u : 0u, server_owner | static_cast<uint64_t>(user) << 32, snap, live,
                              server_epoch()},
                     true);
                if (observer && sched_on()) note(kNSchedTrip, {sched_snap, sched_live, sched_excluded, server_epoch()}, true);
                return;
            }
            case osq::kOpAnnounce: {
                std::vector<uint32_t> keys;
                osq::announce_keys(payload, keys);
                if (keys.empty()) return;
                std::lock_guard lock(g_mu);
                if (!g_copier.trip_active()) return;
                g_copier.on_user2_announce(keys);
                if (sched_on()) {  // the measure of the schedule copies' lines: NPC records already queued
                    size_t npcs = 0;
                    for (uint32_t k : keys) npcs += (k >> 28) == osq::kNpcClass ? 1u : 0u;
                    g_sched_trip.on_user2_announced(npcs);
                }
                release_locked();  // the schedule copies whose actor this 2005 announced go right behind it
                return;
            }
            case osq::kOpRemove: {
                std::vector<uint32_t> keys;
                osq::removed_keys(payload, keys);
                if (keys.empty()) return;
                std::vector<uint64_t> hit;
                {
                    std::lock_guard lock(g_mu);
                    if (!g_copier.trip_active()) return;
                    hit = g_copier.on_user2_remove(keys, g_ledger);
                }
                for (uint64_t seq : hit) {
                    g_bound_removed.fetch_add(1, std::memory_order_relaxed);
                    note(kNBound, {seq, keys.front()});
                }
                return;
            }
            case osq::kOpBranch: {
                const auto seq = osq::branch_seq(payload);
                if (!seq) return;
                const uint64_t h = osq::payload_hash(payload);
                std::lock_guard lock(g_mu);
                g_copier.on_user2_branch(*seq, h);
                return;
            }
            case osq::kOpPrepare: {  // user 2's own scene (its ESC item view): its Reqs about it always pass
                const auto p = osq::parse_prepare(payload, g_prepare_prefix.load(std::memory_order_relaxed));
                const uint32_t me = server_user2_player_key();
                if (!p || !me || p->actor != me) return;
                std::lock_guard lock(g_mu);
                g_copier.on_user2_own(p->seq);
                return;
            }
            case osq::kOpMilestone: {
                if (payload.size() != osq::kMilestonePayload) return;
                const uint32_t actor = osq::le32(payload.data());
                const uint32_t me = server_user2_player_key();
                if (!me || actor != me) return;
                size_t pending = 0, announced = 0;
                bool was = false;
                {
                    std::lock_guard lock(g_mu);
                    if (!g_copier.observer()) return;
                    was = g_copier.gate_is_open();
                    g_copier.on_user2_milestone();
                    pending = g_copier.pending();
                    announced = g_copier.announced_count();
                    release_locked();
                }
                if (!was) note(kNGate, {0, pending, announced}, true);
                return;
            }
            case osq::kOpLoaded: {  // review M2: user 2's 2762 ends the 2322's hold (+ its margin; the tick)
                std::lock_guard lock(g_mu);
                g_copier.on_user2_loaded(now);
                return;
            }
            case osq::kOpComplete: {
                std::lock_guard lock(g_mu);
                g_copier.on_user2_complete(now);
                if (sched_on() && g_sched_trip.on_user2_loaded(2)) {
                    note(kNSchedGate, {2, g_sched_trip.npc_announced(), g_sched_trip.pending()}, true);
                    release_locked();
                }
                return;
            }
            default:
                return;
        }
    } catch (...) {
        g_faults.fetch_add(1, std::memory_order_relaxed);
    }
}

bool observer_seq_copy_filter_req(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    if (!observer_seq_copy_wanted()) return false;
    // observer_sched_copy: user 2's 2549 MoveFieldCompleteReq = it finished loading the host's field; the server
    // answers with the field's 2005s (before user 2's 2144: session 11 G1, 545 NPC records). Never dropped.
    if (opcode == osq::kOpMoveFieldCompleteReq) {
        if (!sched_on()) return false;
        try {
            std::lock_guard lock(g_mu);
            if (g_sched_trip.on_user2_loaded(1)) {
                note(kNSchedGate, {1, g_sched_trip.npc_announced(), g_sched_trip.pending()}, true);
                release_locked();
            }
        } catch (...) {
            g_faults.fetch_add(1, std::memory_order_relaxed);
        }
        return false;
    }
    switch (opcode) {  // the rest never takes the lock
        case osq::kOpTriggerVolume:
        case osq::kOpChartEvent:
        case osq::kOpBranchReq:
        case osq::kOpStageFail:
        // kOpReloadStage 2283 is not here any more (P8 session 15): it carries no sequencer id; fast_travel.cpp (F2/F3).
        case osq::kOpGamePlayData:
        case osq::kOpCandidatePos:
        case osq::kOpDeleteSeqReq:
        case osq::kOpDelayEndReq:
        case osq::kOpPivotReq:
            break;
        default:
            return false;
    }
    try {
        osq::Copier::Req v;
        bool own = false, observing = false;
        {
            std::lock_guard lock(g_mu);
            v = g_copier.judge_req(opcode, payload, g_ledger);
            own = payload.size() >= 8 && g_copier.own(osq::le64(payload.data()));
            observing = g_copier.observer();
        }
        if (v == osq::Copier::Req::Pass) {
            if (opcode == osq::kOpDeleteSeqReq || opcode == osq::kOpDelayEndReq) {
                const size_t k = opcode == osq::kOpDeleteSeqReq ? 0 : 1;
                const uint64_t n = (own ? g_pass_own[k] : g_pass_other[k]).fetch_add(1, std::memory_order_relaxed);
                if (n < 8) note(kNPass, {opcode, payload.size() >= 8 ? osq::le64(payload.data()) : 0u, own ? 1u : 0u}, true);
            }
            return false;
        }
        const size_t i = static_cast<size_t>(v);
        const bool drop = observer_seq_copy_sends();
        const uint64_t n = (drop ? g_filter_drop[i] : g_filter_would[i]).fetch_add(1, std::memory_order_relaxed);
        if (!observing && (v == osq::Copier::Req::HostDelete || v == osq::Copier::Req::HostDelayEnd)) {
            g_drop_outside[v == osq::Copier::Req::HostDelete ? 0 : 1].fetch_add(1, std::memory_order_relaxed);
        }
        if (n < 8) note(kNFilter, {opcode, payload.size() >= 8 && opcode != osq::kOpCandidatePos ? osq::le64(payload.data()) : 0u, drop ? 1u : 0u}, true);
        return drop;
    } catch (...) {
        return false;
    }
}

void observer_seq_copy_tick() noexcept {
    if (!observer_seq_copy_wanted()) return;
    try {
        bool active = false;
        {
            std::lock_guard lock(g_mu);
            active = g_copier.trip_active();
        }
        // The pushes come from take_frame and the sniffer; this only retries and opens the gate on time.
        static uint64_t last_turn_ms = 0;
        const uint64_t turn_ms = GetTickCount64();
        if (turn_ms - last_turn_ms < 100) active = false;
        else last_turn_ms = turn_ms;
        if (active) {
            uintptr_t user2 = 0;
            if (!server_user2(user2) || !user2) {
                clear_trip(ClearWhy::UserGone);
            } else if (server_logout_requested()) {
                clear_trip(ClearWhy::Logout);
            } else {
                std::lock_guard lock(g_mu);
                const bool was = g_copier.gate_is_open();
                if (g_copier.observer() && g_copier.gate_open(p8_now_us()) && !was) {
                    note(kNGate, {1, g_copier.pending(), g_copier.announced_count()}, true);
                }
                if (g_copier.pending() || (g_copier.observer() && !g_copier.milestone_sent()) ||
                    (sched_on() && g_sched_trip.pending())) {
                    release_locked();
                }
            }
        }
        p8p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind < kNoteCount) log::info("{}", line_of(e));
        }
        // A bound reached is said at once (the 60 s summary has the totals).
        {
            static uint64_t full_logged = 0, evicted_logged = 0;
            osq::Copier::Counters c;
            {
                std::lock_guard lock(g_mu);
                c = g_copier.counters();
            }
            if (c.pending_full != full_logged) {
                log::warn("ObserverSeqCopy: {} sequencer(s) found the pending table full (1024): not copied",
                          c.pending_full - full_logged);
                full_logged = c.pending_full;
            }
            if (c.delivered_evicted != evicted_logged) {
                log::warn("ObserverSeqCopy: {} delivered mark(s) evicted (1024 in this trip): their 2810 will not be copied",
                          c.delivered_evicted - evicted_logged);
                evicted_logged = c.delivered_evicted;
            }
        }
        const uint64_t now = GetTickCount64();
        if (!g_last_summary_ms) g_last_summary_ms = now;
        if (now - g_last_summary_ms >= 60000) {
            g_last_summary_ms = now;
            summary();
            if (sched_on()) sched_summary();
        }
    } catch (...) {
    }
}

void observer_seq_copy_on_server_replaced() noexcept {
    if (!observer_seq_copy_wanted()) return;
    try {
        {
            std::lock_guard lock(g_mu);
            g_copier.clear_server();
            g_ledger.clear_all();
            g_sched_trip.clear();
            g_sched_ledger.clear_all();
        }
        note(kNClear, {static_cast<uint64_t>(ClearWhy::Server)}, true);
    } catch (...) {
    }
}

void observer_seq_copy_on_epoch(uint32_t) noexcept {
    if (!observer_seq_copy_wanted()) return;
    try {
        clear_trip(ClearWhy::Epoch);
    } catch (...) {
    }
}

std::string observer_seq_copy_describe() {
    if (!observer_seq_copy_wanted()) return {};
    std::lock_guard lock(g_mu);
    const osq::Copier::Counters c = g_copier.counters();
    std::string sched;
    if (sched_on()) {
        const osq::SchedTrip::Counters s = g_sched_trip.counters();
        sched = std::format(" | sched copy: ledger {}, pending {}, sent {} (+{}), live 2126 {} 2958 {} 2909 {}, dup {}",
                            g_sched_ledger.live(), g_sched_trip.pending(), s.copied, s.follow_copied, s.live_fwd[0],
                            s.live_fwd[1], s.live_fwd[2],
                            s.dup_same + s.dup_other + s.live_native[0] + s.live_native[1] + s.live_native[2] +
                                s.live_native[3]);
    }
    return std::format("seq copy {}: ledger live {}, trip {}, gate {}, pending {}, copied {} (2981 {}), 2322 {}, 2810 {}, "
                       "C>S dropped {}/{} 2276 {} 2105 {} 2888 {} (would {}/{}/{}/{}/{}), refused {}{}",
                       g_mode.load() == osq::Mode::On ? "ON" : "probe", g_ledger.live(),
                       g_copier.observer() ? "observer" : g_copier.trip_active() ? "own field" : "none",
                       g_copier.gate_is_open() ? "open" : "closed", g_copier.pending(), c.copied, c.copied_branches,
                       c.milestones, g_deletes_copied.load(), g_filter_drop[1].load(), g_filter_drop[2].load(),
                       g_filter_drop[3].load(), g_filter_drop[4].load(), g_filter_drop[5].load(), g_filter_would[1].load(),
                       g_filter_would[2].load(), g_filter_would[3].load(), g_filter_would[4].load(), g_filter_would[5].load(),
                       c.refused, sched);
}

}  // namespace cdmp::session2
