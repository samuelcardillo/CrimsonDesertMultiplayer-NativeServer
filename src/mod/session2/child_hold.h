#pragma once
// Build 3527 port: child_hold, character_hold, observer_hold and its family and
// settle policies use verified native entry points, TLS realm, actor-manager
// globals and sector layout. The parent key was measured on live server actors:
// +0xAC named a resolvable actor for 238 of 262 parents, and agreed with hierarchy
// +0x1C in every case (the serializer at 0xB27F140 confirms +0x1C). The publication
// gate and the key retirement stay off on that build: they are not verified. Build
// 2976 and the fake-memory test seams retain their existing behavior.
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the same hooks and checks at 3527's sites + 0xC70 (NotifyAppear,
// its callers, StartActionReq::vf2), + 0xDD0 (the restore writer), + 0xC50 (the realm mark), all with 3527's bytes; TLS
// realm +0x1EB and TransformSync sector +0x548 unchanged (child_hold.cpp, kHoldChecks3576). The publication gate and
// the key retirement stay off there too.
// Build 1.0.0.3663 (static, 2026-11-13; never run): the same hooks and checks in the same functions, from 3527's sites
// NotifyAppear +0x67B20, its callers +0x67A10, StartActionReq::vf2 +0x666E0, the restore writer +0x72750, the realm mark
// +0x63280 (child_hold.cpp, kHoldChecks3663); three call rel32 are new; TLS realm +0x1EB and TransformSync sector +0x548
// unchanged.
// Option D, D-53 (docs/research/pendientes/companeros-publicacion.md §3): the
// server does not publish a child of ANY user (pet, horse, companion; the
// host's as well as user 2's) to the other users until that child has its
// first action.
//
// Why: the server serialises every actor for the others through ONE .rsrc
// function, NotifyAppear 0x2B000C0 (u8 unused, {NwSession** , u32 n}*,
// {u32 keys*, u32 n}*), called only from OnActorSectorChanged 0x2AF8AF0
// (0x2AF90EB new observers <- [actor]; 0x2AF92D1 the moving user's session <-
// every actor of the sectors it enters). A child is created on the server with
// restore byte 0 (no action yet): another user's client builds it with a chart
// and no action, and six native readers crashed on that state
// (companeros-cierre-salida.md §4). Only the actor's controller (its owner's
// client) gives it its first action. User 2's children would reach the host's
// client that way; the host's own (a horse or pet summoned while user 2 is in)
// would reach user 2's real client (P8), which has no containment at all
// (p8-preparacion.md G1): both are held here.
//
// What it does (server side, before anything is serialised):
//   hold     an entry wrapper on NotifyAppear splits the key list: a key is
//            HELD when it is a child-class key (0xB...), it resolves in the
//            ServerActorManager, its owner [actor+0xA0] is a validated user
//            (the host's ServerUserActor, user 2's, or, fail safe as the clock
//            gate, any other ServerUserActor once the host is known; never an
//            NPC, which has no owner), and its restore byte [[CC+0x40]+0x30]
//            (CC = [[actor+0x68]+0x40]) is 0. The original runs with the
//            engine's sessions and the other keys, then with only the owner's
//            session(s) and the held keys (an owner always gets its own child
//            at once); every other recipient is noted as (child, observer) in
//            a bounded table.
//   release  on ServerRunThread only, after StartActionReq::vf2 0x296CAA0
//            returns and, as a fallback, from the OnRecvPacket mid-hook: an
//            entry whose child still resolves BY KEY, has restore byte 1, and
//            whose observer session is still valid and still observes the
//            child's sector (sector+0x68 list, as 0x2AF2E60 reads it) gets one
//            native NotifyAppear([observer], [child]); the 2005 is then
//            serialised with the action, as Kliff's since D-48.
//   drop     once user 2 is gone or leaving, every entry it is part of (as the
//            owner or as the observer) goes; with two users that is all of them.
// Never released with restore 0. Anything unreadable: the original unchanged.
// The only game function called is NotifyAppear itself (its trampoline).
//
// observer_hold=1 (S3, pendientes/p8-impl-s3.md; p8-raiz-invitado.md §6 row 3),
// the same two hooks: an actor WITHOUT owner ([actor+0xA0] == 0, an NPC)
// whose CONTROLLER [actor+0x90] (u32 user key, 0x2A78CF8) is the host's or
// user 2's user key and whose restore byte is 0 goes at once to its
// controller's session(s) and is withheld from every other recipient (an
// "observer"), in its own bounded table. The controller is never held. Its
// release is the same native re-announce (a fresh 2005, never the old one),
// after the controller's client gave it its first action: the host's client
// sends a StartActionReq for every NPC it controls ~0.16 s after it appears
// (session 4 host capture: 956 of 956). After StartActionReq::vf2 only the
// entries of the Req's own actor key ([[ctx+0x18]+5], read before the
// original runs) are evaluated, plus a budgeted pass over the table at most
// every hold::kNpcPassMs, also from the tail of the game's own NotifyAppear
// calls (its thread; entries progress without any StartActionReq). The
// receiving thread's fallback tick only drops (NotifyAppear is never called
// there: the engine's logic runs on another server-realm thread). Every pass
// copies its entries under the lock, decides outside it with SEH reads (no
// VirtualQuery) and re-locks only to remove the entries still there unchanged
// (HoldEntry::stamp). Despawn, observer gone / out of range / its epoch ended
// -> dropped; the observer becoming the controller -> released; still restore
// 0 after hold::kNpcTimeoutMs -> released with restore 0 as the engine would
// (live 2026-10-09: ambient type-6 creatures keep restore 0 while their
// controller starts actions; dropping hid them for good). Another actor behind
// the key, owned by a user with child_hold off, or unreadable for too long
// while the actor still exists and the observer still observes it -> released
// natively (restore as it is) instead of dropped, so the observer never keeps
// an invisible NPC in range. Room for every withheld (NPC, observer) is
// reserved under the lock in the split itself: an NPC is never withheld
// without its entry. With observer_hold=0 nothing of this runs.
//
// character_hold=1 (pendientes/p8-character-hold.md; p8-crash-esc-1831598.md
// §5.2 B), the same two hooks: a user's MAIN character (key class 0xA, owner
// [actor+0xA0] a validated user as for D-53, and that user's character
// [[actor+0xA0]+0xD0] is this very actor) whose restore byte is 0 goes at once
// to its owner's session(s) and is withheld from every other recipient, in its
// own small table. The owner is never held (its own login is never delayed).
// Released by the same native re-announce once its first action was accepted
// (restore 1); still restore 0 after hold::kCharTimeoutMs -> announced natively
// WITH restore 0 (a warning line: what the engine does without the key).
// Dropped only when the observer cannot see it anyway (epoch, despawn/logout,
// observer gone or out of range: field change); another actor behind the key,
// another owner, or unreadable for too long while still in range -> announced
// natively instead (never dropped invisibly). Its pieces without CC (equipment)
// are not held: with the parent absent 0x439AB0 takes its parentless path.
// With observer_hold_acks=1 the character's per-actor packets to user 2 wait for
// its 2005 like an NPC's (observer_hold_acks.h). Off: nothing of this runs.
//
// observer_hold_family=1 (P8 S15/S16, pendientes/p8-s14-viajeros.md §7; was observer_hold_pieces, §6), with
// observer_hold: user 2 never gets an actor record before its parent's. Every 2005 record ends with the parent
// (client actor+0xAC); on the server it is the actor's own u32 +0xAC (hold::kActorParent, verified against the
// records), else the hierarchy component [[actor+0x68]+0x1B8] +0x1C (own actor at +8). A family member (any 0xB key not held otherwise: a piece without CC, a group member with CC,
// a rider) is withheld from a recipient session, in its own bounded table (room reserved in the split), when
//   - its parent is withheld from that session in this very call (any hold), or
//   - its parent has an entry withheld from that session (NPC, family, D-53 child, child_settle tables), or
//   - that session is user 2's live session 2 and the parent has not been announced to it yet: the set of keys
//     NotifyAppear (and take_frame's 2005s) gave it, less the 2516s that removed them, per guest epoch.
// The other recipient(s) get it now (fam::family_owner; mixed -> native, "partial"). It goes in the NotifyAppear
// that releases its parent, behind it (stable sort by depth: parents first, any number of levels), or right
// after the engine's own NotifyAppear that announces its parent to that session (one more call there, at once);
// dropped with its parent. An observer_hold entry (restore 0, load_defer) whose release is due while its parent
// is not with user 2 yet becomes a family entry (released with or after its parent). Natively, as today, when
// the parent never comes (hold::kFamilyOrphanMs waiting for its announcement) or after hold::kFamilyMaxHoldMs;
// for the host's session (no "announced" set: its client has everything since before the hook) a member whose
// parent is no longer withheld goes at once (orphan, as observer_hold_pieces did). Never withheld when the
// hierarchy cannot be read (unlinked) or the table is full: as before the key. probe: counted and logged.
// Whatever the key, with observer_hold=1 take_frame counts the ORPHANS actually queued for user 2 (records
// whose parent it has not got: analyze_capture.py `orphans` on the host).
//
// Threads (p8-auditoria-hilos.md §4 case 3), [session2] notify_thread_rule
// (default 0; P8 review I3, p8-revision-noche.md "Correcciones"):
//   0 = as before the rule (D-53 unchanged): a release after StartActionReq runs
//       on the thread of that handler (server realm); the receiving thread's
//       fallback only on the last thread that called NotifyAppear; no sweep at
//       the tail of NotifyAppear for the children.
//   1 = every native NotifyAppear the holds make (D-53, observer_hold,
//       character_hold) runs only on a thread that the game itself used for
//       NotifyAppear, seen in the entry detour with a return address at one of
//       its two native call sites (0x2AF90F0 / 0x2AF92D6). After a
//       StartActionReq on any other thread the release is deferred to the tail
//       of the next native NotifyAppear (counted).
// Either way, a due release left waiting for a thread that may call NotifyAppear
// for more than hold::kDeferWarnMs gives one WRN line (its age, the thread that
// left it, which holds) and an INF line when it finally runs.
// Static check [V] (2976): the caller 0x2AF8AF0 and its two callers
// (0x2AF8090, 0x2AF86E0) never touch the send context [TLS+0x250] nor the
// bundle-scope functions (0x2961CA0 lookup, 0x2961DE0/0x2961E90 add,
// 0x2961F60 flush, 0x2962220 end): the tail of a native NotifyAppear does not
// open a ScopeSenderAck 2042 around the release; its 2005 meets the same scope
// state as the native 2005 just before it.
//
// child_settle_ms=S (P8 session 8, pendientes/p8-s8-mascotas.md §4.1,
// pendientes/p8-impl-mascotas.md; child_settle_logic.h), default 0 = nothing of
// this runs. The same two hooks: a user's child (0xB, owner a validated user,
// type 4/5/6, ANY restore byte) that D-53 does not hold goes at once to its
// owner's session(s) and is withheld from every other recipient whose copy of
// the owner's MAIN character ([owner+0xD0], 0xA) is in this very call, was
// announced less than S ms ago (an announcement log of the 0xA keys written by
// the detour and by character_hold's releases), or is still withheld by
// character_hold. Released by the same native re-announce, S ms after the
// character's announcement to that observer (after StartActionReq, at the tail
// of a native NotifyAppear; the receiving thread's fallback as D-53's, and with
// notify_thread_rule=0 also a release overdue by hold::kDeferWarnMs), or
// natively after cst::max_wait_ms (also when unreadable). A character in the
// observer's range never announced there is waited for too. A D-53 release
// (restore 1) waits for the same S ms. Dropped only when the observer surely
// cannot see it; a re-hold racing a release is dropped after it. With
// observer_hold_acks=1 its per-actor packets to user 2 wait for its 2005.
//
// Logging: every line is a fixed record pushed to a lock-free ring (no
// formatting on the game's threads, nothing written under g_mu) and formatted
// by child_hold_network_tick on the mod's network thread.

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace cdmp::session2 {

// Offsets, build 1.0.0.2976 (evidence in companeros-publicacion.md §1-§2).
namespace hold {
inline constexpr uint32_t kActorKey = 0x60;          // u32 (0x2AF9062)
inline constexpr uint32_t kActorComponents = 0x68;   // -> components
inline constexpr uint32_t kComponentsCc = 0x40;      // -> CharacterControl (0x296CEFE)
inline constexpr uint32_t kComponentsTs = 0x1A0;     // -> TransformSync (0x2BC5233)
inline constexpr uint32_t kActorInfo = 0x88;         // -> static info; u8 record type at +1 (0x296CE83)
inline constexpr uint32_t kInfoType = 0x01;
inline constexpr uint32_t kActorOwner = 0xA0;        // ServerUserActor* (vf160 = 0x50E6B0)
inline constexpr uint32_t kCcActor = 0x08;           // CC -> its actor (0x2A78CCB)
inline constexpr uint32_t kCcRestore = 0x40;         // CC -> restore state (0x2A78DAF / 0x2328890)
inline constexpr uint32_t kRestoreByte = 0x30;       // u8: 1 once the first action was accepted (0x2328894)
inline constexpr uint32_t kTsActor = 0x08;           // TS -> its actor
inline constexpr uint32_t kTsSector = 0x540;         // TS -> current sector (.xtls 0x10648425, read only)
inline constexpr uint32_t kTsSector3527 = 0x548;     // 3527 ToNear/OnActorSectorChanged (child_hold_3527.json); 3576 too
inline constexpr uint32_t kSectorObservers = 0x68;   // {ServerUserActor*, refs}[n] (0x2AF2F24)
inline constexpr uint32_t kSectorObserverCount = 0x70;
inline constexpr uint32_t kObserverStride = 0x10;
inline constexpr uint32_t kMaxObservers = 256;
inline constexpr uint32_t kUserKey = 0x60;
inline constexpr uint32_t kChildKeyClass = 0xB;      // key >> 28 of NPCs and children (users 0x9, characters 0xA)
inline constexpr size_t kTableCapacity = 64;
inline constexpr uint64_t kTimeoutMs = 3000;
// observer_hold (S3)
inline constexpr uint32_t kActorController = 0x90;   // u32 controlling user key (0x2A78CF8 mov ecx,[rbx+0x90])
// One entry per (NPC, observer). Evidence: the whole session-4 host capture
// (cdmp_packets_20261009-180132.bin) has 956 first appearances of NPCs with a
// user controller and restore 0, and with two users each NPC has one observer;
// live 2026-10-09 (one PC, observer_hold=1): 320 held for user 2 within ~2 min
// and, with 256, "table full -> native 372" during an earlier burst (releases
// took 2.6 s mean, 6.9 s max, and type-6 creatures wait the 10 s timeout).
// 1024 holds every restore-0 NPC of that session at once. Bounded:
// 1024 x sizeof(HoldEntry) (~100 KB), passes budgeted (kNpcPassBudget).
inline constexpr size_t kNpcTableCapacity = 1024;
// Host capture 20261009-180132: first StartActionReq of the host's client
// for 956 new NPCs 141..540 ms (median 161) after their 2005; 10 s is ~20x.
inline constexpr uint64_t kNpcTimeoutMs = 10000;
// observer_load_defer (P8 session 14, pendientes/p8-impl-spawn-action.md): an NPC announced to user 2 while
// user 2 is loading waits for its 2762 at most this long; then the usual rules release it (restore 1: as the
// engine would have, during the load). Session 13: 2549 -> 2762 took 14.7 s (trip 2) and 19.0 s (trip 1).
inline constexpr uint64_t kLoadDeferMaxMs = 60000;
// The log lines of the deferrals and of their releases (each), apart from observer_hold's own budgets.
inline constexpr uint64_t kLoadDeferLogged = 16;
// The budgeted pass over the NPC table: at most every kNpcPassMs, at most
// kNpcPassBudget entries (round robin), so a full table is covered in 0.4 s.
inline constexpr uint64_t kNpcPassMs = 100;
inline constexpr size_t kNpcPassBudget = 256;
// The receiving thread's fallback (drops only) at most this often.
inline constexpr uint64_t kNpcFallbackMs = 250;
// TrocTrStartActionReq::vf2(this, int* res, ctx): ctx is the packet wrapper,
// u16 size at +0x10, raw at +0x18 = {u16 opcode, u8, u16 len, payload}; the
// payload starts with the actor key (decompilation 0x296caa0.c: lVar7 =
// param_3[3]; size - 5 must equal u16 [raw+3]; the deserializer reads raw+5).
inline constexpr uint32_t kReqWrapperSize = 0x10;
inline constexpr uint32_t kReqWrapperRaw = 0x18;
inline constexpr uint32_t kReqRawLen = 0x03;
inline constexpr uint32_t kReqRawPayload = 0x05;
// character_hold
inline constexpr uint32_t kCharKeyClass = 0xA;       // key >> 28 of characters (users' Kliffs 0xA01...)
// ServerUserActor -> its controlled (main) character: [[pj+0xA0]+0xD0] == pj is the
// autosave's "main character of its user" test (.xtls 0x10859ED0, opcion-d-e3-riesgos.md §3.2) and
// LiveTransmog's chain NwSession+0xA0 -> ServerUserActor +0xD0 -> ServerChildOnlyInGameActor
// (orcax-equiphide.md §3.6). Wrong or unreadable -> nothing held (fail safe).
inline constexpr uint32_t kUserCharacter = 0xD0;
// At most a few (2 users: each one's character withheld from the other); bounded.
inline constexpr size_t kCharTableCapacity = 16;
// The obsolete peer script (login_e3lc00act_112627.troc) sends the character's first StartActionReq
// ~5.1 s after it enters the host's field (p8-crash-esc-1831598.md §2.1); a real client sends it
// 9-16 ms after its own ActorLoadDataAck (opcion-d-accion-usuario2.md §3.1). 15 s is ~3x the former.
inline constexpr uint64_t kCharTimeoutMs = 15000;
inline constexpr uint64_t kCharPassMs = 50;         // the passes at most this often (tail / fallback)
// child_settle: at most a few (2 users: each one's pet/horse withheld from the other); bounded.
inline constexpr size_t kSettleTableCapacity = 32;
inline constexpr size_t kAnnounceLogSlots = 64;     // (0xA key, session) -> last announcement
// observer_hold_pieces (P8 sessions 13/14, pendientes/p8-s14-viajeros.md §6): an NPC's carried pieces
// (type 7 "Game Mechanic" without CC: a basket, a bull's load, a wagon's cargo, a leader's rope) name their
// parent in the hierarchy component server and client share (CommonHierarchyActorComponent):
// [[actor+0x68]+0x1B8], its own actor at +8 and the parent's key at +0x1C. Server [V]: 0x279688C mov rax,
// [rbx+0x68] ; 0x2796890 mov rbx,[rax+0x1B8] ; 0x2796897 mov ebx,[rbx+0x1C] -> find by key (0x27968B0).
// Client [V]: 0x15ECA10 finds the parent by [hier+0x1C] (p8-crash-esc-1831598.md §1.2).
inline constexpr uint32_t kComponentsHierarchy = 0x1B8;
inline constexpr uint32_t kHierActor = 0x08;
inline constexpr uint32_t kHierParent = 0x1C;
// observer_hold_family: S14 66 pieces went out before their withheld parent in 600 s (S13: 114), S15 75 orphans
// (44 in the burst after user 2's 2762, when observer_load_defer releases ~330 NPCs). 1024 (member, observer)
// is ~10x the peak; bounded (~150 KB).
inline constexpr size_t kFamilyTableCapacity = 1024;
// A member whose parent is still withheld waits with it at most this long (the parent's own longest wait:
// observer_load_defer's 60 s, then 3 x the restore-0 timeout); then it is announced natively.
inline constexpr uint64_t kFamilyMaxHoldMs = kLoadDeferMaxMs + 3 * kNpcTimeoutMs;
// A member waiting for a parent that is neither withheld nor announced to user 2 (the engine announces it in a
// later NotifyAppear) waits at most this long; then it is announced natively (an orphan, as without the key).
inline constexpr uint64_t kFamilyOrphanMs = kNpcTimeoutMs;
// The keys announced to user 2's session (and not removed since): sized for every actor in its range at once.
inline constexpr size_t kFamilyKnownSlots = 16384;
// observer_hold_family's parent source: the server actor's own u32 +0xAC, the very value its 2005 record carries
// as the parent (the client's actor+0xAC). [V] one-PC regression 2026-10-11 (cdmp_20261011-130754.log): 146
// candidates with hierarchy parent == +0xAC, 0 different, 41 with +0xAC only (hierarchy 0), and every logged
// orphan's record parent was that +0xAC. The hierarchy (+0x1C) is the fallback when +0xAC cannot be read.
inline constexpr uint32_t kActorParent = 0xAC;
// The threads seen calling NotifyAppear natively (kept, never forgotten in a process).
inline constexpr size_t kNativeThreads = 8;
// A due release that waited this long for a thread that may call NotifyAppear: one WRN line.
inline constexpr uint64_t kDeferWarnMs = 2000;

// How long a due release has waited for a thread that may call NotifyAppear (P8
// review I3). Lock-free: the game's threads note, the mod's network thread polls.
// An episode starts with the first deferral and ends when a pass that may
// release runs.
class DeferWatch {
public:
    enum Kind : uint8_t { kChild = 1, kNpc = 2, kChar = 4 };
    struct Report {
        bool warn = false;      // the open episode just went past the limit (once per episode)
        bool resolved = false;  // a warned episode ended (once)
        uint64_t age_ms = 0;
        uint32_t tid = 0;       // the thread of the first deferral
        uint8_t kinds = 0;
        uint64_t count = 0;     // deferrals in the episode
    };
    void deferred(uint64_t now, uint32_t tid, uint8_t kind) noexcept {
        uint64_t expect = 0;
        if (since1_.compare_exchange_strong(expect, now + 1, std::memory_order_acq_rel)) {
            tid_.store(tid, std::memory_order_relaxed);
        }
        kinds_.fetch_or(kind, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
    }
    // A pass that may call NotifyAppear ran: the episode (if any) ends.
    void ran(uint64_t now) noexcept {
        const uint64_t s = since1_.exchange(0, std::memory_order_acq_rel);
        if (!s) return;
        const uint64_t age = now + 1 > s ? now + 1 - s : 0;
        uint64_t m = max_ms_.load(std::memory_order_relaxed);
        while (age > m && !max_ms_.compare_exchange_weak(m, age, std::memory_order_relaxed)) {
        }
        if (warned_.exchange(false, std::memory_order_acq_rel)) {
            resolved_age_.store(age, std::memory_order_relaxed);
            resolved_.store(true, std::memory_order_release);
        }
        kinds_.store(0, std::memory_order_relaxed);
        count_.store(0, std::memory_order_relaxed);
    }
    Report poll(uint64_t now, uint64_t limit) noexcept {
        Report r;
        if (resolved_.exchange(false, std::memory_order_acq_rel)) {
            r.resolved = true;
            r.age_ms = resolved_age_.load(std::memory_order_relaxed);
        }
        const uint64_t s = since1_.load(std::memory_order_acquire);
        if (s && now + 1 >= s + limit && !warned_.load(std::memory_order_relaxed) &&
            !warned_.exchange(true, std::memory_order_acq_rel)) {
            r.warn = true;
            r.age_ms = now + 1 - s;
            r.tid = tid_.load(std::memory_order_relaxed);
            r.kinds = kinds_.load(std::memory_order_relaxed);
            r.count = count_.load(std::memory_order_relaxed);
        }
        return r;
    }
    uint64_t open_ms(uint64_t now) const noexcept {
        const uint64_t s = since1_.load(std::memory_order_relaxed);
        return s && now + 1 > s ? now + 1 - s : 0;
    }
    uint64_t max_ms() const noexcept { return max_ms_.load(std::memory_order_relaxed); }
    void reset() noexcept {
        since1_ = 0;
        tid_ = 0;
        kinds_ = 0;
        count_ = 0;
        max_ms_ = 0;
        resolved_age_ = 0;
        warned_ = false;
        resolved_ = false;
    }

private:
    std::atomic<uint64_t> since1_{0};  // first deferral + 1 (0 = no episode)
    std::atomic<uint32_t> tid_{0};
    std::atomic<uint8_t> kinds_{0};
    std::atomic<uint64_t> count_{0}, max_ms_{0}, resolved_age_{0};
    std::atomic<bool> warned_{false}, resolved_{false};
};
}  // namespace hold

// The game's {T* data; u32 count; u32 capacity}: what both callers build on
// their stack for NotifyAppear (0x2AF90B6..0x2AF90D1, 0x2AF92A4..0x2AF92BF).
// NotifyAppear only reads +0 and +8 (0x2B000F0, 0x2B001B7, 0x2B0021D) and
// frees neither the structs nor what they point to.
struct GameVec {
    const void* data;
    uint32_t count;
    uint32_t capacity;
};
static_assert(sizeof(GameVec) == 16);

// Whose actor an owner [actor+0xA0] is. user2 = session 2's user (0 = not
// known); host = the host's user (0 = not known); host_key = the host's user
// key (0 = not known); user_vtable = ServerUserActor's vtable (0 = do not
// check). Host = exactly the host's user pointer (the one its session reads,
// so its own session is always found as the owner's). Guest = user 2, or (fail
// safe, as the clock gate) a ServerUserActor that is neither, once the host is
// known. A pointer carrying the host's key that is not the host's pointer, an
// owner that is not a user, or anything unreadable -> None (nothing is held:
// the original runs).
enum class OwnerWho : uint8_t { None, Host, Guest };
OwnerWho hold_owner_who(uintptr_t owner, uintptr_t user2, uintptr_t host, uint32_t host_key, uintptr_t user_vtable);
const char* owner_who_name(OwnerWho who);

// The restore byte [[CC+0x40]+0x30] of a server actor, CC = [[actor+0x68]+0x40]
// with [CC+8] == actor. nullopt = no CC or unreadable.
std::optional<uint8_t> child_restore_byte(uintptr_t actor);
// Its current sector [[[actor+0x68]+0x1A0]+0x540] with [TS+8] == actor (0 = in none).
std::optional<uintptr_t> child_sector(uintptr_t actor);
// Is `user` (a pointer value) among the sector's observers (+0x68/+0x70)?
std::optional<bool> sector_observed_by(uintptr_t sector, uintptr_t user);

// NoOwner: an NPC (not held unless observer_hold). The last three only with
// hold_verdict_ex: ChildrenOff = a user's child while child_hold=0;
// CtrlNotUser = an NPC whose controller is neither the host's nor user 2's
// user key (the server's own, 0, or unknown: left native); TableFull = the
// NPC table has no room for its observers (left native, counted).
// NotMain (character_hold): a user's 0xA actor that is not [[owner]+0xD0] (left native).
enum class HoldWhy : uint8_t {
    NotChildKey, Unreadable, NotFound, NoOwner, NotUser, NoCc, Restored, Hold, ChildrenOff, CtrlNotUser, TableFull,
    NotMain
};
const char* hold_why_name(HoldWhy why);
struct HoldVerdict {
    bool hold = false;
    HoldWhy why = HoldWhy::NotChildKey;
    uintptr_t actor = 0;
    uintptr_t owner = 0;  // a child: its owner; an NPC (npc): its controller's user pointer
    OwnerWho owner_who = OwnerWho::None;
    uint8_t type = 0;  // [[actor+0x88]+1] (log only; 0 = unreadable)
    bool npc = false;         // observer_hold: an NPC held by its controller
    uint32_t controller = 0;  // its [actor+0x90]
    bool character = false;   // character_hold: a user's main character held from the others
    bool settle = false;      // child_settle: a user's child withheld until its owner's character settled
    uint32_t main_key = 0;    // child_settle: its owner's main character's key
    uint8_t restore = 0xFF;   // child_settle: its restore byte (log only; 0xFF = unknown)
    bool main_in_call = false;  // child_settle: the character goes in this very call (log only)
    // observer_load_defer: an NPC of the host with restore 1 announced while user 2 loads. With the key at 1 it
    // is held (hold, npc); with probe only marked (Restored, not held) and counted.
    bool defer = false;
    // observer_hold_family: a family member withheld behind its parent (owner = the user that gets it now).
    bool family = false;
    uint32_t parent = 0;
    uint8_t family_why = 0;  // FamilyWhy (log only)
    // S35 publication_gate=1: withheld WITHOUT an entry (its table had no room: never announced natively instead).
    bool no_entry = false;
    // S35 publication_gate: an NPC whose CC could not be read (not proven absent): held (1) or counted (probe).
    bool cc_unknown = false;
};
// observer_hold_family: why a member is withheld.
enum class FamilyWhy : uint8_t {
    ParentInCall,    // its parent is withheld from that session in this very NotifyAppear
    ParentHeld,      // its parent has an entry withheld from that session
    ParentUnknown,   // user 2 has not been given its parent yet
    ReleaseBlocked,  // an observer_hold entry due while its parent was not with user 2 yet
};
const char* family_why_name(FamilyWhy w);
// The predicate for one key (read only, by key through the SAM's map).
HoldVerdict hold_verdict(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                         uintptr_t user_vtable);
// observer_hold: who may control an NPC (both pointers as the sessions read
// them; a key of 0 = that user is not known).
struct ObserverHoldUsers {
    uintptr_t host = 0;
    uint32_t host_key = 0;
    uintptr_t user2 = 0;
    uint32_t user2_key = 0;
    // observer_load_defer (0 off, 1 probe, 2 on; u2f::Mode) and whether user 2 is loading now (its move phase).
    uint8_t load_defer = 0;
    bool user2_loading = false;
    // S35 publication_gate (0 off, 1 probe, 2 on): an NPC whose CC cannot be read is held (2), not announced.
    uint8_t pub_gate = 0;
};
// children = child_hold's rule for users' children (false: ChildrenOff);
// npc = observer_hold's rule for NPCs (nullptr: NoOwner, as before).
// hold_verdict(...) == hold_verdict_ex(..., true, nullptr).
HoldVerdict hold_verdict_ex(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                            uintptr_t user_vtable, bool children, const ObserverHoldUsers* npc);
// All three rules. characters = character_hold's rule for 0xA keys (false: NotChildKey, as before);
// fast = SEH reads only (observer_hold's), else VirtualQuery + SEH (D-53's).
struct HoldRules {
    bool children = true;
    const ObserverHoldUsers* npc = nullptr;
    bool characters = false;
    bool fast = false;
};
HoldVerdict hold_verdict_rules(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                               uintptr_t user_vtable, const HoldRules& rules);
// The controller -> its user pointer (Host / Guest), or None.
OwnerWho npc_controller_who(uint32_t controller, const ObserverHoldUsers& u, uintptr_t& user);

// The split of one NotifyAppear call.
struct HoldGroup {
    uintptr_t owner = 0;
    std::vector<uintptr_t> sessions;  // the owner's session(s) among the recipients (may be empty)
    std::vector<uint32_t> keys;
};
struct HoldRecord {
    uint32_t key = 0;
    uintptr_t observer = 0;       // recipient session the child is withheld from
    uintptr_t observer_user = 0;  // its validated user
    uintptr_t owner = 0;
    OwnerWho owner_who = OwnerWho::None;
    bool observer_host = false;   // observer_user is the host's user
    uint8_t type = 0;
    bool npc = false;             // observer_hold
    uint32_t controller = 0;
    uintptr_t actor = 0;          // the actor at hold time (compared, never followed)
    bool character = false;       // character_hold
    bool settle = false;          // child_settle
    uint32_t main_key = 0;        // child_settle
    uint8_t restore = 0xFF;       // child_settle (log only)
    bool main_in_call = false;    // child_settle (log only)
    bool defer = false;           // observer_load_defer (an NPC entry held because user 2 is loading)
    bool family = false;          // observer_hold_family
    uint32_t parent = 0;          // observer_hold_family: the parent's key
    uint8_t family_why = 0;       // observer_hold_family: FamilyWhy
    bool no_entry = false;        // S35 publication_gate=1: withheld without an entry (its table had no room)
};
struct SplitPlan {
    std::vector<uint32_t> pass;  // to every recipient, in the original order
    std::vector<HoldGroup> groups;
    std::vector<HoldRecord> records;
};
// sessions[i] with users[i] (its validated user; 0 for a null session);
// verdicts[j] for keys[j]; host = the host's user (0 = not known: no observer
// is marked as the host's). A held key is only withheld when some non-null
// recipient is not its owner's session; otherwise it passes. The owner's own
// sessions always get it in this same call. False = nothing to withhold: call
// the original unchanged.
bool plan_split(std::span<const uintptr_t> sessions, std::span<const uintptr_t> users, uintptr_t host,
                std::span<const uint32_t> keys, std::span<const HoldVerdict> verdicts, SplitPlan& plan);

// The (child, observer) table: bounded, per guest epoch.
struct HoldEntry {
    uint32_t key = 0;
    uintptr_t observer = 0;
    uintptr_t observer_user = 0;
    uintptr_t owner = 0;
    OwnerWho owner_who = OwnerWho::None;
    bool observer_host = false;
    uint32_t epoch = 0;
    uint64_t since_ms = 0;
    uint8_t type = 0;
    bool timeout_noted = false;
    // observer_hold (NPC entries only)
    bool npc = false;
    uint32_t controller = 0;     // the controller's user key when held
    uintptr_t actor = 0;         // the actor when held (NPC and character entries; never followed)
    bool ctrl_change_noted = false;
    bool character = false;      // character_hold (its own table)
    bool settle = false;         // child_settle (its own table)
    uint32_t main_key = 0;       // child_settle: the owner's main character
    uint64_t deferred_since = 0; // child_settle: first time a due release had to wait for an allowed thread
    uint64_t not_before_ms = 0;  // child_settle, a re-announce the guest asked for: not released before (backoff)
    bool defer = false;          // observer_load_defer: held (or held again) because user 2 was loading
    bool family = false;         // observer_hold_family (its own table): released right behind its parent
    uint32_t parent = 0;         // observer_hold_family: the parent's key
    uint8_t family_why = 0;      // observer_hold_family: FamilyWhy
    bool npc_origin = false;     // observer_hold_family: an observer_hold entry moved here (ReleaseBlocked)
    bool u2_withheld_noted = false;  // observer_hold: withheld from the host past the timeout (user 2 controls it)
    uint64_t wait_since_ms = 0;  // observer_hold_family: when it began to wait for its parent
    // S35 publication_gate: its first refused release (0 = never refused), when it may be decided again, and why
    // (pubg::Verdict). Kept while the entry is retained; bounded by publication_retain_max_ms from unsafe_since_ms.
    uint64_t unsafe_since_ms = 0;
    uint64_t unsafe_retry_ms = 0;
    uint8_t unsafe_why = 0;
    // Set by the table on every add and refresh (unique per table): a pass
    // that decided on a copy only removes the entry if it is still this one.
    uint64_t stamp = 0;
};

// An entry user 2 is part of: its child's owner is not the host (user 2, or
// the fail-safe "other user"), or its observer is not the host's user (user 2
// is the only other one). A host-owned child observed by the host cannot be
// an entry (the owner's session always gets it), so with two users every
// entry is one.
bool hold_entry_of_user2(const HoldEntry& e);
// observer_hold: when user 2 leaves, the NPC entries it OBSERVES go. An NPC
// that user 2 controlled and the host observes stays: its control passes to
// the host (released then, "the observer is now its controller") or its first
// action arrives (restore 1); otherwise the timeout releases it (restore 0).
bool npc_entry_of_leaving_user2(const HoldEntry& e);

template <size_t N>
class HoldTableN {
public:
    enum class Add : uint8_t { Added, Duplicate, Full };
    Add add(const HoldEntry& e) {
        for (size_t i = 0; i < n_; ++i) {
            if (e_[i].key == e.key && e_[i].observer == e.observer) {
                // Held again (e.g. the host entered another sector of the child):
                // the latest users are kept. A child keeps its first moment and
                // epoch (D-53). An NPC is a fresh announcement withheld again:
                // its moment, epoch, actor and notes restart, so it does not time
                // out early nor count as "another actor behind the key".
                e_[i].observer_user = e.observer_user;
                e_[i].owner = e.owner;
                e_[i].owner_who = e.owner_who;
                e_[i].observer_host = e.observer_host;
                if (e.npc) {
                    e_[i].controller = e.controller;
                    e_[i].since_ms = e.since_ms;
                    e_[i].epoch = e.epoch;
                    e_[i].actor = e.actor;
                    e_[i].type = e.type;
                    e_[i].timeout_noted = false;
                    e_[i].ctrl_change_noted = false;
                    e_[i].defer = e_[i].defer || e.defer;
                } else if (e.family) {
                    // A member withheld again behind its (re-)held parent: its wait restarts with it.
                    e_[i].since_ms = e.since_ms;
                    e_[i].wait_since_ms = e.wait_since_ms;
                    e_[i].epoch = e.epoch;
                    e_[i].actor = e.actor;
                    e_[i].type = e.type;
                    e_[i].parent = e.parent;
                    e_[i].family_why = e.family_why;
                    e_[i].defer = e.defer;
                } else if ((e.character || e.settle) && e.actor != e_[i].actor) {
                    // A character keeps its first moment (its wait is bounded from the
                    // first hold), unless another actor is behind the key now (a new
                    // character after a despawn the passes have not seen): it restarts.
                    e_[i].since_ms = e.since_ms;
                    e_[i].epoch = e.epoch;
                    e_[i].actor = e.actor;
                    e_[i].type = e.type;
                    e_[i].timeout_noted = false;
                }
                e_[i].stamp = ++stamp_;
                return Add::Duplicate;
            }
        }
        if (n_ >= e_.size()) return Add::Full;
        e_[n_] = e;
        e_[n_].stamp = ++stamp_;
        ++n_;
        return Add::Added;
    }
    // The engine announced these keys to these sessions itself: their entries
    // go. Sorted keys are binary-searched (callers sort large lists first).
    size_t forget_announced(std::span<const uint32_t> keys, std::span<const uintptr_t> sessions) {
        const bool sorted = std::is_sorted(keys.begin(), keys.end());
        return drop_if([&](const HoldEntry& e) {
            const bool listed = sorted ? std::binary_search(keys.begin(), keys.end(), e.key)
                                       : std::find(keys.begin(), keys.end(), e.key) != keys.end();
            if (!listed) return false;
            for (const uintptr_t s : sessions) {
                if (s == e.observer) return true;
            }
            return false;
        });
    }
    // The index of the entry with this stamp (hint first), or size() when gone.
    size_t locate(uint64_t stamp, size_t hint) const {
        if (hint < n_ && e_[hint].stamp == stamp) return hint;
        for (size_t i = 0; i < n_; ++i) {
            if (e_[i].stamp == stamp) return i;
        }
        return n_;
    }
    // User 2 is gone or leaving: every entry it is part of goes (hold_entry_of_user2).
    size_t drop_user2_entries() { return drop_if([](const HoldEntry& e) { return hold_entry_of_user2(e); }); }
    template <class Pred>
    size_t drop_if(Pred pred) {
        size_t gone = 0;
        for (size_t i = 0; i < n_;) {
            if (pred(e_[i])) {
                remove_at(i);
                ++gone;
            } else {
                ++i;
            }
        }
        return gone;
    }
    void clear() { n_ = 0; }
    size_t size() const { return n_; }
    static constexpr size_t capacity() { return N; }
    size_t room() const { return N - n_; }
    // S35 publication_gate (review 6): the entry of (key, observer), or nullptr.
    HoldEntry* find(uint32_t key, uintptr_t observer) {
        for (size_t i = 0; i < n_; ++i) {
            if (e_[i].key == key && e_[i].observer == observer) return &e_[i];
        }
        return nullptr;
    }
    size_t older_than(uint64_t now_ms, uint64_t age_ms) const {
        size_t n = 0;
        for (size_t i = 0; i < n_; ++i) {
            if (now_ms - e_[i].since_ms >= age_ms) ++n;
        }
        return n;
    }
    HoldEntry& at(size_t i) { return e_[i]; }
    const HoldEntry& at(size_t i) const { return e_[i]; }
    void remove_at(size_t i) {  // the last entry takes its place
        if (i >= n_) return;
        e_[i] = e_[n_ - 1];
        --n_;
    }

private:
    std::array<HoldEntry, N> e_{};
    size_t n_ = 0;
    uint64_t stamp_ = 0;
};
using HoldTable = HoldTableN<hold::kTableCapacity>;
using NpcHoldTable = HoldTableN<hold::kNpcTableCapacity>;
using CharHoldTable = HoldTableN<hold::kCharTableCapacity>;
using SettleHoldTable = HoldTableN<hold::kSettleTableCapacity>;
using FamilyHoldTable = HoldTableN<hold::kFamilyTableCapacity>;

// observer_hold_family: the parent key a server actor's hierarchy component names (SEH reads). 0 = no parent:
// no hierarchy component ([comps+0x1B8] null), no parent key, or not an 0xB key other than the actor's own.
// nullopt = "unlinked": unreadable, or the component's own actor (+8) is not this actor.
std::optional<uint32_t> piece_parent_key(uintptr_t actor);
// S33: lectura SEH del padre serializado (+AC; jerarquía como respaldo).
std::optional<uint32_t> child_hold_actor_parent(uintptr_t actor) noexcept;
// Configurar antes de los hooks; sólo npc_activation=1 habilita la barrera.
void child_hold_set_retirement(bool on) noexcept;
// npc_activation o npc_family_control distintos de 0: prepare_family lee también el padre de las claves retenidas
// para las sondas. Con ambos a 0 se salta esa lectura, como en c7ae132.
void child_hold_set_npc_family_observe(bool on) noexcept;
// No llama Logout ni modifica autoridad. Cancela la familia completa antes
// de que el llamador retire actores. false: no realizar esa retirada.
// from_publication: el llamador está dentro de una publicación de su hilo (su scope no cuenta).
bool child_hold_retire_family(uint32_t epoch, uint64_t generation,
                              std::span<const uint32_t> keys, bool from_publication = false) noexcept;
void child_hold_actor_created(uint32_t epoch, uint64_t generation, uint32_t key) noexcept;
// Mid hook 0x2792A7B (S33 review): only notes the rebirth of a retired key (no queue work, no CRT copy there);
// child_hold_settle_births does child_hold_actor_created for them, first thing in every publication path
// (NotifyAppear, the mod's own calls, take_frame) before any retired-key filter.
void child_hold_actor_born(uint32_t epoch, uint64_t generation, uint32_t key) noexcept;
void child_hold_settle_births() noexcept;
bool child_hold_retired(uint32_t key) noexcept;
// S38 fase C (revisión §4.1): las entradas de observer_hold_family de esta época cuyo padre está en `parents` y cuya
// clave no: los hijos por los que child_hold_retire_family se negaría. Sólo lectura, try-lock de g_mu (nunca espera):
// -1 = ocupado (inténtese otra vez); si no, cuántos (como mucho `cap` en keys/parents).
int child_hold_held_children(uint32_t epoch, std::span<const uint32_t> parents, uint32_t* keys, uint32_t* parent_of,
                             size_t cap) noexcept;


// User 2's entries go when user 2 is gone OR leaving (its 2001 was handed to
// the server): after a logout the user may still read as valid (D-53 live:
// "still held 1, user 2 gone 0"), and nothing of a departing user is published
// nor published to it.
bool hold_drop_user2(bool user2_present, bool logout_handed);

// What a release decision reads.
struct ReleaseReadings {
    uint32_t epoch_now = 0;
    std::optional<uintptr_t> actor;  // nullopt = unreadable, 0 = gone
    std::optional<uintptr_t> owner;
    std::optional<uint8_t> restore;
    bool observer_valid = false;     // the observer session still has a valid user...
    uintptr_t observer_user = 0;     // ...and this is it
    std::optional<bool> observes;    // that user is among the child's sector's observers
};
// The child, read again BY KEY (never through a kept pointer).
ReleaseReadings read_child_release(uintptr_t sam, uint32_t key, uintptr_t observer_user);
enum class ReleaseStep : uint8_t { Keep, Drop, Release };
ReleaseStep release_step(const HoldEntry& e, const ReleaseReadings& r, const char*& why);

// observer_hold: what an NPC entry's release decision reads (by key again).
struct NpcReleaseReadings {
    uint32_t epoch_now = 0;
    std::optional<uintptr_t> actor;  // nullopt = unreadable, 0 = gone
    std::optional<uintptr_t> owner;  // [actor+0xA0]
    std::optional<uint32_t> controller;
    std::optional<uint8_t> restore;
    bool observer_valid = false;
    uintptr_t observer_user = 0;
    uint32_t observer_key = 0;       // that user's key
    std::optional<bool> observes;
    // observer_load_defer=1 and user 2 is loading now (its move phase): an entry observed by user 2 (not by the
    // host) is kept until its 2762, at most hold::kLoadDeferMaxMs after it was held (set by the pass). Meanwhile
    // only another epoch, a despawn or the observer gone drop it; out of range / unreadable wait for the 2762.
    bool load_wait = false;
    // The age the restore-0 timeout uses (review L2): for an entry held through user 2's load, the time since
    // that load ended (set by the pass); otherwise the entry's age.
    uint64_t timeout_age_ms = UINT64_MAX;
    // P8 U-e (u0-resultados-s28.md §8.17, the 6c12c82 crash): user 2's user key (0 = unknown). An NPC user 2 controls
    // is never released to the HOST's session with restore 0 by the timeout: the host's client would build it with no
    // current action, and an attached piece reads that null action (exe+0x1831598, p8-crash-esc-1831598.md).
    uint32_t user2_key = 0;
};
// By key again, with SEH reads (game::fast_read, no VirtualQuery).
NpcReleaseReadings read_npc_release(uintptr_t sam, uint32_t key, uintptr_t observer_user);
// Why an NPC entry is released.
enum class NpcRelease : uint8_t {
    None,
    Restore1,   // its first action was accepted
    ByControl,  // the observer is now its controller
    Timeout,    // still restore 0 after hold::kNpcTimeoutMs: as the engine would
    Native,     // would have been dropped while still in the observer's range: announced natively instead
    WithheldUser2,  // Keep: past the timeout, to the host's session, user 2 controls it and it is still restore 0
};
const char* npc_release_name(NpcRelease k);
// Drop: another epoch, despawned, observer gone / out of range (the engine
// announces it again when it comes back in range), or (child_hold on) a
// user's child still at restore 0 after 3 x hold::kNpcTimeoutMs.
// Release: restore 1, the observer is now the controller, the timeout (restore
// 0), or Native: another actor behind the key, owned by a user while
// child_hold is off, or unreadable for 3 x the timeout, each only while the
// actor exists and the observer still observes it (else Keep / Drop). Keep:
// anything unreadable, restore 0 before the timeout (also after the
// controller changed to another user), a user's child at restore 0 while
// child_hold is on (D-53: never announced with 0). A release with restore 0 to
// the HOST's client (an NPC user 2 controls) is what the engine does without
// observer_hold: the host's Update containment (D-52, horse_diag) covers it.
// children_rule = child_hold's "never with restore 0" for users' children.
ReleaseStep npc_release_step(const HoldEntry& e, const NpcReleaseReadings& r, uint64_t age_ms, const char*& why,
                             NpcRelease* kind = nullptr, bool children_rule = true);

// observer_hold_family: what the periodic pass reads for a family entry (by key again, SEH reads).
struct FamilyReadings {
    uint32_t epoch_now = 0;
    std::optional<uintptr_t> actor;  // nullopt = unreadable, 0 = gone
    bool observer_valid = false;
    uintptr_t observer_user = 0;
    std::optional<bool> observes;    // the observer is among the member's sector's observers (nullopt: unknown)
    bool parent_held = false;        // its parent still has an entry withheld from this observer (any table)
    bool tracks = false;             // the observer is user 2's session: "announced" is known for it
    bool parent_known = false;       // (tracks) its parent has been announced to it (and not removed since)
};
enum class FamilyRelease : uint8_t {
    None,
    WithParent,     // in its parent's release NotifyAppear, behind it
    AfterParent,    // its parent was announced to that session (by the engine or a release): right after it
    Orphan,         // (the host's session) its parent's entry went without it: natively now
    OrphanTimeout,  // its parent never reached user 2 within hold::kFamilyOrphanMs: natively (an orphan)
    MaxAge,         // still withheld with its parent after hold::kFamilyMaxHoldMs: natively
};
const char* family_release_name(FamilyRelease k);
// The periodic decision for a family entry (its parent's release / drop take it along elsewhere). age_ms: since
// it was withheld; wait_ms: since it began to wait for its parent. Drop: another epoch, despawned, observer
// gone, out of the observer's range (known), or unreadable for hold::kFamilyMaxHoldMs. Keep: its parent still
// withheld there (before the max age), waiting for its parent's announcement (before kFamilyOrphanMs), or
// unreadable. Release: AfterParent / Orphan / OrphanTimeout / MaxAge.
ReleaseStep family_release_step(const HoldEntry& e, const FamilyReadings& r, uint64_t age_ms, uint64_t wait_ms,
                                const char*& why, FamilyRelease* kind = nullptr);

// observer_hold_family + the orphan count, from take_frame: a packet really queued for user 2's live session 2
// (after observer_hold_acks' routing and the push; never one it kept or one that could not be queued). 2005: its
// records are announced to user 2 now (an orphan among them is counted); 2516: those keys are no longer with it;
// 2174 (MoveFieldAck, a field change): it has nothing any more. Any thread; nothing of the game is called.
void child_hold_on_user2_out(uint16_t opcode, std::span<const uint8_t> payload) noexcept;

// character_hold: what a character entry's release decision reads (by key again, SEH reads).
struct CharReleaseReadings {
    uint32_t epoch_now = 0;
    std::optional<uintptr_t> actor;  // nullopt = unreadable, 0 = gone
    std::optional<uintptr_t> owner;  // [actor+0xA0]
    std::optional<uint8_t> restore;
    bool observer_valid = false;
    uintptr_t observer_user = 0;
    std::optional<bool> observes;
};
CharReleaseReadings read_char_release(uintptr_t sam, uint32_t key, uintptr_t observer_user);
enum class CharRelease : uint8_t {
    None,
    Restore1,  // its first action was accepted
    Timeout,   // still restore 0 after hold::kCharTimeoutMs: announced as the engine would (restore 0)
    Native,    // would have been dropped while still in the observer's range: announced natively instead
};
const char* char_release_name(CharRelease k);
// Drop (only when the observer cannot see it now): another epoch, despawned (logout), observer gone,
// observer out of range (field change: the engine announces it again when it comes back), or stale
// (unreadable for 3 x hold::kCharTimeoutMs) without knowing it is in range. Release: restore 1; the
// timeout (restore 0); or Native: another actor behind the key, another owner, unreadable for too long,
// each only while the observer is known to observe it. Keep: restore 0 before the timeout, or anything
// unreadable.
ReleaseStep char_release_step(const HoldEntry& e, const CharReleaseReadings& r, uint64_t age_ms, const char*& why,
                              CharRelease* kind = nullptr);

// child_settle: is `key` a user's child that settles (0xB, owner a validated user as for D-53, type
// 4/5/6, any restore byte), and its owner's main character ([owner+0xD0] with key class 0xA)? SEH reads.
struct SettleCandidate {
    bool ok = false;
    uintptr_t actor = 0, owner = 0;
    OwnerWho owner_who = OwnerWho::None;
    uint8_t type = 0;
    uint32_t main_key = 0;
    uintptr_t main_actor = 0;  // compared / read by SEH only, never kept
};
SettleCandidate settle_candidate(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                                 uintptr_t user_vtable);
// P8 session 9 (child_reannounce, reannounce_logic.h): the guest's client failed to create the HOST's child
// `key`; it goes into child_settle's table for the live session 2, released by the usual native
// NotifyAppear([session 2], [key]) on child_settle's threads, not before delay_ms from now. The mod's network
// thread (SEH reads, g_mu taken briefly). Only a settle candidate (child_settle's rule) owned by the host.
enum class Reannounce : uint8_t {
    Queued,        // in the table; released after the delay
    AlreadyHeld,   // an entry for (key, session 2) is there already
    NotActive,     // child_settle is off (child_settle_ms=0 or its hooks are not in)
    NoUser2,       // no live session 2 / user 2
    Unreadable,    // the actor manager could not be read
    NotCandidate,  // not a user's child of type 4/5/6 with a known main character
    NotHosts,      // a child of user 2 (its own client creates it)
    Full,          // no room in the table
};
const char* reannounce_name(Reannounce r);
// dry_run: only the checks (a candidate of the host answers Queued), nothing is recorded (probe).
Reannounce child_settle_reannounce(uint32_t key, uint32_t delay_ms, bool dry_run = false);

// The owner of a server actor by key ([actor+0xA0], SEH reads; nullopt = not found or unreadable).
// attach_follow's filter (only users' children follow a parent).
std::optional<uintptr_t> hold_actor_owner(uint32_t key);
// Is the child `key` withheld from `observer` now (D-53 or child_settle; observer 0 = from anyone)? A
// try-lock of g_mu: busy counts as withheld (true). Never under g_mu. attach_follow's Makes.
bool child_hold_withheld(uint32_t key, uintptr_t observer) noexcept;

// The actor key of a StartActionReq from vf2's packet wrapper (hold::kReq*;
// SEH reads; nullopt = unreadable or the sizes do not agree, as vf2 checks).
std::optional<uint32_t> start_action_req_key(uintptr_t ctx);

// Install both hooks (NotifyAppear, StartActionReq::vf2) after checking their
// code; false = none (option D goes on without holding).
// children = D-53 (child_hold), observers = S3's observer_hold. The one-argument
// form is child_hold alone, exactly as before.
bool child_hold_install();
bool child_hold_install(bool children, bool observers);
// characters = character_hold ([session2] character_hold, default 0).
bool child_hold_install(bool children, bool observers, bool characters);
bool child_settle_active();
// [session2] notify_thread_rule (default 0 = as before the rule): set before the install.
void child_hold_set_thread_rule(bool on);
// [session2] child_settle_ms (default 0 = off): set before the install (it alone also installs the hooks).
void child_hold_set_settle_ms(uint32_t ms);
// [session2] observer_load_defer (P8 session 14, pendientes/p8-impl-spawn-action.md), HOST, needs observer_hold:
// 0 (default) off | 1 probe (counted and logged, nothing held) | 2 on (u2f::Mode). With it on, an NPC the host
// controls whose NotifyAppear reaches user 2 while user 2 is loading (move phase between its 3093/2437 and the
// 2762 the server wrote for it) is withheld from user 2 even with restore 1, and announced to it natively right
// after its 2762 (at most hold::kLoadDeferMaxMs later); observer_hold's own holds wait for the 2762 too.
void child_hold_set_load_defer(uint8_t mode);
uint8_t child_hold_load_defer();
// [session2] observer_hold_family (pendientes/p8-s14-viajeros.md §7; the old key observer_hold_pieces is its
// alias), HOST, needs observer_hold: 0 (default) off | 1 probe (counts and logs the members that would go out
// before their parent; nothing changes) | 2 on (u2f::Mode): see the header comment.
void child_hold_set_family(uint8_t mode);
uint8_t child_hold_family();
// [session2] publication_gate (S35 fase A, docs/research/s25/s35-fase-a.md; AUDITORIA.md §1 "Cambios obligatorios"),
// HOST, needs observer_hold: 0 (default) off, as before | 1 probe (every publication exit is evaluated and counted /
// logged as WOULD retain; nothing changes) | 2 on (u2f::Mode). With it on no exit of observer_hold /
// observer_hold_family publishes to an observer that does not control it an actor whose state is not proven
// complete (publication_gate_logic.h pubg::admit): restore 0, CC unreadable (unknown, not "proven absent"), actor or
// controller unreadable, or a dependency (its parent) withheld, retained or itself incomplete. Covers the releases
// (Timeout, Native, family MaxAge/Orphan/OrphanTimeout/AfterParent/WithParent, "no room: released anyway") and the
// native exits of a full table (withheld without an entry instead of announced). A retained entry stays in its
// table at most retain_max_ms from its first refusal; then it is dropped WITHOUT being published (the actor stays
// invisible to that observer until the engine announces it again), with a line and counters.
void child_hold_set_publication_gate(uint8_t mode, uint32_t retain_max_ms);
uint8_t child_hold_publication_gate();
// server.cpp, whenever user 2's move phase changes (lock-free; any thread): loading = move_phase_loading(phase).
void child_hold_note_user2_loading(bool loading) noexcept;
// S35 (user2_stages' containment, npc_containment_guard): user 2 is inside a load now (2549 .. 2762), a load older
// than hold::kLoadDeferMaxMs taken as finished. Lock-free, no side effects (no line, no counter).
bool child_hold_user2_loading() noexcept;
uint32_t child_hold_settle_ms();
bool child_hold_thread_rule();
bool child_hold_active();
bool observer_hold_active();
bool character_hold_active();
std::string child_hold_describe();
// ServerRunThread, from the OnRecvPacket mid-hook: the children's fallback
// release (at most every 50 ms, only on a native NotifyAppear thread, so in
// practice refused there) and the NPC and character tables' fallback passes
// (drops only; at most every hold::kNpcFallbackMs). Nothing at all while the
// tables are empty.
void child_hold_server_tick() noexcept;
// From the mod's network thread: formats the queued log lines and drops user
// 2's entries once it is gone or leaving.
void child_hold_network_tick() noexcept;

// Tests only (tests/optd_s3_tests.cpp): what the game provides, replaced.
// Never used by the mod (the seams pointer stays null there).
namespace hold_test {
struct Seams {
    void (*notify)(uintptr_t flag, const GameVec* sessions, const GameVec* keys) = nullptr;  // native NotifyAppear
    uintptr_t sam = 0;   // the ServerActorManager
    uintptr_t base = 0;  // the image base (ServerUserActor's vtable)
    bool realm = true;   // the calling thread runs in the server's realm
    uint64_t (*now_ms)() = nullptr;
    // The calling thread's id (nullptr: GetCurrentThreadId). With the seams every
    // notify() counts as a native NotifyAppear call of that thread.
    uint32_t (*thread_id)() = nullptr;
};
// Installs the seams (nullptr: the game again), empties the tables, the
// reservation, the native threads and every counter, and marks the hold active
// with these rules (no hook is created).
void reset(const Seams* seams, bool children, bool observers);
void reset(const Seams* seams, bool children, bool observers, bool characters);
void notify(uintptr_t flag, const GameVec* sessions, const GameVec* keys);  // notify_detour
// start_action_detour around a Req whose packet wrapper is `ctx` (0: none).
void start_action(uintptr_t ctx);
void server_tick();   // child_hold_server_tick without its thread check
void network_tick();  // child_hold_network_tick, the lines into `lines`
size_t npc_size();          // under the lock
size_t npc_size_atomic();   // the lock-free copy the hooks read
size_t npc_reserved();
bool npc_entry(size_t i, HoldEntry& out);
void fill_npc(size_t n);    // n entries whose keys resolve to nothing
struct Counters {
    uint64_t held = 0, again = 0, full = 0, unrecorded = 0, released = 0, by_control = 0, timeouts = 0,
             native = 0, dropped = 0, deferred = 0, targeted = 0, periodic = 0, evaluated = 0;
};
Counters counters();
std::string lines();  // what network_tick formatted since the last call
// observer_load_defer (reset() puts both back to off / not loading).
void set_load_defer(uint8_t mode, bool user2_loading);
struct LoadDeferCounters {
    uint64_t deferred = 0, would = 0, released = 0, released_at_cap = 0, dropped = 0, waited_max_ms = 0;
    uint64_t dropped_despawned = 0, dropped_gone = 0, dropped_other = 0;  // dropped, by reason
    uint64_t stuck = 0;  // loads taken as finished at hold::kLoadDeferMaxMs (review M1)
};
LoadDeferCounters load_defer_counters();
// observer_hold_family (reset() puts it back to off and empties the announced set and the orphan count).
void set_family(uint8_t mode);
size_t family_size();
bool family_entry(size_t i, HoldEntry& out);
void fill_family(size_t n);  // n family entries whose keys resolve to nothing
bool family_known(uint32_t key);  // in user 2's announced set now
struct FamilyCounters {
    uint64_t seen = 0, would = 0, held = 0, again = 0, full = 0, partial = 0, unlinked = 0, released = 0,
             with_parent = 0, after_parent = 0, orphans = 0, orphan_timeouts = 0, max_age = 0, dropped = 0,
             cleared = 0, forgotten = 0, unrecorded = 0, deferred = 0, converted = 0, blocked_native = 0,
             would_block = 0, held_unknown = 0;
    bool unknown_off = false;  // the safety valve tripped
    uint64_t ac_same = 0, ac_other = 0, ac_only = 0;  // the source probe
    uint64_t out_records = 0, out_orphans = 0;  // take_frame: records queued for user 2, orphans among them
};
FamilyCounters family_counters();
// character_hold and the thread rule.
size_t char_size();
bool char_entry(size_t i, HoldEntry& out);
void fill_char(size_t n);  // n character entries whose keys resolve to nothing
size_t child_size();
struct CharCounters {
    uint64_t held = 0, again = 0, full = 0, released = 0, restore1 = 0, timeouts = 0, native = 0, dropped = 0,
             cleared = 0, forgotten = 0, deferred = 0, not_main = 0;
    uint64_t child_released = 0, child_deferred = 0, npc_deferred = 0, native_threads = 0;
};
CharCounters char_counters();
// notify_thread_rule for the tests (reset() puts it back to 0, the default).
void set_thread_rule(bool on);
uint64_t defer_max_ms();
// child_settle (reset() puts it back to 0).
void set_settle_ms(uint32_t ms);
size_t settle_size();
bool settle_entry(size_t i, HoldEntry& out);
struct SettleCounters {
    uint64_t held = 0, again = 0, full = 0, released = 0, settled = 0, max_wait = 0, native = 0, dropped = 0,
             cleared = 0, forgotten = 0, deferred = 0, d53_waited = 0, announced = 0, raced = 0, fallback = 0;
};
// Records a settle entry directly (a split racing a release, in the tests' fake NotifyAppear).
void add_settle_entry(const HoldEntry& e);
SettleCounters settle_counters();
// S35 publication_gate (reset() puts it back to off, retain 60 s, and zeroes these).
struct PubCounters {
    uint64_t evaluated = 0, published = 0, gone = 0, would = 0, retained = 0, dropped_expired = 0,
             dropped_no_room = 0, withheld_no_entry = 0, would_no_entry = 0, cc_unknown_held = 0,
             cc_unknown_would = 0;
    uint64_t merged = 0, members_dragged = 0, unchecked = 0, shadow_recorded = 0, shadow_recovered = 0,
             shadow_would_drop = 0, shadow_pending = 0, retain_max_ms = 0;
    uint64_t by_verdict[8] = {};  // pubg::Verdict
};
PubCounters pub_counters();
}  // namespace hold_test

}  // namespace cdmp::session2
