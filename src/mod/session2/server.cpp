#include "mod/session2/server.h"
#include "common/native_opcode.h"
#include "mod/game/build_profile.h"

#include <windows.h>

#include <intrin.h>
#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <cstddef>
#include <mutex>
#include <span>
#include <vector>

#include "common/clock.h"
#include "common/troc_frame.h"
#include "mod/game/game_fault.h"
#include "mod/game/rtti.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/net/horse_diag.h"
#include "mod/net/remote_puppet.h"
#include "mod/session2/attach_follow.h"
#include "mod/session2/focus_follow.h"
#include "mod/session2/combat_follow.h"
#include "mod/session2/docked_gimmicks.h"
#include "mod/session2/door_trace.h"
#include "mod/session2/scene_level_share.h"
#include "mod/session2/child_hold.h"
#include "mod/session2/clock_push.h"
#include "mod/session2/clock_push_logic.h"
#include "mod/session2/field_share.h"
#include "mod/session2/guest_lifecycle.h"
#include "mod/session2/guest_save_host.h"
#include "mod/session2/guest_save_tunnel.h"
#include "mod/session2/horse_follow.h"
#include "mod/session2/vehicle_follow.h"
#include "mod/session2/host_scene_diag.h"
#include "mod/session2/shop_probe.h"
#include "mod/session2/shop_trade_probe.h"
#include "mod/session2/observer_hold_scene_order.h"
#include "mod/session2/identity_fix.h"
#include "mod/session2/observer_hold_acks.h"
#include "mod/session2/observer_milestone.h"
#include "mod/session2/observer_scene_copy.h"
#include "mod/session2/observer_seq_copy.h"
#include "mod/session2/housing_share.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/profile_s2.h"
#include "mod/session2/owner_fanout.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/travel_probe.h"
#include "mod/session2/travel_probe_logic.h"
#include "mod/session2/user2_shops.h"
#include "mod/session2/user2_stages.h"
#include "mod/session2/world_anchor.h"

namespace cdmp::session2 {
namespace {

inline uintptr_t addr(uintptr_t legacy_rva) noexcept { return profile::rva(legacy_rva); }

using AllocFn = void*(__fastcall*)(size_t size, size_t align);
using CtorFn = void*(__fastcall*)(void* self, uint8_t flag);
using PushFn = void(__fastcall*)(void* queue, void** item);
using FinderVf1 = uintptr_t(__fastcall*)(void* finder, void* out);

// Ours in the packet buffers we hand to the server (D0 §4: the server never
// reads +0x8010 or +0x8018 of a packet): the magic at +0x8018 marks them, the
// tag at +0x8010 carries the guest epoch (pb_tag, guest_lifecycle.h; C4).
constexpr uint64_t kMagic = 0x32534553'44504F43ull;  // "COPDSES2"
// *(session+0x88): the deferred-queue key while the session has no user. It
// MUST be 0, as for session 1 (the ctor writes 0; the probe reads 0 live).
// 0x2774076..87 takes it as the key and 0x143A580 sends key 0 to the common
// FIFO, but indexes table 0 with any other key, without a bounds check
// (0x143A5CA..D8), and the table has 1 entry: with 2 the server read past it,
// dropped our 2319 without a word and never sent the Ack 2840 (B2,
// docs/research/data/b2-ack2840.md).
constexpr uint32_t kSessionId = 0;
constexpr size_t kMaxOutgoingBytes = 32u << 20;      // a login burst is ~42,000 Acks

uintptr_t g_base = 0;
ServerOptions g_opt;
// The game's allocators (offsets_s2.h, p8-heap-inyeccion.md): only ever called
// on a game thread, chosen exactly as the game's own call sites choose.
AllocFn g_alloc_global = nullptr;  // 0x47EFA78, only if the thread's TLS+0x1FD says so (never seen)
AllocFn g_alloc_thread = nullptr;  // 0x47EF9B0, the calling thread's own heap
CtorFn g_ctor = nullptr;
PushFn g_push = nullptr;
FinderVf1 g_to_near = nullptr;

SafetyHookMid g_recv_hook;
// P2 (inject_logic.h): the host's own client NetworkThread, every turn (<= 16 ms).
SafetyHookMid g_pump_hook;
void on_client_pump(safetyhook::Context& ctx);
SafetyHookInline g_control_hook, g_self_hook;

// Session 2 and its private vtable (COL + 15 entries). Session 2 belongs to
// the server instance it was built in (ServerNet and its session 1): if the
// game replaces them (back to the title, another save), its user is gone and
// the hook builds a new one (review finding 2).
std::atomic<uintptr_t> g_session2{0};
// The server instance session 2 was built in. ServerNet and session 1 may come
// back at the same addresses after a restart (the allocator reuses blocks),
// so the thread is part of it: a new server runs a new ServerRunThread.
std::atomic<uintptr_t> g_built_net{0}, g_built_s1{0};
std::atomic<uint32_t> g_built_tid{0};
std::atomic<uint32_t> g_rebuilt{0};
std::atomic<bool> g_want_session{false};
std::atomic<bool> g_create_failed{false};
uintptr_t* g_vtable = nullptr;

// C4 (reconnect, guest_lifecycle.h): one session 2 per guest epoch. Each one
// stays alive for good (never freed: the native Close leaves the object in
// use, salida.md §2.4/§4.2); a packet buffer goes to the session of the epoch
// it was tagged with, never to a newer one. Index = epoch (0 unused).
constexpr size_t kEpochSlots = kMaxGuestEpochs + 1;
std::atomic<uintptr_t> g_epoch_session[kEpochSlots]{};
std::atomic<uint32_t> g_want_epoch{1};     // network thread: the epoch whose session 2 should exist
std::atomic<uint32_t> g_session_epoch{0};  // server thread: the epoch g_session2 was built for
std::atomic<uint64_t> g_pb_pushed[kEpochSlots]{}, g_pb_seen[kEpochSlots]{}, g_logout_count[kEpochSlots]{};
std::atomic<uint64_t> g_stale_routed{0}, g_untagged_routed{0}, g_late_out{0};

// Opcode -> channel of the server Req handlers (kind 4); 0xFF = not a Req,
// 0xFE = a Req the tunnel never feeds (saving, cheats, dev tools).
constexpr uint8_t kNotReq = 0xFF, kBlocked = 0xFE;
std::array<uint8_t, 0x10000> g_channel;
// The real channel of each blocked Req (kNotReq if none): P8 S25 phase B lets SaveAutoReq 3037 and
// SaveToFileCurrentPlayerReq 2910 through in own-save mode only (guest_save_req_policy).
std::array<uint8_t, 0x10000> g_blocked_channel;

troc::PacketQueue g_outgoing(kMaxOutgoingBytes);
// The save slot the host's own client loaded (its LoginCharacterToFieldServerReq):
// the E3 script loads the same one for user 2. -1 = not seen yet.
std::atomic<int64_t> g_host_slot{-1};
constexpr uint16_t kOpLoginCharacterToFieldServerReq = 3093;
constexpr uint16_t kOpLoginUserToFieldServerReq = 2490;

// E4 mirror. Opcodes of build 2976 (checked against the handler table at install).
constexpr uint16_t kOpMoveActorReq = 2556, kOpStartActionReq = 2223, kOpRotateActorReq = 2828;
constexpr uint16_t kOpMainPlayerDataStartAck = 2756;
constexpr uint16_t kOpMainUserDataStartAck = 2646;  // u32 user key at +0
constexpr uint16_t kOpMoveFieldAck = 2174;          // u8 | u32 actor | u32 | u32 field owner @9 | 0x30 * n
std::atomic<uint32_t> g_user2_userkey{0};           // from user 2's MainUserDataStartAck
std::atomic<uint32_t> g_host_userkey{0};            // the host's user key, read once (session 1's user +0x60)
std::atomic<uint64_t> g_owner_rewrites{0}, g_owner_unexpected{0};
// The same for LoadingFieldDataAck 2643 (travel_probe_logic.h): rewritten, unknown layout / key, other (alias off,
// not a user key, already user 2).
std::atomic<uint64_t> g_load_owner_rewrites{0}, g_load_owner_unexpected{0}, g_load_owner_other{0};
// P8 diagnostics: packets for user 2 that carry the host's user key, by opcode
// (a real client may look such a user up and not find it, p8-cierre-campo.md R1).
std::array<std::atomic<uint32_t>, 4096> g_hostkey_ops{};
// User 2's character key, from the MainPlayerDataStartAck the server sends to session 2.
std::atomic<uint32_t> g_user2_player{0};
struct Mirrored {
    uint64_t due_ms;
    std::vector<uint8_t> packet;
    uint32_t epoch;  // C4: never handed to another epoch's session (review of f15596e, 1)
};
std::mutex g_mirror_mu;
std::deque<Mirrored> g_mirror;  // under g_mirror_mu
constexpr size_t kMaxMirrored = 4096;
std::atomic<uint64_t> g_mirror_copied{0}, g_mirror_dropped{0};
DWORD WINAPI mirror_thread(LPVOID);
std::atomic<bool> g_outgoing_lost{false};
// C4, per session 2 (reset when a new one is built): asked for / handed.
std::atomic<bool> g_logout_asked{false};
std::atomic<uintptr_t> g_logout_handed{0};     // the session 2 the 2001 went to (0 = not yet)
std::atomic<uint64_t> g_logout_asked_ms{0};
std::string g_logout_why;                       // network thread only
constexpr uint64_t kLogoutPendingMs = 60000;    // give up handing it after this
// P8 S25 phase B (§3.6, gsw::FinalSave): a lost link with user 2's own save active gets one 2910 (final save) before
// its 2001 (network thread only; reset with each session 2).
gsw::FinalSave g_final;
bool g_final_logged = false;
// salida-en-carga.md §4: user 2's login/move phase in this epoch (C->S Req in
// server_inject, S->C Acks in take_frame: two threads, hence the lock), and
// the closing of an open move before the 2001 (network thread only, for the
// session 2 it was started for).
std::mutex g_phase_mu;
MovePhaseTracker g_phase;  // under g_phase_mu
MoveCloseSequence g_close;
uintptr_t g_close_session = 0;
constexpr uint16_t kOpNak = 1013;
constexpr uint16_t kOpRemoveActorAck2516 = 2516;  // RemoveActorAck (world_anchor's probe)
std::atomic<uint64_t> g_nak{0}, g_nak_after_logout{0};  // Nak 1013 written to session 2 (this epoch)

MovePhaseTracker phase_snapshot() {
    std::lock_guard lock(g_phase_mu);
    return g_phase;
}
void phase_reset() {
    std::lock_guard lock(g_phase_mu);
    g_phase.reset();
    child_hold_note_user2_loading(move_phase_loading(g_phase.phase()));  // observer_load_defer (P8 S14)
}

// ---------------------------------------------------------------- P2: the queue to the NetworkThread

// Filled by the network thread (and the E4 mirror thread), emptied in order by
// the NetworkThread hook. Nothing of the game is called under g_q_mu.
std::mutex g_q_mu;
inj::InjectQueue g_q;                       // under g_q_mu
std::atomic<size_t> g_q_size{0};            // g_q.size(), read without the lock
std::atomic<size_t> g_in_hand{0};           // popped by the NetworkThread, not pushed (or dropped) yet
std::atomic<uint64_t> g_pb_queued[kEpochSlots]{};
// An exception inside the game's code (alloc, buffer, Q0 push, session build):
// the epoch it happened in; 0 = none. Never reset (C4 quarantines after it).
std::atomic<uint32_t> g_halted_epoch{0};
constexpr uint32_t kMaxExceptionNotes = 8;
inj::ExceptionNote g_exc[kMaxExceptionNotes];  // written once each, by the thread that caught it
std::atomic<bool> g_exc_ready[kMaxExceptionNotes]{};
std::atomic<uint32_t> g_exc_count{0};
uint32_t g_exc_logged = 0;  // network thread only
std::string g_halt_reason;  // network thread only
// The pump (NetworkThread) and what it measures.
std::atomic<uint64_t> g_pump_turns{0}, g_pump_handed{0}, g_pump_stale{0}, g_pump_other_net{0}, g_pump_not_ready{0},
    g_pump_wait_sum{0}, g_pump_wait_max{0}, g_pump_batch_max{0}, g_pump_inflight_max{0}, g_global_heap_flag{0}, g_q_cleared{0};
std::atomic<uint32_t> g_pump_tid{0};
std::atomic<uint64_t> g_pump_last_ms{0};
std::atomic<uint64_t> g_held_not_ready{0}, g_held_full{0};
// Network thread only: the 2001's pacing and the stall watches.
inj::RetryPacer g_logout_pacer;
bool g_logout_halt_logged = false;
inj::StallWatch g_server_watch{1000, 5000}, g_pump_watch{1000, 5000};
uint64_t g_full_logged_at = 0, g_full_logged_count = 0;

uint64_t now_ms() { return GetTickCount64(); }

void atomic_max(std::atomic<uint64_t>& a, uint64_t v) {
    uint64_t cur = a.load(std::memory_order_relaxed);
    while (v > cur && !a.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
    }
}

// SEH filter (no allocation): one note per exception in a step of the
// injection or of session 2's build. P8 review I1 (p8-revision-noche.md): only
// the mod's own steps are handled (inj::step_is_ours; the caller stops the
// injection); inside the game's code that may hold a lock (Q0's push, the
// global heap, the NwSession constructor) the injection is stopped here, one
// line goes straight to the log and the exception is passed on: a real crash
// where it happened, never a server thread left running with a lock taken.
int note_exception(EXCEPTION_POINTERS* ep, inj::Step step, uint16_t opcode, uint32_t epoch) {
    const uint32_t i = g_exc_count.fetch_add(1);
    // Inside the game's code: if anything up the stack handles it, nothing more from us either.
    if (!inj::step_is_ours(step)) g_halted_epoch.store(epoch ? epoch : 1);
    if (i < kMaxExceptionNotes && ep && ep->ExceptionRecord) {
        const EXCEPTION_RECORD* r = ep->ExceptionRecord;
        inj::ExceptionNote& n = g_exc[i];
        n.code = r->ExceptionCode;
        n.address = reinterpret_cast<uint64_t>(r->ExceptionAddress);
        n.in_exe = n.address >= g_base && n.address < g_base + 0x20000000;
        n.rva = n.in_exe ? n.address - g_base : 0;
        n.nparams = r->NumberParameters;
        n.params[0] = r->NumberParameters > 0 ? r->ExceptionInformation[0] : 0;
        n.params[1] = r->NumberParameters > 1 ? r->ExceptionInformation[1] : 0;
        n.thread = GetCurrentThreadId();
        n.step = step;
        n.opcode = opcode;
        n.epoch = epoch;
        n.when_ms = GetTickCount64();
        g_exc_ready[i].store(true, std::memory_order_release);
    }
    if (inj::step_is_ours(step)) return EXCEPTION_EXECUTE_HANDLER;
    game::FixedLine where;
    where.str(inj::step_name(step)).str(" (Req ").dec(opcode).str(", epoch ").dec(epoch).str(")");
    return game::game_fault_continue(ep, "Session2 injection", where.view().data());
}

// The game's own allocator choice (e.g. PostPacket 0x35C692..0x35C6BA), on the
// calling GAME thread: TLS+0x1FD != 0 -> the locked global heap, else the
// thread's own heap. Never called on a thread of the mod. `step` says which
// one runs (for the filter: the global heap's call is under its lock).
void* game_alloc_raw(size_t size, volatile inj::Step& step) {
    const auto tls_array = static_cast<uintptr_t>(__readgsqword(0x58));
    const uint32_t index = *reinterpret_cast<const uint32_t*>(g_base + addr(off::kTlsIndexSlot));
    const uintptr_t tls = *reinterpret_cast<const uintptr_t*>(tls_array + 8ull * index);
    if (*reinterpret_cast<const uint8_t*>(tls + profile::tls_heap_selector_offset()) != 0) {
        g_global_heap_flag.fetch_add(1, std::memory_order_relaxed);
        step = inj::Step::AllocGlobal;
        return g_alloc_global(size, 0x10);
    }
    return g_alloc_thread(size, 0x10);
}

bool game_alloc(size_t size, void*& out, uint16_t opcode, uint32_t epoch) {
    volatile inj::Step step = inj::Step::Alloc;
    __try {
        out = game_alloc_raw(size, step);
        return out != nullptr;
    } __except (note_exception(GetExceptionInformation(), step, opcode, epoch)) {
        // Only Alloc (the thread's own heap, no lock of its own) gets here.
        out = nullptr;
        g_halted_epoch.store(epoch ? epoch : 1);  // the game's heap may be damaged: nothing more
        return false;
    }
}

struct Counters {
    // injected = buffers handed to the server's Q0 by the NetworkThread; inject_failed = exceptions there.
    std::atomic<uint64_t> injected{0}, inject_refused{0}, inject_blocked{0}, inject_failed{0}, recv_ours{0};
    std::atomic<uint64_t> sent_out{0}, sent_bad{0}, save_reqs{0};
    std::atomic<uint64_t> logout_injected{0}, logout_acks{0}, inject_after_logout{0};  // C4
    std::atomic<uint64_t> move_close_injected{0};  // MoveFieldCompleteReq 2549 handed before a 2001
    std::atomic<uint64_t> finder_calls[2]{}, finder_nonempty[2]{}, finder_relayed[2]{}, finder_errors[2]{};
} g_n;

// ---------------------------------------------------------------- guarded helpers (no C++ objects)

template <class T>
bool peek(uintptr_t addr, T& out) {
    __try {
        out = *reinterpret_cast<const T*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// session 2's Send hands the S->C buffer back to Q2 with the game's push
// 0x35DF50 (Q2's lock): an exception inside it is the game's, passed on (I1).
bool guarded_push(uintptr_t queue, void* item) {
    __try {
        void* p = item;
        g_push(reinterpret_cast<void*>(queue), &p);
        return true;
    } __except (game::game_fault_continue(GetExceptionInformation(), "Session2 Send",
                                          "returning an S->C buffer to Q2 (0x35DF50, under the queue's lock)")) {
        return false;  // never reached: the filter passes it on
    }
}

bool guarded_copy(void* dst, uintptr_t src, size_t n) {
    __try {
        std::memcpy(dst, reinterpret_cast<const void*>(src), n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The server instance session 2 was built in is still the current one.
bool same_server() {
    uintptr_t net = 0, s1 = 0;
    return peek(g_base + addr(off::kServerNetSlot), net) && net == g_built_net.load() &&
           peek(net + off::kServerNet_Session, s1) && s1 == g_built_s1.load();
}

// Session 2 if it exists, belongs to the current server and to the epoch the
// network thread wants (C4: between two epochs there is none); 0 otherwise.
uintptr_t live_session2() {
    const uintptr_t s2 = g_session2.load(std::memory_order_acquire);
    return s2 && g_session_epoch.load() == g_want_epoch.load() && same_server() ? s2 : 0;
}

// A copy of the epoch -> session table (for guest_lifecycle's pure helpers).
void epoch_sessions(uintptr_t (&out)[kEpochSlots]) {
    for (size_t e = 0; e < kEpochSlots; ++e) out[e] = g_epoch_session[e].load(std::memory_order_acquire);
}

// The user of a session, only if it is still a ServerUserActor linked back to
// that session (a freed or reused block fails this).
bool session_user(uintptr_t session, uintptr_t& user) {
    uintptr_t vt = 0, back = 0;
    return session && peek(session + off::kSession_User, user) && user && peek(user, vt) &&
           vt == g_base + addr(off::kServerUserActorVtable) && peek(user + off::kUser_Session, back) && back == session;
}

// P1, on ServerRunThread: the steps of ServerModule::Init for the game's own
// session (segunda-sesion.md §1.3, D0 §6), with our vtable. Its memory comes
// from this game thread's own heap, as the server's own allocations
// (p8-heap-inyeccion.md); it is never freed.
bool build_session(uintptr_t& out) {
    void* obj = nullptr;
    if (!game_alloc(off::kSessionSize, obj, 0, g_want_epoch.load())) return false;
    volatile inj::Step step = inj::Step::BuildSession;
    __try {
        std::memset(obj, 0, off::kSessionSize);
        step = inj::Step::BuildCtor;  // allocates (either heap) and may raise 0xA0000002 itself
        g_ctor(obj, 0);
        step = inj::Step::BuildSession;
        const auto s = reinterpret_cast<uintptr_t>(obj);
        *reinterpret_cast<uintptr_t*>(s) = g_base + addr(off::kNwAsyncSessionVtable);
        *reinterpret_cast<uint64_t*>(s + off::kSession_B0) = 0;
        *reinterpret_cast<uint64_t*>(s + off::kSession_B8) = 0;
        *reinterpret_cast<uint16_t*>(s + off::kSession_C0) = 0;
        *reinterpret_cast<uintptr_t*>(s) = reinterpret_cast<uintptr_t>(g_vtable + 1);
        *reinterpret_cast<uint16_t*>(s + off::kSession_Name) = '2';
        // Never read for session 2 (its Send is ours). If something did push
        // there, Q2 is where the server takes S->C buffers back: no leak, no
        // packet for the host's client (decision D-6).
        const uintptr_t server_net = *reinterpret_cast<uintptr_t*>(g_base + addr(off::kServerNetSlot));
        *reinterpret_cast<uintptr_t*>(s + off::kSession_OutQueue) =
            *reinterpret_cast<uintptr_t*>(server_net + off::kServerNet_FreeS2C);
        if (auto* id = *reinterpret_cast<uint32_t**>(s + off::kSession_IdPtr)) *id = kSessionId;
        g_built_net.store(server_net);
        g_built_s1.store(*reinterpret_cast<uintptr_t*>(server_net + off::kServerNet_Session));
        g_built_tid.store(GetCurrentThreadId());
        out = s;
        return true;
    } __except (note_exception(GetExceptionInformation(), step, 0, g_want_epoch.load())) {
        // Only our own writes get here (the constructor's exceptions are passed on).
        g_halted_epoch.store(g_want_epoch.load());  // the game's state may be damaged: nothing more
        return false;
    }
}

// ---------------------------------------------------------------- P3: session 2's Send

// P8 S2 (observer_milestone.h): this thread is inside take_frame (the
// milestone's emitter is never called from here).
thread_local int t_take_frame_depth = 0;

// P8 S3 (observer_hold_acks.h): how observer_hold_acks queues a 2005 and what
// it held for its keys, in order, under its own lock.
bool push_outgoing(std::span<const uint8_t> packet) {
    auto publication = observer_hold_acks_publication_guard();
    const bool ok = g_outgoing.push(packet);
    // P8 session 8 pets (attach_follow.h): a packet observer_hold_acks queues itself (a 2005, the packets it
    // held for it, a spill) still updates the attachments; observe only (nullptr: nothing is made here, under
    // observer_hold_acks' lock).
    if (ok && packet.size() >= 2 && attach_follow_active()) {
        attach_follow_on_out(static_cast<uint16_t>(packet[0] | (packet[1] << 8)), packet, nullptr);
    }
    return ok;
}

// P8 F2 (horse_follow.h): a packet the mod makes (not the server's) goes only while the queue is under
// half its budget: it never takes room a real packet needs (a refused real one ends the conversation).
bool push_outgoing_extra(std::span<const uint8_t> packet) {
    auto publication = observer_hold_acks_publication_guard();
    return g_outgoing.bytes() + packet.size() <= kMaxOutgoingBytes / 2 && g_outgoing.push(packet);
}

// Copies the packet of an S->C frame (AsyncRequestSend+0x30) to the tunnel.
// Runs on the game's threads: nothing may throw out of here. C4: what a
// session 2 of an older epoch still writes never reaches the new guest.
void take_frame(uintptr_t rq, uintptr_t self) noexcept {
    child_hold_settle_births();  // S33 review: a retired key born again (noted in the mid hook) before any filter
    NpcPublicationScope publication;
    struct Depth {
        Depth() { ++t_take_frame_depth; }
        ~Depth() { --t_take_frame_depth; }
    } depth;
    try {
        if (const uint32_t want = g_want_epoch.load(); want > 1) {
            uintptr_t table[kEpochSlots];
            epoch_sessions(table);
            const uint32_t e = epoch_of_session(self, table, kEpochSlots);
            if (e && e < want) {
                g_late_out.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        const uintptr_t frame = rq + off::kRq_Frame;
        uint16_t flen = 0;
        if (!peek(frame, flen) || flen < off::kFrameOverhead + troc::kInternalHeaderSize || flen > 0x8000) {
            g_n.sent_bad.fetch_add(1, std::memory_order_relaxed);  // SendPacket wrote no frame
            return;
        }
        std::vector<uint8_t> p(flen - off::kFrameOverhead);
        const bool copied = guarded_copy(p.data(), frame + off::kFrameHeader, p.size()) &&
                            native_opcode::decode_packet(game::current_build(), p, troc::Dir::ToGuestClient);
        auto v = copied ? troc::parse_wire(p, troc::Dir::ToGuestClient) : std::nullopt;
        // salida-en-carga.md §2: a Nak 1013 for session 2 (e.g. its logout refused), counted.
        if (copied && p.size() >= 2 && (p[0] | (p[1] << 8)) == kOpNak) {
            g_nak.fetch_add(1, std::memory_order_relaxed);
            if (g_logout_handed.load()) g_nak_after_logout.fetch_add(1, std::memory_order_relaxed);
        }
        if (!v) {
            g_n.sent_bad.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        // user2_world_anchor (world_anchor.h): the collector's RemoveActorAck 2516 to user 2, measured (read only;
        // here p is still intact).
        if (v->opcode == kOpRemoveActorAck2516 && world_anchor_active() && self == live_session2()) {
            world_anchor_on_user2_out(v->opcode, v->payload);
        }
        // C4: the server's answers to user 2's logout (7-byte internal Acks).
        if (v->opcode == troc::kOpLogoutSessionAck || v->opcode == troc::kOpLogoutUserAck) {
            g_n.logout_acks.fetch_add(1, std::memory_order_relaxed);
        }
        // salida-en-carga.md §4: user 2's move phase (MoveFieldAck, MoveFieldCompleteAck, LoadingCompleteAck).
        // observer_load_defer (review L1): a load that ENDS here (the 2762) is told after this packet's push, so
        // that the releases it allows queue behind it; one that goes on (or starts) is told at once.
        bool loaded_after_push = false;
        if (v->opcode == mv::kMoveFieldAck || v->opcode == mv::kMoveFieldCompleteAck ||
            v->opcode == mv::kLoadingCompleteAck) {
            std::lock_guard lock(g_phase_mu);
            if (g_phase.on_ack(v->opcode)) {
                const bool loading = move_phase_loading(g_phase.phase());
                if (loading) child_hold_note_user2_loading(true);
                else loaded_after_push = true;
            }
        }
        struct LoadedAfterPush {
            bool& on;
            ~LoadedAfterPush() {
                if (on) child_hold_note_user2_loading(false);
            }
        } loaded_note{loaded_after_push};
        // E4: user 2's character key (u32 at +0 of MainPlayerDataStartAck).
        if ((p[0] | (p[1] << 8)) == kOpMainPlayerDataStartAck && p.size() >= troc::kHeaderSize + 4) {
            uint32_t key = 0;
            std::memcpy(&key, p.data() + troc::kHeaderSize, 4);
            g_user2_player.store(key);
            net::puppet_guard_also_key(key);  // E3b: the host's client gets it before any action
            net::horse_diag_also_key(key);
        }
        // Everything user 2 owns (its character and children: pet, horse...)
        // reaches the host's client with no action; only its controller can
        // start one (companion probe 2026-10-09). Its user key, from its own
        // MainUserDataStartAck, before any of its actors exists.
        if ((p[0] | (p[1] << 8)) == kOpMainUserDataStartAck && p.size() >= troc::kHeaderSize + 4) {
            uint32_t key = 0;
            std::memcpy(&key, p.data() + troc::kHeaderSize, 4);
            net::puppet_guard_owner(key);
            net::horse_diag_owner(key);
            g_user2_userkey.store(key);
        }
        // P8 (docs/research/pendientes/p8-cierre-campo.md): the client takes the
        // owner of the field it moves into (MoveFieldAck +9) as a user it knows
        // and uses its character unchecked (.xtls 0x940B170 via 0x9A5BE0): in the
        // original game a field has one user, itself. In the host's shared field
        // the owner is the host, unknown to user 2's client: it crashed
        // (live 2026-10-09). User 2's copy names user 2 as the owner; the
        // server's field (+0x180) stays the host's, and no client Req sends the
        // owner back.
        // P8 S2 (observer_milestone.h): the owner the SERVER wrote, before user 2's copy is rewritten.
        uint32_t milestone_value = 0;
        // P8 S15 (travel_probe_logic.h): user 2's fast travel in the shared field is answered by 0x2BCA3D0 with
        // LoadingFieldDataAck 2643 (writer 0x299B520) + 3066, not a 2174; its u32 +9 is the same field owner
        // ([field+0x180]), which the client keeps in P+0x12C. Same alias, only on user 2's copy, only the u32 +9
        // (layout 20 + 48n), switchable (user2_loading_owner_alias). The owner the server wrote is kept for the probe.
        uint32_t owner_orig = 0, owner_copy = 0;
        tpl::AliasOut alias = tpl::AliasOut::NotOwnerAck;
        if (v->opcode == kOpMoveFieldAck || v->opcode == tpl::kOpLoadingFieldDataAck) {
            const bool move = v->opcode == kOpMoveFieldAck;
            const size_t n = v->payload.size();
            const uint32_t me = g_user2_userkey.load();
            alias = tpl::alias_owner(p, troc::kHeaderSize, v->opcode, me, move || travel_loading_owner_alias(),
                                     &owner_orig, game::current_build());
            owner_copy = alias == tpl::AliasOut::Rewrite ? me : owner_orig;
            if (move) milestone_value = owner_orig;  // 0 unless the known layout (as before)
            const char* what = move ? "MoveFieldAck 2174" : "LoadingFieldDataAck 2643";
            if (alias == tpl::AliasOut::Rewrite) {
                if ((move ? g_owner_rewrites : g_load_owner_rewrites).fetch_add(1) < 8) {
                    log::info("Session2: user 2's {} names the field owner 0x{:08X} (the host); user 2's copy names user "
                              "2 (0x{:08X}), as a single-player client expects",
                              what, owner_orig, me);
                }
            } else if (alias == tpl::AliasOut::BadLayout || alias == tpl::AliasOut::NoKey) {
                if ((move ? g_owner_unexpected : g_load_owner_unexpected).fetch_add(1) < 4) {
                    log::warn("Session2: user 2's {} of {} bytes is not the known layout (or user 2's key is unknown "
                              "yet): left as it is",
                              what, n);
                }
            } else if (!move && g_load_owner_other.fetch_add(1) < 4) {
                log::info("Session2: user 2's LoadingFieldDataAck 2643 owner 0x{:08X}: {}", owner_orig,
                          tpl::alias_name(alias));
            }
        }
        // Which packets for user 2 still carry the host's user key (counts only).
        if (!g_host_userkey.load()) {
            uintptr_t host = 0;
            uint32_t k = 0;
            if (server_host_user(host) && peek(host + 0x60, k) && k) g_host_userkey.store(k);
        }
        if (uint32_t host_key = 0; v->opcode < g_hostkey_ops.size() && (host_key = g_host_userkey.load()) != 0) {
            const uint8_t k[4] = {static_cast<uint8_t>(host_key), static_cast<uint8_t>(host_key >> 8),
                                  static_cast<uint8_t>(host_key >> 16), static_cast<uint8_t>(host_key >> 24)};
            if (std::search(p.begin(), p.end(), std::begin(k), std::end(k)) != p.end()) {
                g_hostkey_ops[v->opcode].fetch_add(1, std::memory_order_relaxed);
            }
        }
        if (v->opcode == oms::kOpMilestone && v->payload.size() >= 4) std::memcpy(&milestone_value, v->payload.data(), 4);
        const uint16_t opcode = v->opcode;
        // P8 S15 (travel_probe.h): the head of the payload, copied before the packet is queued (read only).
        const bool travel_out = travel_probe_on() && self == live_session2();
        const size_t travel_size = v->payload.size();
        const size_t travel_n = std::min(travel_size, kTravelHead);
        uint8_t travel_head[kTravelHead] = {};
        if (travel_out && travel_n) std::memcpy(travel_head, v->payload.data(), travel_n);
        // P8 session 25 (clock_push.h, T1): a 2762 for user 2 is followed by the host's world clock (2816). Its
        // payload is copied before the route (13 bytes: actor | flag | now).
        uint8_t loading_ack[ckp::kLoadingAckPayload] = {};
        size_t loading_ack_n = 0;
        if (opcode == mv::kLoadingCompleteAck && clock_push_active()) {
            loading_ack_n = std::min(v->payload.size(), sizeof loading_ack);
            std::memcpy(loading_ack, v->payload.data(), loading_ack_n);
        }
        // housing_share (housing_share.h): user 2's own housing login set is replaced by the host's.
        if (housing_share_wanted() && self == live_session2() &&
            housing_share_on_out(opcode, std::span<const uint8_t>(p.data(), p.size()))) {
            return;
        }
        // P8 (observer_hold_acks.h, observer_scene_copy.h): only what goes to the live session 2.
        const bool to_live = (observer_hold_acks_active() || observer_scene_copy_wanted() || horse_follow_active() ||
                              observer_seq_copy_wanted() || attach_follow_active() || combat_follow_active()) &&
                             self == live_session2();
        // P8 S3 (observer_hold_acks.h): a held NPC's packets wait for its 2005; a 2005 is queued with them.
        AckRouteOut ar;
        const AckRoute route = to_live && observer_hold_acks_active()
                                   ? observer_hold_acks_route(opcode, v->payload, p, &push_outgoing, ar)
                                   : AckRoute::Pass;
        if (route == AckRoute::Held) return;  // retenido o cancelado localmente
        // S33: el filtro puede compactar un2005 mixto; los observadores leen
        // el payload NUEVO, nunca el span anterior a la compactación.
        if (opcode == 2005) v = troc::parse_wire(p, troc::Dir::ToGuestClient);
        bool pushed = false;
        if (route == AckRoute::Pushed) {
            pushed = ar.self_pushed;
            const uint64_t ok = (pushed ? 1u : 0u) + ar.extra_pushed - ar.extra_failed;
            g_n.sent_out.fetch_add(ok, std::memory_order_relaxed);
            if (!pushed || ar.extra_failed) g_outgoing_lost.store(true);
        } else {
            pushed = g_outgoing.push(p);
            if (pushed) {
                g_n.sent_out.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_outgoing_lost.store(true);
            }
            // P8 (observer_scene_copy.h): user 2's 2661/2810 and its trips, bound to the push's real result.
            if (to_live) observer_scene_copy_on_out(opcode, v->payload, pushed);
            // P8 F2 (horse_follow.h): a rider's 2697 queued for user 2 -> its horse's, right after it.
            if (to_live && pushed) horse_follow_on_out(opcode, p, &push_outgoing_extra);
            // P8 session 8 pets (attach_follow.h): a child riding the host's character follows its 2697s.
            if (to_live && pushed) attach_follow_on_out(opcode, p, &push_outgoing_extra);
            if (to_live && pushed) focus_follow_count_out(opcode, v->payload);
            // P8 session 9 C1 (combat_follow.h): who fights user 2, and the enemies' real samples (anchors).
            if (to_live && pushed) combat_follow_on_out(opcode, v->payload);
        }
        if (pushed && self == live_session2()) door_trace_packet(DoorTraceStage::ServerGuestOut, p);
        // P8 session 25 (clock_push.h, T1): right behind user 2's 2762, in the same queue, the 2816 with the host's
        // world clock (its flag 1 re-anchored the guest; this puts the host's base and anchor back).
        if (loading_ack_n && pushed && self == live_session2()) {
            clock_push_on_2762(std::span<const uint8_t>(loading_ack, loading_ack_n), g_user2_player.load(),
                               &push_outgoing_extra);
        }
        // P8 S15/S16 (child_hold.h, observer_hold_family): what user 2 is given (2005), loses (2516) or starts over
        // with (2174), in queue order, only once really queued (review 6); the orphans among its records are
        // counted. None of these opcodes is ever kept above (p is intact).
        if (pushed && (opcode == 2005 || opcode == 2516 || opcode == 2174) && self == live_session2()) {
            child_hold_on_user2_out(opcode, v->payload);
        }
        // P8 S15 (travel_probe.h): the Acks queued for user 2 after its 2283 / 2437 (bounded, read only).
        if (travel_out) {
            travel_probe_on_out(opcode, travel_size, std::span<const uint8_t>(travel_head, travel_n), owner_orig,
                                owner_copy, alias, pushed);
        }
        // P8 S1 option A (observer_seq_copy.h): user 2's trips, the 2005/2516 it got, its own 2322; the copies
        // of the host's sequencers go right after the 2005 that completes their bound actors.
        if (to_live) observer_seq_copy_on_out(opcode, v->payload, pushed, opcode == kOpMoveFieldAck ? milestone_value : 0);
        // S46 phase 3, T2 active (observer_hold_acks.h): the scene packets (user 2's own 2661 and what followed it)
        // this 2005 released and the queue took, shown now, outside the route's locks, to the observers that keep
        // state on them (observer_scene_copy's book, observer_seq_copy's own ids, shop_probe's counts), in order.
        if (to_live && !ar.scene_released.empty()) {
            for (const std::vector<uint8_t>& sp : ar.scene_released) {
                const auto sv = troc::parse_wire(sp, troc::Dir::ToGuestClient);
                if (!sv) continue;
                observer_scene_copy_on_out(sv->opcode, sv->payload, true);
                observer_seq_copy_on_out(sv->opcode, sv->payload, true, 0);
                if (shop_probe_active()) shop_probe_on_out(sv->opcode, sv->payload, true, true);
            }
        }
        // P8 session 13 (shop_probe.h): the interaction / shop-scene Acks queued for user 2 (counted only).
        if (shop_probe_active()) shop_probe_on_out(opcode, v->payload, self == live_session2(), pushed);
        // S46 phase 1 (shop_trade_probe.h): the 3000s and Naks queued for user 2, their errors named (read only).
        if (shop_trade_probe_active()) shop_trade_probe_on_out(opcode, v->payload, self == live_session2(), pushed);
        // S46 phase 1, T2 probe (observer_hold_scene_order.h): user 2's own trade 2661 vs its NPCs' 2005s (read only).
        if (observer_hold_scene_order_active()) {
            observer_hold_scene_order_on_out(opcode, v->payload, self == live_session2(), pushed);
        }
        // P8 option U, U2 (user2_shops.h): the shop 2916 / 3000 and Nak 1013 queued for user 2 (the drain wait, aborts).
        user2_shops_on_out(opcode, v->payload, self == live_session2(), pushed);
        // P8 option U, U-1 (user2_stages.h): the 2322 / 2335 really queued for user 2 (abort criterion, counts); the
        // 2005s for U-e's controller check (user2_npc_control).
        if (pushed && (opcode == 2322 || opcode == 2335 || opcode == 2005)) {
            user2_stages_on_out(opcode, v->payload, self == live_session2());
        }
        // P8 B step 2 (owner_fanout.h): user 2's observer trip, by the same rule (counts only).
        if (opcode == kOpMoveFieldAck) owner_fanout_on_move_field(self, pushed, milestone_value);
        // P8 S2: bound to the push's real result (observer_milestone.h).
        if (oms::followed_out(opcode)) observer_milestone_on_out(opcode, self, pushed, milestone_value);
        // P8 S16 (observer_milestone_reload_logic.h): user 2's reload trip (2643/3066 vs 2174/2679, the 2322s).
        if (omr::followed_out(opcode)) {
            observer_milestone_reload_on_out(opcode, self, pushed, opcode == omr::kOpMilestone ? milestone_value : 0);
        }
        // P8 S1 (host_scene_diag.h, s1_scene_diag): the trip's numbering and a copy of the NPC 2005 (read only).
        host_scene_diag_on_out(opcode, p.data(), p.size(), self, pushed);
    } catch (...) {
        g_outgoing_lost.store(true);
    }
}

int* __fastcall session2_send(void* self, int* res, void* rq) {
    int result = 0;
    const auto r = reinterpret_cast<uintptr_t>(rq);
    if (r) {
        take_frame(r, reinterpret_cast<uintptr_t>(self));
        // Hand the buffer back as the client's NetworkThread does (0x35BB5C):
        // the server drops its reference and frees it (D0 §3.2). If that is
        // impossible, report failure: SendPacket then frees it itself.
        uintptr_t server_net = 0, q2 = 0;
        if (!peek(g_base + addr(off::kServerNetSlot), server_net) || !peek(server_net + off::kServerNet_FreeS2C, q2) ||
            !guarded_push(q2, reinterpret_cast<void*>(r + off::kRq_Frame))) {
            result = 1;
        }
    }
    if (res) *res = result;
    return res;
}

// ---------------------------------------------------------------- E4: mirror

}  // namespace
bool server_inject(std::span<const uint8_t> packet);
bool server_user2_present();
namespace {

// The packet the host's client sent, if it moves a player-class actor (key
// 0xA...; NPCs are 0xB...) other than user 2's: copied with user 2's key.
// Runs inside the OnRecvPacket mid-hook: nothing may throw out of here.
void mirror_copy(uintptr_t pkt, uintptr_t rsp) noexcept {
    try {
        const uint32_t user2_key = g_user2_player.load(std::memory_order_relaxed);
        // C4: nothing more once user 2's logout is asked for (the barrier waits
        // for an empty mirror queue).
        if (g_logout_asked.load(std::memory_order_relaxed)) return;
        uint16_t size = 0;
        uint32_t key = 0;
        // OnRecvPacket(ServerNet*, int*, NwSession*, u8* pkt, u16 size, ...): size is the 5th argument.
        if (!user2_key || !peek(rsp + 0x28, size) || size < troc::kHeaderSize + 4 || size > 0x7F00 ||
            !peek(pkt + troc::kHeaderSize, key) || (key >> 28) != 0xA || key == user2_key) {
            return;
        }
        std::vector<uint8_t> p(size);
        if (!guarded_copy(p.data(), pkt, size) ||
            !native_opcode::decode_packet(game::current_build(), p, troc::Dir::ToHostServer)) return;
        std::memcpy(p.data() + troc::kHeaderSize, &user2_key, 4);
        std::lock_guard lock(g_mirror_mu);
        if (g_mirror.size() >= kMaxMirrored) {
            g_mirror_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        g_mirror.push_back({GetTickCount64() + g_opt.mirror_delay_ms, std::move(p), g_want_epoch.load()});
        g_mirror_copied.fetch_add(1, std::memory_order_relaxed);
    } catch (...) {
        g_mirror_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

// ---------------------------------------------------------------- P2: OnRecvPacket entry

// Build 3527, the ways a Req of user 2 can outlive the host's user (run 9, exe+0x2AEF244).
constexpr uintptr_t kServerRecvRet3527 = 0x29AC01A;
constexpr uintptr_t kSeqEventApply3527 = 0x2AEF1F0;
constexpr uintptr_t kSeqEventApplyRet3527 = 0x2AEF4B9;
constexpr uint8_t kSeqEventApplyHead3527[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x44, 0x89, 0x4C, 0x24, 0x20, 0x48,
                                              0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). OnRecvPacket 0x29AC440 (profile_s2.h) is 0x82B bytes as in 3527:
// its only `ret` is at +0x82A (0x29ACC6A). The apply moved by +0xC50 with the same 20-byte head (0x2AEFE40, .pdata
// 0x2AEFE40..0x2AF010A), its `ret` at +0x2C9 (0x2AF0109) as in 3527, and +0x54 (0x2AEFE94) is the same
// `mov rdx,[rdx]` on the null owner's manager that crashed run 9 at exe+0x2AEF244.
// Build 1.0.0.3663 (static, 2026-11-13; never run): OnRecvPacket 0x2A0EA70 (profile_s2.h) is again 0x82B bytes (.pdata
// 0x2A0EA70..0x2A0F29B) with its only `ret` at +0x82A (0x2A0F29A). The apply: kSeqEventApplyHead3527 near 3576 + the
// region's shift has one hit, 0x2B53E50 (3576 +0x64010), a .pdata entry of the same 0x2CA bytes (..0x2B5411A), its
// only `ret` at +0x2C9 (0x2B54119), and +0x54 (0x2B53EA4) is the same `mov rdx,[rdx]` after `lea rdx,[rcx+8]`.
struct GoodbyeGuards {
    uintptr_t recv_ret, apply, apply_ret;
};
constexpr GoodbyeGuards kGoodbye3527{kServerRecvRet3527, kSeqEventApply3527, kSeqEventApplyRet3527};
constexpr GoodbyeGuards kGoodbye3576{0x29ACC6A, 0x2AEFE40, 0x2AF0109};
constexpr GoodbyeGuards kGoodbye3663{0x2A0F29A, 0x2B53E50, 0x2B54119};
const GoodbyeGuards* goodbye_guards() noexcept {
    switch (game::current_build()) {
        case game::Build::v3527: return &kGoodbye3527;
        case game::Build::v3576: return &kGoodbye3576;
        case game::Build::v3663: return &kGoodbye3663;
        default: return nullptr;
    }
}
SafetyHookMid g_seq_event_hook;
uintptr_t g_recv_ret = 0, g_seq_event_ret = 0;
constexpr uint16_t kOpAttackByCollisionReq = 2815;  // logical; native 2150 on 3527
std::atomic<uint64_t> g_friendly_fire_dropped{0};

// AttackByCollisionReq: u32 attacker | u32 target | ... Both belong to a user, and not the same one.
bool cross_player_hit(uintptr_t pkt, uintptr_t rsp) noexcept {
    uint16_t size = 0;
    uint32_t attacker = 0, target = 0;
    if (!peek(rsp + 0x28, size) || size < troc::kHeaderSize + 8 || !peek(pkt + troc::kHeaderSize, attacker) ||
        !peek(pkt + troc::kHeaderSize + 4, target) || attacker == target) {
        return false;
    }
    try {
        const auto a = hold_actor_owner(attacker);
        if (!a || !*a) return false;
        const auto t = hold_actor_owner(target);
        return t && *t && *a != *t;
    } catch (...) {
        return false;
    }
}
std::atomic<bool> g_host_leaving{false};
std::atomic<uint64_t> g_after_host_goodbye{0}, g_seq_event_no_manager{0};

// UpdateSequencerGamePlayDataEventReq's handler passes ServerField::vf48's result here as `this`, and vf48 answers
// null once the field's owner is gone. Queued Reqs already past on_server_recv reach it: they end with no error
// (out = 0: the handler then sends no Nak, and the client that asked is on its way out with the host's world).
void on_seq_event_apply(safetyhook::Context& ctx) {
    if (ctx.rcx) return;
    g_seq_event_no_manager.fetch_add(1, std::memory_order_relaxed);
    *reinterpret_cast<int*>(ctx.rdx) = 0;
    ctx.rax = ctx.rdx;
    ctx.rip = g_seq_event_ret;
}

void install_host_goodbye_guards() {
    constexpr uint8_t kRet = 0xC3;
    const GoodbyeGuards* g = goodbye_guards();
    if (!g) {
        log::warn("Session2: the host's goodbye guards have no addresses for this build; not installed");
        return;
    }
    uint8_t recv_ret = 0, event_ret = 0;
    uint8_t head[sizeof kSeqEventApplyHead3527]{};
    if (!game::safe_read(g_base + g->recv_ret, &recv_ret, 1) ||
        !game::safe_read(g_base + g->apply_ret, &event_ret, 1) ||
        !game::safe_read(g_base + g->apply, head, sizeof head) || recv_ret != kRet || event_ret != kRet ||
        std::memcmp(head, kSeqEventApplyHead3527, sizeof head) != 0) {
        log::warn("Session2: the host's goodbye guards do not match this executable; not installed");
        return;
    }
    g_seq_event_ret = g_base + g->apply_ret;
    g_seq_event_hook = safetyhook::create_mid(reinterpret_cast<void*>(g_base + g->apply), on_seq_event_apply);
    if (!g_seq_event_hook) {
        log::warn("Session2: cannot hook exe+0x{:X}; a Req of user 2 can crash the host's goodbye", g->apply);
    }
    g_recv_ret = g_base + g->recv_ret;  // read by the hook on OnRecvPacket, installed after this
    log::info("Session2: host's goodbye guards ON (user 2's Reqs stop at the host's 2001; exe+0x{:X} tolerates a field "
              "without an owner)",
              g->apply);
}

void on_server_recv(safetyhook::Context& ctx) {
    // P1 lazily, on this thread (ServerRunThread, server realm): the session
    // and its sub-objects come from the game's allocators like the original.
    // OnRecvPacket has one caller, ServerRunThread's loop (D0 §4).
    if (g_session2.load(std::memory_order_acquire) &&
        (GetCurrentThreadId() != g_built_tid.load() || !same_server())) {
        // Another server instance: session 2 (and its user) belonged to the
        // old one. It is left as it is (never freed) and a new one is built.
        // A conversation that had started cannot go on.
        if (g_n.injected.load() > 0) g_outgoing_lost.store(true);
        g_session2.store(0, std::memory_order_release);
        g_session_epoch.store(0);
        g_user2_player.store(0);
        net::puppet_guard_also_key(0);
        net::horse_diag_also_key(0);
        net::puppet_guard_owner(0);
        net::horse_diag_owner(0);
        g_rebuilt.fetch_add(1);
        observer_milestone_on_epoch(g_want_epoch.load(), "the server instance was replaced");
        observer_hold_acks_clear(oha::Discard::Epoch);      // P8 S3: nothing held carries over
        observer_scene_copy_on_epoch(g_want_epoch.load());  // P8: user 2's scenes start again
        observer_seq_copy_on_server_replaced();             // P8 S1 option A: its ledger and ids start again
        world_anchor_on_server_replaced();                  // the old server's fields are not ours to touch
        scene_level_share_on_server_replaced();             // S43: both users' loaded SceneLevels start again
    }
    // C4: a new guest epoch (server_begin_epoch) gets a session 2 of its own;
    // the old one stays as it is (never freed, never reused).
    const uint32_t want = g_want_epoch.load();
    const bool epoch_change = g_session2.load(std::memory_order_acquire) && g_session_epoch.load() != want;
    if (g_want_session.load(std::memory_order_relaxed) &&
        (!g_session2.load(std::memory_order_acquire) || epoch_change) &&
        !g_create_failed.load(std::memory_order_relaxed) && want < kEpochSlots) {
        uintptr_t s = 0;
        if (build_session(s)) {
            if (!epoch_change) {
                // The first session 2, or one rebuilt for a new server: its user may
                // be logged out once. (For a new epoch the network thread reset
                // these before asking for it, and may already have asked again.)
                g_logout_asked.store(false);
                g_logout_handed.store(0);
                phase_reset();  // its user starts its login from nothing
            }
            // The session before its epoch: live_session2() must never pair the
            // old session with the new epoch (review of f15596e, finding 3).
            g_epoch_session[want].store(s, std::memory_order_release);
            g_session2.store(s, std::memory_order_release);
            g_session_epoch.store(want);
        } else {
            g_create_failed.store(true);
        }
    }
    const uintptr_t pkt = ctx.r9;
    const uintptr_t s2 = g_session2.load(std::memory_order_acquire);
    uint16_t op = 0;
    bool from_user2 = false;  // one of our buffers (a Req of user 2, any epoch)
    if (s2 && pkt) {
        const uintptr_t pb = pkt - off::kFrameHeader;
        uintptr_t frame = 0, base = 0;
        uint64_t magic = 0;
        if (peek(pb + off::kPb_FramePtr, frame) && frame == pb && peek(pb + off::kPb_Base, base) && base == pb &&
            peek(pb + off::kPb_Magic, magic) && magic == kMagic) {
            // C4: the session of the epoch the buffer was tagged with. A buffer
            // of an older epoch goes to ITS session (whose user is gone), never
            // to the new guest's; the barrier waits until none is in flight.
            uint32_t tag = 0;
            uintptr_t table[kEpochSlots];
            epoch_sessions(table);
            const PbRoute route =
                peek(pb + off::kPb_Tag, tag) ? route_pb(tag, g_session_epoch.load(), table, kEpochSlots) : PbRoute{};
            if (route.session) {
                ctx.r8 = route.session;
                g_pb_seen[route.epoch].fetch_add(1, std::memory_order_relaxed);
                if (route.stale) g_stale_routed.fetch_add(1, std::memory_order_relaxed);
            } else {
                ctx.r8 = s2;  // as before C4 (cannot happen: every buffer is tagged)
                g_untagged_routed.fetch_add(1, std::memory_order_relaxed);
            }
            g_n.recv_ours.fetch_add(1, std::memory_order_relaxed);
            from_user2 = true;
        }
    }
    // P6, second layer (log only, decision D-5): the server is asked to save.
    if (pkt && peek(pkt, op)) op = native_opcode::decode(game::current_build(), op).value_or(0);
    // Run 9: the host's own goodbye deleted its user, the field's owner, and a Req of user 2 still on its way then
    // found no owner and crashed the server. From the host's goodbye on, user 2's Reqs are not handled.
    if (g_recv_ret) {
        if (!from_user2 && op == troc::kOpLogoutSessionReq) {
            g_host_leaving.store(true, std::memory_order_relaxed);
        } else if (!from_user2 && op == kOpLoginCharacterToFieldServerReq) {
            g_host_leaving.store(false, std::memory_order_relaxed);
        } else if (from_user2 && g_host_leaving.load(std::memory_order_relaxed)) {
            g_after_host_goodbye.fetch_add(1, std::memory_order_relaxed);
            *reinterpret_cast<int*>(ctx.rdx) = 0;
            ctx.rax = ctx.rdx;
            ctx.rip = g_recv_ret;
            return;
        }
    }
    if (op == 3037 || op == 2910) g_n.save_reqs.fetch_add(1, std::memory_order_relaxed);
    // No friendly fire between the two players' sides. The game has no notion of it: a hit from one player's character
    // or companion on the other's counts, the victim's AI answers, and two companions left side by side (a guest
    // playing a copy of the host's save has its twins at the same spots) keep fighting for the whole session.
    if (op == kOpAttackByCollisionReq && g_recv_ret && cross_player_hit(pkt, ctx.rsp)) {
        g_friendly_fire_dropped.fetch_add(1, std::memory_order_relaxed);
        *reinterpret_cast<int*>(ctx.rdx) = 0;
        ctx.rax = ctx.rdx;
        ctx.rip = g_recv_ret;
        return;
    }
    // E4: copy the host player's movement for user 2 (mirror_delay_ms later).
    if (g_opt.mirror_host && (op == kOpMoveActorReq || op == kOpStartActionReq || op == kOpRotateActorReq) &&
        ctx.r8 != s2) {
        mirror_copy(pkt, ctx.rsp);
    }
    // The host's slot: u8 4 | u64 characterNo | u32 slot (opcion-d-login.md).
    uint32_t slot = 0;
    if (op == kOpLoginCharacterToFieldServerReq && ctx.r8 != s2 && peek(pkt + troc::kHeaderSize + 9, slot)) {
        g_host_slot.store(slot);
    }
    // D-53: the held children's fallback release, on this thread only
    // (ServerRunThread, before the packet is handled: no lock of ours or the
    // game's is held here). Returns at once while nothing is held.
    child_hold_server_tick();
    // user2_world_anchor (world_anchor.h): on this thread, before this packet is handled. User 2's 2437 / 2283 / 2001
    // try to clear the slot first (the field's TryLock, up to 5 ms); if its lock stays busy the handler runs with the
    // slot still set and every following packet (the host's too) tries again until it is cleared (counted). Its only
    // periodic point: the watchdog and the fallback clear run when a packet arrives (<= ~5 s apart in play). Returns
    // at once when off; otherwise reads at most every 0.5 s / 5 s.
    world_anchor_server_tick(op, from_user2);
    uint16_t in_size = 0;
    const bool in_sized = pkt && op && peek(ctx.rsp + 0x28, in_size);
    // P8 option U, U-1 (user2_stages.h): user 2's 2001 counted (armed or not); its AI Reqs mark the NPCs U-e gave it
    // (user2_npc_control). No game call from here.
    if (from_user2) user2_stages_server_packet(op, from_user2, pkt, in_sized ? in_size : 0);
    // P8 S28 (docked_gimmicks.h, probe / 1): the 2221 unspawns and who still uses each gimmick (counts only).
    if (in_sized) {
        docked_gimmicks_server_ingress(op, pkt, in_size, from_user2);
        door_trace_ingress(op, pkt, in_size, from_user2);
        // S43 (scene_level_share.h): the SceneLevels each client has loaded (2598 / 2834 / 2104 and its loads). The
        // host's own Reqs are the ones of session 1 (before session 2 exists, the only session there is).
        const uintptr_t s1 = g_built_s1.load(std::memory_order_relaxed);
        scene_level_share_server_ingress(op, pkt, in_size, from_user2, !from_user2 && (!s1 || ctx.r8 == s1));
    }
}

// ---------------------------------------------------------------- P5 / E0b: the emptied finders

bool session_user_key(uintptr_t session, uint32_t& key) {
    uintptr_t user = 0;
    return session_user(session, user) && peek(user + off::kUser_Key, key);
}

// actor->vf(0xE8)(): the actor's own session (null for an NPC), as the game
// asks it. A virtual call into the game's code, on the game's thread.
bool actor_session(uintptr_t actor, uintptr_t& session) {
    __try {
        using GetSession = uintptr_t(__fastcall*)(uintptr_t);
        const uintptr_t vt = *reinterpret_cast<const uintptr_t*>(actor);
        session = reinterpret_cast<GetSession>(*reinterpret_cast<const uintptr_t*>(vt + 0xE8))(actor);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Removes `session` from the game's array {T* data; u32 count; u32 cap}.
bool array_remove(uintptr_t arr, uintptr_t session) {
    __try {
        auto* data = *reinterpret_cast<uintptr_t**>(arr);
        auto& count = *reinterpret_cast<uint32_t*>(arr + off::kArray_Count);
        for (uint32_t i = 0; i < count; ++i) {
            if (data[i] != session) continue;
            for (uint32_t j = i + 1; j < count; ++j) data[j - 1] = data[j];
            --count;
            return true;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ToNear::vf1 takes the actor's lock (finder_common): an exception inside it is
// the game's, passed on (I1); the relay fix stops first, in case something up
// the stack handles it.
std::atomic<bool> g_finder_faulted{false};
int finder_fault(EXCEPTION_POINTERS* ep) {
    g_finder_faulted.store(true);
    return game::game_fault_continue(ep, "Session2 relay fix", "ToNear::vf1 (exe+0x2A75860) built the recipients");
}

bool call_to_near(void* finder, void* out, uintptr_t& ret) {
    __try {
        ret = g_to_near(finder, out);
        return true;
    } __except (finder_fault(GetExceptionInformation())) {
        return false;  // never reached: the filter passes it on
    }
}

uintptr_t finder_common(int which, SafetyHookInline& hook, void* finder, void* out) {
    // unsafe_call: call() would hold the hook's mutex while the original takes
    // the actor's lock, and two server threads could deadlock (review finding 1).
    const uintptr_t original = hook.unsafe_call<uintptr_t>(finder, out);
    g_n.finder_calls[which].fetch_add(1, std::memory_order_relaxed);
    const auto arr = reinterpret_cast<uintptr_t>(out);
    uint32_t count = 0;
    if (g_opt.finder_log && peek(arr + off::kArray_Count, count) && count) {
        g_n.finder_nonempty[which].fetch_add(1, std::memory_order_relaxed);
    }
    if (!g_opt.relay_fix || g_finder_faulted.load(std::memory_order_relaxed)) return original;
    const uintptr_t s2 = live_session2();
    uint32_t key2 = 0;
    if (!s2 || !session_user_key(s2, key2)) return original;  // no user 2: exactly as today
    // Who controls the actor decides whose session is left out. The actor as
    // ToNear reads it (0x2BC5233): TS = [[[finder+0x10]+0x68]+0x1A0], actor = [TS+8].
    uintptr_t a = 0, b = 0, ts = 0, actor = 0;
    uint32_t controller = 0, key1 = 0;
    const uintptr_t s1 = g_built_s1.load();
    if (!peek(reinterpret_cast<uintptr_t>(finder) + off::kFinder_Actor, a) || !a || !peek(a + 0x68, b) || !b ||
        !peek(b + 0x1A0, ts) || !ts || !peek(ts + 8, actor) || !actor ||
        !peek(actor + off::kServerActor_Controller, controller) || !session_user_key(s1, key1)) {
        return original;
    }
    uintptr_t exclude = 0;
    if (which == 1) {
        // ExceptOneSelf: everyone near but the actor's own session; an actor
        // without one (an NPC) stays as the game has it.
        if (!actor_session(actor, exclude) || (exclude != s1 && exclude != s2)) return original;
    } else if (controller == key1) {
        exclude = s1;
    } else if (controller == key2) {
        exclude = s2;
    } else {
        return original;  // a controller we do not know: leave it as the game has it
    }
    uintptr_t ret = 0;
    if (!call_to_near(finder, out, ret) || !array_remove(arr, exclude)) {
        g_n.finder_errors[which].fetch_add(1, std::memory_order_relaxed);
        return original;
    }
    g_n.finder_relayed[which].fetch_add(1, std::memory_order_relaxed);
    return ret;
}

uintptr_t __fastcall except_one_control(void* finder, void* out) { return finder_common(0, g_control_hook, finder, out); }
uintptr_t __fastcall except_one_self(void* finder, void* out) { return finder_common(1, g_self_hook, finder, out); }

// ---------------------------------------------------------------- install

bool head_matches(uintptr_t rva, const uint8_t* expected, size_t n, const char* what) {
    const auto resolved = addr(rva);
    const auto sig = profile::signature(rva, {expected, n});
    if (!resolved || sig.empty()) {
        log::error("Session2: {} has no verified address/signature for this build; option D stays off", what);
        return false;
    }
    std::vector<uint8_t> actual(sig.size());
    if (game::safe_read(g_base + resolved, actual.data(), actual.size()) &&
        std::memcmp(actual.data(), sig.data(), sig.size()) == 0) return true;
    log::error("Session2: {} (exe+0x{:X}) does not start with the expected bytes; option D stays off", what, resolved);
    return false;
}

void load_channels() {
    g_channel.fill(kNotReq);
    g_blocked_channel.fill(kNotReq);
    size_t n = 0, blocked = 0;
    for (uintptr_t a = g_base + addr(off::kTrocInstancesBegin); a < g_base + addr(off::kTrocInstancesEnd); a += 8) {
        auto vt = game::read_ptr(a);
        if (!vt || *vt < g_base || *vt >= g_base + 0x10000000) continue;
        if (game::rtti_name_of_vtable(*vt).rfind(".?AVTrocTr", 0) != 0) continue;
        auto kind = game::read<uint32_t>(a + off::kTroc_Kind);
        auto op = game::read<uint16_t>(a + off::kTroc_Opcode);
        if (op) op = native_opcode::decode(game::current_build(), *op);
        auto ch = game::read<uint8_t>(a + off::kTroc_Channel);
        const std::string name =
            kind && *kind != off::kTrocKindServer ? game::short_class_name(game::rtti_name_of_vtable(*vt), "TrocTr")
                                                  : std::string();
        // ConnectCryptogramToServerReq is an "internal" handler (kind 0x7FFFFFFE) that
        // the server finds by bit mask (Troc::Find, 0x143B351): the login's first
        // Req (opcion-d-p8.md). The other internal ones (timers, the native logout
        // LogoutSessionToServerReq) never come from the tunnel (decision D-16).
        // C4: LogoutSessionToServerReq 2001, the user's own logout (3 bytes, no
        // length; salida.md §1-§2) is the one other internal handler user 2 may
        // reach. Never the global shutdown 2790/2038 nor 2004 (pointers).
        const bool connect = name == "ConnectCryptogramToServerReq" ||
                             (name == "LogoutSessionToServerReq" && op && *op == troc::kOpLogoutSessionReq);
        if (kind && op && ch && (*kind == off::kTrocKindServer || connect) && *ch < kBlocked) {
            const std::string full = game::short_class_name(game::rtti_name_of_vtable(*vt), "TrocTr");
            // The tunnel never asks the host's server to save, delete saves or run cheats.
            // Covers every Req of domain cheat/dev in troc_messages_2976.csv and none
            // of the login or movement scripts (checked against the table).
            bool never = full.rfind("Save", 0) == 0 || full.rfind("DeleteSave", 0) == 0 ||
                         full.rfind("DeleteCharacter", 0) == 0 || full.rfind("ReportFromViewer", 0) == 0;
            for (const char* k : {"Cheat", "ForDev", "Debug", "DevReq", "ByGm", "Test"}) {
                never = never || full.find(k) != std::string::npos;
            }
            g_channel[*op] = never ? kBlocked : *ch;
            if (never) g_blocked_channel[*op] = *ch;
            ++n;
            if (never) ++blocked;
        }
        a += 0x80;  // the rest of this 0x90-byte instance
    }
    if (g_channel[troc::kOpLogoutSessionReq] >= kBlocked) {
        log::error("Session2: LogoutSessionToServerReq 2001 not found among the server's handlers: user 2 cannot "
                   "be logged out (C4 off)");
    }
    log::info("Session2: {} server Req handlers (channel per opcode); {} never fed from the tunnel (save, cheats, dev)",
              n, blocked);
}

bool build_vtable() {
    auto* vt = static_cast<uintptr_t*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!vt) return false;
    // COL at [-1] keeps the RTTI name; then the 15 entries.
    if (!game::safe_read(g_base + addr(off::kNwVirtualAsyncSessionVtable) - 8, vt,
                         (off::kSessionVtableEntries + 1) * sizeof(uintptr_t))) {
        return false;
    }
    if (vt[1 + off::kSessionVfSend] != g_base + addr(off::kSessionSend)) return false;
    vt[1 + off::kSessionVfSend] = reinterpret_cast<uintptr_t>(&session2_send);
    DWORD old = 0;
    VirtualProtect(vt, 4096, PAGE_READONLY, &old);
    g_vtable = vt;
    return true;
}

bool vtable_slot_is(uintptr_t vtable_rva, int slot, uintptr_t fn_rva) {
    const auto vt = addr(vtable_rva), fn = addr(fn_rva);
    if (!vt || !fn) return false;
    auto v = game::read<uintptr_t>(g_base + vt + 8 * slot);
    return v && *v == g_base + fn;
}

}  // namespace

bool server_install(const ServerOptions& opt) {
    g_opt = opt;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!profile::supported_build() || !game::validate_native_catalog()) {
        log::error("Session2: unsupported game build; option D stays off");
        return false;
    }
    const bool hooks_server = opt.create_session || opt.accept_tunnel;
    const bool hooks_finders = opt.finder_log || opt.relay_fix;
    if (hooks_server) {
        if (!head_matches(off::kServerOnRecvPacket, off::kServerOnRecvPacketHead, sizeof off::kServerOnRecvPacketHead,
                          "ServerNet::OnRecvPacket") ||
            !head_matches(off::kSessionSend, off::kSessionSendHead, sizeof off::kSessionSendHead,
                          "NwVirtualAsyncSession::Send") ||
            !head_matches(off::kNwSessionCtor, off::kNwSessionCtorHead, sizeof off::kNwSessionCtorHead,
                          "NwSession::NwSession") ||
            !head_matches(off::kQueuePush, off::kQueuePushHead, sizeof off::kQueuePushHead, "queue push") ||
            !head_matches(off::kAllocGlobal, off::kAllocGlobalHead, sizeof off::kAllocGlobalHead, "alloc") ||
            !head_matches(off::kAllocThread, off::kAllocThreadBytes, sizeof off::kAllocThreadBytes,
                          "the thread's own allocator") ||
            !head_matches(off::kNetLoopPump, off::kNetLoopPumpAob, sizeof off::kNetLoopPumpAob,
                          "the client NetworkThread's turn")) {
            return false;
        }
    }
    if (hooks_finders) {
        if (!vtable_slot_is(off::kToNearExceptOneControlVtable, 1, off::kExceptOneVf1) ||
            !vtable_slot_is(off::kToNearExceptOneSelfVtable, 1, off::kExceptOneSelfVf1) ||
            !vtable_slot_is(off::kToNearVtable, 1, off::kToNearVf1)) {
            log::error("Session2: the recipient finders' vtables are not as expected; option D stays off");
            return false;
        }
        if (!head_matches(off::kExceptOneVf1, off::kExceptOneVf1Head, sizeof off::kExceptOneVf1Head,
                          "ToNearExceptOneControl::vf1") ||
            !head_matches(off::kExceptOneSelfVf1, off::kExceptOneVf1Head, sizeof off::kExceptOneVf1Head,
                          "ToNearExceptOneSelf::vf1") ||
            !head_matches(off::kToNearVf1, off::kToNearVf1Head, sizeof off::kToNearVf1Head, "ToNear::vf1")) {
            return false;
        }
    }

    g_alloc_global = reinterpret_cast<AllocFn>(g_base + addr(off::kAllocGlobal));
    g_alloc_thread = reinterpret_cast<AllocFn>(g_base + addr(off::kAllocThread));
    g_ctor = reinterpret_cast<CtorFn>(g_base + addr(off::kNwSessionCtor));
    g_push = reinterpret_cast<PushFn>(g_base + addr(off::kQueuePush));
    g_to_near = reinterpret_cast<FinderVf1>(g_base + addr(off::kToNearVf1));

    if (hooks_server) {
        load_channels();
        if (!build_vtable()) {
            log::error("Session2: cannot build session 2's vtable; option D stays off");
            return false;
        }
        // Every setting the hook reads is final before it goes in.
        if (g_opt.mirror_host && (g_channel[kOpMoveActorReq] >= kBlocked || g_channel[kOpStartActionReq] >= kBlocked ||
                                  g_channel[kOpRotateActorReq] >= kBlocked)) {
            log::error("Session2: the movement Req opcodes are not server handlers in this game; mirror off");
            g_opt.mirror_host = false;
        }
        g_want_session.store(opt.create_session);
        if (opt.create_session && goodbye_guards()) install_host_goodbye_guards();
        g_recv_hook = safetyhook::create_mid(reinterpret_cast<void*>(g_base + addr(off::kServerOnRecvPacket)), on_server_recv);
        if (!g_recv_hook) {
            g_want_session.store(false);
            log::error("Session2: cannot hook ServerNet::OnRecvPacket; option D stays off");
            return false;
        }
        // P2 (p8-heap-inyeccion.md): the guest's Req are handed to the server
        // by the host's own client NetworkThread, the native forwarder of C->S
        // buffers (no game heap work on a thread of the mod).
        // P8 review M3: the same checked install as every P8 point
        // (p8_install_mid): inside .rsrc, the 39 verified bytes, and safetyhook
        // relocates exactly the first instruction (7 bytes, mov rax,[r15+0xE0]).
        std::vector<gad::Section> secs;
        if (!p8_exe_sections(g_base, secs) ||
            !p8_install_mid(g_base, secs, addr(off::kNetLoopPump), off::kNetLoopPumpPatch,
                            std::span<const uint8_t>(off::kNetLoopPumpAob, sizeof off::kNetLoopPumpAob),
                            on_client_pump, g_pump_hook, "Session2", "the client NetworkThread's turn")) {
            g_want_session.store(false);
            g_recv_hook = {};
            log::error("Session2: cannot hook the client NetworkThread's turn (exe+0x{:X}); option D stays off",
                       addr(off::kNetLoopPump));
            return false;
        }
        log::info("Session2: the guest's Req go to the server from the client NetworkThread (mid-hook exe+0x{:X}, "
                  "every turn <= 16 ms): buffer from that thread's own heap (exe+0x{:X}), push exe+0x{:X}; queue "
                  "{} Req / {} MB, at most {} not yet taken by the server",
                  addr(off::kNetLoopPump), addr(off::kAllocThread), addr(off::kQueuePush), g_q.limits().max_packets,
                  g_q.limits().max_bytes >> 20, g_q.limits().in_flight_max);
        if (g_opt.mirror_host) {
            CloseHandle(CreateThread(nullptr, 0, mirror_thread, nullptr, 0, nullptr));
            log::info("Session2: mirror on: user 2 repeats the host player's movement {} ms later",
                      opt.mirror_delay_ms);
        }
        log::info("Session2: hooked ServerNet::OnRecvPacket (exe+0x{:X}); session 2 {}", addr(off::kServerOnRecvPacket),
                  opt.create_session ? "will be built on the server thread" : "not built (create_session=0)");
    }
    if (hooks_finders) {
        // Created disabled and enabled once assigned: the detours call through
        // these objects (review finding 4).
        g_control_hook = safetyhook::create_inline(reinterpret_cast<void*>(g_base + addr(off::kExceptOneVf1)),
                                                   reinterpret_cast<void*>(&except_one_control),
                                                   SafetyHookInline::StartDisabled);
        g_self_hook = safetyhook::create_inline(reinterpret_cast<void*>(g_base + addr(off::kExceptOneSelfVf1)),
                                                reinterpret_cast<void*>(&except_one_self),
                                                SafetyHookInline::StartDisabled);
        if (!g_control_hook || !g_self_hook || !g_control_hook.enable() || !g_self_hook.enable()) {
            if (g_control_hook) (void)g_control_hook.disable();
            if (g_self_hook) (void)g_self_hook.disable();
            log::error("Session2: cannot hook the recipient finders; finder log and relay fix off");
        } else {
            log::info("Session2: hooked ToNearExceptOneControl/Self::vf1 (finder log {}, relay fix {})", opt.finder_log,
                      opt.relay_fix);
        }
    }
    return true;
}

void server_probe_log(const char* when) {
    using game::read;
    using game::read_ptr;
    const auto sn = read_ptr(g_base + addr(off::kServerNetSlot));
    const auto cn = read_ptr(g_base + addr(off::kClientNetSlot));
    const auto sam = profile::sam_ptr(g_base, [](uintptr_t a) { return game::read_ptr(a); });
    auto rva = [](std::optional<uintptr_t> v) {
        return v ? std::format("exe+0x{:X}", *v - g_base) : std::string("?");
    };
    auto hex = [](auto v) { return v ? std::format("0x{:X}", *v) : std::string("?"); };
    if (!sn) {
        log::info("Session2 probe ({}): no ServerNet yet", when);
        return;
    }
    const auto s1 = read_ptr(*sn + off::kServerNet_Session);
    std::string session = "none";
    if (s1) {
        const auto idp = read_ptr(*s1 + off::kSession_IdPtr);
        const auto id = idp ? read<uint32_t>(*idp) : std::nullopt;
        const auto user = read_ptr(*s1 + off::kSession_User);
        const auto crypto = read_ptr(*s1 + off::kSession_Crypto);
        const auto crypto_on = crypto ? read<uint8_t>(*crypto + 0x24) : std::nullopt;
        const auto outq = read_ptr(*s1 + off::kSession_OutQueue);
        const auto cin = cn ? read_ptr(*cn + off::kClientNet_InQueue) : std::nullopt;
        std::string u = "none";
        if (user) {
            const auto uvt = read_ptr(*user);
            const auto key = read<uint32_t>(*user + off::kUser_Key);
            const auto back = read_ptr(*user + off::kUser_Session);
            u = std::format("{} vt {} key {} +0x1F8 {}", hex(user), rva(uvt), hex(key),
                            back && *back == *s1 ? "== session" : hex(back));
        }
        session = std::format("{} vt {} | id {} | user {} | crypto +0x24 {} | out queue {} (ClientNet+0x18 {})",
                              hex(s1), rva(read_ptr(*s1)), hex(id), u, hex(crypto_on), hex(outq),
                              outq && cin && *outq == *cin ? "same" : "DIFFERENT");
    }
    const auto q2 = read_ptr(*sn + off::kServerNet_FreeS2C);
    const auto q3 = read_ptr(*sn + off::kServerNet_FreeC2S);
    const auto c20 = cn ? read_ptr(*cn + 0x20) : std::nullopt;
    const auto c28 = cn ? read_ptr(*cn + 0x28) : std::nullopt;
    log::info("Session2 probe ({}): ServerNet {} | session 1 {} | Q2 {} Q3 {} (ClientNet+0x20/+0x28 {})", when, hex(sn),
              session, hex(q2), hex(q3), q2 && q3 && c20 && c28 && *q2 == *c20 && *q3 == *c28 ? "same" : "DIFFERENT");
    if (sam) {
        log::info("Session2 probe ({}): SAM {} | free actor keys {} | actors {}", when, hex(sam),
                  hex(read<uint32_t>(*sam + off::kSam_FreeKeys)), hex(read<uint32_t>(*sam + off::kSam_ActorCount)));
    }
    if (const uintptr_t s2 = live_session2()) {
        const auto user = read_ptr(s2 + off::kSession_User);
        const auto idp = read_ptr(s2 + off::kSession_IdPtr);
        log::info("Session2 probe ({}): session 2 0x{:X} | id {} | user {} key {}", when, s2,
                  hex(idp ? read<uint32_t>(*idp) : std::nullopt), hex(user),
                  user ? hex(read<uint32_t>(*user + off::kUser_Key)) : std::string("-"));
    }
    // E3 (opcion-d-e3-riesgos.md §1.3-§1.6): is each user's character in the
    // same field? Main character = [user+0xD0]; TS = [[pj+0x68]+0x1A0];
    // sector = [TS+runtime field layout]. Users in different ServerField instances never
    // share a sector, so the host would not see user 2.
    auto where = [&](std::optional<uintptr_t> session) -> std::string {
        const auto& layout = runtime_field_layout();
        if (!session) return "-";
        const auto user = read_ptr(*session + off::kSession_User);
        const auto pj = user ? read_ptr(*user + 0xD0) : std::nullopt;
        const auto key = pj ? read<uint32_t>(*pj + off::kServerActor_Key) : std::nullopt;
        const auto c68 = pj ? read_ptr(*pj + 0x68) : std::nullopt;
        const auto ts = c68 ? read_ptr(*c68 + 0x1A0) : std::nullopt;
        const auto sector = ts ? read_ptr(*ts + layout.ts_sector) : std::nullopt;
        // Its ServerField: [TS+FieldMover+0x10] (opcion-d-campo-compartido.md §1).
        const auto field = ts ? read_ptr(*ts + layout.ts_field_mover + fld::kFmField) : std::nullopt;
        std::string f = "-";
        if (field) {
            f = std::format("{} owner {} users {} user actors {} generation {}", hex(field),
                            hex(read<uint32_t>(*field + fld::kOwner)),
                            hex(read<uint32_t>(*field + layout.user_count)),
                            hex(read<uint32_t>(*field + layout.user_actors)),
                            hex(read<uint32_t>(*field + layout.key)));
        }
        return std::format("character {} key {} TS {} sector {} field {}", hex(pj), hex(key), hex(ts), hex(sector),
                           f);
    };
    const auto s2 = live_session2();
    log::info("Session2 probe ({}): host {} | user 2 {}", when, where(s1),
              s2 ? where(std::optional<uintptr_t>(s2)) : std::string("-"));
    // The server's world time (FieldTime, exe+0x6A6D238): user 2's MoveField and
    // LoadingCompleteReq 01 copy its save's time here (R1).
    // 3576 (static, 2026-11-06; not yet run): 0x6EAD9B8, what GetCurrentFieldTime 0x22A9BB0 (3527's 0x22A8F70 +0xC40,
    // same head) loads at 0x22A9C20 when the TLS realm byte +0x1EB is set (the client's at 0x6EAD998 otherwise): the
    // Troc block's +0x2000.
    // Build 1.0.0.3663 (static, 2026-11-13; never run): 0x6F31C98. GetCurrentFieldTime is 0x231A180 (clock_gate's
    // kGetterHead, unique in the image); with the TLS realm byte +0x1EB set it loads that 32-byte FieldTime at 0x231A1F4,
    // the client's 0x6F31C78 otherwise (the same +0x20 pair as 3576's); 5 functions read each of the two.
    uint8_t ft[32] = {};
    const auto b = game::current_build();
    const uintptr_t world_time = b == game::Build::v3663   ? 0x6F31C98
                                 : b == game::Build::v3576 ? 0x6EAD9B8
                                 : b == game::Build::v3527 ? 0x6EAB9B8
                                 : b == game::Build::v2976 ? 0x6A6D238
                                                           : 0;
    if (world_time && game::safe_read(g_base + world_time, ft, sizeof ft)) {
        std::string h;
        for (uint8_t byte : ft) h += std::format("{:02X}", byte);
        log::info("Session2 probe ({}): server FieldTime {}", when, h);
    }
}

bool server_session_ready() { return live_session2() != 0; }

bool server_accepts_guest() {
    if (live_session2()) return true;
    const uint32_t want = g_want_epoch.load();
    return g_want_session.load() && !g_create_failed.load() && g_session2.load(std::memory_order_acquire) &&
           same_server() && g_session_epoch.load() != want && want < kEpochSlots;
}

bool server_user2_present() {
    uint32_t key = 0;
    return session_user_key(live_session2(), key);
}

bool server_users(uintptr_t& host, uintptr_t& user2) {
    uintptr_t net = 0, s1 = 0;
    const uintptr_t s2 = live_session2();
    return s2 && peek(g_base + addr(off::kServerNetSlot), net) && peek(net + off::kServerNet_Session, s1) &&
           session_user(s1, host) && session_user(s2, user2);
}

bool server_host_user(uintptr_t& host) {
    uintptr_t net = 0, s1 = 0;
    return peek(g_base + addr(off::kServerNetSlot), net) && peek(net + off::kServerNet_Session, s1) &&
           session_user(s1, host);
}

bool server_user2(uintptr_t& user2) { return session_user(live_session2(), user2); }

bool server_session_user(uintptr_t session, uintptr_t& user) { return session_user(session, user); }

uint32_t server_thread_id() { return g_built_tid.load(); }

uintptr_t server_live_session2() { return live_session2(); }
uintptr_t server_host_session() { return g_built_s1.load(std::memory_order_relaxed); }
uint32_t server_user2_user_key() { return g_user2_userkey.load(); }
uint32_t server_user2_player_key() { return g_user2_player.load(); }
bool server_in_take_frame() { return t_take_frame_depth > 0; }
bool server_user2_in_world() {
    // S25 (docs/research/s25/hora-clima-verificacion.md, C): not after its goodbye (its own 2001 or the host's on a lost
    // link): the phase stays Stable until the next connection, and the weather stream and T2 went on for minutes.
    return live_session2() != 0 && !g_logout_asked.load() && phase_snapshot().phase() == MovePhase::Stable;
}
MovePhaseTracker server_user2_phase() { return phase_snapshot(); }

// P8 S1 option A (observer_seq_copy.h): a copy the mod makes, only into the live session 2's queue and only while
// the queue is under half its budget (push_outgoing_extra: never the room a real packet needs).
bool server_push_extra(std::span<const uint8_t> packet) {
    const bool queued = live_session2() != 0 && push_outgoing_extra(packet);
    owner_fanout_on_extra(packet, queued);  // P8 B step 2: option A's copies, for the comparison (counts only)
    return queued;
}

namespace {

// P2, on the host's client NetworkThread only (on_client_pump): fills a packet
// buffer as ClientNet::PostPacket 0x35C670 does and pushes it to Q0 with the
// same 0x35DF50 the native forwarder (0x14380B0) calls on this thread. The
// buffer comes back to this thread through Q3 and is freed here by the game
// (0x35BB7B-0x35BBE6). An exception is noted (code, address, step) and stops
// the injection for good: no retry (the game's state may be damaged). Only the
// allocation from the thread's own heap and our filling are handled; inside the
// push (Q0's lock) it is passed on (note_exception, P8 review I1).
bool push_native_request(uintptr_t server_net, const uint8_t* pkt, size_t len, uint8_t channel, uint32_t tag,
                  uint16_t opcode, uint32_t epoch) {
    void* mem = nullptr;
    if (!game_alloc(off::kPbSize, mem, opcode, epoch)) return false;
    const auto pb = reinterpret_cast<uintptr_t>(mem);
    const auto flen = static_cast<uint16_t>(len + off::kFrameOverhead);
    volatile inj::Step step = inj::Step::Fill;
    __try {
        std::memset(mem, 0, off::kFrameHeader + len + (off::kFrameOverhead - off::kFrameHeader));
        *reinterpret_cast<uint16_t*>(pb) = flen;
        *reinterpret_cast<uint8_t*>(pb + 2) = channel;
        std::memcpy(reinterpret_cast<void*>(pb + off::kFrameHeader), pkt, len);
        std::memset(reinterpret_cast<void*>(pb + off::kPb_FramePtr), 0, off::kPbSize - off::kPb_FramePtr);
        *reinterpret_cast<uintptr_t*>(pb + off::kPb_FramePtr) = pb;
        *reinterpret_cast<uint16_t*>(pb + off::kPb_Len1) = flen;
        *reinterpret_cast<uint16_t*>(pb + off::kPb_Len2) = flen;
        *reinterpret_cast<uint16_t*>(pb + off::kPb_Cap) = flen;
        *reinterpret_cast<uint8_t*>(pb + off::kPb_IsRequest) = 0;
        *reinterpret_cast<uint32_t*>(pb + off::kPb_Tag) = tag;
        *reinterpret_cast<uint64_t*>(pb + off::kPb_Magic) = kMagic;
        *reinterpret_cast<uint64_t*>(pb + 0x8020) = 0x7FFFFFFFFFFFFFFFull;
        *reinterpret_cast<uintptr_t*>(pb + off::kPb_Base) = pb;
        const uintptr_t q0 = *reinterpret_cast<uintptr_t*>(server_net + off::kServerNet_InQueue);
        void* item = mem;
        step = inj::Step::Push;
        g_push(reinterpret_cast<void*>(q0), &item);
        return true;
    } __except (note_exception(GetExceptionInformation(), step, opcode, epoch)) {
        g_halted_epoch.store(epoch ? epoch : 1);
        return false;
    }
}

// Keep C++ buffer lifetime outside the SEH-only native allocation/publication function.
bool push_request(uintptr_t server_net, const uint8_t* pkt, size_t len, uint8_t channel, uint32_t tag,
                  uint16_t opcode, uint32_t epoch) {
    const auto native = native_opcode::encode_copy(game::current_build(), {pkt, len}, troc::Dir::ToHostServer);
    if (!native) return false;
    return push_native_request(server_net, native->data(), native->size(), channel, tag, opcode, epoch);
}

// The NetworkThread hook's body: hands what is due, in order, bounded by the
// buffers the server has not taken yet (a paused server keeps the rest here).
void pump_body(uintptr_t client_net) {
    g_pump_turns.fetch_add(1, std::memory_order_relaxed);
    const uint64_t now = now_ms();
    g_pump_last_ms.store(now, std::memory_order_relaxed);
    if (!g_q_size.load(std::memory_order_acquire) || g_halted_epoch.load()) return;
    uintptr_t cn = 0, server_net = 0;
    // Only the client of the current game (r15 = ClientNet at 0x35BAD4) and a live server.
    if (!peek(g_base + addr(off::kClientNetSlot), cn) || cn != client_net) {
        g_pump_other_net.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!peek(g_base + addr(off::kServerNetSlot), server_net) || !server_net) return;
    const uint32_t tid = GetCurrentThreadId();
    if (g_pump_tid.load(std::memory_order_relaxed) != tid) g_pump_tid.store(tid);
    const uint32_t epoch = g_want_epoch.load();
    if (epoch >= kEpochSlots) return;
    // P8 review M4: only into the server session 2 belongs to. If the host went
    // back to the title and the server was replaced (or is being destroyed with
    // Req still queued), its Q0 may be freed: the same test inject() made when
    // it queued them (live session, or the built one on this very server waiting
    // for a new epoch), again now; the Req wait (the network thread's epoch and
    // "server replaced" logic decides what becomes of them).
    if (!server_accepts_guest()) {
        g_pump_not_ready.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    size_t n = inj::may_hand(g_pb_pushed[epoch].load(), g_pb_seen[epoch].load(),
                             g_q_size.load(std::memory_order_acquire), g_q.limits());
    size_t handed = 0;
    inj::Pending p;
    while (n--) {
        // P8 review M1: another part may stop the injection meanwhile (an
        // exception on ServerRunThread's build_session): not one more buffer.
        if (g_halted_epoch.load()) break;
        {
            std::lock_guard lock(g_q_mu);
            if (!g_q.pop(p)) break;
            g_in_hand.fetch_add(1);  // before the size goes down: the barrier never sees neither
            g_q_size.store(g_q.size(), std::memory_order_release);
        }
        if (p.epoch != g_want_epoch.load()) {  // the network thread began another epoch meanwhile
            g_in_hand.fetch_sub(1);
            g_pump_stale.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        // Counted before the push: the server thread may see it at once.
        g_pb_pushed[p.epoch].fetch_add(1);
        g_in_hand.fetch_sub(1);  // now counted as pushed (taken back below if the push fails)
        if (!push_request(server_net, p.packet.data(), p.packet.size(), p.channel, p.tag, p.opcode, p.epoch)) {
            g_pb_pushed[p.epoch].fetch_sub(1);
            g_n.inject_failed.fetch_add(1);
            if (!g_halted_epoch.load()) g_halted_epoch.store(p.epoch ? p.epoch : 1);  // a null buffer: stop too
            break;
        }
        g_n.injected.fetch_add(1);
        ++handed;
        const uint64_t wait = now >= p.queued_ms ? now - p.queued_ms : 0;
        g_pump_wait_sum.fetch_add(wait, std::memory_order_relaxed);
        atomic_max(g_pump_wait_max, wait);
    }
    if (handed) {
        g_pump_handed.fetch_add(handed, std::memory_order_relaxed);
        atomic_max(g_pump_batch_max, handed);
        const uint64_t pushed = g_pb_pushed[epoch].load(), seen = g_pb_seen[epoch].load();
        atomic_max(g_pump_inflight_max, pushed > seen ? pushed - seen : 0);
    }
}

// The mid-hook at 0x35BAD4 (NetworkThread, every turn, before the native
// FlushSendQueue): nothing may throw out of here.
void on_client_pump(safetyhook::Context& ctx) {
    try {
        pump_body(ctx.r15);
    } catch (...) {
        g_pump_other_net.fetch_add(1, std::memory_order_relaxed);
    }
}

// P2 for server_inject_ex and, with CloseMove, for the one MoveFieldCompleteReq
// 2549 the logout sequence hands after the 2001 was asked for (the only Req
// besides the 2001 that may go then; salida-en-carga.md §4); with FinalSave,
// the one SaveToFileCurrentPlayerReq 2910 of P8 S25 phase B's final save on a lost link
// (§3.6). Network thread (or the mirror thread): checks and queues, nothing of the game.
enum class InjectKind : uint8_t { Normal, CloseMove, FinalSave };
inj::Outcome inject(std::span<const uint8_t> in, InjectKind kind);

}  // namespace

inj::Outcome server_inject_ex(std::span<const uint8_t> in) { return inject(in, InjectKind::Normal); }
bool server_inject(std::span<const uint8_t> in) { return inject(in, InjectKind::Normal) == inj::Outcome::Queued; }

namespace {

inj::Outcome inject(std::span<const uint8_t> in, InjectKind kind) {
    const bool close_move = kind == InjectKind::CloseMove;
    const bool final_save = kind == InjectKind::FinalSave;
    std::vector<uint8_t> copy;
    std::span<const uint8_t> packet = in;
    if (in.size() >= troc::kHeaderSize + 8 && (in[0] | (in[1] << 8)) == kOpLoginUserToFieldServerReq) {
        copy.assign(in.begin(), in.end());
        // Never 0 (caution) nor all ones (it would take the host's user: relogin
        // branch 0x2C17B88, docs/research/data/b2-login-pasos.md).
        const uint64_t account = g_opt.account && g_opt.account != ~0ull ? g_opt.account : 1;
        std::memcpy(copy.data() + troc::kHeaderSize, &account, 8);
        packet = copy;
    }
    // C2 + P8: a real client's "Play" always asks for the single-player constant
    // 7FFF...FFFF in its 3093 (0x65DB90, docs/research/pendientes/p8-titulo.md),
    // whatever its 2869 said. User 2's identity is the server's: that constant
    // means its own character, F002. Any other number is left for the check.
    if (identity_fix_active() && in.size() >= troc::kHeaderSize + 9 &&
        (in[0] | (in[1] << 8)) == kOpLoginCharacterToFieldServerReq) {
        uint64_t asked = 0;
        std::memcpy(&asked, in.data() + troc::kHeaderSize + 1, sizeof asked);
        if (asked == idf::kNative) {
            copy.assign(in.begin(), in.end());
            const uint64_t own = idf::kUser2;
            std::memcpy(copy.data() + troc::kHeaderSize + 1, &own, sizeof own);
            packet = copy;
            log::info("Session2 C2 identity: user 2's LoginCharacterToFieldServerReq asked for the single-player "
                      "constant 0x{:X}; it is user 2's own character, 0x{:X}",
                      asked, own);
        }
    }
    auto v = troc::parse_wire(packet, troc::Dir::ToHostServer);
    if (!v || packet.size() + off::kFrameOverhead > 0x8000) {
        g_n.inject_refused.fetch_add(1);
        return inj::Outcome::Refused;
    }
    // An exception inside the game's code stopped the injection: nothing more (no retry).
    if (g_halted_epoch.load()) return inj::Outcome::Halted;
    // C4: the buffer carries the epoch of the session 2 it is for.
    const uint32_t epoch = g_want_epoch.load();
    // A new epoch's session is built by the server thread when it takes this
    // very buffer (on_server_recv builds, then routes by the tag), so the
    // guest's first Req may go before the session exists (C4r live test: with
    // the host standing still nothing else reached the server to build it).
    const bool live = live_session2() != 0;
    if (!server_accepts_guest() || epoch >= kEpochSlots || (live && !g_epoch_session[epoch].load())) {
        g_held_not_ready.fetch_add(1);
        return inj::Outcome::NotReady;
    }
    // C4: once user 2's logout is asked for, nothing else of it (tunnel,
    // mirror, anything) reaches the server while the native logout runs.
    // The one exception: the logout sequence's own MoveFieldCompleteReq.
    if (g_logout_asked.load() && v->opcode != troc::kOpLogoutSessionReq &&
        !(close_move && v->opcode == mv::kMoveFieldCompleteReq) && !(final_save && v->opcode == gsw::kOpSaveToFileCurrentPlayerReq)) {
        g_n.inject_after_logout.fetch_add(1);
        return inj::Outcome::AfterLogout;
    }
    // C2 (identity_fix.h): user 2 logs in only with a characterNo of its own;
    // after an identity failure only its 2001 goes on. Logged there.
    if (std::string why; !identity_fix_admit(v->opcode, v->payload, why)) {
        g_n.inject_blocked.fetch_add(1);
        return inj::Outcome::Blocked;
    }
    // housing_share_guest_spawn=0 (housing_share.h): user 2 never spawns the host's housing gimmicks itself.
    if (housing_share_wanted() && housing_share_blocks_request(v->opcode)) {
        g_n.inject_blocked.fetch_add(1);
        return inj::Outcome::Blocked;
    }
    // Two save slots user 2 never loads (opcion-d-p9.md): 3 is CrossSave (saving
    // it uploads the files to Pearl Abyss with the host's account) and 206 is
    // deleted after loading. LoginCharacterToFieldServerReq: u8 | u64 | u32 slot @9.
    if (v->opcode == kOpLoginCharacterToFieldServerReq && v->payload.size() >= 13) {
        uint32_t slot = 0;
        std::memcpy(&slot, v->payload.data() + 9, 4);
        if (slot == 3 || slot == 206) {
            g_n.inject_blocked.fetch_add(1);
            log::warn("Session2: refused user 2's LoginCharacterToFieldServerReq for save slot {} (CrossSave/one-use)",
                      slot);
            return inj::Outcome::Blocked;
        }
    }
    uint8_t channel = g_channel[v->opcode];
    // P8 S25 phase B (§3.7): own-save mode lets user 2's 3037 / 2910 reach the server (SavePlayerToSlot remaps them
    // to its own slot 204 or refuses them; never the host's slot) and drops its 2711 / 2178.
    const gsw::ReqPolicy own = guest_save_req_policy(v->opcode, v->payload);
    if (own == gsw::ReqPolicy::Block) {
        g_n.inject_blocked.fetch_add(1);
        return inj::Outcome::Blocked;
    }
    if (channel == kBlocked && own == gsw::ReqPolicy::Allow && g_blocked_channel[v->opcode] < kBlocked) {
        channel = g_blocked_channel[v->opcode];
    }
    if (channel == kBlocked) {
        g_n.inject_blocked.fetch_add(1);
        return inj::Outcome::Blocked;
    }
    if (channel == kNotReq) {
        g_n.inject_refused.fetch_add(1);
        return inj::Outcome::Refused;
    }
    uintptr_t server_net = 0;
    if (!peek(g_base + addr(off::kServerNetSlot), server_net) || !server_net) {
        g_held_not_ready.fetch_add(1);
        return inj::Outcome::NotReady;
    }
    const bool control = close_move || final_save || v->opcode == troc::kOpLogoutSessionReq;
    {
        std::lock_guard lock(g_q_mu);
        if (!g_q.has_room(packet.size(), control)) {
            g_held_full.fetch_add(1);
            return inj::Outcome::Full;
        }
    }
    const bool phase_req = v->opcode == mv::kLoginCharacterReq || v->opcode == mv::kGameLoadingStartReq ||
                           v->opcode == mv::kMoveFieldCompleteReq || v->opcode == mv::kLoadingCompleteReq;
    inj::Pending p;
    p.packet.assign(packet.begin(), packet.end());
    p.channel = channel;
    p.tag = pb_tag(epoch);
    p.epoch = epoch;
    p.opcode = v->opcode;
    p.queued_ms = now_ms();
    {
        std::lock_guard lock(g_q_mu);
        if (g_q.push(std::move(p), control) != inj::Outcome::Queued) {
            g_held_full.fetch_add(1);
            return inj::Outcome::Full;  // offered again later: the phase has not moved (P8 review M5)
        }
        // The move phase once the Req is surely queued, and still under g_q_mu:
        // the NetworkThread pops under this lock, so the phase moves before the
        // buffer can reach the server (its Ack may come out at once). g_phase_mu
        // is a leaf lock (nothing is taken under it).
        if (phase_req) {
            std::lock_guard phase_lock(g_phase_mu);
            if (g_phase.on_req(v->opcode)) child_hold_note_user2_loading(move_phase_loading(g_phase.phase()));
        }
        g_q_size.store(g_q.size(), std::memory_order_release);
    }
    g_pb_queued[epoch].fetch_add(1);
    if (oms::followed_in(v->opcode)) observer_milestone_on_in(v->opcode);  // P8 S2
    host_scene_diag_on_in(v->opcode, packet);  // P8 S1 (s1_scene_diag): 2549 and the scene Reqs, counted only
    horse_follow_on_guest_req(v->opcode, v->payload);  // P8 F2: user 2's keys and its riding (counted only)
    attach_follow_on_guest_req(v->opcode, v->payload);  // P8 session 8: user 2's pet riding (measured, registry)
    vehicle_follow_on_user2_req(v->opcode, v->payload);  // user 2's character on a ship part (vehicle_follow.h)
    return inj::Outcome::Queued;
}

// E4: hands the mirrored Req to the server when they are due (only while
// user 2 is logged in; before that they are dropped).
DWORD WINAPI mirror_thread(LPVOID) {
    for (;;) {
        Sleep(5);
        std::deque<Mirrored> due;
        {
            std::lock_guard lock(g_mirror_mu);
            const uint64_t now = GetTickCount64();
            while (!g_mirror.empty() && g_mirror.front().due_ms <= now) {
                due.push_back(std::move(g_mirror.front()));
                g_mirror.pop_front();
            }
        }
        if (due.empty()) continue;
        const bool user2 = server_user2_present();
        const uint32_t epoch = g_want_epoch.load();
        for (auto& m : due) {
            if (!user2 || m.epoch != epoch || !server_inject(m.packet)) {
                g_mirror_dropped.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
}

}  // namespace

namespace {

// What the logout waits for, read through user 2 while it is valid (log only).
std::string user2_move_diag() {
    uintptr_t user = 0;
    return server_user2(user) ? read_move_diag(user).describe() : std::string("user 2 not readable");
}

// salida-en-carga.md §4: before the 2001, a field move user 2 left open
// (window A: its MoveFieldAck went out, no MoveFieldCompleteReq after it) is
// closed as its client would have closed it: MoveFieldCompleteReq 2549 00,
// same P2 lane and epoch tag, then its MoveFieldCompleteAck 2144. Nothing is
// written to the game and no other function is called; every wait has a
// limit, past which the 2001 goes as before. True = the 2001 may go now.
bool close_open_move() {
    const auto now = static_cast<uint32_t>(GetTickCount64());
    const MovePhaseTracker t = phase_snapshot();
    std::string note;
    const auto action = g_close.step(now, t, &note);
    if (!note.empty()) log::info("Session2: user 2's logout ({}): {}", g_logout_why, note);
    if (action == MoveCloseSequence::Action::Wait) return false;
    if (action == MoveCloseSequence::Action::HandLogout) {
        if (!note.empty() && g_close.closed_move()) {
            log::info("Session2: user 2's logout ({}): after the injected MoveFieldCompleteReq: {}", g_logout_why,
                      user2_move_diag());
        }
        return true;
    }
    // InjectMoveComplete
    log::info("Session2: user 2's logout ({}): before the MoveFieldCompleteReq: {}", g_logout_why, user2_move_diag());
    const uint8_t zero = 0;
    const inj::Outcome o =
        inject(troc::make(mv::kMoveFieldCompleteReq, 0, std::span<const uint8_t>(&zero, 1)), InjectKind::CloseMove);
    const bool ok = o == inj::Outcome::Queued;
    g_close.injected(ok, now, t);
    if (!ok) {
        log::warn("Session2: user 2's logout ({}): MoveFieldCompleteReq 2549 COULD NOT be queued for the server ({}); "
                  "the 2001 as before",
                  g_logout_why, inj::outcome_name(o));
        return true;
    }
    g_n.move_close_injected.fetch_add(1);
    log::info("Session2: user 2's logout ({}): MoveFieldCompleteReq 2549 00 handed to the server (epoch {}, its "
              "own lane and tag); the 2001 waits for its MoveFieldCompleteAck 2144",
              g_logout_why, g_want_epoch.load());
    return false;
}

// P8 S25 phase B (§3.6): before the 2001 of a lost link, with user 2's own save active, one SaveToFileCurrentPlayerReq
// 2910 (gsw::make_final_save_req: slot 100, name 'Co-op'; a 3037 never saves now, guest_save_wire.h) for user 2, then the
// 2001 once an export of its slot followed (or 15 s). True = the 2001 may go now. Network thread.
bool final_save_step() {
    const uint64_t now = now_ms();
    switch (g_final.step(now, guest_save_exports())) {
        case gsw::FinalSave::Step::Go:
            if (g_final.outcome() != gsw::FinalSave::Outcome::None && !g_final_logged) {
                g_final_logged = true;
                log::info("Session2: user 2's logout ({}): final save: {} ({} ms); the 2001 goes", g_logout_why,
                          gsw::final_outcome_name(g_final.outcome()), g_final.waited(now));
            }
            return true;
        case gsw::FinalSave::Step::Inject: {
            const inj::Outcome o = inject(gsw::make_final_save_req(), InjectKind::FinalSave);
            const bool queued = o == inj::Outcome::Queued;
            g_final.injected(queued, now, guest_save_exports());
            if (queued) {
                guest_save_tunnel_note_final_injected();
                log::info("Session2: user 2's logout ({}): its own save is active: SaveToFileCurrentPlayerReq 2910 (slot 100, 'Co-op') handed to "
                          "the server FIRST; the 2001 waits for the export of slot 204 (15 s at most)",
                          g_logout_why);
                return false;
            }
            log::warn("Session2: user 2's logout ({}): the final SaveToFileCurrentPlayerReq 2910 COULD NOT be queued ({}); the 2001 as "
                      "before (the progress since the last autosave is lost)",
                      g_logout_why, inj::outcome_name(o));
            return true;
        }
        case gsw::FinalSave::Step::Wait: return false;
    }
    return true;
}

// Hands the 2001 if it is due: asked for, not yet handed to this session 2,
// and user 2 exists. Network thread (server_logout_user2 / server_logout_tick).
// Paced (p8-heap-inyeccion.md): one attempt every 250 ms at most, 240 at most
// (60 s), one error line every 5 s with the count; never after an exception in
// the game's code (the heap may be damaged: no logout by injection).
void hand_logout() {
    const uintptr_t s2 = live_session2();
    if (!g_logout_asked.load() || !s2 || g_logout_handed.load() == s2) return;
    if (g_halted_epoch.load()) {
        if (!g_logout_halt_logged) {
            g_logout_halt_logged = true;
            log::error("Session2: user 2's logout ({}): NOT handed: an exception inside the game's code stopped the "
                       "injection (see INJECT EXCEPTION); no 2001 by injection, user 2 stays on the server",
                       g_logout_why);
        }
        return;
    }
    const uint64_t asked = g_logout_asked_ms.load();
    if (!server_user2_present()) {
        if (asked && GetTickCount64() - asked > kLogoutPendingMs) {
            g_logout_asked_ms.store(0);  // log once
            log::warn("Session2: user 2's logout ({}): no user 2 appeared in {} s; nothing to log out",
                      g_logout_why, kLogoutPendingMs / 1000);
        }
        return;
    }
    // salida-en-carga.md §4: a move left open first (window A), natively.
    if (g_close_session != s2) {
        g_close.reset();
        g_close_session = s2;
    }
    if (!close_open_move()) return;
    if (!final_save_step()) return;
    const uint64_t now = now_ms();
    if (!g_logout_pacer.due(now)) return;
    g_logout_pacer.attempted(now);
    if (const inj::Outcome o = server_inject_ex(troc::make_logout_session_req()); o != inj::Outcome::Queued) {
        uint32_t count = 0;
        if (g_logout_pacer.failed_should_log(now, count)) {
            log::error("Session2: user 2's logout ({}): LogoutSessionToServerReq 2001 COULD NOT be queued for the "
                       "server ({}; {} failed attempt(s) since the last line, {} so far); {}",
                       g_logout_why, inj::outcome_name(o), count, g_logout_pacer.attempts(),
                       g_logout_pacer.exhausted() ? "GIVING UP (the barrier will quarantine)"
                                                  : "retried every 250 ms at most");
        }
        return;
    }
    g_logout_handed.store(s2);
    g_n.logout_injected.fetch_add(1);
    if (const uint32_t e = g_want_epoch.load(); e < kEpochSlots) g_logout_count[e].fetch_add(1);
    log::info("Session2: user 2's logout ({}): LogoutSessionToServerReq 2001 queued for the server (the client "
              "NetworkThread hands it in order); it then runs its own logout",
              g_logout_why);
}

}  // namespace

void server_logout_user2(const std::string& why, bool final_save) {
    if (!g_logout_asked.exchange(true)) {
        g_logout_pacer.reset();
        g_final.reset();
        g_final_logged = false;
        if (final_save) g_final.arm();
        observer_milestone_on_logout();  // P8 S2: an undecided trip gets no 2322
        g_logout_why = why;
        g_logout_asked_ms.store(GetTickCount64());
        log::info("Session2: user 2's logout asked for ({}){}", why,
                  server_user2_present() ? "" : "; user 2 does not exist yet: it goes when it does");
    }
    hand_logout();
}

void server_logout_tick() { hand_logout(); }

bool server_logout_requested() { return g_logout_asked.load(); }

bool server_logout_supported() { return g_channel[troc::kOpLogoutSessionReq] < kBlocked; }

bool server_opcode_blocked(uint16_t opcode) { return g_channel[opcode] == kBlocked; }
bool server_opcode_known(uint16_t opcode) { return g_channel[opcode] != kNotReq; }

std::deque<std::vector<uint8_t>> server_take_outgoing() {
    auto publication = observer_hold_acks_publication_guard();
    auto packets = g_outgoing.take_all();
    if (publication.owns_lock()) {
        std::erase_if(packets, [](auto& packet) { return !observer_hold_acks_filter_retired(packet); });
    }
    return packets;
}
bool server_prune_retired_outgoing() noexcept {
    auto publication = observer_hold_acks_publication_guard();
    if (!publication.owns_lock()) return true;
    // Después de marcar tombstones no puede fallar una reinserción: se compacta
    // la cola existente sin reservar memoria y sin alterar el orden de los vivos.
    g_outgoing.filter_in_place([](auto& packet) noexcept {
        return observer_hold_acks_filter_retired(packet);
    });
    return true;
}
bool server_outgoing_lost() { return g_outgoing_lost.load(); }
size_t server_outgoing_bytes() { return g_outgoing.bytes(); }

// ---------------------------------------------------------------- C4: guest epochs (reconnect)

uint32_t server_epoch() { return g_want_epoch.load(); }

bool server_begin_epoch(uint32_t epoch, bool forget_user2_keys) {
    auto publication = observer_hold_acks_publication_guard();
    if (epoch >= kEpochSlots || epoch != g_want_epoch.load() + 1) return false;
    // First: no session 2 is live until the server thread built the new one
    // (live_session2), and what the old one still writes is dropped (take_frame).
    g_want_epoch.store(epoch);
    {
        // The barrier waited for an empty queue; anything left belonged to the old epoch.
        std::lock_guard lock(g_q_mu);
        g_q_cleared.fetch_add(g_q.drop_other_epochs(epoch));
        g_q_size.store(g_q.size(), std::memory_order_release);
    }
    g_logout_asked.store(false);
    g_logout_handed.store(0);
    g_logout_asked_ms.store(0);
    g_logout_why.clear();
    g_final.reset();  // P8 S25 phase B
    g_final_logged = false;
    g_outgoing.clear();
    horse_follow_on_epoch();  // P8 F2: user 2's keys of the old epoch
    attach_follow_on_epoch();  // P8 session 8: the attachments and the registry of the old epoch
    combat_follow_on_epoch();  // P8 session 9 C1: the engaged enemies of the old epoch
    g_outgoing_lost.store(false);
    g_user2_player.store(0);
    // P8 re-entry (s25/reentrada.md §2.2 H4), only with rejoin on (review of c4367f8, 6): the previous user 2's user
    // key and the host client's guards for its keys. The new user 2's MainUserDataStartAck 2646 /
    // MainPlayerDataStartAck 2756 set them again before any of its actors exists (take_frame above), as at the first
    // login.
    if (forget_user2_keys) {
        g_user2_userkey.store(0);
        net::puppet_guard_also_key(0);
        net::horse_diag_also_key(0);
        net::puppet_guard_owner(0);
        net::horse_diag_owner(0);
    }
    {
        std::lock_guard lock(g_mirror_mu);
        g_mirror.clear();
    }
    // salida-en-carga.md §4: the new user 2's move phase starts from nothing.
    phase_reset();
    g_close.reset();
    g_close_session = 0;
    g_nak.store(0);
    g_nak_after_logout.store(0);
    identity_fix_new_epoch();  // C2: the new user 2 starts without the old one's state
    observer_milestone_on_epoch(epoch, "a new guest epoch");  // P8 S2: nothing pending carries over
    observer_hold_acks_clear(oha::Discard::Epoch);            // P8 S3: nothing held carries over
    observer_scene_copy_on_epoch(epoch);                      // P8: user 2's scenes start again
    observer_seq_copy_on_epoch(epoch);                        // P8 S1 option A: the trip's copies end
    return true;
}

uintptr_t server_epoch_session(uint32_t epoch) {
    return epoch < kEpochSlots ? g_epoch_session[epoch].load(std::memory_order_acquire) : 0;
}

bool server_logout_handed() { return g_logout_handed.load() != 0; }

bool server_capture_user2(DepartedSnap& snap) {
    uintptr_t user = 0;
    // p8-tunel-rendimiento.md: the C4 readings use probe_read (no VirtualQuery by default).
    const auto sam = profile::sam_ptr(g_base, [](uintptr_t a) { return probe_ptr(a); });
    if (!session_user(live_session2(), user) || !sam) return false;
    capture_departed(*sam, user, snap);
    // The character key of its MainPlayerDataStartAck (E4/E3b) too, if it resolves.
    const uint32_t k = g_user2_player.load();
    if (k && snap.keys.size() < kMaxDepartedKeys && std::find(snap.keys.begin(), snap.keys.end(), k) == snap.keys.end() &&
        sam_key_resolves(*sam, k) == std::optional<bool>(true)) {
        snap.keys.push_back(k);
    }
    return true;
}

bool server_host_field(FieldSnap& out) {
    out = FieldSnap{};
    uintptr_t host = 0;
    if (!server_host_user(host)) return false;
    // The probe's path (server_probe_log `where`): [user+0xD0] main character,
    // TS = [[pj+0x68]+0x1A0], field = [TS+build FieldMover+0x10].
    const auto key = probe<uint32_t>(host + off::kUser_Key);
    const auto pj = probe_ptr(host + c4::kUserMainCharacter);
    const auto c68 = pj ? probe_ptr(*pj + 0x68) : std::nullopt;
    const auto ts = c68 ? probe_ptr(*c68 + 0x1A0) : std::nullopt;
    const auto field = ts ? probe_ptr(*ts + runtime_field_layout().ts_field_mover + fld::kFmField) : std::nullopt;
    if (!key || !field || !read_field(*field, out)) return false;
    out.host_key = *key;
    out.ok = true;
    return true;
}

void server_barrier_read(uint32_t epoch, const DepartedSnap& snap, BarrierReadings& r) {
    // p8-tunel-rendimiento.md: each reading timed (diagnostics); probe_read, no VirtualQuery by default.
    uint64_t t = cdmp::now_us();
    auto lap = [&t](uint64_t& into) {
        const uint64_t n = cdmp::now_us();
        into += n - t;
        t = n;
    };
    // a. Our own session object (alive for good): its +0x90.
    if (const uintptr_t s = server_epoch_session(epoch)) {
        const auto u = probe<uintptr_t>(s + off::kSession_User);
        r.session_read = u.has_value();
        r.session_user = u.value_or(0);
        // Diagnostics (salida-en-carga.md §2): while the user is still attached
        // (and still a ServerUserActor), what its logout waits for. Read only.
        if (r.session_user) {
            const auto vt = probe_ptr(r.session_user);
            r.move_diag = vt && *vt == g_base + addr(off::kServerUserActorVtable)
                              ? read_move_diag(r.session_user).describe()
                              : std::string("attached user is no ServerUserActor any more");
        }
    }
    r.nak_after_logout = g_nak_after_logout.load();
    lap(r.us_session);
    // b. By key only: the old pointers are never followed.
    if (const auto sam = profile::sam_ptr(g_base, [](uintptr_t a) { return probe_ptr(a); })) {
        r.sam_read = true;
        for (uint32_t k : snap.keys) {
            const auto res = sam_key_resolves(*sam, k);
            if (!res) {
                r.sam_read = false;
                break;
            }
            ++r.keys_checked;
            if (*res && !r.keys_resolving++) r.first_resolving = k;
        }
        lap(r.us_keys);
        if (snap.user_key) {
            const auto listed = sam_user_listed(*sam, snap.user_key);
            if (!listed) r.sam_read = false;
            r.user_listed = listed.value_or(false);
        }
        lap(r.us_list);
    }
    // c. The host's field now, its user list read once (P8 S29, reentrada.md §6): the departed user's pointer and the
    // host's user (session 1's +0x90, the value the list stores for it) only compared, never followed.
    uintptr_t host_user = 0;
    if (server_host_field(r.field) && server_host_user(host_user) && host_user) {
        if (const auto scan = scan_field_list(r.field.field, snap.user, host_user)) {
            r.field_list_read = true;
            r.departed_in_field = scan->departed_listed;
            r.listed_actors = scan->actors;
            r.list_entries = scan->entries;
            r.foreign_entries = scan->foreign;
            r.first_foreign = scan->first_foreign;
        }
    }
    lap(r.us_field);
    // d. (the early queue is session2.cpp's)
    r.outgoing_bytes = g_outgoing.bytes();
    // Our queue to the NetworkThread counts as not yet handed, and so does a Req the NetworkThread has
    // taken from it but not pushed yet (P8 review M2: g_q_size already went down, g_pb_pushed not up yet).
    r.early += g_q_size.load() + g_in_hand.load();
    if (epoch < kEpochSlots) {
        r.pb_pushed = g_pb_pushed[epoch].load();
        r.pb_seen = g_pb_seen[epoch].load();
        r.logout_handed = g_logout_count[epoch].load();
    }
    std::lock_guard lock(g_mirror_mu);
    r.mirror_pending = g_mirror.size();
}

// Queued counts: a buffer in our queue reaches the server in order (or the epoch is halted).
bool server_epoch_reached(uint32_t epoch) { return epoch < kEpochSlots && g_pb_queued[epoch].load() > 0; }

// ---------------------------------------------------------------- P2: diagnostics (network thread)

namespace {

// The server's registered threads and their park flags (offsets_s2.h:
// ServerNet+0xF8 {u32 tid, u8* flag}[+0x100]; flag[0] park asked, [1] parked,
// [2] handling an item). Read only.
std::string server_threads_park() {
    uintptr_t net = 0, arr = 0;
    uint32_t n = 0;
    if (!peek(g_base + addr(off::kServerNetSlot), net) || !net || !peek(net + off::kServerNet_Threads, arr) || !arr ||
        !peek(net + off::kServerNet_ThreadCount, n)) {
        return "server threads unreadable";
    }
    std::string s = std::format("server threads {}:", n);
    for (uint32_t i = 0; i < n && i < 16; ++i) {
        uint32_t tid = 0;
        uintptr_t flag = 0;
        uint8_t b[3] = {};
        if (!peek(arr + i * off::kServerThreadEntry, tid) || !peek(arr + i * off::kServerThreadEntry + 8, flag) ||
            !flag || !peek(flag, b[0]) || !peek(flag + 1, b[1]) || !peek(flag + 2, b[2])) {
            s += " ?";
            continue;
        }
        s += std::format(" T{}{}{}{}", tid, b[0] ? " PARK-ASKED" : "", b[1] ? " PARKED" : "", b[2] ? " busy" : " idle");
        if (tid == g_built_tid.load()) s += "(ServerRunThread)";
    }
    return s;
}

}  // namespace

void server_inject_tick(uint64_t now) {
    // 1. Every exception caught in the game's code, loudly, once each.
    const uint32_t total = g_exc_count.load();
    while (g_exc_logged < total && g_exc_logged < kMaxExceptionNotes &&
           g_exc_ready[g_exc_logged].load(std::memory_order_acquire)) {
        const inj::ExceptionNote& e = g_exc[g_exc_logged];
        ++g_exc_logged;
        log::error("Session2 INJECT EXCEPTION #{}: {}. Injection STOPPED for good (no retry, no logout by "
                   "injection): the game's heap or queue may be damaged",
                   g_exc_logged, inj::describe(e));
        if (g_halt_reason.empty()) g_halt_reason = inj::describe(e);
    }
    if (total > kMaxExceptionNotes && g_exc_logged == kMaxExceptionNotes) {
        static uint32_t told = 0;
        if (told != total) {
            told = total;
            log::error("Session2 INJECT EXCEPTION: {} in all (only the first {} are detailed)", total,
                       kMaxExceptionNotes);
        }
    }
    if (g_halted_epoch.load()) {
        if (g_halt_reason.empty()) g_halt_reason = "the game's allocator returned no buffer";
        if (g_q_size.load()) {
            std::lock_guard lock(g_q_mu);
            g_q_cleared.fetch_add(g_q.clear());
            g_q_size.store(0, std::memory_order_release);
        }
        return;
    }
    // 2. The server not taking our buffers (a host pause, a stuck server thread).
    const uint32_t e = g_want_epoch.load();
    if (e < kEpochSlots) {
        const uint64_t pushed = g_pb_pushed[e].load(), seen = g_pb_seen[e].load();
        switch (g_server_watch.update(now, seen, pushed > seen)) {
            case inj::StallWatch::Event::Enter:
            case inj::StallWatch::Event::Still:
                log::warn("Session2 inject: the server has not taken our buffers for {} ms (epoch {}: handed {}, "
                          "seen {}, {} more held in our queue; user 2 is NOT logged out for this) | {}",
                          g_server_watch.stalled_ms(now), e, pushed, seen, g_q_size.load(), server_threads_park());
                break;
            case inj::StallWatch::Event::Exit:
                log::info("Session2 inject: the server takes our buffers again after {} ms (handed {}, seen {})",
                          g_server_watch.stalled_ms(now), pushed, seen);
                break;
            case inj::StallWatch::Event::None:
                break;
        }
    }
    // 3. The NetworkThread not turning while something waits for it.
    switch (g_pump_watch.update(now, g_pump_turns.load(), g_q_size.load() > 0)) {
        case inj::StallWatch::Event::Enter:
        case inj::StallWatch::Event::Still:
            log::warn("Session2 inject: the client NetworkThread has not turned for {} ms ({} Req waiting, turns {}, "
                      "thread {})",
                      g_pump_watch.stalled_ms(now), g_q_size.load(), g_pump_turns.load(), g_pump_tid.load());
            break;
        case inj::StallWatch::Event::Exit:
            log::info("Session2 inject: the client NetworkThread turns again after {} ms",
                      g_pump_watch.stalled_ms(now));
            break;
        case inj::StallWatch::Event::None:
            break;
    }
    // 4. Our queue at its bound (the guest's Req are held, in order).
    if (const uint64_t full = g_held_full.load(); full != g_full_logged_count && now - g_full_logged_at >= 5000) {
        size_t kb = 0;
        {
            std::lock_guard lock(g_q_mu);
            kb = g_q.bytes() >> 10;
        }
        log::warn("Session2 inject: our queue is full ({} Req, {} KB): {} offers held since the last line (kept in "
                  "order by the network thread)",
                  g_q_size.load(), kb, full - g_full_logged_count);
        g_full_logged_count = full;
        g_full_logged_at = now;
    }
}

bool server_inject_halted() { return g_halted_epoch.load() != 0; }

std::string server_inject_halt_reason() {
    return g_halt_reason.empty() ? std::string("an exception inside the game's code") : g_halt_reason;
}

size_t server_inject_pending() { return g_q_size.load(); }

std::string server_inject_describe() {
    const uint64_t handed = g_pump_handed.load();
    size_t peak = 0;
    {
        std::lock_guard lock(g_q_mu);
        peak = g_q.peak();
    }
    std::string s = std::format(
        "inject queue: waiting {} (peak {}) | handed by the NetworkThread {} (thread {}, turns {}, wait mean {} ms max "
        "{} ms, batch max {}, not yet taken max {}) | held: not ready {} full {} | stale {} cleared {}",
        g_q_size.load(), peak, handed, g_pump_tid.load(), g_pump_turns.load(), handed ? g_pump_wait_sum.load() / handed : 0,
        g_pump_wait_max.load(), g_pump_batch_max.load(), g_pump_inflight_max.load(), g_held_not_ready.load(),
        g_held_full.load(), g_pump_stale.load(), g_q_cleared.load());
    if (g_pump_other_net.load()) s += std::format(" | other ClientNet/errors {}", g_pump_other_net.load());
    if (g_pump_not_ready.load()) {
        s += std::format(" | turns without session 2's server (nothing handed) {}", g_pump_not_ready.load());
    }
    if (g_global_heap_flag.load())
        s += std::format(" | TLS+0x{:X} set (global heap used) {}", profile::tls_heap_selector_offset(),
                         g_global_heap_flag.load());
    if (const uint32_t x = g_exc_count.load()) s += std::format(" | EXCEPTIONS {} (HALTED)", x);
    else if (g_halted_epoch.load()) s += " | HALTED";
    return s;
}

std::string server_epoch_describe() {
    const uint32_t e = g_want_epoch.load();
    std::string s = std::format("session 2 epoch {} ({}) | its buffers {} handed {} seen", e,
                                g_session_epoch.load() == e ? "built" : "being built",
                                e < kEpochSlots ? g_pb_pushed[e].load() : 0, e < kEpochSlots ? g_pb_seen[e].load() : 0);
    if (g_stale_routed.load() || g_untagged_routed.load() || g_late_out.load()) {
        s += std::format(" | old-epoch buffers routed to their own session {} untagged {} | old sessions' output "
                         "dropped {}",
                         g_stale_routed.load(), g_untagged_routed.load(), g_late_out.load());
    }
    if (g_friendly_fire_dropped.load()) s += std::format(" | hits between the players' sides dropped {}", g_friendly_fire_dropped.load());
    if (g_after_host_goodbye.load() || g_seq_event_no_manager.load()) {
        s += std::format(" | after the host's goodbye: Reqs not handled {}, events without an owner {}",
                         g_after_host_goodbye.load(), g_seq_event_no_manager.load());
    }
    return s;
}

std::string server_describe() {
    std::string s = std::format(
        "session 2 {}{}{} | user 2 {} | in: handed {} refused {} blocked {} exceptions {} seen by the server {} | "
        "out: {} packets, {} unreadable{} | save Req seen {}",
        live_session2() ? "ready" : (g_want_session.load() ? "pending" : "off"),
        g_create_failed.load() ? " (CREATION FAILED)" : "",
        g_rebuilt.load() ? std::format(" (rebuilt {}x: the server restarted)", g_rebuilt.load()) : std::string(),
        server_user2_present() ? "logged in" : "no", g_n.injected.load(), g_n.inject_refused.load(),
        g_n.inject_blocked.load(), g_n.inject_failed.load(), g_n.recv_ours.load(), g_n.sent_out.load(),
        g_n.sent_bad.load(), g_outgoing_lost.load() ? " (SOME LOST)" : "", g_n.save_reqs.load());
    s += " | " + server_inject_describe();
    if (const int64_t slot = g_host_slot.load(); slot >= 0) s += std::format(" | host save slot {}", slot);
    if (g_logout_asked.load()) {
        s += std::format(" | user 2 logout asked (2001 handed {}, logout Acks out {}, Req refused after it {}, "
                         "MoveFieldCompleteReq closed before it {}, Nak 1013 {} / after the 2001 {})",
                         g_n.logout_injected.load(), g_n.logout_acks.load(), g_n.inject_after_logout.load(),
                         g_n.move_close_injected.load(), g_nak.load(), g_nak_after_logout.load());
    }
    s += " | user 2 move phase " + phase_snapshot().describe();
    if (const uint32_t k = g_user2_player.load()) s += std::format(" | user 2 character 0x{:08X}", k);
    if (const uint64_t r = g_owner_rewrites.load(); r || g_owner_unexpected.load()) {
        s += std::format(" | MoveFieldAck owner -> user 2: {} (unknown layout {})", r, g_owner_unexpected.load());
    }
    if (const uint64_t r = g_load_owner_rewrites.load(); r || g_load_owner_unexpected.load() || g_load_owner_other.load()) {
        s += std::format(" | LoadingFieldDataAck 2643 owner -> user 2: {} (unknown layout {}, left as written {})", r,
                         g_load_owner_unexpected.load(), g_load_owner_other.load());
    }
    // The opcodes for user 2 that carry the host's user key, most frequent first (top 8).
    {
        std::vector<std::pair<uint32_t, uint16_t>> ops;
        for (size_t i = 0; i < g_hostkey_ops.size(); ++i) {
            if (const uint32_t c = g_hostkey_ops[i].load(std::memory_order_relaxed)) {
                ops.emplace_back(c, static_cast<uint16_t>(i));
            }
        }
        if (!ops.empty()) {
            std::sort(ops.begin(), ops.end(), std::greater<>());
            s += " | to user 2 with the host's key:";
            for (size_t i = 0; i < ops.size() && i < 8; ++i) s += std::format(" {}x{}", ops[i].second, ops[i].first);
        }
    }
    if (g_opt.mirror_host) {
        s += std::format(" | mirror copied {} dropped {}", g_mirror_copied.load(), g_mirror_dropped.load());
    }
    if (const std::string f = server_finder_describe(); !f.empty()) s += " | " + f;
    return s;
}

std::string server_finder_describe() {
    if (!g_control_hook && !g_self_hook) return {};
    return std::format("finders control {}/{} nonempty, {} relayed, {} errors; self {}/{} nonempty, {} relayed, {} errors",
                       g_n.finder_nonempty[0].load(), g_n.finder_calls[0].load(), g_n.finder_relayed[0].load(),
                       g_n.finder_errors[0].load(), g_n.finder_nonempty[1].load(), g_n.finder_calls[1].load(),
                       g_n.finder_relayed[1].load(), g_n.finder_errors[1].load());
}

}  // namespace cdmp::session2
