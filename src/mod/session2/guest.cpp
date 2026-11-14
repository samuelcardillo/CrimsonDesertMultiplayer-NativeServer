#include "mod/session2/guest.h"
#include "common/native_opcode.h"
#include "mod/game/build_profile.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <deque>
#include <cstring>
#include <format>
#include <mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/troc_frame.h"
#include "mod/game/game_errors.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/attach_follow.h"
#include "mod/session2/clock_push.h"
#include "mod/session2/docked_gimmicks.h"
#include "mod/session2/guest_shop_branch.h"
#include "mod/session2/docking_dedupe_logic.h"
#include "mod/session2/guest_actor_diag.h"
#include "mod/session2/guest_reload_wait.h"
#include "mod/session2/guest_bodyanim_diag.h"
#include "mod/session2/guest_diag_worker.h"
#include "mod/session2/guest_goodbye_logic.h"
#include "mod/session2/guest_inbound_logic.h"
#include "mod/session2/guest_s3.h"
#include "mod/session2/guest_save_guest.h"
#include "mod/session2/guest_save_logic.h"
#include "mod/session2/guest_scene_diag.h"
#include "mod/session2/guest_sched_load.h"
#include "mod/session2/guest_seq_play.h"
#include "mod/session2/guest_seq_restore.h"
#include "mod/session2/guest_seq_foreign.h"
#include "mod/session2/guest_seq_present.h"
#include "mod/session2/guest_seq_route.h"
#include "mod/session2/guest_stage_diag.h"
#include "mod/session2/guest_x_interaction.h"
#include "mod/session2/shop_trade_probe.h"
#include "mod/session2/guest_x_veto.h"
#include "mod/session2/guest_x_veto_logic.h"
#include "mod/session2/load_trip.h"
#include "mod/session2/focus_follow.h"
#include "mod/session2/focus_follow_logic.h"
#include "mod/session2/mount_sync.h"
#include "mod/session2/mount_sync_logic.h"
#include "mod/config.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/profile_s2.h"
#include "mod/session2/npc_probe_client.h"
#include "mod/session2/door_trace.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/preload_release_logic.h"
#include "mod/session2/reannounce_logic.h"
#include "mod/session2/rejoin_logic.h"
#include "mod/session2/remote_interp.h"
#include "mod/session2/vehicle_follow.h"
#include "mod/session2/remote_visible.h"
#include "mod/session2/ride_filter.h"
#include "mod/session2/report_guard.h"
#include "mod/session2/slot_refresh.h"
#include "mod/session2/ui_pause_logic.h"
#include "mod/session2/tree_bend.h"
#include "mod/session2/tree_bend_logic.h"
#include "mod/session2/weather_sync.h"

namespace cdmp::session2 {
namespace {

inline uintptr_t addr(uintptr_t legacy_rva) noexcept { return profile::rva(legacy_rva); }

using OnRecvFn = void(__fastcall*)(void* net, void* session, uint64_t unused, const uint8_t* pkt, uint16_t size);
using PushFn = void(__fastcall*)(void* queue, void** item);

constexpr uint16_t kOpConnectCryptogramToServerReq = 2319;
constexpr uint64_t kNoEpoch = 0x7FFFFFFFFFFFFFFFull;  // what PostPacket writes without a session
constexpr uint32_t kHostReadyFreshMs = 3000;

// G2/G3 (p8-preparacion.md §3): what is only counted and logged, never changed.
constexpr uint16_t kOpScopeSenderAck = 2042;
constexpr uint16_t kOpActorAppear = 2005;
constexpr uint16_t kOpDataAck = 2869;
constexpr uint16_t kOp2679 = 2679;
constexpr uint16_t kOpLoginCharacterToFieldServerReq = 3093;  // u8 | u64 characterNo @1 | u32 slot @9
constexpr uint16_t kOpReserveShutDownServerReq = 2790;
// g_ServerFrameworkMode (opcion-d-d0.md §1.1): the u32 the host's server writes
// into its 2002 (0x1051F1E0); the client uses it as PostPacket's index (§1.3).
constexpr uintptr_t kServerFrameworkMode = 0x6A65564;
inline uintptr_t server_framework_mode_rva() noexcept {
    // ServerUserActor::vf58 -> its 2002 writer loads this scalar. In 3527 the
    // writer is 0xE552AB0 and the RIP operand resolves to 0x6EAB858; live = 4.
    // 3576 (static, 2026-11-06; not yet run): 0x6EAD858 (the Troc block's +0x2000). The 2002 writer is protected code
    // again; plain code reads it as the same index: ServerNet::OnRecvPacket 0x29AC4EE `mov r8d,[0x6EAD858]` between
    // the Troc registry 0x161ED50 and Troc::Find 0x161EDB0 (op, index), and the server set-up's switch 0x29FCAB8.
    // Build 1.0.0.3663 (static, 2026-11-13; never run): 0x6F29B70. OnRecvPacket 0x2A0EA70 reads it at the same +0xAE
    // (0x2A0EB1E `mov r8d,[0x6F29B70]`) between the Troc registry 0x165FA60 and Troc::Find 0x165FAC0; the server set-up
    // 0x2A5E840 reads it at the same +0x1318 (0x2A5FB58) and plain code writes it: `mov dword [0x6F29B70],4` (0x2A5E899,
    // 3527's live value); 59 sites read it.
    if (game::current_build() == game::Build::v2976) return kServerFrameworkMode;
    if (game::current_build() == game::Build::v3527) return 0x6EAB858;
    if (game::current_build() == game::Build::v3576) return 0x6EAD858;
    if (game::current_build() == game::Build::v3663) return 0x6F29B70;
    return 0;
}
constexpr uint64_t kMaxDecisionLogged = 32, kMaxInternalLogged = 16, kMaxLoginLogged = 8;

uintptr_t g_base = 0;
bool g_remote_allowed = false;  // guest_mode: observe (default) or remote
// The transport hooks and the two crash guards install on separate threads.
// A remote decision is fail-closed until every requested pre-login guard has
// actually installed its hook. The remote-update guard is intentionally not
// included: it needs the local user key, which exists only after login.
std::atomic<bool> g_layer_guard_requested{false};
std::atomic<bool> g_update_guard_requested{false};
std::atomic<bool> g_remote_guard_requested{false};
OnRecvFn g_on_recv = nullptr;
PushFn g_push = nullptr;
SafetyHookInline g_send_hook;
SafetyHookMid g_pump_hook;

// State of the client's connections (NetworkThread, except where noted).
enum class Mode : uint8_t { Undecided, Local, Remote, Over };
std::atomic<bool> g_active{false};
std::atomic<uint64_t> g_epoch{0};
std::atomic<Mode> g_mode{Mode::Local};
std::atomic<bool> g_had_remote{false};  // a remote connection happened in this game run (re-entry: rejoin_logic.h)
std::atomic<bool> g_broken{false};      // the remote connection lost something: deliver nothing more
uintptr_t g_q3 = 0;                     // validated when the remote connection starts

// From the network thread: the tunnel and the host's readiness (control packets).
std::atomic<bool> g_tunnel_up{false};
std::atomic<uint64_t> g_host_ready_ms{0};
std::atomic<bool> g_host_dead{false};

troc::PacketQueue g_to_host(32u << 20);

// P8 re-entry (rejoin_logic.h, docs/research/s25/reentrada.md §3): [session2] rejoin on the guest. g_rj is touched by
// the NetworkThread (decide, a new conversation, a local 3093), the mod's network thread (EPOCH / ready / 2002 frames,
// the REJOIN requests) and the HUD's caller: under g_rj_mu, never while calling the game.
std::mutex g_rj_mu;
rjl::GuestRejoin g_rj;          // under g_rj_mu
std::string g_rj_last_why;      // under g_rj_mu: the last re-entry decision's reason (the HUD)
std::atomic<uint8_t> g_rj_mode{0};
// The remote conversations of this run (1 = the first): guest_conversation_id(). Modules with state of one remote
// conversation compare it on their own thread and start again when it changes.
std::atomic<uint32_t> g_conversation{0};
// The host's "ready" frames, counted; the count when the last remote conversation ended (B2: a ready of the old
// conversation never makes the host look ready for a new connection).
std::atomic<uint64_t> g_ready_count{0}, g_ready_floor{0};
std::atomic<uint64_t> c_rj_sent{0}, c_rj_epochs{0};
uint64_t g_rj_lines = 0;  // the mod's network thread
constexpr uint64_t kRjLines = 40;

// P8 mounts (mount_sync.h): this client's own MountBegin / MountCommit / MountDetach, into the queue to the host
// BEFORE the client's next packet (so a Begin precedes every Req its vf53 call emitted). Two drainers: the
// NetworkThread (guest_send: blocking, and its own packet goes in inside the same step) and the mod's network
// thread (guest_take_outgoing: try only, when the client is idle). msl::OutboundDrain makes each pop + push one step
// (no event overtakes another, no Req overtakes its Begin) and keeps a refused event to offer it again first.
msl::OutboundDrain g_mount_drain;
std::atomic<uint64_t> g_mount_drain_logged{0};  // failures already logged (the mod's network thread)
// focus_follow's state goes the same way: one frame at most, its order against the rest does not matter.
bool pop_mount_event(std::vector<uint8_t>& f) { return mount_sync_pop_outbound(f) || focus_follow_pop_outbound(f); }
bool push_to_host(const std::vector<uint8_t>& f) { return g_to_host.push(f); }
void flush_mount_events() noexcept {
    try {
        g_mount_drain.drain(pop_mount_event, push_to_host, /*blocking=*/false);
    } catch (...) {
    }
}

// The host's packets for the client (guest_inbound_logic.h): queued by the
// mod's network thread (guest_deliver, no game call there), handed to
// ClientNet::OnRecvPacket only by the client NetworkThread (guest_pump at
// 0x35BAD4), at most gin::kMaxPerTurn per turn, oldest first.
std::mutex g_in_mutex;
gin::InboundQueue g_from_host;  // under g_in_mutex
gin::DeliveryStats g_in_stats;  // under g_in_mutex
// Which thread does the client's network work (the pump claims it), and the
// mod's network thread (only for the record).
gin::ThreadOwner g_net_owner;
std::atomic<uint32_t> g_mod_net_tid{0};
std::atomic<uint64_t> g_turns{0}, g_send_calls{0};
std::atomic<bool> g_owner_logged{false};

uint64_t now_us() {
    static const int64_t freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return f.QuadPart ? f.QuadPart : 1;
    }();
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return static_cast<uint64_t>(t.QuadPart / freq * 1000000 + t.QuadPart % freq * 1000000 / freq);
}

void clear_from_host() noexcept {
    try {
        std::lock_guard lk(g_in_mutex);
        g_from_host.clear();
    } catch (...) {
    }
}

// The client's goodbye when the host can no longer answer it (live P8
// 2026-10-09: the host's game closed, the link BROKE, the guest's 2001 was
// dropped and its client waited on the loading screen until Alt+F4). The
// native answers are what the host's server sent the first time that day:
// 2003 then 2002, 7 bytes each, u32 = this process's g_ServerFrameworkMode
// ("D3 07 FF 04 00 00 00", "D2 07 FF 04 00 00 00", index 4 = own 4).
std::atomic<uint64_t> g_goodbye_ms{0};      // when the client's 2001 went out (0 = none pending)
std::atomic<bool> g_goodbye_answered{false};  // an answer (the host's or ours) reached the client
// P8 session 6 (pendientes/p8-salida-invitado.md): with a field of the host
// loaded, the local answer crashed the client at exe+0x2045A6A (its own user,
// the field's owner, deleted before the field); there the process ends instead
// (guest_goodbye_logic.h). The last packet of the host's server through the
// tunnel tells "still unloading" from "silent".
std::atomic<uint64_t> g_last_in_ms{0};
std::atomic<bool> g_goodbye_ending{false};  // once: the line and TerminateProcess
// [session2] guest_goodbye_end (P8 review M10; default 1, a documented exception to
// the default-off rule): 0 = never TerminateProcess, the client keeps waiting.
std::atomic<bool> g_goodbye_end_on{true};
std::atomic<bool> g_goodbye_end_off_logged{false};
constexpr UINT kGoodbyeExitCode = 0x2001;    // the process's exit code when it ends here
// B1 (pendientes/p8-s9-cinematica.md §7.5, §8; review 5): [session2] guest_local_after_remote = allow | stuck
// (default allow). With stuck, a save loaded on this PC's own server (its 3093 on a local connection) after this run
// already played on the host's server ends the game only when the load is SEEN stuck (gxv::LocalLoadWatch: no 2549
// 45 s after the 3093 and the same loading state for 20 s); in session 9 it stayed in state 0x0C until Alt+F4.
// guest_send (the NetworkThread) only stamps the frames; the diagnostics thread decides (guest_local_load_watch).
std::atomic<uint8_t> g_local_after_remote{static_cast<uint8_t>(gxv::LocalAfterRemote::Allow)};
std::atomic<uint64_t> g_ll_3093_ms{0}, g_ll_2549_ms{0};  // the last local 3093 / 2549 after a remote connection
std::atomic<uint64_t> g_ll_epoch{0};                    // the local connection of that 3093
std::atomic<bool> g_local_ending{false};                // once: the line and TerminateProcess
constexpr UINT kLocalAfterRemoteExitCode = 0x2003;
gxv::LocalLoadWatch g_ll_watch;                         // the diagnostics thread only
uint64_t g_ll_seen_3093 = 0, g_ll_seen_2549 = 0;        // the diagnostics thread only

// P8 title (pendientes/p8-titulo.md): the guest's own slot table, rebuilt
// with the game's refresh when its 2490 goes to the host (its local server
// never runs UserLogin). Armed by guest_send, run by guest_pump (both the
// NetworkThread); the diagnostic is armed by the install thread.
namespace sr = slot_refresh;
constexpr uint16_t kOpLoginUserToFieldServerReq = 2490;
constexpr uint64_t kSlotTestKey = ~0ull;  // the diagnostic's own key (never an epoch PostPacket writes)
std::mutex g_refresh_mutex;
sr::Planner g_refresh;                   // under g_refresh_mutex
std::atomic<bool> g_refresh_wanted{false};  // the pump's fast path
bool g_slot_test = false;                // [session2] guest_slot_refresh_test
std::atomic<bool> g_local_login_out{false};  // the client's 2490 went to its own server (observe/local)
int g_refresh_code = 0;                  // NetworkThread: 0 = not checked, 1 = the expected code, -1 = not
std::atomic<uint32_t> g_refresh_done{0}, g_refresh_last_count{0};
std::atomic<bool> g_refresh_stopped{false};

struct Counters {
    std::atomic<uint64_t> sent{0}, delivered{0}, bad_frames{0}, deliver_errors{0}, dropped{0}, observed{0};
    std::atomic<uint64_t> kept_local{0};  // C4: 2790 never sent to the host
    std::atomic<uint32_t> remote{0}, local{0};
    std::atomic<uint16_t> first_op{0};
    // G2: the logout messages (out 2001, in 2002/2003) and the 2002's index
    // against this process's own g_ServerFrameworkMode.
    std::atomic<uint64_t> out_2001{0}, in_2002{0}, in_2003{0};
    std::atomic<uint32_t> last_2002_index{0}, own_mode{0};
    std::atomic<int> index_match{-1};  // -1 = no 2002 yet / own mode unreadable, 0 = differs, 1 = equal
    // G3: what was delivered to ClientNet::OnRecvPacket, and the guest's own 3093.
    std::atomic<uint64_t> in_2042{0}, in_2005{0}, in_2869{0}, in_2679{0};
    std::atomic<uint64_t> out_3093{0}, last_character_no{0};
    std::atomic<uint32_t> last_3093_slot{0};
    std::atomic<uint64_t> decision_logged{0}, internal_logged{0}, login_logged{0}, first_2042_logged{0};
} g_n;
// P8 re-entry (s25/reentrada.md §1.1 B5): what belongs to the CURRENT remote conversation (g_n is per run): reset by
// guest_conversation_begin.
struct ConversationCounters {
    std::atomic<uint64_t> out_3093{0};  // "a field of the host is loaded" (the goodbye rule) and the own save's sent_3093
} g_conv;

template <class... Args>
void note(std::atomic<uint64_t>& counter, uint64_t cap, std::format_string<Args...> fmt, Args&&... args) {
    if (counter.fetch_add(1) >= cap) return;
    log::info(fmt, std::forward<Args>(args)...);
}

std::string hex_bytes(std::span<const uint8_t> p, size_t max = 16) {
    std::string s;
    for (size_t i = 0; i < p.size() && i < max; ++i) s += std::format("{}{:02X}", i ? " " : "", p[i]);
    if (p.size() > max) s += " ...";
    return s;
}

uint16_t opcode_of(std::span<const uint8_t> p) {
    return p.size() >= 2 ? static_cast<uint16_t>(p[0] | (p[1] << 8)) : uint16_t{0};
}

template <class T>
bool peek(uintptr_t addr, T& out) {
    __try {
        out = *reinterpret_cast<const T*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
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

bool guarded_push(uintptr_t queue, uintptr_t item) {
    __try {
        void* p = reinterpret_cast<void*>(item);
        g_push(reinterpret_cast<void*>(queue), &p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool guarded_on_recv(uintptr_t net, uintptr_t session, const uint8_t* pkt, uint16_t size) {
    __try {
        g_on_recv(reinterpret_cast<void*>(net), reinterpret_cast<void*>(session), 0, pkt, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool host_ready() {
    const uint64_t at = g_host_ready_ms.load();
    return g_tunnel_up.load() && !g_host_dead.load() && at && GetTickCount64() - at < kHostReadyFreshMs &&
           g_ready_count.load() > g_ready_floor.load();
}

rjl::Mode rj_mode() noexcept { return static_cast<rjl::Mode>(g_rj_mode.load(std::memory_order_relaxed)); }

// P8 re-entry: the current remote conversation is over (the host answered the goodbye, or the connection stopped).
// Any thread. The first notice only: the old "ready" stops counting, and with rejoin the requests start.
void rejoin_over(const char* why) noexcept {
    try {
        bool changed = false;
        rjl::Phase phase = rjl::Phase::NoRemote;
        uint32_t conv = 0, asking = 0;
        bool capable = false;
        {
            std::lock_guard lk(g_rj_mu);
            changed = g_rj.on_remote_over(GetTickCount64());
            phase = g_rj.phase();
            conv = g_rj.conversation();
            asking = g_rj.asking();
            capable = g_rj.host_capable();
        }
        if (!changed) return;
        g_ready_floor.store(g_ready_count.load());
        const rjl::Mode m = rj_mode();
        log::info("Session2 guest rejoin [{}]: remote conversation {} is over ({}) | {}", rjl::mode_name(m), conv, why,
                  phase == rjl::Phase::Asking
                      ? std::format("asking the host for conversation {} (REJOIN every {} ms, at most {}){}", asking,
                                    rjl::kRetryMs, rjl::kMaxAsks, m == rjl::Mode::Probe ? " - probe" : "")
                  : m == rjl::Mode::Off ? std::string("rejoin=0: the next connection stays local, as before")
                  : !capable ? std::string("the host never sent its C4 state (control state 14): an older host or its "
                                           "rejoin=0; the next connection stays local")
                             : std::string(rjl::phase_name(phase)));
    } catch (...) {
    }
}

// Stops delivering for this connection (anything already queued is from it).
void end_remote(const char* why) noexcept {
    if (!g_broken.exchange(true)) {
        clear_from_host();
        mount_sync_reset("the connection to the host stops");  // P8 mounts (review (7))
        docked_gimmicks_guest_reset("the connection to the host stops");  // P8 S28: own key, user, local-only keys
        try {
            log::error("Session2 guest: the connection to the host's server stops: {}", why);
        } catch (...) {
        }
        // P8 re-entry: with rejoin on, this client's own key on the host goes with the remote session (B9).
        if (rj_mode() != rjl::Mode::Off) mount_sync_forget_local_key();
        rejoin_over(why);
    }
}

// P8 re-entry (s25/reentrada.md §1.4): a client connection was decided REMOTE. The client NetworkThread (guest_send),
// before the connection's first packet is queued. What belongs to one remote conversation starts again here; the
// modules whose state lives on other threads compare guest_conversation_id() there and start again themselves.
// Review of c4367f8, 6: the first remote conversation (and so rejoin=0) only counts it; everything else is for a
// re-entry conversation.
void preload_release_reset() noexcept;

void guest_conversation_begin(uint64_t epoch) noexcept {
    preload_release_reset();
    uint32_t conv = 0;
    uint32_t granted = 0;
    try {
        std::lock_guard lk(g_rj_mu);
        granted = g_rj.phase() == rjl::Phase::Granted ? g_rj.granted_epoch() : 0;
        conv = g_rj.on_remote_begin(GetTickCount64());
        g_rj_last_why.clear();
    } catch (...) {
    }
    g_conversation.store(conv);
    // P8 S28: every remote conversation, the first included (a local world earlier in this run taught other keys and
    // another own user): the docked-gimmick keys of the old world mean nothing now.
    docked_gimmicks_guest_reset("a new remote conversation");
    if (!rjl::reentry_conversation(conv)) return;
    // B3-B5: the goodbye's safety net and "a field of the host is loaded" belong to this conversation.
    g_goodbye_ms.store(0);
    g_goodbye_answered.store(false);
    g_last_in_ms.store(0);
    g_conv.out_3093.store(0);
    size_t mount_left = 0, stale = 0;
    try {
        mount_left = g_mount_drain.discard(pop_mount_event);  // mount_sync's outbound events of the old conversation
        // Review of c4367f8, 4: nothing of the old conversation goes to the host's new epoch: only the REJOIN
        // requests stay queued (they are this one's; the host answers a late one with its state).
        for (auto& p : g_to_host.take_all()) {
            if (rjl::is_rejoin_frame(p)) {
                (void)g_to_host.push(p);
            } else {
                ++stale;
            }
        }
    } catch (...) {
    }
    guest_save_guest_conversation_begin(conv);  // B6-B8 (no new upload; the final save once per conversation)
    mount_sync_reset("a new remote conversation (re-entry)");
    mount_sync_forget_local_key();  // B9
    try {
        log::info("Session2 guest: remote conversation {} begins (client connection epoch 0x{:X}, host epoch {}): "
                  "re-entry in the same game run | goodbye state, field flag and own-save holds reset | mount events "
                  "of the old conversation dropped {} | stale frames to the host dropped {} | the other modules start "
                  "again on their threads",
                  conv, epoch, granted, mount_left, stale);
    } catch (...) {
    }
}

// The mod's network thread: the host's EPOCH frame (state 14).
void rejoin_on_epoch_frame(const std::vector<uint8_t>& packet) noexcept {
    try {
        const auto e = rjl::parse_epoch_frame(packet);
        if (!e) return;
        c_rj_epochs.fetch_add(1, std::memory_order_relaxed);
        rjl::Phase before = rjl::Phase::NoRemote, after = rjl::Phase::NoRemote;
        bool was_capable = false, would = false;
        uint32_t asking = 0;
        {
            std::lock_guard lk(g_rj_mu);
            before = g_rj.phase();
            was_capable = g_rj.host_capable();
            const bool would_before = g_rj.probe_would();
            g_rj.on_epoch(*e, GetTickCount64());
            after = g_rj.phase();
            would = !would_before && g_rj.probe_would();
            asking = g_rj.asking();
        }
        const bool log_it = !was_capable || before != after || would ||
                            (e->reason != rjl::Reason::Heartbeat && g_rj_lines < kRjLines);
        if (!log_it) return;
        ++g_rj_lines;
        log::info("Session2 guest rejoin [{}]: host EPOCH: C4 {} epoch {} ({}, for conversation {}) | {} -> {}{}",
                  rjl::mode_name(rj_mode()), rjl::host_state_name(e->state), e->epoch, rjl::reason_name(e->reason),
                  e->conversation, rjl::phase_name(before), rjl::phase_name(after),
                  after == rjl::Phase::Granted && before != after
                      ? std::format(": the client's next connection (back at the title) goes to the host once a 'ready' "
                                    "follows (conversation {})",
                                    asking)
                  : would ? std::format(" (probe: the host would begin epoch {}; nothing started)", e->epoch + 1)
                          : std::string());
    } catch (...) {
    }
}

// The mod's network thread (guest_take_outgoing): a REJOIN when due, ahead of anything of the client.
void rejoin_tick() noexcept {
    if (rj_mode() == rjl::Mode::Off) return;
    try {
        std::optional<rjl::Rejoin> r;
        uint32_t asks = 0;
        rjl::Phase phase = rjl::Phase::NoRemote;
        rjl::Refusal refusal = rjl::Refusal::None;
        {
            std::lock_guard lk(g_rj_mu);
            const rjl::Phase before = g_rj.phase();
            // Review of c4367f8, 5: never while the tunnel is down (not sent, not counted).
            r = g_rj.due(GetTickCount64(), g_tunnel_up.load());
            asks = g_rj.asks();
            phase = g_rj.phase();
            refusal = g_rj.refusal();
            if (before != phase && phase == rjl::Phase::Refused) {
                log::warn("Session2 guest rejoin: no re-entry in this run: {}", rjl::refusal_text(refusal));
            }
        }
        if (!r) return;
        const auto f = rjl::rejoin_frame(*r);
        const bool queued = g_to_host.push(std::vector<uint8_t>(f.begin(), f.end()));
        if (queued) c_rj_sent.fetch_add(1, std::memory_order_relaxed);
        if (asks <= 3 || asks == rjl::kMaxAsks) {
            log::info("Session2 guest rejoin [{}]: REJOIN #{} for conversation {} (last host epoch played {}){}",
                      rjl::mode_name(rj_mode()), asks, r->conversation, r->last_epoch, queued ? "" : " NOT queued");
        }
    } catch (...) {
    }
}

std::string rejoin_describe() {
    if (rj_mode() == rjl::Mode::Off) return {};
    try {
        std::lock_guard lk(g_rj_mu);
        return std::format(" | rejoin [{}]: {} | conversation {} (asking {}, asks {}) | host C4 {} epoch {} (EPOCH frames "
                           "{}), granted epoch {} | REJOIN sent {} | ready count {} (floor {})",
                           rjl::mode_name(rj_mode()), g_rj.phase() == rjl::Phase::Refused
                                                          ? std::string("refused: ") + rjl::refusal_text(g_rj.refusal())
                                                          : std::string(rjl::phase_name(g_rj.phase())),
                           g_rj.conversation(), g_rj.asking(), g_rj.asks(), rjl::host_state_name(g_rj.last_state()),
                           g_rj.last_epoch(), c_rj_epochs.load(), g_rj.granted_epoch(), c_rj_sent.load(),
                           g_ready_count.load(), g_ready_floor.load());
    } catch (...) {
        return {};
    }
}

// P8 mounts (§12): the host's character key and its mount events are taken only while this client plays on the host
// on a connection that is not broken (end_remote leaves g_mode Remote until the client connects again).
bool remote_live_for_keys() noexcept { return g_mode.load() == Mode::Remote && !g_broken.load(); }

// docking_dedupe (docking_dedupe_logic.h): the same equipment-docking request at most once per 2 s to the host.
std::atomic<bool> g_dock_on{true};
std::mutex g_dock_mu;
ddd::Dedupe g_dock;
std::atomic<uint64_t> c_dock_dropped{0}, c_dock_passed{0};
bool docking_withhold(const uint8_t* p, size_t n) noexcept {
    if (!g_dock_on.load(std::memory_order_relaxed) || !p || n < 5) return false;
    // The client's packets are decoded to the logical numbering when they are taken (native_opcode::decode_packet),
    // so this compares the logical opcode (live 2026-11-06: the native 2288 never matched here).
    if (static_cast<uint16_t>(p[0] | (p[1] << 8)) != ddd::kLogicalOpcode) return false;
    bool drop = false;
    try {
        const std::lock_guard lock(g_dock_mu);
        drop = g_dock.drop(ddd::fingerprint(std::span<const uint8_t>(p, n)), GetTickCount64());
    } catch (...) {
        return false;
    }
    (drop ? c_dock_dropped : c_dock_passed).fetch_add(1, std::memory_order_relaxed);
    return drop;
}

// The packet of a C->S buffer (ClientNet::PostPacket's layout, D0 §4), or
// empty if the buffer is not what we expect.
std::vector<uint8_t> frame_packet(uintptr_t self, uintptr_t pb) noexcept {
    try {
        uintptr_t frame = 0, base = 0, crypto = 0;
        uint16_t flen = 0;
        uint8_t crypto_on = 0;
        if (!peek(pb + off::kPb_FramePtr, frame) || frame != pb || !peek(pb + off::kPb_Base, base) || base != pb ||
            !peek(pb + off::kPb_Len2, flen) || flen < off::kFrameOverhead + troc::kInternalHeaderSize ||
            flen - off::kFrameOverhead > troc::kMaxPacketSize) {
            return {};
        }
        // With the session's crypto on, the frame would already be encrypted (0x35BF99).
        if (peek(self + off::kSession_Crypto, crypto) && crypto && peek(crypto + 0x24, crypto_on) && crypto_on) {
            return {};
        }
        std::vector<uint8_t> p(flen - off::kFrameOverhead);
        // C4: also the client's 3-byte native goodbye 2001 (salida.md §1.1).
        if (!guarded_copy(p.data(), pb + off::kFrameHeader, p.size()) ||
            !native_opcode::decode_packet(game::current_build(), p, troc::Dir::ToHostServer)) {
            return {};
        }
        return p;
    } catch (...) {
        return {};
    }
}

// The decision for a new connection, taken on its FIRST packet: remote only if
// it is ConnectCryptogramToServerReq (the connection really starts now, none
// of it went to the local server), the host said its session 2 is ready, and
// this game run has not had a remote connection yet.
// G2: one log line per decision with its reason (the conditions are the ones
// host_ready() reads, in that order).
Mode decide(uint16_t first_op, uint64_t epoch) {
    g_n.first_op.store(first_op);
    const uint64_t now = GetTickCount64();
    const uint64_t ready_at = g_host_ready_ms.load();
    const bool tunnel = g_tunnel_up.load(), dead = g_host_dead.load(), had = g_had_remote.load();
    const bool ready_after_over = g_ready_count.load() > g_ready_floor.load();
    const char* why = nullptr;
    // P8 re-entry (rejoin_logic.h): after a remote conversation, only a granted re-entry may go remote again.
    rjl::Verdict rv;
    if (had) {
        try {
            std::lock_guard lk(g_rj_mu);
            rv = g_rj.judge(now);
        } catch (...) {
            rv = rjl::Verdict{false, false, "the re-entry state could not be read"};
        }
    }
    if (!g_remote_allowed) {
        why = "guest_mode=observe";
    } else if (had && !rv.remote) {
        why = rv.why.c_str();
    } else if (g_layer_guard_requested.load(std::memory_order_acquire) && !guest_layer_guard_ready()) {
        why = "the requested guest_layer_guard is not installed yet (or its verified hook was refused)";
    } else if (g_update_guard_requested.load(std::memory_order_acquire) && !guest_update_guard_ready()) {
        why = "the requested guest_update_guard is not installed yet (or its verified hook was refused)";
    } else if (g_remote_guard_requested.load(std::memory_order_acquire) && !guest_remote_update_guard_ready()) {
        why = "the complete remote character guard set is not installed yet (or a verified hook was refused)";
    } else if (first_op != kOpConnectCryptogramToServerReq) {
        why = "its first packet is not ConnectCryptogramToServerReq 2319 (part of it may already be local)";
    } else if (!tunnel) {
        why = "the tunnel to the host is down";
    } else if (dead) {
        why = "the host said its end of the tunnel is dead";
    } else if (!ready_at) {
        why = "no 'ready' from the host yet";
    } else if (!ready_after_over) {
        why = "no 'ready' from the host since the last remote conversation ended";
    } else if (now - ready_at >= kHostReadyFreshMs) {
        why = "the host's last 'ready' is too old";
    }
    Mode m = Mode::Local;
    if (!why) {
        uintptr_t net = 0, q3 = 0;
        // Q3 is where the buffers go back: checked once, with VirtualQuery, before relying on it.
        if (!game::safe_read(g_base + addr(off::kClientNetSlot), &net, sizeof net) || !net ||
            !game::safe_read(net + off::kClientNet_FreeC2S, &q3, sizeof q3) || !q3 ||
            !game::safe_read(q3, &net, sizeof net)) {
            why = "ClientNet's Q3 is unreadable";
        } else {
            g_q3 = q3;
            m = Mode::Remote;
            why = "the host is ready";
        }
    }
    // P8 re-entry: the reason of a decision after a remote conversation, for the HUD and the log.
    std::string rejoin_note;
    if (had && g_remote_allowed) {
        if (m == Mode::Remote) {
            rejoin_note = " | " + rv.why;
        } else if (rv.remote) {
            rejoin_note = " | " + rv.why + " (but this connection stays local: see above)";
        }
        try {
            std::lock_guard lk(g_rj_mu);
            g_rj_last_why = m == Mode::Remote ? std::string() : std::string(why ? why : "?");
            // Review of c4367f8, 1: a post-conversation connection decided LOCAL ends the re-entry for this run (its
            // title and Continue load a local game; a later grant must never say "the host waits for you").
            if (m != Mode::Remote) {
                const rjl::Phase before = g_rj.phase();
                g_rj.on_local_connection();
                if (before != g_rj.phase()) {
                    rejoin_note += std::format(" | rejoin [{}]: no re-entry in this run (this connection is local)",
                                               rjl::mode_name(rj_mode()));
                }
            }
        } catch (...) {
        }
    }
    try {
        const std::string ready = ready_at ? std::format("{} ms ago", now - ready_at) : std::string("never");
        note(g_n.decision_logged, kMaxDecisionLogged,
             "Session2 guest: connection (epoch 0x{:X}) -> {}: {} | first packet {} | tunnel {} | last host ready {} | "
             "host dead {} | had remote {} | guest_mode {}{}",
             epoch, m == Mode::Remote ? "REMOTE" : "local", why, first_op, tunnel ? "up" : "down", ready,
             dead ? "yes" : "no", had ? "yes" : "no", g_remote_allowed ? "remote" : "observe", rejoin_note);
    } catch (...) {
    }
    return m;
}

// G2/G3, out (log only): the guest's goodbye 2001 and its 3093's characterNo.
void note_out(std::span<const uint8_t> p) {
    const uint16_t op = opcode_of(p);
    if (op == troc::kOpLogoutSessionReq && p.size() == troc::kInternalHeaderSize) {
        g_n.out_2001.fetch_add(1, std::memory_order_relaxed);
        note(g_n.internal_logged, kMaxInternalLogged, "Session2 guest: out LogoutSessionToServerReq 2001: {}",
             hex_bytes(p));
    } else if (op == kOpLoginCharacterToFieldServerReq && p.size() >= troc::kHeaderSize + 13) {
        uint64_t character_no = 0;
        uint32_t slot = 0;
        std::memcpy(&character_no, p.data() + troc::kHeaderSize + 1, sizeof character_no);
        std::memcpy(&slot, p.data() + troc::kHeaderSize + 9, sizeof slot);
        g_n.out_3093.fetch_add(1, std::memory_order_relaxed);
        g_conv.out_3093.fetch_add(1, std::memory_order_relaxed);
        g_n.last_character_no.store(character_no);
        g_n.last_3093_slot.store(slot);
        note(g_n.login_logged, kMaxLoginLogged,
             "Session2 guest: out LoginCharacterToFieldServerReq 3093: characterNo 0x{:016X} ({}), save slot {}",
             character_no,
             character_no == 0x7FFFFFFFFFFFF002ull   ? "F002: the host's identity fix, as expected"
             : character_no == 0x7FFFFFFFFFFFFFFFull ? "7FFF...FFFF: the single-player constant, NOT the host's F002"
                                                     : "unexpected",
             slot);
    }
}

// G2, in (log only): the logout Acks 2002/2003; the 2002's u32 against this
// process's own g_ServerFrameworkMode (never rewritten).
void note_in(std::span<const uint8_t> p, uint16_t op) {
    if (op == troc::kOpLogoutSessionAck && p.size() == troc::kLogoutAckSize) {
        g_goodbye_answered.store(true);
        // P8 re-entry: the host answered this remote conversation's goodbye natively: it is over (the client gets the
        // 2002 as always; nothing here stops its delivery).
        if (g_mode.load() == Mode::Remote && !g_broken.load()) rejoin_over("the host answered the client's goodbye 2002");
    }
    if (op == troc::kOpLogoutSessionAck && p.size() == troc::kLogoutAckSize) {
        g_n.in_2002.fetch_add(1, std::memory_order_relaxed);
        uint32_t index = 0, mode = 0;
        std::memcpy(&index, p.data() + troc::kInternalHeaderSize, sizeof index);
        const auto mode_rva = server_framework_mode_rva();
        const bool own = g_base && mode_rva && game::safe_read(g_base + mode_rva, &mode, sizeof mode);
        g_n.last_2002_index.store(index);
        g_n.own_mode.store(own ? mode : 0);
        g_n.index_match.store(own ? (mode == index ? 1 : 0) : -1);
        note(g_n.internal_logged, kMaxInternalLogged,
             "Session2 guest: in LogoutSessionToServerAck 2002: {} | index {} vs own [exe+0x{:X}] {} -> {}",
             hex_bytes(p), index, mode_rva, own ? std::format("{}", mode) : std::string("unreadable"),
             !own ? "cannot compare" : mode == index ? "equal" : "DIFFERENT (logged only, not rewritten)");
    } else if (op == troc::kOpLogoutUserAck && p.size() == troc::kLogoutAckSize) {
        g_n.in_2003.fetch_add(1, std::memory_order_relaxed);
        note(g_n.internal_logged, kMaxInternalLogged, "Session2 guest: in LogoutUserToServerAck 2003: {}",
             hex_bytes(p));
    }
}

// G3: what reached ClientNet::OnRecvPacket (counts only; the first 2042 is logged).
void count_delivered(std::span<const uint8_t> p) {
    switch (opcode_of(p)) {
        case kOpScopeSenderAck:
            if (g_n.in_2042.fetch_add(1, std::memory_order_relaxed) == 0) {
                note(g_n.first_2042_logged, 1, "Session2 guest: first ScopeSenderAck 2042 delivered ({} bytes)",
                     p.size());
            }
            break;
        case kOpActorAppear: g_n.in_2005.fetch_add(1, std::memory_order_relaxed); break;
        case kOpDataAck: g_n.in_2869.fetch_add(1, std::memory_order_relaxed); break;
        case kOp2679: g_n.in_2679.fetch_add(1, std::memory_order_relaxed); break;
        default: break;
    }
}

// ---------------------------------------------------------------- P8 title: the slot table

bool client_connected(uintptr_t net);

using SaveMgrFn = void(__fastcall*)(void* save_manager);
using LockFn = void(__fastcall*)(void* lock);

// The busy byte under the save manager's own lock, as 0x2A22492..0x2A224B4
// (take) and 0x2A224D3..0x2A224EF (release) do it, reloading the lock from
// [g] each time. take: 0 = it was free and is now ours, 1 = busy (left
// alone). release: 0. -1 = a fault (the lock may stay held by this thread).
int guarded_busy(uintptr_t g, bool take) {
    __try {
        void* lock = *reinterpret_cast<void* const*>(g + off::kSaveMgr_Lock);
        LockFn const* vt = *reinterpret_cast<LockFn const* const*>(lock);
        vt[1](lock);
        auto* busy = reinterpret_cast<volatile uint8_t*>(g + off::kSaveMgr_Busy);
        int r = 0;
        if (!take) {
            *busy = 0;
        } else if (*busy) {
            r = 1;
        } else {
            *busy = 1;
        }
        vt[2](lock);
        return r;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// 0x1870C20(g): 0, or the code of the exception that stopped it.
DWORD guarded_refresh_slots(uintptr_t g) {
    DWORD code = 0;
    __try {
        reinterpret_cast<SaveMgrFn>(g_base + addr(off::kSaveMgrRefreshSlots))(reinterpret_cast<void*>(g));
    } __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        return code ? code : 1;
    }
    return 0;
}

// The code the refresh copies, byte for byte (once per run).
bool refresh_code_ok(std::string& why) {
    struct Check {
        uintptr_t rva;
        std::span<const uint8_t> bytes;
        const char* what;
    };
    const Check checks[] = {
        {off::kSlotRefreshReqSequence, off::kSlotRefreshReqSequenceBytes, "SaveDataSlotRefreshReq's sequence"},
        {off::kSaveMgrRefreshSlots, off::kSaveMgrRefreshSlotsHead, "the refresh thunk 0x1870C20"},
        {off::kTitlePlayReadsSaveMgr, off::kTitlePlayReadsSaveMgrBytes, "the title's read of [WorldSystem+0x88]"},
        {off::kWindowsLockVf1, off::kWindowsLockVf1Head, "WindowsLock vf1 (lock)"},
        {off::kWindowsLockVf2, off::kWindowsLockVf2Head, "WindowsLock vf2 (unlock)"},
    };
    for (const auto& c : checks) {
        const auto resolved = addr(c.rva);
        const auto sig = profile::signature(c.rva, c.bytes);
        if (!resolved || sig.empty()) {
            why = std::format("{} has no verified address/signature for this build", c.what);
            return false;
        }
        std::vector<uint8_t> actual(sig.size());
        if (!game::safe_read(g_base + resolved, actual.data(), actual.size())) {
            why = std::format("{} (exe+0x{:X}) is unreadable", c.what, resolved);
            return false;
        }
        if (const int at = sr::first_mismatch(actual, sig); at >= 0) {
            why = std::format("{} (exe+0x{:X}) differs at +{}: {}", c.what, resolved, at, hex_bytes(actual, 24));
            return false;
        }
    }
    uintptr_t vf1 = 0, vf2 = 0;
    if (!game::safe_read(g_base + addr(off::kWindowsLock3Vtable) + 8, &vf1, sizeof vf1) ||
        !game::safe_read(g_base + addr(off::kWindowsLock3Vtable) + 16, &vf2, sizeof vf2) ||
        vf1 != g_base + addr(off::kWindowsLockVf1) || vf2 != g_base + addr(off::kWindowsLockVf2)) {
        why = std::format("WindowsLock<3>'s vtable (exe+0x{:X}) has vf1 0x{:X} vf2 0x{:X}", off::kWindowsLock3Vtable,
                          vf1, vf2);
        return false;
    }
    return true;
}

// The table as the title reads it (no lock, like 0x9096890).
std::vector<sr::Entry> read_slot_table(uintptr_t g, uint32_t& count) {
    count = 0;
    uint32_t capacity = 0;
    uintptr_t data = 0;
    if (!game::safe_read(g + off::kSaveMgr_Count, &count, sizeof count) ||
        !game::safe_read(g + off::kSaveMgr_Capacity, &capacity, sizeof capacity) ||
        !game::safe_read(g + off::kSaveMgr_Slots, &data, sizeof data) || !data || count > capacity) {
        return {};
    }
    const uint32_t n = count < sr::kMaxEntriesRead ? count : sr::kMaxEntriesRead;
    const uint32_t stride = profile::save_slot_entry_size();
    if (stride < 16 || stride > 0x100) return {};
    std::vector<uint8_t> raw(static_cast<size_t>(n) * stride);
    if (n && !game::safe_read(data, raw.data(), raw.size())) return {};
    if (stride == sr::kEntrySize) return sr::parse_entries(raw, n);
    std::vector<sr::Entry> entries;
    entries.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        const size_t at = static_cast<size_t>(i) * stride;
        sr::Entry e;
        std::memcpy(&e.slot, raw.data() + at, sizeof e.slot);
        std::memcpy(&e.time, raw.data() + at + 8, sizeof e.time);
        entries.push_back(e);
    }
    return entries;
}

// One try of the native refresh (SaveDataSlotRefreshReq 0x2A22380 without its
// Ack), on the NetworkThread. `why` says what happened.
sr::Attempt try_refresh([[maybe_unused]] uintptr_t net, bool test, std::string& why) {
    if (g_refresh_code == 0) g_refresh_code = refresh_code_ok(why) ? 1 : -1;
    if (g_refresh_code < 0) {
        if (why.empty()) why = "the game's code is not the expected one";
        return sr::Attempt::Refused;
    }
    const auto ws = game::read_ptr(g_base + addr(off::kWorldSystemSlot));
    const auto g = ws ? game::read_ptr(*ws + off::kWorldSystem_SaveManager) : std::nullopt;
    if (!g) {
        why = ws ? "no save manager at [WorldSystem+0x88] yet" : "no WorldSystem yet";
        return sr::Attempt::NotReady;
    }
    const auto storage = game::read_ptr(*g + off::kSaveMgr_Storage);
    const auto lock = game::read_ptr(*g + off::kSaveMgr_Lock);
    if (!storage || !lock) {
        why = std::format("the save manager 0x{:X} has no {} yet", *g, storage ? "lock" : "storage");
        return sr::Attempt::NotReady;
    }
    if (*lock != *g + off::kSaveMgr_LockObj || !game::has_vtable(*lock, g_base + addr(off::kWindowsLock3Vtable))) {
        why = std::format("the save manager 0x{:X}'s lock 0x{:X} is not its own WindowsLock<3>", *g, *lock);
        return sr::Attempt::Refused;
    }
    // The server's pointer to the manager (what 0x2A22380 uses): the same
    // object, or not set yet. Anything else contradicts the analysis.
    const auto lookup = game::read_ptr(g_base + addr(off::kServerActorLookupSlot));
    const auto server_g = lookup ? game::read_ptr(*lookup + off::kServerActorLookup_SaveManager) : std::nullopt;
    if (server_g && *server_g != *g) {
        why = std::format("the title's save manager 0x{:X} is not the server's 0x{:X}", *g, *server_g);
        return sr::Attempt::Refused;
    }
    // The diagnostic only before the client's login: once its 2490 is out, the
    // server's UserLogin may be about to take the busy byte, and finding it
    // set would fail that login. (While this runs on the NetworkThread, no
    // 2490 can leave.)
    // Connected is fine (the NetworkThread only turns once the client connects,
    // live P8-T 2026-10-09); its 2490 being out is not.
    if (test && g_local_login_out.load()) {
        why = "the client's LoginUserToFieldServerReq 2490 already went to its own server: the diagnostic only runs "
              "before its login (start the game again)";
        return sr::Attempt::Refused;
    }
    uint32_t before = 0, folders = 0;
    (void)read_slot_table(*g, before);
    (void)game::safe_read(*storage + off::kSaveStorage_FolderCount, &folders, sizeof folders);

    const int taken = guarded_busy(*g, true);
    if (taken < 0) {
        why = std::format("a fault taking the save manager 0x{:X}'s lock", *g);
        return sr::Attempt::Fault;
    }
    if (taken > 0) {
        why = std::format("the save manager 0x{:X} is busy (byte +0x60 set: a login or refresh of the game)", *g);
        return sr::Attempt::Busy;
    }
    const uint64_t t0 = GetTickCount64();
    const DWORD code = guarded_refresh_slots(*g);
    const uint64_t took = GetTickCount64() - t0;
    // Released also after a fault, so the game's own login is not "busy" forever.
    const int released = guarded_busy(*g, false);
    if (code) {
        why = std::format("exception 0x{:08X} inside the game's refresh 0x{:X} after {} ms (busy byte {})", code,
                          off::kSaveMgrRefreshSlots, took, released == 0 ? "released" : "NOT released: fault");
        return sr::Attempt::Fault;
    }
    if (released < 0) {
        why = std::format("a fault releasing the save manager 0x{:X}'s busy byte after the refresh", *g);
        return sr::Attempt::Fault;
    }
    uint32_t after = 0;
    const auto entries = read_slot_table(*g, after);
    uint8_t busy_now = 0xFF;
    (void)game::safe_read(*g + off::kSaveMgr_Busy, &busy_now, 1);
    g_refresh_done.fetch_add(1);
    g_refresh_last_count.store(after);
    log::info("Session2 guest: title slots refreshed locally (no local login{}): {} slots {} | before {} | slot "
              "folders {} | Play/Load {} | {} ms | manager 0x{:X} (server's {}) | busy byte now {}{}",
              test ? ", DIAGNOSTIC guest_slot_refresh_test" : "", after, sr::describe(entries), before, folders,
              sr::title_would_enable(entries) ? "enabled" : "still grey (no slot 0-2 or 100-108)", took, *g,
              server_g ? "the same" : "not set yet", busy_now,
              test ? " | before the client's connection: its local login comes after this (and must not say busy)"
                   : "");
    why.clear();
    return sr::Attempt::Done;
}

void arm_title_refresh(uint64_t epoch) noexcept {
    try {
        std::lock_guard lk(g_refresh_mutex);
        if (!g_refresh.arm(epoch, GetTickCount64())) return;
        g_refresh_wanted.store(true);
        log::info("Session2 guest: the client's LoginUserToFieldServerReq 2490 went to the host (epoch 0x{:X}); its "
                  "local server will not log in, so the title's slots are refreshed here on the next NetworkThread "
                  "turn", epoch);
    } catch (...) {
    }
}

// From guest_pump: the pending refresh, if due. Nothing escapes.
void pump_title_refresh(uintptr_t net) noexcept {
    if (!g_refresh_wanted.load(std::memory_order_relaxed)) return;
    try {
        const uint64_t now = GetTickCount64();
        uint64_t key = 0;
        {
            std::lock_guard lk(g_refresh_mutex);
            key = g_refresh.key();
            // A connection's refresh only while that connection is remote.
            if (g_refresh.pending() && key != kSlotTestKey &&
                (g_mode.load() != Mode::Remote || key != g_epoch.load())) {
                g_refresh.cancel();
                g_refresh_wanted.store(false);
                log::warn("Session2 guest: title slot refresh dropped: connection 0x{:X} is no longer remote", key);
                return;
            }
            if (!g_refresh.due(now)) {
                if (!g_refresh.pending()) g_refresh_wanted.store(false);
                return;
            }
        }
        const bool test = key == kSlotTestKey;
        std::string why;
        const sr::Attempt a = try_refresh(net, test, why);
        sr::Outcome o;
        uint32_t tries = 0;
        {
            std::lock_guard lk(g_refresh_mutex);
            o = g_refresh.report(a, now);
            tries = g_refresh.attempts();
            g_refresh_wanted.store(g_refresh.pending());
        }
        const char* what = test ? "diagnostic title slot refresh" : "title slot refresh";
        switch (o) {
            case sr::Outcome::Retry:
                if (tries == 1) log::info("Session2 guest: {} waits ({}); retrying every 100 ms", what, why);
                break;
            case sr::Outcome::GaveUp:
                log::warn("Session2 guest: title slots NOT refreshed: {} gave up after {} tries ({})", what, tries, why);
                break;
            case sr::Outcome::Stopped:
                g_refresh_stopped.store(true);
                log::error("Session2 guest: title slots NOT refreshed, and never tried again in this run: {}", why);
                break;
            case sr::Outcome::Finished: break;
        }
    } catch (...) {
    }
}

// ---------------------------------------------------------------- out: Send

// guest_send must run on the pump's thread (FlushSendQueue is only called from
// the NetworkThread's loop, p8-auditoria-hilos.md). Measured, never refused.
void check_send_thread() noexcept {
    g_send_calls.fetch_add(1, std::memory_order_relaxed);
    const DWORD tid = GetCurrentThreadId();
    if (g_net_owner.check(tid) != gin::ThreadOwner::Seen::FirstForeign) return;
    try {
        log::warn("Session2 guest: NwVirtualSyncSession::Send ran on thread {}, NOT the client NetworkThread {} that "
                  "turns at exe+0x{:X} (the static analysis says it cannot); its buffer still goes back to Q3 as "
                  "always. Counted in the status line (Send off the NetworkThread)",
                  tid, g_net_owner.owner(), addr(off::kNetLoopPump));
    } catch (...) {
    }
}

int* __fastcall guest_send(void* self, int* res, void* pbv) {
    check_send_thread();
    const auto s = reinterpret_cast<uintptr_t>(self);
    const auto pb = reinterpret_cast<uintptr_t>(pbv);
    // The packet's own epoch (+0x8020, written by PostPacket), else the session's.
    uint64_t epoch = kNoEpoch;
    if (!pb || !peek(pb + 0x8020, epoch) || epoch == kNoEpoch) peek(s + off::kSyncSession_Epoch, epoch);
    if (epoch != g_epoch.load()) {
        g_epoch.store(epoch);
        if (g_mode.load() == Mode::Remote) {
            // A new connection after the remote one (back to the title...): nothing of the old one is delivered.
            // Without the re-entry (rejoin_logic.h) it stays local (g_had_remote); with it, decide() goes remote only
            // when the host began a new epoch for this guest's next conversation.
            const bool was_broken = g_broken.load();
            end_remote(rj_mode() == rjl::Mode::On
                           ? "the client reconnected (back to the title); the re-entry decides where the new connection "
                             "goes"
                           : "the client reconnected; restart the game to play on the host again (a save loaded now "
                             "on this PC's own server may never finish loading; guest_local_after_remote=stuck ends "
                             "it)");
            // P8 mounts (§12, review of 458cf49 (1)): an earlier end_remote already ran its reset, but a control state 4
            // of the host may have come in since: forget the host's key again (its own character may get that key).
            if (was_broken) mount_sync_reset("the client reconnected after the remote connection broke");
        }
        g_mode.store(Mode::Undecided);
    }
    if (g_mode.load() == Mode::Undecided) {
        uint16_t op = 0;
        if (pb) peek(pb + off::kFrameHeader, op);
        op = native_opcode::decode(game::current_build(), op).value_or(0);
        const Mode m = decide(op, epoch);
        if (m == Mode::Remote) {
            g_had_remote.store(true);
            g_broken.store(false);
            clear_from_host();
            g_n.remote.fetch_add(1);
            guest_conversation_begin(epoch);
        } else {
            g_n.local.fetch_add(1);
        }
        g_mode.store(m);
    }
    if (g_mode.load() != Mode::Remote) {
        g_n.observed.fetch_add(1, std::memory_order_relaxed);
        if (uint16_t op = 0; pb && peek(pb + off::kFrameHeader, op)) {
            op = native_opcode::decode(game::current_build(), op).value_or(0);
            if (op == kOpLoginUserToFieldServerReq) g_local_login_out.store(true);
            // P8 re-entry: a save loaded on this PC's own server after a remote conversation ends the re-entry.
            if (op == gxv::kOpLoginCharacterToFieldServerReq && g_had_remote.load()) {
                bool changed = false;
                try {
                    std::lock_guard lk(g_rj_mu);
                    const rjl::Phase before = g_rj.phase();
                    g_rj.on_local_game();
                    changed = before != g_rj.phase();
                } catch (...) {
                }
                if (changed) {
                    try {
                        log::info("Session2 guest rejoin [{}]: a save was loaded on this PC's own server (3093, local "
                                  "connection epoch 0x{:X}): no re-entry to the host in this run",
                                  rjl::mode_name(rj_mode()), epoch);
                    } catch (...) {
                    }
                }
            }
            // B1 (stuck): stamps only; the frame goes to the local server as always.
            if (g_local_after_remote.load(std::memory_order_relaxed) ==
                    static_cast<uint8_t>(gxv::LocalAfterRemote::Stuck) &&
                g_had_remote.load()) {
                if (op == gxv::kOpLoginCharacterToFieldServerReq) {
                    g_ll_epoch.store(epoch);
                    g_ll_3093_ms.store(GetTickCount64());
                } else if (op == gxv::kOpMoveFieldCompleteReq) {
                    g_ll_2549_ms.store(GetTickCount64());
                }
            }
        }
        return g_send_hook.unsafe_call<int*>(self, res, pbv);
    }

    if (pb) {
        if (g_broken.load()) {
            g_n.dropped.fetch_add(1, std::memory_order_relaxed);
            // Its goodbye still gets the native answers (guest_pump).
            try {
                const auto p = frame_packet(s, pb);
                if (opcode_of(p) == troc::kOpLogoutSessionReq) {
                    note_out(p);
                    g_goodbye_ms.store(GetTickCount64());
                }
            } catch (...) {
            }
        } else {
            auto p = frame_packet(s, pb);
            bool ok = false;
            try {
                // C4: the client's ReserveShutDownServerReq 2790 on quitting is its
                // own server's business: never the host's (salida.md §1.3, §4.1).
                if (opcode_of(p) == kOpReserveShutDownServerReq) {
                    g_n.kept_local.fetch_add(1, std::memory_order_relaxed);
                    ok = true;
                } else {
                    try {
                        if (!p.empty()) note_out(p);  // G2/G3: log only, never decides anything
                    } catch (...) {
                    }
                    // P8 mounts (§12): the observer's self-check. A StartActionReq 2223 for the host's rider or its
                    // horse is counted and warned (fix B degraded); with mount_sync=1 it is WITHHELD (never reaches
                    // the host's server), as if sent.
                    // P8 S28 (docked_gimmicks.h, mode 1): a state request (3082 2758 2609 2774 3089 2779 2826 2618) of a
                    // gimmick this client drives only for its own screen is WITHHELD the same way (the host stays
                    // its controller); probe counts it.
                    const bool withheld = mount_sync_guest_outgoing(p.data(), p.size()) ||
                                          docked_gimmicks_guest_withhold(p.data(), p.size()) ||
                                          docking_withhold(p.data(), p.size()) ||
                                          guest_shop_withhold(p.data(), p.size());
                    // P8 S25 phase B (guest_save_guest.h, guest_own_save=1): the 3093 waits for the host's SAVE_ACK
                    // and the goodbye behind one SaveToFileCurrentPlayerReq 2910 (gs.before); a held packet (and every one after
                    // it) goes later, in order, from guest_pump. Probe or off: nothing changes.
                    GuestSaveSend gs;
                    if (!withheld && !p.empty()) gs = guest_save_guest_on_send(p, g_conv.out_3093.load() != 0);
                    // P8 mounts: the events first, then this packet, in one step (a Begin goes before the Req its
                    // commit emitted). An event the queue refused stays pending and this packet is not sent either
                    // (the queue is full: the connection ends below, as for any refused packet).
                    g_mount_drain.drain(pop_mount_event, push_to_host, /*blocking=*/true, [&] {
                        ok = gs.before.empty() || g_to_host.push(gs.before);
                        ok = ok && (withheld || gs.held || (!p.empty() && g_to_host.push(p)));
                    });
                    npc_probe_client_out(p, epoch, ok && !withheld && !gs.held);
                    if (ok && !withheld && !gs.held) door_trace_packet(DoorTraceStage::GuestSend, p);
                    if (withheld) {
                        guest_scene_diag_on_out(p);  // G4 still counts the client's Req (review of 458cf49 (4))
                        p.clear();                   // nothing else below looks at it
                    }
                    if (ok) load_trip_on_out(p);  // P8 S2 (load_diag): 2549 / 2445, a fixed record only
                    if (ok) guest_reload_wait_on_out(opcode_of(p));  // P8 S15: the client's 2283 time only
                    if (ok) guest_scene_diag_on_out(p);  // P8 S1 (guest_scene_diag): G4, counts / a fixed record
                    // A held goodbye starts its wait when it really goes (guest_pump, release_held).
                    if (ok && !gs.held && opcode_of(p) == troc::kOpLogoutSessionReq) g_goodbye_ms.store(GetTickCount64());
                    // P8 title: where the local UserLogin would have refreshed the slots.
                    if (ok && opcode_of(p) == kOpLoginUserToFieldServerReq) arm_title_refresh(epoch);
                }
            } catch (...) {
            }
            if (ok) {
                g_n.sent.fetch_add(1, std::memory_order_relaxed);
            } else {
                // Never to the local server instead (two worlds): this connection is lost.
                g_n.bad_frames.fetch_add(1, std::memory_order_relaxed);
                end_remote("a packet of the client could not be sent");
            }
        }
        // The buffer goes back as the server would after reading it (0x27735E4):
        // to Q3, where the NetworkThread frees it in this same turn
        // (opcion-d-p8.md §1.3). If that fails, it is lost (32 KB), never freed twice.
        if (!guarded_push(g_q3, pb)) end_remote("a buffer could not go back to Q3");
    }
    // Always 0: anything else makes FlushSendQueue disconnect (0x35C490).
    if (res) *res = 0;
    return res;
}

// ---------------------------------------------------------------- in: the NetworkThread pump

// ---------------------------------------------------------------- the 2322 written back (preload_release_logic.h)

// NetworkThread only, like everything that hands packets to the client.
prl::Release g_preload_release;
uint64_t g_preload_next_ms = 0;
uint8_t g_preload_last_state = 0xFF, g_preload_last_marker = 0xFF;
constexpr uint64_t kPreloadTickMs = 100;
constexpr uintptr_t kVtClientSequencerStageManager3527 = 0x59572E0;
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): pa::ClientSequencerStageManager by RTTI
// (vtable_map_3549_3576.json), and the world slot 0x71C0100 (core_globals_3576.json; reader_profile() is null on
// 3576). The chain is 3527's: ClientField::vf48 0xAAABB0 (0xAAA7A0 +0x410, slot +0x48 of ClientField 0x594DB40) reads
// field+0x180 and actor +0x68 -> +0xA8 -> +0x18; the loading state machine 0x855C50 writes its state at +0x15C and
// compares the manager's marker +0x259 with 2 (0x8562EF), and 0x85741E sets that marker to 1.
constexpr uintptr_t kVtClientSequencerStageManager3576 = 0x5959438;
constexpr uintptr_t kWorldSystem3576 = 0x71C0100;
// Build 1.0.0.3663 (static, 2026-11-13; never run). Two objects of the chain grew, so 3663 has its own offsets:
// - pa::ClientSequencerStageManager 0x59D57E8 by RTTI (vtable_map_3576_3663.json); its vf4 (0xBD7D00 -> protected
//   0x9C966B0) writes the marker at +0x261 = 1 (0x9C9674C), as does its inlined copy 0x883E61; the 2322 handler's only
//   store 0xCD563B (handler 0xCD5450 +0x1EB, as 3527's 0xC9CB9B) writes +0x261 = 2. No plain code touches +0x259 there.
// - the field-change controller P = [world+0x60]: the loading state machine 0x8825B0 (rcx = P, its only caller 0xC17471)
//   switches on movzx r14d,byte [P+0x24C] (0x882699), reads the field holder at [P+0x1B0] for ClientField::vf48 0xAE0710
//   (slot 9 of 0x59C97C0; it reads field+0x180 and actor +0x68 -> +0xA8 -> +0x18) and compares [manager+0x261] with 2
//   (0x882D87). 3527's +0x15C / +0xC0 are +0x24C / +0x1B0: P grew by 0xF0 below +0xC0. Plain code reads
//   [[world]+0x60]+0x24C as "loading" (0x3EF4AA, 0x569219, 0x574253, 0x5DAF97, 0x5EF34A: dec al ; cmp al,0x17).
// - the states: one more than 3527's (the "loading" tests take 1..0x18, state 0x18 sets 0x19), and the marker wait is
//   0x12 (its case 0x882D78), 3527's 0x11 (preload_release_logic.h). preload_state_3527() maps them back.
// - unchanged: world 0x72451C0 (profile_s2.h), world+0x30 -> manager -> +0x50 the local actor (0x3EE4BA: the same
//   chain; the state machine's [P+0x1A8]+0x50 too), actor +0x68 -> +0xA8 -> +0x18 (vf48 above). The actor's +0x60
//   (key) and +0x90 (user) are 3527's, NOT re-derived (a wrong +0x90 only makes "field is own" false: nothing is sent).
constexpr uintptr_t kVtClientSequencerStageManager3663 = 0x59D57E8;
constexpr uintptr_t kWorldSystem3663 = 0x72451C0;

// The field-change controller's offsets, [P+state] (u8) and [P+field_holder] (-> the client's field), and the
// ClientSequencerStageManager's marker [M+marker] (u8).
struct LoadController {
    uint32_t state, field_holder, marker;
};
LoadController load_controller() noexcept {
    if (game::is_3663()) return {0x24C, 0x1B0, 0x261};
    return {0x15C, 0xC0, 0x259};
}

// 3663's state number in 3527's numbering for prl (preload_release_logic.h): 3663's marker wait 0x12 is 3527's 0x11
// and its last state 0x19 is 3527's 0x18; its 0x11 (the step just before the wait) is reported as 0x10, never as the
// wait. Below that the numbers are passed through (where the extra state sits is not known: logs only).
uint8_t preload_state_3527(uint8_t raw) noexcept {
    if (!game::is_3663()) return raw;
    if (raw == prl::kStateWaitPreload) return static_cast<uint8_t>(prl::kStateWaitPreload - 1);
    return raw > prl::kStateWaitPreload ? static_cast<uint8_t>(raw - 1) : raw;
}
uint8_t g_preload_raw_state = 0;  // the state as the game numbers it (NetworkThread only, for the log)

void preload_release_reset() noexcept {
    g_preload_release.reset();
    g_preload_next_ms = 0;
    g_preload_last_state = g_preload_last_marker = 0xFF;
}

// The chain of the loading state 0x856090 and of its manager lookup 0xAAA7A0.
// Builds 3527, 3576 and 3663 only; a null anywhere means "not there yet" (readable stays false).
prl::Facts read_preload_facts() noexcept {
    prl::Facts f;
    f.now_ms = GetTickCount64();
    const bool v3576 = game::current_build() == game::Build::v3576;
    const bool v3663 = game::current_build() == game::Build::v3663;
    const auto* profile = game::reader_profile();
    if (!v3576 && !v3663 && !profile) return f;
    const uintptr_t world_slot = v3663 ? kWorldSystem3663 : v3576 ? kWorldSystem3576 : profile->world_system;
    const uintptr_t vt_sequencer = v3663   ? kVtClientSequencerStageManager3663
                                   : v3576 ? kVtClientSequencerStageManager3576
                                           : kVtClientSequencerStageManager3527;
    const LoadController lc = load_controller();
    uintptr_t world = 0, controller_object = 0, field_holder = 0, field = 0, manager = 0, actor = 0, components = 0,
              component = 0, sequencer = 0, vt = 0;
    uint32_t owner = 0, local_user = 0;
    uint8_t raw_state = 0;
    if (!peek(g_base + world_slot, world) || !world) return f;
    if (!peek(world + 0x60, controller_object) || !controller_object) return f;
    if (!peek(controller_object + lc.state, raw_state)) return f;
    g_preload_raw_state = raw_state;
    f.state = preload_state_3527(raw_state);
    if (!peek(controller_object + lc.field_holder, field_holder) || !field_holder) return f;
    if (!peek(field_holder, field) || !field || !peek(field + 0x180, owner)) return f;
    if (!peek(world + 0x30, manager) || !manager) return f;
    if (!peek(manager + 0x50, actor) || !actor) return f;
    if (!peek(actor + 0x60, f.own_key) || !peek(actor + 0x90, local_user)) return f;
    if (!peek(actor + 0x68, components) || !components) return f;
    if (!peek(components + 0xA8, component) || !component) return f;
    if (!peek(component + 0x18, sequencer) || !sequencer) return f;
    if (!peek(sequencer, vt) || vt != g_base + vt_sequencer) return f;
    if (!peek(sequencer + lc.marker, f.marker)) return f;
    f.field_is_own = owner != 0 && owner == local_user;
    f.readable = true;
    return f;
}

void preload_release_tick(uintptr_t net) noexcept {
    const auto build = game::current_build();
    if (build != game::Build::v3527 && build != game::Build::v3576 && build != game::Build::v3663) return;
    const uint64_t now = GetTickCount64();
    if (now < g_preload_next_ms) return;
    g_preload_next_ms = now + kPreloadTickMs;
    try {
        const prl::Facts f = read_preload_facts();
        // Each change of the game's own number (3663's 0x10 and 0x11 are both 3527's 0x10).
        const uint8_t game_state = build == game::Build::v3663 ? g_preload_raw_state : f.state;
        if (f.readable && (game_state != g_preload_last_state || f.marker != g_preload_last_marker)) {
            g_preload_last_state = game_state;
            g_preload_last_marker = f.marker;
            log::info("Session2 guest load: state 0x{:X} marker {} (own 0x{:X}, field is own {}){}", f.state, f.marker,
                      f.own_key, f.field_is_own,
                      build == game::Build::v3663 ? std::format(" (3527's numbering; the game's 0x{:X})", g_preload_raw_state)
                                                  : std::string());
        }
        const prl::Action action = g_preload_release.decide(f);
        if (action == prl::Action::None) return;
        uintptr_t session = 0;
        uint64_t epoch = 0;
        if (!peek(net + off::kClientNet_Session, session) || !session) return;
        if (!peek(session + off::kSyncSession_Epoch, epoch) || epoch != g_epoch.load()) return;
        // The whole message: op, slot -1, u16 size, the character's key.
        const uint8_t logical[] = {static_cast<uint8_t>(prl::kOpPlayAllPreLoad & 0xFF),
                                   static_cast<uint8_t>(prl::kOpPlayAllPreLoad >> 8),
                                   0xFF,
                                   4,
                                   0,
                                   static_cast<uint8_t>(f.own_key),
                                   static_cast<uint8_t>(f.own_key >> 8),
                                   static_cast<uint8_t>(f.own_key >> 16),
                                   static_cast<uint8_t>(f.own_key >> 24)};
        const auto native = native_opcode::encode_copy(game::current_build(), logical, troc::Dir::ToGuestClient);
        if (!native) return;
        g_preload_release.on_sent(now);
        const bool ok = guarded_on_recv(net, session, native->data(), static_cast<uint16_t>(native->size()));
        log::warn("Session2 guest load: state 0x{:X} with marker {}: PlayAllPreLoadSequencerAck {} for 0x{:X}{} (#{} in this wait)",
                  f.state, f.marker, action == prl::Action::Repeat ? "repeated" : "synthesized, none came on this trip,",
                  f.own_key, ok ? "" : " FAULTED", g_preload_release.sent_this_wait());
        if (!ok) end_remote("the repeated 2322 faulted in ClientNet::OnRecvPacket");
    } catch (...) {
    }
}

// What the release needs to know of a packet the client just got.
void preload_release_on_delivered(std::span<const uint8_t> p) noexcept {
    if (p.size() < troc::kHeaderSize) return;
    const uint16_t op = static_cast<uint16_t>(p[0] | p[1] << 8);
    if (op == prl::kOpMoveFieldAck) {
        g_preload_release.on_trip();
    } else if (op == prl::kOpPlayAllPreLoad && p.size() >= troc::kHeaderSize + 4) {
        uint32_t key = 0;
        std::memcpy(&key, p.data() + troc::kHeaderSize, sizeof key);
        g_preload_release.on_delivered_2322(key);
    }
}

// NetworkThread only (guest_pump): the oldest packets of the host, at most
// gin::kMaxPerTurn, into ClientNet::OnRecvPacket - where the game itself calls
// it (0x35BB53), so its copy of each packet uses this thread's own heap. The
// queue's lock is never held while the game's code runs.
void deliver_all(uintptr_t net) noexcept {
    try {
        uintptr_t session = 0;
        uint64_t epoch = 0;
        if (!peek(net + off::kClientNet_Session, session) || !session) return;
        // Only into the connection the packets belong to.
        if (!peek(session + off::kSyncSession_Epoch, epoch) || epoch != g_epoch.load()) return;
        // Only the NetworkThread gets here (guest_pump): reused, no allocation
        // of the array per turn once it has grown (the packets are the mod's heap).
        static std::vector<gin::Item> batch;
        batch.clear();
        size_t left = 0;
        {
            std::lock_guard lk(g_in_mutex);
            g_from_host.take(gin::kMaxPerTurn, batch);
            left = g_from_host.size();
        }
        if (batch.empty()) return;
        gin::DeliveryStats turn;
        turn.on_batch(batch.size(), left);
        for (auto& item : batch) {
            if (g_broken.load()) break;
            const auto& p = item.packet;
            // P8 S1 option A (guest_seq_route.h): a 2661/2810/2322 naming another character is never handed
            // to the client unless its routing is on (it would land in this client's own manager).
            if (guest_seq_route_gate(p)) continue;
            // P8 S28 (docked_gimmicks.h): a 2005's gimmicks docked to this client's character, classified and
            // (docked_gimmicks=1) given this client's user as controller, before the game reads it (same size).
            docked_gimmicks_guest_deliver(item.packet);
            // P8 guest_schedule_load: the schedule files this 2005 / 2335 / 2874 names, before the game handles it.
            guest_sched_load_before_deliver(p);
            const uint64_t handed_us = now_us();
            const auto native = native_opcode::encode_copy(game::current_build(), p, troc::Dir::ToGuestClient);
            if (!native) {
                g_n.deliver_errors.fetch_add(1, std::memory_order_relaxed);
                end_remote("host packet cannot be encoded for this game build");
                break;
            }
            if (guarded_on_recv(net, session, native->data(), static_cast<uint16_t>(native->size()))) {
                npc_probe_client_delivered(p, epoch, item.queued_us);  // S33: entregado, no prueba de aplicacion.
                door_trace_packet(DoorTraceStage::GuestDeliver, p, handed_us);
                turn.on_delivered(item.queued_us, handed_us);
                g_n.delivered.fetch_add(1, std::memory_order_relaxed);
                try {
                    count_delivered(p);  // G3: counts only
                } catch (...) {
                }
                preload_release_on_delivered(p);
                load_trip_on_delivered(p);  // P8 S2 (load_diag): 2322 / 2762 handed to OnRecvPacket
                clock_probe_on_delivered(p);  // P8 session 25 (clock_probe): the 2816 / 2762 handed (counts only)
                guest_scene_diag_on_delivered(p);  // P8 S1 (guest_scene_diag): NPC 2005 / scene packets, a fixed record
                // guest_shop_branch: after this client's own shop 2916, the scene's Acks (this client only); and the
                // answers to its own branch requests for that scene.
                static std::vector<std::vector<uint8_t>> extra;
                extra.clear();
                guest_shop_after_deliver(p, extra);
                guest_shop_drain(extra);
                for (const auto& x : extra) {
                    const auto xn = native_opcode::encode_copy(game::current_build(), x, troc::Dir::ToGuestClient);
                    if (!xn || !guarded_on_recv(net, session, xn->data(), static_cast<uint16_t>(xn->size()))) {
                        g_n.deliver_errors.fetch_add(1, std::memory_order_relaxed);
                        end_remote("a local shop Ack faulted in ClientNet::OnRecvPacket");
                        break;
                    }
                }
            } else {
                // A fault inside the game's packet code: never call it again for
                // this connection (a lock may be held).
                g_n.deliver_errors.fetch_add(1, std::memory_order_relaxed);
                end_remote("a packet of the host faulted in ClientNet::OnRecvPacket");
            }
        }
        batch.clear();
        std::lock_guard lk(g_in_mutex);
        g_in_stats.merge(turn);
    } catch (...) {
        end_remote("out of memory while delivering");
    }
}

// The 2003 + 2002 the host would have sent, into the client's own session
// (its NetworkThread, as deliver_all). Once per goodbye.
void answer_goodbye(uintptr_t net) noexcept {
    try {
        uintptr_t session = 0;
        uint64_t epoch = 0;
        uint32_t mode = 0;
        if (!peek(net + off::kClientNet_Session, session) || !session) return;
        if (!peek(session + off::kSyncSession_Epoch, epoch) || epoch != g_epoch.load()) return;
        const auto mode_rva = server_framework_mode_rva();
        if (!mode_rva || !game::safe_read(g_base + mode_rva, &mode, sizeof mode)) return;
        g_goodbye_answered.store(true);
        for (const uint16_t op : {troc::kOpLogoutUserAck, troc::kOpLogoutSessionAck}) {
            uint8_t ack[troc::kLogoutAckSize] = {static_cast<uint8_t>(op & 0xFF), static_cast<uint8_t>(op >> 8), 0xFF};
            std::memcpy(ack + troc::kInternalHeaderSize, &mode, sizeof mode);
            if (!native_opcode::encode_packet(game::current_build(), ack, troc::Dir::ToGuestClient)) break;
            const bool ok = guarded_on_recv(net, session, ack, sizeof ack);
            log::warn("Session2 guest: the host cannot answer the client's goodbye ({}); answered locally with {} {}{}",
                      g_broken.load() ? "connection broken" : "no answer in 5 s", op, hex_bytes(ack),
                      ok ? "" : " (FAULTED in OnRecvPacket)");
            if (!ok) break;
        }
    } catch (...) {
    }
}

// The goodbye with a field of the host loaded and no host to answer it
// (guest_goodbye_logic.h): one line, then TerminateProcess. Never the local
// 2003/2002 here: the client would delete its own user (the field's owner)
// before the field and crash at exe+0x2045A6A (sessions 5 and 6). The log is
// asynchronous (p8-impl-log-async.md): the queued lines get at most
// log::kTerminateFlushMs to reach the file before the process ends; the packet
// recorder's last seconds may not.
void end_without_host(const goodbye::State& s) noexcept {
    if (g_goodbye_ending.exchange(true)) return;
    try {
        // Read only, for the record: the loading state's Q (the client's field,
        // [[[exe+0x6D69190]+0x60]+0xC0]) and its state byte [P+0x15C] (3663: +0x1B0 and +0x24C, load_controller()).
        uintptr_t world = 0, p = 0, q = 0;
        uint8_t state = 0;
        const LoadController lc = load_controller();
        const bool have_p = game::safe_read(g_base + addr(off::kWorldSystemSlot), &world, sizeof world) && world &&
                            game::safe_read(world + 0x60, &p, sizeof p) && p;
        const bool have_q = have_p && game::safe_read(p + lc.field_holder, &q, sizeof q);
        const bool have_state = have_p && game::safe_read(p + lc.state, &state, sizeof state);
        log::error("Session2 guest: the client said goodbye (2001) {} ms ago with a field of the host (its 3093 went "
                   "to the host) and {}. Answering locally would delete its own user, the field's owner, before the "
                   "field (session 6: crash at exe+0x2045A6A 22 ms later), so the game ENDS NOW (TerminateProcess, "
                   "exit code 0x{:X}) | field Q 0x{:X}{}, loading state {} | last packet of the host {} | "
                   "pendientes/p8-salida-invitado.md",
                   goodbye::elapsed(s.now_ms, s.goodbye_ms), goodbye::end_reason(s), kGoodbyeExitCode, q,
                   have_q ? "" : " (unreadable)", have_state ? std::format("0x{:02X}", state) : std::string("unreadable"),
                   s.last_in_ms ? std::format("{} ms ago", goodbye::elapsed(s.now_ms, s.last_in_ms))
                                : std::string("never"));
    } catch (...) {
    }
    log::flush(log::kTerminateFlushMs);  // bounded: the writer writes what is queued; nothing waits longer
    if (!TerminateProcess(GetCurrentProcess(), kGoodbyeExitCode)) {
        // Not expected. The client keeps waiting for its 2002 (the old hang),
        // which is still better than the crash; the user closes the game.
        try {
            log::error("Session2 guest: TerminateProcess failed (error {}); the client keeps waiting for its 2002: "
                       "close the game from the task manager",
                       GetLastError());
        } catch (...) {
        }
    }
}

// B1's twin of end_without_host: a save loaded on this PC's own server after a session on the host's server in this
// run, seen stuck. One line, a bounded flush, TerminateProcess. The diagnostics thread (guest_local_load_watch).
void end_local_after_remote(uint64_t epoch, uint64_t waited_ms, uint8_t state) noexcept {
    if (g_local_ending.exchange(true)) return;
    try {
        log::error("Session2 guest: a game loaded on this PC's own server after a session on the host's server in this "
                   "run is STUCK: no MoveFieldCompleteReq 2549 {:.1f} s after its 3093 (local connection epoch 0x{:X}), "
                   "loading state 0x{:02X} unchanged for {} s or more (session 9: 0x0C until Alt+F4). The game ENDS NOW "
                   "(TerminateProcess, exit code 0x{:X}). Restart the game to play on the host or alone | "
                   "guest_local_after_remote=stuck, pendientes/p8-s9-cinematica.md",
                   static_cast<double>(waited_ms) / 1000.0, epoch, state, gxv::LocalLoadWatch::kStillMs / 1000,
                   kLocalAfterRemoteExitCode);
    } catch (...) {
    }
    log::flush(log::kTerminateFlushMs);  // bounded, as end_without_host
    if (!TerminateProcess(GetCurrentProcess(), kLocalAfterRemoteExitCode)) {
        try {
            log::error("Session2 guest: TerminateProcess failed (error {}); the stuck local load goes on: close the "
                       "game from the task manager",
                       GetLastError());
        } catch (...) {
        }
    }
}

// Once: which thread turns at 0x35BAD4 (the one the game uses for OnRecvPacket
// and the C->S buffers). The pump never refuses its own thread.
void note_pump_thread() noexcept {
    g_turns.fetch_add(1, std::memory_order_relaxed);
    const gin::ThreadOwner::Seen seen = g_net_owner.check(GetCurrentThreadId());
    const bool own = seen == gin::ThreadOwner::Seen::Owner || seen == gin::ThreadOwner::Seen::First;
    if (own && g_owner_logged.load(std::memory_order_relaxed)) return;
    try {
        if (own) {
            if (g_owner_logged.exchange(true)) return;
            log::info("Session2 guest: the client NetworkThread is thread {} (mid-hook exe+0x{:X}, every turn <= 16 "
                      "ms): only it hands the host's packets to ClientNet::OnRecvPacket (exe+0x{:X}, at most {} per "
                      "turn, oldest first) and returns the client's buffers to Q3 (exe+0x{:X}); the mod's network "
                      "thread only queues them (at most {} packets / {} MB)",
                      g_net_owner.owner(), addr(off::kNetLoopPump), addr(off::kClientOnRecvPacket), gin::kMaxPerTurn,
                      addr(off::kQueuePush), gin::kLimits.max_packets, gin::kLimits.max_bytes >> 20);
        } else if (seen == gin::ThreadOwner::Seen::FirstForeign) {
            log::warn("Session2 guest: exe+0x{:X} turned on thread {}, not on {} (two client NetworkThreads?); "
                      "counted in the status line",
                      addr(off::kNetLoopPump), GetCurrentThreadId(), g_net_owner.owner());
        }
    } catch (...) {
    }
}

// P8 S25 phase B (guest_save_guest.h): the client's packets a hold kept back go to the host once it ends, in order
// (the NetworkThread, like guest_send); a broken connection drops them (a held goodbye then starts the goodbye's own
// handling, as an unanswered one).
void release_held() noexcept {
    try {
        GuestSaveRelease r = guest_save_guest_release(g_broken.load());
        if (r.packets.empty() && !r.goodbye) return;
        const uint64_t now = GetTickCount64();
        if (g_broken.load()) {
            if (r.goodbye) g_goodbye_ms.store(now);
            return;
        }
        for (auto& p : r.packets) {
            if (!g_to_host.push(p)) {
                end_remote("a held packet of the client could not be sent");
                if (r.goodbye) g_goodbye_ms.store(now);
                return;
            }
            if (opcode_of(p) == troc::kOpLogoutSessionReq) g_goodbye_ms.store(now);
        }
    } catch (...) {
    }
}

void guest_pump(safetyhook::Context& ctx) {
    note_pump_thread();
    pump_title_refresh(ctx.r15);  // also the diagnostic, in observe mode
    if (g_mode.load(std::memory_order_relaxed) != Mode::Remote) return;
    release_held();
    // A goodbye the host may not answer: BROKEN, silent, or (with a field) too late.
    if (const uint64_t at = g_goodbye_ms.load(std::memory_order_relaxed); at) {
        const goodbye::State s{GetTickCount64(),
                               at,
                               g_last_in_ms.load(std::memory_order_relaxed),
                               g_goodbye_answered.load(std::memory_order_relaxed),
                               g_broken.load(std::memory_order_relaxed),
                               g_conv.out_3093.load(std::memory_order_relaxed) != 0};
        switch (goodbye::decide(s)) {
            case goodbye::Action::AnswerLocally:
                answer_goodbye(ctx.r15);  // the title (no field): as before
                g_goodbye_ms.store(0);
                return;
            case goodbye::Action::EndProcess:
                if (g_goodbye_end_on.load(std::memory_order_relaxed)) {
                    end_without_host(s);  // does not return, unless TerminateProcess failed
                    return;
                }
                if (!g_goodbye_end_off_logged.exchange(true)) {
                    try {
                        log::warn("Session2 guest: the client said goodbye with a field of the host and {}; "
                                  "guest_goodbye_end=0: the process is NOT ended and no local 2003/2002 is sent "
                                  "(it would crash at exe+0x2045A6A): the client keeps waiting for its 2002",
                                  goodbye::end_reason(s));
                    } catch (...) {
                    }
                }
                break;  // whatever still comes from the host is delivered
            case goodbye::Action::Wait: break;
        }
    }
    if (g_broken.load(std::memory_order_relaxed)) return;
    deliver_all(ctx.r15);  // r15 = ClientNet at this point of the loop
    if (!g_broken.load(std::memory_order_relaxed)) preload_release_tick(ctx.r15);
}

// ---------------------------------------------------------------- install

bool head_matches(uintptr_t rva, const uint8_t* expected, size_t n) {
    const auto resolved = addr(rva);
    const auto sig = profile::signature(rva, {expected, n});
    if (!resolved || sig.empty()) return false;
    std::vector<uint8_t> actual(sig.size());
    return game::safe_read(g_base + resolved, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), sig.data(), sig.size()) == 0;
}

bool client_connected(uintptr_t net) {
    auto slot4 = game::read<uintptr_t>(net + off::kClientNet_Slot4);
    return !slot4 || *slot4 != 0;
}

uint64_t session_epoch(uintptr_t net) {
    auto session = game::read_ptr(net + off::kClientNet_Session);
    auto e = session ? game::read<uint64_t>(*session + off::kSyncSession_Epoch) : std::nullopt;
    return e ? *e : 0;
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!profile::supported_build()) {
        log::error("Session2 guest: unsupported game build; P8 off");
        return 0;
    }
    // As early as the game allows: the native singleton catalogue has run its
    // static initialization, ClientNet exists, and the code is the one we
    // know. The ASI worker can start before the catalogue constructors, so a
    // failed catalogue check here is readiness, not an unsupported build.
    uintptr_t net = 0;
    bool catalog = false, heads = false;
    for (int i = 0; i < 24000; ++i) {  // 2 minutes
        catalog = game::validate_native_catalog();
        heads = catalog &&
                head_matches(off::kSyncSessionSend, off::kSyncSessionSendHead, sizeof off::kSyncSessionSendHead) &&
                head_matches(off::kNetLoopPump, off::kNetLoopPumpAob, sizeof off::kNetLoopPumpAob) &&
                head_matches(off::kClientOnRecvPacket, off::kClientOnRecvPacketHead,
                             sizeof off::kClientOnRecvPacketHead) &&
                head_matches(off::kQueuePush, off::kQueuePushHead, sizeof off::kQueuePushHead);
        auto n = game::read_ptr(g_base + addr(off::kClientNetSlot));
        if (heads && n) {
            net = *n;
            break;
        }
        Sleep(5);
    }
    if (!net) {
        log::error("Session2 guest: {} after 2 minutes; P8 off",
                   !catalog ? "the native singleton catalogue was not initialized or did not validate"
                            : heads ? "no ClientNet" : "the client's network functions are not the expected ones");
        return 0;
    }
    const auto too_late = [&] {
        log::warn("Session2 guest: the client had already connected to its own server; this game stays local "
                  "and P8 is not installed. Start the game again (with the host already in the world)");
    };
    if (client_connected(net)) {
        too_late();
        return 0;
    }
    g_on_recv = reinterpret_cast<OnRecvFn>(g_base + addr(off::kClientOnRecvPacket));
    g_push = reinterpret_cast<PushFn>(g_base + addr(off::kQueuePush));
    // The connection that exists now (none) stays local: only a new epoch is decided.
    g_epoch.store(session_epoch(net));
    g_mode.store(Mode::Local);

    // P8 review M3: the NetworkThread's turn through the same checked install as
    // every P8 point (.rsrc only, the 39 verified bytes, exactly the 7-byte first
    // instruction relocated). The Send hook is prepared first: nothing is written
    // to the game unless both can go in.
    g_send_hook = safetyhook::create_inline(reinterpret_cast<void*>(g_base + addr(off::kSyncSessionSend)),
                                            reinterpret_cast<void*>(&guest_send), SafetyHookInline::StartDisabled);
    std::vector<gad::Section> secs;
    const bool pump_ok =
        g_send_hook && p8_exe_sections(g_base, secs) &&
        p8_install_mid(g_base, secs, addr(off::kNetLoopPump), off::kNetLoopPumpPatch,
                       std::span<const uint8_t>(off::kNetLoopPumpAob, sizeof off::kNetLoopPumpAob), guest_pump,
                       g_pump_hook, "Session2 guest", "the client NetworkThread's turn");
    if (!pump_ok || !g_send_hook.enable()) {
        if (g_send_hook) (void)g_send_hook.disable();
        g_pump_hook = {};
        log::error("Session2 guest: cannot hook the client's Send/NetworkThread; P8 off");
        return 0;
    }
    // The client may have connected while the hooks went in: that connection
    // was (partly) local. The first-packet rule keeps it local; say so.
    if (client_connected(net)) too_late();
    // Before the host's character can arrive (remote_visible_logic.h); a failure leaves it unseen, and is logged.
    (void)remote_visible_install();
    g_active.store(true);
    // P8-T (opcion-d-pruebas.md): the title's refresh once, now, on one PC
    // (observe: the client's own login still runs later and must not be "busy").
    if (g_slot_test) {
        if (g_remote_allowed) {
            log::warn("Session2 guest: guest_slot_refresh_test=1 ignored with guest_mode=remote (it is the "
                      "single-PC check, with guest_mode=observe)");
        } else {
            try {
                std::lock_guard lk(g_refresh_mutex);
                if (g_refresh.arm(kSlotTestKey, GetTickCount64(), {100, 600})) g_refresh_wanted.store(true);
                log::info("Session2 guest: DIAGNOSTIC guest_slot_refresh_test=1: the title's slot refresh runs once "
                          "on the next NetworkThread turn (up to 60 s while the save manager is not ready)");
            } catch (...) {
            }
        }
    }
    log::info("Session2 guest (P8): hooked NwVirtualSyncSession::Send (exe+0x{:X}) and the NetworkThread "
              "(exe+0x{:X}); mode {}", addr(off::kSyncSessionSend), addr(off::kNetLoopPump),
              g_remote_allowed ? "REMOTE: the next connection goes to the host if it is ready"
                               : "observe (guest_mode=observe: everything stays local, only counted)");
    // The counters once a minute, also without [net] (the network loop is what
    // logs guest_describe()). guest_describe() reads atomics only.
    for (int minute = 1;; ++minute) {
        Sleep(60000);
        log::info("Session2 guest (minute {}): {}", minute, guest_describe());
    }
}

}  // namespace

namespace {

// K1 on the guest (p8-preparacion.md, RPT-0): the guest's own game reports
// errors to Sentry with save files and a screenshot attached (live P8,
// 2026-10-09). The host's report guard, the same hook, as early as the game's
// code is there (it is retried every 5 ms for 2 minutes) and whatever P8 does
// afterwards (observe or remote, installed or not). Once on, it stays on.
DWORD WINAPI report_guard_thread(LPVOID) {
    // Use the same exact PE/image validation as the transport. The reporter
    // is independent of the native singleton catalogue (whose constructors
    // may not have run yet); report_guard_try_install() selects and checks the
    // build-specific reporter entry before creating the hook.
    if (!profile::supported_build()) {
        log::error("Session2 guest: unsupported game build; the report guard (K1) is NOT on: move "
                   "crashpad_handler.exe out (K2) before playing");
        return 0;
    }
    for (int i = 0; i < 24000; ++i) {  // 2 minutes
        if (report_guard_try_install()) {
            log::info("Session2 guest report guard ON (K1): the game's error reports with files (saves, log) are "
                      "not sent until the game closes (exe+0x{:X}, after {} ms)",
                      report_guard_target_rva(), i * 5);
            return 0;
        }
        Sleep(5);
    }
    log::error("Session2 guest: the game's error reporter (exe+0x{:X}) is not the expected code after 2 minutes; the "
               "report guard (K1) is NOT on: move crashpad_handler.exe out (K2)",
               report_guard_target_rva());
    return 0;
}

}  // namespace

void guest_start(bool remote, bool slot_refresh_test, bool actor_diag, bool layer_guard, bool s3_diag, bool crash_dump,
                 bool update_guard) {
    g_remote_allowed = remote;
    // Publish the requirements before any install/network thread can decide a
    // connection. Readiness itself comes from the guard modules' hook atomics.
    g_layer_guard_requested.store(layer_guard, std::memory_order_release);
    g_update_guard_requested.store(update_guard, std::memory_order_release);
    const bool remote_update_guard = loaded_config().s2_guest_remote_update_guard;
    g_remote_guard_requested.store(remote_update_guard, std::memory_order_release);
    g_slot_test = slot_refresh_test;
    g_goodbye_end_on.store(loaded_config().s2_guest_goodbye_end);
    {
        bool bad = false;
        const auto policy = gxv::parse_local_after_remote(loaded_config().s2_guest_local_after_remote, &bad);
        if (bad) {
            log::warn("Session2 guest: guest_local_after_remote={} is not allow or stuck: allow",
                      loaded_config().s2_guest_local_after_remote);
        }
        g_local_after_remote.store(static_cast<uint8_t>(policy));
    }
    if (!loaded_config().s2_guest_goodbye_end) {
        log::info("Session2 guest: guest_goodbye_end=0: a goodbye with a field of the host and no host to answer "
                  "will NOT end the process (the client keeps waiting for its 2002)");
    }
    // P8 S25 phase B (guest_save_guest.h): [session2] guest_own_save on the guest: its own worker picks and reads the
    // slot now, long before the tunnel's first connection. Only with guest_mode=remote (observe never plays there).
    if (remote) {
        guest_save_guest_configure(loaded_config().s2_guest_own_save);
    } else if (gsv::parse_mode(loaded_config().s2_guest_own_save).mode != gsv::Mode::Off) {
        log::warn("Session2 guest save: guest_own_save='{}' needs guest_mode=remote; it stays off",
                  loaded_config().s2_guest_own_save);
    }
    // P8 re-entry (rejoin_logic.h): [session2] rejoin on the guest. Only with guest_mode=remote (observe never plays on
    // the host). Before the tunnel opens (mod.cpp announces caps 0x08 from guest_rejoin_caps()).
    {
        const std::string& raw = loaded_config().s2_rejoin;
        const auto rp = rjl::parse_mode(raw);
        if (!rp.known) {
            log::warn("Session2 guest: rejoin='{}' is not 0, probe or 1; it stays off", raw);
        } else if (rp.mode != rjl::Mode::Off && !remote) {
            log::warn("Session2 guest: rejoin='{}' needs guest_mode=remote; it stays off", raw);
        } else if (rp.mode != rjl::Mode::Off) {
            {
                std::lock_guard lk(g_rj_mu);
                g_rj.set_mode(rp.mode);
            }
            g_rj_mode.store(static_cast<uint8_t>(rp.mode));
            log::info("Session2 guest: rejoin ON ({}): after a remote conversation (back to the title), this client asks "
                      "the host for a new epoch on the same tunnel connection (control state 13, caps 0x{:02X}) and {}",
                      rjl::mode_name(rp.mode), troc::kCapsRejoin,
                      rp.mode == rjl::Mode::On
                          ? "its next connection goes to the host once the host began it (state 14) and a 'ready' "
                            "followed; otherwise it stays local with the reason on the HUD"
                          : "logs what it would do (probe: the next connection stays local, as before)");
        }
    }
    // K1 first, on its own thread (P8's install below waits for ClientNet).
    CloseHandle(CreateThread(nullptr, 0, report_guard_thread, nullptr, 0, nullptr));
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
    // P8 actors of the host's field (pendientes/p8-actores-anfitrion.md §4.4,
    // §4.1(i)): its own thread too; nothing when the three keys are 0. S34: guest_remote_update_guard rides on that
    // thread. Hooks install before remote admission; the local key arms their
    // ownership filter later. It owns Update, so guest_s3 leaves that site alone.
    guest_actor_diag_start(actor_diag, layer_guard, remote_update_guard);
    // S3 (pendientes/p8-impl-s3.md): its own thread; nothing when the three keys are 0.
    guest_s3_start(s3_diag, crash_dump, update_guard, actor_diag, /*update_site_taken=*/remote_update_guard);
    // P8 phase 2 (pendientes/p8-observador-escenas.md Fase 2): read-only; its install thread
    // waits for the game's code, its lines come from the diagnostics thread below.
    guest_stage_diag_start(loaded_config().s2_guest_stage_diag);
    // P8 S1, NPC scenes (pendientes/p8-s1-escenas-npc.md §5.2): G1-G4, read only.
    guest_scene_diag_start(loaded_config().s2_guest_scene_diag);
    // P8 S2 (pendientes/p8-2322-observador.md §6): the client's loading cycles, read only (load_diag).
    load_trip_start(loaded_config().s2_load_diag);
    // P8 S1 option A (pendientes/p8-impl-opcion-a.md): the host's sequencer Acks into the host character's
    // own stage manager; its install thread waits for guest_stage_diag's and P8Probe's (shared addresses).
    // P8 guest_seq_play (pendientes/p8-impl-escenas-play.md): the tick of the host character's manager X
    // (and its 2 -> 3 step); with _live, its live scenes and the 2524 routed to X (guest_seq_route's fifth point).
    {
        const Config& lc = loaded_config();
        guest_seq_play_start(lc.s2_guest_seq_play, lc.s2_guest_seq_play_live, lc.s2_guest_seq_route);
        // guest_sched_route (pendientes/p8-impl-horarios-x.md): the host's NPC schedule stages into X as well.
        guest_seq_route_start(lc.s2_guest_seq_route, lc.s2_guest_seq_watch,
                              guest_seq_play_wanted() && lc.s2_guest_seq_play_live, lc.s2_guest_seq_route_deny,
                              lc.s2_guest_sched_route, lc.s2_guest_sched_bind, lc.s2_guest_seq_route_2524,
                              lc.s2_guest_seq_route_2524_allow);
        // S44 (research/s25/s44-escenas-del-anfitrion.md): the other player's binding in the host's scenes routed to X,
        // and the read-only probes of what a scene does with it.
        guest_seq_foreign_start(lc.s2_guest_seq_foreign_probe, lc.s2_guest_seq_foreign_player, lc.s2_guest_seq_route,
                                guest_seq_present_needs_p1(lc.s2_guest_seq_foreign_present_probe,
                                                           lc.s2_guest_seq_foreign_present,
                                                           lc.s2_guest_seq_foreign_timeline));
        // S45 (research/s25/s45-escenas-ajenas.md): read-only probes of what another player's scene does to this
        // client's camera, input and interface (S-A in P1 above, S-B / S-C timeline events, S-D per frame), and R-A
        // (guest_seq_foreign_present): another player's stage processor gets the mod's "world only" table in P1.
        // R-B (guest_seq_foreign_timeline): the camera starts of that stage's timeline are skipped at their entry.
        guest_seq_present_start(lc.s2_guest_seq_foreign_present_probe, lc.s2_guest_seq_foreign_present,
                                lc.s2_guest_seq_foreign_timeline, lc.s2_guest_seq_route);
        // P8 session 13 (pendientes/p8-impl-secuenciador-bodyanim.md): read-only BodyAnim / CC+0x70 measures of the
        // watched sequencer NPCs (G5 list of guest_seq_route).
        guest_bodyanim_diag_start(lc.s2_guest_seq_bodyanim_diag, lc.s2_guest_seq_route, lc.s2_s1_diag);
        // P8 session 9 (pendientes/p8-s9-cinematica.md §8): X's stages never reload this client's field.
        guest_x_veto_start(lc.s2_guest_x_stage_veto, lc.s2_guest_x_camera_veto, lc.s2_guest_x_ui_veto,
                           lc.s2_guest_x_ui_veto_allow, lc.s2_guest_seq_route);
        // P8 session 13, C1 (pendientes/p8-impl-tenderos-c1.md): the prompt check of an NPC entry added from X looks
        // its stage up in X (guest_x_veto notes each X it sees).
        guest_x_interaction_start(lc.s2_guest_x_interaction_stage, lc.s2_guest_seq_route);
        // S46 phase 2 (research/s25/s46-tenderos.md): R0 in this client (X's entries against M's). Its lookups need M
        // (guest_seq_play's frame hook) and the X noted (guest_x_interaction): without them R0 stays native.
        shop_trade_probe_start_guest(lc.s2_shop_interaction_own_delete);
    }
    // P8 guest_schedule_load (pendientes/p8-impl-horarios.md): the NPC schedule files of the host's world, loaded on
    // the NetworkThread before the packets that name them are delivered; the lookups watched read-only.
    guest_sched_load_start(loaded_config().s2_guest_schedule_load);
    // P8 seq_actor_restore (pendientes/p8-impl-seq-restore.md): a remote actor announced in a seq_bodyanim action
    // no chart has keeps its login (idle wait or no restore) instead of being destroyed.
    guest_seq_restore_start(loaded_config().s2_seq_actor_restore);
    // Their 5 s reports and this file's status line: on their own thread, off the
    // network thread (p8-hilo-red.md).
    guest_diag_worker_start();
}

void guest_local_load_watch() noexcept {
    if (g_local_after_remote.load(std::memory_order_relaxed) != static_cast<uint8_t>(gxv::LocalAfterRemote::Stuck)) return;
    try {
        const uint64_t now = GetTickCount64();
        if (const uint64_t t = g_ll_3093_ms.load(); t && t != g_ll_seen_3093) {
            g_ll_seen_3093 = t;
            g_ll_watch.note_frame(gxv::LocalAfterRemote::Stuck, true, gxv::kOpLoginCharacterToFieldServerReq, t);
            log::info("Session2 guest: a save is loading on this PC's own server after a session on the host's server "
                      "(3093, local connection epoch 0x{:X}): watched (ended only if seen stuck: no 2549 in {} s and "
                      "the same loading state for {} s)",
                      g_ll_epoch.load(), gxv::LocalLoadWatch::kStuckMs / 1000, gxv::LocalLoadWatch::kStillMs / 1000);
        }
        if (const uint64_t t = g_ll_2549_ms.load(); t && t != g_ll_seen_2549 && t >= g_ll_seen_3093) {
            g_ll_seen_2549 = t;
            if (g_ll_watch.armed()) {
                log::info("Session2 guest: the local load sent its MoveFieldCompleteReq 2549 after {:.1f} s: not stuck",
                          static_cast<double>(t - g_ll_watch.since_ms()) / 1000.0);
            }
            g_ll_watch.note_frame(gxv::LocalAfterRemote::Stuck, true, gxv::kOpMoveFieldCompleteReq, t);
        }
        if (!g_ll_watch.armed()) return;
        uintptr_t world = 0, p = 0;
        uint8_t state = 0;
        const bool ok = game::safe_read(g_base + addr(off::kWorldSystemSlot), &world, sizeof world) && world &&
                        game::safe_read(world + 0x60, &p, sizeof p) && p &&
                        game::safe_read(p + load_controller().state, &state, sizeof state);
        if (g_ll_watch.sample(now, state, ok)) end_local_after_remote(g_ll_epoch.load(), now - g_ll_watch.since_ms(), state);
    } catch (...) {
    }
}

void guest_set_tunnel_up(bool up) {
    g_tunnel_up.store(up);
    if (!up && g_mode.load() == Mode::Remote) end_remote("the tunnel to the host went down");
}

namespace {
// P8 mounts (mount_sync.h, mode 1): the host's packets held, in order, while a MountBegin of the host's character
// waits for its MountCommit (<= 500 ms, bounded). The mod's network thread only (guest_deliver,
// guest_take_outgoing). A new connection drops what was held for the old one.
std::deque<std::vector<uint8_t>> g_ms_held;
size_t g_ms_held_bytes = 0;
uint64_t g_ms_held_epoch = 0;
void deliver_body(std::vector<uint8_t>&& packet);
void ms_release() {
    if (g_ms_held.empty()) return;
    if (g_ms_held_epoch != g_epoch.load()) {
        g_ms_held.clear();
        g_ms_held_bytes = 0;
        return;
    }
    if (mount_sync_guest_holding()) return;
    const size_t n = g_ms_held.size();
    while (!g_ms_held.empty()) {
        std::vector<uint8_t> p = std::move(g_ms_held.front());
        g_ms_held.pop_front();
        g_ms_held_bytes -= std::min(g_ms_held_bytes, p.size());
        deliver_body(std::move(p));
    }
    mount_sync_note_hold(false, n);
}
}  // namespace

void guest_deliver(std::vector<uint8_t>&& packet) {
    auto v = troc::parse_wire(packet, troc::Dir::ToGuestClient);  // also the 7-byte logout Acks
    if (v && v->opcode == troc::kControlOpcode) {
        // P8 re-entry (rejoin_logic.h): the host's C4 state / the epoch it began for this guest (state 14).
        if (rjl::is_epoch_frame(packet)) {
            rejoin_on_epoch_frame(packet);
            return;
        }
        // P8 S25 phase B (guest_save_guest.h): the host's own-save frames (states 7-10), never the game's.
        if (guest_save_guest_on_control(packet)) return;
        // P8 mounts (mount_sync.h): the host's MountBegin / MountCommit / MountDetach, never the game's. Only while this
        // client plays on the host (p8-impl-monturas.md §12): after end_remote they are dropped, so that a game loaded
        // later on this PC's own server never has transactions of the host's (same-keyed) character.
        if (msl::is_frame(packet)) {
            if (remote_live_for_keys() && mount_sync_on_frame(packet, g_epoch.load())) ms_release();  // a Commit may end a hold
            return;
        }
        // P8 S29 (tree_bend.h): the host's tree bend, state 15 (its exact 57-byte form), never the game's. Only while
        // this client plays on the host, as the mount events (a later local game never gets the host's bends).
        if (tbl::is_frame(packet)) {
            if (remote_live_for_keys()) (void)tree_bend_on_frame(packet, g_epoch.load());
            return;
        }
        // Which character the host plays (focus_follow.h, state 16), never the game's. Only while playing on the host.
        if (ffl::is_frame(packet)) {
            if (remote_live_for_keys()) (void)focus_follow_on_frame(packet, g_epoch.load());
            return;
        }
        // P8 S25 weather (weather_sync.h): the host's weather sample, state 12 (its exact 277-byte form), never the game's.
        if (weather_sync_guest_on_control(packet)) return;
        const uint8_t state = v->payload.empty() ? 0 : v->payload[0];
        // P8 S25 phase B: the host's end of the tunnel exists: the own-save upload is queued now, BEFORE the host
        // counts as ready below, so it is ahead of the client's first packet (its 2319 / 2490) in the tunnel.
        if (state != troc::kControlHostDead) guest_save_guest_host_seen(!g_had_remote.load());
        if (state == troc::kControlHostReady) {
            g_host_ready_ms.store(GetTickCount64());
            g_ready_count.fetch_add(1);
            g_host_dead.store(false);
            try {
                std::lock_guard lk(g_rj_mu);
                g_rj.on_ready();
            } catch (...) {
            }
        } else if (state == troc::kControlHostDead) {
            g_host_dead.store(true);
            if (g_mode.load() == Mode::Remote) end_remote("the host stopped its end of the tunnel");
            try {
                std::lock_guard lk(g_rj_mu);
                g_rj.on_host_dead();
            } catch (...) {
            }
        } else if (state == troc::kControlHostCharacter) {
            // Only while this client plays on the host and the connection is not broken (§12, review of 458cf49 (1):
            // end_remote leaves g_mode Remote until the client's next connection, the tunnel may still bring this).
            if (remote_live_for_keys()) {
                // P8 session 9 (ride_filter.h): the host's character key, the only one ride_filter touches here.
                ride_filter_guest_control(v->payload.data(), v->payload.size(), g_epoch.load());
                // P8 mounts: the host's character is the rider this client observes (end_remote forgets it).
                if (v->payload.size() == 5) mount_sync_set_remote_key(msl::get32(v->payload.data() + 1));
            }
        }
        return;
    }
    if (v) {
        g_last_in_ms.store(GetTickCount64(), std::memory_order_relaxed);  // a packet of the host's server
        try {
            note_in(packet, v->opcode);  // G2: log only, before any decision about delivering it
        } catch (...) {
        }
        guest_save_guest_on_host_packet(v->opcode, v->payload);  // P8 S25 phase B: the 3016 (log, a failed final save)
    }
    if (g_mode.load() != Mode::Remote || g_broken.load()) return;  // nothing to deliver to
    // P8 mounts: this client's own character key (its MainPlayerDataStartAck 2756, u32 at +0).
    if (v && v->opcode == 2756 && v->payload.size() >= 4) {
        mount_sync_set_local_key(msl::get32(v->payload.data()));
    }
    if (v) focus_follow_count_in(v->opcode, v->payload);
    // P8 mounts (mode 1): held in order while a Begin of the host's character waits for its Commit.
    if (!g_ms_held.empty() || mount_sync_guest_holding()) {
        ms_release();
        if (!g_ms_held.empty() || mount_sync_guest_holding()) {
            if (!msl::hold_fits(g_ms_held.size(), g_ms_held_bytes, packet.size())) {
                mount_sync_cancel_holds("guest");  // the bound: the old behaviour for that transaction
                ms_release();
            } else {
                if (g_ms_held.empty()) {
                    g_ms_held_epoch = g_epoch.load();
                    mount_sync_note_hold(false, 0);
                }
                g_ms_held_bytes += packet.size();
                g_ms_held.push_back(std::move(packet));
                return;
            }
        }
    }
    deliver_body(std::move(packet));
}

namespace {
void deliver_body(std::vector<uint8_t>&& packet) {
    if (g_mode.load() != Mode::Remote || g_broken.load()) return;  // nothing to deliver to
    auto v = troc::parse_wire(packet, troc::Dir::ToGuestClient);
    // S3: what is queued for the client (2005 with each record's restore byte, 2723, 2991). Read only.
    const uint64_t probe_queued_us = now_us();
    if (v) npc_probe_client_received(v->opcode, v->payload, g_epoch.load(), probe_queued_us);
    if (v && guest_s3_wanted()) guest_s3_on_host_packet(v->opcode, v->payload, g_epoch.load());
    if (v) load_trip_on_in(v->opcode, v->payload);  // P8 S2 (load_diag): a fixed record, formatted elsewhere
    if (v) guest_reload_wait_on_in(v->opcode);      // P8 S15 (guest_reload_wait_fix): 2174 / 2643 / 3066 times only
    // P8 session 8 pets (attach_follow.h): which owned actors ride a character (remote_interp's gaps); off: nothing.
    if (v) attach_registry_on_in(v->opcode, v->payload);
    // P8 session 25 (remote_interp.h, remote_interp_combat): the enemies engaged with this client's character; off:
    // nothing.
    if (v) remote_interp_on_host_packet(v->opcode, v->payload);
    // The other player's ship parts (vehicle_follow.h): their controller's local positions; off: nothing.
    if (v) vehicle_follow_on_in(v->opcode, v->payload);
    // P8 session 9, D1 (ride_filter.h): the host character's mount/dismount actions -> native locomotion, in
    // place, before the client gets the packet; probe: counted only. Off: nothing.
    if (v && ride_filter_active()) ride_filter_on_guest_packet(packet, g_epoch.load());
    // The mod's network thread only queues: the NetworkThread hands it to the game (guest_pump).
    if (!g_mod_net_tid.load(std::memory_order_relaxed)) g_mod_net_tid.store(GetCurrentThreadId());
    gin::Push pushed = gin::Push::Full;
    {
        std::lock_guard lk(g_in_mutex);
        pushed = g_from_host.push(std::move(packet), probe_queued_us);
    }
    if (pushed != gin::Push::Queued) end_remote("too many packets of the host waiting");
}
}  // namespace

namespace {

// P8 session 9, P1 (reannounce_logic.h): the client's CreateOwnedActor failures of a user's child -> "re-announce
// K" to the host through the tunnel's own control packet. The mod's network thread only (guest_take_outgoing).
std::atomic<uint8_t> g_rean_mode{0};
ran::Attempts<32> g_rean;            // network thread only
uint64_t g_rean_cursor = 0;          // network thread only
uint64_t g_rean_epoch = 0;           // the connection the attempts belong to
bool g_rean_cursor_set = false;
std::atomic<uint64_t> c_rean_failures{0}, c_rean_sent{0}, c_rean_would{0}, c_rean_push_failed{0}, c_rean_lost{0},
    c_rean_not_remote{0};
std::atomic<uint64_t> c_rean_verdict[ran::kVerdicts] = {};
std::atomic<uint64_t> g_rean_last{0}, c_rean_no_hook{0};
bool g_rean_no_hook_warned = false;  // network thread only
uint64_t g_rean_lines = 0;
constexpr uint64_t kReanLines = 32;

void reannounce_tick() {
    const auto mode = static_cast<ran::Mode>(g_rean_mode.load(std::memory_order_relaxed));
    if (mode == ran::Mode::Off) return;
    // The failures come from the game errors hook, installed with the sniffer (late_init): without it nothing
    // is ever seen (review 2026-10-10): counted and warned once, the cursor waits for the hook.
    if (!game::game_errors_installed()) {
        c_rean_no_hook.fetch_add(1, std::memory_order_relaxed);
        if (!g_rean_no_hook_warned && g_mode.load() == Mode::Remote) {
            g_rean_no_hook_warned = true;
            log::warn("Session2 guest: child_reannounce is on but the game errors hook is not installed ([sniffer] "
                      "enabled=0 or its install failed): no creation failure can be seen, nothing will be asked");
        }
        return;
    }
    if (!g_rean_cursor_set) {  // failures before this run's first tick are not ours to answer
        g_rean_cursor = game::game_errors_actor_create_failures();
        g_rean_cursor_set = true;
        return;
    }
    uint64_t values[16];
    uint64_t lost = 0;
    const size_t n = game::game_errors_actor_create_failures_since(g_rean_cursor, values, 16, &lost);
    if (lost) c_rean_lost.fetch_add(lost, std::memory_order_relaxed);
    if (!n) return;
    const uint64_t epoch = g_epoch.load();
    if (epoch != g_rean_epoch) {  // a new client connection: new attempts
        g_rean_epoch = epoch;
        g_rean.reset();
    }
    const bool live = g_mode.load() == Mode::Remote && g_tunnel_up.load() && !g_broken.load();
    for (size_t i = 0; i < n; ++i) {
        c_rean_failures.fetch_add(1, std::memory_order_relaxed);
        if (!live) {
            c_rean_not_remote.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const auto f = ran::split_failure(values[i]);
        uint8_t attempt = 0;
        const ran::Verdict v = f ? g_rean.next(f->key, GetTickCount64(), attempt) : ran::Verdict::NotAChild;
        c_rean_verdict[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
        bool sent = false;
        if (v == ran::Verdict::Ask && mode == ran::Mode::On) {
            const auto payload = ran::encode(f->key, f->owner, attempt);
            sent = g_to_host.push(troc::make(troc::kControlOpcode, -1, payload));
            (sent ? c_rean_sent : c_rean_push_failed).fetch_add(1, std::memory_order_relaxed);
        } else if (v == ran::Verdict::Ask) {
            c_rean_would.fetch_add(1, std::memory_order_relaxed);
        }
        if (f) g_rean_last.store(values[i], std::memory_order_relaxed);
        if (g_rean_lines < kReanLines) {
            ++g_rean_lines;
            log::info("Session2 guest reannounce [{}]: CreateOwnedActor failed for 0x{:016X} (owner user high, actor "
                      "low) -> {}{}",
                      ran::mode_name(mode), values[i], ran::verdict_name(v),
                      v != ran::Verdict::Ask ? std::string()
                      : mode == ran::Mode::On
                          ? std::format(": attempt {} of {} asked of the host ({}; it waits {} ms)", attempt,
                                        ran::kMaxAttempts, sent ? "sent" : "NOT queued", ran::backoff_ms(attempt))
                          : std::format(": attempt {} of {} would be asked (probe)", attempt, ran::kMaxAttempts));
        }
    }
}

std::string reannounce_describe() {
    const auto mode = static_cast<ran::Mode>(g_rean_mode.load());
    if (mode == ran::Mode::Off) return {};
    std::string v;
    for (size_t i = 0; i < ran::kVerdicts; ++i) {
        v += std::format("{}{} {}", i ? ", " : "", ran::verdict_name(static_cast<ran::Verdict>(i)),
                         c_rean_verdict[i].load());
    }
    return std::format(" | child reannounce [{}]{}: failures {} (not remote {}, lost {}) [{}] | asked {} (not queued "
                       "{}), would ask {} | last 0x{:016X}",
                       ran::mode_name(mode), game::game_errors_installed() ? "" : " (NO game errors hook)",
                       c_rean_failures.load(), c_rean_not_remote.load(), c_rean_lost.load(), v,
                       c_rean_sent.load(), c_rean_push_failed.load(), c_rean_would.load(), g_rean_last.load());
}

}  // namespace

bool guest_reannounce_configure(const std::string& raw, bool errors_hook_expected) {
    const auto p = ran::parse_mode(raw);
    if (!p.known) {
        log::warn("Session2 guest: child_reannounce='{}' is not 0, probe or 1; it stays off", raw);
        return false;
    }
    if (p.mode != ran::Mode::Off && !errors_hook_expected) {
        log::warn("Session2 guest: child_reannounce='{}' needs [sniffer] enabled=1 (the game errors hook that sees "
                  "the creation failures is installed with it); it stays off",
                  raw);
        return false;
    }
    g_rean_mode.store(static_cast<uint8_t>(p.mode));
    if (p.mode == ran::Mode::Off) return false;
    log::info("Session2 guest: child_reannounce ON ({}): each CreateOwnedActor failure (exe+0x8BDF7C) of a user's "
              "child {} (at most {} per key and connection, not twice within {} ms)",
              ran::mode_name(p.mode),
              p.mode == ran::Mode::On ? "asks the host, through the tunnel's own control packet, to re-announce it"
                                      : "is logged with what would be asked (probe: nothing sent)",
              ran::kMaxAttempts, ran::kMinGapMs);
    return true;
}

std::deque<std::vector<uint8_t>> guest_take_outgoing(size_t link_backlog) {
    door_trace_flush();
    try {
        rejoin_tick();
        reannounce_tick();
        ms_release();  // P8 mounts: a hold whose Commit never came ends here (timeout)
    } catch (...) {
    }
    // P8 mounts: events even while the client sends nothing. P8 re-entry (review of c4367f8, 4): with rejoin on, only
    // while this client plays on the host (an event made locally or at the title would reach the host's next epoch).
    if (rj_mode() != rjl::Mode::Off && !remote_live_for_keys()) {
        try {
            (void)g_mount_drain.discard(pop_mount_event);
        } catch (...) {
        }
    } else {
        flush_mount_events();
    }
    // P8 S29 (tree_bend.h): this client's own tree bends (state 15), only while it plays on the host (whatever rejoin
    // says: a bend of a local game never goes to the host). Not ordered with the client's Req: no hold needed.
    if (remote_live_for_keys()) {
        try {
            std::vector<uint8_t> f;
            while (tree_bend_pop_outbound(f)) {
                if (!g_to_host.push(f)) {  // review L3: never lost silently
                    tree_bend_note_unsent();
                    break;
                }
            }
        } catch (...) {
        }
    } else {
        tree_bend_discard_outbound();
    }
    if (const uint64_t failed = g_mount_drain.failed(); failed != g_mount_drain_logged.load()) {
        g_mount_drain_logged.store(failed);
        try {
            log::warn("Session2 guest: mount_sync: the queue to the host refused a mount event ({} so far); it is kept "
                      "and offered again first (events pushed {}, drain busy {})",
                      failed, g_mount_drain.pushed(), g_mount_drain.busy());
        } catch (...) {
        }
    }
    // P8 S25 phase B (guest_save_guest.h): the own-save frames (offer, acknowledgements, the upload's chunks paced under
    // 256 KB of tunnel backlog) go FIRST: the upload was queued before the host counted as ready, so before any packet
    // of the client in g_to_host, and while chunks of it are left the client's packets stay in g_to_host (in order).
    bool upload_pending = false;
    std::deque<std::vector<uint8_t>> out = guest_save_guest_take_outgoing(link_backlog, upload_pending);
    if (upload_pending) return out;
    if (out.empty()) return g_to_host.take_all();
    for (auto& p : g_to_host.take_all()) out.push_back(std::move(p));
    return out;
}
uint32_t guest_conversation_id() noexcept { return g_conversation.load(std::memory_order_relaxed); }

uint8_t guest_rejoin_caps() { return rj_mode() != rjl::Mode::Off ? troc::kCapsRejoin : uint8_t{0}; }

std::string guest_rejoin_hud() {
    if (rj_mode() == rjl::Mode::Off) return {};
    try {
        std::lock_guard lk(g_rj_mu);
        std::string s = g_rj.hud_text();
        if (!s.empty() && !g_rj_last_why.empty() && g_rj.phase() != rjl::Phase::Granted) {
            s += "\n(motivo: " + g_rj_last_why + ")";
        }
        return s;
    } catch (...) {
        return {};
    }
}

bool guest_active() { return g_active.load(); }
bool guest_remote() { return g_mode.load() == Mode::Remote; }
bool guest_local_after_remote() { return g_had_remote.load() && g_mode.load() != Mode::Remote; }
bool guest_host_ready() { return host_ready(); }

bool guest_remote_live() noexcept {
    return uip::guest_live(g_mode.load() == Mode::Remote, g_tunnel_up.load(), g_broken.load());
}
uint64_t guest_connection_epoch() noexcept { return g_epoch.load(std::memory_order_relaxed); }

namespace {
// G2/G3 (p8-preparacion.md §3): atomics only, like the rest.
std::string guest_describe_g2() {
    const int match = g_n.index_match.load();
    const uint64_t character_no = g_n.last_character_no.load();
    return std::format(
        " | kept local (2790) {} | logout: out 2001 {}, in 2002 {} 2003 {} (last 2002 index {} vs own mode {}: {}) | "
        "delivered 2042 {} 2005 {} 2869 {} 2679 {} | out 3093 {} (characterNo {}, slot {}) | title slot refresh: "
        "{} done, last {} slots{}",
        g_n.kept_local.load(), g_n.out_2001.load(), g_n.in_2002.load(), g_n.in_2003.load(), g_n.last_2002_index.load(),
        g_n.own_mode.load(), match < 0 ? "-" : match ? "equal" : "DIFFERENT", g_n.in_2042.load(), g_n.in_2005.load(),
        g_n.in_2869.load(), g_n.in_2679.load(), g_n.out_3093.load(),
        g_n.out_3093.load() ? std::format("0x{:016X}", character_no) : std::string("-"), g_n.last_3093_slot.load(),
        g_refresh_done.load(), g_refresh_last_count.load(), g_refresh_stopped.load() ? " (STOPPED)" : "");
}
// The host's packets on their way in, and who did the client's network work.
std::string guest_describe_threads() {
    size_t waiting = 0, peak = 0, bytes = 0;
    uint64_t full = 0, cleared = 0;
    gin::DeliveryStats st;
    {
        std::lock_guard lk(g_in_mutex);
        waiting = g_from_host.size();
        peak = g_from_host.peak();
        bytes = g_from_host.bytes();
        full = g_from_host.full();
        cleared = g_from_host.cleared();
        st = g_in_stats;
    }
    const uint64_t foreign = g_net_owner.foreign();
    return std::format(
        " | in queue: waiting {} ({} KB, peak {}) full {} cleared {} | handed by the NetworkThread T{} (turns {}, "
        "batches {}, batch max {}, capped {}, wait mean {:.1f} ms max {:.1f} ms) | mod network thread T{} only "
        "queues | Send calls {} | Send/pump off the NetworkThread {}{}",
        waiting, bytes >> 10, peak, full, cleared, g_net_owner.owner(), g_turns.load(), st.batches, st.batch_max,
        st.capped, st.wait_mean_ms(), static_cast<double>(st.wait_max_us) / 1000.0, g_mod_net_tid.load(),
        g_send_calls.load(), foreign, foreign ? std::format(" (last T{})", g_net_owner.last_foreign()) : std::string());
}
// P8 session 8 pets (p8-s8-mascotas.md §1.1): CreateOwnedActor's failure of a child announced with its
// owner (exe+0x8BDF7C, "Actor 생성에 실패했습니다"), counted by the game errors hook (its line shows only 10 times).
std::string actor_create_failures_text() {
    uint64_t last = 0;
    const uint64_t n = game::game_errors_actor_create_failures(&last);
    if (!n) return {};
    return std::format(" | owned actor creation failed {} (last 0x{:016X}: owner user high, actor low)", n, last);
}

}  // namespace

void guest_set_docking_dedupe(bool on) {
    g_dock_on.store(on);
    log::info("Session2 guest: docking_dedupe={}{}", on ? 1 : 0,
              on ? ": the same equipment-docking request (OnDemandEquipDockingGimmickSpawnReq) at most once per 2 s"
                 : "");
}

std::string guest_describe() {
    const Mode m = g_mode.load();
    const char* mode = m == Mode::Remote ? "REMOTE (host's server)" : m == Mode::Undecided ? "deciding" : "local";
    return std::format("Session2 guest: hooks {} ({}) | connection {}{} | host ready {} | connections remote {} "
                       "local {} (first packet of the last one: {}) | out {} packets, {} bad, {} dropped | in {} "
                       "delivered, {} errors | local packets {}",
                       g_active.load() ? "on" : "off", g_remote_allowed ? "remote" : "observe", mode,
                       g_broken.load() ? " BROKEN" : "", host_ready() ? "yes" : "no", g_n.remote.load(),
                       g_n.local.load(), g_n.first_op.load(), g_n.sent.load(), g_n.bad_frames.load(),
                       g_n.dropped.load(), g_n.delivered.load(), g_n.deliver_errors.load(), g_n.observed.load()) +
           guest_describe_g2() + guest_describe_threads() +
           std::format(" | docking dedupe {}: dropped {} of {}", g_dock_on.load() ? "on" : "off", c_dock_dropped.load(),
                       c_dock_dropped.load() + c_dock_passed.load()) +
           std::format(" | report guard (K1) {} (not sent {}, Sentry on for {})",
                       report_guard_active() ? "on" : "OFF", report_guard_dropped(), report_guard_dropped_live()) +
           (guest_actor_diag_wanted() ? guest_actor_diag_describe() : std::string()) + guest_s3_describe() +
           guest_stage_diag_describe() + guest_scene_diag_describe() + guest_seq_route_describe() + guest_bodyanim_diag_describe() + guest_seq_play_describe() +
           guest_sched_load_describe() + guest_seq_restore_describe() + load_trip_describe() + guest_diag_worker_describe() +
           actor_create_failures_text() + reannounce_describe() + guest_save_guest_describe() + rejoin_describe();
}

}  // namespace cdmp::session2
