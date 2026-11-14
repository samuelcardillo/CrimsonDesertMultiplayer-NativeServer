#include "mod/session2/session2.h"

#include <windows.h>

#include <atomic>
#include <deque>
#include <format>

#include "common/clock.h"
#include "common/tick_profile.h"
#include "common/troc_frame.h"
#include "mod/config.h"
#include "mod/game/game_fault.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/net/horse_diag.h"
#include "mod/net/remote_puppet.h"
#include "mod/net/troc_sniffer.h"
#include "mod/session2/attach_follow.h"
#include "mod/session2/child_hold.h"
#include "mod/session2/clock_gate.h"
#include "mod/session2/clock_push.h"
#include "mod/session2/clock_push_logic.h"
#include "mod/session2/combat_follow.h"
#include "mod/session2/companion_probe.h"
#include "mod/session2/fast_travel.h"
#include "mod/session2/field_share.h"
#include "mod/session2/interaction_condition.h"
#include "mod/session2/guest_lifecycle.h"
#include "mod/session2/horse_follow.h"
#include "mod/session2/host_scene_diag.h"
#include "mod/session2/identity_fix.h"
#include "mod/session2/identity_probe.h"
#include "mod/session2/guest_save_host.h"
#include "mod/session2/guest_save_tunnel.h"
#include "mod/session2/focus_follow.h"
#include "mod/session2/mount_sync.h"
#include "mod/session2/observer_hold_acks.h"
#include "mod/session2/observer_milestone.h"
#include "mod/session2/observer_scene_copy.h"
#include "mod/session2/observer_seq_copy.h"
#include "mod/session2/housing_share.h"
#include "mod/session2/rope_probe.h"
#include "mod/session2/tree_bend.h"
#include "mod/session2/docked_gimmicks.h"
#include "mod/session2/shop_probe.h"
#include "mod/session2/shop_trade_probe.h"
#include "mod/session2/observer_hold_scene_order.h"
#include "mod/session2/user2_shops.h"
#include "mod/session2/user2_stages.h"
#include "mod/session2/npc_probe_client.h"
#include "mod/session2/door_trace.h"
#include "mod/session2/scene_level_share.h"
#include "mod/session2/enemy_damage_probe.h"
#include "mod/session2/npc_action_probe.h"
#include "mod/session2/observer_stage.h"
#include "mod/session2/owner_fanout.h"
#include "mod/session2/reannounce_logic.h"
#include "mod/session2/rejoin_logic.h"
#include "mod/session2/remote_visible.h"
#include "mod/session2/report_guard.h"
#include "mod/session2/ride_filter.h"
#include "mod/session2/host_save_export.h"
#include "mod/session2/save_hooks.h"
#include "mod/session2/server.h"
#include "mod/session2/travel_probe.h"
#include "mod/session2/user2_funnels.h"
#include "mod/session2/user2_funnels_logic.h"
#include "mod/session2/world_anchor.h"

namespace cdmp::session2 {
namespace {

// Written once by install() (late-init thread), read by the network thread.
std::atomic<bool> g_installed{false};
std::atomic<bool> g_tunnel_on{false};
std::atomic<uint8_t> g_rean_mode{0};  // P8 session 9 child_reannounce, host side (ran::Mode)

// Network thread only.
// Guest Req held in order: before session 2 existed, or while the server side
// could not queue them (inject_logic.h: NotReady / Full). Never a logout by
// itself: only past this bound (the hold limit) does the conversation end.
std::deque<std::vector<uint8_t>> g_early;
constexpr size_t kMaxEarly = 512;
// After an offer was held, the next try waits this long (backoff; p8-heap-inyeccion.md).
constexpr uint64_t kHoldRetryMs = 20;
uint64_t g_hold_retry_at = 0;
uint64_t g_held_offers = 0, g_dropped_offers = 0, g_dropped_logged = 0;
bool g_halt_handled = false;  // an exception in the game's code stopped the injection (handled once)
bool g_tunnel_dead = false;
uint32_t g_last_control_ms = 0;
std::string g_dead_reason;
uint64_t g_blocked_from_guest = 0;
uint64_t g_unknown_from_guest = 0;
uint64_t g_after_goodbye = 0;          // guest packets dropped after its logout (C4)
uint32_t g_link_down_since_ms = 0;     // C4: when the guest's connection went away (0 = connected)
constexpr uint32_t kLinkLostMs = 15000;  // longer than the session's own 5 s peer timeout

// C4, reconnect=1 (guest_lifecycle.h). Network thread only, like the above.
bool g_reconnect = false;  // written by install() before the tunnel opens
uint32_t g_ready_reset_link = ~0u;  // the connection whose reset in READY was logged (network thread)
GuestLifecycle g_lc{GuestLifecycle::Config{10000, 60000, 500, kMaxGuestEpochs}};
DepartedSnap g_snap;          // user 2 of this epoch, captured while valid
FieldSnap g_baseline;         // the host's field before user 2 came in (this epoch; check c's information only, S29)
bool g_user_seen = false;     // user 2 existed in this epoch
troc::TrocLink* g_link = nullptr;
uint32_t g_now_ms = 0;
uint32_t g_last_link_epoch = 0;
uint32_t g_last_sample_ms = 0, g_last_barrier_ms = 0;
unsigned g_last_pattern = ~0u;
std::string g_last_barrier;      // the last evaluation, for describe()
uint64_t g_not_admitted = 0;     // guest packets outside the current epoch's connection
uint64_t g_out_discarded = 0;    // server packets for a guest that is no longer there
constexpr uint32_t kSampleMs = 1000, kBarrierMs = 250;

// P8 re-entry (rejoin_logic.h, docs/research/s25/reentrada.md §3): [session2] rejoin on the host. Written by install()
// before the tunnel opens (Off unless reconnect is on); network thread afterwards, like the above.
rjl::Mode g_rejoin = rjl::Mode::Off;
uint32_t g_rejoin_started_for = 0;  // the guest conversation the current epoch was started for in-band (0 = none)
uint32_t g_rejoin_started_ms = 0;   // when (the network thread's clock): an unused grant is given up (rjl::grant_unused)
uint64_t c_rejoin_unused = 0;       // epochs begun for a re-entry and never used
uint64_t c_rejoin_in = 0, c_rejoin_bad = 0, c_rejoin_started = 0, c_rejoin_repeat = 0, c_rejoin_probe = 0,
         c_rejoin_ignored = 0, c_rejoin_off = 0, c_epoch_out = 0;
uint64_t g_rejoin_lines = 0;
constexpr uint64_t kRejoinLines = 64;

rjl::HostState c4_state() {
    switch (g_lc.state()) {
        case GuestState::Active: return rjl::HostState::Active;
        case GuestState::Retiring: return rjl::HostState::Retiring;
        case GuestState::Clean: return rjl::HostState::Clean;
        case GuestState::Ready: return rjl::HostState::Ready;
        case GuestState::Quarantined: return rjl::HostState::Quarantined;
    }
    return rjl::HostState::Quarantined;
}

// The EPOCH frame (state 14), only to a guest that announced caps 0x08 on this connection.
void push_epoch(troc::TrocLink& link, rjl::Reason reason, uint32_t conversation) {
    if (g_rejoin == rjl::Mode::Off || (link.peer_caps() & troc::kCapsRejoin) == 0) return;
    const rjl::Epoch e{c4_state(), reason, g_lc.epoch(), conversation};
    const auto f = rjl::epoch_frame(e);
    if (link.push(std::span<const uint8_t>(f.data(), f.size()))) ++c_epoch_out;
}

// p8-tunel-rendimiento.md: where a tick of tunnel_tick goes (the network
// loop's "host tunnel" phase), part by part. Network thread only.
enum TickPart : size_t {
    kPartChildHold,
    kPartHoldAcks,
    kPartInjectWatch,
    kPartLinkState,
    kPartSample,
    kPartLogout,
    kPartHeldReq,
    kPartOutgoing,
    kPartBarrier,
    kPartControl,
    kPartLinkFlush,
    kPartCount
};
constexpr const char* kPartNames[kPartCount] = {
    "child hold",          "hold acks",       "inject watch", "link state", "user 2 sample/capture",
    "logout (2549/2001)",  "held guest Req",  "outgoing to the link", "C4 barrier", "control",
    "link flush"};
constexpr uint64_t kSlowTickUs = 50'000;  // a tick above this is logged with its parts
constexpr uint64_t kSlowTickLines = 200;
TickProfile g_prof;
uint64_t g_slow_tick_lines = 0;
std::string g_last_barrier_reads;  // the timing of the last barrier's reads (diagnostics)
void prof(TickPart p) { g_prof.mark(p, now_us()); }

DWORD WINAPI probe_thread(LPVOID) {
    server_probe_log("install");
    bool user2 = false;
    for (int minute = 1;; ++minute) {
        // Every 10 s, a snapshot as soon as user 2 appears or leaves; one a minute otherwise.
        for (int i = 0; i < 6; ++i) {
            Sleep(10000);
            if (server_user2_present() != user2) {
                user2 = !user2;
                server_probe_log(user2 ? "user 2 logged in" : "user 2 gone");
            }
        }
        server_probe_log(std::format("minute {}", minute).c_str());
        // The finder counters, also without [net] (the network loop is what logs describe()).
        if (const std::string f = server_finder_describe(); !f.empty()) {
            log::info("Session2 probe (minute {}): {}", minute, f);
        }
        if (field_share_active()) {
            log::info("Session2 probe (minute {}): {} | {} | {}", minute, field_share_describe(),
                      net::puppet_guard_describe(), net::horse_diag_describe());
        }
        if (clock_gate_active()) log::info("Session2 probe (minute {}): {}", minute, clock_gate_describe());
        if (identity_probe_active()) log::info("Session2 probe (minute {}): {}", minute, identity_probe_describe());
        if (identity_fix_wanted()) log::info("Session2 probe (minute {}): {}", minute, identity_fix_describe());
        if (guest_save_mode() != gsv::Mode::Off) {
            log::info("Session2 probe (minute {}): {}", minute, guest_save_describe());
        }
        if (companion_probe_active()) log::info("Session2 probe (minute {}): {}", minute, companion_probe_describe());
        if (child_hold_active()) log::info("Session2 probe (minute {}): {}", minute, child_hold_describe());
        if (horse_follow_active() || horse_follow_guest_probe_active() || horse_follow_reverse_active()) log::info("Session2 probe (minute {}): {}", minute, horse_follow_describe());
        if (attach_follow_active()) log::info("Session2 probe (minute {}): {}", minute, attach_follow_describe());
        if (report_guard_active()) {
            log::info("Session2 probe (minute {}): error reports not sent {} (Sentry on for {})", minute,
                      report_guard_dropped(), report_guard_dropped_live());
        }
    }
}

// The sniffer has one tap (its writer thread): it feeds every reader of the host client's capture.
std::atomic<bool> g_tap_scene_diag{false}, g_tap_seq_copy{false}, g_tap_owner_fanout{false}, g_tap_travel{false},
    g_tap_mount_sync{false}, g_tap_rope_probe{false}, g_tap_docked_gimmicks{false}, g_tap_user2_stages{false},
    g_tap_quest_policy{false};
void sniffer_fanout(const uint8_t* packet, size_t size, uint64_t t_us, bool server_to_client) noexcept {
    npc_probe_client_sniff(packet, size, t_us, server_to_client); // S33: retorna inmediatamente con 0.
    door_trace_packet(server_to_client ? DoorTraceStage::HostClientAck : DoorTraceStage::HostClientReq,
                      std::span<const uint8_t>(packet, size), t_us); // El módulo ignora este tap en el invitado.
    if (g_tap_scene_diag.load(std::memory_order_relaxed)) host_scene_diag_sniffed(packet, size, t_us, server_to_client);
    if (g_tap_seq_copy.load(std::memory_order_relaxed)) observer_seq_copy_sniffed(packet, size, t_us, server_to_client);
    if (housing_share_wanted()) housing_share_sniffed(packet, size, server_to_client);  // the host's houses for user 2
    if (g_tap_owner_fanout.load(std::memory_order_relaxed)) owner_fanout_sniffed(packet, size, server_to_client);
    // P8 S16 (travel_probe.h): the host client's 2661/2981/2322 burst after user 2's 2873 (counts only).
    if (g_tap_travel.load(std::memory_order_relaxed)) travel_probe_host_sniffed(packet, size, t_us, server_to_client);
    // P8 S18 (mount_sync.h): the self-check, this client never requests actions of user 2's rider / horse.
    if (g_tap_mount_sync.load(std::memory_order_relaxed)) mount_sync_sniffed(packet, size, server_to_client);
    // P8 S27 (rope_probe.h): the grappling device's gimmick events and 2005s, read only, on both PCs.
    if (g_tap_rope_probe.load(std::memory_order_relaxed)) rope_probe_sniffed(packet, size, t_us, server_to_client);
    // P8 S28 (docked_gimmicks.h): the host client's 2005s classified (docked to which character), read only.
    if (g_tap_docked_gimmicks.load(std::memory_order_relaxed)) {
        docked_gimmicks_sniffed(packet, size, t_us, server_to_client);
    }
    // P8 option U, U-h (user2_stages.h): the schedule packets of user 2's own stages at the host's client (counts).
    if (g_tap_user2_stages.load(std::memory_order_relaxed)) user2_stages_sniffed(packet, size, server_to_client);
    // P8 S34 (user2_funnels.h, quest_policy): the host client's quest Acks 3009/3088/2738/2346 (counts only).
    if (g_tap_quest_policy.load(std::memory_order_relaxed)) user2_funnels_sniffed(packet, size, server_to_client);
}

void begin_logout(LogoutTrigger t, const std::string& why);

// P8 session 9 (ride_filter on the guest, review 2026-10-10): the host's main character key ([host user+0xD0],
// its +0x60, class 0xA), told to the guest once a second with the control state. Network thread, guarded reads.
void push_host_character(troc::TrocLink& link) {
    uintptr_t host = 0;
    if (!server_host_user(host) || !host) return;
    const auto actor = game::read_ptr(host + hold::kUserCharacter);
    if (!actor || !*actor) return;
    const auto key = game::read<uint32_t>(*actor + hold::kActorKey);
    if (!key || (*key >> 28) != hold::kCharKeyClass) return;
    mount_sync_set_local_key(*key);  // P8 mounts: the host's own rider (the one it publishes)
    const uint8_t p[5] = {troc::kControlHostCharacter, static_cast<uint8_t>(*key), static_cast<uint8_t>(*key >> 8),
                          static_cast<uint8_t>(*key >> 16), static_cast<uint8_t>(*key >> 24)};
    link.push(troc::make(troc::kControlOpcode, -1, std::span<const uint8_t>(p, sizeof p)));
}

void kill_tunnel(const std::string& why) {
    if (g_reconnect) {
        // C4: the conversation of this epoch is over, not the tunnel: the same
        // native logout, then the barrier, then a new epoch may begin.
        begin_logout(LogoutTrigger::LinkLost, why);
        return;
    }
    if (g_tunnel_dead) return;
    g_tunnel_dead = true;
    g_dead_reason = why;
    g_early.clear();
    log::error("Session2: the Troc tunnel stops: {}; session 2's conversation is lost until the game restarts", why);
    // C4 (salida.md §4.1): user 2 can no longer say goodbye itself; its user,
    // character and place in the host's field would stay for good. The host's
    // server gets the same native logout a goodbye would have sent.
    // P8 S25 phase B (§3.6): with user 2's own save active, one SaveToFileCurrentPlayerReq 2910 goes before its 2001.
    server_logout_user2("link lost: " + why, guest_save_final_save_wanted());
}

// A guest Req for the server. Save/cheat Req are dropped by policy; any other
// refusal means the conversation is no longer what the guest believes.
// Internal or local messages that never reach the host's server, whatever its
// handler table says (C4 review): the global shutdown 2790 and its timer 2038,
// 2004 (pointers), and the client-local connect/disconnect 1001-1008. Also
// SetFieldTimeReq 2125 (sleep, explicit time): the world clock is the host's
// (reloj.md §5.1, 0x2BC8970 publishes for any field owner).
constexpr uint16_t kOpSetFieldTimeReq = 2125;
bool never_from_guest(uint16_t opcode) {
    return opcode == 2790 || opcode == 2038 || opcode == 2004 || opcode == kOpSetFieldTimeReq ||
           (opcode >= 1001 && opcode <= 1008);
}
// P8 session 25, W1 (block_guest_weather, research/noche/clima-hora.md §5.2): user 2's SyncWeatherStateReq 2560
// writes the host field's weather flags (0x20E6FE0, no owner check; the server answers nothing). Written by
// install() before the tunnel opens; network thread afterwards.
bool g_block_weather = false;
uint64_t g_weather_blocked = 0;
// P8 S25 phase B (§3.7): user 2's Req the own-save policy dropped (2711 / 2178) or let through (3037 / 2910).
uint64_t g_own_save_blocked = 0, g_own_save_allowed = 0;

// p8-heap-inyeccion.md: an exception inside the game's code while handing
// user 2's Req (the NetworkThread caught it and logged it): the game's heap or
// queue may be damaged. Nothing more is injected in this run, not even the
// 2001 (no logout by injection, user 2 stays on the server); with reconnect
// the lifecycle is quarantined (no more logins, the host goes on).
void halt_tick() {
    if (g_halt_handled || !server_inject_halted()) return;
    g_halt_handled = true;
    const std::string why = "an exception inside the game's code while handing user 2's Req (" +
                            server_inject_halt_reason() + ")";
    g_dropped_offers += g_early.size();
    g_early.clear();
    log::error("Session2: the Troc tunnel STOPS: {}; no retry and no logout by injection (user 2 stays on the "
               "server until the game restarts)",
               why);
    if (g_reconnect) {
        g_lc.quarantine(why);
        log::error("Session2 C4: QUARANTINED: {}; no more logins in this run, the host goes on", why);
    } else if (!g_tunnel_dead) {
        g_tunnel_dead = true;
        g_dead_reason = why;
    }
}

// A guest Req for the server (inject_logic.h). True = dealt with (taken, or
// dropped by policy, or the injection is halted); false = HOLD it, in order,
// and offer it again later (session 2 not ready, or our queue to the server
// full because the server is not taking them: a host pause is one such case).
// Save/cheat Req and non-server packets are dropped by policy. Nothing here
// ends the conversation: only the link (or the hold limit) does.
bool offer(const std::vector<uint8_t>& p) {
    auto v = troc::parse_wire(p, troc::Dir::ToHostServer);
    if (v && never_from_guest(v->opcode)) {
        ++g_blocked_from_guest;
        return true;
    }
    if (v && ckp::guest_req_blocked_by_env(v->opcode, g_block_weather)) {
        if (g_weather_blocked++ == 0) {
            log::info("Session2 W1: user 2's SyncWeatherStateReq 2560 dropped (block_guest_weather=1): the host's field "
                      "weather flags stay the host client's; counted from now on");
        }
        return true;
    }
    // C4: once user 2 has said goodbye (or was logged out), nothing more of it
    // reaches the server: the native logout runs on its own.
    if (server_logout_requested()) {
        ++g_after_goodbye;
        return true;
    }
    if (v && v->opcode == troc::kOpLogoutSessionReq) {
        if (g_reconnect) {
            begin_logout(LogoutTrigger::Goodbye, "goodbye from user 2");
        } else {
            server_logout_user2("goodbye from user 2");
        }
        if (!server_user2_present() && !server_session_ready()) {
            kill_tunnel("user 2 said goodbye before its session existed");  // no silent dead end
        }
        return true;
    }
    // P8 S25 phase B (§3.7, guest_save_tunnel.h): with user 2's own slot live (guest_own_save=1), SaveAutoReq 3037 and a
    // SaveToFileCurrentPlayerReq 2910 for slot 100-108 reach the server (SavePlayerToSlot remaps them to slot 204 or
    // refuses them: never the host's slot); a 2910 for slot 3 or malformed, CreateCharacterReq 2711 and
    // NewGameStartReq 2178 never do. Otherwise as before.
    const gsw::ReqPolicy own = v ? guest_save_req_policy(v->opcode, v->payload) : gsw::ReqPolicy::Default;
    if (own == gsw::ReqPolicy::Block) {
        if (g_own_save_blocked++ < 8) {
            log::warn("Session2 guest save: user 2's Req {} dropped (own-save mode: {})", v->opcode,
                      v->opcode == gsw::kOpSaveToFileCurrentPlayerReq
                          ? "a 2910 must name a manual slot 100-108 with a well-formed payload"
                          : "a new character on the host's server would be saved as the guest's game");
        }
        return true;
    }
    if (v && own != gsw::ReqPolicy::Allow && server_opcode_blocked(v->opcode)) {
        ++g_blocked_from_guest;
        return true;
    }
    // P8 session 15 F2 (fast_travel.h): user 2's ReloadStageStartReq 2283 never writes the host's
    // TransformSync+0x550: dropped here unless F3 (user2_fast_travel=1) takes it or user 2 is in a field of its own.
    // Judged on every offer (a held Req is offered again), counted and logged once, on its final disposition.
    const FastTravelVerdict ft = v ? fast_travel_host_judge(v->opcode, v->payload) : FastTravelVerdict{};
    if (ft.drop) {
        fast_travel_host_record(ft, "dropped by F2");
        return true;
    }
    // P8 S16 (observer_milestone.h, observer_milestone_reload): user 2's PreLoadSequencerReq 2873 of a reload trip
    // in the host's field never re-prepares the host's sequencers: mode 1 drops it here (its 2322 is emitted on the
    // server's thread at its next Req). Judged on every offer, recorded once on its final disposition.
    const ReloadVerdict rv = v ? observer_milestone_reload_judge(v->opcode) : ReloadVerdict{};
    if (rv.drop) {
        observer_milestone_reload_record(rv, /*handed=*/false);
        travel_probe_on_user2_2873(/*handed=*/false);
        return true;
    }
    // P8 S1 option A (observer_seq_copy.h): user 2 never drives the host's sequencers (nor, while it
    // observes the host's field, its stage candidates). Dropped and counted there (probe: only counted).
    // quest_policy (user2_funnels.h, politica-misiones.md): user 2's 2372 never reaches the host's quest manager.
    // Judged on every offer (a held Req is offered again), recorded once on its final disposition.
    const QuestPolicyVerdict qp = v ? user2_funnels_policy_judge(v->opcode, v->payload) : QuestPolicyVerdict{};
    if (qp.drop) {
        user2_funnels_policy_record(qp, /*handed=*/false);
        return true;
    }
    const bool seq_filtered = v && observer_seq_copy_filter_req(v->opcode, v->payload);
    // P8 session 13 (shop_probe.h): user 2's 2671/2720/2436/2591 and that filter's verdict, counted only.
    if (v) shop_probe_on_user2_req(v->opcode, v->payload, seq_filtered);
    if (seq_filtered) {
        user2_funnels_policy_record(qp, /*handed=*/false);
        return true;
    }
    // Not a server Req (e.g. the client's own 1001 connect frame): not for
    // the server, dropped and counted.
    if (!v || !server_opcode_known(v->opcode)) {
        ++g_unknown_from_guest;
        fast_travel_host_record(ft, "not a server Req here");
        user2_funnels_policy_record(qp, /*handed=*/false);
        return true;
    }
    const inj::Outcome o = server_inject_ex(p);
    switch (inj::disposition(o)) {
        case inj::Disposition::Done:
            fast_travel_host_record(ft, "handed to the server");
            user2_funnels_policy_record(qp, /*handed=*/true);
            observer_milestone_reload_record(rv, /*handed=*/true);
            if (v->opcode == omr::kOpPreLoadSequencerReq) travel_probe_on_user2_2873(/*handed=*/true);
            if (own == gsw::ReqPolicy::Allow) {
                guest_save_tunnel_note_req(v->opcode, v->payload);
                if (g_own_save_allowed++ < 16) {
                    const auto s = gsw::parse_save_req(v->payload);
                    log::info("Session2 guest save: user 2's {} {}{} handed to the server ({})",
                              v->opcode == gsw::kOpSaveAutoReq ? "SaveAutoReq" : "SaveToFileCurrentPlayerReq", v->opcode,
                              s ? std::format(" (slot {}{})", s->slot, gsw::is_final_save_req(v->payload) ? ", the guest's final save" : "")
                                : std::string(),
                              v->opcode == gsw::kOpSaveAutoReq
                                  ? "a 3037 queues an autosave of reason 7, which does not save now (guest_save_wire.h)"
                                  : "own-save mode: it saves now, to slot 204, then to the guest");
                }
            }
            return true;
        case inj::Disposition::Hold:
            ++g_held_offers;
            return false;
        case inj::Disposition::Drop:
            fast_travel_host_record(ft, "dropped by the tunnel's policy");
            user2_funnels_policy_record(qp, /*handed=*/false);
            ++g_dropped_offers;
            if (g_dropped_logged < 16) {
                ++g_dropped_logged;
                log::warn("Session2: user 2's Req {} dropped ({}); the conversation goes on", v->opcode,
                          inj::outcome_name(o));
            }
            return true;
        case inj::Disposition::Stop:
            fast_travel_host_record(ft, "not handed: the injection stopped");
            user2_funnels_policy_record(qp, /*handed=*/false);
            halt_tick();
            return true;
    }
    return true;
}

// The server's packets for user 2, after this client's own mount events (mount_sync.h). Order: the outgoing
// queue is taken FIRST, then the events are drained: a 2991 the server wrote for the host's mount Req was queued
// after that Req, which the host client sent after its vf53 entry (the MountBegin), so every Begin that precedes a
// packet taken here is already in the ring and goes before it.
void push_outgoing(troc::TrocLink& link) {
    auto out = server_take_outgoing();
    std::vector<uint8_t> f;
    while (mount_sync_pop_outbound(f)) link.push(f);
    if (focus_follow_pop_outbound(f)) link.push(f);  // which character the host plays (state 16)
    // P8 S29 (tree_bend.h): the host's own tree bends (state 15), in this conversation only.
    while (tree_bend_pop_outbound(f)) link.push(f);
    for (auto& p : out) link.push(p);
}
void discard_mount_events() {
    std::vector<uint8_t> f;
    while (mount_sync_pop_outbound(f)) {
    }
    tree_bend_discard_outbound();  // P8 S29: no conversation for the host's bends
    focus_follow_discard_outbound();
}

// Keeps a Req that could not be offered now, in order. Past the bound the
// conversation cannot stay consistent: that, not the wait, ends it.
void hold_req(std::vector<uint8_t>&& p) {
    if (g_early.size() >= kMaxEarly) {
        kill_tunnel(std::format("more than {} Req held (session 2 not ready, or the server not taking user 2's Req "
                                "for too long: {} more were waiting in the queue to the server)",
                                kMaxEarly, server_inject_pending()));
        return;
    }
    g_early.push_back(std::move(p));
}

// Offers the held Req in order; stops at the first one that must still wait
// (and waits kHoldRetryMs before the next try).
template <class StillActive>
void drain_held(StillActive still_active) {
    const uint64_t now = GetTickCount64();
    if (g_early.empty() || now < g_hold_retry_at) return;
    // P8 mounts: how many held Req went on after a mount_sync hold (the summary's 'released').
    static bool s_ms_held = false;
    size_t released = 0;
    while (!g_early.empty() && still_active()) {
        // P8 mounts (mount_sync.h, mode 1): user 2's Req wait while a MountBegin of its character waits for its
        // MountCommit (bounded); then they go on in their order.
        if (mount_sync_host_holding(g_early.size())) {
            s_ms_held = true;
            break;
        }
        if (!offer(g_early.front())) {
            g_hold_retry_at = now + kHoldRetryMs;
            break;
        }
        if (!g_early.empty()) g_early.pop_front();  // begin_logout may have emptied it
        if (s_ms_held) ++released;
    }
    if (s_ms_held && released && !mount_sync_host_holding(g_early.size())) {
        mount_sync_note_hold(true, released);
        s_ms_held = false;
    }
}

// ---------------------------------------------------------------- C4: reconnect (guest_lifecycle.h)

// User 2's keys while it is valid: from the moment it exists until its 2001
// is handed (after that the native logout may free it at any time).
void capture_user2() {
    if (server_user2_present() && !server_logout_handed()) server_capture_user2(g_snap);
}

// ACTIVE -> RETIRING: one native logout, whatever the trigger (salida.md §4.1).
void begin_logout(LogoutTrigger t, const std::string& why) {
    const uint32_t epoch = g_lc.epoch();
    if (!g_lc.begin_logout(t, g_now_ms)) return;  // only once, from ACTIVE
    capture_user2();
    g_after_goodbye += g_early.size();  // what had not reached the server yet never will
    g_early.clear();
    mount_sync_reset("user 2 logs out");  // P8 mounts (review (7))
    if (t == LogoutTrigger::LinkLost) log::error("Session2: the Troc tunnel stops for epoch {}: {}", epoch, why);
    log::info("Session2 C4: logout begin epoch={} user=0x{:08X} trigger={} ({}); {} keys of user 2 captured",
              epoch, g_snap.user_key, logout_trigger_name(t), why, g_snap.keys.size());
    // P8 S25 phase B (§3.6): a lost link with user 2's own save active saves it first (one SaveToFileCurrentPlayerReq
    // 2910 before the 2001); a guest that says goodbye sent its own 2910 before its 2001.
    server_logout_user2(t == LogoutTrigger::Goodbye ? why : "link lost: " + why,
                        t == LogoutTrigger::LinkLost && guest_save_final_save_wanted());
    if (server_logout_handed()) g_lc.note_handed(g_now_ms);
    g_last_pattern = ~0u;
    g_last_barrier_ms = 0;
}

// C2: an identity failure seen on the server thread (identity_fix.cpp) asks
// for user 2's native logout here, on the network thread, like a goodbye.
void identity_logout_tick() {
    std::string why;
    if (!identity_fix_take_logout(why)) return;
    if (g_reconnect) {
        begin_logout(LogoutTrigger::Goodbye, why);
    } else {
        server_logout_user2(why);
    }
}

// READY -> ACTIVE: a new connection after the barrier gets epoch+1 and a new session 2. P8 re-entry: inband_for != 0
// = the same connection, asked for by the guest's REJOIN for that conversation (GuestLifecycle::start_epoch_inband).
void start_epoch(uint32_t link_epoch, uint32_t inband_for = 0) {
    const uint32_t next = g_lc.epoch() + 1;
    // Review of c4367f8, 6: the previous user 2's keys are forgotten only with rejoin on (rejoin=0: as before).
    if (!server_begin_epoch(next, rjl::host_forgets_user2_keys(g_rejoin))) {
        g_lc.quarantine(std::format("the server side could not begin epoch {}", next));
        log::error("Session2 C4: QUARANTINED: {}", g_lc.quarantine_reason());
        return;
    }
    if (inband_for) {
        g_lc.start_epoch_inband(link_epoch);
    } else {
        g_lc.start_epoch(link_epoch);
    }
    g_rejoin_started_for = inband_for;
    g_rejoin_started_ms = g_now_ms;
    g_snap = DepartedSnap{};
    g_baseline = FieldSnap{};
    g_user_seen = false;
    g_early.clear();
    mount_sync_reset("a new guest connection");  // P8 mounts (review (7))
    g_link_down_since_ms = 0;
    g_last_pattern = ~0u;
    g_last_barrier.clear();
    if (g_link) g_link->reset();  // its broken state belonged to the old conversation
    if (inband_for) {
        ++c_rejoin_started;
        log::info("Session2 C4: epoch={} begins IN-BAND on the same guest connection (link {}, guest conversation {}); "
                  "a new session 2 is built for it",
                  next, link_epoch, inband_for);
    } else {
        log::info("Session2 C4: epoch={} begins on a new guest connection (link {}); a new session 2 is built for it",
                  next, link_epoch);
    }
    // P8 re-entry: the new epoch's EPOCH goes first (after the reset), ahead of its first "ready" and of anything the
    // new session 2 writes.
    if (g_link) {
        push_epoch(*g_link, inband_for ? rjl::Reason::StartRejoin : rjl::Reason::StartConnection, inband_for);
    }
}

// P8 re-entry: the guest's REJOIN (state 13), before the C4 admission (a READY host admits nothing). Network thread.
void on_guest_rejoin(const std::vector<uint8_t>& packet, uint32_t link_epoch) {
    ++c_rejoin_in;
    const auto r = rjl::parse_rejoin_frame(packet);
    if (!r) {
        ++c_rejoin_bad;
        return;
    }
    rjl::HostIn in;
    in.mode = g_reconnect ? g_rejoin : rjl::Mode::Off;
    in.state = c4_state();
    in.conversation = g_lc.conversation();
    in.started_for = g_rejoin_started_for;
    in.request = *r;
    rjl::HostAction a = rjl::host_decide(in);
    if (a == rjl::HostAction::StartInBand && !g_lc.may_start_inband(link_epoch)) a = rjl::HostAction::Ignore;
    const uint32_t epoch_before = g_lc.epoch();
    bool adopted = false;
    switch (a) {
        case rjl::HostAction::StartInBand: start_epoch(link_epoch, r->conversation); break;
        case rjl::HostAction::Repeat:
            ++c_rejoin_repeat;
            // Review of c4367f8, 8: an unbound epoch begun by a new transport connection is free: it becomes this
            // conversation's (and the unused-grant timeout applies to it).
            if (g_rejoin_started_for == 0) {
                g_rejoin_started_for = r->conversation;
                g_rejoin_started_ms = g_now_ms;
                adopted = true;
            }
            if (g_link) push_epoch(*g_link, rjl::Reason::StartRejoin, g_rejoin_started_for);
            break;
        case rjl::HostAction::ProbeWould:
            ++c_rejoin_probe;
            if (g_link) push_epoch(*g_link, rjl::Reason::ProbeWould, r->conversation);
            break;
        case rjl::HostAction::Ignore:
            ++c_rejoin_ignored;
            if (g_link) push_epoch(*g_link, rjl::Reason::Ignored, r->conversation);
            break;
        case rjl::HostAction::Off: ++c_rejoin_off; break;
    }
    // Review of c4367f8, 7: the probe's answers are rate-limited like the rest; a start always has its line.
    if (a == rjl::HostAction::StartInBand || adopted || g_rejoin_lines < kRejoinLines) {
        ++g_rejoin_lines;
        log::info("Session2 rejoin [{}]: the guest asks for conversation {} ({}; it last played epoch {}) | C4 {} epoch "
                  "{} on link {} -> {}",
                  rjl::mode_name(in.mode), r->conversation, r->kind == rjl::Kind::Probe ? "probe" : "real",
                  r->last_epoch, rjl::host_state_name(in.state), epoch_before, link_epoch,
                  a == rjl::HostAction::ProbeWould
                      ? std::format("probe: would begin epoch {} in-band (nothing started)", epoch_before + 1)
                  : adopted ? std::format("the free epoch {} (begun on a new connection, nobody spoke yet) is now this "
                                          "conversation's",
                                          epoch_before)
                            : std::string(rjl::host_action_name(a)));
    }
}

void barrier_tick(uint32_t now) {
    const uint32_t epoch = g_lc.epoch();
    BarrierReadings r;
    r.early = g_early.size();
    r.expect_handed = g_lc.handed();
    server_barrier_read(epoch, g_snap, r);
    g_last_barrier_reads = std::format("a session {:.1f} ms, b {} keys {:.1f} ms, b user list {:.1f} ms, c field {:.1f} ms",
                                       r.us_session / 1000.0, g_snap.keys.size(), r.us_keys / 1000.0,
                                       r.us_list / 1000.0, r.us_field / 1000.0);
    const BarrierResult b = evaluate_barrier(g_baseline, g_snap, r);
    g_last_barrier = b.describe();
    if (b.pattern() != g_last_pattern) {
        g_last_pattern = b.pattern();
        log::info("Session2 C4: barrier epoch={} check a session {} ({})", epoch, b.session.pass ? "pass" : "FAIL",
                  b.session.detail);
        log::info("Session2 C4: barrier epoch={} check b sam {} ({})", epoch, b.sam.pass ? "pass" : "FAIL",
                  b.sam.detail);
        log::info("Session2 C4: barrier epoch={} check c field {} ({})", epoch, b.field.pass ? "pass" : "FAIL",
                  b.field.detail);
        log::info("Session2 C4: barrier epoch={} check d queues {} ({})", epoch, b.queues.pass ? "pass" : "FAIL",
                  b.queues.detail);
        // Diagnostics only (salida-en-carga.md §2): what a stuck logout waits for.
        if (!r.move_diag.empty() || r.nak_after_logout) {
            log::info("Session2 C4: barrier epoch={} diagnostics: attached user {} | Nak 1013 after the 2001 {}", epoch,
                      r.move_diag.empty() ? std::string("none") : r.move_diag, r.nak_after_logout);
        }
    }
    const bool nothing_reached = !server_epoch_reached(epoch) && !g_user_seen && !g_snap.any();
    // The server took every buffer of the epoch and none for a while, and no
    // user 2 ever existed (a refused login): there is nothing to log out.
    static uint64_t seen_last = ~0ull;
    static uint32_t seen_change_ms = 0;
    if (r.pb_seen != seen_last) {
        seen_last = r.pb_seen;
        seen_change_ms = now;
    }
    const bool quiet_without_user = !g_user_seen && !g_snap.any() && r.pb_pushed == r.pb_seen &&
                                    now - seen_change_ms >= g_lc.config().quiet_ms;
    switch (g_lc.on_barrier(now, nothing_reached, b, quiet_without_user)) {
        case GuestLifecycle::Step::Wait:
            break;
        case GuestLifecycle::Step::Clean:
            log::info("Session2 C4: logout complete epoch={} ({})", epoch,
                      g_lc.handed() ? "native logout finished: " + g_last_barrier
                                    : std::string("nothing of it had reached the server"));
            // A guest that reconnected during the logout is already newer than the epoch it left: it may start the next.
            if (const uint32_t link_now = g_link ? g_link->session_epoch() : 0;
                g_lc.make_ready(g_lc.bound_link() && *g_lc.bound_link() < link_now ? *g_lc.bound_link() : link_now)) {
                log::info("Session2 C4: reconnect epoch={} ready (a NEW guest connection starts it)", epoch + 1);
            } else {
                log::error("Session2 C4: QUARANTINED: {}; no more logins in this run, the host goes on",
                           g_lc.quarantine_reason());
            }
            break;
        case GuestLifecycle::Step::Quarantined:
            log::error("Session2 C4: QUARANTINED: {}; no more logins in this run, the host goes on (guards kept)",
                       g_lc.quarantine_reason());
            log::error("Session2 C4: barrier at quarantine: {}", g_last_barrier);
            log::error("Session2 C4: diagnostics at quarantine: attached user {} | Nak 1013 after the 2001 {}",
                       r.move_diag.empty() ? std::string("none") : r.move_diag, r.nak_after_logout);
            break;
    }
}

void tunnel_tick_reconnect(troc::TrocLink& link, uint32_t now_ms) {
    g_link = &link;
    g_now_ms = now_ms;
    const uint32_t le = link.session_epoch();
    // A new connection, noticed before link.tick() would call the link broken.
    if (le != g_last_link_epoch) {
        g_last_link_epoch = le;
        if (g_lc.state() == GuestState::Active) {
            if (!g_lc.conversation()) {
                link.reset();  // nobody had said anything yet: nothing to lose
                // The guest that asked for this epoch is gone and a new process took its place. The epoch is now that
                // process's, however long it stays at the title: giving it up would leave READY waiting for a
                // connection newer than the one already here, and nobody would ever start the next epoch.
                g_rejoin_started_for = 0;
            } else if (*g_lc.bound_link() != le) {
                kill_tunnel("the guest's connection restarted");
            }
        }
    }
    // Every tick: the connection may have come during the logout or come later. Stays broken on a failed identity.
    if (g_lc.link_reset_due(link.broken())) {
        link.reset();
        if (!link.broken() && g_ready_reset_link != le) {
            g_ready_reset_link = le;
            log::info("Session2 C4: the broken link starts over in READY (connection {}): the next guest's identity can "
                      "arrive",
                      le);
        }
    }
    // Every tick, not only the one that saw the new epoch: connected() also needs the peer's identity, a round trip
    // later. Nothing else would start it: the guest sends nothing until READY, and READY needs an active epoch.
    if (g_lc.state() == GuestState::Ready && link.connected() && g_lc.may_start(le)) {
        start_epoch(le);
    }
    // Review of c4367f8, 1: an epoch begun for a re-entry that nobody used (the guest's client went to its own server,
    // or the guest closed the game) is given up: its logout finds nothing of it on the server and C4 is READY again.
    if (g_rejoin != rjl::Mode::Off &&
        rjl::grant_unused(c4_state(), g_lc.conversation(), g_rejoin_started_for, g_rejoin_started_ms, now_ms)) {
        const uint32_t conv = g_rejoin_started_for;
        g_rejoin_started_for = 0;
        ++c_rejoin_unused;
        log::warn("Session2 rejoin: epoch {} was begun for guest conversation {} and nothing of it came in {} s: it is "
                  "given up (logout without a user 2, then READY again)",
                  g_lc.epoch(), conv, rjl::kGrantUnusedMs / 1000);
        begin_logout(LogoutTrigger::Goodbye, std::format("the epoch begun for guest conversation {} was never used", conv));
    }
    if (g_lc.state() == GuestState::Active) {
        if (link.broken()) {
            if (g_lc.conversation()) {
                kill_tunnel("the link broke (reconnection or overflow)");
            } else {
                link.reset();
            }
        }
        if (g_lc.state() == GuestState::Active && server_outgoing_lost()) kill_tunnel("a packet of the server was lost");
    }
    prof(kPartLinkState);
    // User 2 of this epoch: the baseline of the host's field until it exists (information for check c only: P8 S29,
    // reentrada.md §6), then its keys.
    if ((g_lc.state() == GuestState::Active || g_lc.state() == GuestState::Retiring) &&
        now_ms - g_last_sample_ms >= kSampleMs) {
        g_last_sample_ms = now_ms;
        if (server_user2_present()) {
            if (!g_user_seen) {
                g_user_seen = true;
                log::info("Session2 C4: user 2 of epoch {} exists; host field baseline {}", g_lc.epoch(),
                          g_baseline.ok ? std::format("0x{:X} owner 0x{:08X} users 0x{:X} userActors 0x{:X} open {} "
                                                      "generation 0x{:08X}",
                                                      g_baseline.field, g_baseline.owner, g_baseline.users,
                                                      g_baseline.user_actors, g_baseline.open, g_baseline.generation)
                                        : std::string("not taken (user 2 came in before the host was in its world, "
                                                      "S29 step 2): the barrier's check c is structural only"));
            }
            capture_user2();
        } else if (g_lc.state() == GuestState::Active && !g_user_seen && !server_logout_requested()) {
            FieldSnap f;
            if (server_host_field(f)) g_baseline = f;
        }
    }
    prof(kPartSample);
    identity_logout_tick();
    // A 2001 asked for during the login goes once user 2 exists (keys first).
    if (server_logout_requested() && !server_logout_handed()) capture_user2();
    server_logout_tick();
    if (g_lc.state() == GuestState::Retiring && !g_lc.handed() && server_logout_handed()) g_lc.note_handed(now_ms);
    prof(kPartLogout);
    // A guest that is simply gone (no goodbye, the link never breaks) is logged out too.
    if (link.connected()) {
        g_link_down_since_ms = 0;
    } else if (!g_link_down_since_ms) {
        g_link_down_since_ms = now_ms ? now_ms : 1;
    } else if (g_lc.state() == GuestState::Active && now_ms - g_link_down_since_ms >= kLinkLostMs &&
               server_user2_present()) {
        kill_tunnel(std::format("the guest has been gone for {} s", kLinkLostMs / 1000));
    }
    const bool same_link = g_lc.bound_link() && *g_lc.bound_link() == le && link.connected() && !link.broken();
    if (g_lc.state() == GuestState::Active) {
        if (server_accepts_guest()) drain_held([] { return g_lc.state() == GuestState::Active; });
        prof(kPartHeldReq);
        push_outgoing(link);
    } else if (g_lc.state() == GuestState::Retiring && same_link) {
        push_outgoing(link);  // a guest that said goodbye gets its logout Acks
    } else {
        g_out_discarded += server_take_outgoing().size();
        discard_mount_events();
    }
    prof(kPartOutgoing);
    if (g_lc.state() == GuestState::Retiring && now_ms - g_last_barrier_ms >= kBarrierMs) {
        g_last_barrier_ms = now_ms;
        barrier_tick(now_ms);
    }
    prof(kPartBarrier);
    // Once a second, tell a P8 guest whether it may start a conversation.
    if (link.connected() && now_ms - g_last_control_ms >= 1000) {
        g_last_control_ms = now_ms;
        const bool ours = le >= g_lc.min_link() && (!g_lc.bound_link() || *g_lc.bound_link() == le);
        // P8 re-entry: the C4 state for a guest that speaks states 13-14 (ahead of the ready in the channel).
        push_epoch(link, rjl::Reason::Heartbeat, rjl::heartbeat_conversation(g_lc.conversation(), g_rejoin_started_for));
        const uint8_t state = g_lc.state() == GuestState::Quarantined ? troc::kControlHostDead
                              : g_lc.state() == GuestState::Active && ours && server_accepts_guest()
                                  ? troc::kControlHostReady
                                  : 0;
        if (state) link.push(troc::make(troc::kControlOpcode, -1, std::span<const uint8_t>(&state, 1)));
        push_host_character(link);
    }
    prof(kPartControl);
    link.tick(now_ms);
    prof(kPartLinkFlush);
}

// The end of one tunnel_tick: a slow one is logged with its parts.
void end_tick(const troc::TrocLink& link) {
    if (g_prof.end(now_us(), kSlowTickUs) <= kSlowTickUs || g_slow_tick_lines >= kSlowTickLines) return;
    ++g_slow_tick_lines;
    std::string extra;
    if (g_prof.part_us(kPartBarrier) >= 1000 && !g_last_barrier_reads.empty()) {
        extra += " | barrier reads: " + g_last_barrier_reads;
    }
    if (g_prof.part_us(kPartLinkFlush) >= 1000 || g_prof.part_us(kPartOutgoing) >= 1000) {
        extra += std::format(" | link backlog {} B", link.backlog_bytes());
    }
    log::warn("Session2 host tunnel: one tick took {}{}{}", g_prof.text(kPartNames), extra,
              g_slow_tick_lines == kSlowTickLines ? " (last such line)" : "");
}

// 3527's layout (3527, 3549 and 3576): the join stages below that 3527 requires, 3576 requires as well. A module of
// those not ported to 3576 refuses it, and then the tunnel stays closed, as on 3527.
// Build 1.0.0.3663 (static, 2026-11-13; never run): the same join stages are required (its loading machine still waits
// for the 2322's marker, guest.cpp read_preload_facts), so a stage not ported to 3663 keeps the tunnel closed there too.
// This is about which stages are required, not about struct offsets (each module carries its own).
bool layout_3527() noexcept {
    const auto b = game::current_build();
    return b == game::Build::v3527 || b == game::Build::v3576 || b == game::Build::v3663;
}

}  // namespace

bool install(const Options& opt) {
    const bool writes =
        opt.create_session || opt.accept_tunnel || opt.relay_fix || opt.block_save_trocs || opt.mirror_host ||
        opt.share_field;
    log::info("Session2 (option D): probe {} finder log {} | save guard {} block save trocs {} | create session {} "
              "accept tunnel {} relay fix {} | account {} | mirror {} ({} ms)",
              opt.probe, opt.finder_log, saveguard::mode_name(opt.save_guard), opt.block_save_trocs,
              opt.create_session, opt.accept_tunnel, opt.relay_fix, opt.account, opt.mirror_host,
              opt.mirror_delay_ms);
    if (writes && opt.save_guard == saveguard::Mode::Off) {
        log::error("Session2: the stages that write to the game need [session2] save_guard=1 (or redirect); option "
                   "D stays off");
        return false;
    }
    // The guard only when something writes to the game (review finding 6):
    // the read-only stages (probe, finder log) leave saving alone.
    // RPT-0 (K1): before anything can make a save fail, the game's error
    // reports with files attached are cut (docs/research/opcion-d-rpt0.md).
    // If a later step fails it stays cut: the conservative side.
    // save_guard=trace (session 24) lets option D run with the saves NOT
    // protected, to log the game's save sequence: a lab with copied saves.
    // save_guard=redirect (session 24): the game saves into a sandbox copy of
    // the folder (pendientes/p8-guardado-desviado.md); block if it cannot.
    if (writes && !report_guard_install()) return false;
    // P8 S35 phase E (host_save_export.h): host_save=export|probe archives the previous sandbox before the rebuild.
    if (writes) {
        const bool v3527 = game::current_build() == game::Build::v3527;
        const bool v3549 = game::is_3549();
        const bool v3576 = game::is_3576();
        const bool v3663 = game::is_3663();
        host_save_configure({loaded_config().s2_host_save, loaded_config().s2_host_save_dir,
                             loaded_config().s2_host_save_keep,
                             v3663   ? "1.0.0.3663"
                             : v3576 ? "1.0.0.3576"
                             : v3549 ? "1.0.0.3549"
                             : v3527 ? "1.0.0.3527"
                                     : "",
                             v3663   ? "0x6AF5D198"
                             : v3576 ? "0x6AED2E85"
                             : v3549 ? "0x6AEB7D59"
                             : v3527 ? "0x6AEA07A6"
                                     : ""});
    }
    if (writes && !save_hooks_install(opt.save_guard)) return false;
    if (opt.block_save_trocs) {
        log::warn("Session2: block_save_trocs is not implemented yet (decision D-5): save Req are only counted");
    }
    if (opt.accept_tunnel && !opt.create_session) {
        log::warn("Session2: accept_tunnel needs create_session=1; the tunnel stays closed");
    }
    if (opt.mirror_host && !opt.create_session) log::warn("Session2: mirror_host needs create_session=1; mirror off");
    ServerOptions so;
    so.probe = opt.probe;
    so.finder_log = opt.finder_log;
    so.create_session = opt.create_session;
    so.accept_tunnel = opt.accept_tunnel && opt.create_session;
    so.relay_fix = opt.relay_fix;
    so.mirror_host = opt.mirror_host && opt.create_session;
    so.mirror_delay_ms = opt.mirror_delay_ms;
    so.account = opt.account;
    // P-RELOJ (pendientes/reloj.md): before session 2 exists (server_install
    // builds it and opens the tunnel), user 2's travels and loads stop
    // publishing the world clock; its parking field's fixed time froze the
    // host's world at midnight with scale 0 (C1e-C4b). No gate, no guest.
    if (opt.clock_gate && opt.create_session && !clock_gate_install()) {
        log::error("Session2: the clock gate could not be installed and user 2's login would freeze the world "
                   "clock (reloj.md); option D stays off");
        return false;
    }
    if (!opt.clock_gate && opt.create_session) {
        log::warn("Session2: clock_gate=0: user 2's login will freeze the world clock (reloj.md)");
    }
    if (!server_install(so)) return false;
    // P8 session 25 (clock_push.h, research/noche/clima-hora.md §5): the host's world clock to user 2 (T1 after its
    // 2762s, T2 on a publish), and W1: user 2's 2560 never writes the host field's weather flags. Before the tunnel.
    clock_push_configure(loaded_config().s2_user2_clock_push, opt.create_session);
    g_block_weather = loaded_config().s2_block_guest_weather && opt.create_session;
    if (loaded_config().s2_block_guest_weather && !opt.create_session) {
        log::warn("Session2: block_guest_weather needs create_session=1; off");
    }
    if (g_block_weather) {
        log::info("Session2 W1 ON (block_guest_weather=1): user 2's SyncWeatherStateReq 2560 never reaches the host's "
                  "server (it would write the host field's weather flags, 0x20E6FE0, with no owner check); counted");
    }
    // C2 (pendientes/identidad.md §5): before the tunnel opens and before the
    // probe (which then shares its two entry hooks). Wanted and not installed:
    // user 2's logins are refused (§5.2 fail safe), the host goes on.
    if (opt.identity_fix && !opt.create_session) log::warn("Session2: identity_fix needs create_session=1; off");
    if (opt.identity_fix && opt.create_session) {
        identity_fix_set_wanted(true);
        if (!identity_fix_install()) {
            log::error("Session2: the C2 identity fix could not be installed; option D REFUSES user 2's logins "
                       "(LoginUserToFieldServerReq / LoginCharacterToFieldServerReq) instead of sharing the host's "
                       "characterNo");
            return false;
        }
    }
    if (!opt.identity_fix && opt.create_session) {
        log::warn("Session2: identity_fix=0: user 2's character shares the host's characterNo 0x7FFFFFFFFFFFFFFF "
                  "(identidad.md)");
    }
    // C2-0 (pendientes/identidad.md §6): read only, before the tunnel opens
    // (nothing of user 2 reaches the server until install() returns). Only
    // diagnostics: if it cannot go in, option D goes on without it.
    if (opt.identity_probe && !opt.create_session) log::warn("Session2: identity_probe needs create_session=1; off");
    if (opt.identity_probe && opt.create_session && !identity_probe_install()) {
        log::warn("Session2: the C2 identity probe could not be installed; option D goes on without it");
    }
    // P8 session 25 (noche/progreso-invitado.md, "Implementado (fase A)"): user 2's own save slot in the save
    // sandbox. Before the tunnel opens (its LoadSlot hook must see user 2's first login) and after the C2 fix and
    // probe (it shares their 0x20688A0 entry hook). Needs save_guard=redirect; otherwise forced off (one line).
    {
        const std::string& raw = loaded_config().s2_guest_own_save;
        const gsv::ParsedMode p = gsv::parse_mode(raw);
        if (!p.known) {
            log::warn("Session2: guest_own_save='{}' is not 0, probe or 1; it stays off", raw);
        } else if (p.mode != gsv::Mode::Off && !opt.create_session) {
            log::warn("Session2: guest_own_save='{}' needs create_session=1; it stays off", raw);
        } else if (p.mode != gsv::Mode::Off) {
            GuestSaveOptions go;
            go.mode = p.mode;
            go.debug_dir = loaded_config().s2_guest_own_save_debug_dir;
            const uint64_t peer = loaded_config().steam_peer_id;
            go.guest_id = peer ? std::to_string(peer) : std::string(go.debug_dir.empty() ? "unknown" : "local-debug");
            // Phase B (guest_save_tunnel.h): the tunnel's states 6-11 once the hooks are in (nothing when forced off).
            if (guest_save_install(go)) guest_save_tunnel_install();
        }
    }
    // Companions step A (pendientes/companeros.md §A): read only, same rules. Its
    // restore point sits after 0x8646D0's first 16 bytes (horse_diag's, below).
    if (opt.companion_probe && !opt.create_session) log::warn("Session2: companion_probe needs create_session=1; off");
    if (opt.companion_probe && opt.create_session && !companion_probe_install()) {
        log::warn("Session2: the companion probe could not be installed; option D goes on without it");
    }
    // E3b: without it user 2 keeps its own field (E3); a failure here leaves
    // the rest of option D as it was.
    if (opt.share_field && !opt.create_session) log::warn("Session2: share_field needs create_session=1; off");
    if (opt.share_field && opt.create_session) {
        if (!interaction_condition_install()) {
            log::error("Session2: required interaction serializer fix unavailable; the tunnel stays closed");
            return false;
        }
        if (!field_share_install()) {
            log::error("Session2: shared-field hooks could not be installed; the tunnel stays closed");
            return false;
        }
        // Not a reason to close the tunnel: the players would still share a world, just unseen (logged).
        (void)remote_visible_install();
        // C1: user 2's character reaches the host's client with an action
        // chart but no action, and animating it crashed (exe+0x1F63FE6). The
        // co-op's guards: 0x2329700 skips the layer update of the keys they
        // are given (now also user 2's character, set from its
        // MainPlayerDataStartAck, which comes before it enters any field);
        // 0x1F63F70 advances nothing on ANY layer with no playback, the state
        // in which the original would crash reading [0+0x10].
        if (!net::puppet_install_layer_guards()) {
            log::error("Session2 E3b: the action-layer crash guards could not be installed; the tunnel stays closed");
            return false;
        }
        // C1b/C1d: the guards above held, then the movement update crashed
        // (0x88F832, called only from CharacterControl::PostUpdate 0x860D30).
        // The co-op's containment skips the whole character update (0x85FBA0)
        // and post-update (0x860D30) of a copy while it has no action.
        if (!net::horse_diag_install(/*contain=*/true)) {
            log::error("Session2 E3b: the character-update containment could not be installed; the tunnel stays closed");
            return false;
        }
    }
    // D-53 (pendientes/companeros-publicacion.md §3): the root fix of the
    // companions' crashes. A child of any user (user 2's, and since G1 the
    // host's too) reaches the other users only once the server accepted its
    // first action (restore byte 1), as Kliff since D-48. Before the tunnel opens, like every hook above. Without it the
    // children are published as before, with restore 0, and only the D-52
    // containment on the host's client stands between them and its readers.
    if (opt.child_hold && !opt.create_session) log::warn("Session2: child_hold needs create_session=1; off");
    if (opt.observer_hold && !opt.create_session) log::warn("Session2: observer_hold needs create_session=1; off");
    // P8 (pendientes/p8-character-hold.md): character_hold, the same two hooks for a user's main character.
    const bool character_hold = loaded_config().s2_character_hold;
    if (character_hold && !opt.create_session) log::warn("Session2: character_hold needs create_session=1; off");
    // S3 (pendientes/p8-impl-s3.md): observer_hold extends the same two hooks
    // to the NPCs a user controls; with observer_hold=0 this is D-53 as before.
    // P8 review I3: the thread rule has its own key (default 0 = as before the rule).
    child_hold_set_thread_rule(loaded_config().s2_notify_thread_rule);
    // P8 session 8 pets (pendientes/p8-impl-mascotas.md): child_settle_ms, the same two hooks for a user's
    // child announced together with (or just after) its owner's character.
    const uint32_t settle_ms = loaded_config().s2_child_settle_ms;
    if (settle_ms && !opt.create_session) log::warn("Session2: child_settle_ms needs create_session=1; off");
    child_hold_set_settle_ms(opt.create_session ? settle_ms : 0);
    // P8 session 14 (pendientes/p8-impl-spawn-action.md): observer_load_defer, observer_hold's split and passes for
    // the NPCs announced to user 2 while it loads.
    {
        const std::string& raw = loaded_config().s2_observer_load_defer;
        const u2f::ParsedMode p = u2f::parse_mode(raw);
        uint8_t mode = 0;
        if (!p.known) {
            log::warn("Session2: observer_load_defer='{}' is not 0, probe or 1; it stays off", raw);
        } else if (p.mode != u2f::Mode::Off && !(opt.observer_hold && opt.create_session)) {
            log::warn("Session2: observer_load_defer='{}' needs observer_hold=1 (and create_session=1); it stays off",
                      raw);
        } else {
            mode = static_cast<uint8_t>(p.mode);
        }
        child_hold_set_load_defer(mode);
        if (mode) {
            log::info("Session2: observer_load_defer {}: an NPC the host controls announced to user 2 while user 2 "
                      "loads (login or field change, until its 2762) {} (max wait {} ms; observer_hold's own holds "
                      "wait for the 2762 too{})",
                      mode >= 2 ? "ON" : "PROBE",
                      mode >= 2 ? "is withheld from user 2 even with restore 1 and announced natively after its 2762"
                                : "is counted and logged (WOULD be withheld); nothing is withheld",
                      hold::kLoadDeferMaxMs, mode >= 2 ? "" : " only with 1");
        }
    }
    // P8 S15/S16 (pendientes/p8-s14-viajeros.md §7): observer_hold_family (the old observer_hold_pieces is its
    // alias), user 2 never gets an actor record before its parent's.
    {
        const bool alias = loaded_config().s2_observer_hold_family.empty();
        const std::string& raw = alias ? loaded_config().s2_observer_hold_pieces : loaded_config().s2_observer_hold_family;
        const char* key = alias ? "observer_hold_pieces (alias of observer_hold_family)" : "observer_hold_family";
        const u2f::ParsedMode p = u2f::parse_mode(raw);
        uint8_t mode = 0;
        if (!p.known) {
            log::warn("Session2: {}='{}' is not 0, probe or 1; it stays off", key, raw);
        } else if (p.mode != u2f::Mode::Off && !(opt.observer_hold && opt.create_session)) {
            log::warn("Session2: {}='{}' needs observer_hold=1 (and create_session=1); it stays off", key, raw);
        } else {
            mode = static_cast<uint8_t>(p.mode);
        }
        if (!alias && loaded_config().s2_observer_hold_pieces != "0") {
            log::info("Session2: observer_hold_pieces='{}' is ignored: observer_hold_family='{}' is set",
                      loaded_config().s2_observer_hold_pieces, raw);
        }
        child_hold_set_family(mode);
        if (mode) {
            log::info("Session2: {} {}: an actor record (0xB key) whose parent (hierarchy +0x{:X} -> key +0x{:X}) is "
                      "withheld from a session, or has not been announced to user 2 yet, {} (table of {}; waits at most "
                      "{} ms for a parent that is not withheld, {} ms with a withheld one; 2356 joins "
                      "observer_hold_acks' held opcodes)",
                      key, mode >= 2 ? "ON" : "PROBE", hold::kComponentsHierarchy, hold::kHierParent,
                      mode >= 2 ? "is withheld there too and announced right behind its parent (in its release, or "
                                  "right after the engine announces it; dropped with it; natively if it never comes)"
                                : "is counted and logged (WOULD be withheld); nothing is withheld",
                      hold::kFamilyTableCapacity, hold::kFamilyOrphanMs, hold::kFamilyMaxHoldMs);
        }
        if (opt.observer_hold && opt.create_session) {
            log::info("Session2: family order: every 2005 / 2516 queued for user 2 is checked; a record naming a parent "
                      "user 2 has not been given is counted as an ORPHAN (WRN line; 0 is the native order)");
        }
    }
    // S35 fase A (docs/research/s25/s35-fase-a.md; AUDITORIA.md §1 "Cambios obligatorios"): the safe publication
    // invariant, an admission rule on every publication exit of observer_hold / observer_hold_family.
    {
        const std::string& raw = loaded_config().s2_publication_gate;
        const u2f::ParsedMode p = u2f::parse_mode(raw);
        uint8_t mode = 0;
        if (!p.known) {
            log::warn("Session2: publication_gate='{}' is not 0, probe or 1; it stays off", raw);
        } else if (p.mode != u2f::Mode::Off && !(opt.observer_hold && opt.create_session)) {
            log::warn("Session2: publication_gate='{}' needs observer_hold=1 (and create_session=1); it stays off", raw);
        } else {
            mode = static_cast<uint8_t>(p.mode);
        }
        child_hold_set_publication_gate(mode, loaded_config().s2_publication_retain_max_ms);
    }
    if ((opt.child_hold || opt.observer_hold || character_hold || settle_ms) && opt.create_session &&
        !child_hold_install(opt.child_hold, opt.observer_hold, character_hold)) {
        if (settle_ms) {
            log::error("Session2: the child settle could not be installed; a user's child goes in the same 2005 as "
                       "its owner's character as before");
        }
        if (character_hold) {
            log::error("Session2: the character hold could not be installed; a user's character reaches the other "
                       "user with restore 0 as before");
        }
        if (opt.child_hold) {
            log::error("Session2: the child hold (D-53) could not be installed; option D goes on WITHOUT holding the "
                       "users' children (they reach the other user with restore 0; only the host's client has the D-52 "
                       "containment)");
        }
        if (opt.observer_hold) {
            log::error("Session2: the observer hold (S3) could not be installed; NPCs reach the other user with "
                       "restore 0 as before");
        }
    }
    if (!opt.child_hold && opt.share_field && opt.create_session) {
        log::warn("Session2: child_hold=0: user 2's children reach the host without an action (only D-52 contains it)");
    }
    // P8 S1+S2 (pendientes/p8-observador-escenas.md): read-only ledger of the stage/sequencer packets and of
    // what a non-owner entry lacks. Its own thread; nothing is sent (the send mode is refused).
    // P8 S2 (pendientes/p8-2322-observador.md): the native 2322 for user 2 as an observer. Decided (and,
    // with observer_milestone_send=1, emitted) in observer_stage's entry hook: that hook is installed in
    // measure mode if observer_stage_sync=0. Configured first: observer_stage's thread verifies its code.
    const Config& lc = loaded_config();
    // p8-tunel-rendimiento.md: how the C4 readings read game memory (network thread).
    set_probe_safe_reads(lc.s2_c4_safe_reads);
    if (lc.s2_c4_safe_reads) {
        log::info("Session2: c4_safe_reads=1: the C4 readings check every page with VirtualQuery first (slow on the "
                  "game's heap regions)");
    } else {
        // P8 review I2 (p8-revision-noche.md, "Correcciones"): the default is a pure cost change, said once.
        log::info("Session2: C4 readings with SEH-guarded direct reads (default; c4_safe_reads=1 = VirtualQuery "
                  "first): same values and failures, a guard page touched is re-armed");
    }
    // P8 S3 (pendientes/p8-escenas-y-acks.md §3): a withheld NPC's per-actor packets wait for its 2005.
    bool acks_on = false;  // S46 T2 needs it
    if (lc.s2_observer_hold_acks) {
        if (!opt.create_session || !(observer_hold_active() || character_hold_active())) {
            log::warn("Session2: observer_hold_acks needs observer_hold=1 or character_hold=1 (installed) and "
                      "create_session=1; off");
        } else {
            observer_hold_acks_configure(true);
            acks_on = true;
            log::info("Session2: observer_hold_acks ON: the per-NPC packets (2723, 2404, 2586, 2991, 2697, 2642, 2506, "
                      "2402, 2645, 2434; actor key at +0) of an NPC observer_hold withholds from user 2 wait in "
                      "take_frame for its 2005 and go right after it, in their order; a dropped hold discards them; "
                      "at most 1024 keys, 32 packets / 32 KB per key, 4 MB in all (over a bound: in order at once, "
                      "as without the key); never for the controller");
        }
    }
    // S46 phase 1, T2 (research/s25/s46-tenderos.md): user 2's own trade 2661 behind its NPCs' 2005s (probe only).
    if (!lc.s2_observer_hold_scene_order.empty() && lc.s2_observer_hold_scene_order != "0") {
        if (!opt.create_session) {
            log::warn("Session2: observer_hold_scene_order needs create_session=1; off");
        } else {
            observer_hold_scene_order_configure(lc.s2_observer_hold_scene_order, acks_on);
        }
    }
    // P8 (pendientes/p8-escenas-y-acks.md §2): user 2's own scenes get their 2810 (observer_stage's 2810 hook).
    const bool scene_copy = lc.s2_observer_scene_copy && opt.create_session;
    if (lc.s2_observer_scene_copy && !opt.create_session) log::warn("Session2: observer_scene_copy needs create_session=1; off");
    if (scene_copy) {
        observer_scene_copy_configure(true);
        log::info("Session2: observer_scene_copy wanted{}",
                  lc.s2_observer_stage_sync ? "" : "; observer_stage's hooks go in in measure mode for its 2810 hook");
    }
    // P8 F2 (pendientes/p8-impl-interp-remota.md): a rider's 2697 to user 2 is followed by its horse's.
    if (lc.s2_horse_follow != "0" && !lc.s2_horse_follow.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: horse_follow needs create_session=1; off");
        } else {
            horse_follow_configure(lc.s2_horse_follow);
        }
    }
    // P8 session 8 pets (pendientes/p8-impl-mascotas.md): a child riding its owner's character follows it.
    if (lc.s2_attach_follow != "0" && !lc.s2_attach_follow.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: attach_follow needs create_session=1; off");
        } else {
            attach_follow_configure(lc.s2_attach_follow);
        }
    }
    // Run8 on 3527 completed the private park-field load but never released
    // the shared-field loading screen: the native owner-only path omits the
    // observer's PlayAllPreLoadSequencerAck. This is a required join stage,
    // checked synchronously before install() can admit the guest tunnel.
    const bool milestone_required = layout_3527() && opt.create_session && opt.share_field;
    const bool milestone_wanted = milestone_required || lc.s2_observer_milestone || lc.s2_observer_milestone_send;
    if (milestone_wanted && !opt.create_session) {
        log::warn("Session2: observer_milestone{} needs create_session=1; off",
                  lc.s2_observer_milestone_send ? "_send" : "");
    }
    const oms::Mode milestone = milestone_wanted && opt.create_session
                                    ? observer_milestone_configure(lc.s2_observer_milestone || milestone_required,
                                                                   lc.s2_observer_milestone_send || milestone_required)
                                    : oms::Mode::Off;
    if (milestone != oms::Mode::Off) {
        log::info("Session2: observer_milestone {} (observer_milestone={}, observer_milestone_send={}){}",
                  oms::mode_name(milestone), lc.s2_observer_milestone || milestone_required ? 1 : 0,
                  lc.s2_observer_milestone_send || milestone_required ? 1 : 0,
                  layout_3527()
                      ? "; synchronous verified loading-completion hook"
                      : lc.s2_observer_stage_sync ? "" : "; observer_stage's hooks go in in measure mode for its entry hook");
        if (layout_3527() && !observer_milestone_install_current()) {
            log::error("Session2: required observer loading-completion hook unavailable; the tunnel stays closed");
            return false;
        }
    }
    // P8 S16 (observer_milestone.h): user 2's reload trips (its 2873 and the 2322 for its character). After the above:
    // it needs observer_milestone's verified emitter and thread.
    if (const omr::ParsedMode rm = omr::parse_mode(lc.s2_observer_milestone_reload); rm.mode != omr::Mode::Off || !rm.known) {
        if (!opt.create_session) {
            log::warn("Session2: observer_milestone_reload needs create_session=1; off");
        } else {
            observer_milestone_reload_configure(lc.s2_observer_milestone_reload);
        }
    }
    // P8 S27 (observer_milestone.h): a reload trip at user 2's 2437 too (the revive). After the above: it needs the
    // reload ledger and observer_milestone's SEND mode.
    if (const omr::ParsedMode am = omr::parse_mode(lc.s2_observer_milestone_reload_any);
        am.mode != omr::Mode::Off || !am.known) {
        if (!opt.create_session) {
            log::warn("Session2: observer_milestone_reload_any needs create_session=1; off");
        } else {
            observer_milestone_reload_any_configure(lc.s2_observer_milestone_reload_any);
        }
    }
    // P8 S16 (travel_probe.h): the host client's burst after user 2's 2873 (TravelAck's host side-effect counter).
    if (opt.create_session && travel_probe_on()) {
        if (loaded_config().sniffer_enabled) {
            g_tap_travel.store(true);
            net::sniffer_set_tap(&sniffer_fanout);
        } else {
            log::warn("Travel probe: [sniffer] enabled=0: TravelAck cannot count the host client's 2661/2981/2322 after "
                      "user 2's 2873");
        }
    }
    // P8 S1, NPC scenes (pendientes/p8-s1-escenas-npc.md §5, "Implementado para la medida"): read-only probes
    // H1-H3, installed and formatted by observer_stage's thread (measure mode when observer_stage_sync=0); the
    // host client's S>C capture feeds its scene ledger from the sniffer's writer thread.
    // S33: configured once, before any hook. Review: only with user2_stages (they observe U-1 / U-e); their hooks and
    // H1b go in from user2_stages' install (or with SceneDiag when s1_scene_diag=1): they force neither SceneDiag nor
    // observer_stage. The host client's capture reaches them through user2_stages' sniffer tap.
    if (opt.create_session) {
        const bool stages_on = !lc.s2_user2_stages.empty() && lc.s2_user2_stages != "0";
        user2_stages_set_npc_probes(lc.s2_npc_activation, lc.s2_npc_family_control, lc.s2_user2_road_control,
                                    stages_on);
        NpcS35Config s35;
        s35.evidence = lc.s2_npc_action_evidence;
        s35.guard = lc.s2_npc_containment_guard;
        s35.degradation = lc.s2_npc_degradation;
        s35.no_progress_ms = lc.s2_npc_no_progress_ms;
        s35.req_grace_ms = lc.s2_npc_req_grace_ms;
        s35.guest_silence_ms = lc.s2_npc_guest_silence_ms;
        s35.postpone_max_ms = lc.s2_npc_postpone_max_ms;
        user2_stages_set_npc_s35(s35);
        user2_stages_set_npc_family(lc.s2_npc_family_types);  // S36 fase B
        user2_stages_set_family_vehicles(lc.s2_npc_family_vehicles);  // S42, apagado por defecto
        enemy_damage_probe_start(lc.s2_enemy_damage_probe, true);
        if (lc.s2_door_trace == "probe" || lc.s2_door_trace == "1") net::sniffer_set_tap(&sniffer_fanout);
        user2_stages_set_road_carts(lc.s2_user2_road_carts);   // S38 fase C (revisión §3.2)
        npc_action_probe_configure(user2_stages_npc_probes_on());
    }
    const bool scene_diag = lc.s2_s1_scene_diag && opt.create_session;
    if (lc.s2_s1_scene_diag && !opt.create_session) log::warn("Session2: s1_scene_diag needs create_session=1; off");
    if (scene_diag) {
        host_scene_diag_configure(true);
        g_tap_scene_diag.store(true);
        net::sniffer_set_tap(&sniffer_fanout);
        log::info("Session2: s1_scene_diag ON (read only){}",
                  lc.s2_observer_stage_sync ? "" : "; observer_stage's hooks go in in measure mode for its thread");
    }
    // P8 S1 option A, sequencers (pendientes/p8-impl-opcion-a.md): the host client's sequencers copied to user 2.
    // No hook of its own: the sniffer's writer thread (ledger), take_frame (trips, order), offer (filter).
    if (lc.s2_observer_seq_copy != "0" && !lc.s2_observer_seq_copy.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: observer_seq_copy needs create_session=1; off");
        } else if (!loaded_config().sniffer_enabled) {
            log::warn("Session2: observer_seq_copy needs [sniffer] enabled=1 (the host client's 2661/2981/2810/2322 "
                      "are its ledger); off");
        } else {
            observer_seq_copy_configure(lc.s2_observer_seq_copy, lc.s2_observer_seq_copy_only,
                                        lc.s2_observer_seq_copy_2322, lc.s2_observer_seq_copy_2100);
            // pendientes/p8-impl-horarios-snapshot.md: the host's schedule stages, on the same path (before the tap).
            observer_sched_copy_configure(lc.s2_observer_sched_copy);
            // P8 session 14 review M2: with observer_load_defer on, the host's 2322 copy waits for the snapshot
            // copies whose actors it withholds during user 2's load (until its 2762 + 2 s).
            observer_seq_copy_set_milestone_hold(child_hold_load_defer() >= 2 && observer_hold_active() ? 2000 : 0);
            if (observer_seq_copy_wanted()) {
                g_tap_seq_copy.store(true);
                net::sniffer_set_tap(&sniffer_fanout);
            }
        }
    }
    // housing_share (housing_share.h): the host client's housing Acks (the tap) replace user 2's own (take_frame).
    if (lc.s2_housing_share != "0" && !lc.s2_housing_share.empty()) {
        if (!opt.create_session || !loaded_config().sniffer_enabled) {
            log::warn("Session2: housing_share needs create_session=1 and [sniffer] enabled=1; off");
        } else {
            housing_share_set_level_states(lc.s2_housing_share_level_states != 0);
            housing_share_configure(lc.s2_housing_share, lc.s2_housing_share_live_ops, lc.s2_housing_share_edits,
                                    lc.s2_housing_share_guest_spawn, lc.s2_housing_share_rekey,
                                    lc.s2_housing_share_drop_gimmicks);
            if (housing_share_wanted()) net::sniffer_set_tap(&sniffer_fanout);
        }
    }
    if (lc.s2_observer_sched_copy && !observer_sched_copy_wanted()) {
        log::warn("Session2: observer_sched_copy=1 needs observer_seq_copy=probe or 1 (with create_session=1 and "
                  "[sniffer] enabled=1); off");
    }
    // P8 strategy B step 2 (pendientes/p8-impl-owner-fanout.md): ToTarget::vf1 counts, by writer, the Acks for
    // the host's session while user 2 observes its field. Before observer_stage_install: its thread verifies
    // vf1's bytes through owner_fanout_read_unpatched. Nothing is sent; failing leaves option D as it was.
    if (lc.s2_owner_fanout != "0" && !lc.s2_owner_fanout.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: owner_fanout needs create_session=1; off");
        } else {
            owner_fanout_configure(lc.s2_owner_fanout);
            if (owner_fanout_wanted() && owner_fanout_install(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)))) {
                if (loaded_config().sniffer_enabled) {
                    g_tap_owner_fanout.store(true);
                    net::sniffer_set_tap(&sniffer_fanout);
                } else {
                    log::warn("OwnerFanout: [sniffer] enabled=0: the summary cannot compare with the host client's "
                              "packets (hook counts only)");
                }
            }
        }
    }
    if (const uint32_t oss = lc.s2_observer_stage_sync;
        oss || (milestone != oms::Mode::Off && !layout_3527()) || scene_copy || scene_diag) {
        if (!opt.create_session) {
            log::warn("Session2: observer_stage_sync needs create_session=1; off");
        } else {
            observer_stage_install(oss ? oss : 1);
        }
    }
    // P8 session 9 (pendientes/p8-impl-s9-movimiento.md): D1 ride_filter's host side (through the sniffer's
    // OnRecvPacket hook), P1 child_reannounce's host side, C1 combat_follow, M1 guest_horse_probe.
    if (ride_filter_configure(lc.s2_ride_filter, /*guest=*/false)) ride_filter_host_attach();
    // P8 S18 (mount_sync.h, pendientes/p8-impl-monturas.md §11): the observer's self-check on the host client's C>S.
    if (mount_sync_active()) {
        if (loaded_config().sniffer_enabled) {
            g_tap_mount_sync.store(true);
            net::sniffer_set_tap(&sniffer_fanout);
        } else {
            log::warn("MountSync: [sniffer] enabled=0: the self-check (no StartActionReq 2223 for user 2's rider) cannot "
                      "count");
        }
    }
    if (const auto rp = ran::parse_mode(lc.s2_child_reannounce); !rp.known) {
        log::warn("Session2: child_reannounce='{}' is not 0, probe or 1; it stays off", lc.s2_child_reannounce);
    } else if (rp.mode != ran::Mode::Off) {
        g_rean_mode.store(static_cast<uint8_t>(rp.mode));
        log::info("Session2 child reannounce ON ({}): user 2's \"re-announce K\" for a child of the host its client "
                  "could not create {} (at most {} per key and epoch; waits {}/{}/{} ms){}",
                  ran::mode_name(rp.mode),
                  rp.mode == ran::Mode::On ? "goes into child_settle's table, released natively to session 2"
                                           : "is logged only (probe)",
                  ran::kMaxAttempts, ran::backoff_ms(1), ran::backoff_ms(2), ran::backoff_ms(3),
                  rp.mode == ran::Mode::On && !child_settle_active()
                      ? " | WARNING: child_settle_ms=0 or its hooks are not in: nothing can be re-announced"
                      : "");
    }
    if (lc.s2_combat_follow != "0" && !lc.s2_combat_follow.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: combat_follow needs create_session=1; off");
        } else {
            combat_follow_start(lc.s2_combat_follow, lc.s2_combat_follow_v2);  // P8 session 25: the combat stream
        }
    } else if (lc.s2_combat_follow_v2 != "0" && !lc.s2_combat_follow_v2.empty()) {
        log::warn("Session2: combat_follow_v2 needs combat_follow; off");
    }
    // The world around user 2 (noche/mundo-invitado.md, "Implementado"): the collector's second anchor. No hook of its
    // own: the OnRecvPacket hook (ServerRunThread) and take_frame call it; its lines from tunnel_tick.
    if (lc.s2_user2_world_anchor != "0" && !lc.s2_user2_world_anchor.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: user2_world_anchor needs create_session=1; off");
        } else {
            world_anchor_configure(lc.s2_user2_world_anchor);
        }
    }
    if (lc.s2_guest_horse_probe != "0" && !lc.s2_guest_horse_probe.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: guest_horse_probe needs create_session=1; off");
        } else {
            horse_follow_configure_guest_probe(lc.s2_guest_horse_probe);
        }
    }
    // P8 mount ride (pendientes/p8-impl-monturas-cabalgata.md): user 2's horse samples derived from its rider, for the
    // host's client only (the sniffer's OnRecvPacket hook, in by now).
    if (lc.s2_horse_follow_reverse != "0" && !lc.s2_horse_follow_reverse.empty()) {
        if (!opt.create_session) {
            log::warn("Session2: horse_follow_reverse needs create_session=1; off");
        } else {
            horse_follow_reverse_configure(lc.s2_horse_follow_reverse);
        }
    }
    // P8 session 13, the shopkeepers' server side (pendientes/p8-impl-tenderos-c1.md): read-only probes.
    // S2 (pendientes/p8-impl-tenderos-s2.md): funcnpc_twin, probe only in this build.
    const bool twin_wanted = !lc.s2_funcnpc_twin.empty() && lc.s2_funcnpc_twin != "0";
    if (lc.s2_shop_probe || twin_wanted) {
        if (!opt.create_session) {
            log::warn("Session2: shop_probe / funcnpc_twin need create_session=1; off");
        } else {
            shop_probe_start(lc.s2_shop_probe, lc.s2_funcnpc_twin);
        }
    }
    // P8 option U, U-0 (research/s25/mundo-escenarios-propios.md): read-only probe of the stage managers.
    const auto key_on = [](const std::string& v) { return !v.empty() && v != "0"; };
    if (key_on(lc.s2_user2_stages) || key_on(lc.s2_user2_timer_route)) {
        if (!opt.create_session) {
            log::warn("Session2: user2_stages / user2_timer_route need create_session=1; off");
        } else {
            user2_stages_set_fast_rearm(lc.s2_user2_fast_rearm);  // S37 phase D, before the start
            user2_stages_start(lc.s2_user2_stages, lc.s2_user2_timer_route, lc.s2_user2_stages_elements,
                               lc.s2_user2_npc_control, lc.s2_user2_drain_at_host_prepare);
            user2_stages_set_trade_list(lc.s2_user2_shop_trade_list);  // S46 phase 3, T1 (s46-tenderos.md §9)
            g_tap_user2_stages.store(true);
            net::sniffer_set_tap(&sniffer_fanout);
        }
    }
    if (key_on(lc.s2_user2_shop_trade_list) && !(key_on(lc.s2_user2_stages) && opt.create_session)) {
        log::warn("Session2: user2_shop_trade_list={} needs user2_stages (U-f is its element filter): off",
                  lc.s2_user2_shop_trade_list);
    }
    // S43 (scene_level_share.h): SceneLevels ready for user 2 too, and not deleted while the other user has them.
    if (key_on(lc.s2_scene_level_share)) {
        if (!opt.create_session) {
            log::warn("Session2: scene_level_share needs create_session=1; off");
        } else {
            scene_level_share_start(lc.s2_scene_level_share, lc.s2_guest);
        }
    }
    // S46 phases 1 and 2 (research/s25/s46-tenderos.md): the probes of the trade chain, U2-c and R0 (the host's server).
    if (lc.s2_shop_trade_probe || key_on(lc.s2_user2_shop_trade_route) || key_on(lc.s2_shop_interaction_own_delete)) {
        if (!opt.create_session) {
            log::warn("Session2: shop_trade_probe / user2_shop_trade_route / shop_interaction_own_delete need "
                      "create_session=1 on the host; off");
        } else {
            shop_trade_probe_start(lc.s2_shop_trade_probe, lc.s2_user2_shop_trade_route,
                                   lc.s2_shop_interaction_own_delete);
        }
    }
    // P8 option U, U2 (research/s25/tiendas-u2.md): the Reqs of user 2's own shop scenes to its own manager.
    if (key_on(lc.s2_user2_shop_route)) {
        if (!opt.create_session) {
            log::warn("Session2: user2_shop_route needs create_session=1; off");
        } else {
            user2_shops_start(lc.s2_user2_shop_route, lc.s2_shop_probe);
        }
    }
    if (opt.probe) CloseHandle(CreateThread(nullptr, 0, probe_thread, nullptr, 0, nullptr));
    // C4: before the tunnel opens (the network thread reads it after g_tunnel_on).
    if (opt.reconnect && !so.accept_tunnel) log::warn("Session2: reconnect needs accept_tunnel=1; off");
    if (opt.reconnect && so.accept_tunnel && !server_logout_supported()) {
        log::warn("Session2: reconnect needs LogoutSessionToServerReq 2001 (not found); off");
    }
    g_reconnect = opt.reconnect && so.accept_tunnel && server_logout_supported();
    if (g_reconnect) {
        log::info("Session2 C4: reconnect on: after user 2's logout and a clean barrier (budget {} s), a new guest "
                  "connection logs in again with a new epoch and a session 2 of its own (at most {} in this run)",
                  g_lc.config().budget_ms / 1000, kMaxGuestEpochs);
    }
    // P8 re-entry (rejoin_logic.h): needs reconnect (the barrier and READY are C4's).
    if (const auto rp = rjl::parse_mode(loaded_config().s2_rejoin); !rp.known) {
        log::warn("Session2: rejoin='{}' is not 0, probe or 1; it stays off", loaded_config().s2_rejoin);
    } else if (rp.mode != rjl::Mode::Off && !g_reconnect) {
        log::warn("Session2: rejoin='{}' needs reconnect=1 (and accept_tunnel=1); it stays off",
                  loaded_config().s2_rejoin);
    } else if (rp.mode != rjl::Mode::Off) {
        g_rejoin = rp.mode;
        log::info("Session2 rejoin ON ({}): in C4's READY, the guest's REJOIN (control state 13) {}; the C4 state goes "
                  "to the guest once a second as control state 14 (only to a guest that announced caps 0x{:02X})",
                  rjl::mode_name(rp.mode),
                  rp.mode == rjl::Mode::On ? "begins the next epoch on the same connection (no new transport Hello)"
                                           : "is answered 'would begin' (probe: nothing started)",
                  troc::kCapsRejoin);
    }
    g_tunnel_on.store(so.accept_tunnel);
    g_installed.store(true);
    return true;
}

bool installed() { return g_installed.load(); }

void sniffer_tap_rope_probe() {
    g_tap_rope_probe.store(true);
    net::sniffer_set_tap(&sniffer_fanout);
}

void sniffer_tap_docked_gimmicks() {
    g_tap_docked_gimmicks.store(true);
    net::sniffer_set_tap(&sniffer_fanout);
}

void sniffer_tap_quest_policy() {
    g_tap_quest_policy.store(true);
    net::sniffer_set_tap(&sniffer_fanout);
}

bool tunnel_wanted() { return g_installed.load() && g_tunnel_on.load(); }

namespace {

// P8 session 9, P1 (reannounce_logic.h): the guest's "re-announce K" control packets. Network thread only.
ran::Attempts<32> g_rean_host;
uint32_t g_rean_epoch = 0;
std::atomic<uint64_t> c_rean_in{0}, c_rean_bad{0}, c_rean_other{0}, c_rean_accepted{0}, c_rean_probe{0};
std::atomic<uint64_t> c_rean_verdict[ran::kVerdicts] = {};
std::atomic<uint64_t> c_rean_result[8] = {};
uint64_t g_rean_lines = 0;
constexpr uint64_t kReanLines = 32;

// A control packet from the guest (opcode 1): never offered to the server.
// The exact frame only (ran::is_reannounce_frame: opcode 1, slot -1, 10-byte payload, state 3).
void on_guest_control(const std::vector<uint8_t>& packet) {
    c_rean_in.fetch_add(1, std::memory_order_relaxed);
    const auto mode = static_cast<ran::Mode>(g_rean_mode.load(std::memory_order_relaxed));
    const auto r = ran::decode(std::span<const uint8_t>(packet).subspan(troc::kHeaderSize));
    if (!r) {
        c_rean_bad.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (const uint32_t e = server_epoch(); e != g_rean_epoch) {
        g_rean_epoch = e;
        g_rean_host.reset();
    }
    std::string what;
    if (mode == ran::Mode::Off) {
        what = "child_reannounce=0 here: ignored";
    } else {
        uint8_t attempt = 0;
        const uint64_t now = GetTickCount64();
        const ran::Verdict verdict = g_rean_host.accept_peek(r->key, r->attempt, now, attempt);
        c_rean_verdict[static_cast<size_t>(verdict)].fetch_add(1, std::memory_order_relaxed);
        if (verdict != ran::Verdict::Ask) {
            what = ran::verdict_name(verdict);
        } else {
            // The key goes into the attempt table only once child_settle confirmed it is a child of the host
            // (review 2026-10-10): anything else the guest names never uses up the per-key or per-epoch caps.
            const bool probe = mode == ran::Mode::Probe;
            const Reannounce res = child_settle_reannounce(r->key, ran::backoff_ms(attempt), probe);
            c_rean_result[static_cast<size_t>(res) & 7].fetch_add(1, std::memory_order_relaxed);
            if (res == Reannounce::Queued) {
                g_rean_host.commit(r->key, now);
                (probe ? c_rean_probe : c_rean_accepted).fetch_add(1, std::memory_order_relaxed);
            }
            what = probe ? std::format("attempt {}: {} (probe: nothing queued; it would wait {} ms)", attempt,
                                       res == Reannounce::Queued ? "a child of the host" : reannounce_name(res),
                                       ran::backoff_ms(attempt))
                         : std::format("attempt {}: {} (native NotifyAppear to session 2 not before {} ms)", attempt,
                                       reannounce_name(res), ran::backoff_ms(attempt));
        }
    }
    if (g_rean_lines < kReanLines) {
        ++g_rean_lines;
        log::info("Session2 child reannounce [{}]: user 2's client could not create 0x{:08X} (owner user 0x{:08X}, its "
                  "attempt {}) -> {}",
                  ran::mode_name(mode), r->key, r->owner, r->attempt, what);
    }
}

std::string reannounce_host_describe() {
    const auto mode = static_cast<ran::Mode>(g_rean_mode.load());
    if (mode == ran::Mode::Off && !c_rean_in.load()) return {};
    std::string res;
    for (size_t i = 0; i <= static_cast<size_t>(Reannounce::Full); ++i) {
        res += std::format("{}{} {}", i ? ", " : "", reannounce_name(static_cast<Reannounce>(i)), c_rean_result[i].load());
    }
    return std::format("Session2 child reannounce [{}]: asked by user 2 {} (malformed {}, other opcode-1 frames passed on {}) | "
                       "too soon {}, exhausted {}, epoch cap {} | children of the host: probe {}, queued {} [{}]",
                       ran::mode_name(mode), c_rean_in.load(), c_rean_bad.load(), c_rean_other.load(),
                       c_rean_verdict[static_cast<size_t>(ran::Verdict::TooSoon)].load(),
                       c_rean_verdict[static_cast<size_t>(ran::Verdict::Exhausted)].load(),
                       c_rean_verdict[static_cast<size_t>(ran::Verdict::EpochCap)].load(), c_rean_probe.load(),
                       c_rean_accepted.load(), res);
}

}  // namespace

void tunnel_on_packet(std::vector<uint8_t>&& packet, uint32_t link_epoch, uint32_t now_ms) {
    // P8 S25 phase B (guest_save_tunnel.h): the guest's own-save control frames (states 6, 7, 8, 11), never a server
    // Req, and before the C4 admission below: an upload never binds a conversation (a reconnection before the
    // client's first Req stays as free as before).
    if (guest_save_tunnel_on_frame(packet, now_ms)) return;
    // P8 re-entry (rejoin_logic.h): the guest's REJOIN, never a server Req, before the C4 admission below (in READY no
    // packet is admitted; this one may start the next epoch on this very connection).
    if (rjl::is_rejoin_frame(packet)) {
        g_now_ms = now_ms;
        on_guest_rejoin(packet, link_epoch);
        return;
    }
    if (g_reconnect) {
        g_now_ms = now_ms;
        // A new connection after the barrier, seen here before tunnel_tick did.
        if (g_lc.may_start(link_epoch)) start_epoch(link_epoch);
        const bool control = g_rejoin != rjl::Mode::Off && packet.size() >= 2 &&
                             (packet[0] | (packet[1] << 8)) == troc::kControlOpcode;
        if (control) {
            // P8 re-entry (review of c4367f8, 4), with rejoin on (rejoin=0: as before): a control frame (mount events,
            // re-announce requests) never binds a conversation: it is taken only inside one already bound to this
            // connection (a stale one of the guest's previous conversation never enters the next epoch).
            if (!g_lc.conversation() || g_lc.bound_link() != std::optional<uint32_t>(link_epoch)) {
                ++g_not_admitted;
                return;
            }
        } else if (!g_lc.admit(link_epoch)) {
            // Only the current epoch's connection: never a packet of an older one.
            ++g_not_admitted;
            return;
        }
    }
    if (g_tunnel_dead) return;

    // P8 session 9, P1: the tunnel's own control packet from the guest (child_reannounce), never a server Req.
    // Only the exact frame (opcode 1, slot -1, its 10-byte payload): no Troc message uses opcode 1 (the game's
    // lowest is 1002); any other opcode-1 frame goes on and is dropped by offer() as no server Req.
    if (ran::is_reannounce_frame(packet)) {
        on_guest_control(packet);
        return;
    }
    // P8 S29 (tree_bend.h): user 2's tree bend (state 15), never a server Req; only here, inside the conversation.
    if (tree_bend_on_frame(packet, link_epoch)) return;
    // Which character user 2 plays (focus_follow.h, state 16), never a server Req.
    if (focus_follow_on_frame(packet, link_epoch)) return;
    // P8 mounts (mount_sync.h): user 2's MountBegin / MountCommit / MountDetach, never a server Req. A Commit may
    // end a hold: the held Req go on at the next drain.
    if (mount_sync_on_frame(packet, link_epoch)) return;
    if (packet.size() >= 2 && (packet[0] | (packet[1] << 8)) == troc::kControlOpcode) {
        c_rean_other.fetch_add(1, std::memory_order_relaxed);
    }
    if (!server_accepts_guest() || !g_early.empty() || mount_sync_host_holding(g_early.size())) {
        if (g_early.empty() && server_accepts_guest()) mount_sync_note_hold(true, 0);
        hold_req(std::move(packet));  // after what is already held, in order
        return;
    }
    if (!offer(packet)) hold_req(std::move(packet));
}

void tunnel_tick(troc::TrocLink& link, uint32_t now_ms) {
    enemy_damage_probe_poll(); // S42, único consumidor; con 0 retorna sin trabajo.
    door_trace_flush();
    g_prof.begin(now_us());
    child_hold_network_tick();
    prof(kPartChildHold);
    observer_hold_acks_tick();  // P8 S3: expiry, user 2 gone, its lines (nothing when off)
    observer_hold_scene_order_tick();  // S46 T2 probe: its lines (nothing when off)
    attach_follow_tick();       // P8 session 8 pets: its lines (nothing when off)
    ride_filter_tick();         // P8 session 9 D1: its lines and the minute's summary (nothing when off)
    {
        // P8 session 9 P1: the host side's counts once a minute (nothing when off and never asked).
        static uint32_t last_rean_ms = 0;
        if (now_ms - last_rean_ms >= 60000) {
            last_rean_ms = now_ms;
            if (const std::string s = reannounce_host_describe(); !s.empty()) log::info("{}", s);
        }
    }
    observer_seq_copy_tick();   // P8 S1 option A: the gate's timeout, refused copies again, its lines (nothing when off)
    owner_fanout_tick();        // P8 B step 2: trip lines, the 60 s summary (nothing when off)
    world_anchor_tick();        // user2_world_anchor: the 60 s summary (nothing when off)
    prof(kPartHoldAcks);
    // p8-heap-inyeccion.md: what the NetworkThread caught or measured, then a halt if there was an exception.
    server_inject_tick(GetTickCount64());
    halt_tick();
    // P8 S25 phase B: the own-save answers, status and results to the guest (paced; nothing when off).
    guest_save_tunnel_tick(link, now_ms);
    prof(kPartInjectWatch);
    if (g_reconnect) {
        tunnel_tick_reconnect(link, now_ms);
        end_tick(link);
        return;
    }
    if (!g_tunnel_dead && link.broken()) kill_tunnel("the link broke (reconnection or overflow)");
    if (!g_tunnel_dead && server_outgoing_lost()) kill_tunnel("a packet of the server was lost");
    identity_logout_tick();
    server_logout_tick();  // C4: a goodbye asked for during the login goes once user 2 exists
    // C4: a guest that is simply gone (no goodbye, the link never breaks: it
    // just stays unconnected) is logged out too, once it has a user here.
    if (link.connected()) {
        g_link_down_since_ms = 0;
    } else if (!g_link_down_since_ms) {
        g_link_down_since_ms = now_ms ? now_ms : 1;
    } else if (!g_tunnel_dead && now_ms - g_link_down_since_ms >= kLinkLostMs && server_user2_present()) {
        kill_tunnel(std::format("the guest has been gone for {} s", kLinkLostMs / 1000));
    }
    prof(kPartLogout);
    if (!g_tunnel_dead) {
        if (server_session_ready()) drain_held([] { return !g_tunnel_dead; });
        prof(kPartHeldReq);
        push_outgoing(link);
    } else {
        server_take_outgoing();  // keep the queue from filling
        discard_mount_events();
    }
    prof(kPartOutgoing);
    // Once a second, tell a P8 guest whether it may start a conversation
    // (guest.cpp waits for "ready" before sending its client's login here).
    if (link.connected() && now_ms - g_last_control_ms >= 1000) {
        g_last_control_ms = now_ms;
        const uint8_t state = g_tunnel_dead ? troc::kControlHostDead
                              : server_session_ready() ? troc::kControlHostReady
                                                       : 0;
        if (state) link.push(troc::make(troc::kControlOpcode, -1, std::span<const uint8_t>(&state, 1)));
        push_host_character(link);
    }
    prof(kPartControl);
    link.tick(now_ms);
    prof(kPartLinkFlush);
    end_tick(link);
}

std::string describe() {
    if (!installed()) {
        if (save_hooks_tracing()) return "Session2: off, save guard TRACE (" + save_hooks_trace_describe() + ")";
        if (save_hooks_redirecting()) {
            return "Session2: off, save guard REDIRECT (" + save_hooks_redirect_describe() + ")";
        }
        return save_hooks_active() ? std::format("Session2: off, save guard ON (refused {})", save_hooks_blocked())
                                   : "Session2: off";
    }
    const char* const mode = save_hooks_tracing() ? "TRACE" : save_hooks_active() ? "on" : "off";
    const std::string guard = save_hooks_redirecting()
                                  ? "REDIRECT (" + save_hooks_redirect_describe() + ")"
                                  : std::format("{} (refused {}, reads {})", mode, save_hooks_blocked(),
                                                save_hooks_reads());
    std::string s = std::format("Session2: save guard {} | report guard {} (not sent {}) | {}", guard,
                                report_guard_active() ? "on" : "off", report_guard_dropped(), server_describe());
    if (save_hooks_tracing()) s += " | save trace: " + save_hooks_trace_describe();
    if (field_share_active()) {
        s += " | " + field_share_describe();
        if (layout_3527()) {
            s += " | " + interaction_condition_describe();
            s += " | " + remote_visible_describe();
        }
    }
    if (clock_gate_active()) s += " | " + clock_gate_describe();
    if (const std::string m = clock_push_describe(); !m.empty()) s += " | " + m;
    if (g_block_weather || g_weather_blocked) s += std::format(" | guest weather Req 2560 dropped {}", g_weather_blocked);
    if (child_hold_active()) s += " | " + child_hold_describe();
    if (observer_hold_acks_active()) s += " | " + observer_hold_acks_describe();
    if (horse_follow_active() || horse_follow_guest_probe_active() || horse_follow_reverse_active()) s += " | " + horse_follow_describe();
    if (attach_follow_active()) s += " | " + attach_follow_describe();
    if (const std::string m = mount_sync_describe(); !m.empty()) s += " | " + m;
    if (observer_stage_active()) s += " | " + observer_stage_describe();
    if (const std::string m = observer_milestone_describe(); !m.empty()) s += " | " + m;
    if (const std::string m = observer_scene_copy_describe(); !m.empty()) s += " | " + m;
    if (const std::string m = host_scene_diag_describe(); !m.empty()) s += " | " + m;
    if (const std::string m = observer_seq_copy_describe(); !m.empty()) s += " | " + m;
    if (housing_share_wanted()) s += " | " + housing_share_describe();
    if (const std::string m = owner_fanout_describe(); !m.empty()) s += " | " + m;
    if (const std::string m = world_anchor_describe(); !m.empty()) s += " | " + m;
    s += " | " + fast_travel_host_describe();
    if (identity_fix_wanted()) s += " | " + identity_fix_describe();
    if (guest_save_mode() != gsv::Mode::Off) s += " | " + guest_save_describe();
    if (const std::string m = guest_save_tunnel_describe(); !m.empty()) s += " | " + m;
    if (g_own_save_blocked || g_own_save_allowed) {
        s += std::format(" | own-save Req: 3037/2910 handed {}, 2711/2178 dropped {}", g_own_save_allowed,
                         g_own_save_blocked);
    }
    if (g_blocked_from_guest) s += std::format(" | guest save/cheat Req dropped {}", g_blocked_from_guest);
    if (g_unknown_from_guest) s += std::format(" | guest packets that are no server Req dropped {}", g_unknown_from_guest);
    if (g_after_goodbye) s += std::format(" | guest packets after its logout dropped {}", g_after_goodbye);
    if (g_held_offers || g_dropped_offers || !g_early.empty()) {
        s += std::format(" | guest Req held now {} (holds {}), dropped by policy {}", g_early.size(), g_held_offers,
                         g_dropped_offers);
    }
    if (g_tunnel_dead) s += " | TUNNEL STOPPED: " + g_dead_reason;
    // P8 review I2: a read of the mod touched a guard page (re-armed by the filter); I1: exceptions inside
    // the game's code passed on (only visible here if something up the stack handled them).
    if (const game::GuardStats g = game::guard_stats(); g.rearmed || g.failed) {
        s += std::format(" | GUARD PAGES touched by the mod's reads: re-armed {}, could not re-arm {}", g.rearmed,
                         g.failed);
    }
    if (const uint32_t f = game::game_faults_passed()) s += std::format(" | GAME FAULTS passed on {}", f);
    // p8-tunel-rendimiento.md: the host tunnel's ticks in this report's window.
    s += " | host tunnel " + g_prof.window_text(kPartNames, kSlowTickUs);
    g_prof.take_window();
    if (g_reconnect) {
        s += std::format(" | C4 guest epoch {} {}", g_lc.epoch(), guest_state_name(g_lc.state()));
        if (g_rejoin != rjl::Mode::Off || c_rejoin_in) {
            s += std::format(" | rejoin [{}]: asked {} (bad {}), started in-band {} (this epoch for conversation {}), "
                             "answered again {}, probe {}, not now {}, off {}, unused given up {} | EPOCH out {}",
                             rjl::mode_name(g_rejoin), c_rejoin_in, c_rejoin_bad, c_rejoin_started,
                             g_rejoin_started_for, c_rejoin_repeat, c_rejoin_probe, c_rejoin_ignored, c_rejoin_off,
                             c_rejoin_unused,
                             c_epoch_out);
        }
        if (const auto b = g_lc.bound_link()) s += std::format(" (connection {})", *b);
        if (g_lc.state() == GuestState::Quarantined) s += " | QUARANTINED: " + g_lc.quarantine_reason();
        if (!g_last_barrier.empty()) s += " | last barrier: " + g_last_barrier;
        if (g_not_admitted) s += std::format(" | guest packets of another connection dropped {}", g_not_admitted);
        if (g_out_discarded) s += std::format(" | server packets for a departed guest dropped {}", g_out_discarded);
        s += " | " + server_epoch_describe();
    }
    return s;
}

}  // namespace cdmp::session2
