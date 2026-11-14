#pragma once
// Settings read from cdmp.ini next to the mod. Missing keys use the defaults
// below, and a default file is written if none exists.

#include <cstdint>
#include <string>

#include "common/save_guard.h"

namespace cdmp {

struct Config {
    std::string player_name = "Player";
    uint32_t startup_delay_ms = 0;
    // [general] background_full_speed (also read under [session2]; [general] wins): 1 = two copies on one PC
    // (CDMP_ROLE set) only: while another window has the foreground, this process's GPU scheduling class goes up
    // so the copy in the background keeps its share of the GPU (bg_speed_logic.h). Without a role: a WRN, ignored.
    bool background_full_speed = false;

    std::string peer_host = "127.0.0.1";
    uint16_t peer_port = 37015;
    uint32_t send_rate_hz = 20;
    bool net_enabled = true;
    // [net] transport=udp|steam, role=guest|host. A guest connects to the host
    // (or to cdmp_peer); a host waits for one player.
    bool net_transport_steam = false;
    bool net_role_host = false;
    bool host_loopback_only = false;  // UDP host for a single-PC test: listen on 127.0.0.1 only
    // [steam] peer_steamid: guest = the host's SteamID64 (0 = the only friend
    // playing); host = accept only this friend (0 = any friend playing).
    uint64_t steam_peer_id = 0;
    int steam_channel = 67;
    // [steam] send_rate_min_kb / send_rate_max_kb / send_buffer_kb: Steam
    // networking's send limits (KB/s, KB). send_rate_min_kb=0 leaves Steam's
    // defaults (256 KB/s, 512 KB). See SteamSendLimits.
    uint32_t steam_send_rate_min_kb = 1024;
    uint32_t steam_send_rate_max_kb = 8192;
    uint32_t steam_send_buffer_kb = 4096;
    // [steam] recv_buffer_kb / recv_buffer_messages: what Steam keeps received
    // and not yet read before it drops packets (0 = Steam's 1 MB / 1000).
    uint32_t steam_recv_buffer_kb = 16384;
    uint32_t steam_recv_buffer_messages = 16384;

    bool overlay_enabled = true;  // kill switch for the DX12 hook
    bool overlay_self_marker = true;  // dev aid while validating the projection

    bool sniffer_enabled = true;  // hook internal client/server packets (needed by co-op)
    bool sniffer_record = true;   // also write them to cdmp_packets_*.log/.bin (dev; 50-100 MB/session)

    // Experiment 4c: F9 spawns a clone of the player, F10 removes it. Writes
    // packets into the game, so it is off unless explicitly enabled.
    bool dev_clone_hotkeys = false;
    uint32_t dev_mirror_delay_ms = 300;  // simulated latency of the mirrored clone
    float dev_mirror_offset_m = 2.5f;    // sideways offset; 0 = walk the player's exact path
    // Combat injection tests (combate-coop.md §6, T2/T3): WRITE to the game's
    // server. Only with a save backup, and never save afterwards.
    bool dev_combat_tests = false;
    // Ctrl+F9 / Ctrl+Shift+F9: next / previous minimap icon for the other player.
    bool dev_minimap_cycle = false;
    // Ctrl+F5: an enemy targets the other player's copy (aggro_test.h).
    bool dev_aggro_test = false;
    // Ctrl+F6: send the nearest enemy to the other player (enemy_relay.h).
    bool dev_enemy_relay = false;
    // Ctrl+F10 / Ctrl+F11 experiments of piece 4 (piece4_test.h); they write to the game.
    bool dev_piece4_test = false;
    // Every 2 s, log who sits in the attacker lists of our player and of the
    // other player's copy (attack_probe.h). Read only.
    bool dev_attack_probe = false;

    // Co-op over the network ([coop]): the other player (or, through
    // cdmp_peer --mode relay with nobody else connected, yourself) appears as
    // a remote character. Writes packets into the game; off by default.
    bool coop_enabled = false;
    uint32_t coop_delay_ms = 300;  // playout delay; longer = smoother climb-ups
    float coop_offset_m = 0.0f;    // sideways offset of the remote character
    // Experimental, off by default: the copy's horse is not created by the
    // client (owned load) or crashes the game (ownerless load); live tests 1-2.
    bool coop_horse = false;       // the other player's horse + mount/dismount fixes
    // Works since the copy got its own character number (live test 3).
    bool coop_equip = true;        // relay equipment changes
    // Mirrored damage: each world keeps its enemies; hits by the other player
    // are applied to our enemy of the same type nearest to theirs.
    bool coop_damage = true;
    // The other player as a pin on the world map and minimap.
    bool coop_map_pin = true;
    uint8_t coop_map_pin_shape = 4;    // 0-13 (the game's default pin: 4)
    uint8_t coop_map_pin_colour = 14;  // 0-14 (the game's default pin: 14)
    // The other player's icon on the minimap: offset in the game's icon
    // table (0x124 = an outlined arrow, the one chosen in the live test;
    // 0x126 = our own arrow; no other colours exist), 0 = none,
    // -1 = diagnostic (log what the game decides).
    int coop_minimap_icon = 0x124;
    // Our enemies may attack the other player's copy (aggro_test.h). Off
    // until the hits reach the other player and they see our enemies.
    bool coop_enemies_target_copy = false;
    // The other player's blows on the copies of our enemies hurt them
    // (guest_hits.h). Off until tested with two players.
    bool coop_guest_hits = false;
    // ...and stagger them (restriction + hit buff, pieza4-tambaleo.md):
    // experimental until a live test shows the stagger.
    bool coop_guest_hit_stagger = false;
    // Our player reacts (stagger, knock-down) to the other player's enemies'
    // blows on our copy over there: experimental until tested.
    bool coop_player_hit_react = false;
    // ...and can die from them (a normal death): experimental until tested.
    bool coop_player_hit_lethal = false;
    // How many of our enemies at a time may attack the other player's copy
    // (copia-objetivo-sin-ataques.md); 0 = the game decides (they mostly wait).
    int coop_copy_attack_slots = 0;

    // Option D ([session2], docs/OPCION-D-EMULADOR.md): the host's own game
    // server serves the guest as a second user. Everything is off by default
    // and each stage has its own switch; none works without enabled=1, and
    // none runs together with [coop] (the copies model).
    bool s2_enabled = false;
    // E0: log the server's session, user and sector fields once in game (read only).
    bool s2_probe = true;
    // P6: refuse writes under %LOCALAPPDATA%\Pearl Abyss\CD\save while enabled
    // (save_guard=0|1|trace|redirect; trace = refuse nothing and log every operation
    // under the folder, session 24, lab only; redirect = every operation under the
    // folder goes to a sandbox copy of it made at start, session 24).
    saveguard::Mode s2_save_guard = saveguard::Mode::Block;
    // P6, second layer: skip the server's save Req/timers instead of only logging them.
    bool s2_block_save_trocs = false;
    // E0b: log how many sessions each recipient finder collects (read only).
    bool s2_finder_log = false;
    // E1: build session 2 and watch its sends (no user yet).
    bool s2_create_session = false;
    // E2+: feed the tunnel's packets to the server as session 2.
    bool s2_accept_tunnel = false;
    // P5: the "near, except one" finders collect the sector's observers again.
    bool s2_relay_fix = false;
    // Account number written into the guest's LoginUserToFieldServerReq (0 = the host's).
    uint64_t s2_account = 1;
    // E4 on one PC: user 2 repeats the host player's movement mirror_delay_ms later.
    bool s2_mirror_host = false;
    uint32_t s2_mirror_delay_ms = 1000;
    // E3b: user 2 enters the host's ServerField (opcion-d-campo-compartido.md).
    bool s2_share_field = false;
    // P-RELOJ: user 2's travels and loads never publish the world clock.
    bool s2_clock_gate = true;
    // C2-0: read-only log of user 2's characterNo during its login (pendientes/identidad.md §6).
    bool s2_identity_probe = false;
    // C2 (session2/identity_fix.h): user 2's own characterNo. Default 1 with create_session.
    bool s2_identity_fix = false;
    // Companions step A: read-only log of user 2's children on the host's client (pendientes/companeros.md §A).
    bool s2_companion_probe = false;
    // D-53: user 2's children are published to the other users only after their first action
    // (pendientes/companeros-publicacion.md §3). Default: on when share_field=1.
    bool s2_child_hold = false;
    // C4 (reconnect): user 2 may log out and log in again in the same run
    // (guest_lifecycle.h). 0 = as before: the tunnel stays dead after a logout.
    bool s2_reconnect = false;
    // P8 re-entry, HOST AND GUEST (session2/rejoin_logic.h, docs/research/s25/reentrada.md): "0" (default) | "probe" |
    // "1". The guest goes back to the title and plays on the host again in the same game run (a new conversation in
    // the same tunnel connection, control states 13/14, caps 0x08). The host needs reconnect=1.
    std::string s2_rejoin = "0";
    // P8 on the GUEST's PC: its client plays on the host's server through the
    // tunnel (opcion-d-p8.md). Excludes every host-side stage above.
    bool s2_guest = false;
    // guest_mode=observe (default: hooks in, everything local, only counted; G0)
    // or remote (the client's connection goes to the host when it is ready).
    bool s2_guest_remote = false;
    // P8-T (opcion-d-pruebas.md): with guest=1 guest_mode=observe, run the
    // title's slot refresh once right after install, before the local login,
    // to check it on one PC. Diagnostic; off by default.
    bool s2_guest_slot_refresh_test = false;
    // P8 guest, the host's field actors (pendientes/p8-actores-anfitrion.md §4.4):
    // read-only probe of the failed logins, the restore and the loading wait list.
    bool s2_guest_actor_diag = false;
    // P8 guest (§4.1(i)): the co-op's action-layer guard for every actor not
    // controlled locally (actor +0x90 != the local user key).
    bool s2_guest_layer_guard = false;
    // S3 (pendientes/p8-impl-s3.md), HOST: NPCs controlled by a user with restore 0 reach only their
    // controller until their first action (child_hold.h, observer_hold). Needs create_session.
    bool s2_observer_hold = false;
    // P8 session 14 (pendientes/p8-impl-spawn-action.md), HOST, needs observer_hold=1: "0" (default) | "probe" |
    // "1". An NPC the host controls announced to user 2 while user 2 loads (login or field change, until the
    // server wrote its 2762) is withheld from user 2 even with restore 1 and announced natively after its 2762
    // (session 13: the field snapshot's NPCs, created on the guest before its owner was valid, are the half of
    // the town that looked paralyzed). probe: counted and logged, nothing withheld.
    std::string s2_observer_load_defer = "0";
    // P8 sessions 13/14 (pendientes/p8-s14-viajeros.md §6), HOST, needs observer_hold=1: "0" (default) | "probe" |
    // "1". An NPC's carried pieces (no CC: a basket, a bull's load, a wagon's cargo) whose parent observer_hold
    // withholds from user 2 are withheld too and announced right after their parent (S14: 66 pieces reached the
    // guest 0.12-0.5 s BEFORE their parent: invisible travelers). probe: counted and logged, nothing withheld.
    std::string s2_observer_hold_pieces = "0";
    // P8 S15/S16 (pendientes/p8-s14-viajeros.md §7), HOST, needs observer_hold=1: "0" | "probe" | "1"; empty
    // (the key absent) = the old observer_hold_pieces' value (its alias). user 2 never gets an actor record before
    // its parent's (the record's +0xAC): every family member (pieces, group members with CC, riders) waits behind
    // a parent withheld from it or not announced to it yet and goes right behind it (S15: 75 orphans).
    std::string s2_observer_hold_family;
    // S3, GUEST (session2/guest_s3.h): read-only per-actor history of the first action (no engine calls).
    bool s2_guest_s3_diag = false;
    // S3, GUEST: a minidump + the last history records on an access violation in the game's code.
    bool s2_guest_crash_dump = false;
    // S3, GUEST, CONTENTION: 0x232D5C0 returns at once for an actor not controlled locally whose current
    // action is null (the known invalid access at 0x232D5FF). Not a fix.
    bool s2_guest_update_guard = false;
    // P8 S2 (pendientes/p8-raiz-invitado.md §4, §7.2; p8-impl-s1s2.md): read-only
    // probes of the loading state's two predicates, the 2322 milestone and, on
    // the host, the field-owner branch, the 2322 emission and the ExtraReward UI.
    bool s2_load_diag = false;
    // P8 S1 (§3, §7.1): read-only probes of the action-chart lookup, the
    // BodyAnimation graphs (CC+0x70/+0x78) and the sequencer binding; host and guest.
    bool s2_s1_diag = false;
    // P8 S1+S2, HOST (session2/observer_stage.h, pendientes/p8-observador-escenas.md): user 2 as an
    // observer of the field's existing stages/sequencers. 0 off; 1 MEASURE ONLY (read-only ledger of the
    // 2661/2810/2981/2322 the server emits and of the snapshot a non-owner entry lacks); 2+ = the send
    // mode, NOT implemented (refused, runs as 1). Needs create_session.
    uint32_t s2_observer_stage_sync = 0;
    // P8 phase 2, GUEST (session2/guest_stage_diag.h, pendientes/p8-observador-escenas.md Fase 2): read-only
    // probe of where the client routes 2661/2981/2810/2322 (which stage manager), 0xA9CA40's result, the NPC
    // side of the sequencer binding (0x9ED290) and the M+0x231 writes. guest=1 only.
    bool s2_guest_stage_diag = false;
    // P8 S2, HOST (session2/observer_milestone.h, pendientes/p8-2322-observador.md): the native
    // PlayAllPreLoadSequencerAck 2322 for user 2 after its observer entry into a field it does not own.
    // observer_milestone=1: follow user 2's trips and DECIDE + log only (stage A, nothing called);
    // observer_milestone_send=1: also EMIT it, once per trip, on the server's logic thread (stage B;
    // implies the first). Both need create_session; they install observer_stage's entry hook
    // (measure mode) when observer_stage_sync=0. observer_stage_sync=2 never sends.
    bool s2_observer_milestone = false;
    bool s2_observer_milestone_send = false;
    // P8 S16, HOST (session2/observer_milestone_reload_logic.h, pendientes/p8-impl-viaje-rapido.md §12): user 2's
    // fast travel that reloads the host's field. "0" (default) | "probe" (decide and log) | "1" (its 2873 dropped, ONE
    // 2322 for its character at its next Req). Needs observer_milestone (+_send for 1) and user2_fast_travel=1.
    std::string s2_observer_milestone_reload = "0";
    // P8 S27, HOST (session2/observer_milestone_reload_logic.h, docs/research/s25/reaparicion.md): a reload trip of
    // user 2 opens at ITS 2437 whenever none is open (a revive 2362, or any path without an F3 2283). "0" (default:
    // only F3 trips, as in S16) | "probe" (those trips only say WOULD DROP / WOULD EMIT) | "1" (dropped + emitted as
    // an F3 trip). Needs observer_milestone_reload=probe|1 and observer_milestone_send=1.
    std::string s2_observer_milestone_reload_any = "0";
    // P8, HOST (session2/observer_scene_copy.h, pendientes/p8-escenas-y-acks.md §2): a scene user 2
    // starts in the host's field (e.g. the ESC "view item" sequencer) lives in the field owner's stage
    // manager, so its closing DeleteSequencerAck 2810 goes to the host's character. 1 = the native
    // 2810 emitter runs once more for user 2's character (its own scenes only). Needs create_session;
    // installs observer_stage's hooks (measure mode) when observer_stage_sync=0.
    bool s2_observer_scene_copy = false;
    // P8 S3, HOST (session2/observer_hold_acks.h, pendientes/p8-escenas-y-acks.md §3): the per-NPC
    // packets (2723, 2404, ...) of an NPC observer_hold withholds from user 2 wait for its 2005 and go
    // right after it, in order (else user 2's client drops them). Needs observer_hold=1 or character_hold=1.
    bool s2_observer_hold_acks = false;
    // P8, HOST (session2/child_hold.h, pendientes/p8-character-hold.md): a user's main character (0xA...)
    // announced with restore 0 to another user waits for its first accepted action (restore 1), at most
    // 15 s (then announced with restore 0, a warning); never for its owner. Needs create_session.
    bool s2_character_hold = false;
    // P8 review of 10-10 I3 (pendientes/p8-revision-noche.md, "Correcciones"), HOST: 1 = the holds
    // (child_hold, observer_hold, character_hold) call NotifyAppear only on a thread the game itself
    // used for NotifyAppear (a release after StartActionReq on another thread waits for the tail of
    // the next native NotifyAppear). 0 (default) = the threads as before that rule (D-53 unchanged).
    bool s2_notify_thread_rule = false;
    // P8 review M10, GUEST: the client's goodbye with a field of the host loaded and no host to answer
    // ends the process (TerminateProcess) instead of the local 2003/2002 that crashed at exe+0x2045A6A
    // (sessions 5 and 6: a crash report to Pearl Abyss). Default 1, a documented exception to the
    // default-off rule; 0 = never ends it: the client keeps waiting for its 2002 (the old hang).
    bool s2_guest_goodbye_end = true;

    // ---- P8 tunnel performance (pendientes/p8-tunel-rendimiento.md) ----
    // HOST and GUEST: 1 = the Troc tunnel's batches to the guest are compressed (common/lz_block.h;
    // same packets, same order). The guest's end says once per connection that it decodes them; the
    // host compresses only then. On the guest, 1 = say it (0 = the host sends raw). Default 0.
    bool s2_tunnel_compress = false;
    // HOST: 1 = the C4 readings (user 2's keys, the barrier) check every page with VirtualQuery first,
    // as before; 0 (default) = SEH-guarded direct reads, the same values without VirtualQuery (which
    // walks the page table of the game's huge heap regions: 0.1-6 ms a call on the network thread).
    // Default 0 on purpose (P8 review I2): a pure cost change - the same values and the same failures,
    // and since the review a guard page touched is re-armed (game::fast_read), so the page ends as
    // safe_read would leave it (untouched).
    bool s2_c4_safe_reads = false;
    // P8, host and guest (session2/ui_pause.h, pendientes/p8-pausa-esc.md): menus do not pause the world
    // while another player is connected. "0" (default, nothing installed) | "probe" (read only: log the UI
    // time scale's transitions and the view behind them) | "1" (1.0 instead of a UI pause while a P8
    // session is live) | "force" (always; one-PC tests). The raw ini value; parsed by ui_pause_logic.h.
    std::string s2_ui_pause_block = "0";
    // Host and guest, build 3527 (session2/seq_marker.h): the own sequencer manager's load marker is put back if it
    // falls with no load running. Without it the host gets no death screen once a guest has joined.
    bool s2_seq_marker_guard = true;
    bool s2_seq_marker_trace = false;
    // Host and guest, builds 3527 and 3549 (session2/pivot_guard.h): a scene's ChangePivot with no target skips, instead
    // of closing the game.
    bool s2_change_pivot_guard = true;
    // Host and guest, build 3663 (session2/ride_null_guard.h): a riding character's update with no mount on this
    // client goes on as if on foot, instead of closing the game (a join with the other player's ship out).
    bool s2_ride_null_guard = true;
    // Host and guest, builds 3527 and 3549 (session2/focus_follow.h): each PC shows the character the other player
    // controls and hides the one left behind.
    bool s2_focus_follow = true;
    // Host and guest, builds 3527 and 3549 (session2/field_leave_guard.h): the other player leaving a field does not
    // unload the manager of its owner, so the host keeps its town NPCs when the guest leaves.
    bool s2_field_leave_guard = true;
    // Guest (session2/docking_dedupe_logic.h): the same equipment-docking request at most once per 2 s (the rest only
    // ever got a Nak, and filled the tunnel).
    bool s2_docking_dedupe = true;
    // Guest, builds 3527 and 3549 (session2/achievement_guard.h): once the game has played in a host's world, no Steam
    // achievement is unlocked until it is restarted (it holds the host's progress there).
    bool s2_achievement_guard = true;
    // Host, build 3549, log only (session2/manager_probe.h): who changes the sequencer managers' state.
    bool s2_manager_probe = false;
    // P8 S1, NPC scenes, MEASUREMENT ONLY (pendientes/p8-s1-escenas-npc.md §5, "Implementado para la medida").
    // HOST (session2/host_scene_diag.h), s1_scene_diag=1: H1 the server's StartActionReq flag 0x2A78D0D (kept local
    // vs relayed, per NPC key and hash), H2 who binds the host client's scene NPCs and when, H3 the host's scene
    // ledger and where the first NPC 2005 of each trip of user 2 sits. Needs create_session; installs
    // observer_stage in measure mode for its thread. Read only.
    bool s2_s1_scene_diag = false;
    // GUEST (session2/guest_scene_diag.h), guest_scene_diag=1: G1 each NPC's AI block and handle, G2 a read-only
    // replica of NPCScheduleManager's lookup, G3 the host character's manager X, G4 the client's C>S scene Reqs.
    // guest=1 only. Read only.
    bool s2_guest_scene_diag = false;
    // P8 gameplay for user 2 (session2/user2_funnels.h, pendientes/p8-impl-rango-embudos.md). HOST only, each
    // "0" (default, nothing installed) | "probe" (count only) | "1"; the raw ini values, parsed by
    // user2_funnels_logic.h. rank_permit: on the host's client, the host's enemies grant a rank permit on user 2's
    // character (vf188(5) at 0x221E281 / 0x221F29F answers 1 for it). quest_per_user: inside user 2's Req,
    // ServerField::vf40 returns user 2's quest manager. kill_loot_per_user: inside user 2's Req, DeadActor 0x62 and
    // the dead body's loot recipient go to user 2 instead of the field owner (the host).
    std::string s2_rank_permit = "0";
    std::string s2_quest_per_user = "0";
    // quest_policy, HOST (docs/research/s25/politica-misiones.md): "0" | "probe" | "1", independent of quest_per_user.
    // 1: user 2's respawn / safe position follows the HOST's quest manager; its UpdateTraceMissionReq 2372 is answered
    // by its own (never the host's; dropped when its own cannot be read); its MissionTriggerInOutReq 2112 measured.
    std::string s2_quest_policy = "0";
    std::string s2_kill_loot_per_user = "0";
    // P8 session 15, fast travel (session2/fast_travel.h, pendientes/p8-impl-viaje-rapido.md). user2_fast_travel,
    // HOST: "0" (default) | "probe" | "1" (F3: inside user 2's 2283 the vf48 call returning to 0x2A5F7FC answers user
    // 2's own sequencer manager; anything else than a live 1 = F2: the 2283 is dropped before the server).
    // guest_fast_travel_veto, GUEST: "0" (default) | "probe" | "1" (F1: the client's fast-travel entry 0x655110
    // returns 0 without effect while this game plays on the host, with a HUD notice).
    std::string s2_user2_fast_travel = "0";
    // user2_revive_manager, HOST (P8 S28, F4; session2/fast_travel_logic.h, research/s25/u0-resultados-s28.md): "0"
    // (default) | "probe" | "1". Inside user 2's ReviveLoadingReq 2362 the reload setter 0x2BC4950's vf48 answers user
    // 2's own sequencer manager, so user 2's revive never resets the host's manager +0x6A0. Needs create_session=1.
    std::string s2_user2_revive_manager = "0";
    std::string s2_guest_fast_travel_veto = "0";
    // guest_reload_wait_fix, GUEST (session2/guest_reload_wait.h, pendientes/p8-s15-viaje-tunel.md §8): "0" (default) |
    // "probe" | "1". Needs guest_actor_diag=1. probe: the load machine's trace per trip and, at state 0x12, the
    // blocking actor; 1: also removes from the wait list a host NPC that was already NOT READY (+0x5E 8) when a
    // reload in the same field began (as 0x12 removes a ready one), at most 16 per trip.
    std::string s2_guest_reload_wait_fix = "0";
    // P8 session 15, HOST (session2/travel_probe.h, p8-impl-viaje-rapido.md §11). user2_loading_owner_alias: 1 (default)
    // = user 2's copy of LoadingFieldDataAck 2643 names user 2 as the field owner (u32 +9), as its 2174 already does.
    // user2_travel_probe: 1 = read-only lines TravelBegin/Context/Prepared/Consume/Ack around user 2's 2283/2437.
    bool s2_loading_owner_alias = true;
    bool s2_user2_travel_probe = false;
    // P8, the other player's character as a native remote actor (session2/remote_motion.h,
    // pendientes/p8-impl-escalada.md). HOST and GUEST, all default 0.
    // remote_climb: "0" | "probe" (count PointClimb::Enter failures by control mode) | "1" (a failed Enter of a
    // remote player's character in control mode 2 returns 1: it follows the network during free wall climbs).
    std::string s2_remote_climb = "0";
    // wallup_send: 1 = the byte exe+0x6D76D5C is set to 1, so this client sends UpdateWallUpDataReq (2851) while
    // its character climbs up a ledge (the server relays it as 2893 to the other player).
    bool s2_wallup_send = false;
    // dismount_probe: 1 = read-only samples (30 ms) of the other player's character around mount/dismount (and
    // climbs), compact log.
    bool s2_dismount_probe = false;
    // divergence_probe: 1 = read-only, every 30 ms: the other player's character in this client's memory (its
    // TransformSync) against the position this mod's own channel reports for it (the HUD's); beyond 1.5 m for
    // more than 1 s, one line per second (method, actions, control mode, the interpolation buffer mc+0x3D0).
    // Host and guest (pendientes/p8-impl-log-async.md §3).
    bool s2_divergence_probe = false;
    // freeze_watchdog: 1 = a mod thread watches the main loop's frames (ui_pause / guest_seq_play hooks, else
    // Present); no frame for > 300 ms: stack samples of the frozen thread (RIP, return addresses in the exe /
    // cdmp.asi / hook stubs, the mod hook it is in). Host and guest, read only (pendientes/p8-impl-freeze-watchdog.md).
    bool s2_freeze_watchdog = false;
    // P8 remote movement (session2/remote_interp.h, horse_follow.h; pendientes/p8-impl-interp-remota.md), each
    // "0" (default, nothing installed) | "probe" (measure only) | "1"; the raw ini values.
    // remote_interp, host AND guest: the remote actors' (0xB...) interpolation delay per actor from their own
    // cadence (4 mid hooks at the reads of exe+0x6CB9548) and the buffer-emptying threshold 1000 -> 2500 ms.
    // horse_follow, HOST (needs create_session): every rider's MoveActorAck to user 2 is followed by a synthetic
    // MoveActorAck of its horse (the rider's Path world transform); user 2's own riding is only measured.
    std::string s2_remote_interp = "0";
    std::string s2_horse_follow = "0";
    // P8 session 8 pets (pendientes/p8-s8-mascotas.md, p8-impl-mascotas.md), all default 0 / "0".
    // child_settle_ms, HOST (session2/child_hold.h, needs create_session): a user's child (type 4/5/6, any
    // restore byte) is not announced to another user in the same NotifyAppear as its owner's character (nor
    // less than this many ms after it): withheld and re-announced natively once the character settled there.
    uint32_t s2_child_settle_ms = 0;
    // remote_interp_owned_cap_ms, host AND guest (session2/remote_interp.h, needs remote_interp): the delay
    // of an 0xB actor with an owner ([actor+0xA0] != 0: pets, horses, companions) is capped at this; its gaps
    // are not recorded while a StartAction seen on the network attaches it to a character.
    uint32_t s2_remote_interp_owned_cap_ms = 0;
    // attach_follow, HOST (session2/attach_follow.h, needs create_session): "0" | "probe" | "1". A user's child
    // riding its owner's character (StartAction with an 0xA Path parent) gets, with 1, a synthetic 2697 to
    // user 2 every 3rd 2697 of the character (character pose x the action's Path local); user 2's riding
    // children are measured only.
    std::string s2_attach_follow = "0";
    // P8 session 9 (pendientes/p8-s9-combate-montura.md §6, p8-impl-s9-movimiento.md), each "0" (default) |
    // "probe" | "1"; the raw ini values.
    // ride_filter, host AND guest (session2/ride_filter.h): the other player's mount/dismount StartActionAck becomes
    // the native on-foot / riding action before its client sees it (RideOn/RideOff never entered). Host: needs
    // [sniffer] enabled (its OnRecvPacket hook).
    std::string s2_ride_filter = "0";
    // mount_sync, host AND guest (session2/mount_sync.h, pendientes/p8-impl-monturas.md): "0" | "probe" | "1". The
    // controller's native rider<->horse commit (0x2228260) and retirement (0x2228E40) published through the tunnel;
    // probe: the stage 1 probes and what the observer would do; 1: the observer replays them natively.
    std::string s2_mount_sync = "0";
    // ride_dismount, host AND guest (P8 S18, session2/ride_filter_logic.h Dismount, pendientes/p8-impl-monturas.md
    // §11): "rewrite" (default, S17: every dismount action of the other player rewritten) | "partial" (only the
    // def+0xA & 0x40 ones, fix A) | "native" (with mount_sync=1: RideOff runs and the gate detour 0x2329A90 lets the
    // next action out, fix B).
    std::string s2_ride_dismount = "rewrite";
    // mount_seat, host AND guest (P8 S21, session2/mount_sync.h, pendientes/p8-impl-monturas.md §13): "0" (default) |
    // "probe" | "1". With mount_sync=1 the observer also calls ClientVehicle vf54 0xA45760 after its vf53: the remote
    // rider is seated on the saddle bone here (attach type 4) instead of placed by its own network samples.
    std::string s2_mount_seat = "0";
    // ride_hold_pos, host AND guest (P8 S21, same place): "0" (default) | "probe" | "1". Installed with mount_sync: the
    // remote player's empty interpolation buffer while it mounts (0x88E6A0's early return) gives its current pose,
    // not (0,0,0) (1 only with mount_sync=1; otherwise counted).
    std::string s2_ride_hold_pos = "0";
    // mount_relink, host AND guest (P8 S26, session2/mount_sync.h, docs/research/s25/montura-regresion.md section 10):
    // "0" (default) | "probe" | "1". With mount_sync=1: a link the observer applied and the game retired before the
    // remote rider's RideOn is applied again at the rider's next pre-mount action.
    std::string s2_mount_relink = "0";
    // child_reannounce, host AND guest: the guest asks the host (tunnel control packet) to re-announce a host's
    // child its client could not create; the host re-announces it natively through child_settle (needs
    // child_settle_ms > 0), at most 3 times per key with 2/4/8 s waits.
    std::string s2_child_reannounce = "0";
    // combat_follow, HOST (session2/combat_follow.h, needs create_session): the host client's enemies in combat
    // with user 2 get synthetic MoveActorAck 2697 to user 2 at ~16 Hz from the host client's memory.
    std::string s2_combat_follow = "0";
    // combat_follow_v2, HOST (needs combat_follow; P8 session 25, docs/research/noche/combate-retardo.md §6.1): "0" |
    // "probe" | "1". The combat stream: also enemies fighting any character near user 2, 30 Hz, the game's movement
    // thresholds, 100 ms keepalive of the same pose, no cutoff without real samples, the 12 nearest.
    std::string s2_combat_follow_v2 = "0";
    // remote_interp_combat, GUEST (needs remote_interp; same report §6.2): "0" | "probe" | "1". The host's enemies in
    // combat get D = max(last 3 arrival gaps) + 80 within [120, 400], falling at 1 ms per ms.
    std::string s2_remote_interp_combat = "0";
    // user2_world_anchor, HOST (session2/world_anchor.h, needs create_session; noche/mundo-invitado.md): "0" (default)
    // | "probe" | "1". User 2's character is the field's second anchor of the server's NPC collector ([field+0x2E4/
    // +0x2E8], written under the field's lock) while it stands in a field the host owns: its surroundings no longer
    // die ~250 m from the host. probe: "would" lines only. Both measure the collector's removals near user 2.
    std::string s2_user2_world_anchor = "0";
    // guest_horse_probe, HOST (horse_follow.h, needs create_session): "0" | "probe" (1 is refused: nothing is
    // ever sent). User 2's riding Req cadence vs its horse's, and the synthetic 2556 of the horse built and
    // checked, never sent.
    std::string s2_guest_horse_probe = "0";
    // P8 mount ride (session2/horse_follow.h, remote_interp.h; pendientes/p8-impl-monturas-cabalgata.md).
    // horse_follow_reverse, HOST (needs create_session, [sniffer] enabled, child_hold): "0" | "probe" | "1". User 2's
    // rider on its own horse: each of its MoveActorAck reaching the host's client is preceded by one of the horse
    // (the rider's Path world pose and ts), only if newer than the horse's last; never to the server nor to user 2.
    std::string s2_horse_follow_reverse = "0";
    // remote_interp_pair, host AND guest (needs remote_interp and [sniffer] enabled): 0 | 1. A ridden horse's delay
    // targets its rider's (the game's) while its samples are dense enough; the same no-jump approach.
    bool s2_remote_interp_pair = false;
    // remote_interp_players, host AND guest (needs remote_interp): "0" | "probe" | "1". The other player's character
    // gets an interpolation delay that follows how late its samples arrive (remote_interp_logic.h, "the players' class").
    std::string s2_remote_interp_players = "0";
    // P8 S1 option A, the sequencer part (session2/observer_seq_copy.h, guest_seq_route.h;
    // pendientes/p8-impl-opcion-a.md), each "0" (default) | "probe" | "1"; the raw ini values.
    // observer_seq_copy, HOST (needs create_session and [sniffer] enabled): the host client's sequencers
    // (2981 + 2661, then 2810) copied byte for byte to user 2 after the 2005 of their bound actors, plus the
    // host's 2322 once per observer trip (observer_seq_copy_2322, default 1); user 2's C>S about them dropped.
    // observer_seq_copy_only: hex sequencer ids and/or actor keys ("1AB,1AD,B0100C0F"); empty = all.
    // guest_seq_route, GUEST: a 2661/2981/2810/2322 naming another character goes to THAT character's stage
    // manager (X) instead of the field owner's (M). guest_seq_watch: hex actor keys whose state (exists,
    // login, sequencer component) is logged on change (G5), besides the actors of the routed 2661s.
    std::string s2_observer_seq_copy = "0";
    std::string s2_observer_seq_copy_only;
    bool s2_observer_seq_copy_2322 = true;
    bool s2_observer_seq_copy_2100 = false;  // 1: user 2's 2100 dropped while it observes the host's field
    // observer_sched_copy (pendientes/p8-impl-horarios-snapshot.md), HOST, on top of observer_seq_copy: the host
    // client's live schedule stages (2335 + 2958/2909) copied to user 2 on its observer trip, and the 2126/2958/2909
    // of the stages user 2 has, live. 0 (default) | 1.
    bool s2_observer_sched_copy = false;
    // P8 strategy B step 2 (session2/owner_fanout.h; pendientes/p8-impl-owner-fanout.md), HOST: "0" (default) |
    // "probe". A hook at ToTarget::vf1 counts, by writer and opcode, the Acks for the host's session while user 2
    // observes its field (what step 3 would add user 2 to). "1" is reserved for step 3: refused, off.
    std::string s2_owner_fanout = "0";
    std::string s2_guest_seq_route = "0";
    std::string s2_guest_seq_watch;
    // guest_seq_route_deny, GUEST (pendientes/p8-impl-escenas-play.md §15): hex resources of host sequencers never
    // put into X (field-reloading cutscenes). Default: the session 9 camp liberation 0x8CD771B1.
    std::string s2_guest_seq_route_deny = "8CD771B1";
    // guest_seq_foreign_player, GUEST (session2/guest_seq_foreign.h; research/s25/s44-escenas-del-anfitrion.md): "0"
    // (default, as before S44) | "probe" | "1". In guest_seq_route's 0xC0612A hook, a 2661 routed to X (its owner is
    // another player's character) gets the binding to that owner neutralized (type 5/4 -> 0) in the handler's own
    // vector: no scene ever moves the other player's copy. probe: '[would foreign]' lines only.
    std::string s2_guest_seq_foreign_player = "0";
    // guest_seq_foreign_probe, GUEST (same header): 0 (default) | 1. Read-only probes P1 0x602940 (a scene's actor list
    // at its start), P2 vf21 0x601470 / vf22 0x601C10 (SequencerControl targets), P3 0x6034FA (alignments).
    bool s2_guest_seq_foreign_probe = false;
    // guest_seq_foreign_present_probe, GUEST (session2/guest_seq_present.h; research/s25/s45-escenas-ajenas.md): 0
    // (default: no hook, no cost) | 1. READ-ONLY probes of what another player's scene does to this client's camera,
    // input and interface: S-A in P1, S-A2 in guest_x_veto, S-B / S-C at five timeline events' and StartLoading's
    // starts, S-D per frame in guest_seq_play's hook.
    bool s2_guest_seq_foreign_present_probe = false;
    // guest_seq_foreign_present, GUEST (R-A; same header and doc §3.1): "0" (default: nothing) | "probe" | "1". In P1,
    // the processor of another player's stage (client vtable 0x558C080) gets its vptr pointed at the mod's "world only"
    // table (its presentation slots = the common processor's): probe only logs '[R-A WOULD CUT presentation]'.
    std::string s2_guest_seq_foreign_present = "0";
    // guest_seq_foreign_timeline, GUEST (R-B; same header and doc §3.2): "0" (default: nothing) | "probe" | "1". The
    // camera starts (CameraSelectorEventData / SequencerPlayerCameraPreset, slot 99) of another player's stage's
    // timeline: probe logs '[R-B WOULD SKIP]', 1 returns at the entry without running them.
    std::string s2_guest_seq_foreign_timeline = "0";
    // guest_sched_route, GUEST (session2/guest_seq_route.h; pendientes/p8-impl-horarios-x.md): "0" | "probe" | "1".
    // A 2335/2126/2958/2909 (NPC schedule stage) naming another character goes to THAT character's stage manager X
    // (where the NPCs' vf13 0x9ED290 looks) instead of M; the delete / changes of a key follow its 2335.
    std::string s2_guest_sched_route = "0";
    // guest_sched_bind, GUEST (session2/guest_sched_bind.h; pendientes/p8-impl-horarios-enlace.md): "0" | "probe" | "1",
    // needs guest_sched_route=1. Right after a routed 2335 put its stage into X, the host character's NPCs of that
    // scene that vf13 left unbound (comp+0x318 == 0) are bound with the game's own 0x9F2FA0 (probe: only listed).
    std::string s2_guest_sched_bind = "0";
    // guest_seq_play, GUEST (session2/guest_seq_play.h; pendientes/p8-impl-escenas-play.md): "0" | "probe" | "1".
    // The routed X (the host character's stage manager) gets the frame's tick 0xA953C0 and, once per routed
    // 2322, +0x231 = 3. guest_seq_play_live (needs guest_seq_play): also 0xAA3E70(X, dt) and the 2524 to X.
    std::string s2_guest_seq_play = "0";
    bool s2_guest_seq_play_live = false;
    // guest_seq_route_2524, GUEST (session2/guest_seq_route.h; pendientes/p8-impl-secuenciador-bodyanim.md): "0" |
    // "probe" | "1", independent of guest_seq_play_live. probe: every 2524 classified by its scene (world / shop /
    // personal / ...), nothing routed; 1: only the WORLD scenes' 2524 into X. guest_seq_route_2524_allow: optional hex
    // 2661 resources (with 1, only those; empty = every WORLD scene).
    std::string s2_guest_seq_route_2524 = "0";
    std::string s2_guest_seq_route_2524_allow;
    // guest_seq_bodyanim_diag, GUEST (session2/guest_bodyanim_diag.h; same document): read-only. G5 lines of the
    // watched NPCs' control component (CC+0x70/+0x78, +0x23A, the layers' actions) and mid hooks at BodyAnim 0xA79770
    // and its graph configuration 0x2432F60 (counted, lines for the watched actors only).
    bool s2_guest_seq_bodyanim_diag = false;
    // guest_x_stage_veto / guest_x_camera_veto, GUEST (session2/guest_x_veto.h; pendientes/p8-s9-cinematica.md §8):
    // "0" | "probe" | "1". A stage of ANOTHER character's manager X (needs guest_seq_route=1) never reloads this
    // client's field (V1 0x5F2A3A + V0 0x778AB0); the camera / screen handlers are only counted ('1' acts as probe).
    std::string s2_guest_x_stage_veto = "0";
    std::string s2_guest_x_camera_veto = "probe";
    // guest_x_ui_veto, GUEST (session2/guest_x_veto.h; pendientes/p8-s10.md section 4): "0" | "probe" | "1". The
    // dialogue / interface / camera handlers run by X's stages, counted per handler (G = X / own M); with 1 the ones
    // whose native early way out was read whole (TimelineEvent, SetInteraction, InputBlock, UIControl, UIShowMinimap,
    // UIStageGuide) take it for X; the rest stay probe.
    std::string s2_guest_x_ui_veto = "0";
    // guest_x_ui_veto_allow, GUEST (session2/guest_x_veto.h; pendientes/p8-impl-veto-interaccion.md): handler names
    // (comma / blank separated) that are never vetoed for X, both directions running natively. Default SetInteraction
    // (the NPCs' dynamic interaction entries: world state). "", "0" or "none": every vetoable handler acts with 1.
    std::string s2_guest_x_ui_veto_allow = "SetInteraction";
    // guest_x_interaction_stage, GUEST (session2/guest_x_interaction.h; pendientes/p8-impl-tenderos-c1.md): "0" |
    // "probe" | "1". C1: the prompt check 0x2126920 of an NPC's dynamic interaction entry looks its stage id up in X
    // (the host character's manager) when it is not in M but is in X (RAX := X at 0x2126A1F); probe decides and counts.
    std::string s2_guest_x_interaction_stage = "0";
    // shop_probe, HOST (session2/shop_probe.h; pendientes/p8-impl-tenderos-c1.md): read-only probes of the server's
    // shop scenes (owner gate 0x288B87A, 0x288AAEF, the 2671 result, the server's 0x2126920) and user 2's
    // 2671/2720/2436/2591 with observer_seq_copy's R1 verdict. Needs create_session=1.
    bool s2_shop_probe = false;
    // funcnpc_twin, HOST (session2/shop_probe.h; pendientes/p8-impl-tenderos-s2.md): "0" | "probe" | "1" (held as
    // probe in this build). S2: logs which shop scene a twin for user 2 would be prepared for; nothing is called.
    std::string s2_funcnpc_twin = "0";
    // user2_stages, HOST (session2/user2_stages.h; research/s25/mundo-escenarios-propios.md, u0-resultados-s28.md §8):
    // "0" | "probe" | "1". probe: read only (both players' stage managers, timers, closes, the distance in cells, and
    // what U-1 would do). 1 (U-1): user 2's own manager is armed far from the host in the shared field (schedule
    // stages only) and drained near it / at its loads / at its logout. Needs create_session=1 (1 also user2_funnels'
    // subject: user2_fast_travel or user2_revive_manager not 0).
    std::string s2_user2_stages = "0";
    // user2_timer_route, HOST (session2/user2_stages.h; u0-resultados-s28.md §8): "0" | "probe" | "1". In a field the
    // host owns, user 2's own 2043/2045/2046 timers reach ITS manager (not the field owner's): its 2043 chain no longer
    // lives on the host's manager. probe: counted as "would". Needs user2_funnels' subject (user2_fast_travel or
    // user2_revive_manager not 0). user2_stages=1 needs it at 1.
    std::string s2_user2_timer_route = "0";
    // user2_stages_elements, HOST (session2/user2_stages.h; research/s25/tiendas-u2.md): "schedule" (default) |
    // "schedule+funcnpc". With U-1 armed and user2_shop_route live, user 2's manager prepares its cd_seq_funcnpc_*
    // (shop) scenes too; every other sequencer element stays skipped.
    std::string s2_user2_stages_elements = "schedule";
    // user2_npc_control, HOST (session2/user2_stages.h; u0-resultados-s28.md §8.17, U-e): "0" | "probe" | "1". The
    // NPCs born for user 2's armed stages get user 2 as controller (its client runs their AI, not the host's far one);
    // probe: '[would control]' and their reason-42 logouts counted. Acts only with user2_stages=1 armed. S43: its
    // reason-42 abort counts only the logouts that repeat a stage slot (schedule data, node) within 60 s (S31's
    // respawn loop; an unknown slot counts too); a native group's AI logout (many slots once) is only logged.
    std::string s2_user2_npc_control = "0";
    // S33: nuevas piezas, apagadas por defecto. npc_activation: 0 | probe | 1;
    // 1 activa contencion local en servidor, el cliente siempre observa.
    // Familia (S36) y viajeros (S38) admiten 1 en el anfitrión, con sus requisitos; en el invitado sólo observan.
    std::string s2_npc_activation = "0";
    std::string s2_npc_family_control = "0";
    // S36 fase B, HOST (docs/research/s25/s36-fase-b.md; AUDITORIA.md §2, §6): npc_family_control = 0 | probe | 1 (1 sólo
    // con user2_stages=1, user2_npc_control=1, npc_activation=1, npc_action_evidence=1, npc_degradation=1 y
    // publication_gate=1; si no, probe). npc_family_types: la cohorte de miembros, "3,6" por defecto (7 sólo explícito).
    std::string s2_npc_family_types = "3,6";
    // S42: familias de horario; 0 conserva S40. probe observa; 1 se degrada a probe (sin nueva autoridad).
    std::string s2_npc_family_vehicles = "0";
    // S42: retorno nativo de inmunidad; probe/1 sólo observan (1 más detalle).
    std::string s2_enemy_damage_probe = "0";
    // S42: 2928/2145/2953 y resultado nativo; probe/1 sólo observan, no fuerzan puertas.
    std::string s2_door_trace = "0";
    // [session2] housing_trace = 0 (default) | 1, any role, build 3576: logs calls into the client's housing code
    // (diagnostic, observation only; housing_trace.h).
    bool s2_housing_trace = false;
    // [session2] housing_redraw = 0 (default) | 1, guest, build 3576, EXPERIMENTAL: after the last part of a live house
    // list (2733) the active house stage is rebuilt, so the host's construction edits show without joining again.
    bool s2_housing_redraw = false;
    // [session2] housing_gimmick_guard = 0 (default) | 1, guest, build 3576: the guest skips the owner's update of the
    // house's gimmicks (pa::VHousingManager slot 35), which crashed it with the host's gimmick records kept.
    bool s2_housing_gimmick_guard = false;
    // S43 (docs/research/s25/s43-puertas-y-r42.md), HOST: scene_level_share = 0 | probe | 1. A: user 2's own 2598 / 2104
    // marks the SceneLevel ready (owner gate 0x283044D); B: a 2834 delete of a level the other user still has loaded is
    // skipped (0x2829E60). 0: nothing installed; probe: measures only.
    std::string s2_scene_level_share = "0";
    // S38 fase C, HOST (docs/research/s25/s38-fase-c.md): user2_road_control = 0 | probe | 1. Los viajeros del
    // AutoSpawnRoadReq 2550 del invitado (raíz y caravana entera, tipos 3/5/6) nacen con el usuario 2 como controlador
    // (1) o sólo se mide (probe). 1 sólo con npc_activation=1, observer_hold=1 y publication_gate=1 (si no, probe). En
    // el invitado cualquier valor distinto de 0 sólo observa (npc_probe_client).
    std::string s2_user2_road_control = "0";
    // S38 fase C (revisión §3.2): user2_road_carts = 0 | probe | 1. Con 0 (por defecto) las raíces tipo 5 (carros,
    // caballos con jinete o guía) quedan fuera del modo 1 de user2_road_control (probe las sigue midiendo). S40 carros
    // (docs/research/s25/s40-carros.md): probe = con user2_road_control=1, sus unidades se miden enteras sin escribir
    // nada mientras los demás viajeros se asignan; 1 = se asignan enteras (raíz, jinete, vehículos enlazados).
    std::string s2_user2_road_carts = "0";
    // S35 fase A, HOST (docs/research/s25/s35-fase-a.md; AUDITORIA.md §1, §4). "0" | "probe" | "1", 0 = S34.
    //  npc_action_evidence: el progreso de una unidad por el criterio H1b (acción nativa autorizada y aplicada; rama
    //    payload+0x281 = activación) en lugar del emisor S34 mal leído (param4 no es la sesión).
    //  npc_containment_guard: no retirar por silencio/carga del invitado; una Req pospone hasta plazo+gracia;
    //    revalidar Req/aplicación/versión al EJECUTAR la retirada.
    //  npc_degradation: con npc_activation=1, una contención no lista no rearma el aborto global de 5 s (pausa U-e).
    //  publication_gate: nunca publicar a un observador que no lo controla un actor con estado incompleto
    //    (restore 0, CC ilegible, dependencia retenida) por ninguna salida de child_hold (liberaciones y tabla llena).
    //  Plazos en ms, experimentales: npc_no_progress_ms (5000 = S34), npc_req_grace_ms, npc_guest_silence_ms,
    //    publication_retain_max_ms (la retención acotada de un actor inseguro antes de soltar su entrada sin publicar).
    std::string s2_npc_action_evidence = "0";
    std::string s2_npc_containment_guard = "0";
    std::string s2_npc_degradation = "0";
    std::string s2_publication_gate = "0";
    uint32_t s2_npc_no_progress_ms = 5000;
    uint32_t s2_npc_req_grace_ms = 8000;
    uint32_t s2_npc_guest_silence_ms = 2000;
    uint32_t s2_npc_postpone_max_ms = 60000;  // revisión S35: tope de la posposición por silencio/carga (0 = sin tope)
    uint32_t s2_publication_retain_max_ms = 60000;
    // S34, GUEST (net/horse_diag.h, horse_diag_install_remote): guest_remote_update_guard 0 | 1. CharacterControl
    // Update 0x85FBA0 / PostUpdate 0x860D30 return at once for an actor another user controls (+0x90 non-zero, not
    // the local key) while a layer has a chart and no action (Shadow's crash at 0x88F832). Off by default.
    bool s2_guest_remote_update_guard = false;
    // user2_drain_at_host_prepare, HOST (session2/user2_stages.h; u0-resultados-s28.md §8.17): "0" | "probe" | "1". At
    // the host's preparation near user 2 (<= 7 cells, same field) with user 2's manager armed: that manager is drained
    // at once, before the host's stages are created (the S31 handover's 2.9 s gap). probe: logged with its context.
    std::string s2_user2_drain_at_host_prepare = "0";
    // user2_fast_rearm, HOST (session2/user2_stages.h; docs/research/s25/s37-fase-d.md): "0" | "probe" | "1". S37 phase
    // D: the fast re-arm of U-1 when the host itself leaves user 2's area (no hysteresis + a one-shot 2043). 1 needs
    // user2_stages=1. probe: '[would FAST REARM]' and what it would have saved.
    std::string s2_user2_fast_rearm = "0";
    // user2_shop_route, HOST (session2/user2_shops.h; research/s25/tiendas-u2.md): "0" | "probe" | "1". The Reqs of
    // user 2's own shop scenes reach its own manager (U2-a at the scene handlers' vf48, U2-b at 0x2126A1F), and U-1's
    // distance drain waits while it is in a shop. Needs shop_probe=1 and user2_funnels' subject (as user2_stages=1).
    std::string s2_user2_shop_route = "0";
    // S46 phase 1 (session2/shop_trade_probe.h; docs/research/s25/s46-tenderos.md), HOST, READ ONLY:
    // shop_trade_probe = 0 | 1 (default 0: no hook). P1/P1b (the stage check of 2789/2366 in 0x21F2780), P2/P2a (the
    // server's SetInteraction exit / entry: the NPC's entries, R0's verdict, [would orphan]), P5/P6 (the 2671's
    // InteractionInfo and vf170), P3 (eErrNo names) and the ledger of the shop NPCs' entries ([orphan]).
    bool s2_shop_trade_probe = false;
    // user2_shop_trade_route = 0 | probe | 1 (S46 U2-c): at 0x21F28A1, for user 2's own trade check with U-1 armed and
    // a live scene of mgr2 on the NPC: probe '[would route to mgr2]'; 1 (phase 2) RAX := mgr2.
    std::string s2_user2_shop_trade_route = "0";
    // observer_hold_scene_order = 0 | probe | 1 (S46 T2), HOST, needs observer_hold_acks=1: user 2's own 2661 of a
    // trade scene (smithy / butcher) whose bound NPCs observer_hold still withholds. probe: '[would hold scene]' with
    // the keys, the delay and the scene's opcodes it would have held, nothing held. 1 (S46 phase 3, T2 active): the 2661
    // and every later packet of its scene id are KEPT in observer_hold_acks' route and queued right after the 2005 of
    // the last of those NPCs, in order (s46-tenderos.md §9).
    std::string s2_observer_hold_scene_order = "0";
    // user2_shop_trade_list = 0 | probe | 1 (S46 phase 3, T1), HOST, with user2_stages: 1 = with U-1 armed far (>= 10
    // cells) U-f lets through ONLY the cd_seq_funcnpc_* whose base name hashes to the trade list (smithy 0xA7132561,
    // butcher 0x978345CA), instead of user2_stages_elements; probe = the verdict in the lines only.
    std::string s2_user2_shop_trade_list = "0";
    // shop_interaction_own_delete = 0 | probe | 1 (S46 phase 2, R0; session2/shop_trade_probe.h), HOST and GUEST: at
    // SetInteraction's exit (P2 0x2369862, the actor's lock held), when the native erase would take ANOTHER stage's
    // entry, this stage has its own, the key is the shop's (0x000F4321) and an entry with that key belongs to the other
    // manager (host mgrH / mgr2; guest X / M): 1 swaps the two 0x30-byte entries (this stage's own then goes). On the
    // guest '1' is held as probe.
    std::string s2_shop_interaction_own_delete = "0";
    // guest_local_after_remote, GUEST (session2/guest.cpp; pendientes/p8-s9-cinematica.md §8): "allow" | "stuck".
    // stuck: a save loaded on this PC's own server after a session on the host's in the same run ends the game only
    // when that load is seen stuck (session 9: loading state 0x0C forever). allow (default): as before.
    std::string s2_guest_local_after_remote = "allow";
    // P8 session 25, hour and weather (session2/clock_push.h; research/noche/clima-hora.md §5).
    // user2_clock_push, HOST (needs create_session and the clock gate): "0" (default) | "probe" | "1". T1: right
    // after every LoadingCompleteAck 2762 queued for user 2, a native SetFieldTimeAck 2816 with the server's world
    // clock exe+0x6A6D238; T2: the same when that clock changes while user 2 is in the world. probe: logged only.
    std::string s2_user2_clock_push = "0";
    // block_guest_weather, HOST: 1 = user 2's SyncWeatherStateReq 2560 never reaches the host's server (it writes the
    // host field's weather flags with no owner check, 0x20E6FE0), counted. Default 0.
    bool s2_block_guest_weather = false;
    // clock_probe, HOST and GUEST, read only: every 5 s one 'ClockProbe' line (both clocks, the time manager
    // +0x28..+0x57, the 2188 bias; on the guest the 2816/2762 handed to its client). Default 0.
    bool s2_clock_probe = false;
    // weather_sync, HOST and GUEST (session2/weather_sync.h; research/noche/clima-sincronizar.md "Implementado"):
    // "0" (default) | "probe" (read-only X / vector / tick % 60000 lines) | "selftest" (host alone: the Weather
    // Viewer flag X+0x31 and precipitation 1.0 for 30 s, then put back) | "1" (host sends its vector as tunnel
    // control state 12 to a guest with caps 0x04; the guest writes it in viewer mode at 0x3DC4730's entry).
    std::string s2_weather_sync = "0";
    // weather_sync_radius_m, GUEST (mode 1): farther from the host than this, the guest keeps its own weather.
    uint32_t s2_weather_sync_radius_m = 2000;
    // catch_seq, HOST (session2/catch_seq.h; research/s25/finisher-sigilo.md): "0" (default) | "probe" | "1". An inline
    // hook at the entry of ClientCatch_ApplyResult 0x935DD0 (the 2156 apply). probe: every grab logged (keys, who
    // controls each, the packet's sequence byte against the grabber's). 1: a remote grabber's mismatching sequence is
    // replaced by its byte here when the victim is controlled here, so the native catch applies (guest finishers).
    std::string s2_catch_seq = "0";
    // remote_rope, BOTH PCs (session2/remote_rope.h; research/s25/gancho-cuerda.md): "0" (default) | "probe" | "1".
    // The grappling hook's rope of the OTHER player: at RemoteCatchComponent_Apply 0x592340's entry a remote thrower's
    // tree handle is translated to this PC's (F1) and its stale slot released first (F3); on the host the server's
    // tree release also sends the native 2471 ToNear (F2: 0x27D9110, and 0x1807390 for the launch). probe: computed and
    // logged (native-equivalent reads: the lookup's lock and reference, vf70 / vf3B0), no game state written.
    std::string s2_remote_rope = "0";
    // rope_probe, BOTH PCs (session2/rope_probe.h; research/s25/gancho-cuerda.md section 13): 0 (default) | 1. Log
    // only: the tree bend (hooks at the entries of ClientFrameEventTreePulling::vf1 0x6D46D0 and of the per-frame
    // apply 0x8A30C0) and the grappling device (its gimmick events sent and its 2005 received, from the sniffer).
    bool s2_rope_probe = false;
    // tree_bend, BOTH PCs (session2/tree_bend.h; research/s25/gancho-cuerda.md section 14): "0" (default) | "probe" |
    // "1". The other player's tree bend: this client's own SetBend values (TreeComponent::SetBend 0x349EA10, from its
    // thrower's input) go through the tunnel (control state 15) in probe and 1; the observer logs what it would apply
    // at the remote thrower's RemoteCatch tick 0x59C0D0 (probe) or applies it with the same natives (1).
    std::string s2_tree_bend = "0";
    // docked_gimmicks, BOTH PCs (session2/docked_gimmicks.h; research/s25/gimmicks-dueno.md): "0" (default) | "probe" |
    // "1". The gimmicks docked to a player character (the grappling device): 1 on the GUEST gives the host's 2005
    // records docked to its own character its user as controller (local drive: its own rope drawn) and withholds its
    // state requests for them (the host stays the controller); probe (and 1) logs the classification and, once the
    // world is up, log-only hooks (client requests 0x8E59D0 / 0x8E5F60; host: docking spawns, controller write,
    // server accept / reject, 2221 unspawns). The host is never rewritten. No server authority (phase 2) yet.
    std::string s2_docked_gimmicks = "0";
    // docked_gimmicks_other, GUEST (session2/docked_gimmicks.h; research/s25/gimmicks-dueno.md section 8): "0"
    // (default) | "probe" | "1". The mirror of docked_gimmicks=1 for the records docked to the OTHER player's character (the
    // host's grappling device, so the host's rope is drawn on the guest): rewritten to the guest's user with 1, their
    // state requests withheld (the host stays the controller); probe counts. Needs docked_gimmicks on; the host
    // ignores it (logged).
    std::string s2_docked_gimmicks_other = "0";
    // [session2] guest_gimmick_interact = 0 | trace | 1 and guest_gimmick_interact_events (hex hashes), guest
    // (gimmick_interact_logic.h): the market stalls' "Buy" on objects the host controls.
    std::string s2_guest_gimmick_interact = "0";
    std::string s2_guest_gimmick_interact_events;
    // [session2] interact_gate = 0 | probe | 1, interact_gate_errors (hex), interact_gate_pass (interact_gate.h):
    // the client's press-time interaction evaluation (build 3549), probed on both roles, bypassed on the guest.
    std::string s2_interact_gate = "0";
    std::string s2_interact_gate_errors;
    std::string s2_interact_gate_pass = "3";
    std::string s2_interact_gate_types = "7";
    // [session2] vehicle_follow = 0 | probe | 1 (vehicle_follow.h): the other player's ship drawn where its controller has
    // it (build 3576). Either PC.
    std::string s2_vehicle_follow = "0";
    uint32_t s2_vehicle_follow_delay_ms = 300;
    // [session2] store_gate = 0 | probe | 1 (store_gate.h), both roles: the guest's buy/sell passes the shop-scene test.
    std::string s2_store_gate = "0";
    // [session2] guest_shop_branch = 0 | 1 (guest_shop_branch.h), guest: the shopkeepers' window on the guest.
    std::string s2_guest_shop_branch = "0";
    // [session2] shop_ui_trace = 0 | 1 (shop_ui_trace.h), both roles, log only: the shop window's UI events.
    std::string s2_shop_ui_trace = "0";
    // [session2] guest_shop_window = 0 | 1 (guest_shop_window.h), guest: its press on a shopkeeper opens the buy window.
    std::string s2_guest_shop_window = "0";
    // [session2] housing_share = 0 | probe | 1 | live (housing_share.h), host: the guest sees the host's houses (1: login set only; live: also live changes, UNSAFE).
    std::string s2_housing_share = "0";
    // [session2] housing_share_live_ops = "" | logical opcodes, e.g. 2623 (with housing_share=live only): the live
    // changes forwarded to the guest, one at a time while each is tested; empty = all but 2500 (2500 never).
    std::string s2_housing_share_live_ops;
    // [session2] housing_share_edits = 0 | 1 (with housing_share=1 or live), host: the host's construction-mode edits
    // reach the guest (its client's SyncHousingPlacedSceneObjectListReq 2408, sent to user 2 as the login Ack 2733).
    bool s2_housing_share_edits = false;
    // [session2] housing_share_guest_spawn = 0 (default) | 1 (with housing_share), host: 0 drops user 2's own spawn
    // requests of the housing gimmicks (2492, 2446), so only the host's client spawns them (the guest crash of 2026-11-07).
    bool s2_housing_share_guest_spawn = false;
    // [session2] housing_share_rekey = 0 (default) | 1 | opcode list (with housing_share), host: 0 keeps the host's key
    // (the house is another player's: the guest sees the host's props, never its walls, and never crashes); 1 gives
    // user 2 the host's housing under its own key (it owns the house: walls too, but its client crashes when the host
    // opens the construction mode); a list re-keys only those housing opcodes (hsh::parse_rekey; 35245,2733 crashed too).
    std::string s2_housing_share_rekey = "0";
    // [session2] housing_share_drop_gimmicks = 0 (default) | all | waiting, host: the host's 2733 reaches user 2 without
    // its gimmick records (category 4: doors, furniture), all of them or those of the host's latest 2500 waiting list
    // (3576, 7-nov: `waiting` keeps 4 records that draw the roof; with no 2500 known yet it drops them all, as `all`).
    std::string s2_housing_share_drop_gimmicks = "0";
    // [session2] housing_share_level_states = 0 (default) | 1, host: the host's ChangeGameLevelStateAck (2344) for user 2
    // with its house list at login (the house plot's phase level follows it: without it the guest saw a pond).
    uint32_t s2_housing_share_level_states = 0;
    // gimmick_event_dedup, BOTH PCs (session2/gimmick_event_dedup_logic.h; research/s25/gimmicks-dueno.md section 7):
    // "0" (default) | "probe" | "1". CreateProjectileFromGimmickEventReq 2779 has no controller check on the server, so
    // both clients' 2779 make two projectiles. GUEST: each outgoing 2779 decided against the controller the last 2005
    // gave its gimmick (probe: logged; 1: withheld when it is the other user). HOST: log only (2779 by origin, 2250
    // duplicates).
    std::string s2_gimmick_event_dedup = "0";
    // guest_schedule_load, GUEST (session2/guest_sched_load.h; pendientes/p8-impl-horarios.md): "0" | "probe" | "1".
    // The NPC schedule files a host 2005 / 2335 / 2874 names, loaded (1) with the native 0x1864140 on the
    // NetworkThread before the packet is delivered; probe decides and logs only.
    std::string s2_guest_schedule_load = "0";
    // schedule_load_selfcheck, HOST or GUEST (session2/guest_sched_load.h): read-only lines about the schedule
    // manager, its context names and the session-8 resources (what guest_schedule_load=1 relies on).
    bool s2_schedule_load_selfcheck = false;
    // seq_actor_restore, GUEST (session2/guest_seq_restore.h; pendientes/p8-impl-seq-restore.md): "0" | "probe" |
    // "1". A remote actor announced in a seq_bodyanim action no chart has restores the idle wait (or nothing)
    // instead of failing its login (eErrNoInvalidActionChart), so the copied 2661 of its sequencer finds it.
    std::string s2_seq_actor_restore = "0";
    // P8 session 25, HOST (session2/guest_save_host.h; noche/progreso-invitado.md "Implementado (fase A)"):
    // guest_own_save = "0" | "probe" | "1". User 2 loads and saves its own slot (204) in the save sandbox; needs
    // save_guard=redirect. probe: log-only probes of LoadSlot / SavePlayerToSlot / FlushPendingSaveData.
    // Phase B (guest_save_tunnel.h / guest_save_guest.h, "Implementado (fase B)"): the same key on the GUEST (with
    // guest=1 guest_mode=remote): probe = its slot is uploaded and the results stored, nothing held; 1 = also the 3093
    // waits for the host's SAVE_ACK and the goodbye for the final save.
    std::string s2_guest_own_save = "0";
    // Phase A: a folder with lobby.save + save.save staged as the guest's slot at install (empty = none).
    std::wstring s2_guest_own_save_debug_dir;
    // P8 session 35, phase E, HOST (session2/host_save_export.h; research/s25/s35-fase-e-guardado.md):
    // host_save = "sandbox" (default, today's behaviour) | "export" | "probe". With save_guard=redirect, export
    // archives the previous sandbox (and its _prev) into a verified generation under host_save_dir before the
    // rebuild; probe also classifies each archived slot and journals Save/Flush (with guest_own_save probe or 1).
    // "real" is refused (audit S34 §5): the real save folder is never written.
    std::string s2_host_save = "sandbox";
    // Where the generations go; empty = <bin64>\cdmp_save_exports; a relative path is under bin64. Recommended:
    // C:\Emulador CD\backups\host_save_exports (uninstalling the game deletes bin64).
    std::wstring s2_host_save_dir;
    // Valid generations kept (1-500; the newest is never pruned).
    uint32_t s2_host_save_keep = 20;
};

Config load_config(const std::wstring& ini_path);
// The result of the last load_config call (a default Config before the first). Written once by the
// worker before the late-init thread starts; read from session2::install.
const Config& loaded_config();
// sizeof(Config) as config.cpp saw it. A translation unit left compiled against an older config.h reads
// every field after the change at the wrong offset (S44, 15-10: the guest's title menu vanished); the
// worker compares this with its own sizeof(Config) and installs nothing on a mismatch.
std::size_t config_layout_size();

}  // namespace cdmp
