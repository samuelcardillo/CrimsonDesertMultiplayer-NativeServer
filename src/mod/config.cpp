#include "mod/config.h"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cwchar>

namespace cdmp {
namespace {

constexpr wchar_t kDefaultIni[] =
    L"; Crimson Desert Multiplayer (cdmp) settings\r\n"
    L"[general]\r\n"
    L"player_name=Player\r\n"
    L"; Wait before starting, in milliseconds\r\n"
    L"startup_delay_ms=0\r\n"
    L"\r\n"
    L"[net]\r\n"
    L"enabled=1\r\n"
    L"; udp (direct or through cdmp_peer.exe) or steam (no port forwarding)\r\n"
    L"transport=udp\r\n"
    L"; guest connects to the host or to cdmp_peer; host waits for one player\r\n"
    L"role=guest\r\n"
    L"; UDP: address of the host or of cdmp_peer.exe (a UDP host listens on peer_port)\r\n"
    L"peer_host=127.0.0.1\r\n"
    L"peer_port=37015\r\n"
    L"send_rate_hz=20\r\n"
    L"\r\n"
    L"[steam]\r\n"
    L"; Guest: the host's SteamID64 (empty = the only friend playing Crimson Desert)\r\n"
    L"; Host: accept only this friend (empty = any friend playing)\r\n"
    L"peer_steamid=\r\n"
    L"\r\n"
    L"[overlay]\r\n"
    L"; 0 turns off the in-game overlay completely (no graphics hooks)\r\n"
    L"enabled=1\r\n"
    L"; Draw a cross on your own character (to check the projection)\r\n"
    L"self_marker=1\r\n"
    L"\r\n"
    L"[sniffer]\r\n"
    L"; 1 logs the game's internal client/server messages to cdmp_packets.log/.bin\r\n"
    L"enabled=1\r\n"
    L"\r\n"
    L"[coop]\r\n"
    L"; 1 shows the other player (through cdmp_peer) as a character in your world\r\n"
    L"enabled=0\r\n"
    L"; Playout delay in ms (longer = smoother climbing, more lag)\r\n"
    L"delay_ms=300\r\n"
    L"; Sideways offset of the other player in metres (0 = exact position)\r\n"
    L"offset_m=0\r\n";

std::wstring read_string(const std::wstring& path, const wchar_t* section, const wchar_t* key,
                         const std::string& fallback) {
    wchar_t buf[256];
    const std::wstring def(fallback.begin(), fallback.end());
    GetPrivateProfileStringW(section, key, def.c_str(), buf, 256, path.c_str());
    return buf;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr,
                                      0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr,
                        nullptr);
    return s;
}

uint32_t read_uint(const std::wstring& path, const wchar_t* section, const wchar_t* key,
                   uint32_t fallback) {
    return GetPrivateProfileIntW(section, key, static_cast<INT>(fallback), path.c_str());
}

// A distance in metres, within +-50; anything else keeps the fallback.
float read_metres(const std::wstring& path, const wchar_t* section, const wchar_t* key,
                  float fallback) {
    const std::wstring s = read_string(path, section, key, "");
    if (s.empty()) return fallback;
    wchar_t* end = nullptr;
    const float v = std::wcstof(s.c_str(), &end);
    return end != s.c_str() && std::isfinite(v) && std::fabs(v) <= 50.0f ? v : fallback;
}

// The last load_config result (loaded_config()).
Config g_loaded;

}  // namespace

std::size_t config_layout_size() { return sizeof(Config); }

Config load_config(const std::wstring& ini_path) {
    if (GetFileAttributesW(ini_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        HANDLE h = CreateFileW(ini_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            // UTF-16 BOM so GetPrivateProfileStringW reads it as Unicode.
            const wchar_t bom = 0xFEFF;
            DWORD written = 0;
            WriteFile(h, &bom, sizeof bom, &written, nullptr);
            WriteFile(h, kDefaultIni, sizeof kDefaultIni - sizeof(wchar_t), &written, nullptr);
            CloseHandle(h);
        }
    }

    Config c;
    c.player_name = narrow(read_string(ini_path, L"general", L"player_name", c.player_name));
    c.startup_delay_ms = read_uint(ini_path, L"general", L"startup_delay_ms", c.startup_delay_ms);
    c.background_full_speed =
        read_uint(ini_path, L"general", L"background_full_speed",
                  read_uint(ini_path, L"session2", L"background_full_speed", 0)) != 0;
    c.net_enabled = read_uint(ini_path, L"net", L"enabled", 1) != 0;
    c.peer_host = narrow(read_string(ini_path, L"net", L"peer_host", c.peer_host));
    c.peer_port = static_cast<uint16_t>(read_uint(ini_path, L"net", L"peer_port", c.peer_port));
    c.send_rate_hz = std::clamp(read_uint(ini_path, L"net", L"send_rate_hz", c.send_rate_hz), 1u, 60u);
    c.net_transport_steam = read_string(ini_path, L"net", L"transport", "udp") == L"steam";
    c.net_role_host = read_string(ini_path, L"net", L"role", "guest") == L"host";
    c.host_loopback_only = read_uint(ini_path, L"net", L"host_loopback_only", 0) != 0;
    c.steam_peer_id = _wcstoui64(read_string(ini_path, L"steam", L"peer_steamid", "").c_str(), nullptr, 10);
    c.steam_channel = static_cast<int>(read_uint(ini_path, L"steam", L"channel", 67));
    // 0 = Steam's defaults; otherwise 64 KB/s .. 64 MB/s, the maximum never below the minimum.
    c.steam_send_rate_min_kb = read_uint(ini_path, L"steam", L"send_rate_min_kb", c.steam_send_rate_min_kb);
    if (c.steam_send_rate_min_kb) c.steam_send_rate_min_kb = std::clamp(c.steam_send_rate_min_kb, 64u, 65536u);
    c.steam_send_rate_max_kb = std::clamp(read_uint(ini_path, L"steam", L"send_rate_max_kb", c.steam_send_rate_max_kb),
                                          std::max(c.steam_send_rate_min_kb, 64u), 65536u);
    c.steam_send_buffer_kb =
        std::clamp(read_uint(ini_path, L"steam", L"send_buffer_kb", c.steam_send_buffer_kb), 512u, 65536u);
    // 0 = Steam's defaults; otherwise 1 MB .. 256 MB and 1000 .. 1,000,000 messages.
    c.steam_recv_buffer_kb = read_uint(ini_path, L"steam", L"recv_buffer_kb", c.steam_recv_buffer_kb);
    if (c.steam_recv_buffer_kb) c.steam_recv_buffer_kb = std::clamp(c.steam_recv_buffer_kb, 1024u, 262144u);
    c.steam_recv_buffer_messages = read_uint(ini_path, L"steam", L"recv_buffer_messages", c.steam_recv_buffer_messages);
    if (c.steam_recv_buffer_messages) {
        c.steam_recv_buffer_messages = std::clamp(c.steam_recv_buffer_messages, 1000u, 1000000u);
    }
    c.overlay_enabled = read_uint(ini_path, L"overlay", L"enabled", 1) != 0;
    c.overlay_self_marker = read_uint(ini_path, L"overlay", L"self_marker", 1) != 0;
    c.sniffer_enabled = read_uint(ini_path, L"sniffer", L"enabled", 1) != 0;
    c.sniffer_record = read_uint(ini_path, L"sniffer", L"record", 1) != 0;
    c.dev_clone_hotkeys = read_uint(ini_path, L"dev", L"clone_hotkeys", 0) != 0;
    c.dev_mirror_delay_ms = std::min(read_uint(ini_path, L"dev", L"mirror_delay_ms", 300), 5000u);
    c.dev_mirror_offset_m = read_metres(ini_path, L"dev", L"mirror_offset_m", c.dev_mirror_offset_m);
    c.dev_combat_tests = read_uint(ini_path, L"dev", L"combat_tests", 0) != 0;
    c.dev_minimap_cycle = read_uint(ini_path, L"dev", L"minimap_cycle", 0) != 0;
    c.dev_aggro_test = read_uint(ini_path, L"dev", L"aggro_test", 0) != 0;
    c.dev_enemy_relay = read_uint(ini_path, L"dev", L"enemy_relay", 0) != 0;
    c.dev_piece4_test = read_uint(ini_path, L"dev", L"piece4_test", 0) != 0;
    c.dev_attack_probe = read_uint(ini_path, L"dev", L"attack_probe", 0) != 0;
    c.coop_enabled = read_uint(ini_path, L"coop", L"enabled", 0) != 0;
    c.coop_delay_ms = std::clamp(read_uint(ini_path, L"coop", L"delay_ms", c.coop_delay_ms), 50u, 5000u);
    c.coop_offset_m = read_metres(ini_path, L"coop", L"offset_m", c.coop_offset_m);
    c.coop_horse = read_uint(ini_path, L"coop", L"horse", 0) != 0;
    c.coop_equip = read_uint(ini_path, L"coop", L"equip", 1) != 0;
    c.coop_damage = read_uint(ini_path, L"coop", L"damage", 1) != 0;
    c.coop_map_pin = read_uint(ini_path, L"coop", L"map_pin", 1) != 0;
    c.coop_enemies_target_copy = read_uint(ini_path, L"coop", L"enemies_target_copy", 0) != 0;
    c.coop_guest_hits = read_uint(ini_path, L"coop", L"guest_hits", 0) != 0;
    c.coop_guest_hit_stagger = read_uint(ini_path, L"coop", L"guest_hit_stagger", 0) != 0;
    c.coop_player_hit_react = read_uint(ini_path, L"coop", L"player_hit_react", 0) != 0;
    c.coop_player_hit_lethal = read_uint(ini_path, L"coop", L"player_hit_lethal", 0) != 0;
    c.coop_copy_attack_slots = static_cast<int>(std::min(read_uint(ini_path, L"coop", L"copy_attack_slots", 0), 8u));
    c.coop_map_pin_shape = static_cast<uint8_t>(std::min(read_uint(ini_path, L"coop", L"map_pin_shape", 4), 13u));
    c.coop_map_pin_colour = static_cast<uint8_t>(std::min(read_uint(ini_path, L"coop", L"map_pin_colour", 14), 14u));
    c.s2_enabled = read_uint(ini_path, L"session2", L"enabled", 0) != 0;
    c.s2_probe = read_uint(ini_path, L"session2", L"probe", 1) != 0;
    // 0 | 1 | trace | redirect; anything unknown keeps the safe side (block).
    c.s2_save_guard = saveguard::parse_mode(narrow(read_string(ini_path, L"session2", L"save_guard", "1")))
                          .value_or(saveguard::Mode::Block);
    c.s2_block_save_trocs = read_uint(ini_path, L"session2", L"block_save_trocs", 0) != 0;
    c.s2_finder_log = read_uint(ini_path, L"session2", L"finder_log", 0) != 0;
    c.s2_create_session = read_uint(ini_path, L"session2", L"create_session", 0) != 0;
    c.s2_accept_tunnel = read_uint(ini_path, L"session2", L"accept_tunnel", 0) != 0;
    c.s2_relay_fix = read_uint(ini_path, L"session2", L"relay_fix", 0) != 0;
    c.s2_mirror_host = read_uint(ini_path, L"session2", L"mirror_host", 0) != 0;
    c.s2_share_field = read_uint(ini_path, L"session2", L"share_field", 0) != 0;
    c.s2_clock_gate = read_uint(ini_path, L"session2", L"clock_gate", 1) != 0;
    c.s2_identity_probe = read_uint(ini_path, L"session2", L"identity_probe", 0) != 0;
    c.s2_identity_fix = read_uint(ini_path, L"session2", L"identity_fix", c.s2_create_session ? 1 : 0) != 0;
    c.s2_companion_probe = read_uint(ini_path, L"session2", L"companion_probe", 0) != 0;
    c.s2_child_hold = read_uint(ini_path, L"session2", L"child_hold", c.s2_share_field ? 1 : 0) != 0;
    c.s2_reconnect = read_uint(ini_path, L"session2", L"reconnect", 0) != 0;
    c.s2_rejoin = narrow(read_string(ini_path, L"session2", L"rejoin", "0"));
    c.s2_guest = read_uint(ini_path, L"session2", L"guest", 0) != 0;
    c.s2_guest_remote = read_string(ini_path, L"session2", L"guest_mode", "observe") == L"remote";
    c.s2_guest_slot_refresh_test = read_uint(ini_path, L"session2", L"guest_slot_refresh_test", 0) != 0;
    c.s2_guest_actor_diag = read_uint(ini_path, L"session2", L"guest_actor_diag", 0) != 0;
    c.s2_guest_layer_guard = read_uint(ini_path, L"session2", L"guest_layer_guard", 0) != 0;
    c.s2_observer_hold = read_uint(ini_path, L"session2", L"observer_hold", 0) != 0;
    c.s2_observer_load_defer = narrow(read_string(ini_path, L"session2", L"observer_load_defer", "0"));
    c.s2_observer_hold_pieces = narrow(read_string(ini_path, L"session2", L"observer_hold_pieces", "0"));
    c.s2_observer_hold_family = narrow(read_string(ini_path, L"session2", L"observer_hold_family", ""));
    c.s2_guest_s3_diag = read_uint(ini_path, L"session2", L"guest_s3_diag", 0) != 0;
    c.s2_guest_crash_dump = read_uint(ini_path, L"session2", L"guest_crash_dump", 0) != 0;
    c.s2_guest_update_guard = read_uint(ini_path, L"session2", L"guest_update_guard", 0) != 0;
    c.s2_load_diag = read_uint(ini_path, L"session2", L"load_diag", 0) != 0;
    c.s2_s1_diag = read_uint(ini_path, L"session2", L"s1_diag", 0) != 0;
    c.s2_observer_stage_sync = read_uint(ini_path, L"session2", L"observer_stage_sync", 0);
    c.s2_guest_stage_diag = read_uint(ini_path, L"session2", L"guest_stage_diag", 0) != 0;
    c.s2_observer_milestone = read_uint(ini_path, L"session2", L"observer_milestone", 0) != 0;
    c.s2_observer_milestone_send = read_uint(ini_path, L"session2", L"observer_milestone_send", 0) != 0;
    c.s2_observer_milestone_reload = narrow(read_string(ini_path, L"session2", L"observer_milestone_reload", "0"));
    c.s2_observer_milestone_reload_any =
        narrow(read_string(ini_path, L"session2", L"observer_milestone_reload_any", "0"));
    c.s2_observer_scene_copy = read_uint(ini_path, L"session2", L"observer_scene_copy", 0) != 0;
    c.s2_observer_hold_acks = read_uint(ini_path, L"session2", L"observer_hold_acks", 0) != 0;
    c.s2_character_hold = read_uint(ini_path, L"session2", L"character_hold", 0) != 0;
    // P8 review of 10-10 (pendientes/p8-revision-noche.md, "Correcciones").
    c.s2_notify_thread_rule = read_uint(ini_path, L"session2", L"notify_thread_rule", 0) != 0;
    c.s2_guest_goodbye_end = read_uint(ini_path, L"session2", L"guest_goodbye_end", 1) != 0;
    // P8 tunnel performance (pendientes/p8-tunel-rendimiento.md).
    c.s2_tunnel_compress = read_uint(ini_path, L"session2", L"tunnel_compress", 0) != 0;
    c.s2_c4_safe_reads = read_uint(ini_path, L"session2", L"c4_safe_reads", 0) != 0;
    c.s2_ui_pause_block = narrow(read_string(ini_path, L"session2", L"ui_pause_block", "0"));
    c.s2_seq_marker_guard = read_uint(ini_path, L"session2", L"seq_marker_guard", 1) != 0;
    c.s2_seq_marker_trace = read_uint(ini_path, L"session2", L"seq_marker_trace", 0) != 0;
    c.s2_change_pivot_guard = read_uint(ini_path, L"session2", L"change_pivot_guard", 1) != 0;
    c.s2_ride_null_guard = read_uint(ini_path, L"session2", L"ride_null_guard", 1) != 0;
    c.s2_focus_follow = read_uint(ini_path, L"session2", L"focus_follow", 1) != 0;
    c.s2_field_leave_guard = read_uint(ini_path, L"session2", L"field_leave_guard", 1) != 0;
    c.s2_docking_dedupe = read_uint(ini_path, L"session2", L"docking_dedupe", 1) != 0;
    c.s2_achievement_guard = read_uint(ini_path, L"session2", L"achievement_guard", 1) != 0;
    c.s2_manager_probe = read_uint(ini_path, L"session2", L"manager_probe", 0) != 0;
    c.s2_s1_scene_diag = read_uint(ini_path, L"session2", L"s1_scene_diag", 0) != 0;
    c.s2_guest_scene_diag = read_uint(ini_path, L"session2", L"guest_scene_diag", 0) != 0;
    // P8 gameplay for user 2 (pendientes/p8-impl-rango-embudos.md).
    c.s2_rank_permit = narrow(read_string(ini_path, L"session2", L"rank_permit", "0"));
    c.s2_quest_per_user = narrow(read_string(ini_path, L"session2", L"quest_per_user", "0"));
    c.s2_quest_policy = narrow(read_string(ini_path, L"session2", L"quest_policy", "0"));
    c.s2_kill_loot_per_user = narrow(read_string(ini_path, L"session2", L"kill_loot_per_user", "0"));
    // P8 session 15, fast travel (pendientes/p8-impl-viaje-rapido.md).
    c.s2_user2_fast_travel = narrow(read_string(ini_path, L"session2", L"user2_fast_travel", "0"));
    c.s2_user2_revive_manager = narrow(read_string(ini_path, L"session2", L"user2_revive_manager", "0"));
    c.s2_guest_fast_travel_veto = narrow(read_string(ini_path, L"session2", L"guest_fast_travel_veto", "0"));
    c.s2_guest_reload_wait_fix = narrow(read_string(ini_path, L"session2", L"guest_reload_wait_fix", "0"));
    c.s2_loading_owner_alias = read_uint(ini_path, L"session2", L"user2_loading_owner_alias", 1) != 0;
    c.s2_user2_travel_probe = read_uint(ini_path, L"session2", L"user2_travel_probe", 0) != 0;
    // P8 remote climb / wall-up / dismount (pendientes/p8-impl-escalada.md).
    c.s2_remote_climb = narrow(read_string(ini_path, L"session2", L"remote_climb", "0"));
    c.s2_wallup_send = read_uint(ini_path, L"session2", L"wallup_send", 0) != 0;
    c.s2_dismount_probe = read_uint(ini_path, L"session2", L"dismount_probe", 0) != 0;
    c.s2_divergence_probe = read_uint(ini_path, L"session2", L"divergence_probe", 0) != 0;
    c.s2_freeze_watchdog = read_uint(ini_path, L"session2", L"freeze_watchdog", 0) != 0;
    // P8 remote movement (pendientes/p8-impl-interp-remota.md).
    c.s2_remote_interp = narrow(read_string(ini_path, L"session2", L"remote_interp", "0"));
    c.s2_horse_follow = narrow(read_string(ini_path, L"session2", L"horse_follow", "0"));
    // P8 session 8 pets (pendientes/p8-impl-mascotas.md).
    c.s2_child_settle_ms = read_uint(ini_path, L"session2", L"child_settle_ms", 0);
    c.s2_remote_interp_owned_cap_ms = read_uint(ini_path, L"session2", L"remote_interp_owned_cap_ms", 0);
    c.s2_attach_follow = narrow(read_string(ini_path, L"session2", L"attach_follow", "0"));
    // P8 session 9 (pendientes/p8-impl-s9-movimiento.md).
    c.s2_ride_filter = narrow(read_string(ini_path, L"session2", L"ride_filter", "0"));
    c.s2_mount_sync = narrow(read_string(ini_path, L"session2", L"mount_sync", "0"));
    c.s2_ride_dismount = narrow(read_string(ini_path, L"session2", L"ride_dismount", "rewrite"));
    c.s2_mount_seat = narrow(read_string(ini_path, L"session2", L"mount_seat", "0"));
    c.s2_ride_hold_pos = narrow(read_string(ini_path, L"session2", L"ride_hold_pos", "0"));
    c.s2_mount_relink = narrow(read_string(ini_path, L"session2", L"mount_relink", "0"));
    c.s2_child_reannounce = narrow(read_string(ini_path, L"session2", L"child_reannounce", "0"));
    c.s2_combat_follow = narrow(read_string(ini_path, L"session2", L"combat_follow", "0"));
    // P8 session 25, the combat stream (noche/combate-retardo.md §6).
    c.s2_combat_follow_v2 = narrow(read_string(ini_path, L"session2", L"combat_follow_v2", "0"));
    c.s2_remote_interp_combat = narrow(read_string(ini_path, L"session2", L"remote_interp_combat", "0"));
    // docs/research/noche/mundo-invitado.md ("Implementado").
    c.s2_user2_world_anchor = narrow(read_string(ini_path, L"session2", L"user2_world_anchor", "0"));
    c.s2_guest_horse_probe = narrow(read_string(ini_path, L"session2", L"guest_horse_probe", "0"));
    // P8 mount ride (pendientes/p8-impl-monturas-cabalgata.md).
    c.s2_horse_follow_reverse = narrow(read_string(ini_path, L"session2", L"horse_follow_reverse", "0"));
    c.s2_remote_interp_pair = read_uint(ini_path, L"session2", L"remote_interp_pair", 0) != 0;
    c.s2_remote_interp_players = narrow(read_string(ini_path, L"session2", L"remote_interp_players", "0"));
    // P8 S1 option A, sequencers (pendientes/p8-impl-opcion-a.md).
    c.s2_observer_seq_copy = narrow(read_string(ini_path, L"session2", L"observer_seq_copy", "0"));
    c.s2_observer_seq_copy_only = narrow(read_string(ini_path, L"session2", L"observer_seq_copy_only", ""));
    c.s2_observer_seq_copy_2322 = read_uint(ini_path, L"session2", L"observer_seq_copy_2322", 1) != 0;
    c.s2_observer_seq_copy_2100 = read_uint(ini_path, L"session2", L"observer_seq_copy_2100", 0) != 0;
    c.s2_observer_sched_copy = read_uint(ini_path, L"session2", L"observer_sched_copy", 0) != 0;
    // P8 strategy B step 2 (pendientes/p8-impl-owner-fanout.md).
    c.s2_owner_fanout = narrow(read_string(ini_path, L"session2", L"owner_fanout", "0"));
    c.s2_guest_seq_route = narrow(read_string(ini_path, L"session2", L"guest_seq_route", "0"));
    c.s2_guest_seq_watch = narrow(read_string(ini_path, L"session2", L"guest_seq_watch", ""));
    c.s2_guest_seq_route_deny = narrow(read_string(ini_path, L"session2", L"guest_seq_route_deny", "8CD771B1"));
    // S44, the host's scenes on the guest (research/s25/s44-escenas-del-anfitrion.md).
    c.s2_guest_seq_foreign_player = narrow(read_string(ini_path, L"session2", L"guest_seq_foreign_player", "0"));
    c.s2_guest_seq_foreign_probe = read_uint(ini_path, L"session2", L"guest_seq_foreign_probe", 0) != 0;
    // S45, another player's scenes on this client's camera / input (research/s25/s45-escenas-ajenas.md).
    c.s2_guest_seq_foreign_present_probe =
        read_uint(ini_path, L"session2", L"guest_seq_foreign_present_probe", 0) != 0;
    c.s2_guest_seq_foreign_present = narrow(read_string(ini_path, L"session2", L"guest_seq_foreign_present", "0"));
    c.s2_guest_seq_foreign_timeline = narrow(read_string(ini_path, L"session2", L"guest_seq_foreign_timeline", "0"));
    // P8 NPC schedule stages into X (pendientes/p8-impl-horarios-x.md).
    c.s2_guest_sched_route = narrow(read_string(ini_path, L"session2", L"guest_sched_route", "0"));
    // P8 the NPCs' binding retry for those stages (pendientes/p8-impl-horarios-enlace.md).
    c.s2_guest_sched_bind = narrow(read_string(ini_path, L"session2", L"guest_sched_bind", "0"));
    // P8 guest_seq_play (pendientes/p8-impl-escenas-play.md).
    c.s2_guest_seq_play = narrow(read_string(ini_path, L"session2", L"guest_seq_play", "0"));
    c.s2_guest_seq_play_live = read_uint(ini_path, L"session2", L"guest_seq_play_live", 0) != 0;
    // P8 session 13 (pendientes/p8-impl-secuenciador-bodyanim.md).
    c.s2_guest_seq_route_2524 = narrow(read_string(ini_path, L"session2", L"guest_seq_route_2524", "0"));
    c.s2_guest_seq_route_2524_allow = narrow(read_string(ini_path, L"session2", L"guest_seq_route_2524_allow", ""));
    c.s2_guest_seq_bodyanim_diag = read_uint(ini_path, L"session2", L"guest_seq_bodyanim_diag", 0) != 0;
    // P8 session 9 (pendientes/p8-s9-cinematica.md §8).
    c.s2_guest_x_stage_veto = narrow(read_string(ini_path, L"session2", L"guest_x_stage_veto", "0"));
    c.s2_guest_x_camera_veto = narrow(read_string(ini_path, L"session2", L"guest_x_camera_veto", "probe"));
    c.s2_guest_x_ui_veto = narrow(read_string(ini_path, L"session2", L"guest_x_ui_veto", "0"));
    // P8 session 11 (pendientes/p8-impl-veto-interaccion.md).
    c.s2_guest_x_ui_veto_allow =
        narrow(read_string(ini_path, L"session2", L"guest_x_ui_veto_allow", c.s2_guest_x_ui_veto_allow));
    c.s2_guest_local_after_remote = narrow(read_string(ini_path, L"session2", L"guest_local_after_remote", "allow"));
    // P8 session 13, the shopkeepers (pendientes/p8-impl-tenderos-c1.md).
    c.s2_guest_x_interaction_stage =
        narrow(read_string(ini_path, L"session2", L"guest_x_interaction_stage", "0"));
    c.s2_shop_probe = read_uint(ini_path, L"session2", L"shop_probe", 0) != 0;
    c.s2_funcnpc_twin = narrow(read_string(ini_path, L"session2", L"funcnpc_twin", "0"));
    // P8 option U, U-0 (research/s25/mundo-escenarios-propios.md).
    c.s2_user2_stages = narrow(read_string(ini_path, L"session2", L"user2_stages", "0"));
    c.s2_user2_timer_route = narrow(read_string(ini_path, L"session2", L"user2_timer_route", "0"));
    // P8 option U, U2 (research/s25/tiendas-u2.md).
    c.s2_user2_stages_elements =
        narrow(read_string(ini_path, L"session2", L"user2_stages_elements", "schedule"));
    c.s2_user2_shop_route = narrow(read_string(ini_path, L"session2", L"user2_shop_route", "0"));
    c.s2_shop_trade_probe = read_uint(ini_path, L"session2", L"shop_trade_probe", 0) != 0;
    c.s2_user2_shop_trade_route = narrow(read_string(ini_path, L"session2", L"user2_shop_trade_route", "0"));
    c.s2_observer_hold_scene_order = narrow(read_string(ini_path, L"session2", L"observer_hold_scene_order", "0"));
    c.s2_user2_shop_trade_list = narrow(read_string(ini_path, L"session2", L"user2_shop_trade_list", "0"));
    c.s2_shop_interaction_own_delete =
        narrow(read_string(ini_path, L"session2", L"shop_interaction_own_delete", "0"));
    // P8 option U, S31 (u0-resultados-s28.md §8.17): U-e and the drain at the host's preparation.
    c.s2_user2_npc_control = narrow(read_string(ini_path, L"session2", L"user2_npc_control", "0"));
    c.s2_npc_activation = narrow(read_string(ini_path, L"session2", L"npc_activation", "0"));
    c.s2_npc_family_control = narrow(read_string(ini_path, L"session2", L"npc_family_control", "0"));
    c.s2_npc_family_types = narrow(read_string(ini_path, L"session2", L"npc_family_types", "3,6"));
    c.s2_npc_family_vehicles = narrow(read_string(ini_path, L"session2", L"npc_family_vehicles", "0"));
    c.s2_enemy_damage_probe = narrow(read_string(ini_path, L"session2", L"enemy_damage_probe", "0"));
    c.s2_door_trace = narrow(read_string(ini_path, L"session2", L"door_trace", "0"));
    c.s2_housing_trace = read_uint(ini_path, L"session2", L"housing_trace", 0) != 0;
    c.s2_housing_redraw = read_uint(ini_path, L"session2", L"housing_redraw", 0) != 0;
    c.s2_housing_gimmick_guard = read_uint(ini_path, L"session2", L"housing_gimmick_guard", 0) != 0;
    c.s2_scene_level_share = narrow(read_string(ini_path, L"session2", L"scene_level_share", "0"));
    c.s2_user2_road_control = narrow(read_string(ini_path, L"session2", L"user2_road_control", "0"));
    c.s2_user2_road_carts = narrow(read_string(ini_path, L"session2", L"user2_road_carts", "0"));
    // S35 fase A (docs/research/s25/s35-fase-a.md).
    c.s2_npc_action_evidence = narrow(read_string(ini_path, L"session2", L"npc_action_evidence", "0"));
    c.s2_npc_containment_guard = narrow(read_string(ini_path, L"session2", L"npc_containment_guard", "0"));
    c.s2_npc_degradation = narrow(read_string(ini_path, L"session2", L"npc_degradation", "0"));
    c.s2_publication_gate = narrow(read_string(ini_path, L"session2", L"publication_gate", "0"));
    c.s2_npc_no_progress_ms = read_uint(ini_path, L"session2", L"npc_no_progress_ms", c.s2_npc_no_progress_ms);
    c.s2_npc_req_grace_ms = read_uint(ini_path, L"session2", L"npc_req_grace_ms", c.s2_npc_req_grace_ms);
    c.s2_npc_guest_silence_ms = read_uint(ini_path, L"session2", L"npc_guest_silence_ms", c.s2_npc_guest_silence_ms);
    c.s2_npc_postpone_max_ms = read_uint(ini_path, L"session2", L"npc_postpone_max_ms", c.s2_npc_postpone_max_ms);
    c.s2_publication_retain_max_ms =
        read_uint(ini_path, L"session2", L"publication_retain_max_ms", c.s2_publication_retain_max_ms);
    c.s2_guest_remote_update_guard = read_uint(ini_path, L"session2", L"guest_remote_update_guard", 0) != 0;
    c.s2_user2_drain_at_host_prepare =
        narrow(read_string(ini_path, L"session2", L"user2_drain_at_host_prepare", "0"));
    c.s2_user2_fast_rearm = narrow(read_string(ini_path, L"session2", L"user2_fast_rearm", "0"));
    // P8 guest_schedule_load (pendientes/p8-impl-horarios.md).
    c.s2_guest_schedule_load = narrow(read_string(ini_path, L"session2", L"guest_schedule_load", "0"));
    c.s2_schedule_load_selfcheck = read_uint(ini_path, L"session2", L"schedule_load_selfcheck", 0) != 0;
    // P8 seq_actor_restore (pendientes/p8-impl-seq-restore.md).
    c.s2_seq_actor_restore = narrow(read_string(ini_path, L"session2", L"seq_actor_restore", "0"));
    // P8 session 25, hour and weather (research/noche/clima-hora.md §5).
    c.s2_user2_clock_push = narrow(read_string(ini_path, L"session2", L"user2_clock_push", "0"));
    c.s2_block_guest_weather = read_uint(ini_path, L"session2", L"block_guest_weather", 0) != 0;
    c.s2_clock_probe = read_uint(ini_path, L"session2", L"clock_probe", 0) != 0;
    // P8 session 25, weather in viewer mode (research/noche/clima-sincronizar.md "Implementado").
    c.s2_weather_sync = narrow(read_string(ini_path, L"session2", L"weather_sync", "0"));
    c.s2_weather_sync_radius_m = read_uint(ini_path, L"session2", L"weather_sync_radius_m", 2000);
    // P8 session 25, the guest's grabs (finishers, takedowns) on the host's client (research/s25/finisher-sigilo.md).
    c.s2_catch_seq = narrow(read_string(ini_path, L"session2", L"catch_seq", "0"));
    // P8 session 25, the other player's grappling-hook rope (research/s25/gancho-cuerda.md).
    c.s2_remote_rope = narrow(read_string(ini_path, L"session2", L"remote_rope", "0"));
    // P8 session 27, measure-first probes for the tree bend and the grappling device (research/s25/gancho-cuerda.md).
    c.s2_rope_probe = read_uint(ini_path, L"session2", L"rope_probe", 0) != 0;
    // P8 session 29, the other player's tree bend through the tunnel (research/s25/gancho-cuerda.md section 14).
    c.s2_tree_bend = narrow(read_string(ini_path, L"session2", L"tree_bend", "0"));
    // P8 session 28, the gimmicks docked to a player character (research/s25/gimmicks-dueno.md).
    c.s2_docked_gimmicks = narrow(read_string(ini_path, L"session2", L"docked_gimmicks", "0"));
    // P8 session 29, the same for the other player's character (research/s25/gimmicks-dueno.md section 8).
    c.s2_docked_gimmicks_other = narrow(read_string(ini_path, L"session2", L"docked_gimmicks_other", "0"));
    c.s2_guest_gimmick_interact = narrow(read_string(ini_path, L"session2", L"guest_gimmick_interact", "0"));
    c.s2_guest_gimmick_interact_events =
        narrow(read_string(ini_path, L"session2", L"guest_gimmick_interact_events", ""));
    c.s2_interact_gate = narrow(read_string(ini_path, L"session2", L"interact_gate", "0"));
    c.s2_interact_gate_errors = narrow(read_string(ini_path, L"session2", L"interact_gate_errors", ""));
    c.s2_interact_gate_pass = narrow(read_string(ini_path, L"session2", L"interact_gate_pass", "3"));
    c.s2_interact_gate_types = narrow(read_string(ini_path, L"session2", L"interact_gate_types", "7"));
    c.s2_vehicle_follow = narrow(read_string(ini_path, L"session2", L"vehicle_follow", "0"));
    c.s2_vehicle_follow_delay_ms = read_uint(ini_path, L"session2", L"vehicle_follow_delay_ms", 300);
    c.s2_store_gate = narrow(read_string(ini_path, L"session2", L"store_gate", "0"));
    c.s2_guest_shop_branch = narrow(read_string(ini_path, L"session2", L"guest_shop_branch", "0"));
    c.s2_shop_ui_trace = narrow(read_string(ini_path, L"session2", L"shop_ui_trace", "0"));
    c.s2_guest_shop_window = narrow(read_string(ini_path, L"session2", L"guest_shop_window", "0"));
    c.s2_housing_share = narrow(read_string(ini_path, L"session2", L"housing_share", "0"));
    c.s2_housing_share_live_ops = narrow(read_string(ini_path, L"session2", L"housing_share_live_ops", ""));
    c.s2_housing_share_edits = read_uint(ini_path, L"session2", L"housing_share_edits", 0) != 0;
    c.s2_housing_share_guest_spawn = read_uint(ini_path, L"session2", L"housing_share_guest_spawn", 0) != 0;
    c.s2_housing_share_rekey = narrow(read_string(ini_path, L"session2", L"housing_share_rekey", "0"));
    c.s2_housing_share_drop_gimmicks = narrow(read_string(ini_path, L"session2", L"housing_share_drop_gimmicks", "0"));
    c.s2_housing_share_level_states = read_uint(ini_path, L"session2", L"housing_share_level_states", 0);
    // P8 session 28, the duplicated gimmick projectiles 2779 (research/s25/gimmicks-dueno.md section 7).
    c.s2_gimmick_event_dedup = narrow(read_string(ini_path, L"session2", L"gimmick_event_dedup", "0"));
    // P8 session 25, the guest's own save, phase A (noche/progreso-invitado.md).
    c.s2_guest_own_save = narrow(read_string(ini_path, L"session2", L"guest_own_save", "0"));
    {
        // A path (no comment on its line): a longer buffer than read_string's; spaces, quotes and a trailing
        // separator dropped.
        wchar_t buf[1024];
        GetPrivateProfileStringW(L"session2", L"guest_own_save_debug_dir", L"", buf, 1024, ini_path.c_str());
        std::wstring v = buf;
        while (!v.empty() && (v.back() == L' ' || v.back() == L'\t' || v.back() == L'"' || v.back() == L'\\')) {
            v.pop_back();
        }
        while (!v.empty() && (v.front() == L' ' || v.front() == L'\t' || v.front() == L'"')) v.erase(0, 1);
        c.s2_guest_own_save_debug_dir = v;
    }
    // P8 session 35, phase E (session2/host_save_export.h): the host's sandbox exported before each rebuild.
    c.s2_host_save = narrow(read_string(ini_path, L"session2", L"host_save", "sandbox"));
    {
        // A path, read as guest_own_save_debug_dir is, except that a drive root keeps its separator ("C:\" is not
        // "C:", the current folder of that drive; review L13).
        wchar_t buf[1024];
        GetPrivateProfileStringW(L"session2", L"host_save_dir", L"", buf, 1024, ini_path.c_str());
        std::wstring v = buf;
        const auto drive_root = [&] { return v.size() == 3 && v[1] == L':' && (v[2] == L'\\' || v[2] == L'/'); };
        while (!v.empty() && (v.back() == L' ' || v.back() == L'\t' || v.back() == L'"' ||
                              ((v.back() == L'\\' || v.back() == L'/') && !drive_root()))) {
            v.pop_back();
        }
        while (!v.empty() && (v.front() == L' ' || v.front() == L'\t' || v.front() == L'"')) v.erase(0, 1);
        c.s2_host_save_dir = v;
    }
    c.s2_host_save_keep = read_uint(ini_path, L"session2", L"host_save_keep", c.s2_host_save_keep);
    c.s2_mirror_delay_ms = std::clamp(read_uint(ini_path, L"session2", L"mirror_delay_ms", 1000), 100u, 10000u);
    {
        const std::wstring v = read_string(ini_path, L"session2", L"account", "1");
        c.s2_account = v.empty() ? 1 : _wcstoui64(v.c_str(), nullptr, 0);
        // All ones (also "-1" or an overflow) is the one value that matches the
        // host's user in the relogin branch (0x2C17B88: UserLogin writes -1 to
        // component+0x78) and would move it to session 2, closing session 1
        // (docs/research/data/b2-login-pasos.md). Never used.
        if (c.s2_account == ~0ull) c.s2_account = 1;
    }
    {
        // Decimal or 0x-hex; "-1" diagnostic.
        const std::wstring v = read_string(ini_path, L"coop", L"minimap_icon", "");
        if (!v.empty()) c.coop_minimap_icon = static_cast<int>(std::wcstol(v.c_str(), nullptr, 0));
    }
    g_loaded = c;
    return c;
}

const Config& loaded_config() { return g_loaded; }

}  // namespace cdmp
