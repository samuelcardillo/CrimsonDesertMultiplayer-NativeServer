#include "mod/mod.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cmath>
#include <exception>
#include <optional>
#include <memory>
#include <string>
#include <vector>

#include "build_id.h"
#include "common/client_session.h"
#include "common/clock.h"
#include "common/loop_health.h"
#include "common/transport.h"
#include "common/udp.h"
#include "mod/config.h"
#include "mod/game/game_errors.h"
#include "mod/game/offsets.h"
#include "mod/game/build_profile.h"
#include "mod/game/player_reader.h"
#include "mod/game/safe_memory.h"
#include "mod/bg_speed.h"
#include "mod/log.h"
#include "mod/role.h"
#include "mod/net/coop.h"
#include "mod/net/aggro_test.h"
#include "mod/net/attack_probe.h"
#include "mod/net/enemy_relay.h"
#include "mod/net/horse_diag.h"
#include "mod/net/local_capture.h"
#include "mod/net/guest_hits.h"
#include "mod/net/piece4_test.h"
#include "mod/net/player_hits.h"
#include "mod/net/puppet_minimap.h"
#include "mod/net/remote_puppet.h"
#include "mod/net/steam_transport.h"
#include "mod/net/troc_sniffer.h"
#include "mod/session2/catch_seq.h"
#include "mod/session2/remote_rope.h"
#include "mod/session2/rope_probe.h"
#include "mod/session2/tree_bend.h"
#include "mod/session2/docked_gimmicks.h"
#include "mod/session2/interact_gate.h"
#include "mod/session2/vehicle_follow.h"
#include "mod/session2/guest_shop_window.h"
#include "mod/session2/shop_ui_trace.h"
#include "mod/session2/store_gate.h"
#include "mod/session2/guest_shop_branch.h"
#include "mod/session2/clock_push.h"
#include "mod/session2/fast_travel.h"
#include "mod/session2/travel_probe.h"
#include "mod/session2/freeze_watchdog.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_diag_worker.h"
#include "mod/session2/guest_reload_wait.h"
#include "mod/session2/guest_save_guest.h"
#include "mod/session2/guest_save_tunnel.h"
#include "mod/session2/guest_sched_load.h"
#include "mod/session2/guest_s3.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/npc_probe_client.h"
#include "mod/session2/door_trace.h"
#include "mod/session2/housing_redraw.h"
#include "mod/session2/housing_trace.h"

#include "mod/session2/server.h"
#include "mod/session2/session2.h"
#include "mod/session2/remote_motion.h"
#include "mod/session2/remote_interp.h"
#include "mod/session2/save_hooks.h"
#include "mod/session2/mount_sync.h"
#include "mod/session2/ride_filter.h"
#include "mod/session2/achievement_guard.h"
#include "mod/session2/field_leave_guard.h"
#include "mod/session2/focus_follow.h"
#include "mod/session2/manager_probe.h"
#include "mod/session2/pivot_guard.h"
#include "mod/session2/ride_null_guard.h"
#include "mod/session2/seq_marker.h"
#include "mod/session2/ui_pause.h"
#include "mod/session2/user2_funnels.h"
#include "mod/session2/weather_sync.h"
#include "mod/render/dx12_hook.h"
#include "mod/render/hud.h"

#pragma comment(lib, "version.lib")

namespace cdmp {
namespace {

// The commit this build comes from (build_id.h): both players must match.
constexpr uint32_t kModBuild = CDMP_BUILD_ID;

HMODULE g_self = nullptr;
HANDLE g_thread = nullptr;
HANDLE g_stop = nullptr;
HANDLE g_late_thread = nullptr;

bool stop_requested(DWORD wait_ms = 0) {
    return WaitForSingleObject(g_stop, wait_ms) == WAIT_OBJECT_0;
}

std::wstring module_path(HMODULE module) {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
        if (n == 0) return {};
        if (n < path.size()) {
            path.resize(n);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

std::wstring dir_of(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring{} : path.substr(0, slash + 1);
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

std::string file_version(const std::wstring& path) {
    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return "unknown";
    std::vector<uint8_t> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return "unknown";
    VS_FIXEDFILEINFO* info = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &len) || !info)
        return "unknown";
    return std::format("{}.{}.{}.{}", HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS),
                       HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS));
}

// Facts that identify the exact game build. Every offset/signature we find
// later is only valid for one build, so the log must always say which one.
bool log_process_info() {
    const std::wstring exe = module_path(nullptr);
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

    log::info("Host process: {} (PID {})", narrow(exe), GetCurrentProcessId());
    log::info("Host version: {}  image base: 0x{:X}  image size: 0x{:X}  PE timestamp: 0x{:08X}",
              file_version(exe), base, nt->OptionalHeader.SizeOfImage, nt->FileHeader.TimeDateStamp);

    const bool in_game = exe.ends_with(L"\\CrimsonDesert.exe");
    log::info("{}", in_game ? "Running inside CrimsonDesert.exe"
                            : "Not running inside the game (test host); game features stay off");

    if (HMODULE winmm = GetModuleHandleW(L"winmm.dll")) {
        log::info("winmm.dll loaded from: {}", narrow(module_path(winmm)));
    }
    return in_game;
}

// CDMP_ROLE (role_logic.h): the role, and whether this process is the first of it. Read by the worker before the log
// opens (it names the log).
struct RoleStart {
    role::Role role = role::Role::None;
    std::wstring raw;       // the variable as given (empty when absent)
    bool valid = true;      // false: a value that is neither host nor guest
    bool extra = false;     // another process of this role holds the role's mutex
    bool mutex_ok = true;
};

RoleStart read_role() {
    RoleStart rs;
    wchar_t buf[64] = {};
    const DWORD n = GetEnvironmentVariableW(role::kEnvVar, buf, 64);
    if (n == 0) return rs;
    rs.raw = n < 64 ? std::wstring(buf, n) : std::wstring(L"(more than 63 characters)");
    const auto parsed = n < 64 ? role::parse(rs.raw) : std::nullopt;
    if (!parsed) {
        rs.valid = false;
        return rs;
    }
    rs.role = *parsed;
    if (rs.role == role::Role::None) return rs;
    // Never closed: held until the process ends (the system releases it then, also after a crash).
    const HANDLE m = CreateMutexW(nullptr, FALSE, role::mutex_name(rs.role).c_str());
    if (!m) {
        rs.mutex_ok = false;
    } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
        rs.extra = true;
    }
    return rs;
}

// With a role: who started this process (the launcher, Steam, or another CrimsonDesert.exe) and its command line,
// to tell the game's short-lived second process apart in the logs.
void log_parent() {
    DWORD parent = 0;
    std::wstring parent_exe;
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{sizeof pe};
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            if (pe.th32ProcessID == GetCurrentProcessId()) parent = pe.th32ParentProcessID;
        }
        for (BOOL ok = Process32FirstW(snap, &pe); parent && ok; ok = Process32NextW(snap, &pe)) {
            if (pe.th32ProcessID == parent) parent_exe = pe.szExeFile;
        }
        CloseHandle(snap);
    }
    log::info("Role: parent PID {} ({}) | command line: {}", parent,
              parent_exe.empty() ? "not running any more" : narrow(parent_exe), narrow(GetCommandLineW()));
}

// Outside the game (test host) there is no player to read, so we walk a 2 m
// circle instead, flagged as synthetic.
proto::PlayerState synthetic_state(uint32_t t_ms) {
    const float angle = static_cast<float>(t_ms % 8000) / 8000.0f * 6.2831853f;
    proto::PlayerState s;
    s.pos = {2.0f * std::cos(angle), 0.0f, 2.0f * std::sin(angle)};
    s.rot = {0.0f, std::sin(angle * 0.5f), 0.0f, std::cos(angle * 0.5f)};
    s.flags = proto::kStateSynthetic;
    return s;
}

// Where the local player's state comes from: game memory inside the game,
// the synthetic circle in the test host.
class LocalSource {
public:
    explicit LocalSource(bool in_game) : in_game_(in_game) {
        if (!in_game_) return;
        reader_.set_follow_focus(true);  // the panel and the other player's marker follow a character switch
        if (reader_.init()) {
            // 3576's and 3663's profiles are static evidence only so far (build_profile.h): said so in the log.
            const bool static_only =
                game::current_build() == game::Build::v3576 || game::current_build() == game::Build::v3663;
            log::info("Game reader enabled (build {} {})", game::reader_profile()->version,
                      static_only ? "offsets from static analysis, not yet run" : "verified offsets");
        } else {
            log::warn("Game reader DISABLED: {}. Only networking will run.",
                      reader_.last_failure());
        }
    }

    // nullopt while the player is not in the world: nothing is sent then.
    std::optional<proto::PlayerState> sample(uint32_t now) {
        if (!in_game_) return synthetic_state(now);

        last_ = reader_.read();
        // Log only transitions, not every failed 20 Hz read.
        const std::string status = last_ ? "in world" : reader_.last_failure();
        if (status != status_) {
            log::info("Local player: {}", status);
            status_ = status;
        }
        if (!last_) return std::nullopt;

        proto::PlayerState s;
        s.pos = last_->position;
        s.rot = last_->rotation;
        s.health = last_->health;
        s.health_max = last_->health_max;
        // Ships (session2/vehicle_follow.h): this character's key and what it stands on; zeros when the module is off.
        float anchor_pos[3] = {}, anchor_rot[4] = {0, 0, 0, 1};
        if (session2::vehicle_follow_own_anchor(&s.self_key, &s.anchor, anchor_pos, anchor_rot)) {
            s.anchor_pos = {anchor_pos[0], anchor_pos[1], anchor_pos[2]};
            s.anchor_rot = {anchor_rot[0], anchor_rot[1], anchor_rot[2], anchor_rot[3]};
        }
        return s;
    }

    const std::optional<game::PlayerSnapshot>& snapshot() const { return last_; }
    bool in_game() const { return in_game_; }
    const std::string& status() const { return status_; }

    std::string describe() const {
        if (!in_game_) return "synthetic";
        if (!last_) return "unavailable (" + status_ + ")";
        const auto& p = *last_;
        return std::format("pos ({:.2f}, {:.2f}, {:.2f}) rot ({:.3f}, {:.3f}, {:.3f}, {:.3f}) "
                           "hp {:.1f}/{:.1f} stamina {:.1f}/{:.1f} | check vs game global {:.2f} m",
                           p.position.x, p.position.y, p.position.z, p.rotation.x, p.rotation.y,
                           p.rotation.z, p.rotation.w, p.health, p.health_max, p.stamina,
                           p.stamina_max, p.static_pos_error);
    }

private:
    bool in_game_;
    game::PlayerReader reader_;
    std::optional<game::PlayerSnapshot> last_;
    std::string status_;
};

void run_network(const Config& cfg, LocalSource& local) {
    if (!net::startup()) {
        log::error("Winsock startup failed");
        return;
    }

    // A guest knows whom to talk to; a host learns it from the first Hello.
    const bool host = cfg.net_role_host;
    std::unique_ptr<net::Transport> transport;
    net::SteamTransport* steam = nullptr;
    std::optional<net::PeerAddr> peer;
    if (cfg.net_transport_steam) {
        if (!local.in_game()) {
            log::error("The Steam transport only works inside the game");
            net::cleanup();
            return;
        }
        net::SteamSendLimits limits;
        limits.rate_min = static_cast<int32_t>(cfg.steam_send_rate_min_kb * 1024);
        limits.rate_max = static_cast<int32_t>(cfg.steam_send_rate_max_kb * 1024);
        limits.buffer = static_cast<int32_t>(cfg.steam_send_buffer_kb * 1024);
        limits.recv_buffer = static_cast<int32_t>(cfg.steam_recv_buffer_kb * 1024);
        limits.recv_messages = static_cast<int32_t>(cfg.steam_recv_buffer_messages);
        auto st = std::make_unique<net::SteamTransport>(cfg.steam_channel, host, cfg.steam_peer_id, limits);
        steam = st.get();
        transport = std::move(st);
        if (!host && cfg.steam_peer_id) {
            peer = net::PeerAddr::steam(cfg.steam_peer_id);
            steam->set_peer(cfg.steam_peer_id);
        }
    } else {
        auto udp = std::make_unique<net::UdpTransport>();
        bool ok = false;
        if (host) {
            ok = udp->open(cfg.peer_port, cfg.host_loopback_only);
        } else if (auto ep = net::Endpoint::resolve(cfg.peer_host, cfg.peer_port)) {
            peer = net::PeerAddr::udp(*ep);
            ok = udp->open(0, ep->is_loopback());
        } else {
            log::error("Cannot resolve peer host '{}'", cfg.peer_host);
            net::cleanup();
            return;
        }
        if (!ok) {
            log::error("Cannot open UDP socket: {}", net::UdpSocket::last_error());
            net::cleanup();
            return;
        }
        transport = std::move(udp);
    }
    log::info("Network: {} as {}; peer {}", transport->status(), host ? "host" : "guest",
              peer ? peer->str() : (host ? "= whoever connects" : "= the only friend playing"));

    ClientSession session(
        cfg.player_name, kModBuild,
        [&](const std::vector<uint8_t>& bytes) {
            if (peer) transport->send(*peer, bytes);
        },
        [](const std::string& text) { log::info("Session: {}", text); },
        host ? ClientSession::Role::Responder : ClientSession::Role::Initiator);
    if (steam) {
        // Backpressure: reliable fragments wait while Steam's queue is full.
        // With that pacing a larger window keeps the faster send rate busy
        // (512 x 1100 B in flight ~ 4 MB/s at a 130 ms RTT). UDP keeps 128
        // and no probe, as before.
        session.set_congestion_probe([&transport] { return transport->congested(); });
        session.set_reliable_window(512);
    }
    bool was_connected = false;
    uint64_t last_channel_state = 0;  // session.stats().remote_states at the last divergence_probe publication
    uint32_t last_friend_scan = 0;
    size_t last_friend_count = SIZE_MAX;

    std::unique_ptr<net::CoopLink> coop;
    if (cfg.coop_enabled && local.in_game()) {
        coop = std::make_unique<net::CoopLink>(session, cfg.coop_delay_ms, cfg.coop_offset_m,
                                               cfg.coop_map_pin);
    }

    // Option D: the host's end of the Troc tunnel, once [session2] is up; or,
    // on the guest's PC (P8), the client's end.
    std::unique_ptr<troc::TrocLink> s2_link;
    std::unique_ptr<troc::TrocLink> s2_guest_link;

    const uint32_t state_interval = 1000 / cfg.send_rate_hz;
    uint32_t last_state = 0;
    uint32_t last_report = now_ms();
    // Ctrl+F12 writes a numbered mark in the log: both players press it at the
    // same moment ("now!") so their logs can be lined up afterwards.
    bool mark_was_down = false;
    int marks = 0;
    uint64_t guest_role_reports = 0;
    std::vector<uint8_t> buf(proto::kMaxPacketSize);
    // How long each turn of this loop takes and how long Steam goes unread
    // (p8-hilo-red.md): on the 5 s line, plus a warning for any single turn
    // above 250 ms with the time of each of its phases.
    using Phase = LoopHealth::Phase;
    LoopHealth health;
    uint64_t slow_lines = 0;
    constexpr uint64_t kSlowLines = 200;

    while (!stop_requested()) {
        health.begin(now_us());
        transport->poll(now_ms());

        // Steam guest without a configured host: the only friend playing.
        if (steam && !host && !peer && steam->ready() && now_ms() - last_friend_scan >= 2000) {
            last_friend_scan = now_ms();
            const auto playing = steam->friends_playing();
            if (playing.size() == 1) {
                peer = net::PeerAddr::steam(playing[0].id);
                steam->set_peer(playing[0].id);
                log::info("Network: connecting to '{}' (the only friend playing)", playing[0].name);
            } else if (playing.size() != last_friend_count) {
                last_friend_count = playing.size();
                log::info("Network: {} friends playing; put the host's SteamID64 in [steam] "
                          "peer_steamid (listed above when Steam got ready)",
                          playing.size());
            }
        }
        health.mark(Phase::Poll, now_us());
        // P8 S25 phase B (guest_save_tunnel.h): both ends' SteamID64 for the guest's own save (0 = UDP / not known).
        session2::guest_save_set_net_ids(steam ? steam->own_id() : 0,
                                         peer && peer->kind == net::PeerAddr::Kind::Steam ? peer->value : 0);

        // Everything that is waiting, not one datagram per loop: with ~100
        // events/s (a busy city) handling one per loop built a backlog of
        // seconds in the first real test (RTT up to 2.9 s).
        net::PeerAddr from;
        int timeout = 5;
        for (int handled = 0; handled < 512; ++handled) {
            const uint64_t pump_start = now_us();
            auto n = transport->recv(from, buf, timeout);
            health.pump(pump_start, now_us(), n ? 1 : 0);
            if (!n) break;
            timeout = 0;
            if (host && !peer) {
                // Lock onto the first player who greets us.
                auto packet = proto::decode({buf.data(), *n});
                if (packet && std::holds_alternative<proto::Hello>(packet->body)) {
                    peer = from;
                    if (steam) steam->set_peer(from.value);
                    log::info("Network: player at {} is joining", from.str());
                }
            }
            if (peer && from == *peer) session.on_datagram({buf.data(), *n}, now_ms());
        }
        health.mark(Phase::Recv, now_us());

        const uint32_t now = now_ms();
        session.tick(now);
        // P8 divergence_probe (pendientes/p8-impl-log-async.md §3): each new position of the other
        // player from this channel (the HUD's), for remote_motion's thread. Atomics and a short lock.
        if (const auto& rs = session.remote_state(); rs && session.stats().remote_states != last_channel_state) {
            last_channel_state = session.stats().remote_states;
            session2::remote_motion_channel_position(rs->pos.x, rs->pos.y, rs->pos.z);
            // Ships: what the other player's character stands on (vehicle_follow.h); off or unknown key: nothing.
            const float anchor_pos[3] = {rs->anchor_pos.x, rs->anchor_pos.y, rs->anchor_pos.z};
            const float anchor_rot[4] = {rs->anchor_rot.x, rs->anchor_rot.y, rs->anchor_rot.z, rs->anchor_rot.w};
            session2::vehicle_follow_on_peer_state(rs->self_key, rs->anchor, anchor_pos, anchor_rot);
        }
        const bool connected = session.state() == ClientSession::State::Connected;
        if (host && was_connected && !connected && peer) {
            log::info("Network: {} left; waiting for a player", peer->str());
            peer.reset();
        }
        was_connected = connected;
        health.mark(Phase::Session, now_us());
        if (!s2_link && !coop && session2::tunnel_wanted()) {
            s2_link = std::make_unique<troc::TrocLink>(
                session, troc::Dir::ToGuestClient, troc::Dir::ToHostServer,
                [&session](std::vector<uint8_t>&& p, uint32_t at) {
                    session2::tunnel_on_packet(std::move(p), session.epoch(), at);
                });
            s2_link->require_identity(game::pe_identity().timestamp, native_opcode::kMappingFingerprint);
            // p8-tunel-rendimiento.md: compressed batches to a guest that says it decodes them.
            s2_link->set_compress(cfg.s2_tunnel_compress);
            log::info("Session2: Troc tunnel open on the network link (the guest is whoever connects){}",
                      cfg.s2_tunnel_compress ? "; tunnel_compress=1: batches compressed once the guest says it "
                                               "decodes them"
                                             : "");
        }
        if (s2_link) session2::tunnel_tick(*s2_link, now);
        // P8 S25 weather (weather_sync.h): the host's newest weather sample as control state 12 (weather_sync=1 and a
        // guest that announced caps 0x04; nothing otherwise). Flushed by the next tunnel_tick.
        if (s2_link) session2::weather_sync_host_tick(*s2_link, now);
        health.mark(Phase::HostTunnel, now_us());
        if (!s2_guest_link && !coop && session2::guest_active()) {
            s2_guest_link = std::make_unique<troc::TrocLink>(
                session, troc::Dir::ToHostServer, troc::Dir::ToGuestClient,
                [](std::vector<uint8_t>&& p, uint32_t) { session2::guest_deliver(std::move(p)); });
            s2_guest_link->require_identity(game::pe_identity().timestamp, native_opcode::kMappingFingerprint);
            // p8-tunel-rendimiento.md: tell the host this end decodes compressed batches; P8 S25 phase B: and that it
            // speaks the own-save states 6-11 (guest_own_save=probe or 1).
            // P8 re-entry (rejoin_logic.h): and that it speaks states 13-14 (rejoin=probe or 1).
            const uint8_t caps = static_cast<uint8_t>((cfg.s2_tunnel_compress ? troc::kCapsCompressed : 0) |
                                                      session2::guest_save_guest_caps() |
                                                      session2::guest_rejoin_caps());
            s2_guest_link->set_announce_flags(caps);
            log::info("Session2 guest: Troc tunnel open on the network link{}{}",
                      cfg.s2_tunnel_compress ? "; tunnel_compress=1: the host may send compressed batches" : "",
                      caps & troc::kCapsGuestSave ? "; guest_own_save: caps 0x02 (states 6-11)" : "");
        }
        // P8 S25 weather (weather_sync.h): with weather_sync=1 this end also announces caps 0x04 (state 12), before
        // its first packet of a connection (TrocLink sends the flags then).
        if (const uint8_t wcaps = session2::weather_sync_guest_caps();
            s2_guest_link && wcaps && !(s2_guest_link->announce_flags() & wcaps)) {
            s2_guest_link->set_announce_flags(static_cast<uint8_t>(s2_guest_link->announce_flags() | wcaps));
            log::info("Session2 guest: weather_sync=1: the tunnel also announces caps 0x{:02X} (the host's weather, "
                      "state 12)",
                      wcaps);
        }
        if (s2_guest_link) {
            // A link broken by a reconnection is fresh again for the next client
            // connection, as long as no remote one is going on (that one is lost).
            if (s2_guest_link->broken() && !session2::guest_remote()) s2_guest_link->reset();
            session2::guest_set_tunnel_up(s2_guest_link->connected() && !s2_guest_link->broken());
            // P8 S25 phase B: the own-save upload belongs to one connection (a new session epoch gets it again, once
            // the host speaks on it; never in the iteration that first sees the epoch: TrocLink::tick resets then).
            session2::guest_save_guest_tunnel(s2_guest_link->connected() && !s2_guest_link->broken(),
                                              s2_guest_link->session_epoch());
            // P8 S25 phase B review (item 1): the own-save upload is paced by the link's backlog, and a packet the
            // link refuses (its 16 MB backlog: the link is then broken and resets) is counted, not ignored.
            size_t refused = 0;
            for (auto& p : session2::guest_take_outgoing(s2_guest_link->backlog_bytes())) {
                if (!s2_guest_link->push(p)) ++refused;
            }
            session2::guest_save_guest_push_refused(refused);
            s2_guest_link->tick(now);
        }
        health.mark(Phase::GuestTunnel, now_us());
        if (coop) {
            std::optional<proto::Vec3> pos;
            proto::Quat rot;
            if (local.snapshot()) {
                pos = local.snapshot()->position;
                rot = local.snapshot()->rotation;
            }
            coop->update(pos, rot, now);
        }
        health.mark(Phase::Coop, now_us());

        if (now - last_state >= state_interval) {
            last_state = now;
            if (auto state = local.sample(now)) session.send_local_state(*state, now);

            render::HudData hud;
            hud.host = host;
            hud.host_search_hint = steam && !host && !peer;
            hud.connected = session.state() == ClientSession::State::Connected;
            hud.peer_name = session.peer_name();
            hud.rtt_ms = session.stats().rtt_ms;
            hud.local = local.snapshot();
            hud.local_status = local.status();
            hud.remote = session.remote_state();
            hud.peer_problem = session.peer_problem();
            // In co-op, put the marker on the character actually drawn (it
            // plays the network state `delay` ms later).
            if (coop && hud.remote) {
                if (auto pos = net::puppet_position()) hud.remote->pos = *pos;
            }
            // Option D (S25, docs/research/s25/invisibles.md): the marker only while both games play the host's world.
            if (s2_link) {
                hud.same_world = session2::server_user2_in_world();
            } else if (s2_guest_link) {
                hud.same_world = session2::guest_remote();
                hud.s2_guest = true;
                hud.alone_after_remote = session2::guest_local_after_remote();
                hud.host_ready = session2::guest_host_ready();
                // P8 re-entry: what the re-entry is doing (or why it cannot), while not playing on the host. The text
                // follows the re-entry's phase alone (empty while playing): after the goodbye the connection still
                // reads as remote and live until the client connects again, so S28 never showed the grant.
                hud.rejoin_text = session2::guest_rejoin_hud();
            }
            // P8 S26: a controller that publishes no mount (this PC's or the other's), on the panel.
            hud.mount_problem = session2::mount_sync_hud_problem();
            render::hud_update(std::move(hud));
        }
        health.mark(Phase::State, now_us());

        const bool mark_down = (GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(VK_F12) & 0x8000);
        if (mark_down && !mark_was_down) log::warn("=== MARK {} (Ctrl+F12) ===", ++marks);
        mark_was_down = mark_down;
        if (now - last_report >= 5000) {
            last_report = now;
            const auto& st = session.stats();
            const char* state =
                session.state() == ClientSession::State::Connected ? "connected" : "connecting";
            std::string remote = "none";
            if (const auto& rs = session.remote_state()) {
                remote = std::format("({:.2f}, {:.2f}, {:.2f}) hp {:.1f}", rs->pos.x, rs->pos.y,
                                     rs->pos.z, rs->health);
            }
            log::info("Net: {} | sent {} recv {} rejected {} | rtt {:.1f} ms | remote states {} | "
                      "last remote {} | reliable pending {} refused {} resent {} held back {} | unknown kinds {} | {} | {}",
                      state, st.sent, st.received, st.rejected, st.rtt_ms, st.remote_states, remote,
                      session.reliable_pending(), session.reliable_refused(), session.reliable_resent(),
                      session.reliable_held_back(), st.unknown_kinds, transport->status(),
                      health.window_text(health.take_window(now_us())));
            if (!session.peer_problem().empty()) log::warn("Net: {}", session.peer_problem());
            log::info("Local: {}", local.describe());
            // The asynchronous log itself (p8-impl-log-async.md): drops and the slowest write.
            log::info("Log: {}", log::describe());
            if (coop) log::info("{}", coop->describe());
            if (session2::installed()) log::info("{}", session2::describe());
            // CDMP_ROLE=guest: where its saves went, once a minute.
            if (session2::save_hooks_guest_role() && ++guest_role_reports % 12 == 1) {
                log::info("Role guest: save redirect {}", session2::save_hooks_redirect_describe());
            }
            if (s2_link) log::info("Session2: {}", s2_link->describe());
            // P8 guest diagnostics (the loading state's wait list, the restore
            // lines, the S3 history, the "Session2 guest:" status line): on
            // their own low-priority thread (guest_diag_worker.h); this is a
            // SetEvent and never waits. They took 4-8 s here per report in
            // session 5 and the host timed the guest out (p8-hilo-red.md).
            session2::guest_diag_kick();
            if (s2_guest_link) log::info("Session2 guest: {}", s2_guest_link->describe());
            if (cfg.overlay_enabled) {
                const auto ov = render::status();
                log::info("Overlay: installed {} disabled {} | presents {} drawn {} | queue {}{}",
                          ov.installed, ov.disabled, ov.presents, ov.frames_drawn,
                          ov.queue_source.empty() ? "-" : ov.queue_source,
                          ov.last_error.empty() ? "" : " | error: " + ov.last_error);
            }
        }
        health.mark(Phase::Report, now_us());
        if (auto slow = health.end(now_us())) {
            if (slow_lines++ < kSlowLines) {
                log::warn("Net: {}{}", health.slow_text(*slow),
                          slow_lines == kSlowLines ? " (the last such line; the 5 s line keeps counting them)" : "");
            }
        }
    }

    coop.reset();
    s2_link.reset();
    s2_guest_link.reset();
    session.disconnect(now_ms());
    transport.reset();
    net::cleanup();
    log::info("Network stopped");
}

// The game's own top-level window, once it is visible and reasonably large.
bool game_window_visible() {
    struct Ctx {
        DWORD pid;
        bool found;
    } ctx{GetCurrentProcessId(), false};
    EnumWindows(
        [](HWND hwnd, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<Ctx*>(lp);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            RECT r{};
            if (pid == c->pid && IsWindowVisible(hwnd) && GetClientRect(hwnd, &r) &&
                r.right - r.left >= 640 && r.bottom - r.top >= 360) {
                c->found = true;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

struct LateInit {
    bool in_game;
    bool overlay;
    bool sniffer;
    bool clone_hotkeys;
    uint32_t mirror_delay_ms;
    float mirror_offset_m;
    bool coop;
    float coop_offset_m;
    bool coop_horse;
    bool coop_equip;
    bool coop_damage;
    bool combat_tests;
    bool record;
    std::wstring dir;
    int minimap_icon;
    bool minimap_cycle;
    bool aggro_test;
    bool enemies_target_copy;
    bool enemy_relay;
    bool piece4_test;
    bool guest_hits, guest_hit_stagger, player_hit_react, player_hit_lethal;
    bool attack_probe;
    int copy_attack_slots;
    uint8_t pin_shape, pin_colour;
    bool session2 = false;  // option D ([session2])
    session2::Options session2_opt{};
};

// Dev: Ctrl+F9 / Ctrl+Shift+F9 walk the game's icon table for the other
// player's minimap icon. The game only draws a changed icon if it creates it
// anew (live test: changing it in place made it vanish), so each step
// reloads the copy.
void minimap_cycle_loop() {
    log::info("Minimap: Ctrl+F9 / Ctrl+Shift+F9 change the other player's icon");
    bool was_down = false;
    while (!stop_requested(50)) {
        const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool down = ctrl && (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
        if (down && !was_down) {
            const bool back = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            int at = net::puppet_minimap_offset();
            if (at < 0xEA || at > 0x16C) at = game::build_2976::kMinimapIconPlayerArrow;
            else at += back ? -2 : 2;
            if (at > 0x16C) at = 0xEA;
            if (at < 0xEA) at = 0x16C;
            net::puppet_minimap_set_offset(at);
            net::puppet_request_reload();
        }
        was_down = down;
        net::puppet_minimap_tick();
    }
}

// Combat injection tests (dev, combate-coop.md §6). They post client->server
// packets into the game's own server, next to the nearest NPC:
//   Ctrl+F6  T2: VaryStatByAccInputReq(npc, HP, -5)      does HP drop? death? loot?
//   Ctrl+F7  T3: AttackByCollisionReq(npc, player, ...)  native hit reaction/damage?
// Results show in cdmp_packets.log (VaryHPAck, AttackTargetAck, NotifyHandleDeadAck...).
void combat_test_loop() {
    log::warn("Combat tests ON: Ctrl+F6 = T2 (HP -5 on nearest NPC), Ctrl+F7 = T3 (collision hit). "
              "These WRITE to the game: do not save afterwards");
    game::PlayerReader reader;
    reader.init();
    bool f6_was = false, f7_was = false;
    auto packet = [](uint16_t op, const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> p(5 + payload.size());
        const uint16_t len = static_cast<uint16_t>(payload.size());
        std::memcpy(p.data(), &op, 2);
        p[2] = 0;  // slot 0, as in every captured Req
        std::memcpy(p.data() + 3, &len, 2);
        std::memcpy(p.data() + 5, payload.data(), payload.size());
        return p;
    };
    while (!stop_requested(50)) {
        const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool f6 = ctrl && (GetAsyncKeyState(VK_F6) & 0x8000) != 0;
        const bool f7 = ctrl && (GetAsyncKeyState(VK_F7) & 0x8000) != 0;
        if ((f6 && !f6_was) || (f7 && !f7_was)) {
            auto me = reader.read();
            auto npc = me ? net::capture_nearest_actor(me->position, 15.0f) : std::nullopt;
            // Prefer the enemy the player just hit (certainly has hit points).
            if (npc && net::capture_last_attack_target() && npc->key != net::capture_last_attack_target()) {
                log::info("Combat test: nearest enemy 0x{:08X} is not the last one you hit (0x{:08X}); "
                          "using the nearest",
                          npc->key, net::capture_last_attack_target());
            }
            if (!npc) {
                log::warn("Combat test: no enemy with hit points moving within 15 m (hit one first)");
            } else if (f6) {
                std::vector<uint8_t> b(16);
                const uint32_t hp_stat = 0x000F4240;
                const int64_t delta = -5000;  // -5 HP (x1000)
                std::memcpy(b.data(), &npc->key, 4);
                std::memcpy(b.data() + 4, &hp_stat, 4);
                std::memcpy(b.data() + 8, &delta, 8);
                const bool ok = net::sniffer_inject_c2s(packet(2181, b));
                log::info("Combat test T2: VaryStatByAccInputReq(0x{:08X} at {:.1f} m, HP, -5) {}",
                          npc->key, npc->distance, ok ? "queued" : "NOT queued");
            } else {
                // victim, attacker, u32, vec3 position, vec3 direction, u32 hash, u32.
                std::vector<uint8_t> b(44, 0);
                const uint32_t player = net::capture_own_player_key();
                uint32_t hash = net::capture_last_attack_hash();
                if (!hash) hash = 0xF2EE2678;  // a hash seen in captura 2
                const float pos[3] = {npc->pos.x, npc->pos.y + 1.0f, npc->pos.z};
                const float dx = npc->pos.x - me->position.x, dz = npc->pos.z - me->position.z;
                const float len = std::sqrt(dx * dx + dz * dz) + 1e-4f;
                const float dir[3] = {dx / len, 0.0f, dz / len};
                std::memcpy(b.data(), &npc->key, 4);
                std::memcpy(b.data() + 4, &player, 4);
                std::memcpy(b.data() + 12, pos, 12);
                std::memcpy(b.data() + 24, dir, 12);
                std::memcpy(b.data() + 36, &hash, 4);
                const bool ok = net::sniffer_inject_c2s(packet(2815, b));
                log::info("Combat test T3: AttackByCollisionReq(0x{:08X} at {:.1f} m, hash 0x{:08X}) {}",
                          npc->key, npc->distance, hash, ok ? "queued" : "NOT queued");
            }
        }
        f6_was = f6;
        f7_was = f7;
    }
}

// Single-PC mirror (dev): F9 spawns a copy of the player that replays the
// player's own events after `delay_ms`, F10 removes it, F11 pauses it. Same
// sender (local_capture) and receiver (remote_puppet) as co-op, minus the
// network and with the same game clock on both ends.
void mirror_hotkey_loop(uint32_t delay_ms) {
    log::info("Mirror hotkeys active: F9 = spawn your copy, F10 = remove it, "
              "F11 = mirroring on/off (delay {} ms)", delay_ms);
    auto mirror_sink = [delay_ms](const proto::GameEvent& ev) {
        if (ev.kind == proto::EventKind::Damage) return;  // same world: would double every hit
        net::puppet_event(ev, static_cast<int64_t>(delay_ms), delay_ms);
    };
    game::PlayerReader reader;
    reader.init();
    bool mirror_on = true;
    bool f9_was = false, f10_was = false, f11_was = false;
    while (!stop_requested(50)) {
        const bool f9 = (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
        const bool f10 = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
        const bool f11 = (GetAsyncKeyState(VK_F11) & 0x8000) != 0;
        if (f11 && !f11_was) {
            mirror_on = !mirror_on;
            log::info("Mirror {}", mirror_on ? "ON" : "OFF");
            net::capture_set_sink(mirror_on && net::puppet_spawned() ? net::EventSink(mirror_sink)
                                                                     : net::EventSink{});
        }
        if (f9 && !f9_was) {
            auto me = reader.read();
            auto info = me ? net::capture_spawn_info(me->position, me->rotation) : std::nullopt;
            if (!me) {
                log::warn("F9: player not in world ({})", reader.last_failure());
            } else if (!info) {
                log::warn("F9: no templates yet (load a save with the sniffer on, then try again)");
            } else if (net::puppet_spawn(*info)) {
                if (mirror_on) net::capture_set_sink(mirror_sink);
            }
        }
        if (f10 && !f10_was) {
            net::capture_set_sink({});
            if (!net::puppet_remove()) log::warn("F10: nothing to remove");
        }
        f9_was = f9;
        f10_was = f10;
        f11_was = f11;
    }
    net::capture_set_sink({});
}

// Hooks are installed only once the game is fully up: installing the overlay
// at process start (creating our probe D3D12 device while the game and
// Streamline initialise theirs) left the game stuck on a black window.
DWORD WINAPI late_init(LPVOID param) {
    std::unique_ptr<LateInit> init(static_cast<LateInit*>(param));
    if (init->in_game) {
        log::info("Late init: waiting for the game to finish starting up");
        const auto* profile = game::reader_profile();
        if (!profile) {
            log::error("Late init: unsupported game build; native integration disabled");
            return 0;
        }
        const auto world_slot = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) +
                                profile->world_system;
        // WorldSystem exists from the title screen on, i.e. after the game
        // created its device and swap chain and started presenting.
        while (!stop_requested(500)) {
            uintptr_t world = 0;
            game::safe_read(world_slot, &world, sizeof world);
            if (world != 0 && game_window_visible()) break;
        }
        if (stop_requested(5000)) return 0;
        log::info("Late init: game is up, installing hooks");
    }
    bool sniffer_ok = false;
    if (init->sniffer && init->in_game) sniffer_ok = net::sniffer_install(init->dir, g_stop, init->record);
    if (sniffer_ok) game::game_errors_install();  // drained by the sniffer's writer thread
    if (init->overlay) render::install(render::hud_draw);
    if (init->session2) {
        session2::install(init->session2_opt);
        session2::door_trace_install(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)));
    }
    if (init->combat_tests && sniffer_ok) {
        CloseHandle(CreateThread(
            nullptr, 0, [](LPVOID) -> DWORD { combat_test_loop(); return 0; }, nullptr, 0, nullptr));
    }
    // Templates and injection both live in the sniffer's hooks.
    if ((init->coop || init->clone_hotkeys) && !sniffer_ok) {
        log::warn("Co-op and the mirror need the sniffer ([sniffer] enabled=1); not active");
    } else if (init->coop) {
        // The co-op link sets the puppet offset (it depends on who is connected).
        net::puppet_set_horse_enabled(init->coop_horse);
        net::puppet_set_equip_enabled(init->coop_equip);
        // The mirrored damage and the other player's hits on our enemies'
        // copies would both hurt the same enemy: hits win.
        if (init->coop_damage && init->guest_hits) log::info("Co-op: mirrored damage off ([coop] guest_hits=1)");
        net::capture_set_damage_enabled(init->coop_damage && !init->guest_hits);
        net::puppet_install_climb_fix();
        // Horse and enemy copies (the other player may send theirs at any
        // time) need the crash containment (docs/INFORME-CABALLO-CRASH.md)
        // and the action-layer guards; without them they are refused.
        const bool contained = net::horse_diag_install(/*contain=*/true);
        const bool guarded = contained && net::puppet_install_layer_guards();
        if (!contained) {
            net::puppet_set_horse_enabled(false);
            log::warn("Horse and enemy copies disabled: their crash containment could not be installed");
        } else if (!guarded) {
            log::warn("Enemy copies disabled: their crash guards could not be installed");
        }
        net::enemy_set_receive_enabled(guarded);
        // Sending OUR enemies (Ctrl+F6 / Ctrl+F7): the host only.
        if (init->enemy_relay && guarded) {
            CloseHandle(CreateThread(
                nullptr, 0, [](LPVOID) -> DWORD { net::enemy_test_loop(g_stop); return 0; }, nullptr, 0, nullptr));
        }
        net::capture_install_equip_hook();
        if (init->attack_probe) {
            CloseHandle(CreateThread(
                nullptr, 0, [](LPVOID) -> DWORD { net::attack_probe_loop(g_stop); return 0; }, nullptr, 0, nullptr));
        }
        if (init->piece4_test) {
            CloseHandle(CreateThread(
                nullptr, 0, [](LPVOID) -> DWORD { net::piece4_test_loop(g_stop); return 0; }, nullptr, 0, nullptr));
        }
        net::guest_hits_set_enabled(init->guest_hits, init->guest_hit_stagger);
        net::hits_set_react(init->player_hit_react, init->player_hit_lethal);
        net::puppet_map_pin_style(init->pin_shape, init->pin_colour);
        // Before any puppet loads: the game picks its icon when it spawns.
        const bool minimap = net::puppet_minimap_install(init->minimap_icon);
        if ((init->aggro_test || init->enemies_target_copy) && net::aggro_test_install()) {
            net::aggro_set_copy_targetable(init->enemies_target_copy);
            net::aggro_set_copy_attack_slots(init->enemies_target_copy ? init->copy_attack_slots : 0);
            net::hits_set_enabled(init->enemies_target_copy);
            if (init->aggro_test) {
                CloseHandle(CreateThread(
                    nullptr, 0, [](LPVOID) -> DWORD { net::aggro_test_loop(g_stop); return 0; }, nullptr, 0,
                    nullptr));
            }
        }
        net::coop_set_ready();
        if (minimap) {
            CloseHandle(CreateThread(
                nullptr, 0,
                [](LPVOID cycle) -> DWORD {
                    if (cycle) {
                        minimap_cycle_loop();
                    } else {
                        while (!stop_requested(1000)) net::puppet_minimap_tick();
                    }
                    return 0;
                },
                init->minimap_cycle ? reinterpret_cast<LPVOID>(1) : nullptr, 0, nullptr));
        }
        if (init->clone_hotkeys) log::info("Mirror hotkeys off while co-op is enabled");
    } else if (init->clone_hotkeys) {
        net::puppet_set_offset(init->mirror_offset_m);
        net::puppet_install_climb_fix();
        net::capture_install_equip_hook();
        mirror_hotkey_loop(init->mirror_delay_ms);
    }
    return 0;
}

DWORD WINAPI worker(LPVOID) {
    const std::wstring dir = dir_of(module_path(g_self));
    // Two copies on one PC (role_logic.h, docs/research/dos-instancias.md): CDMP_ROLE picks this process's ini, file
    // names and saves. Absent: everything as before.
    const RoleStart rs = read_role();
    role::set_current(rs.role);
    log::open(dir + role::log_name(rs.role, rs.extra));
    log::info("=== Crimson Desert Multiplayer {} (build {:08X}{}, protocol {}) ===", CDMP_VERSION, kModBuild,
              CDMP_BUILD_DIRTY ? " + local changes" : "", proto::kVersion);
    const auto file_exists = [](const std::wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; };
    const role::IniChoice ini = role::choose_ini(rs.role, file_exists(dir + role::tagged(L"cdmp", rs.role) + L".ini"),
                                                 file_exists(dir + L"cdmp.ini"));
    if (!rs.valid) {
        log::error("Role: CDMP_ROLE='{}' is not 'host' or 'guest': the mod stays OFF in this process (no hooks, no "
                   "network, nothing redirected)",
                   narrow(rs.raw));
    } else if (rs.role == role::Role::None) {
        log::info("Role: none (CDMP_ROLE not set) | ini '{}' | log '{}'", narrow(dir + ini.name),
                  narrow(log::current_path()));
    } else {
        log::info("Role: {} (CDMP_ROLE={}) | ini '{}'{} | log '{}' (alias {}) | {}", role::name_a(rs.role),
                  narrow(rs.raw), narrow(dir + ini.name), ini.fell_back ? " (FALLBACK)" : "",
                  narrow(log::current_path()), narrow(role::log_name(rs.role, rs.extra)),
                  rs.extra ? "NOT the first process of this role: this one stays inert" : "first process of this role");
        if (ini.fell_back) {
            log::warn("Role: '{}' is absent: '{}' is read instead (the other copy's ini?)",
                      narrow(dir + role::tagged(L"cdmp", rs.role) + L".ini"), narrow(dir + ini.name));
        }
        if (!rs.mutex_ok) log::warn("Role: the role's mutex could not be created; this process counts as the first");
    }
    log::info("Mod file: {}", narrow(module_path(g_self)));

    try {
        const bool in_game = log_process_info();
        if (!rs.valid) return 0;
        if (rs.role != role::Role::None) log_parent();
        // The guest's saves: before anything else (the game reads its save list early), in every guest-role process
        // (the later ones too). Never on the real folder: a failure ends the game here, before it touched a save.
        // Not in a test host (cdmp_host unloads the mod: KernelBase hooks would be left pointing into it).
        if (rs.role == role::Role::Guest && !in_game) {
            log::info("Role guest: not inside the game (test host): the save redirect is not installed");
        } else if (rs.role == role::Role::Guest && !session2::save_hooks_install_guest_role()) {
            log::error("Role guest: the save redirect is NOT installed; the game is ended now so that it never "
                       "writes the real save folder");
            log::flush(2000);
            TerminateProcess(GetCurrentProcess(), 0xCD60);
            return 0;
        }
        if (rs.extra) {
            log::warn("Role {}: another process of this role runs the mod (the game's short-lived second "
                      "CrimsonDesert.exe?): nothing else is installed here{}",
                      role::name_a(rs.role),
                      rs.role == role::Role::Guest ? " (the save redirect above stays, as in the first one)" : "");
            return 0;
        }
        if (config_layout_size() != sizeof(Config)) {
            log::error("Config layout mismatch: config.cpp has sizeof(Config) {} but this file {} (a stale object "
                       "from an incremental build): nothing is installed; rebuild from a clean build folder",
                       config_layout_size(), sizeof(Config));
            return 0;
        }
        const Config cfg = load_config(dir + ini.name);
        if (rs.role == role::Role::Guest && !(cfg.s2_enabled && cfg.s2_guest)) {
            log::warn("Role guest: the ini has no [session2] enabled=1 guest=1; this copy is not a P8 guest");
        }
        if (rs.role == role::Role::Host && cfg.s2_enabled && cfg.s2_guest) {
            log::warn("Role host: the ini says [session2] guest=1 (a guest's ini?)");
        }
        if (rs.role != role::Role::None && cfg.net_enabled && cfg.net_transport_steam) {
            log::warn("Role {}: [net] transport=steam: both copies on this PC share one SteamID; use transport=udp "
                      "(docs/research/dos-instancias.md)",
                      role::name_a(rs.role));
        }
        // Two copies on one PC: the copy in the background keeps its GPU share (bg_speed_logic.h). Right after the
        // config, before the first frame: no hook, its own thread.
        bgspeed::start(bgspeed::gate(cfg.background_full_speed, rs.role != role::Role::None, in_game),
                       role::name_a(rs.role));
        log::info("Config: player '{}', peer {}:{}, {} Hz, net {}, co-op {}", cfg.player_name,
                  cfg.peer_host, cfg.peer_port, cfg.send_rate_hz, cfg.net_enabled ? "on" : "off",
                  cfg.coop_enabled ? "on" : "off");
        // Everything that changes behaviour, so a log sent by the other player
        // says how their game was set up.
        log::info("Config: net {} {} | coop delay {} ms, offset {:.2f} m, horse {}, equip {}, damage mirror {}, "
                  "map pin {}, minimap icon {:#x}, enemies target copy {}, guest hits {}, stagger {}, player react {} lethal {}",
                  cfg.net_transport_steam ? "steam" : "udp", cfg.net_role_host ? "host" : "guest", cfg.coop_delay_ms,
                  cfg.coop_offset_m, cfg.coop_horse, cfg.coop_equip, cfg.coop_damage, cfg.coop_map_pin,
                  cfg.coop_minimap_icon, cfg.coop_enemies_target_copy, cfg.coop_guest_hits, cfg.coop_guest_hit_stagger,
                  cfg.coop_player_hit_react, cfg.coop_player_hit_lethal);
        log::info("Config: dev clone {} combat {} minimap cycle {} aggro {} enemy relay {} piece4 {} | sniffer {} "
                  "record {} | overlay {}",
                  cfg.dev_clone_hotkeys, cfg.dev_combat_tests, cfg.dev_minimap_cycle, cfg.dev_aggro_test,
                  cfg.dev_enemy_relay, cfg.dev_piece4_test, cfg.sniffer_enabled, cfg.sniffer_record,
                  cfg.overlay_enabled);

        log::info("Config: session2 (option D) {} | probe {} finder log {} save guard {} create session {} "
                  "accept tunnel {} relay fix {} account {} mirror {} ({} ms) share field {} clock gate {} identity probe {} "
                  "identity fix {} companion probe {} child hold {} reconnect {} | guest (P8) {} mode {} slot refresh test {} "
                  "actor diag {} layer guard {} | S3: observer hold {} guest s3 diag {} crash dump {} update guard {} "
                  "| P8 load diag {} s1 diag {} ui pause block '{}' | S1 scenes: host s1_scene_diag {} guest_scene_diag {} "
                  "| P8 gameplay: rank permit '{}' quest per user '{}' kill loot per user '{}' | P8 remote motion: "
                  "remote_climb '{}' wallup_send {} dismount_probe {} divergence_probe {} | P8 movement: remote interp "
                  "'{}' horse follow '{}'",
                  cfg.s2_enabled ? "ON" : "off", cfg.s2_probe, cfg.s2_finder_log,
                  saveguard::mode_name(cfg.s2_save_guard), cfg.s2_create_session, cfg.s2_accept_tunnel,
                  cfg.s2_relay_fix, cfg.s2_account,
                  cfg.s2_mirror_host, cfg.s2_mirror_delay_ms, cfg.s2_share_field, cfg.s2_clock_gate,
                  cfg.s2_identity_probe, cfg.s2_identity_fix, cfg.s2_companion_probe, cfg.s2_child_hold,
                  cfg.s2_reconnect, cfg.s2_guest, cfg.s2_guest_remote ? "remote" : "observe",
                  cfg.s2_guest_slot_refresh_test, cfg.s2_guest_actor_diag, cfg.s2_guest_layer_guard, cfg.s2_observer_hold,
                  cfg.s2_guest_s3_diag, cfg.s2_guest_crash_dump, cfg.s2_guest_update_guard, cfg.s2_load_diag,
                  cfg.s2_s1_diag, cfg.s2_ui_pause_block, cfg.s2_s1_scene_diag, cfg.s2_guest_scene_diag,
                  cfg.s2_rank_permit, cfg.s2_quest_per_user, cfg.s2_kill_loot_per_user, cfg.s2_remote_climb,
                  cfg.s2_wallup_send, cfg.s2_dismount_probe, cfg.s2_divergence_probe, cfg.s2_remote_interp,
                  cfg.s2_horse_follow);
        log::info("Config: P8 pets: child_settle_ms {} remote_interp_owned_cap_ms {} attach_follow '{}'",
                  cfg.s2_child_settle_ms, cfg.s2_remote_interp_owned_cap_ms, cfg.s2_attach_follow);
        log::info("Config: P8 session 9: ride_filter '{}' child_reannounce '{}' combat_follow '{}' guest_horse_probe "
                  "'{}'",
                  cfg.s2_ride_filter, cfg.s2_child_reannounce, cfg.s2_combat_follow, cfg.s2_guest_horse_probe);
        log::info("Config: P8 mount ride: horse_follow_reverse '{}' (host) remote_interp_pair {}",
                  cfg.s2_horse_follow_reverse, cfg.s2_remote_interp_pair ? 1 : 0);
        log::info("Config: P8 session 25 combat stream: combat_follow_v2 '{}' (host) remote_interp_combat '{}' (guest)",
                  cfg.s2_combat_follow_v2, cfg.s2_remote_interp_combat);
        log::info("Config: P8 world around user 2: user2_world_anchor '{}' (host)", cfg.s2_user2_world_anchor);
        log::info("Config: P8 re-entry: rejoin '{}' (host and guest; the host needs reconnect=1, now {})", cfg.s2_rejoin,
                  cfg.s2_reconnect ? 1 : 0);
        log::info("Config: P8 mounts: mount_sync '{}' ride_dismount '{}' mount_seat '{}' ride_hold_pos '{}' "
                  "mount_relink '{}'",
                  cfg.s2_mount_sync, cfg.s2_ride_dismount, cfg.s2_mount_seat, cfg.s2_ride_hold_pos,
                  cfg.s2_mount_relink);
        // P8 S18 (pendientes/p8-impl-monturas.md §11): before ride_filter and mount_sync start, on both PCs.
        session2::ride_dismount_configure(cfg.s2_ride_dismount);
        log::info("Config: P8 NPC schedules: guest_schedule_load '{}' schedule_load_selfcheck {} observer_sched_copy {}",
                  cfg.s2_guest_schedule_load, cfg.s2_schedule_load_selfcheck, cfg.s2_observer_sched_copy ? 1 : 0);
        log::info("Config: P8 X veto: guest_x_stage_veto '{}' guest_x_camera_veto '{}' guest_x_ui_veto '{}' "
                  "guest_x_ui_veto_allow '{}' guest_local_after_remote '{}'",
                  cfg.s2_guest_x_stage_veto, cfg.s2_guest_x_camera_veto, cfg.s2_guest_x_ui_veto,
                  cfg.s2_guest_x_ui_veto_allow, cfg.s2_guest_local_after_remote);
        log::info("Config: S44/S45 foreign scenes (guest): guest_seq_foreign_player '{}' guest_seq_foreign_probe {} "
                  "guest_seq_foreign_present_probe {} guest_seq_foreign_present '{}' guest_seq_foreign_timeline '{}'",
                  cfg.s2_guest_seq_foreign_player, cfg.s2_guest_seq_foreign_probe ? 1 : 0,
                  cfg.s2_guest_seq_foreign_present_probe ? 1 : 0, cfg.s2_guest_seq_foreign_present,
                  cfg.s2_guest_seq_foreign_timeline);
        log::info("Config: P8 shopkeepers: guest_x_interaction_stage '{}' shop_probe {} funcnpc_twin '{}' | option U: "
                  "user2_stages '{}' user2_timer_route '{}' user2_npc_control '{}' user2_drain_at_host_prepare '{}' "
                  "user2_fast_rearm '{}'",
                  cfg.s2_guest_x_interaction_stage, cfg.s2_shop_probe ? 1 : 0, cfg.s2_funcnpc_twin,
                  cfg.s2_user2_stages, cfg.s2_user2_timer_route, cfg.s2_user2_npc_control,
                  cfg.s2_user2_drain_at_host_prepare, cfg.s2_user2_fast_rearm);
        log::info("Config: S46 shopkeepers (phase 3): shop_trade_probe {} (host, read only) user2_shop_trade_route '{}' "
                  "(host, U2-c) observer_hold_scene_order '{}' (host, T2) user2_shop_trade_list '{}' (host, T1) "
                  "shop_interaction_own_delete '{}' (R0, host and guest) | related: user2_shop_route '{}' "
                  "user2_stages_elements '{}' observer_hold_acks {}",
                  cfg.s2_shop_trade_probe ? 1 : 0, cfg.s2_user2_shop_trade_route, cfg.s2_observer_hold_scene_order,
                  cfg.s2_user2_shop_trade_list, cfg.s2_shop_interaction_own_delete, cfg.s2_user2_shop_route,
                  cfg.s2_user2_stages_elements, cfg.s2_observer_hold_acks ? 1 : 0);
        log::info("Config S33: npc_activation '{}' npc_family_control '{}' user2_road_control '{}' (cliente sólo observacion)"
                  " | S34 guest_remote_update_guard {} (guest)",
                  cfg.s2_npc_activation, cfg.s2_npc_family_control, cfg.s2_user2_road_control,
                  cfg.s2_guest_remote_update_guard ? 1 : 0);
        log::info("Config: P8 session 10: freeze_watchdog {} | log file {}", cfg.s2_freeze_watchdog,
                  narrow(log::current_path()));
        log::info("Config: P8 session 15 fast travel: user2_fast_travel '{}' (host) user2_revive_manager '{}' (host, F4) "
                  "guest_fast_travel_veto '{}' (guest) guest_reload_wait_fix '{}' (guest)",
                  cfg.s2_user2_fast_travel, cfg.s2_user2_revive_manager, cfg.s2_guest_fast_travel_veto,
                  cfg.s2_guest_reload_wait_fix);
        log::info("Config: P8 session 15 travel (host): user2_loading_owner_alias {} user2_travel_probe {}",
                  cfg.s2_loading_owner_alias ? 1 : 0, cfg.s2_user2_travel_probe ? 1 : 0);
        log::info("Config: P8 S16 reload (host): observer_milestone_reload '{}' | P8 S27 observer_milestone_reload_any "
                  "'{}'",
                  cfg.s2_observer_milestone_reload, cfg.s2_observer_milestone_reload_any);
        log::info("Config: P8 session 25 hour/weather: user2_clock_push '{}' (host) block_guest_weather {} (host) "
                  "clock_probe {} (both)",
                  cfg.s2_user2_clock_push, cfg.s2_block_guest_weather ? 1 : 0, cfg.s2_clock_probe ? 1 : 0);
        log::info("Config: P8 session 25 weather: weather_sync '{}' (both) weather_sync_radius_m {} (guest)",
                  cfg.s2_weather_sync, cfg.s2_weather_sync_radius_m);
        log::info("Config: P8 session 25 grabs: catch_seq '{}' (host)", cfg.s2_catch_seq);
        log::info("Config: P8 session 25 rope: remote_rope '{}' (both; the server's 2471 on the host) rope_probe {} "
                  "(both, log only) tree_bend '{}' (both; tunnel control state 15)",
                  cfg.s2_remote_rope, cfg.s2_rope_probe ? 1 : 0, cfg.s2_tree_bend);
        log::info("Config: P8 session 28 docked gimmicks: docked_gimmicks '{}' (both; 1 rewrites on the guest only) "
                  "docked_gimmicks_other '{}' (guest; the host ignores it) gimmick_event_dedup '{}' (both; 1 "
                  "withholds on the guest only, the host logs)",
                  cfg.s2_docked_gimmicks, cfg.s2_docked_gimmicks_other, cfg.s2_gimmick_event_dedup);
        // P8 session 10 (pendientes/p8-impl-freeze-watchdog.md): before ANY module installs a hook, so that every
        // mid hook installed through p8_install_mid gets its thread mark. Both roles; its own thread.
        session2::freeze_watchdog_start(in_game && cfg.s2_enabled && cfg.s2_freeze_watchdog, cfg.s2_guest);

        if (cfg.startup_delay_ms > 0 && stop_requested(cfg.startup_delay_ms)) return 0;

        LocalSource local(in_game);

        // The overlay only makes sense inside the game; a test host would
        // otherwise keep patched DXGI vtables pointing into an unloaded DLL.
        // cdmp_dx12_test opts in explicitly (and never unloads the mod).
        const bool overlay_allowed =
            in_game || GetEnvironmentVariableW(L"CDMP_TEST_OVERLAY", nullptr, 0) > 0;
        const bool overlay = overlay_allowed && cfg.overlay_enabled;
        const bool sniffer = in_game && cfg.sniffer_enabled;
        if (in_game && !cfg.overlay_enabled) log::info("Overlay disabled in cdmp.ini");
        if (in_game && !cfg.sniffer_enabled) log::info("Sniffer disabled in cdmp.ini");
        // Option D never runs with the copies model.
        bool session2 = in_game && cfg.s2_enabled && !cfg.coop_enabled;
        if (in_game && cfg.s2_enabled && cfg.coop_enabled) {
            log::warn("Session2 (option D) needs [coop] enabled=0; staying off");
        }
        // On the P8 guest the dev tools that inject packets stay off (they would
        // reach a client that plays on the host's server).
        const bool p8_guest = in_game && cfg.s2_enabled && !cfg.coop_enabled && cfg.s2_guest;
        // P8, the guest's side: as early as possible (the client connects to its
        // own server seconds after start), and never with the host-side stages.
        if (session2) {
            session2::door_trace_start(cfg.s2_door_trace, cfg.s2_guest);
            session2::housing_trace_start(cfg.s2_housing_trace);
            session2::housing_redraw_start(cfg.s2_housing_redraw && cfg.s2_guest, cfg.s2_housing_gimmick_guard && cfg.s2_guest);
            session2::npc_probe_client_start(cfg.s2_npc_activation, cfg.s2_npc_family_control,
                                            cfg.s2_user2_road_control, cfg.s2_guest, g_stop);
        }
        if (session2 && cfg.s2_guest) {
            if (cfg.s2_create_session || cfg.s2_accept_tunnel || cfg.s2_relay_fix || cfg.s2_mirror_host ||
                cfg.s2_share_field) {
                log::error("Session2: guest=1 is the guest's PC; it cannot run with the host's stages "
                           "(create_session, accept_tunnel, relay_fix, mirror_host). Option D stays off");
            } else {
                // P8 session 9 (pendientes/p8-impl-s9-movimiento.md): before any packet of the host can arrive.
                session2::ride_filter_configure(cfg.s2_ride_filter, /*guest=*/true);
                session2::guest_reannounce_configure(cfg.s2_child_reannounce, cfg.sniffer_enabled);
                // P8 session 15 (pendientes/p8-s15-viaje-tunel.md §8): before guest_actor_diag's hook can run.
                session2::guest_reload_wait_configure(cfg.s2_guest_reload_wait_fix, cfg.s2_guest_actor_diag);
                session2::guest_start(cfg.s2_guest_remote, cfg.s2_guest_slot_refresh_test, cfg.s2_guest_actor_diag,
                                      cfg.s2_guest_layer_guard, cfg.s2_guest_s3_diag, cfg.s2_guest_crash_dump,
                                      cfg.s2_guest_update_guard);
                // P8 S1/S2 read-only probes (pendientes/p8-impl-s1s2.md): their own thread.
                session2::p8_probes_start({cfg.s2_load_diag, cfg.s2_s1_diag, /*host=*/false});
                // NPC schedule files (pendientes/p8-impl-horarios.md §8): read-only self-check, its own thread.
                session2::schedule_selfcheck_start(cfg.s2_schedule_load_selfcheck, /*host=*/false);
                // Menus do not pause this guest's world while it plays on the host (p8-pausa-esc.md); its own thread.
                session2::ui_pause_start(cfg.s2_ui_pause_block, /*guest=*/true);
                session2::seq_marker_start(cfg.s2_seq_marker_guard, /*guest=*/true, cfg.s2_seq_marker_trace);
                session2::pivot_guard_start(cfg.s2_change_pivot_guard, /*guest=*/true);
                session2::ride_null_guard_start(cfg.s2_ride_null_guard, /*guest=*/true);
                session2::focus_follow_start(cfg.s2_focus_follow, /*guest=*/true);
                session2::field_leave_guard_start(cfg.s2_field_leave_guard, /*guest=*/true);
                session2::achievement_guard_start(cfg.s2_achievement_guard);
                session2::guest_set_docking_dedupe(cfg.s2_docking_dedupe);
                // The host's character climbs / climbs up / dismounts as a native remote actor here
                // (pendientes/p8-impl-escalada.md); its own thread, nothing with the three keys at 0.
                session2::remote_motion_start({cfg.s2_remote_climb, cfg.s2_wallup_send, cfg.s2_dismount_probe,
                                               cfg.s2_divergence_probe},
                                              /*guest=*/true);
                // The host's NPCs, animals and horses move smoothly here (p8-impl-interp-remota.md); its own thread.
                session2::remote_interp_start(cfg.s2_remote_interp, /*guest=*/true, cfg.s2_remote_interp_owned_cap_ms,
                                              cfg.s2_remote_interp_pair, cfg.s2_remote_interp_combat,
                                              cfg.s2_remote_interp_players);
                // P8 mounts (pendientes/p8-impl-monturas.md): the rider<->horse commit both ways; its own thread.
                session2::mount_sync_start(cfg.s2_mount_sync, /*guest=*/true, cfg.s2_mount_seat, cfg.s2_ride_hold_pos,
                                           cfg.s2_mount_relink);
                // F1 (pendientes/p8-impl-viaje-rapido.md): no fast travel while playing on the host; its own thread.
                session2::guest_fast_travel_start(cfg.s2_guest_fast_travel_veto);
                // P8 session 25 (noche/clima-hora.md §6): read-only clock probe, its own thread (nothing with 0).
                session2::clock_probe_start(cfg.s2_clock_probe, /*guest=*/true);
                // P8 session 25 (noche/clima-sincronizar.md): the host's weather in viewer mode; its own thread.
                session2::weather_sync_start(cfg.s2_weather_sync, /*guest=*/true, cfg.s2_weather_sync_radius_m);
                // P8 session 25 (s25/finisher-sigilo.md): host only; warned and off here if set.
                session2::catch_seq_start(cfg.s2_catch_seq, /*guest=*/true);
                // P8 session 25 (s25/gancho-cuerda.md): the host's rope on this client (F1 handle, F3 stale slot);
                // its own thread installs the hooks once the world is up. Nothing with remote_rope=0.
                session2::remote_rope_start(cfg.s2_remote_rope, /*guest=*/true);
                // P8 session 27 (s25/gancho-cuerda.md section 13): the tree-bend and grappling-device probes, log only;
                // its own thread installs the hooks once the world is up. Nothing with rope_probe=0.
                session2::rope_probe_start(cfg.s2_rope_probe, /*guest=*/true);
                // P8 session 29 (s25/gancho-cuerda.md section 14): its own tree bends sent to the host, the host's
                // logged (probe) or applied here (1); its own thread installs the hooks once the world is up.
                session2::tree_bend_start(cfg.s2_tree_bend, /*guest=*/true);
                // P8 session 28 (s25/gimmicks-dueno.md): its own character's docked gimmicks (local drive with 1) and
                // the log-only probes; its own thread installs the hooks once the world is up. Nothing with 0.
                session2::docked_gimmicks_start(cfg.s2_docked_gimmicks, /*guest=*/true);
                // P8 session 29 (s25/gimmicks-dueno.md section 8): the same for the host's character (its rope drawn
                // here). Needs docked_gimmicks on. Nothing with 0.
                session2::docked_gimmicks_other_start(cfg.s2_docked_gimmicks_other, /*guest=*/true);
                session2::docked_gimmicks_interact_start(cfg.s2_guest_gimmick_interact,
                                                         cfg.s2_guest_gimmick_interact_events, /*guest=*/true);
                // P8 session 28 (s25/gimmicks-dueno.md section 7): its 2779 for gimmicks the host controls. Nothing with 0.
                session2::gimmick_event_dedup_start(cfg.s2_gimmick_event_dedup, /*guest=*/true);
                session2::interact_gate_start(cfg.s2_interact_gate, cfg.s2_interact_gate_errors,
                                              cfg.s2_interact_gate_pass, cfg.s2_interact_gate_types, /*guest=*/true);
                session2::store_gate_start(cfg.s2_store_gate, /*guest=*/true);
                session2::guest_shop_branch_start(cfg.s2_guest_shop_branch, /*guest=*/true, dir + ini.name);
                session2::shop_ui_trace_start(cfg.s2_shop_ui_trace, /*guest=*/true);
                session2::guest_shop_window_start(cfg.s2_guest_shop_window, /*guest=*/true);
                // 13-nov (vehicle_follow.h): the host's ship drawn where the host has it. Nothing with 0.
                session2::vehicle_follow_start(cfg.s2_vehicle_follow, /*guest=*/true, cfg.s2_vehicle_follow_delay_ms);
            }
            session2 = false;  // nothing of the host's side on the guest's PC
        }
        // The same bounded crash collector is useful on the host's client: no
        // S3 probes or guards, only first-chance records and the chained
        // top-level/minidump capture explicitly requested by the config.
        if (session2 && cfg.s2_guest_crash_dump) {
            session2::guest_s3_start(/*diag=*/false, /*crash_dump=*/true, /*update_guard=*/false,
                                     /*actor_diag=*/false, /*update_site_taken=*/false);
        }
        // The same probes on the host's PC (S1 on its client, S2 on its server
        // and its ExtraReward UI); nothing without load_diag / s1_diag.
        if (session2) session2::p8_probes_start({cfg.s2_load_diag, cfg.s2_s1_diag, /*host=*/true});
        // P8 session 25 (noche/clima-hora.md §6): the same read-only clock probe on the host, for the comparison.
        if (session2) session2::clock_probe_start(cfg.s2_clock_probe, /*guest=*/false);
        // P8 session 25 (noche/clima-sincronizar.md): the weather probe / selftest / samples on the host; its own thread.
        if (session2) session2::weather_sync_start(cfg.s2_weather_sync, /*guest=*/false, cfg.s2_weather_sync_radius_m);
        // P8 session 25 (s25/finisher-sigilo.md): the guest's grabs applied on the host's client (the enemies'
        // controller); its own thread installs the hook once the world is up. Nothing with catch_seq=0.
        if (session2) session2::catch_seq_start(cfg.s2_catch_seq, /*guest=*/false);
        // P8 session 25 (s25/gancho-cuerda.md): user 2's rope on the host's client (F1, F3) and the server's 2471 for
        // tree releases (F2); its own thread installs the hooks once the world is up. Nothing with remote_rope=0.
        if (session2) session2::remote_rope_start(cfg.s2_remote_rope, /*guest=*/false);
        // P8 session 27 (s25/gancho-cuerda.md section 13): the same log-only rope probes on the host.
        if (session2) session2::rope_probe_start(cfg.s2_rope_probe, /*guest=*/false);
        // P8 session 29 (s25/gancho-cuerda.md section 14): the same on the host (its bends to the guest, user 2's here).
        if (session2) session2::tree_bend_start(cfg.s2_tree_bend, /*guest=*/false);
        // P8 session 28 (s25/gimmicks-dueno.md): the host side is log only (never rewritten); nothing with 0.
        if (session2) session2::docked_gimmicks_start(cfg.s2_docked_gimmicks, /*guest=*/false);
        // P8 session 29: a guest key; the host logs that it ignores it.
        if (session2) session2::docked_gimmicks_other_start(cfg.s2_docked_gimmicks_other, /*guest=*/false);
        // P8 session 28 (s25/gimmicks-dueno.md section 7): the 2779 / 2250 duplicates, log only on the host.
        if (session2) session2::gimmick_event_dedup_start(cfg.s2_gimmick_event_dedup, /*guest=*/false);
        if (session2) {
            session2::interact_gate_start(cfg.s2_interact_gate, cfg.s2_interact_gate_errors, cfg.s2_interact_gate_pass,
                                          cfg.s2_interact_gate_types, /*guest=*/false);
            session2::store_gate_start(cfg.s2_store_gate, /*guest=*/false);
            session2::shop_ui_trace_start(cfg.s2_shop_ui_trace, /*guest=*/false);
            // 13-nov (vehicle_follow.h): user 2's ships drawn where user 2 has them. Nothing with 0.
            session2::vehicle_follow_start(cfg.s2_vehicle_follow, /*guest=*/false, cfg.s2_vehicle_follow_delay_ms);
        }
        // The same read-only schedule self-check on the host (its client is the reference: p8-impl-horarios.md §8).
        if (session2) session2::schedule_selfcheck_start(cfg.s2_schedule_load_selfcheck, /*host=*/true);
        // Menus do not pause the host's world while user 2 is logged in (p8-pausa-esc.md); nothing with ui_pause_block=0.
        if (session2) session2::ui_pause_start(cfg.s2_ui_pause_block, /*guest=*/false);
        // The host gets no death screen once a guest has joined without this (session2/seq_marker.h).
        if (session2) session2::seq_marker_start(cfg.s2_seq_marker_guard, /*guest=*/false, cfg.s2_seq_marker_trace);
        if (session2) session2::pivot_guard_start(cfg.s2_change_pivot_guard, /*guest=*/false);
        if (session2) session2::ride_null_guard_start(cfg.s2_ride_null_guard, /*guest=*/false);
        if (session2) session2::focus_follow_start(cfg.s2_focus_follow, /*guest=*/false);
        if (session2) session2::field_leave_guard_start(cfg.s2_field_leave_guard, /*guest=*/false);
        if (session2) session2::manager_probe_start(cfg.s2_manager_probe);
        // User 2's character climbs / climbs up / dismounts as a native remote actor on the host's client
        // (pendientes/p8-impl-escalada.md); its own thread, nothing with the three keys at 0.
        if (session2) {
            session2::remote_motion_start({cfg.s2_remote_climb, cfg.s2_wallup_send, cfg.s2_dismount_probe,
                                           cfg.s2_divergence_probe},
                                          /*guest=*/false);
        }
        // User 2's pet and horse move smoothly on the host's client (p8-impl-interp-remota.md); nothing with 0.
        if (session2) {
            session2::remote_interp_start(cfg.s2_remote_interp, /*guest=*/false, cfg.s2_remote_interp_owned_cap_ms,
                                          cfg.s2_remote_interp_pair, cfg.s2_remote_interp_combat,
                                          cfg.s2_remote_interp_players);
            // P8 mounts (pendientes/p8-impl-monturas.md): the rider<->horse commit both ways; its own thread.
            session2::mount_sync_start(cfg.s2_mount_sync, /*guest=*/false, cfg.s2_mount_seat, cfg.s2_ride_hold_pos,
                                       cfg.s2_mount_relink);
        }
        // P8 gameplay for user 2 (pendientes/p8-impl-rango-embudos.md): the host's enemies' rank permit on user 2
        // (its client) and the quest / DeadActor / loot funnels inside user 2's Reqs (its server); host only, its own
        // thread; nothing with the three keys at 0.
        if (session2) {
            session2::User2FunnelOptions fo{cfg.s2_rank_permit, cfg.s2_quest_per_user, cfg.s2_kill_loot_per_user,
                                            cfg.s2_user2_fast_travel, cfg.s2_user2_revive_manager,
                                            cfg.s2_create_session};
            fo.quest_policy = cfg.s2_quest_policy;
            session2::user2_funnels_start(fo);
            log::info("Config: P8 quest_policy '{}'", cfg.s2_quest_policy);
            // F2 (pendientes/p8-impl-viaje-rapido.md): user 2's 2283 never reaches the server unless F3 is live.
            if (cfg.s2_create_session) {
                session2::fast_travel_host_configure(cfg.s2_user2_fast_travel);
                // P8 S15 (travel_probe.h): the 2643 owner alias of user 2's copy and the read-only travel probe.
                session2::travel_configure(cfg.s2_loading_owner_alias, cfg.s2_user2_travel_probe);
            }
        }
        if (overlay || sniffer || session2) {
            if (overlay) render::hud_configure({cfg.overlay_self_marker});
            auto* init = new LateInit{in_game, overlay, sniffer,
                                                      in_game && !p8_guest && cfg.dev_clone_hotkeys,
                                                      cfg.dev_mirror_delay_ms, cfg.dev_mirror_offset_m,
                                                      in_game && cfg.coop_enabled, cfg.coop_offset_m,
                                                      cfg.coop_horse, cfg.coop_equip, cfg.coop_damage,
                                                      in_game && !p8_guest && cfg.dev_combat_tests, cfg.sniffer_record,
                                                      dir, cfg.coop_minimap_icon, cfg.dev_minimap_cycle,
                                                      in_game && !p8_guest && cfg.dev_aggro_test,
                                                      cfg.coop_enemies_target_copy,
                                                      in_game && !p8_guest && cfg.dev_enemy_relay,
                                                      in_game && !p8_guest && cfg.dev_piece4_test,
                                                      cfg.coop_guest_hits, cfg.coop_guest_hit_stagger,
                                                      cfg.coop_player_hit_react, cfg.coop_player_hit_lethal,
                                                      in_game && !p8_guest && cfg.dev_attack_probe, cfg.coop_copy_attack_slots,
                                                      cfg.coop_map_pin_shape, cfg.coop_map_pin_colour};
            init->session2 = session2;
            init->session2_opt = {cfg.s2_probe, cfg.s2_save_guard, cfg.s2_block_save_trocs, cfg.s2_finder_log,
                                  cfg.s2_create_session, cfg.s2_accept_tunnel, cfg.s2_relay_fix, cfg.s2_account,
                                  cfg.s2_mirror_host, cfg.s2_mirror_delay_ms, cfg.s2_share_field,
                                  cfg.s2_clock_gate, cfg.s2_identity_probe, cfg.s2_reconnect,
                                  cfg.s2_companion_probe, cfg.s2_child_hold, cfg.s2_identity_fix,
                                  cfg.s2_observer_hold};
            g_late_thread = CreateThread(nullptr, 0, late_init, init, 0, nullptr);
        }

        if (cfg.net_enabled) run_network(cfg, local);
    } catch (const std::exception& e) {
        log::error("Unhandled exception in worker: {}", e.what());
    } catch (...) {
        log::error("Unhandled non-standard exception in worker");
    }

    log::info("Worker exiting");
    return 0;
}

}  // namespace

void start(HMODULE self) {
    g_self = self;
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
}

void stop() {
    if (!g_thread) return;
    SetEvent(g_stop);
    WaitForSingleObject(g_thread, 10000);
    CloseHandle(g_thread);
    if (g_late_thread) {
        WaitForSingleObject(g_late_thread, 10000);
        CloseHandle(g_late_thread);
        g_late_thread = nullptr;
    }
    session2::npc_probe_client_stop(); // S33: late_init ya termino; el observador no sobrevive a g_stop.
    bgspeed::stop();
    CloseHandle(g_stop);
    g_thread = nullptr;
    g_stop = nullptr;
    log::close();
}

}  // namespace cdmp
