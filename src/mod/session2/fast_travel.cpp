#include "mod/session2/fast_travel.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/render/hud.h"
#include "mod/session2/fast_travel_logic.h"
#include "mod/session2/field_share.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"
#include "mod/session2/travel_probe.h"
#include "mod/session2/user2_funnels.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;

// ---------------------------------------------------------------- F2 (host, network thread)

constexpr uint32_t kUserKey = 0x60;
constexpr uint32_t kUserMainCharacter = 0xD0;
constexpr uint32_t kActorComponents = 0x68;
constexpr uint32_t kComponentsTransformSync = 0x1A0;
constexpr uint32_t kFieldOwner = 0x180;
constexpr uintptr_t kVtServerSequencerStageManager = 0x5B17A58;
constexpr uint64_t kDropLines = 16;

std::atomic<uint8_t> g_host_mode{0};
std::atomic<uint64_t> g_seen{0}, g_gates[static_cast<size_t>(ftl::Gate::Count)] = {}, g_lines{0};

struct SafeMem {
    bool ptr(uintptr_t a, uintptr_t& v) const {
        uintptr_t p = 0;
        if (!game::safe_read(a, &p, sizeof p)) return false;
        if (p && (p < 0x10000 || p > 0x00007FFFFFFFFFFFull)) return false;
        v = p;
        return true;
    }
    bool u32(uintptr_t a, uint32_t& v) const { return game::safe_read(a, &v, sizeof v); }
};

struct Reading {
    ftl::Where where = ftl::Where::Unknown;
    uint32_t owner = 0, host_key = 0, user2_key = 0, char_key = 0;
    bool mgr_ok = false;      // for the line only: F3 hands 0x2896120 a block when it is not readable
    bool subject_ok = false;  // ExecuteTroc's subject test passes on this character now (user2_funnels)
    ftl::MgrFail why = ftl::MgrFail::None;
};

// Read only, guarded: user 2's character, the owner of the field it is in, its own sequencer manager and whether
// user2_funnels' subject will recognise it.
Reading read_user2() {
    Reading r;
    const SafeMem m;
    uintptr_t host = 0, u2 = 0, pj = 0, comps = 0, ts = 0, field = 0;
    if (server_host_user(host) && host) m.u32(host + kUserKey, r.host_key);
    if (!server_user2(u2) || !u2) return r;
    m.u32(u2 + kUserKey, r.user2_key);
    if (!m.ptr(u2 + kUserMainCharacter, pj) || !pj) return r;
    m.u32(pj + kUserKey, r.char_key);
    const bool owner_ok = m.ptr(pj + kActorComponents, comps) && comps &&
                          m.ptr(comps + kComponentsTransformSync, ts) && ts && m.ptr(ts + runtime_field_layout().ts_field_mover + fld::kFmField, field) &&
                          field && m.u32(field + kFieldOwner, r.owner);
    r.where = ftl::where_is(owner_ok, r.owner, r.host_key, r.user2_key);
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    // pa::ServerSequencerStageManager by RTTI; 3576 (static, 2026-11-06; not yet run): vtable_map_3549_3576.json.
    // Build 1.0.0.3663 (static, 2026-11-13; never run): 0x5F5A758 by RTTI (vtable_map_3576_3663.json). The line only.
    const auto build = game::current_build();
    const uintptr_t seq_vt = build == game::Build::v3663   ? uintptr_t{0x5F5A758}
                             : build == game::Build::v3576 ? uintptr_t{0x5EE0B88}
                             : build == game::Build::v3527 ? uintptr_t{0x5EDE980}
                             : build == game::Build::v2976 ? kVtServerSequencerStageManager
                                                           : 0;
    r.mgr_ok = seq_vt && ftl::seq_manager_of(m, pj, base + seq_vt, &r.why).has_value();
    if (!seq_vt) r.why = ftl::MgrFail::ManagerClass;
    r.subject_ok = user2_funnels_subject_ready(pj);
    return r;
}

std::string fmt_key(uint32_t k) { return k ? std::format("0x{:08X}", k) : std::string("none"); }

// ---------------------------------------------------------------- F1 (guest)

// 0x655110's entry (verified with capstone on the 2976 exe, p8-impl-viaje-rapido.md §3): mov [rsp+0x18],rbx ;
// mov [rsp+0x10],edx ; mov [rsp+8],rcx ; push rbp ; push rsi ; push rdi ; push r14 ; push r15 ;
// lea rbp,[rsp-0x1B0] ; sub rsp,0x2B0. No rip-relative instruction among them.
constexpr uintptr_t kFastTravel = 0x655110;
constexpr uint8_t kFastTravelBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x18, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89,
                                        0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48,
                                        0x8D, 0xAC, 0x24, 0x50, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xB0,
                                        0x02, 0x00, 0x00};
constexpr uint32_t kFastTravelBoundaries[] = {5, 9, 14, 15, 16, 17, 19, 21, 29, 36};
// Its callee that sends the point's 2283 (called from 0x6555C6 only), checked too so the lines can name it.
constexpr uintptr_t kFastTravelPoint = 0xA9A860;
constexpr uint8_t kFastTravelPointBytes[] = {0x44, 0x89, 0x4C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18,
                                             0x89, 0x54, 0x24, 0x10, 0x55, 0x53, 0x56, 0x57, 0x41, 0x56};
// The call 0x6555C6 (E8 rel32 -> 0xA9A860) inside 0x655110.
constexpr uintptr_t kPointCall = 0x6555C6;
constexpr uint8_t kPointCallBytes[] = {0xE8, 0x95, 0x52, 0x44, 0x00};

std::atomic<uint8_t> g_guest_mode{0};
std::atomic<bool> g_guest_started{false}, g_guest_on{false};
SafetyHookInline g_hook;
std::atomic<uint64_t> g_calls{0}, g_acts[static_cast<size_t>(ftl::GuestAct::Count)] = {};
p8p::EventRing<64> g_ring;
constexpr uint64_t kGuestLines = 200;
std::atomic<uint64_t> g_guest_lines{0};

// On the game's thread: atomics, the lock-free ring and (veto) two atomic stores for the HUD. No lock, no allocation.
uint64_t fast_travel_detour(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9) {
    g_calls.fetch_add(1, std::memory_order_relaxed);
    const auto mode = static_cast<ftl::Mode>(g_guest_mode.load(std::memory_order_relaxed));
    const bool remote = guest_remote_live();
    const ftl::GuestAct act = ftl::decide_guest(mode, remote);
    g_acts[static_cast<size_t>(act)].fetch_add(1, std::memory_order_relaxed);
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = 1;
    e.v[0] = static_cast<uint64_t>(act);
    e.v[1] = rdx & 0xFFFFFFFFull;  // edx: the point (-1 = none)
    e.v[2] = r8 & 0xFFFFFFFFull;   // r8d: its index
    e.v[3] = r9 & 0xFFFFFFFFull;   // r9d: an actor to travel to (0 = a point)
    e.v[4] = remote ? 1 : 0;
    e.v[5] = reinterpret_cast<uintptr_t>(_ReturnAddress());
    if (act == ftl::GuestAct::Veto) {
        render::hud_notice(render::Notice::FastTravelVetoed, 6000);
        g_ring.push(e);
        return 0;  // al = 0: "not sent", as the function's own refusal paths (0x6553A8, 0x6554F5, 0x6555D2)
    }
    const uint64_t r = g_hook.unsafe_call<uint64_t>(rcx, rdx, r8, r9);
    e.v[6] = r & 0xFF;
    e.v[7] = 1;  // the original ran
    if (act == ftl::GuestAct::NativeLogged || remote) g_ring.push(e);
    return r;
}

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

bool bytes_at(uintptr_t base, uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

bool player_in_world(uintptr_t base) {
    uintptr_t world = 0, mgr = 0, vt = 0, actor = 0, avt = 0;
    return peek(base + g2976::kWorldSystemSlot, world) && world &&
           peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
           vt == base + g2976::kVtClientActorManager && peek(mgr + g2976::kActorManager_ControlledActor, actor) &&
           actor && peek(actor, avt) && avt == base + g2976::kVtControlledActor;
}

void drain_guest() {
    p8p::Event e;
    while (g_ring.pop(e)) {
        if (g_guest_lines.fetch_add(1) >= kGuestLines) continue;
        const auto act = static_cast<ftl::GuestAct>(e.v[0]);
        const std::string what =
            e.v[3] ? std::format("to actor 0x{:08X}", e.v[3])
                   : std::format("to point {} (index {})", static_cast<int32_t>(e.v[1]), e.v[2]);
        const std::string line = std::format(
            "GuestFastTravel (guest_fast_travel_veto={}) {} T{}: 0x655110 {} from exe+0x{:X} | connection {} | {}{}",
            ftl::mode_name(static_cast<ftl::Mode>(g_guest_mode.load())), p8_when(e.qpc_us), e.tid, what,
            e.v[5] - reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)), e.v[4] ? "REMOTE (on the host)" : "local",
            ftl::guest_act_name(act),
            e.v[7] ? std::format(", it returned {}{}", e.v[6],
                                 e.v[4] ? " - a 2283 to the HOST: without user2_fast_travel=1 there the host drops it "
                                          "and this guest will be logged out (p8-s14-teleport-cierre.md)"
                                        : "")
                   : std::string(", HUD notice shown"));
        if (act == ftl::GuestAct::Veto || e.v[4]) {
            log::warn("{}", line);
        } else {
            log::info("{}", line);
        }
    }
}

DWORD WINAPI guest_thread(LPVOID) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<gad::Section> secs;
    if (base != g2976::kImageBase || !peek(base, dos) || !peek(base + dos.e_lfanew, nt) ||
        nt.FileHeader.TimeDateStamp != g2976::kPeTimestamp || !p8_exe_sections(base, secs)) {
        log::error("GuestFastTravel: unsupported game build or unreadable sections; guest_fast_travel_veto stays off");
        return 0;
    }
    log::info("GuestFastTravel: waiting for the local player in the world before hooking 0x655110");
    for (int stable = 0; stable < 6;) {
        Sleep(500);
        stable = player_in_world(base) ? stable + 1 : 0;
    }
    struct Site {
        uintptr_t rva;
        std::span<const uint8_t> bytes;
        const char* what;
    };
    const Site sites[] = {{kFastTravel, kFastTravelBytes, "the fast-travel entry 0x655110"},
                          {kFastTravelPoint, kFastTravelPointBytes, "its point sender 0xA9A860"},
                          {kPointCall, kPointCallBytes, "the call 0x6555C6 -> 0xA9A860"}};
    for (const Site& s : sites) {
        if (!gad::in_real_code(secs, static_cast<uint32_t>(s.rva), static_cast<uint32_t>(s.bytes.size())) ||
            !bytes_at(base, s.rva, s.bytes)) {
            log::error("GuestFastTravel: {} (exe+0x{:X}) is not build 2976's .rsrc code; REFUSED, nothing written",
                       s.what, s.rva);
            return 0;
        }
    }
    const auto* b = std::begin(kFastTravelBoundaries);
    const auto* e = std::end(kFastTravelBoundaries);
    auto whole = [&](const std::vector<uint8_t>& o) {
        return std::find(b, e, static_cast<uint32_t>(o.size())) != e && o.size() <= sizeof kFastTravelBytes &&
               std::memcmp(o.data(), kFastTravelBytes, o.size()) == 0;
    };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(base + kFastTravel, reinterpret_cast<void*>(&fast_travel_detour), whole,
                                  "GuestFastTravel", "0x655110");
    if (!h) {
        log::error("GuestFastTravel: the hook on 0x655110 could not be prepared ({}); REFUSED",
                   game::inline_error_text(h.error()));
        return 0;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("GuestFastTravel: the hook on 0x655110 would patch {} bytes, not whole verified instructions; "
                   "REFUSED, nothing written",
                   orig.size());
        return 0;
    }
    g_hook = std::move(*h);
    if (!g_hook.enable()) {
        log::error("GuestFastTravel: the hook on 0x655110 could not be enabled; REFUSED");
        g_hook = {};
        return 0;
    }
    g_guest_on.store(true);
    const auto mode = static_cast<ftl::Mode>(g_guest_mode.load());
    log::info("GuestFastTravel: guest_fast_travel_veto={} ON: exe+0x655110 hooked ({} bytes); while this game plays on "
              "the host: {}",
              ftl::mode_name(mode), orig.size(),
              mode == ftl::Mode::On ? "the map's fast travel returns 0 without effect and a HUD notice is shown"
                                    : "logged only (the travel goes on natively)");
    for (uint64_t tick = 1;; ++tick) {
        Sleep(250);
        drain_guest();
        if (tick % 240 == 0) {
            log::info("GuestFastTravel summary: calls {} | native {} | probe-logged {} | VETOED {} | events lost {}",
                      g_calls.load(), g_acts[0].load(), g_acts[1].load(), g_acts[2].load(), g_ring.dropped());
        }
    }
}

}  // namespace

// ---------------------------------------------------------------- host

void fast_travel_host_configure(const std::string& user2_fast_travel) {
    const ftl::ParsedMode m = ftl::parse_mode(user2_fast_travel);
    g_host_mode.store(static_cast<uint8_t>(m.mode));
    log::info("FastTravel F2 (host): user2_fast_travel={}: user 2's ReloadStageStartReq 2283 in the host's field is {}",
              ftl::mode_name(m.mode),
              m.mode == ftl::Mode::On
                  ? "handed to the server only while F3 is live and ExecuteTroc's subject recognises user 2's "
                    "character; otherwise DROPPED"
                  : m.mode == ftl::Mode::Probe
                        ? "DROPPED: probe only checks that F3 installs (its sites and the subject), it never lets a 2283 "
                          "through; the guest needs guest_fast_travel_veto=1 to stay in the game"
                        : "DROPPED (user2_fast_travel is not 1); the guest needs guest_fast_travel_veto=1 to stay in the "
                          "game");
}

FastTravelVerdict fast_travel_host_judge(uint16_t opcode, std::span<const uint8_t> payload) {
    FastTravelVerdict v;
    if (opcode != ftl::kOpReloadStageStartReq) return v;
    v.relevant = true;
    const Reading r = read_user2();
    ftl::GateIn in;
    in.opcode = opcode;
    in.f3 = static_cast<ftl::Mode>(g_host_mode.load());
    in.f3_live = user2_funnels_fast_travel_live();
    in.subject_ok = r.subject_ok;
    in.where = r.where;
    const ftl::Gate g = ftl::decide_gate(in);
    v.gate = static_cast<uint8_t>(g);
    v.drop = g == ftl::Gate::Drop;
    const auto p = ftl::parse_reload(payload);
    v.reload = p;
    v.size = payload.size();
    v.user2_user = r.user2_key;
    v.char_key = r.char_key;
    v.owner = r.owner;
    v.host_user = r.host_key;
    v.where = r.where;
    const std::string dest =
        p ? std::format("FieldInfoKey 0x{:X}, target actor {}, first u32 {}, position ({:.1f}, {:.1f}, {:.1f}), flag {}",
                        p->field_info_key, fmt_key(p->target_actor), p->a, p->pos[0], p->pos[1], p->pos[2], p->flag)
          : std::format("{} bytes (not the 53 of build 2976)", payload.size());
    v.line = std::format(
        "FastTravel F2: user 2's ReloadStageStartReq 2283 ({}) | user 2 (character {}) is in {} (owner {}, host {}, "
        "user 2 {}) | ExecuteTroc's subject {} | its own sequencer manager {} | F3 {} ({}) -> {}",
        dest, fmt_key(r.char_key), ftl::where_name(r.where), fmt_key(r.owner), fmt_key(r.host_key), fmt_key(r.user2_key),
        r.subject_ok ? "recognises it" : "would NOT recognise it", r.mgr_ok ? "readable" : ftl::mgr_fail_name(r.why),
        ftl::mode_name(in.f3), in.f3_live ? "live" : "not live", ftl::gate_name(g));
    return v;
}

void fast_travel_host_record(const FastTravelVerdict& v, const char* outcome) {
    if (!v.relevant) return;
    g_seen.fetch_add(1);
    if (v.gate < static_cast<uint8_t>(ftl::Gate::Count)) g_gates[v.gate].fetch_add(1);
    if (travel_probe_on()) {
        TravelBeginInfo b;
        b.reload = v.reload ? &*v.reload : nullptr;
        b.size = v.size;
        b.user2_user = v.user2_user;
        b.char_key = v.char_key;
        b.owner = v.owner;
        b.host_user = v.host_user;
        b.where = ftl::where_name(v.where);
        b.gate = ftl::gate_name(static_cast<ftl::Gate>(v.gate));
        b.outcome = outcome;
        travel_probe_begin(b);
    }
    if (g_lines.fetch_add(1) >= kDropLines) return;
    if (v.drop) {
        log::warn("{} ({}); the guest's client is already loading: without guest_fast_travel_veto=1 it will be logged "
                  "out (eErrNoInvalidFieldInfoKey)",
                  v.line, outcome);
    } else {
        log::info("{} ({})", v.line, outcome);
    }
}

ftl::Where fast_travel_user2_where(uint32_t* owner) noexcept {
    try {
        const Reading r = read_user2();
        if (owner) *owner = r.owner;
        return r.where;
    } catch (...) {
        return ftl::Where::Unknown;
    }
}

std::string fast_travel_host_describe() {
    return std::format("fast travel 2283 of user 2: {} (to the server with F3 {}, own field {}, DROPPED {})",
                       g_seen.load(), g_gates[static_cast<size_t>(ftl::Gate::PassF3)].load(),
                       g_gates[static_cast<size_t>(ftl::Gate::Pass)].load(),
                       g_gates[static_cast<size_t>(ftl::Gate::Drop)].load());
}

// ---------------------------------------------------------------- guest

void guest_fast_travel_start(const std::string& mode) {
    const ftl::ParsedMode m = ftl::parse_mode(mode);
    if (!m.known) log::warn("GuestFastTravel: guest_fast_travel_veto='{}' is not 0, probe or 1; off", mode);
    g_guest_mode.store(static_cast<uint8_t>(m.mode));
    if (m.mode == ftl::Mode::Off) {
        log::info("GuestFastTravel: guest_fast_travel_veto=0: the map's fast travel is native (on the host it ends in a "
                  "logout unless the host runs user2_fast_travel=1)");
        return;
    }
    if (g_guest_started.exchange(true)) return;
    CloseHandle(CreateThread(nullptr, 0, guest_thread, nullptr, 0, nullptr));
}

}  // namespace cdmp::session2
