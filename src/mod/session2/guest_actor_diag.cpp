#include "mod/session2/guest_actor_diag.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "mod/game/character_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/net/horse_diag.h"
#include "mod/net/remote_puppet.h"
#include "mod/session2/companion_probe.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_reload_wait.h"
#include "mod/session2/guest_s3.h"
#include "mod/session2/load_trip.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;

// ---------------------------------------------------------------- the points (build 2976, .rsrc)

// FinishGroup 0x4FD2E0 (cdmp_ActorLogin_FinishGroup). Per actor of the group:
// 0x4FD390 mov rdi,[rsi+8] (the actor) ; ... ; 0x4FD3AA cmp word [rdi+0x5E],8 ;
// je ; mov ebp,[exe+0x6CDB92C] ; test ; jne 0x4FD488 (unlock, then the error) ;
// ... 0x4FD3E0 call [rax+0x140] (loginCharacter) ; mov ebp,[rax] ; test ; jne
// 0x4FD491. 0x4FD491 (lea rax,[rip+..], 7 bytes) is the error branch both paths
// share: rdi = actor, ebp = the error. No rel32 branch of any executable
// section lands in 0x4FD492..0x4FD497 (raw scan of the read-only copy) and the
// function's own short branches do not either (capstone, linear).
constexpr uintptr_t kFinishHead = 0x4FD2E0;
constexpr uint8_t kFinishHeadBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C,
                                        0x24, 0x10, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56};
constexpr uintptr_t kFinishActor = 0x4FD390;
constexpr uint8_t kFinishActorBytes[] = {0x48, 0x8B, 0x7E, 0x08, 0x48, 0x8D, 0x5F, 0x18};
constexpr uintptr_t kFinishState = 0x4FD3AA;
constexpr uint8_t kFinishStateBytes[] = {0x66, 0x83, 0x7F, 0x5E, 0x08, 0x74, 0x0E, 0x8B, 0x2D, 0x75, 0xE5,
                                         0x7D, 0x06, 0x85, 0xED, 0x0F, 0x85, 0xC9, 0x00, 0x00, 0x00};
constexpr uintptr_t kFinishLogin = 0x4FD3E0;
constexpr uint8_t kFinishLoginBytes[] = {0xFF, 0x90, 0x40, 0x01, 0x00, 0x00, 0x8B, 0x28,
                                         0x85, 0xED, 0x0F, 0x85, 0xA1, 0x00, 0x00, 0x00};
constexpr uintptr_t kFinishError = 0x4FD488;
constexpr uint8_t kFinishErrorBytes[] = {0x48, 0x8B, 0x03, 0x48, 0x8B, 0xCB, 0xFF, 0x50, 0x10, 0x48, 0x8D,
                                         0x05, 0xD8, 0x94, 0x08, 0x05, 0x48, 0x89, 0x44, 0x24, 0x58, 0xC7,
                                         0x44, 0x24, 0x50, 0x06, 0x00, 0x00, 0x00, 0x89, 0x6C, 0x24, 0x48};
constexpr uintptr_t kFinishErrorHook = kFinishError + 9;  // 0x4FD491
constexpr uint32_t kFinishErrorPatch = 7;                 // the relocated lea
// The "actor +0x5E != 8" error (0x4FD3B1) and eErrNoInvalidActionChart (0x863995),
// both u32 globals the game fills at start (0 in the file).
constexpr uintptr_t kErrStateGlobal = 0x6CDB92C;
constexpr uintptr_t kErrActionChartGlobal = 0x6CF6C50;
constexpr uint32_t kErrActionChart = 0x349EFD61;     // lookup3 of the name (p8-actores-anfitrion.md §1.3)
constexpr uint32_t kErrCharacterData = 0xD9917FF3;   // eErrNoInvalidCharacterData (§1.4)

// The restore: cmp::kRestore* (companion_probe.h). Patched bytes: 0x8646FC
// mov rsi,rdx + mov r13,rcx (6); 0x864B1D mov rax,rsi + lea r11,[rsp+0x160] (11).
constexpr uint32_t kRestorePatch = 6, kRestoreExitPatch = 11;

// The field-change state machine 0x7797F0 (rcx = P): movzx r14d,byte [rdi+0x15C]
// at 0x7798D0; state 0x12 at 0x779ED0: mov rdx,[rsi+0x78] ; mov edx,[rdx] ; mov
// rcx,[r14+8] ; call 0x464290 (Find) ... call [rcx+0x1D8].
constexpr uintptr_t kWorldSystem_FieldChange = 0x60;  // P = [WorldSystem+0x60] (§3)
constexpr uint32_t kP_State = 0x15C;                  // u8
constexpr uint32_t kP_Manager = 0xB8;                 // M; its +0x10 is the lock state 0x12 takes
constexpr uint32_t kManager_Container = 0x08;         // C = ClientActorContainer
constexpr uint32_t kContainer_WaitKeys = 0x78;        // u32*
constexpr uint32_t kContainer_WaitCount = 0x80;       // u32
constexpr uintptr_t kStateSite = 0x7798D0;
constexpr uint8_t kStateSiteBytes[] = {0x44, 0x0F, 0xB6, 0xB7, 0x5C, 0x01, 0x00, 0x00};
// The state's transitions as they happen (p8-raiz-invitado.md §4.3, §7.2): a
// mid hook on that read, movzx r14d,byte [rdi+0x15C] (8 bytes, patch 8), then
// mov [rbp+0xD0],r14b. 0x7797F0 jumps back to 0x7798B6 whenever a state
// handler changed [rdi+0x15C] (0x77A1B0..0x77A1BD), so every value a call goes
// through passes here. RDI = P since 0x779823. No branch of the function nor
// any rel32 of .rsrc/.xtls/.text lands in 0x7798D1..0x7798D7 (p8-impl-s1s2.md §2).
constexpr uint32_t kStatePatch = 8;
constexpr uint8_t kStateHookBytes[] = {0x44, 0x0F, 0xB6, 0xB7, 0x5C, 0x01, 0x00, 0x00,
                                       0x44, 0x88, 0xB5, 0xD0, 0x00, 0x00, 0x00};
constexpr uintptr_t kWaitSite = 0x779ED0;
constexpr uint8_t kWaitSiteBytes[] = {0x48, 0x8B, 0x56, 0x78, 0x8B, 0x12, 0x49, 0x8B, 0x4E, 0x08, 0xE8, 0xB1,
                                      0xA3, 0xCE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x13, 0x48, 0x8B, 0x08, 0x48,
                                      0x8B, 0x91, 0xD8, 0x01, 0x00, 0x00};
constexpr uintptr_t kFind = 0x464290;
constexpr uint8_t kFindBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x83, 0xB9, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x44,
                                  0x8B, 0xC2, 0x4C, 0x8B, 0xD1, 0x74, 0x4F, 0x8B, 0x89, 0x88, 0x00, 0x00, 0x00,
                                  0x85, 0xC9, 0x74, 0x45, 0x33, 0xD2, 0x41, 0x8B, 0xC0, 0xF7, 0xF1, 0x44, 0x8B,
                                  0xDA, 0x33, 0xD2, 0x49, 0xC1, 0xE3, 0x08, 0x4D, 0x03, 0x9A, 0x98, 0x00, 0x00,
                                  0x00, 0x41, 0x8B, 0x1B};
// vf1D8 = 0x4FE240: +0xC2 && +0xCF (read here, never called).
constexpr uint32_t kActor_State = 0x5E, kActor_C2 = 0xC2, kActor_CF = 0xCF;

constexpr uint64_t kFinishLines = 64, kRestoreFailLines = 64, kRestoreOkLines = 16, kGuardLines = 64;
constexpr uint64_t kTickLines = 400, kTransitionLines = 400;
// Every key of the wait list up to 1024 (the session-4 list had 173; the first
// version read 64), with the slots it could not read counted (§4.3).
constexpr size_t kWaitRead = 1024, kWaitShown = 16;

// ---------------------------------------------------------------- state

uintptr_t g_base = 0, g_image_end = 0;
std::vector<gad::Section> g_secs;  // written once by the install thread before any hook goes in
std::atomic<bool> g_diag{false}, g_guard{false}, g_started{false};
std::atomic<bool> g_finish_on{false}, g_restore_on{false}, g_wait_on{false}, g_guard_on{false}, g_state_on{false};
// S34 guest_remote_update_guard (net/horse_diag.h): wanted / installed / tried (the install thread only).
std::atomic<bool> g_rug{false}, g_rug_on{false};
bool g_rug_tried = false;
std::atomic<uint32_t> g_local{0};
SafetyHookMid g_finish, g_restore, g_restore_exit, g_state;

// The loading state's transitions (the hook at 0x7798D0 -> the install thread).
p8p::EventRing<256> g_state_ring;
std::atomic<int> g_state_seen{-1};
std::atomic<uint64_t> g_state_hits{0}, g_state_changes{0}, g_state_other_p{0};
gad::LineBudget g_transition_lines{kTransitionLines};
uint64_t g_state_since_us = 0;  // install thread only: when the current state began
int g_state_since_value = -1;

gad::LineBudget g_finish_lines{kFinishLines}, g_restore_fail_lines{kRestoreFailLines},
    g_restore_ok_lines{kRestoreOkLines}, g_guard_lines{kGuardLines}, g_tick_lines{kTickLines};
gad::KeySet<1024> g_failed_login;    // keys FinishGroup failed
gad::KeySet<1024> g_failed_restore;  // keys whose restore returned an error
gad::KeySet<4096> g_guard_keys;      // keys the guard held at least once

std::atomic<uint64_t> g_fin_total{0}, g_fin_remote{0}, g_fin_chart{0};
std::atomic<uint32_t> g_fin_last_key{0}, g_fin_last_code{0};
std::atomic<uint64_t> g_rs_calls{0}, g_rs_remote{0}, g_rs_no_local{0}, g_rs_byte0{0}, g_rs_ok{0}, g_rs_chart{0},
    g_rs_other{0}, g_rs_after_no_action{0};
std::atomic<uint32_t> g_rs_last_fail_key{0};
std::atomic<uint64_t> g_guard_skips{0};
std::atomic<uint32_t> g_guard_last_key{0};
std::atomic<int> g_tick_state{-1};
std::atomic<uint32_t> g_tick_wait{0}, g_tick_blocker{0};
std::atomic<uint64_t> g_tick_12_since{0};  // GetTickCount64 when state 0x12 began (0 = not in it)

// SEH only, no VirtualQuery (p8-hilo-red.md): on the Shadow guest each
// VirtualQuery of the game's heap cost ~0.5-2 ms during a field load, and the
// 5 s wait-list walk (~20 reads per key, 193 keys) took 2.5-8 s with them.
// Used on the game's threads too (the restore hooks). Heap objects only,
// never thread stacks (a guard page would be consumed): game::fast_read.
template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::fast_read(a, &v, sizeof v);
}

uintptr_t peekp(uintptr_t a) {
    uintptr_t v = 0;
    return peek(a, v) ? v : 0;
}

// The hot path (the guard's observer and the mid hooks): plain SEH, no VirtualQuery, inline.
template <class T>
bool fast_peek(uintptr_t a, T& v) {
    if (!a) return false;
    __try {
        v = *reinterpret_cast<const volatile T*>(a);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::string rva(uintptr_t a) {
    if (a >= g_base && a < g_image_end) return std::format("exe+0x{:X}", a - g_base);
    return std::format("0x{:X}", a);
}

uint32_t err_global(uintptr_t at) {
    uint32_t v = 0;
    return peek(g_base + at, v) ? v : 0;
}

std::string error_name(uint32_t code) {
    if (code == 0) return "ok";
    const uint32_t chart = err_global(kErrActionChartGlobal);
    if (code == kErrActionChart || (chart && code == chart)) return "eErrNoInvalidActionChart";
    if (code == kErrCharacterData) return "eErrNoInvalidCharacterData";
    if (const uint32_t st = err_global(kErrStateGlobal); st && code == st) return "actor +0x5E != 8 (exe+0x6CDB92C)";
    return "other";
}

bool is_chart_error(uint32_t code) {
    const uint32_t chart = err_global(kErrActionChartGlobal);
    return code && (code == kErrActionChart || (chart && code == chart));
}

// ---------------------------------------------------------------- sections and bytes

bool read_sections() {
    g_secs.clear();
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!peek(g_base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || !peek(g_base + dos.e_lfanew, nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    g_image_end = g_base + nt.OptionalHeader.SizeOfImage;
    const uintptr_t first = g_base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                            nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections && i < 64; ++i) {
        IMAGE_SECTION_HEADER h{};
        if (!peek(first + i * sizeof h, h)) return false;
        gad::Section s;
        std::memcpy(s.name, h.Name, 8);
        s.va = h.VirtualAddress;
        s.size = h.Misc.VirtualSize;
        s.flags = h.Characteristics;
        g_secs.push_back(s);
    }
    return !g_secs.empty();
}

std::string rsrc_text() {
    for (const gad::Section& s : g_secs) {
        if (gad::is_real_code(s)) {
            return std::format("hooked bytes checked inside {} [exe+0x{:X}, exe+0x{:X})", s.name, s.va,
                               static_cast<uint64_t>(s.va) + s.size);
        }
    }
    return "no real code section";
}

// The hook's patched bytes must be real code: .rsrc, never .xtls.
bool code_section_ok(uintptr_t at, uint32_t len, const char* what) {
    if (gad::in_real_code(g_secs, static_cast<uint32_t>(at), len)) return true;
    const gad::Section* s = gad::section_of(g_secs, static_cast<uint32_t>(at));
    log::error("GuestDiag: {} (exe+0x{:X}, {} bytes) is not inside .rsrc (section {}); REFUSED, not hooked", what, at,
               len, s ? s->name : "none");
    return false;
}

bool bytes_match(uintptr_t at, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + at, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

struct Check {
    uintptr_t at;
    std::span<const uint8_t> bytes;
};

bool all_match(std::span<const Check> checks) {
    return std::all_of(checks.begin(), checks.end(), [](const Check& c) { return bytes_match(c.at, c.bytes); });
}

std::string first_mismatch(std::span<const Check> checks) {
    for (const Check& c : checks) {
        if (!bytes_match(c.at, c.bytes)) return std::format("exe+0x{:X}", c.at);
    }
    return "none";
}

const Check kFinishChecks[] = {{kFinishHead, kFinishHeadBytes},   {kFinishActor, kFinishActorBytes},
                               {kFinishState, kFinishStateBytes}, {kFinishLogin, kFinishLoginBytes},
                               {kFinishError, kFinishErrorBytes}};
const Check kRestoreChecks[] = {{cmp::kRestoreSite, cmp::kRestoreSiteBytes},
                                {cmp::kRestoreLock, cmp::kRestoreLockBytes},
                                {cmp::kRestartCall, cmp::kRestartCallBytes},
                                {cmp::kRestoreExit, cmp::kRestoreExitBytes}};
const Check kWaitChecks[] = {{kStateSite, kStateSiteBytes}, {kWaitSite, kWaitSiteBytes}, {kFind, kFindBytes}};
bool guard_checks_match() {
    return game::character_profile::matches(g_base, g2976::kActionLayerAdvance,
                                            g2976::kActionLayerAdvanceHead) &&
           game::character_profile::matches(g_base, g2976::kActionLayersAdvance,
                                            g2976::kActionLayersAdvanceHead);
}

std::string guard_mismatch() {
    if (!game::character_profile::matches(g_base, g2976::kActionLayerAdvance,
                                          g2976::kActionLayerAdvanceHead)) {
        return std::format("exe+0x{:X}", game::character_profile::rva(g2976::kActionLayerAdvance));
    }
    if (!game::character_profile::matches(g_base, g2976::kActionLayersAdvance,
                                          g2976::kActionLayersAdvanceHead)) {
        return std::format("exe+0x{:X}", game::character_profile::rva(g2976::kActionLayersAdvance));
    }
    return "none";
}

// ---------------------------------------------------------------- 1. FinishGroup's error

struct ActorSnap {
    uintptr_t p = 0, vt = 0;
    uint32_t key = 0, control = 0;
    uint16_t state = 0;
    bool ok = false;
};

ActorSnap read_actor_fast(uintptr_t actor) {
    ActorSnap a;
    a.p = actor;
    a.ok = actor && fast_peek(actor, a.vt) && fast_peek(actor + g2976::kActor_Key, a.key) &&
           fast_peek(actor + g2976::kActor_OwnerUser, a.control) && fast_peek(actor + kActor_State, a.state);
    return a;
}

void on_finish_error(safetyhook::Context& ctx) noexcept {
    g_fin_total.fetch_add(1, std::memory_order_relaxed);
    const ActorSnap a = read_actor_fast(ctx.rdi);
    const uint32_t code = static_cast<uint32_t>(ctx.rbp);
    const uint32_t local = g_local.load(std::memory_order_relaxed);
    const bool remote = gad::remote_controlled(a.control, local);
    if (remote) g_fin_remote.fetch_add(1, std::memory_order_relaxed);
    if (a.ok) g_failed_login.insert(a.key);
    g_fin_last_key.store(a.key, std::memory_order_relaxed);
    g_fin_last_code.store(code, std::memory_order_relaxed);
    try {
        if (is_chart_error(code)) g_fin_chart.fetch_add(1, std::memory_order_relaxed);
        if (!g_finish_lines.take()) return;
        log::info("GuestDiag login FAILED (FinishGroup exe+0x4FD491): actor 0x{:X} key 0x{:08X} control(+0x90) "
                  "0x{:08X} ({}) vt {} +5E 0x{:04X} | error 0x{:08X} ({}) | local user 0x{:08X}{}",
                  a.p, a.key, a.control,
                  !local ? "local user unknown" : remote ? "NOT controlled here" : "controlled here", rva(a.vt),
                  a.state, code, error_name(code), local, a.ok ? "" : " | actor unreadable");
    } catch (...) {
    }
}

// ---------------------------------------------------------------- 2. the restore

struct LayerSnap {
    bool present = false;
    uintptr_t chart = 0, def = 0, current = 0, playback = 0;
    uint32_t hash = 0;
};

struct RestoreFrame {
    uintptr_t cc = 0, cc_vt = 0, actor_vt = 0;
    uint32_t key = 0, control = 0;
    int restore = -1;
    LayerSnap layer[2];
};
thread_local RestoreFrame t_rf;
thread_local bool t_rf_on = false;

// A LayerSnap packed for the restore ring: bit 0 present, 1 chart, 2 default
// chart, 3 current, 4 playback; the hash (+0x3C) in the high 32 bits.
uint64_t layer_bits(const LayerSnap& l) {
    return static_cast<uint64_t>((l.present ? 1 : 0) | (l.chart ? 2 : 0) | (l.def ? 4 : 0) | (l.current ? 8 : 0) |
                                 (l.playback ? 16 : 0)) |
           static_cast<uint64_t>(l.hash) << 32;
}

std::string layer_text_bits(uint64_t b) {
    if (!(b & 1)) return "none";
    return std::format("chart {} hash(+3C) 0x{:08X} default chart {} cur {} play {}", (b & 2) ? "yes" : "NO", b >> 32,
                       (b & 4) ? "yes" : "NO", (b & 8) ? 1 : 0, (b & 16) ? 1 : 0);
}

// The restore lines (on_restore_exit -> the 5 s tick).
p8p::EventRing<256> g_restore_ring;
std::atomic<uint64_t> g_restore_ring_lost{0};
uint64_t g_restore_ring_lost_logged = 0;  // tick only

void on_restore(safetyhook::Context& ctx) noexcept {
    g_rs_calls.fetch_add(1, std::memory_order_relaxed);
    t_rf_on = false;
    try {
        CompControl c;
        if (!comp_read_control(ctx.rcx, c)) return;
        const uint32_t local = g_local.load(std::memory_order_relaxed);
        if (!local) {
            g_rs_no_local.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (!gad::remote_controlled(c.owner, local)) return;
        g_rs_remote.fetch_add(1, std::memory_order_relaxed);
        RestoreFrame& f = t_rf;
        f = RestoreFrame{};
        f.cc = ctx.rcx;
        f.cc_vt = c.cc_vt;
        f.actor_vt = c.actor_vt;
        f.key = c.key;
        f.control = c.owner;
        f.restore = c.restore;
        for (uint32_t i = 0; i < 2; ++i) {
            LayerSnap& l = f.layer[i];
            const uintptr_t lp = peekp(ctx.rcx + cmp::kCcLayer0 + 8 * i);
            l.def = peekp(ctx.rcx + cmp::kCcDefaultChart0 + 8 * i);
            if (!lp) continue;
            l.present = true;
            l.chart = c.layer[i].chart;
            l.current = c.layer[i].current;
            l.playback = c.layer[i].playback;
            peek(lp + cmp::kLayerRestoreHash, l.hash);
        }
        t_rf_on = true;
    } catch (...) {
    }
}

void on_restore_exit(safetyhook::Context& ctx) noexcept {
    if (!t_rf_on || ctx.r13 != t_rf.cc) return;
    t_rf_on = false;
    try {
        const RestoreFrame& f = t_rf;
        uint32_t code = 0;
        const bool code_ok = peek(ctx.rsi, code);
        const char* verdict = nullptr;
        bool fail = false;
        if (f.restore == 0) {
            g_rs_byte0.fetch_add(1, std::memory_order_relaxed);
            verdict = "restore byte 0: nothing restored (native)";
        } else if (code_ok && code == 0) {
            g_rs_ok.fetch_add(1, std::memory_order_relaxed);
            verdict = "restored";
        } else if (code_ok && is_chart_error(code)) {
            g_rs_chart.fetch_add(1, std::memory_order_relaxed);
            verdict = "RestartLayerAction 0x863880 FAILED";
            fail = true;
        } else {
            g_rs_other.fetch_add(1, std::memory_order_relaxed);
            verdict = "FAILED (other)";
            fail = true;
        }
        if (fail) {
            g_failed_restore.insert(f.key);
            g_rs_last_fail_key.store(f.key, std::memory_order_relaxed);
        }
        guest_s3_note_restore(f.key, f.control, f.restore, code, code_ok);  // S3 history (no-op when off)
        // §3.4: the layers again at the single exit, after RestartLayerAction
        // 0x863880 (and 0x2329A90 when it succeeded) ran: what the restore left.
        CompControl after;
        const bool after_ok = comp_read_control(ctx.r13, after);
        bool after_no_action = false;
        for (uint32_t i = 0; after_ok && i < 2; ++i) after_no_action |= after.layer[i].would_crash();
        if (after_no_action) g_rs_after_no_action.fetch_add(1, std::memory_order_relaxed);
        if (!(fail ? g_restore_fail_lines : g_restore_ok_lines).take()) return;
        // M7: no formatting on the game's thread: a fixed record, formatted by
        // the 5 s tick (restore_report).
        p8p::Event e;
        e.v[0] = f.key | static_cast<uint64_t>(f.control) << 32;
        e.v[1] = f.actor_vt;
        e.v[2] = f.cc_vt;
        e.v[3] = static_cast<uint64_t>(f.restore < 0 ? 0xFF : f.restore & 0xFF) |
                 static_cast<uint64_t>(code_ok) << 8 | static_cast<uint64_t>(after_ok) << 9 |
                 static_cast<uint64_t>(after_no_action) << 10 | static_cast<uint64_t>(code) << 32;
        e.v[4] = layer_bits(f.layer[0]);
        e.v[5] = layer_bits(f.layer[1]);
        for (uint32_t i = 0; after_ok && i < 2; ++i) {
            const CompLayer& l = after.layer[i];
            e.v[6] |= static_cast<uint64_t>((l.present ? 1 : 0) | (l.chart ? 2 : 0) | (l.current ? 4 : 0) |
                                            (l.playback ? 8 : 0))
                      << (4 * i);
        }
        e.v[7] = reinterpret_cast<uint64_t>(verdict);  // a string literal
        e.qpc_us = p8_now_us();
        e.tid = GetCurrentThreadId();
        if (!g_restore_ring.push(e)) g_restore_ring_lost.fetch_add(1, std::memory_order_relaxed);
    } catch (...) {
    }
}

// The 5 s tick: the restore lines queued by on_restore_exit.
void restore_report() {
    p8p::Event e;
    while (g_restore_ring.pop(e)) {
        const uint64_t* v = e.v;
        const bool code_ok = (v[3] >> 8) & 1, after_ok = (v[3] >> 9) & 1, after_no_action = (v[3] >> 10) & 1;
        const uint32_t code = static_cast<uint32_t>(v[3] >> 32);
        const uint32_t restore = v[3] & 0xFF;
        auto after_text = [&](uint32_t i) {
            const uint64_t b = (v[6] >> (4 * i)) & 0xF;
            if (!(b & 1)) return std::string("none");
            return std::format("chart {} cur {} play {}", (b & 2) ? "yes" : "NO", (b & 4) ? 1 : 0, (b & 8) ? 1 : 0);
        };
        log::info("GuestDiag restore (0x8646D0 -> exit 0x864B1D) actor key 0x{:08X} control 0x{:08X} vt {} CC vt {} | "
                  "restore byte [[CC+0x40]+0x30] {} | before: L0 {} | L1 {} | result {} ({}) -> {} | after (exit): {} "
                  "| T{} {}",
                  v[0] & 0xFFFFFFFF, v[0] >> 32, rva(v[1]), rva(v[2]),
                  restore == 0xFF ? std::string("?") : std::to_string(restore), layer_text_bits(v[4]),
                  layer_text_bits(v[5]), code_ok ? std::format("0x{:08X}", code) : std::string("unreadable"),
                  code_ok ? error_name(code) : std::string("-"), reinterpret_cast<const char*>(v[7]),
                  after_ok ? std::format("L0 {} | L1 {}{}", after_text(0), after_text(1),
                                         after_no_action ? " | a layer has a chart and NO action" : "")
                           : std::string("CC unreadable"),
                  e.tid, p8_when(e.qpc_us));
    }
    const uint64_t lost = g_restore_ring_lost.load();
    if (lost != g_restore_ring_lost_logged) {
        log::warn("GuestDiag: {} restore line(s) lost (ring full)", lost - g_restore_ring_lost_logged);
        g_restore_ring_lost_logged = lost;
    }
}

// ---------------------------------------------------------------- B. the layer guard's observer

void on_guard_skip(uint32_t key, uint32_t control) noexcept {
    g_guard_skips.fetch_add(1, std::memory_order_relaxed);
    if (g_guard_keys.insert(key) != gad::KeySet<4096>::Insert::Added) return;
    g_guard_last_key.store(key, std::memory_order_relaxed);
    if (!g_guard_lines.take()) return;
    try {
        // S3 (p8-raiz-invitado.md §5.2): say which pointer is missing (same thread as the skip).
        log::info("GuestDiag guard: holding actor 0x{:08X} (control 0x{:08X}, not the local user 0x{:08X}): {}; its "
                  "layer update (0x2329700) is skipped until its first action{}{}",
                  key, control, g_local.load(std::memory_order_relaxed),
                  net::puppet_guard_reason_text(net::puppet_guard_last_reason()),
                  g_failed_login.contains(key) ? " | its login FAILED" : "",
                  g_failed_restore.contains(key) ? " | its restore FAILED" : "");
    } catch (...) {
    }
}

// ---------------------------------------------------------------- the local user key

void refresh_local() noexcept {
    try {
        // Build 1.0.0.3576 (static, 2026-11-06; not yet run): no reader profile yet; world slot 0x71C0100
        // (core_globals_3576.json), ClientActorManager vtable 0x5946C40 (RTTI).
        // Build 1.0.0.3663 (static, 2026-11-13; never run): world slot 0x72451C0 (profile_s2.h rva3663), ClientActorManager
        // vtable 0x59C2760 (RTTI).
        uintptr_t world_slot = 0, vt_mgr = 0;
        if (game::current_build() == game::Build::v3663) {
            world_slot = 0x72451C0;
            vt_mgr = 0x59C2760;
        } else if (game::current_build() == game::Build::v3576) {
            world_slot = 0x71C0100;
            vt_mgr = 0x5946C40;
        } else if (const auto* profile = game::reader_profile()) {
            world_slot = profile->world_system;
            vt_mgr = profile->vt_actor_manager;
        } else {
            return;
        }
        const auto ws = game::read_ptr(g_base + world_slot);
        const auto mgr = ws ? game::read_ptr(*ws + g2976::kWorldSystem_ActorManager) : std::nullopt;
        if (!mgr || !game::has_vtable(*mgr, g_base + vt_mgr)) return;
        const auto ctrl = game::read_ptr(*mgr + g2976::kActorManager_ControlledActor);
        uint32_t key = 0;
        if (!ctrl || !peek(*ctrl + g2976::kActor_OwnerUser, key)) return;
        if (comp_key_class(key) != KeyClass::User) return;  // not a user key yet (title, loading)
        const uint32_t old = g_local.exchange(key);
        if (old == key) return;
        uint32_t own = 0;
        peek(*ctrl + g2976::kActor_Key, own);
        log::info("GuestDiag: local user key 0x{:08X} (controlled actor 0x{:08X} at 0x{:X}){}", key, own, *ctrl,
                  old ? std::format("; was 0x{:08X}", old) : std::string());
        if (g_guard_on.load()) net::puppet_guard_not_controlled_by(key, &on_guard_skip);
        if (g_rug_on.load()) net::horse_diag_contain_remote(key);
    } catch (...) {
    }
}

// ---------------------------------------------------------------- 3. the loading state and its wait list

struct GameMem {
    bool u32(uintptr_t a, uint32_t& v) const { return peek(a, v); }
    bool ptr(uintptr_t a, uintptr_t& v) const { return peek(a, v); }
};

void tick_wait_list() {
    const uintptr_t ws = peekp(g_base + g2976::kWorldSystemSlot);
    const uintptr_t p = ws ? peekp(ws + kWorldSystem_FieldChange) : 0;
    uint8_t state = 0;
    if (!p || !peek(p + kP_State, state)) return;
    const uintptr_t m = peekp(p + kP_Manager);
    const uintptr_t c = m ? peekp(m + kManager_Container) : 0;
    const uintptr_t keys = c ? peekp(c + kContainer_WaitKeys) : 0;
    uint32_t n = 0;
    if (c) peek(c + kContainer_WaitCount, n);
    // Find's header once for the whole walk (the game may change it meanwhile:
    // every read is guarded, a stale entry only gives a wrong line).
    const gad::ContainerView view = gad::container_view(GameMem{}, c);
    // Every slot up to kWaitRead (§4.3): a slot whose key cannot be read is
    // counted and kept (key_ok = false), never a reason to stop reading.
    std::vector<gad::WaitRead> list;
    std::vector<uint32_t> controls;
    const uint32_t read_n = keys ? static_cast<uint32_t>(std::min<size_t>(n, kWaitRead)) : 0;
    list.reserve(read_n);
    controls.reserve(read_n);
    for (uint32_t i = 0; i < read_n; ++i) {
        gad::WaitRead r;
        uint32_t control = 0;
        r.key_ok = peek(keys + 4 * static_cast<uintptr_t>(i), r.e.key);
        if (r.key_ok) {
            if (const uintptr_t actor = gad::container_find_in(GameMem{}, view, r.e.key)) {
                r.e.found = peek(actor + kActor_State, r.e.state) && peek(actor + kActor_C2, r.e.c2) &&
                            peek(actor + kActor_CF, r.e.cf);
                peek(actor + g2976::kActor_OwnerUser, control);
                // P8 S15 (guest_reload_wait.h): since when each key is not ready (no-op when that key is off).
                if (r.e.found) guest_reload_wait_note_entry(r.e.key, gad::entry_ready(r.e));
            }
        }
        list.push_back(r);
        controls.push_back(control);
    }
    const gad::WaitScan scan = gad::scan_wait_list(list, n);
    const uint32_t blocker_key = scan.verdict == gad::WaitVerdict::Blocks ? scan.key : 0;
    const int old_state = g_tick_state.exchange(state);
    const uint64_t now = GetTickCount64();
    if (state == 0x12) {
        uint64_t zero = 0;
        g_tick_12_since.compare_exchange_strong(zero, now);
    } else {
        g_tick_12_since.store(0);
    }
    const uint32_t old_n = g_tick_wait.exchange(n);
    g_tick_blocker.store(blocker_key);
    // Quiet when nothing waits and nothing changed.
    if (old_state == state && n == 0 && old_n == 0) return;
    if (!g_tick_lines.take()) return;
    // The slots that can hold the state (not ready or unreadable) first, in list order.
    std::string s;
    size_t shown = 0, worth = 0;
    for (size_t i = 0; i < list.size(); ++i) {
        const gad::WaitRead& r = list[i];
        const bool interesting = !r.key_ok || (r.e.found && !gad::entry_ready(r.e));
        if (!interesting) continue;
        ++worth;
        if (shown >= kWaitShown) continue;
        ++shown;
        if (!r.key_ok) {
            s += std::format(" #{} UNREADABLE", i);
            continue;
        }
        const gad::WaitEntry& e = r.e;
        s += std::format(" #{} 0x{:08X}(+5E 0x{:04X} C2 {} CF {} ctrl 0x{:08X} NOT READY{}{})", i, e.key, e.state,
                         unsigned{e.c2}, unsigned{e.cf}, controls[i],
                         g_failed_login.contains(e.key) ? " LOGIN FAILED" : "",
                         g_failed_restore.contains(e.key) ? " RESTORE FAILED" : "");
    }
    if (worth > shown) s += std::format(" ... (+{})", worth - shown);
    std::string verdict;
    switch (scan.verdict) {
        case gad::WaitVerdict::Empties: verdict = "nobody (the list empties)"; break;
        case gad::WaitVerdict::Blocks: verdict = std::format("0x{:08X} (slot #{})", scan.key, scan.index); break;
        case gad::WaitVerdict::Undetermined:
            verdict = scan.garbage_count ? std::string("? (count not plausible)")
                                         : std::format("? (the replay reaches slot #{}, {})", scan.index,
                                                       static_cast<size_t>(scan.index) < list.size()
                                                           ? "unreadable"
                                                           : "beyond the slots read");
            break;
    }
    const uint64_t since = g_tick_12_since.load();
    log::info("GuestDiag loading: state [P+0x15C] 0x{:02X}{} (P 0x{:X}, M 0x{:X}, container 0x{:X}) | wait list total {} "
              "inspected {} unreadable {} | not found {} ready {} NOT READY {} | not ready / unreadable:{} | state 0x12 "
              "waits for {}{}",
              state, old_state != state && old_state >= 0 ? std::format(" (was 0x{:02X})", old_state) : std::string(),
              p, m, c, scan.total, scan.inspected, scan.unreadable, scan.not_found, scan.ready, scan.not_ready,
              s.empty() ? std::string(" none") : s, verdict,
              since ? std::format(" | in 0x12 for {} s", (now - since) / 1000) : std::string());
}

// ---------------------------------------------------------------- 3b. the state's transitions, as they happen

// Game thread, every pass of 0x7797F0 through its state switch: one compare,
// an event only when the value differs from the last one seen.
void on_state(safetyhook::Context& ctx) noexcept {
    g_state_hits.fetch_add(1, std::memory_order_relaxed);
    // Only the field-change P the 5 s report reads ([[WorldSystem]+0x60]).
    uintptr_t ws = 0, expected = 0;
    if (!fast_peek(g_base + g2976::kWorldSystemSlot, ws) || !fast_peek(ws + kWorldSystem_FieldChange, expected) ||
        expected != ctx.rdi) {
        g_state_other_p.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    uint8_t state = 0;
    if (!fast_peek(ctx.rdi + kP_State, state)) return;
    const int old = g_state_seen.exchange(state, std::memory_order_relaxed);
    // P8 S15 (guest_reload_wait.h): every pass, before the state handler runs; nothing when it is off.
    if (guest_reload_wait_active()) guest_reload_wait_on_pass(ctx.rdi, state, old);
    if (old == state) return;
    g_state_changes.fetch_add(1, std::memory_order_relaxed);
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.v[0] = ctx.rdi;
    e.v[1] = static_cast<uint64_t>(static_cast<int64_t>(old));
    e.v[2] = state;
    g_state_ring.push(e);  // full: counted by the ring
}

// Install thread, every 5 s.
void drain_transitions() {
    p8p::Event e;
    while (g_state_ring.pop(e)) {
        const int old = static_cast<int>(static_cast<int64_t>(e.v[1]));
        const unsigned now_state = static_cast<unsigned>(e.v[2] & 0xFF);
        std::string in_old;
        if (g_state_since_value == old && g_state_since_us && e.qpc_us >= g_state_since_us) {
            in_old = std::format(" after {:.3f} s in 0x{:02X}", static_cast<double>(e.qpc_us - g_state_since_us) / 1e6,
                                 static_cast<unsigned>(old));
        }
        g_state_since_us = e.qpc_us;
        g_state_since_value = static_cast<int>(now_state);
        load_trip_on_state(old, static_cast<int>(now_state), e.qpc_us);  // P8 S2: GuestLoad's trip summaries
        if (!g_transition_lines.take()) continue;
        try {
            log::info("GuestDiag loading transition: [P+0x15C] {} -> 0x{:02X}{}{} | {} | P 0x{:X} T{}",
                      old < 0 ? std::string("(first seen)") : std::format("0x{:02X}", static_cast<unsigned>(old)),
                      now_state, in_old, old == 0x11 ? " | EXIT FROM 0x11" : "", p8_when(e.qpc_us), e.v[0], e.tid);
        } catch (...) {
        }
    }
}

// ---------------------------------------------------------------- install

bool hook_mid(uintptr_t at, uint32_t patch, SafetyHookMid& h, safetyhook::MidHookFn fn, const char* what) {
    if (!code_section_ok(at, patch, what)) return false;
    h = safetyhook::create_mid(reinterpret_cast<void*>(g_base + at), fn);
    if (!h) {
        log::error("GuestDiag: cannot hook {} (exe+0x{:X})", what, at);
        return false;
    }
    return true;
}

void install_diag() {
    if (all_match(kFinishChecks)) {
        g_finish_on = hook_mid(kFinishErrorHook, kFinishErrorPatch, g_finish, on_finish_error, "FinishGroup's error");
    } else {
        log::error("GuestDiag: FinishGroup 0x4FD2E0 is not the expected code (at {}); that point is REFUSED",
                   first_mismatch(kFinishChecks));
    }
    if (companion_probe_active()) {
        log::warn("GuestDiag: the companion probe already hooks the restore (0x8646FC/0x864B1D); not hooked twice");
    } else if (all_match(kRestoreChecks)) {
        // "After" only with "before" (it pairs with it).
        g_restore_on = hook_mid(cmp::kRestoreHook, kRestorePatch, g_restore, on_restore, "the restore 0x8646FC") &&
                       hook_mid(cmp::kRestoreExitHook, kRestoreExitPatch, g_restore_exit, on_restore_exit,
                                "the restore's exit 0x864B1D");
        if (!g_restore_on) g_restore = {};
    } else {
        log::error("GuestDiag: RestoreActionsFromLoadData 0x8646D0 is not the expected code (at {}); that point is "
                   "REFUSED",
                   first_mismatch(kRestoreChecks));
    }
    // Read only (no hook): the code we replay must be the one we read.
    if (all_match(kWaitChecks)) {
        g_wait_on = true;
    } else {
        log::error("GuestDiag: the loading state 0x7797F0 / Find 0x464290 are not the expected code (at {}); the wait "
                   "list is not read",
                   first_mismatch(kWaitChecks));
    }
    // The state's transitions when they happen (§4.3): a checked mid hook
    // (bytes, .rsrc, exactly the 8 verified bytes relocated) or nothing.
    g_state_on = p8_install_mid(g_base, g_secs, kStateSite, kStatePatch, kStateHookBytes, on_state, g_state, "GuestDiag",
                                "the loading state's read 0x7798D0");
    log::info("GuestDiag ON (read only): FinishGroup error exe+0x{:X} {} | restore exe+0x{:X}/exe+0x{:X} {} (layers "
              "before and after) | loading state and the whole wait list (up to {} keys) every 5 s {} | state "
              "transitions at exe+0x{:X} {} | {}",
              kFinishErrorHook, g_finish_on ? "on" : "OFF", cmp::kRestoreHook, cmp::kRestoreExitHook,
              g_restore_on ? "on" : "OFF", kWaitRead, g_wait_on ? "on" : "OFF", kStateSite, g_state_on ? "on" : "OFF",
              rsrc_text());
}

void install_guard() {
    const uintptr_t layer = game::character_profile::rva(g2976::kActionLayerAdvance);
    const uintptr_t layers = game::character_profile::rva(g2976::kActionLayersAdvance);
    const auto layer_sig = game::character_profile::signature(g2976::kActionLayerAdvance,
                                                               g2976::kActionLayerAdvanceHead);
    const auto layers_sig = game::character_profile::signature(g2976::kActionLayersAdvance,
                                                                g2976::kActionLayersAdvanceHead);
    const bool sections = layer && layers && !layer_sig.empty() && !layers_sig.empty() &&
                          code_section_ok(layer, static_cast<uint32_t>(layer_sig.size()),
                                          "ActionLayer AdvancePlayback") &&
                          code_section_ok(layers, static_cast<uint32_t>(layers_sig.size()),
                                          "CharacterControl AdvanceActionLayers");
    if (!sections || !guard_checks_match() || !net::puppet_install_layer_guards()) {
        log::error("GuestDiag: the action-layer guard could NOT be installed ({}); remote actors stay unguarded",
                   !sections ? "outside .rsrc or no build profile" : guard_mismatch());
        return;
    }
    g_guard_on = true;
    log::info("GuestDiag guard ON: exe+0x{:X} returns at once on any layer with no playback; exe+0x{:X} skips the "
              "layer update of every actor whose +0x90 is not the local user key while a layer has a chart and no "
              "action. Armed when the local user key is known | {}",
              layer, layers, rsrc_text());
    if (const uint32_t local = g_local.load()) net::puppet_guard_not_controlled_by(local, &on_guard_skip);
}

// The complete build-specific guard set is required before remote admission.
// Its ownership filtering activates separately when the local user is known.
// All hooks sit at checked function entries; guest_s3 leaves Update to them.
void install_remote_update_guard() {
    g_rug_tried = true;
    if (!net::horse_diag_install_remote()) {
        log::error("RemoteUpdateGuard: the complete requested character guard set could NOT be installed; "
                   "remote admission remains closed (guest_remote_update_guard=1)");
        return;
    }
    const uint32_t local = g_local.load();
    net::horse_diag_contain_remote(local);
    g_rug_on = true;
    if (game::current_build() == game::Build::v3576 || game::current_build() == game::Build::v3663) {
        log::info("RemoteUpdateGuard ON for {}: Update, PostUpdate, movement phase and action query at "
                  "character_profile's {} addresses; local user 0x{:08X}. Missing selected action/playback defers "
                  "remote movement; native action restore remains active",
                  game::current_build() == game::Build::v3663 ? 3663 : 3576,
                  game::current_build() == game::Build::v3663 ? 3663 : 3576, local);
        return;
    }
    if (game::current_build() == game::Build::v3527) {
        log::info("RemoteUpdateGuard ON for 3527: Update exe+0x944E70, PostUpdate exe+0x946060, "
                  "movement phase exe+0x94F7F0 and action query exe+0xB0B230; local user 0x{:08X}. "
                  "Missing selected action/playback defers remote movement; native action restore remains active",
                  local);
        return;
    }
    log::info("RemoteUpdateGuard ON (guest_remote_update_guard=1, S34): CharacterControl::Update 0x85FBA0 and "
              "PostUpdate 0x860D30 return at once for every actor whose controller (+0x90) is a user other than the "
              "local one 0x{:08X} while a layer has a chart and no current action or playback (Shadow's crash at "
              "exe+0x88F832, MovementController_UpdateByMode, called only from 0x860D30); the local user's actors and "
              "those with +0x90 = 0 are never touched. horse_diag's containment, entry mid hooks",
              local);
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const game::Build build = game::current_build();
    // Build 1.0.0.3576 (static, 2026-11-06): this module installs nothing of its own there (the probes stay off, as on
    // 3527); the layer guard and the remote update guard go through character_profile / remote_puppet / horse_diag,
    // which refuse 3576 until they are ported. Only the local user key is read (refresh_local).
    // Build 1.0.0.3663 (static, 2026-11-13): the same; its only address is the world slot / actor manager vtable of
    // refresh_local. The guards stay off until character_profile / remote_puppet / horse_diag admit 3663. The
    // field-change controller P (3663: [world+0x60] grew by 0xF0, state +0x24C, manager +0x1A8, one more load state)
    // is read only by the 2976 probes below (tick_wait_list / on_state, g_diag), which are forced off here.
    if (build == game::Build::unsupported ||
        !(game::legacy_layout() || build == game::Build::v3576 || build == game::Build::v3663)) {
        log::error("GuestDiag: unsupported game build; guest_actor_diag / guest_layer_guard stay off");
        return 0;
    }
    if ((build == game::Build::v3527 || build == game::Build::v3576 || build == game::Build::v3663) &&
        g_diag.exchange(false)) {
        log::warn("GuestDiag: optional guest_actor_diag probes are not ported to build {} and stay off; required "
                  "guest guards remain enabled",
                  build == game::Build::v3663 ? 3663 : build == game::Build::v3576 ? 3576 : 3527);
    }
    if (!read_sections()) {
        log::error("GuestDiag: the game's section table is unreadable; nothing is hooked");
        return 0;
    }
    // As early as the game's code is there (2 minutes), like the guest's other hooks.
    for (int i = 0; i < 24000; ++i) {
        const bool diag = !g_diag || (all_match(kFinishChecks) && all_match(kRestoreChecks) && all_match(kWaitChecks));
        const bool guard = !g_guard || guard_checks_match();
        if (diag && guard && game::validate_native_catalog()) break;
        Sleep(5);
    }
    if (g_guard) install_guard();
    if (g_diag) install_diag();
    // Install before remote admission. Ownership filtering remains disarmed
    // at local key zero, then refresh_local arms it when the guest exists.
    // Waiting for that key to install would make admission readiness circular.
    if (g_rug.load() && !g_rug_tried) install_remote_update_guard();
    // The local user key, every second (the guard needs it as soon as the
    // guest's character exists; the host's NPCs come after it). The state's
    // transitions are written every 5 s (formatting never on the game's thread).
    for (uint64_t tick = 1;; ++tick) {
        refresh_local();
        if (g_rug_on.load()) {
            try {
                net::horse_diag_remote_report();
            } catch (...) {
            }
        }
        if (tick % 5 == 0 && g_state_on.load()) {
            try {
                drain_transitions();
            } catch (...) {
            }
        }
        Sleep(1000);
    }
}

}  // namespace

void guest_actor_diag_start(bool diag, bool layer_guard, bool remote_update_guard) {
    if (!diag && !layer_guard && !remote_update_guard) return;
    if (g_started.exchange(true)) return;
    g_diag = diag;
    g_guard = layer_guard;
    g_rug = remote_update_guard;
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

bool guest_layer_guard_ready() noexcept { return g_guard_on.load(std::memory_order_acquire); }
bool guest_remote_update_guard_ready() noexcept { return g_rug_on.load(std::memory_order_acquire); }

void guest_actor_diag_tick() noexcept {
    if (!g_started.load()) return;
    try {
        restore_report();
    } catch (...) {
    }
    if (g_wait_on.load()) {
        try {
            tick_wait_list();
        } catch (...) {
        }
    }
    guest_reload_wait_tick();  // noexcept; P8 S15 lines (after the walk that feeds its ages)
}

bool guest_actor_diag_wanted() { return g_started.load(); }

uint32_t guest_actor_diag_local_user() { return g_local.load(std::memory_order_relaxed); }

std::string guest_actor_diag_describe() {
    std::string s = std::format(" | GuestDiag local user 0x{:08X}", g_local.load());
    if (g_diag.load()) {
        s += std::format(
            " | login failures {} (not controlled here {}, action chart {}; last 0x{:08X} code 0x{:08X}) | restore "
            "{} calls, {} remote (before the local key: {}): restored {}, byte 0 {}, CHART FAILED {}, other failed {} "
            "(last failed 0x{:08X}; chart and no action at the exit {}) | loading state 0x{:02X}, wait list {}, waits "
            "for 0x{:08X} | transitions {} (state reads {}, other P {}, ring dropped {}) | points {}/{}/{}/{}",
            g_fin_total.load(), g_fin_remote.load(), g_fin_chart.load(), g_fin_last_key.load(),
            g_fin_last_code.load(), g_rs_calls.load(), g_rs_remote.load(), g_rs_no_local.load(), g_rs_ok.load(),
            g_rs_byte0.load(), g_rs_chart.load(), g_rs_other.load(), g_rs_last_fail_key.load(),
            g_rs_after_no_action.load(), static_cast<unsigned>(g_tick_state.load() & 0xFF), g_tick_wait.load(),
            g_tick_blocker.load(), g_state_changes.load(), g_state_hits.load(), g_state_other_p.load(),
            g_state_ring.dropped(), g_finish_on.load() ? "finish" : "-", g_restore_on.load() ? "restore" : "-",
            g_wait_on.load() ? "wait" : "-", g_state_on.load() ? "transitions" : "-");
    }
    if (g_guard.load()) {
        s += std::format(" | guard {}: held actors {} (skips {}, last 0x{:08X}) | {}", g_guard_on.load() ? "on" : "OFF",
                         g_guard_keys.size(), g_guard_skips.load(), g_guard_last_key.load(),
                         net::puppet_guard_describe());
    }
    if (g_rug.load()) {
        s += g_rug_on.load() ? net::horse_diag_remote_describe() : std::string(" | remote update guard OFF");
    }
    s += guest_reload_wait_describe();  // P8 S15; empty when off
    return s;
}

}  // namespace cdmp::session2
