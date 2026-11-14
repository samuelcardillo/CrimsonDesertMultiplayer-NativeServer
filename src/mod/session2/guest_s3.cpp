#include "mod/session2/guest_s3.h"

#include <windows.h>

#include <dbghelp.h>
#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "mod/game/character_profile.h"
#include "mod/game/fault_line.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/role.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_s3_logic.h"
#include "mod/session2/offsets_s2.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using s3::Ev;
using s3::Record;

// ---------------------------------------------------------------- the sites (build 2976, all .rsrc)
//
// Bytes verified against D:\RE\CrimsonDesert_2976\bin\CrimsonDesert.exe
// (SHA-256 57DA440D...E1E7) and p8-raiz-invitado.md §7.3. "patch" = the whole
// instructions SafetyHook overwrites (>= 5 bytes); no rel32 branch of any
// executable section and no branch of the function itself lands inside them
// (raw scan + capstone, pendientes/p8-impl-s3.md §3).
struct Site {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    uint32_t patch;
    const char* what;
};
// 0x232D5C0 (void; rcx = CC, dl = layer, r8 = snapshot of layer +0/+8/+0x10).
// mov [rsp+0x20],r9 (5).
constexpr uint8_t kNullConsumerBytes[] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x89, 0x44,
                                          0x24, 0x18, 0x88, 0x54, 0x24, 0x10, 0x48, 0x89};
// 0x232D5FB mov rax,[r8+0x10] ; 0x232D5FF movzx eax,word [rax+0xE4]: the read.
constexpr uint8_t kNullReadBytes[] = {0x49, 0x8B, 0x40, 0x10, 0x0F, 0xB7, 0x80, 0xE4, 0x00, 0x00, 0x00};
// Build 3527 preserved the consumer ABI and entry instructions.  The first
// dereference is still snapshot+0x10, while the action field it verifies moved
// from +0xE4 to +0xE8.
constexpr uint8_t kNullRead3527Bytes[] = {0x49, 0x8B, 0x40, 0x10, 0x0F, 0xB7,
                                          0x80, 0xE8, 0x00, 0x00, 0x00};
// 0x85FBA0 CharacterControl::Update (rcx = CC). mov [rsp+0x10],rbx (5).
constexpr uint8_t kUpdateBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57,
                                    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
// 0x48B120 2723's consumer ([rcx] = CC). mov [rsp+0x10],rbx (5).
constexpr uint8_t kSpawnBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74,
                                   0x24, 0x18, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56};
// 0x48B197 test al,al ; jne 0x48B1B2 ; mov [rsi],r12d (7): AL = vf188(5).
constexpr uint8_t kSpawnAlBytes[] = {0x84, 0xC0, 0x75, 0x17, 0x44, 0x89, 0x26, 0x48, 0x8B, 0x8D, 0x80, 0x00, 0x00, 0x00};
// 0x48B18F mov dl,5 ; 0x48B191 call [rax+0x188] (the test it follows).
constexpr uint8_t kSpawnCallBytes[] = {0xB2, 0x05, 0xFF, 0x90, 0x88, 0x01, 0x00, 0x00};
// 0x48AD40 2991's consumer ([rcx] = CC, r9b = flag). mov [rsp+0x10],rbx (5).
constexpr uint8_t kAckBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74,
                                 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55};
// 0x863530 StartAction (CC, int* res, actions, u64 session) -> res; 4 integer
// arguments, none on the stack (prologue 0x863530..0x863557). mov [rsp+0x10],rbx (5).
constexpr uint8_t kStartBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x44,
                                   0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55};

constexpr Site kNullConsumer{0x232D5C0, kNullConsumerBytes, 5, "0x232D5C0 (null-action consumer)"};
constexpr Site kUpdate{0x85FBA0, kUpdateBytes, 5, "CharacterControl::Update 0x85FBA0"};
constexpr Site kSpawn{0x48B120, kSpawnBytes, 5, "2723's consumer 0x48B120"};
constexpr Site kSpawnAl{0x48B197, kSpawnAlBytes, 7, "2723's vf188(5) test 0x48B197"};
constexpr Site kAck{0x48AD40, kAckBytes, 5, "2991's consumer 0x48AD40"};
constexpr Site kStart{0x863530, kStartBytes, 5, "StartAction 0x863530"};
constexpr uintptr_t kNullRead = 0x232D5FB;
constexpr uintptr_t kSpawnCall = 0x48B18F;

// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the consumer moved whole by +0xDD0 to 0x251ED90 (.pdata begins
// there); the only place within +0x3000 of 3527's where kNullConsumerBytes is followed at +0x3B by kNullRead3527Bytes
// (0x251EDCB, the same +0xE8 read). Its first 0x3B bytes save r8 and do not change it.
constexpr uintptr_t kNullConsumer3576 = 0x251ED90, kNullRead3576 = 0x251EDCB;
// Build 1.0.0.3663 (static, 2026-11-13; never run): kNullRead3527Bytes occurs once in the whole code section, at
// 0x259075B, and kNullConsumerBytes is 0x3B before it: the consumer 0x2590720 (.pdata begins there; 3576 + 0x71990),
// whose first 0x3B bytes save r8 (mov r15,r8) and do not change it; it then reads CC+8 (0x25907A0) and the layers
// CC+0x88 / +0x90 (0x25907EF / 0x2590812) as before. Its only caller 0x259070E (rcx = CC, dl, r8 = the snapshot).
constexpr uintptr_t kNullConsumer3663 = 0x2590720, kNullRead3663 = 0x259075B;

Site null_consumer_site() noexcept {
    if (game::current_build() == game::Build::v3663) {
        return {kNullConsumer3663, kNullConsumerBytes, 5, "null-action consumer"};
    }
    if (game::current_build() == game::Build::v3576) {
        return {kNullConsumer3576, kNullConsumerBytes, 5, "null-action consumer"};
    }
    if (game::current_build() == game::Build::v3527) {
        return {0x251DFC0, kNullConsumerBytes, 5, "null-action consumer"};
    }
    return kNullConsumer;
}

uintptr_t null_read_rva() noexcept {
    const game::Build b = game::current_build();
    return b == game::Build::v3663   ? kNullRead3663
           : b == game::Build::v3576 ? kNullRead3576
           : b == game::Build::v3527 ? 0x251DFFB
                                     : kNullRead;
}

std::span<const uint8_t> null_read_bytes() noexcept {
    const game::Build b = game::current_build();
    return b == game::Build::v3527 || b == game::Build::v3576 || b == game::Build::v3663
               ? std::span<const uint8_t>{kNullRead3527Bytes}
               : std::span<const uint8_t>{kNullReadBytes};
}

// Offsets (build 2976; p8-raiz-invitado.md §5, companeros.md).
constexpr uint32_t kCc_Actor = 0x08, kCc_Ack60 = 0x60, kCc_Default0 = 0x70, kCc_Default1 = 0x78, kCc_Layer0 = 0x88,
                   kCc_Layer1 = 0x90, kCc_Pending = 0xA8;
constexpr uint32_t kLayer_Cur = 0x10, kLayer_Play = 0x18, kLayer_Hash = 0x3C;
constexpr uint32_t kActor_State = 0x5E, kActor_C1 = 0xC1, kActor_C2 = 0xC2, kActor_CF = 0xCF, kActor_C8 = 0xC8;
constexpr uint32_t kAck60_Flags = 0x10;

constexpr uint16_t kOp2005 = 2005, kOp2723 = 2723, kOp2991 = 2991;

// Budgets.
constexpr size_t kRingSize = 8192;          // 1 MB
constexpr size_t kTickLines = 150;          // per 5 s tick
constexpr size_t kHistoryLines = 40;        // per interesting actor, once
constexpr size_t kCrashFlush = 64;          // records flushed to the log on a crash
constexpr uint64_t kStuckMs = 5000;         // a guarded actor without an action for this long is "stuck"
constexpr uint32_t kMaxCrashEvents = 8, kMaxDumps = 2;

// ---------------------------------------------------------------- state

uintptr_t g_base = 0;
uint32_t g_rsrc_va = 0, g_rsrc_size = 0;
std::atomic<bool> g_started{false}, g_diag{false}, g_crash{false}, g_guard{false}, g_actor_diag{false};
// S34: guest_remote_update_guard (horse_diag) owns 0x85FBA0's entry; the first-Update point is not hooked.
std::atomic<bool> g_update_taken{false};
std::atomic<bool> g_null_on{false}, g_update_on{false}, g_spawn_on{false}, g_spawn_al_on{false}, g_ack_on{false},
    g_start_on{false}, g_crash_on{false};
std::atomic<uint32_t> g_local{0};
std::atomic<uint32_t> g_epoch{0};
uint8_t* g_ret = nullptr;  // a lone `ret`

SafetyHookMid g_h_null, g_h_update, g_h_spawn, g_h_spawn_al, g_h_ack;
SafetyHookInline g_h_start;

s3::Ring<kRingSize> g_ring;
// Bounded at half their slots (guest_s3_logic.h kMaxProbe): 8192 keys each, 1024 guarded actors.
using Keys = s3::KeySet<16384>;
Keys g_first_update, g_first_null, g_first_2723, g_first_2991, g_history_done;
s3::GuardTable<2048> g_guard_tab;

int64_t g_qpc_freq = 1, g_qpc_base = 0;
FILETIME g_ft_base{};

std::atomic<uint64_t> c_rx2005{0}, c_rx2005_r0{0}, c_rx2005_r1{0}, c_rx2005_rx{0}, c_rx2723{0}, c_rx2991{0},
    c_restore_ok{0}, c_restore_b0{0}, c_restore_fail{0}, c_first_upd{0}, c_first_upd_noact{0}, c_spawn{0},
    c_spawn_al1{0}, c_spawn_al0{0}, c_ack{0}, c_ack_discard{0}, c_start[3][3] = {}, c_null{0}, c_null_remote{0},
    c_null_local{0}, c_skips{0}, c_recovered{0}, c_stuck{0}, c_lost{0}, c_suppressed{0}, c_crash_events{0},
    c_dumps{0}, c_errors{0}, c_crash_recorded{0}, c_crash_busy{0};

// ---------------------------------------------------------------- reads (hot paths: plain SEH)

template <class T>
bool fp(uintptr_t a, T& v) {
    if (a < 0x10000) return false;
    __try {
        v = *reinterpret_cast<const volatile T*>(a);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uintptr_t fpp(uintptr_t a) {
    uintptr_t v = 0;
    return fp(a, v) ? v : 0;
}

struct ActorIds {
    uintptr_t actor = 0;
    uint32_t key = 0, control = 0;
};

ActorIds ids_of_cc(uintptr_t cc) {
    ActorIds a;
    a.actor = fpp(cc + kCc_Actor);
    if (!a.actor || !fp(a.actor + g2976::kActor_Key, a.key) || !fp(a.actor + g2976::kActor_OwnerUser, a.control)) {
        a.key = 0;
    }
    return a;
}

uint32_t actor_flags(uintptr_t actor) {
    uint8_t c1 = 0, c2 = 0, cf = 0, c8 = 0;
    fp(actor + kActor_C1, c1);
    fp(actor + kActor_C2, c2);
    fp(actor + kActor_CF, cf);
    fp(actor + kActor_C8, c8);
    return c1 | (c2 << 8) | (cf << 16) | (static_cast<uint32_t>(c8) << 24);
}

// bit0 L0 chart, bit1 L0 cur, bit2 L0 play, bit3 L1 chart, bit4 L1 cur, bit5 L1 play
uint8_t layer_bits(uintptr_t cc) {
    uint8_t bits = 0;
    const uint32_t chart = game::character_profile::layer_chart_offset();
    for (uint32_t i = 0; i < 2; ++i) {
        const uintptr_t l = fpp(cc + kCc_Layer0 + 8 * i);
        if (!l) continue;
        if (fpp(l + chart)) bits |= static_cast<uint8_t>(1u << (3 * i));
        if (fpp(l + kLayer_Cur)) bits |= static_cast<uint8_t>(2u << (3 * i));
        if (fpp(l + kLayer_Play)) bits |= static_cast<uint8_t>(4u << (3 * i));
    }
    return bits;
}

bool chart_without_action(uint8_t bits) {
    return ((bits & 1) && !(bits & 2)) || ((bits & 8) && !(bits & 16));
}

uint64_t qpc() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return static_cast<uint64_t>(t.QuadPart);
}

Record rec(Ev ev, uint32_t key, uint32_t control) {
    Record r;
    r.qpc = qpc();
    r.tid = GetCurrentThreadId();
    r.epoch = g_epoch.load(std::memory_order_relaxed);
    r.key = key;
    r.control = control;
    r.ev = ev;
    return r;
}

void push(const Record& r) { g_ring.push(r); }

uint32_t local() { return g_local.load(std::memory_order_relaxed); }

// ---------------------------------------------------------------- hooks

// 0x232D5C0's entry: the probe (snapshot +0x10 null) and the guard.
void on_null_consumer(safetyhook::Context& ctx) noexcept {
    uintptr_t cur = 0;
    if (!fp(ctx.r8 + kLayer_Cur, cur)) return;
    if (cur) {
        // Only while some guarded actor has not had an action again.
        if (g_guard_tab.open() == 0) return;
        const ActorIds a = ids_of_cc(ctx.rcx);
        auto* s = a.key ? g_guard_tab.find(a.key) : nullptr;
        if (!s || s->recovered_qpc.load(std::memory_order_relaxed)) return;
        const uint64_t now = qpc();
        if (!g_guard_tab.recover(*s, now)) return;
        c_recovered.fetch_add(1, std::memory_order_relaxed);
        Record r = rec(Ev::GuardRecovered, a.key, a.control);
        r.a = static_cast<uint32_t>((now - s->first_qpc.load(std::memory_order_relaxed)) * 1000 / g_qpc_freq);
        r.b = s->skips.load(std::memory_order_relaxed);
        r.c = static_cast<uint8_t>(ctx.rdx);
        push(r);
        return;
    }
    const ActorIds a = ids_of_cc(ctx.rcx);
    const uint32_t loc = local();
    const bool remote = s3::remote_controlled(a.control, loc);
    const bool skip = s3::guard_skips(g_guard.load(std::memory_order_relaxed) && g_null_on.load(std::memory_order_relaxed),
                                      true, a.control, loc) &&
                      a.key != 0;
    c_null.fetch_add(1, std::memory_order_relaxed);
    (remote ? c_null_remote : c_null_local).fetch_add(1, std::memory_order_relaxed);
    if (g_diag.load(std::memory_order_relaxed) && a.key &&
        g_first_null.insert(a.key) == Keys::Insert::Added) {
        Record r = rec(Ev::NullAction, a.key, a.control);
        r.a = static_cast<uint8_t>(ctx.rdx);
        const uintptr_t cc = ctx.rcx;
        const uintptr_t l0 = fpp(cc + kCc_Layer0), l1 = fpp(cc + kCc_Layer1);
        const uint32_t chart = game::character_profile::layer_chart_offset();
        if (l0) {
            r.v[0] = fpp(l0 + kLayer_Cur);
            r.v[1] = fpp(l0 + kLayer_Play);
            r.v[2] = fpp(l0 + chart);
            r.v[8] = fpp(l0);
            r.v[9] = fpp(l0 + 8);
            fp(l0 + kLayer_Hash, r.b);
        }
        if (l1) {
            r.v[3] = fpp(l1 + kLayer_Cur);
            r.v[4] = fpp(l1 + kLayer_Play);
            r.v[5] = fpp(l1 + chart);
            fp(l1 + kLayer_Hash, r.c);
            if (fpp(l1)) r.flags |= 4;
            if (fpp(l1 + 8)) r.flags |= 8;
        }
        r.v[6] = fpp(cc + kCc_Default0);
        r.v[7] = fpp(cc + kCc_Default1);
        uint8_t pending = 0;
        if (fp(cc + kCc_Pending, pending) && pending) r.flags |= 16;
        if (a.actor) {
            fp(a.actor + kActor_State, r.u16);
            r.d = actor_flags(a.actor);
        }
        if (remote) r.flags |= 1;
        if (skip) r.flags |= 2;
        push(r);
    }
    if (!skip) return;
    c_skips.fetch_add(1, std::memory_order_relaxed);
    bool first = false;
    g_guard_tab.touch(a.key, a.control, qpc(), first);
    if (first && g_diag.load(std::memory_order_relaxed)) {
        Record r = rec(Ev::GuardFirst, a.key, a.control);
        r.a = static_cast<uint8_t>(ctx.rdx);
        push(r);
    }
    // Return at once: the path 0x232D5C0 takes for an action with no entries.
    ctx.rip = reinterpret_cast<uintptr_t>(g_ret);
}

// 0x85FBA0's entry: the first Update of each remote actor.
void on_update(safetyhook::Context& ctx) noexcept {
    const ActorIds a = ids_of_cc(ctx.rcx);
    if (!a.key || !s3::remote_controlled(a.control, local())) return;
    if (g_first_update.insert(a.key) != Keys::Insert::Added) return;
    Record r = rec(Ev::FirstUpdate, a.key, a.control);
    r.flags = layer_bits(ctx.rcx);
    fp(a.actor + kActor_State, r.u16);
    r.a = actor_flags(a.actor);
    uint8_t pending = 0;
    fp(ctx.rcx + kCc_Pending, pending);
    r.b = pending;
    c_first_upd.fetch_add(1, std::memory_order_relaxed);
    if (chart_without_action(r.flags)) c_first_upd_noact.fetch_add(1, std::memory_order_relaxed);
    push(r);
}

thread_local ActorIds t_spawn{};

void on_spawn(safetyhook::Context& ctx) noexcept {
    const uintptr_t cc = fpp(ctx.rcx);
    t_spawn = ids_of_cc(cc);
    if (!t_spawn.key) return;
    c_spawn.fetch_add(1, std::memory_order_relaxed);
    if (!s3::remote_controlled(t_spawn.control, local())) return;
    Record r = rec(Ev::Spawn2723, t_spawn.key, t_spawn.control);
    uint8_t c8 = 0;
    fp(t_spawn.actor + kActor_C8, c8);
    r.a = c8;
    push(r);
}

void on_spawn_al(safetyhook::Context& ctx) noexcept {
    const uint8_t al = static_cast<uint8_t>(ctx.rax & 0xFF);
    (al ? c_spawn_al1 : c_spawn_al0).fetch_add(1, std::memory_order_relaxed);
    const ActorIds a = t_spawn;
    t_spawn = {};
    if (!a.key || !s3::remote_controlled(a.control, local())) return;
    Record r = rec(Ev::Spawn2723Vf188, a.key, a.control);
    r.a = al;
    uint8_t c8 = 0;
    fp(a.actor + kActor_C8, c8);
    r.b = c8;
    push(r);
}

void on_ack(safetyhook::Context& ctx) noexcept {
    const uintptr_t cc = fpp(ctx.rcx);
    const ActorIds a = ids_of_cc(cc);
    if (!a.key) return;
    c_ack.fetch_add(1, std::memory_order_relaxed);
    const uint8_t flag = static_cast<uint8_t>(ctx.r9 & 0xFF);
    uint8_t bits = 0;
    const uintptr_t a60 = fpp(cc + kCc_Ack60);
    const bool read_ok = a60 && fp(a60 + kAck60_Flags, bits);
    const bool discard = read_ok && (bits & 1) && flag == 0;
    if (discard) c_ack_discard.fetch_add(1, std::memory_order_relaxed);
    if (!s3::remote_controlled(a.control, local())) return;
    Record r = rec(Ev::Ack2991, a.key, a.control);
    r.a = flag;
    r.b = read_ok ? (bits & 1u) : 0xFFu;
    r.c = discard ? 1 : 0;
    push(r);
}

int* __fastcall start_detour(uintptr_t cc, int* res, uintptr_t actions, uint64_t session) noexcept {
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    int* out = g_h_start.unsafe_call<int*>(cc, res, actions, session);
    const ActorIds a = ids_of_cc(cc);
    if (!a.key) return out;
    const auto caller = s3::start_caller(ret >= g_base ? ret - g_base : 0);
    int code = -1;
    const bool code_ok = fp(reinterpret_cast<uintptr_t>(out), code);
    const uint8_t bits = layer_bits(cc);
    const bool installed = (bits & 2) != 0;  // layer 0 has a current action right after
    const size_t col = !code_ok || code != 0 ? 2 : installed ? 0 : 1;
    c_start[static_cast<size_t>(caller)][col].fetch_add(1, std::memory_order_relaxed);
    if (!s3::remote_controlled(a.control, local())) return out;
    Record r = rec(Ev::StartAction, a.key, a.control);
    r.a = code_ok ? static_cast<uint32_t>(code) : 0xFFFFFFFFu;
    r.b = static_cast<uint32_t>(caller);
    r.c = static_cast<uint32_t>(session);
    r.flags = bits;
    r.v[0] = ret >= g_base ? ret - g_base : ret;
    push(r);
    return out;
}

// ---------------------------------------------------------------- the local user key

// P8 re-entry (s25/reentrada.md §1.4): the guard table's keys belong to one remote conversation (the next one reuses
// them). Its own loop (refresh_local's caller, every second); the table's new generation is lock-free.
uint32_t g_guard_conv = 0;
void guard_conversation_check() noexcept {
    const uint32_t conv = guest_conversation_id();
    if (conv == g_guard_conv) return;
    g_guard_conv = conv;
    if (conv < 2) return;
    g_guard_tab.new_generation();
    try {
        log::info("GuestS3: remote conversation {} (re-entry): the update guard's per-key state starts again (generation "
                  "{}; {} key(s) seen so far in this run, the per-run bound stays)",
                  conv, g_guard_tab.generation(), g_guard_tab.size());
    } catch (...) {
    }
}

void refresh_local() noexcept {
    guard_conversation_check();
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
        const auto key = ctrl ? game::read<uint32_t>(*ctrl + g2976::kActor_OwnerUser) : std::nullopt;
        if (!key || (*key >> 28) != 0x9) return;  // not a user key yet (title, loading)
        const uint32_t old = g_local.exchange(*key);
        if (old != *key) {
            log::info("GuestS3: local user key 0x{:08X}{} (actors with another +0x90 count as remote)", *key,
                      old ? std::format("; was 0x{:08X}", old) : std::string());
        }
    } catch (...) {
    }
}

// ---------------------------------------------------------------- install

bool read_rsrc() {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!game::safe_read(g_base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !game::safe_read(g_base + dos.e_lfanew, &nt, sizeof nt) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const uintptr_t first =
        g_base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections && i < 64; ++i) {
        IMAGE_SECTION_HEADER h{};
        if (!game::safe_read(first + i * sizeof h, &h, sizeof h)) return false;
        // By its flags: the protector renames the sections on every build (gad::is_real_code).
        if ((h.Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(h.Characteristics & IMAGE_SCN_MEM_WRITE)) {
            g_rsrc_va = h.VirtualAddress;
            g_rsrc_size = h.Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

bool in_rsrc(uintptr_t rva, uint32_t len) {
    return g_rsrc_size && len && rva >= g_rsrc_va &&
           static_cast<uint64_t>(rva) + len <= static_cast<uint64_t>(g_rsrc_va) + g_rsrc_size;
}

bool bytes_match(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

// The patch SafetyHook chose must be exactly the verified instructions.
template <class H>
bool patch_ok(const H& h, const Site& s) {
    const auto& ob = h.original_bytes();
    if (ob.size() == s.patch && s.patch <= s.bytes.size() && std::memcmp(ob.data(), s.bytes.data(), ob.size()) == 0) {
        return true;
    }
    log::error("GuestS3: {} (exe+0x{:X}): the hook would overwrite {} bytes, {} verified; REFUSED, not hooked",
               s.what, s.rva, ob.size(), s.patch);
    return false;
}

bool site_ok(const Site& s) {
    if (!bytes_match(s.rva, s.bytes)) {
        log::error("GuestS3: {} (exe+0x{:X}) is not the expected code; REFUSED, not hooked", s.what, s.rva);
        return false;
    }
    if (!in_rsrc(s.rva, s.patch)) {
        log::error("GuestS3: {} (exe+0x{:X}, {} bytes) is not inside .rsrc; REFUSED, not hooked", s.what, s.rva,
                   s.patch);
        return false;
    }
    return true;
}

bool make_mid(const Site& s, SafetyHookMid& out, safetyhook::MidHookFn fn) {
    if (!site_ok(s)) return false;
    auto h = safetyhook::MidHook::create(reinterpret_cast<void*>(g_base + s.rva), fn, safetyhook::MidHook::StartDisabled);
    if (!h) {
        log::error("GuestS3: cannot hook {} (exe+0x{:X})", s.what, s.rva);
        return false;
    }
    if (!patch_ok(*h, s)) return false;  // destroyed disabled: nothing was written
    if (!h->enable()) {
        log::error("GuestS3: cannot enable {} (exe+0x{:X})", s.what, s.rva);
        return false;
    }
    out = std::move(*h);
    return true;
}

bool make_start() {
    if (!site_ok(kStart)) return false;
    auto h = safetyhook::InlineHook::create(reinterpret_cast<void*>(g_base + kStart.rva),
                                            reinterpret_cast<void*>(&start_detour), safetyhook::InlineHook::StartDisabled);
    if (!h) {
        log::error("GuestS3: cannot hook {} (exe+0x{:X})", kStart.what, kStart.rva);
        return false;
    }
    if (!patch_ok(*h, kStart)) return false;
    g_h_start = std::move(*h);  // the detour calls through it: in place before enabling
    if (!g_h_start.enable()) {
        log::error("GuestS3: cannot enable {} (exe+0x{:X})", kStart.what, kStart.rva);
        return false;
    }
    return true;
}

bool code_ready() {
    if (!game::validate_native_catalog()) return false;
    // The crash capture waits for the same marker (the game's code decrypted in place).
    if (g_guard.load() || g_diag.load() || g_crash.load()) {
        const Site consumer = null_consumer_site();
        if (!bytes_match(consumer.rva, consumer.bytes) || !bytes_match(null_read_rva(), null_read_bytes())) return false;
    }
    if (g_diag.load()) {
        // With guest_remote_update_guard, 0x85FBA0 is horse_diag's (its bytes change once hooked).
        const bool update_ok = g_update_taken.load() || bytes_match(kUpdate.rva, kUpdate.bytes);
        if (!update_ok || !bytes_match(kSpawn.rva, kSpawn.bytes) || !bytes_match(kSpawnAl.rva, kSpawnAl.bytes) ||
            !bytes_match(kAck.rva, kAck.bytes) || !bytes_match(kStart.rva, kStart.bytes)) {
            return false;
        }
    }
    return true;
}

void install_crash();
void rearm_crash_filter();

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const game::Build build = game::current_build();
    if (build == game::Build::unsupported ||
        !(game::legacy_layout() || build == game::Build::v3576 || build == game::Build::v3663)) {
        log::error("GuestS3: unsupported game build; guest_s3_diag / guest_crash_dump / guest_update_guard stay off");
        return 0;
    }
    if ((build == game::Build::v3527 || build == game::Build::v3576 || build == game::Build::v3663) &&
        g_diag.exchange(false)) {
        log::warn("GuestS3: optional guest_s3_diag probes are not ported to build {} and stay off; the required "
                  "guest update guard remains enabled",
                  build == game::Build::v3663 ? 3663 : build == game::Build::v3576 ? 3576 : 3527);
    }
    if (!read_rsrc()) {
        log::error("GuestS3: the game's section table has no .rsrc; nothing is installed");
        return 0;
    }
    LARGE_INTEGER f, t;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    GetSystemTimeAsFileTime(&g_ft_base);
    g_qpc_freq = f.QuadPart ? f.QuadPart : 1;
    g_qpc_base = t.QuadPart;
    if (g_diag.load() && !g_actor_diag.load()) {
        log::warn("GuestS3: guest_s3_diag=1 with guest_actor_diag=0: the restore results (exit 0x864B1D, hooked by "
                  "guest_actor_diag only) are NOT recorded; the 'restore' events and the restore counters stay at 0. "
                  "Set guest_actor_diag=1 to have them");
    }
    // As early as the game's code is there (2 minutes), like the guest's other
    // hooks; the crash capture too (nothing of it before the code is there).
    bool ready = false;
    for (int i = 0; i < 24000 && !(ready = code_ready()); ++i) Sleep(5);
    if (!ready) log::warn("GuestS3: the game's code is not the expected one after 2 minutes; installing what matches");
    if (g_crash.load()) install_crash();
    if (g_guard.load() || g_diag.load()) {
        const Site consumer = null_consumer_site();
        const uintptr_t read_rva = null_read_rva();
        const auto read_bytes = null_read_bytes();
        g_ret = static_cast<uint8_t*>(VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (g_ret) {
            g_ret[0] = 0xC3;
            DWORD old = 0;
            VirtualProtect(g_ret, 16, PAGE_EXECUTE_READ, &old);
            FlushInstructionCache(GetCurrentProcess(), g_ret, 16);
        }
        if (!g_ret) {
            log::error("GuestS3: no memory for the return stub; nothing hooked");
        } else {
            if (!bytes_match(read_rva, read_bytes)) {
                log::error("GuestS3: exe+0x{:X} is not the expected read of the current action; exe+0x{:X} REFUSED",
                           read_rva, consumer.rva);
            } else {
                g_null_on = make_mid(consumer, g_h_null, on_null_consumer);
            }
            if (g_diag.load()) {
                // One owner per entry: with guest_remote_update_guard=1, horse_diag hooks 0x85FBA0.
                if (!g_update_taken.load()) g_update_on = make_mid(kUpdate, g_h_update, on_update);
                g_spawn_on = make_mid(kSpawn, g_h_spawn, on_spawn);
                // The AL point only with its entry (it reads the entry's actor) and its call.
                if (g_spawn_on && bytes_match(kSpawnCall, kSpawnCallBytes)) {
                    g_spawn_al_on = make_mid(kSpawnAl, g_h_spawn_al, on_spawn_al);
                } else if (g_spawn_on) {
                    log::error("GuestS3: 0x48B18F is not the expected vf188(5) call; 0x48B197 REFUSED");
                }
                g_ack_on = make_mid(kAck, g_h_ack, on_ack);
                g_start_on = make_start();
            }
        }
        log::info("GuestS3 ON: {}{} | sites: exe+0x{:X} {} | Update 0x85FBA0 {} | 2723 0x48B120 {} / 0x48B197 {} | "
                  "2991 0x48AD40 {} | StartAction 0x863530 {} | crash capture {} | patched bytes checked inside .rsrc "
                  "[exe+0x{:X}, exe+0x{:X})",
                  g_diag.load() ? "probe (read only)" : "no probe",
                  g_guard.load() ? ", UPDATE GUARD (contention, not a fix): 0x232D5C0 returns at once for an actor "
                                   "not controlled locally whose current action is null"
                                 : "",
                  consumer.rva, g_null_on ? "on" : "OFF",
                  g_update_on ? "on" : (g_update_taken.load() && g_diag.load()) ? "left to guest_remote_update_guard"
                                                                                  : "-",
                  g_spawn_on ? "on" : "-",
                  g_spawn_al_on ? "on" : "-", g_ack_on ? "on" : "-", g_start_on ? "on" : "-",
                  g_crash_on ? "on" : (g_crash.load() ? "OFF" : "-"), g_rsrc_va,
                  static_cast<uint64_t>(g_rsrc_va) + g_rsrc_size);
        if (g_guard.load() && !g_null_on) {
            log::error("GuestS3: the update guard could NOT be installed; actors without an action stay unguarded at "
                       "exe+0x{:X}", consumer.rva);
        }
    } else {
        log::info("GuestS3 ON: crash capture {} only", g_crash_on ? "on" : "OFF");
    }
    for (;;) {
        refresh_local();
        // Every second: our top-level filter back in front if the game's crash
        // reporter replaced it (p8-hilo-red.md section 4: session 5's exit
        // crash never reached it).
        if (g_crash_on.load()) rearm_crash_filter();
        Sleep(1000);
    }
}

// ---------------------------------------------------------------- formatting (tick and crash only)

std::string narrow(const std::wstring& w) {
    std::string s;
    s.reserve(w.size());
    for (const wchar_t ch : w) s.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
    return s;
}

std::string when(uint64_t q) {
    const int64_t dq = static_cast<int64_t>(q) - g_qpc_base;
    ULARGE_INTEGER u;
    u.LowPart = g_ft_base.dwLowDateTime;
    u.HighPart = g_ft_base.dwHighDateTime;
    u.QuadPart += static_cast<uint64_t>(dq * 10000000 / g_qpc_freq);
    FILETIME ft{u.LowPart, u.HighPart}, lft{};
    SYSTEMTIME st{};
    FileTimeToLocalFileTime(&ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    return std::format("{:02}:{:02}:{:02}.{:03}", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

std::string layers_text(uint8_t b) {
    return std::format("L0 chart {} cur {} play {} | L1 chart {} cur {} play {}", b & 1 ? 1 : 0, b & 2 ? 1 : 0,
                       b & 4 ? 1 : 0, b & 8 ? 1 : 0, b & 16 ? 1 : 0, b & 32 ? 1 : 0);
}

std::string flags_text(uint32_t f) {
    return std::format("C1 {} C2 {} CF {} C8 {}", f & 0xFF, (f >> 8) & 0xFF, (f >> 16) & 0xFF, f >> 24);
}

const char* caller_name(uint32_t c) {
    switch (static_cast<s3::StartCaller>(c)) {
        case s3::StartCaller::Spawn2723: return "2723 0x48B120";
        case s3::StartCaller::Ack2991: return "2991 0x48AD40";
        case s3::StartCaller::Other: break;
    }
    return "other";
}

std::string text_of(const Record& r) {
    std::string s = std::format("[{} T{} e{}] {} 0x{:08X} ctrl 0x{:08X}: ", when(r.qpc), r.tid, r.epoch,
                                s3::ev_name(r.ev), r.key, r.control);
    switch (r.ev) {
        case Ev::Rx2005:
            s += std::format("type {} owner 0x{:08X} restore {} ({} bytes)", r.a, r.c,
                             r.b == 0xFF ? std::string("?") : std::to_string(r.b), r.d);
            break;
        case Ev::Rx2723:
        case Ev::Rx2991:
            s += std::format("A0 hash 0x{:08X} ({} bytes)", r.a, r.b);
            break;
        case Ev::Restore:
            s += std::format("restore byte {} -> result {}", r.a == 0xFF ? std::string("?") : std::to_string(r.a),
                             r.flags & 1 ? std::format("0x{:08X}", r.b) : std::string("unreadable"));
            break;
        case Ev::FirstUpdate:
            s += std::format("{} | +5E 0x{:04X} {} | CC+A8 {}{}", layers_text(r.flags), r.u16, flags_text(r.a), r.b,
                             chart_without_action(r.flags) ? " | CHART WITHOUT ACTION" : "");
            break;
        case Ev::Spawn2723:
            s += std::format("entered, actor +C8 {}", r.a);
            break;
        case Ev::Spawn2723Vf188:
            s += std::format("AL {} (C8 {}) -> {}", r.a, r.b,
                             r.a ? "applies" : "returns success WITHOUT applying (remote control)");
            break;
        case Ev::Ack2991:
            s += std::format("flag(r9b) {} bit [[CC+60]+10]&1 {}{}", r.a, r.b == 0xFF ? std::string("?") : std::to_string(r.b),
                             r.c ? " -> DISCARDED (returns 0)" : "");
            break;
        case Ev::StartAction:
            s += std::format("from {} (ret exe+0x{:X}) session {} -> result {} | after: {} -> {}", caller_name(r.b),
                             r.v[0], r.c, r.a == 0xFFFFFFFF ? std::string("unreadable") : std::format("0x{:08X}", r.a),
                             layers_text(r.flags),
                             r.a != 0 ? "error" : (r.flags & 2) ? "action INSTALLED" : "success WITHOUT an action on L0");
            break;
        case Ev::NullAction:
            s += std::format(
                "layer {} snapshot+10 NULL ({}{}) | L0 +0 0x{:X} +8 0x{:X} cur 0x{:X} play 0x{:X} chart 0x{:X} hash(+3C) "
                "0x{:08X} | L1 +0 {} +8 {} cur 0x{:X} play 0x{:X} chart 0x{:X} hash 0x{:08X} | CC+70 0x{:X} +78 0x{:X} "
                "+A8 {} | actor +5E 0x{:04X} {}",
                r.a, r.flags & 1 ? "not controlled here" : "controlled here", r.flags & 2 ? ", GUARDED" : "", r.v[8],
                r.v[9], r.v[0], r.v[1], r.v[2], r.b, r.flags & 4 ? "set" : "0", r.flags & 8 ? "set" : "0", r.v[3], r.v[4],
                r.v[5], r.c, r.v[6], r.v[7], r.flags & 16 ? "set" : "0", r.u16, flags_text(r.d));
            break;
        case Ev::GuardFirst:
            s += std::format("update guard: first skip (layer {}); contention, not a fix", r.a);
            break;
        case Ev::GuardRecovered:
            s += std::format("update guard: has an action again (layer {}) {} ms after its first skip, {} skips", r.c,
                             r.a, r.b);
            break;
        case Ev::Crash:
            s += std::format("exception 0x{:08X} at exe+0x{:X}{} ({} 0x{:X}) | rax 0x{:X} rbx 0x{:X} rcx 0x{:X} rdx "
                             "0x{:X} rsi 0x{:X} rdi 0x{:X} r8 0x{:X} r9 0x{:X} rsp 0x{:X} (the game's handlers ran next)",
                             r.a, r.c, r.flags & 1 ? " (the known site)" : "",
                             r.b == 0 ? "read of" : r.b == 1 ? "write to" : r.b == 8 ? "execute at" : "access to", r.v[0],
                             r.v[1], r.v[2], r.v[3], r.v[4], r.v[5], r.v[6], r.v[7], r.v[8], r.v[9]);
            break;
        default:
            break;
    }
    return s;
}

// Always printed (the rest is counted and shown in an actor's history).
bool notable(const Record& r) {
    switch (r.ev) {
        case Ev::NullAction:
        case Ev::Spawn2723Vf188:
        case Ev::Crash:
            return true;  // (the guard's own lines come from its table: guard_report)
        case Ev::Rx2005:
            return r.b == 0;  // published without an action
        case Ev::FirstUpdate:
            return chart_without_action(r.flags);
        case Ev::Restore:
            return r.a != 0 && (r.flags & 1) && r.b != 0;  // a failed restore
        case Ev::Ack2991:
            return r.c != 0;
        case Ev::StartAction:
            // The first one per actor and consumer, and every one that did not install.
            return r.a != 0 || !(r.flags & 2) ||
                   (r.b == 1 ? g_first_2723 : g_first_2991).insert(r.key) == Keys::Insert::Added;
        default:
            return false;
    }
}

bool interesting(const Record& r) { return r.ev == Ev::NullAction || r.ev == Ev::GuardFirst; }

void print_history(uint32_t key, uint64_t upto) {
    std::vector<Record> mine;
    for (uint64_t i = g_ring.oldest(); i < upto && mine.size() < 4 * kHistoryLines; ++i) {
        Record r;
        if (g_ring.read(i, r) && r.key == key) mine.push_back(r);
    }
    const size_t from = mine.size() > kHistoryLines ? mine.size() - kHistoryLines : 0;
    log::info("GuestS3 history of 0x{:08X} ({} record(s) in the ring{}):", key, mine.size(),
              from ? std::format(", the last {}", kHistoryLines) : std::string());
    for (size_t i = from; i < mine.size(); ++i) log::info("GuestS3   {}", text_of(mine[i]));
}

uint64_t g_cursor = 0;
std::string g_last_summary;

// The update guard's keys from its table (works without the probe too):
// each new key once (the first kGuardKeyLines), each recovery once.
constexpr uint64_t kGuardKeyLines = 64;
std::atomic<uint64_t> g_guard_key_lines{0};

void guard_report() {
    if (!g_guard_tab.size()) return;
    for (size_t i = 0; i < g_guard_tab.capacity(); ++i) {
        auto& s = g_guard_tab.at(i);
        const uint32_t key = s.key.load(std::memory_order_acquire);
        if (!key) continue;
        const uint8_t logged = s.logged.load();
        if (!(logged & 1)) {
            s.logged.fetch_or(1);
            if (g_guard_key_lines.fetch_add(1) < kGuardKeyLines) {
                log::info("GuestS3 update guard: holding 0x{:08X} (ctrl 0x{:08X}, local 0x{:08X}) since {}: 0x232D5C0 "
                          "entered with its current action (snapshot+0x10) null; returned at once (CONTENTION, not a "
                          "fix)",
                          key, s.control.load(), local(), when(s.first_qpc.load()));
            }
        }
        const uint64_t rec_q = s.recovered_qpc.load();
        if (rec_q && !(logged & 2)) {
            s.logged.fetch_or(2);
            log::info("GuestS3 update guard: 0x{:08X} has a current action again {} ms after its first skip ({} "
                      "skips){}",
                      key, (rec_q - s.first_qpc.load()) * 1000 / g_qpc_freq, s.skips.load(),
                      (logged & 4) ? " (it had been reported STUCK)" : "");
        }
    }
}

void stuck_report() {
    if (!g_guard_tab.size()) return;
    const uint64_t now = qpc();
    size_t shown = 0;
    for (size_t i = 0; i < g_guard_tab.capacity() && shown < 16; ++i) {
        auto& s = g_guard_tab.at(i);
        const uint32_t key = s.key.load(std::memory_order_acquire);
        if (!key || s.recovered_qpc.load() || (s.logged.load() & 4)) continue;
        const uint64_t age = (now - s.first_qpc.load()) * 1000 / g_qpc_freq;
        if (age < kStuckMs) continue;
        s.logged.fetch_or(4);
        c_stuck.fetch_add(1);
        ++shown;
        log::warn("GuestS3 update guard: 0x{:08X} (ctrl 0x{:08X}) is STUCK: no current action {} ms after its first "
                  "skip ({} skips, last {} ms ago). The guard only contains it; its first action never got installed",
                  key, s.control.load(), age, s.skips.load(), (now - s.last_qpc.load()) * 1000 / g_qpc_freq);
    }
}

std::string summary() {
    auto st = [](size_t c) {
        return std::format("{}/{}/{}", c_start[c][0].load(), c_start[c][1].load(), c_start[c][2].load());
    };
    return std::format(
        "GuestS3: 2005 records {} (restore 0: {}, 1: {}, no CC: {}) | rx 2723 {} 2991 {} | restore ok {} byte0 {} "
        "failed {} | first Update {} (chart without action {}) | 2723 consumer {} (vf188 true {}, FALSE {}) | 2991 "
        "consumer {} (discarded {}) | StartAction installed/success-without-action/error: from 2723 {}, from 2991 {}, "
        "other {} | null action at 0x232D5C0 {} (not controlled here {}, controlled here {}) | guard skips {} keys {} "
        "recovered {} stuck {} (table full {}) | ring {} records, {} lost before printing, {} lines suppressed | crash "
        "events {} (recorded {}, concurrent {}) dumps {}",
        c_rx2005.load(), c_rx2005_r0.load(), c_rx2005_r1.load(), c_rx2005_rx.load(), c_rx2723.load(), c_rx2991.load(),
        c_restore_ok.load(), c_restore_b0.load(), c_restore_fail.load(), c_first_upd.load(), c_first_upd_noact.load(),
        c_spawn.load(), c_spawn_al1.load(), c_spawn_al0.load(), c_ack.load(), c_ack_discard.load(), st(1), st(2), st(0),
        c_null.load(), c_null_remote.load(), c_null_local.load(), c_skips.load(), g_guard_tab.size(), c_recovered.load(),
        c_stuck.load(), g_guard_tab.full(), g_ring.head(), c_lost.load(), c_suppressed.load(), c_crash_events.load(),
        c_crash_recorded.load(), c_crash_busy.load(), c_dumps.load());
}

void tick_once() {
    const uint64_t head = g_ring.head();
    const uint64_t oldest = g_ring.oldest();
    if (g_cursor < oldest) {
        c_lost.fetch_add(oldest - g_cursor);
        g_cursor = oldest;
    }
    size_t lines = 0;
    for (; g_cursor < head; ++g_cursor) {
        Record r;
        if (!g_ring.read(g_cursor, r)) continue;
        if (interesting(r) && g_history_done.insert(r.key) == Keys::Insert::Added &&
            lines + kHistoryLines < kTickLines) {
            print_history(r.key, g_cursor + 1);
            lines += kHistoryLines;
            continue;
        }
        if (!notable(r)) continue;
        if (lines >= kTickLines) {
            c_suppressed.fetch_add(1);
            continue;
        }
        log::info("GuestS3 {}", text_of(r));
        ++lines;
    }
    guard_report();
    stuck_report();
    std::string s = summary();
    if (s != g_last_summary) {
        log::info("{}", s);
        g_last_summary = std::move(s);
    }
}

// ---------------------------------------------------------------- crash capture
//
// The vectored handler (added LAST, once the game's code is there) only
// RECORDS: an access violation inside the game's .rsrc becomes one fixed
// record in the ring (a wait-free push: no formatting, no lock, no I/O, no
// VirtualQuery, no wait), at most kMaxCrashRecords of them. The capture
// itself (log lines, the last records, the minidump) runs from the top-level
// filter (chained to the previous one) and, in the vectored handler, ONLY at
// the build-profiled current-action dereference (movzx eax,word [rax+field]
// with a null current action, p8-raiz-invitado.md §5): the P8 crash, which the game
// does not handle and ends the process; its reporter (Sentry) may replace our
// top-level filter, so there the vectored handler is the only place sure to run.

uintptr_t known_crash_site_rva() noexcept { return null_read_rva() + 4; }
constexpr uint32_t kMaxCrashRecords = 64;
constexpr size_t kKeepDumps = 2;  // cdmp_crash_*.dmp kept next to cdmp.asi (the newest)

using MiniDumpWriteDumpFn = BOOL(WINAPI*)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION,
                                          PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
MiniDumpWriteDumpFn g_write_dump = nullptr;
// The filter ours chains to: the one before ours, or the one that replaced ours
// (rearm_crash_filter puts ours back in front of it).
std::atomic<LPTOP_LEVEL_EXCEPTION_FILTER> g_prev_uef{nullptr};
std::atomic<uint32_t> g_uef_rearms{0};
std::wstring g_dump_dir;
// cdmp_crash, or cdmp_crash.<role> with CDMP_ROLE (role.h): set with g_dump_dir, before any crash can be handled.
std::wstring g_dump_stem = L"cdmp_crash";
HANDLE g_dump_go = nullptr, g_dump_done = nullptr;
HANDLE g_dump_thread = nullptr;  // signalled once the thread is gone (ExitProcess ends it)
EXCEPTION_POINTERS* g_dump_ep = nullptr;
DWORD g_dump_tid = 0;
std::atomic<uint32_t> g_dump_n{0};
s3::CrashGate<kMaxCrashEvents> g_crash_gate;
thread_local bool t_in_crash = false;

struct Range {
    uintptr_t base;
    uint32_t size;
};
std::array<Range, 40> g_ranges{};
size_t g_n_ranges = 0, g_next_range = 0;

bool readable(uintptr_t a, uint32_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (a < 0x10000 || !VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof mbi)) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return false;
    return a + n <= reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
}

void add_range(uintptr_t base, uint32_t size) {
    if (g_n_ranges < g_ranges.size() && readable(base, size)) g_ranges[g_n_ranges++] = {base, size};
}

BOOL CALLBACK dump_callback(PVOID, const PMINIDUMP_CALLBACK_INPUT in, PMINIDUMP_CALLBACK_OUTPUT out) {
    if (!in || !out) return TRUE;
    if (in->CallbackType == MemoryCallback) {
        if (g_next_range >= g_n_ranges) return FALSE;
        out->MemoryBase = g_ranges[g_next_range].base;
        out->MemorySize = g_ranges[g_next_range].size;
        ++g_next_range;
        return TRUE;
    }
    return TRUE;
}

// Keeps the newest `keep` cdmp_crash_*.dmp in the dump folder (bin64); returns how many went.
size_t rotate_dumps(size_t keep) {
    if (g_dump_dir.empty()) return 0;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((g_dump_dir + g_dump_stem + L"_*.dmp").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    std::vector<std::pair<uint64_t, std::wstring>> files;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const uint64_t t = static_cast<uint64_t>(fd.ftLastWriteTime.dwHighDateTime) << 32 | fd.ftLastWriteTime.dwLowDateTime;
        files.emplace_back(t, fd.cFileName);
    } while (FindNextFileW(h, &fd) && files.size() < 4096);
    FindClose(h);
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    size_t gone = 0;
    for (size_t i = keep; i < files.size(); ++i) {
        if (DeleteFileW((g_dump_dir + files[i].second).c_str())) ++gone;
    }
    return gone;
}

// One minidump of g_dump_ep / g_dump_tid: from the dump thread, or from the
// crashing thread itself when the dump thread is gone (`inline_note`).
void write_dump(const char* inline_note) {
    // The new one makes kKeepDumps.
    const size_t rotated = rotate_dumps(kKeepDumps - 1);
    SYSTEMTIME t{};
    GetLocalTime(&t);
    const std::wstring path =
        std::format(L"{}{}_{:04}{:02}{:02}-{:02}{:02}{:02}_{}_{}.dmp", g_dump_dir, g_dump_stem, t.wYear, t.wMonth, t.wDay,
                    t.wHour, t.wMinute, t.wSecond, GetCurrentProcessId(), g_dump_n.load());
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    BOOL ok = FALSE;
    if (f != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei{g_dump_tid, g_dump_ep, FALSE};
        MINIDUMP_CALLBACK_INFORMATION cb{dump_callback, nullptr};
        g_next_range = 0;
        const auto type = static_cast<MINIDUMP_TYPE>(MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithThreadInfo |
                                                     MiniDumpWithUnloadedModules | MiniDumpIgnoreInaccessibleMemory);
        ok = g_write_dump(GetCurrentProcess(), GetCurrentProcessId(), f, type, &mei, nullptr, &cb);
        CloseHandle(f);
    }
    if (ok) c_dumps.fetch_add(1);
    log::warn("GuestS3 crash capture: minidump {} {}{}{}", narrow(path),
              ok ? "written (local only)" : std::format("NOT written (error {})", GetLastError()),
              rotated ? std::format("; {} older dump(s) removed (the newest {} are kept)", rotated, kKeepDumps)
                      : std::string(),
              inline_note ? std::format(" | {}", inline_note) : std::string());
}

DWORD WINAPI dump_thread(LPVOID) {
    for (;;) {
        if (WaitForSingleObject(g_dump_go, INFINITE) != WAIT_OBJECT_0) return 0;
        write_dump(nullptr);
        SetEvent(g_dump_done);
    }
}

std::string ctx_text(const CONTEXT& c) {
    return std::format("rax 0x{:X} rbx 0x{:X} rcx 0x{:X} rdx 0x{:X} rsi 0x{:X} rdi 0x{:X} rbp 0x{:X} rsp 0x{:X} r8 "
                       "0x{:X} r9 0x{:X} r12 0x{:X} r13 0x{:X} r14 0x{:X} r15 0x{:X}",
                       c.Rax, c.Rbx, c.Rcx, c.Rdx, c.Rsi, c.Rdi, c.Rbp, c.Rsp, c.R8, c.R9, c.R12, c.R13, c.R14, c.R15);
}

// The client's ClientHierarchyActorComponent vtable (build 2976, RVA 0x5578BB8): its +8 is its actor too, and
// [+0x1C] the key of its hierarchy PARENT (0x15ECA10 finds the parent by that key). S35 (AUDITORIA.md §1 / §6, DMP
// 180710_6364_1): Shadow's second crash read the layer of B01004BF (R14 actor, RDX CC); RSI was this component of
// B0100578, which only QUERIED its parent B01004BF through the hierarchy. The S34 line called RSI a CharacterControl
// of B0100578: wrong actor. Such a register is now named for what it is, with its parent's key.
constexpr uint32_t kVtClientHierarchy = 0x5578BB8, kHier_Parent = 0x1C;

// A register that looks like a CharacterControl (its +8 is an actor whose key is an actor key).
void describe_cc(const char* reg, uintptr_t cc) {
    const ActorIds a = ids_of_cc(cc);
    if (!a.key || ((a.key >> 28) != 0xA && (a.key >> 28) != 0xB)) return;
    if (const uintptr_t vt = fpp(cc); vt && g_base && vt == g_base + kVtClientHierarchy) {
        uint32_t parent = 0;
        fp(cc + kHier_Parent, parent);
        log::warn("GuestS3 crash capture: {} 0x{:X} is the ClientHierarchyActorComponent (vtable exe+0x{:X}) of actor "
                  "0x{:X} key 0x{:08X} ctrl 0x{:08X}, NOT a CharacterControl: its hierarchy parent is key 0x{:08X} (the "
                  "actor whose layer such a query reads; look for that key's CharacterControl in the other registers)",
                  reg, cc, kVtClientHierarchy, a.actor, a.key, a.control, parent);
        add_range(a.actor, 0x100);
        add_range(cc, 0x40);
        return;
    }
    const uint8_t bits = layer_bits(cc);
    log::warn("GuestS3 crash capture: {} 0x{:X} looks like a CharacterControl: actor 0x{:X} key 0x{:08X} ctrl 0x{:08X} "
              "(local 0x{:08X}) | {} | actor {}",
              reg, cc, a.actor, a.key, a.control, local(), layers_text(bits), flags_text(actor_flags(a.actor)));
    add_range(a.actor, 0x100);
    for (uint32_t i = 0; i < 2; ++i) {
        if (const uintptr_t l = fpp(cc + kCc_Layer0 + 8 * i)) add_range(l, 0x120);
    }
    add_range(cc, 0x200);
}

void flush_records() {
    const uint64_t head = g_ring.head();
    const uint64_t from = head > kCrashFlush ? head - kCrashFlush : 0;
    log::warn("GuestS3 crash capture: the last {} record(s) of the S3 history:", head - from);
    for (uint64_t i = std::max(from, g_ring.oldest()); i < head; ++i) {
        Record r;
        if (g_ring.read(i, r)) log::warn("GuestS3   {}", text_of(r));
    }
}

// The capture: never from the vectored handler except at the profiled known site.
// One thread at a time, never twice for one address, at most
// kMaxCrashEvents (g_crash_gate); a concurrent crash goes on at once.
void capture(EXCEPTION_POINTERS* ep, const char* how) {
    const auto* er = ep->ExceptionRecord;
    const uintptr_t at = reinterpret_cast<uintptr_t>(er->ExceptionAddress);
    const auto gate = g_crash_gate.enter(at);
    if (gate != s3::CrashGate<kMaxCrashEvents>::Enter::Go) {
        if (gate == s3::CrashGate<kMaxCrashEvents>::Enter::Busy) c_crash_busy.fetch_add(1);
        return;
    }
    struct Leave {
        ~Leave() {
            // The log is asynchronous (p8-impl-log-async.md): the capture's lines reach the file before
            // the game's reporter (or Windows) ends the process; bounded, no lock held.
            log::flush(log::kCrashFlushMs);  // wait only (the writer writes; no lock, no I/O here)
            g_crash_gate.leave();
        }
    } leave;
    try {
        const uint64_t kind = er->NumberParameters >= 2 ? er->ExceptionInformation[0] : ~0ull;
        const uint64_t addr = er->NumberParameters >= 2 ? er->ExceptionInformation[1] : 0;
        log::warn("GuestS3 crash capture ({}): exception 0x{:08X} at {} ({} 0x{:X}), thread {} | {}", how,
                  static_cast<uint32_t>(er->ExceptionCode),
                  at >= g_base && in_rsrc(at - g_base, 1) ? std::format("exe+0x{:X}", at - g_base)
                                                          : std::format("0x{:X}", at),
                  kind == 0 ? "read of" : kind == 1 ? "write to" : kind == 8 ? "execute at" : "access to", addr,
                  GetCurrentThreadId(), ep->ContextRecord ? ctx_text(*ep->ContextRecord) : std::string("no context"));
        flush_records();
        if (!g_write_dump || !g_dump_go) return;
        const uint32_t n = g_dump_n.fetch_add(1);
        if (n >= kMaxDumps) return;
        g_n_ranges = 0;
        add_range(reinterpret_cast<uintptr_t>(g_ring.data()), static_cast<uint32_t>(g_ring.bytes()));
        if (const CONTEXT* c = ep->ContextRecord) {
            const std::pair<const char*, uintptr_t> regs[] = {{"rcx", c->Rcx}, {"rbx", c->Rbx}, {"rsi", c->Rsi},
                                                              {"rdi", c->Rdi}, {"r12", c->R12}, {"r13", c->R13},
                                                              {"r14", c->R14}, {"r15", c->R15}};
            for (const auto& [name, v] : regs) describe_cc(name, v);
            for (const uintptr_t v : {c->Rax, c->Rcx, c->Rdx, c->R8, c->R9, c->Rbx, c->Rsi, c->Rdi}) add_range(v, 0x100);
        }
        g_dump_ep = ep;
        g_dump_tid = GetCurrentThreadId();
        // During ExitProcess (Alt+F4) the dump thread may already be gone: the
        // dump is written from this thread then.
        if (!g_dump_thread || WaitForSingleObject(g_dump_thread, 0) == WAIT_OBJECT_0) {
            write_dump("written from the crashing thread: the dump thread is gone (process exit)");
            return;
        }
        ResetEvent(g_dump_done);
        SetEvent(g_dump_go);
        WaitForSingleObject(g_dump_done, 30000);
    } catch (...) {
        c_errors.fetch_add(1);
    }
}

bool in_game_code(uintptr_t at) { return at >= g_base && in_rsrc(at - g_base, 1); }

// Records only (see above); the capture only at the known site.
LONG CALLBACK crash_veh(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const EXCEPTION_RECORD* er = ep->ExceptionRecord;
    const uintptr_t at = reinterpret_cast<uintptr_t>(er->ExceptionAddress);
    if (!in_game_code(at)) return EXCEPTION_CONTINUE_SEARCH;
    c_crash_events.fetch_add(1, std::memory_order_relaxed);
    const uint64_t kind = er->NumberParameters >= 2 ? er->ExceptionInformation[0] : ~0ull;
    const uint64_t addr = er->NumberParameters >= 2 ? er->ExceptionInformation[1] : 0;
    const bool known = at - g_base == known_crash_site_rva();
    if (c_crash_recorded.fetch_add(1, std::memory_order_relaxed) < kMaxCrashRecords) {
        Record r = rec(Ev::Crash, 0, 0);
        r.a = static_cast<uint32_t>(er->ExceptionCode);
        r.b = static_cast<uint32_t>(kind);
        r.c = static_cast<uint32_t>(at - g_base);
        r.flags = known ? 1 : 0;
        r.v[0] = addr;
        if (const CONTEXT* c = ep->ContextRecord) {
            r.v[1] = c->Rax;
            r.v[2] = c->Rbx;
            r.v[3] = c->Rcx;
            r.v[4] = c->Rdx;
            r.v[5] = c->Rsi;
            r.v[6] = c->Rdi;
            r.v[7] = c->R8;
            r.v[8] = c->R9;
            r.v[9] = c->Rsp;
        }
        push(r);
    }
    if (known && kind == 0 && addr < 0x10000 && !t_in_crash) {
        t_in_crash = true;
        capture(ep, "first chance at the profiled null-action fault, vectored; the game does not handle it");
        t_in_crash = false;
    }
    return EXCEPTION_CONTINUE_SEARCH;  // never handled here
}

thread_local bool t_in_uef = false;

std::string where_is(const void* p);

// crashpad_handler.exe next to the game's exe (Sentry's default handler path,
// "%#/crashpad_handler.exe"; opcion-d-rpt0.md). Out of bin64 = K2. Computed once
// in install_crash (P8 review M9: never std::wstring/GetModuleFileNameW inside
// the top-level filter, where the heap may be the damaged thing).
std::atomic<bool> g_crashpad_present{true};
bool crashpad_present() {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (!n || n >= MAX_PATH) return true;  // unknown: keep the old behaviour (chain)
    std::wstring path = buf;
    path.resize(path.find_last_of(L"\\/") + 1);
    path += L"crashpad_handler.exe";
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// s3::uef_end said Terminate: the capture is done (or was done before for this
// address); wait for another thread's capture, if one is running, then end the
// process with the exception code. One line first: never silently.
[[noreturn]] void end_after_capture(uint32_t code, uintptr_t at) {
    const uint64_t t0 = GetTickCount64();
    while (g_crash_gate.busy() && GetTickCount64() - t0 < 35000) Sleep(50);
    // P8 review M9: written without allocating (the heap may be what failed);
    // the filter behind ours was named at install and by each re-arm line.
    game::FixedLine l;
    l.str("GuestS3 crash capture: unhandled exception ").hex32(code).str(" at ");
    if (at >= g_base && in_rsrc(at - g_base, 1)) {
        l.str("exe+").hex(at - g_base);
    } else {
        l.hex(at);
    }
    l.str(": the process ENDS NOW (TerminateProcess with that code; guest_crash_dump=1 and no crashpad_handler.exe: "
          "the filter behind ours would pass it on to Windows' error reporting, which kept the game alive 5 min 40 s "
          "in P8 session 6)");
    if (g_crash_gate.busy()) l.str(" | another thread's capture still running after 35 s");
    log::flush(log::kCrashFlushMs);  // wait only, bounded (with the capture's and emergency's: <= ~1 s in all)
    log::emergency(log::Level::Error, l.view());
    TerminateProcess(GetCurrentProcess(), code);
    // TerminateProcess on the own process does not return.
    for (;;) Sleep(INFINITE);
}

LONG WINAPI crash_uef(EXCEPTION_POINTERS* ep) {
    // Entered again through a filter that chains back to us: nothing twice, no loop.
    if (t_in_uef) return EXCEPTION_CONTINUE_SEARCH;
    t_in_uef = true;
    const auto prev = g_prev_uef.load();
    // A stack overflow leaves no stack to format or dump with: straight to the previous filter.
    if (ep && ep->ExceptionRecord && ep->ExceptionRecord->ExceptionCode != STATUS_STACK_OVERFLOW && !t_in_crash) {
        t_in_crash = true;
        capture(ep, "unhandled, top-level filter");
        t_in_crash = false;
    }
    // Only an access violation with guest_crash_dump=1 (this filter exists only
    // then) and no crashpad_handler.exe: the process ends here (s3::uef_end).
    if (ep && ep->ExceptionRecord) {
        const auto code = static_cast<uint32_t>(ep->ExceptionRecord->ExceptionCode);
        if (s3::uef_end(code, g_crash.load(), g_crashpad_present.load()) == s3::UefEnd::Terminate) {
            end_after_capture(code, reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
        }
    }
    // Otherwise never handled here: the game's reporter (or Windows) decides, as without us.
    const LONG r = prev && prev != &crash_uef ? prev(ep) : EXCEPTION_CONTINUE_SEARCH;
    t_in_uef = false;
    return r;
}

std::string where_is(const void* p) {
    const auto a = reinterpret_cast<uintptr_t>(p);
    if (!a) return "none";
    HMODULE m = nullptr;
    wchar_t buf[MAX_PATH] = {};
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           static_cast<LPCWSTR>(p), &m) &&
        GetModuleFileNameW(m, buf, MAX_PATH)) {
        std::wstring name = buf;
        name = name.substr(name.find_last_of(L"\\/") + 1);
        return std::format("{}+0x{:X}", narrow(name), a - reinterpret_cast<uintptr_t>(m));
    }
    return std::format("0x{:X} (no module)", a);
}

// Install thread, every second. Someone sets its own top-level filter after
// ours without chaining to it, so an unhandled crash never reached ours
// (session 5, the exit crash at exe+0x2045A6A: "crash events 1 (recorded 1)
// ... dumps 0"). In session 6 it was the CRT's __scrt_unhandled_exception_filter
// (exe+0x4896E00, [V] bytes: C++ exception -> terminate, else
// EXCEPTION_CONTINUE_SEARCH), not crashpad. Ours goes back in front, chained
// to it; nothing is handled here (crash_uef may end the process: s3::uef_end).
void rearm_crash_filter() {
    const LPTOP_LEVEL_EXCEPTION_FILTER cur = SetUnhandledExceptionFilter(crash_uef);
    if (cur == crash_uef) return;
    g_prev_uef.store(cur);
    const uint32_t n = g_uef_rearms.fetch_add(1) + 1;
    if (n <= 8) {
        log::warn("GuestS3 crash capture: the top-level exception filter had been replaced by {} (the game's crash "
                  "reporter?); ours is in front again and chains to it ({} time(s))",
                  where_is(reinterpret_cast<const void*>(cur)), n);
    }
}

// After code_ready() (the game's code is there): nothing of the protector's
// start-up runs through these handlers.
void install_crash() {
    HMODULE self = nullptr;
    wchar_t buf[MAX_PATH] = {};
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&install_crash), &self) &&
        GetModuleFileNameW(self, buf, MAX_PATH)) {
        g_dump_dir = buf;
        g_dump_dir.resize(g_dump_dir.find_last_of(L"\\/") + 1);
    }
    g_dump_stem = role::tagged(L"cdmp_crash");
    if (HMODULE dbg = LoadLibraryExW(L"dbghelp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        g_write_dump = reinterpret_cast<MiniDumpWriteDumpFn>(GetProcAddress(dbg, "MiniDumpWriteDump"));
    }
    g_dump_go = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_dump_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_write_dump && g_dump_go && g_dump_done && !g_dump_dir.empty()) {
        // Kept open: capture() checks whether the thread still exists.
        g_dump_thread = CreateThread(nullptr, 0, dump_thread, nullptr, 0, nullptr);
    } else {
        g_write_dump = nullptr;
        log::warn("GuestS3 crash capture: no dbghelp / no folder; only the log lines are written");
    }
    const size_t old_dumps = rotate_dumps(kKeepDumps);
    g_crashpad_present.store(crashpad_present());  // once, here (never inside the filter)
    // Last in the list: the game's and the protector's own handlers see their
    // exceptions first; this one only records.
    const PVOID veh = AddVectoredExceptionHandler(0, crash_veh);
    if (!veh) log::error("GuestS3 crash capture: the vectored handler could not be added");
    g_prev_uef.store(SetUnhandledExceptionFilter(crash_uef));
    g_crash_on = veh != nullptr;
    log::info("GuestS3 crash capture {}: access violations in the game's .rsrc code are recorded (first chance, "
              "vectored, last in the list, at most {}; recorded only, printed by the 5 s tick); unhandled exceptions "
              "(top-level filter, chained; stack overflows passed straight on) and the known site exe+0x{:X} write "
              "the last {} S3 records to this log and a minidump (at most {}; the newest {} kept, {} older removed) "
              "to {}; never handled here (previous top-level filter {})",
              veh ? "ON" : "OFF (top-level filter only)", kMaxCrashRecords, known_crash_site_rva(), kCrashFlush, kMaxDumps,
              kKeepDumps, old_dumps, narrow(g_dump_dir),
              g_prev_uef.load() ? where_is(reinterpret_cast<const void*>(g_prev_uef.load())) + ", chained" : "none");
    // pendientes/p8-salida-invitado.md §3: read once here (P8 review M9: not inside the filter any more).
    log::info("GuestS3 crash capture: crashpad_handler.exe {} -> an unhandled access violation {}",
              g_crashpad_present.load() ? "is next to the game" : "is NOT next to the game (K2)",
              g_crashpad_present.load() ? "is chained to the previous filter after the capture, as before"
                                 : "ENDS the process right after the capture (TerminateProcess with the exception "
                                   "code), instead of waiting in Windows' error reporting; other exceptions are chained "
                                   "as before");
}

}  // namespace

// ---------------------------------------------------------------- public

void guest_s3_start(bool diag, bool crash_dump, bool update_guard, bool actor_diag, bool update_site_taken) {
    if (!diag && !crash_dump && !update_guard) return;
    if (g_started.exchange(true)) return;
    g_diag = diag;
    g_actor_diag = actor_diag;
    g_update_taken = update_site_taken;
    g_crash = crash_dump;
    g_guard = update_guard;
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

bool guest_update_guard_ready() noexcept { return g_null_on.load(std::memory_order_acquire); }

bool guest_s3_wanted() { return g_started.load(); }

void guest_s3_tick() noexcept {
    // The crash capture's records too (printed here, never in its handler).
    if (!g_started.load() || (!g_diag.load() && !g_guard.load() && !g_crash_on.load())) return;
    try {
        tick_once();
    } catch (...) {
        c_errors.fetch_add(1);
    }
}

std::string guest_s3_describe() {
    if (!g_started.load()) return {};
    return std::format(" | GuestS3 diag {} guard {} crash {} | local 0x{:08X} | null actions {} (remote {}) | guard "
                       "skips {} keys {} recovered {} stuck {} | 2723 vf188 false {} | dumps {}",
                       g_diag.load() ? "on" : "off", g_guard.load() ? (g_null_on.load() ? "ON" : "OFF") : "off",
                       g_crash_on.load() ? "on" : "off", local(), c_null.load(), c_null_remote.load(), c_skips.load(),
                       g_guard_tab.size(), c_recovered.load(), c_stuck.load(), c_spawn_al0.load(), c_dumps.load());
}

void guest_s3_on_host_packet(uint16_t opcode, std::span<const uint8_t> payload, uint64_t epoch) noexcept {
    if (!g_started.load(std::memory_order_relaxed)) return;
    g_epoch.store(static_cast<uint32_t>(epoch), std::memory_order_relaxed);
    if (!g_diag.load(std::memory_order_relaxed)) return;
    try {
        if (opcode == kOp2005) {
            std::array<s3::Rec2005, 512> recs;
            const size_t n = s3::parse_2005(payload, recs);
            for (size_t i = 0; i < n; ++i) {
                const s3::Rec2005& x = recs[i];
                if (x.type == 0 || x.type > 6) continue;  // users' records and gimmicks
                c_rx2005.fetch_add(1, std::memory_order_relaxed);
                (x.restore == 0 ? c_rx2005_r0 : x.restore == 1 ? c_rx2005_r1 : c_rx2005_rx)
                    .fetch_add(1, std::memory_order_relaxed);
                Record r = rec(Ev::Rx2005, x.key, x.controller);
                r.a = x.type;
                r.b = x.restore < 0 ? 0xFF : static_cast<uint32_t>(x.restore);
                r.c = x.owner;
                r.d = x.size;
                push(r);
            }
        } else if ((opcode == kOp2723 || opcode == kOp2991) && payload.size() >= 12) {
            uint32_t key = 0, hash = 0;
            std::memcpy(&key, payload.data(), 4);
            std::memcpy(&hash, payload.data() + 8, 4);
            (opcode == kOp2723 ? c_rx2723 : c_rx2991).fetch_add(1, std::memory_order_relaxed);
            Record r = rec(opcode == kOp2723 ? Ev::Rx2723 : Ev::Rx2991, key, 0);
            r.a = hash;
            r.b = static_cast<uint32_t>(payload.size());
            push(r);
        }
    } catch (...) {
        c_errors.fetch_add(1, std::memory_order_relaxed);
    }
}

void guest_s3_note_restore(uint32_t key, uint32_t control, int restore, uint32_t code, bool code_ok) noexcept {
    if (!g_started.load(std::memory_order_relaxed) || !g_diag.load(std::memory_order_relaxed)) return;
    if (restore == 0) {
        c_restore_b0.fetch_add(1, std::memory_order_relaxed);
    } else if (code_ok && code == 0) {
        c_restore_ok.fetch_add(1, std::memory_order_relaxed);
    } else {
        c_restore_fail.fetch_add(1, std::memory_order_relaxed);
    }
    Record r = rec(Ev::Restore, key, control);
    r.a = restore < 0 ? 0xFF : static_cast<uint32_t>(restore);
    r.b = code;
    r.flags = code_ok ? 1 : 0;
    push(r);
}

}  // namespace cdmp::session2
