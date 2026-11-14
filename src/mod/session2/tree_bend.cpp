#include "mod/session2/tree_bend.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/player_reader.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/rope_probe.h"
#include "mod/session2/tree_bend_logic.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using tbl::Mode;

constexpr uintptr_t kCodeBegin = 0x1000;
// Where everything is, per build (tree_bend_logic.h). Log lines and comments keep the 2976 names (the research is written
// against that build); the addresses they print are this build's.
struct Addrs {
    uintptr_t code_end;
    uintptr_t vf2, vf2_slot, apply, apply_call, set_bend, set_bend_call, tick, tick_jump, get_target, find_tree;
    uintptr_t client_vtbl, main_thread_id;
    uint32_t control_f6, state_base, state_dir;
    std::span<const uint8_t> apply_call_bytes, set_bend_call_bytes, tick_jump_bytes;
};
const Addrs kAddrs2976{0x51EB000,
                       tbl::kVf2, tbl::kVf2Slot, tbl::kApply, tbl::kApplyCall, tbl::kSetBend, tbl::kSetBendCall, tbl::kTick,
                       tbl::kTickJump, tbl::kGetTarget, tbl::kFindTree,
                       tbl::kClientRemoteCatchVtbl, tbl::kMainThreadId,
                       tbl::kControl_F6, tbl::kStateBase, tbl::kState_Dir,
                       tbl::kApplyCallBytes, tbl::kSetBendCallBytes, tbl::kTickJumpBytes};
const Addrs kAddrs3527{tbl::kCodeEnd3527,
                       tbl::kVf23527, tbl::kVf2Slot3527, tbl::kApply3527, tbl::kApplyCall3527, tbl::kSetBend3527,
                       tbl::kSetBendCall3527, tbl::kTick3527, tbl::kTickJump3527, tbl::kGetTarget3527, tbl::kFindTree3527,
                       tbl::kClientRemoteCatchVtbl3527, tbl::kMainThreadId3527,
                       tbl::kControl_F63527, tbl::kStateBase3527, tbl::kState_Dir3527,
                       tbl::kApplyCallBytes3527, tbl::kSetBendCallBytes3527, tbl::kTickJumpBytes3527};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): tree_bend_logic.h's 3576 table; 3527's data offsets.
const Addrs kAddrs3576{tbl::kCodeEnd3576,
                       tbl::kVf23576, tbl::kVf2Slot3576, tbl::kApply3576, tbl::kApplyCall3576, tbl::kSetBend3576,
                       tbl::kSetBendCall3576, tbl::kTick3576, tbl::kTickJump3576, tbl::kGetTarget3576, tbl::kFindTree3576,
                       tbl::kClientRemoteCatchVtbl3576, tbl::kMainThreadId3576,
                       tbl::kControl_F63527, tbl::kStateBase3527, tbl::kState_Dir3527,
                       tbl::kApplyCallBytes3527, tbl::kSetBendCallBytes3576, tbl::kTickJumpBytes3576};
// Build 1.0.0.3663 (static, 2026-11-13; never run): tree_bend_logic.h's 3663 table; 3527's data offsets (f6 +0xFA, the
// slot state +0xA4C, the state's +0x3C0 / +0x3C8, all read again in 3663's code there).
const Addrs kAddrs3663{tbl::kCodeEnd3663,
                       tbl::kVf23663, tbl::kVf2Slot3663, tbl::kApply3663, tbl::kApplyCall3663, tbl::kSetBend3663,
                       tbl::kSetBendCall3663, tbl::kTick3663, tbl::kTickJump3663, tbl::kGetTarget3663, tbl::kFindTree3663,
                       tbl::kClientRemoteCatchVtbl3663, tbl::kMainThreadId3663,
                       tbl::kControl_F63527, tbl::kStateBase3527, tbl::kState_Dir3527,
                       tbl::kApplyCallBytes3663, tbl::kSetBendCallBytes3663, tbl::kTickJumpBytes3663};
const Addrs& addrs() noexcept {
    static const Addrs& a = game::current_build() == game::Build::v3663   ? kAddrs3663
                            : game::current_build() == game::Build::v3576 ? kAddrs3576
                            : game::current_build() == game::Build::v3527 ? kAddrs3527
                                                                          : kAddrs2976;
    return a;
}
// tbl::slot_state with this build's base.
uintptr_t slot_state(uintptr_t comp, uint8_t slot) noexcept {
    return comp + addrs().state_base + slot * tbl::kStateStride;
}
constexpr uint32_t kLoopMs = 10;
constexpr uint64_t kWorldTickMs = 500;
constexpr uint32_t kWorldTicks = 6;
constexpr uint64_t kMinuteMs = 60000;
constexpr uint64_t kEventLines = 400;
constexpr uint64_t kTailMs = 3000, kTailStepMs = 100;

enum EventKind : uint16_t {
    kEvVf2Start = 1,  // M1: a run of vf2 calls for a player character began
    kEvBend = 2,      // M3: a native SetBend
    kEvApply = 3,     // M4: an observer outcome (rate-limited)
    kEvRx = 4,        // a received frame that starts or ends a run (the network thread)
    kEvFault = 5,     // mode 1: a native call of the apply faulted (once per run)
};

std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_started{false}, g_guest{false}, g_hooks_on{false};
uintptr_t g_base = 0;
SafetyHookMid g_m1, g_m2, g_m3;
SafetyHookInline g_m4;

struct Range {
    uintptr_t lo = 0, hi = 0;
};
Range g_code[4];
size_t g_code_n = 0;
bool in_code(uintptr_t a) {
    for (size_t i = 0; i < g_code_n; ++i) {
        if (a >= g_code[i].lo && a < g_code[i].hi) return true;
    }
    return false;
}

p8p::EventRing<1024> g_ring;
// Review L1: per connection (switched on a new connection or when full; KeySwitch in tree_bend_logic.h).
tbl::KeySwitch<32> g_keyset;
tbl::KeyTable<32>& keys() { return g_keyset.active(); }
std::atomic<uint64_t> g_conn_epoch{0}, g_conn_changes{0};  // the last connection a frame came on (network threads)
// Review B1: the threads of this client's own native SetBend (M3) and of the tick for a remote thrower (M4), on THIS PC;
// and whether the native SetBend ran inside a RemoteCatch tick 0x59C0D0 (M4's depth counter).
tbl::TidSet<16> g_tids_m3_own, g_tids_m4_remote;
std::atomic<uint64_t> g_m3_in_tick{0}, g_m3_same_comp{0}, g_m3_out_tick{0};
thread_local int t_tick_depth = 0;
thread_local uintptr_t t_tick_comp = 0;
std::atomic<uint64_t> c_unsent{0};  // review L3: frames popped that the guest's queue to the host refused
std::atomic<uint64_t> g_m1_other{0}, g_m2_other{0}, g_m3_unmatched{0}, g_m4_other{0}, g_m4_own{0};
std::atomic<uint64_t> g_fights{0}, g_self_calls{0};
// S29: 0x8A30C0's inline SetBend copy for a REMOTE player here (rope_probe's hook -> tree_bend_note_pull): a fight too.
std::atomic<uint64_t> g_fights_inline{0}, g_pull_remote{0}, g_pull_own_inline{0};
std::atomic<bool> g_pull_seen{false};
// S29 guard: this PC's own open bend (M3, its own character): the tree's scene id and the time of its last SetBend.
// Review B-L1: one consistent copy (seqlock, tbl::OwnBend); records skipped because another thread was writing, counted.
tbl::OwnBend g_own_bend;
std::atomic<uint64_t> g_own_bend_skipped{0};
// Review B-M1: the time of this PC's own player's last inline bend in 0x8A30C0 (its tree's scene id is not at hand).
std::atomic<uint64_t> g_own_inline_us{0};
// S29 guard: the first fault of a native call turns application off for the rest of the run.
std::atomic<bool> g_apply_off{false};
std::atomic<uint64_t> g_outcome[static_cast<size_t>(tbl::Outcome::Count)] = {};
std::atomic<uint32_t> g_seq{0};

// The thrower side: the sender and its frames (the module's thread produces, the network threads consume).
std::mutex g_out_mu;
tbl::OutQueue g_out;  // under g_out_mu
std::atomic<uint64_t> c_sent{0}, c_popped{0}, c_refused{0};

// The observer side: what was received (network threads write, M4 reads with a try-lock).
SRWLOCK g_rx_lock = SRWLOCK_INIT;
tbl::Receiver g_rx;  // under g_rx_lock
std::atomic<uint64_t> c_rx[static_cast<size_t>(tbl::Rx::Count)] = {};
std::atomic<uint64_t> c_rx_bad{0}, c_rx_ignored{0}, c_rx_busy{0};

// M2 -> M3 on the same thread: the apply's context (its state pointer identifies SetBend's caller); M4 -> M3: our own
// SetBend call (not a native one).
struct ApplyCtx {
    uintptr_t actor = 0;
    uintptr_t state = 0;
    uint32_t key = 0;
    uint8_t ctl = 0xFF;
    uint8_t flag = 0;
};
thread_local ApplyCtx t_ctx{};
thread_local bool t_self = false;

Mode mode() { return static_cast<Mode>(g_mode.load(std::memory_order_relaxed)); }
uint64_t now_ms() { return p8_now_us() / 1000; }
uint32_t next_seq() { return g_seq.fetch_add(1, std::memory_order_relaxed) + 1; }
bool main_thread() {
    const auto id = game::fast<uint32_t>(g_base + addrs().main_thread_id);
    return id && *id == GetCurrentThreadId();
}
uint64_t pack2(float lo, float hi) {
    uint32_t a = 0, b = 0;
    std::memcpy(&a, &lo, 4);
    std::memcpy(&b, &hi, 4);
    return uint64_t{a} | (uint64_t{b} << 32);
}
float lo_f(uint64_t v) {
    const uint32_t a = static_cast<uint32_t>(v);
    float f;
    std::memcpy(&f, &a, 4);
    return f;
}
float hi_f(uint64_t v) {
    const uint32_t a = static_cast<uint32_t>(v >> 32);
    float f;
    std::memcpy(&f, &a, 4);
    return f;
}
uint64_t scene_lo(const uint8_t* s) {
    uint64_t v = 0;
    std::memcpy(&v, s, 8);
    return v;
}
uint64_t scene_hi(const uint8_t* s) {
    uint64_t v = 0;
    std::memcpy(&v, s + 8, 8);
    return v;
}
void scene_from(uint64_t lo, uint64_t hi, uint8_t* s) {
    std::memcpy(s, &lo, 8);
    std::memcpy(s + 8, &hi, 8);
}

int access_filter(const EXCEPTION_POINTERS* ep) noexcept {
    const EXCEPTION_RECORD* r = ep ? ep->ExceptionRecord : nullptr;
    if (!r) return EXCEPTION_CONTINUE_SEARCH;
    return r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || r->ExceptionCode == EXCEPTION_IN_PAGE_ERROR
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}
// Review L4: a slot of the CALLER's frame on this same thread (committed stack, the 5th argument at [entry rsp+0x28]):
// a plain SEH read, as docked_gimmicks / rope_probe (fast_read is for the game's heap).
bool seh_copy(uintptr_t a, void* out, size_t n) noexcept {
    if (a < 0x10000 || a > 0x00007FFFFFFFFFFFull - n) return false;
    __try {
        const volatile uint8_t* s = reinterpret_cast<const volatile uint8_t*>(a);
        uint8_t* d = static_cast<uint8_t*>(out);
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}

// The actor's key and control byte (guarded reads); key 0 when unreadable.
void actor_key(uintptr_t actor, uint32_t& key, uint8_t& ctl) noexcept {
    key = 0;
    ctl = 0xFF;
    if (!actor) return;
    if (const auto k = game::fast<uint32_t>(actor + tbl::kActor_Key)) key = *k;
    if (const auto c = game::fast<uint8_t>(actor + tbl::kActor_Control)) ctl = *c;
}
uintptr_t catch_comp(uintptr_t actor) noexcept {
    const auto comps = game::fast_ptr(actor + tbl::kActor_Comps);
    const auto comp = comps ? game::fast_ptr(*comps + tbl::kComps_RemoteCatch) : std::nullopt;
    return comp ? *comp : 0;
}
// Slot `slot` of a RemoteCatch component: kind, state, scene id.
tbl::SlotView read_slot(uintptr_t comp, uint8_t slot) noexcept {
    tbl::SlotView v;
    if (!comp) return v;
    const auto kind = game::fast<uint8_t>(tbl::slot_target(comp, slot) + tbl::kSlot_Kind);
    const auto state = game::fast<uint8_t>(slot_state(comp, slot));
    if (!kind || !state || !game::fast_read(tbl::slot_target(comp, slot) + tbl::kSlot_Scene, v.scene, 16)) return v;
    v.kind = *kind;
    v.state = *state;
    v.read_ok = true;
    return v;
}
// Before a native that takes the thrower's lock (FUN_1405b1600: cdmp_Actor_Lock of [[comp+8]+8]): the component is
// the client's and the lock object's vtable entries are the game's code (as remote_rope's release_safe).
bool client_comp_ok(uintptr_t comp) noexcept {
    const auto vt = game::fast<uint64_t>(comp);
    if (!vt || *vt != g_base + addrs().client_vtbl) return false;
    const auto actor = game::fast_ptr(comp + tbl::kComp_Owner);
    const auto lock = actor ? game::fast_ptr(*actor + tbl::kActor_LockObj) : std::nullopt;
    const auto lvt = lock ? game::fast_ptr(*lock) : std::nullopt;
    if (!lvt) return false;
    for (const uint32_t slot : tbl::kLockVf) {
        const auto f = game::fast_ptr(*lvt + slot);
        if (!f || !in_code(*f)) return false;
    }
    return true;
}

// ---------------------------------------------------------------- M1: RemoteCatchFunctions vf2 (log only)

void m1_fn(safetyhook::Context& ctx) {
    uint32_t key = 0;
    uint8_t ctl = 0xFF;
    actor_key(ctx.r8, key, ctl);
    tbl::KeyStats* s = keys().get(key);
    if (!s) {
        g_m1_other.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const bool main = main_thread();
    uint8_t f6 = 0xFF;
    const auto comps = game::fast_ptr(ctx.r8 + tbl::kActor_Comps);
    const auto control = comps ? game::fast_ptr(*comps + tbl::kComps_Control) : std::nullopt;
    const auto a = control ? game::fast_ptr(*control + tbl::kControl_F6a) : std::nullopt;
    const auto b = a ? game::fast_ptr(*a + tbl::kControl_F6b) : std::nullopt;
    if (b) {
        if (const auto v = game::fast<uint8_t>(*b + addrs().control_f6)) f6 = *v;
    }
    s->ctl.store(ctl, std::memory_order_relaxed);
    const uint64_t calls = s->m1_calls.fetch_add(1, std::memory_order_relaxed) + 1;
    if (main) s->m1_main.fetch_add(1, std::memory_order_relaxed);
    if (t_tick_depth > 0) s->m1_in_tick.fetch_add(1, std::memory_order_relaxed);
    if (f6 == 1) s->m1_f6.fetch_add(1, std::memory_order_relaxed);
    const uint64_t now = p8_now_us();
    const uint64_t prev = s->m1_last_us.exchange(now, std::memory_order_relaxed);
    if (!prev || now - prev > tbl::kRunGapUs) {
        s->m1_runs.fetch_add(1, std::memory_order_relaxed);
        p8p::Event e;
        e.qpc_us = now;
        e.tid = GetCurrentThreadId();
        e.kind = kEvVf2Start;
        e.v[0] = key | (uint64_t{ctl} << 32) | (uint64_t{static_cast<uint8_t>(ctx.r9)} << 40) | (uint64_t{f6} << 48) |
                 (uint64_t{main ? 1u : 0u} << 56);
        e.v[1] = calls;
        e.v[2] = next_seq();
        g_ring.push(e);
    }
}

// ---------------------------------------------------------------- M2: the bend's apply (counts; context for M3)

void m2_fn(safetyhook::Context& ctx) {
    ApplyCtx c;
    c.actor = ctx.r9;
    c.flag = static_cast<uint8_t>(ctx.r8 & 0xFF);
    uint64_t st = 0;
    if (seh_copy(ctx.rsp + 0x28, &st, sizeof st)) c.state = static_cast<uintptr_t>(st);
    actor_key(c.actor, c.key, c.ctl);
    t_ctx = c;
    tbl::KeyStats* s = keys().get(c.key);
    if (!s) {
        g_m2_other.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    s->ctl.store(c.ctl, std::memory_order_relaxed);
    (c.flag ? s->m2_flag1 : s->m2_flag0).fetch_add(1, std::memory_order_relaxed);
    if (c.ctl == 0) g_fights.fetch_add(1, std::memory_order_relaxed);  // the native path for a REMOTE character here
}

// ---------------------------------------------------------------- M3: SetBend (the thrower's values)

void m3_fn(safetyhook::Context& ctx) {
    if (t_self) {
        g_self_calls.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const uintptr_t tree = ctx.rcx;
    const uintptr_t dirp = ctx.rdx;
    const float amount = ctx.xmm2.f32[0];
    const ApplyCtx c = t_ctx;
    const bool matched = c.state && dirp == c.state + addrs().state_dir;
    float dir[3] = {0.0f, 0.0f, 0.0f};
    (void)game::fast_read(dirp, dir, sizeof dir);
    uint8_t scene[16] = {};
    if (matched) {
        if (const uintptr_t comp = catch_comp(c.actor)) (void)game::fast_read(tbl::slot_target(comp, 0) + tbl::kSlot_Scene, scene, 16);
    } else {
        g_m3_unmatched.fetch_add(1, std::memory_order_relaxed);
    }
    const bool main = main_thread();
    // Review B1: inside this client's RemoteCatch tick 0x59C0D0 (M4's depth on this thread), and inside the tick of this
    // actor's own component? Measured, never refused on.
    const bool in_tick = t_tick_depth > 0;
    const bool same_comp = in_tick && matched && t_tick_comp && t_tick_comp == catch_comp(c.actor);
    if (matched) {
        if (tbl::KeyStats* s = keys().get(c.key)) {
            s->m3_calls.fetch_add(1, std::memory_order_relaxed);
            if (main) s->m3_main.fetch_add(1, std::memory_order_relaxed);
            if (in_tick) s->m3_in_tick.fetch_add(1, std::memory_order_relaxed);
            if (same_comp) s->m3_same_comp.fetch_add(1, std::memory_order_relaxed);
            s->m3_tid.store(GetCurrentThreadId(), std::memory_order_relaxed);
        }
        if (c.ctl == 0) {
            g_fights.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_tids_m3_own.add(GetCurrentThreadId());
            if (tbl::scene_set(scene)) {  // S29 guard: the observer skips this tree while it is bent here
                if (!g_own_bend.record(scene_lo(scene), scene_hi(scene), p8_now_us())) {
                    g_own_bend_skipped.fetch_add(1, std::memory_order_relaxed);
                }
            }
            (in_tick ? g_m3_in_tick : g_m3_out_tick).fetch_add(1, std::memory_order_relaxed);
            if (same_comp) g_m3_same_comp.fetch_add(1, std::memory_order_relaxed);
        }
    }
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEvBend;
    e.flags = static_cast<uint16_t>((matched ? 1u : 0u) | (main ? 2u : 0u) | (in_tick ? 4u : 0u) | (same_comp ? 8u : 0u));
    e.v[0] = (matched ? c.key : 0u) | (uint64_t{matched ? c.ctl : uint8_t{0xFF}} << 32) | (uint64_t{c.flag} << 40);
    e.v[1] = tree;
    e.v[2] = pack2(amount, dir[0]);
    e.v[3] = pack2(dir[1], dir[2]);
    e.v[4] = scene_lo(scene);
    e.v[5] = scene_hi(scene);
    e.v[6] = next_seq();
    g_ring.push(e);
}

// ---------------------------------------------------------------- M4: the RemoteCatch tick (the observer)

using TickFn = uint64_t (*)(uint64_t comp, float dt);
using GetTargetFn = uint64_t (*)(uint64_t comp, uint8_t slot);
using FindTreeFn = uint64_t (*)(uint64_t obj);
using SetBendFn = void (*)(uint64_t tree, const float* dir, float amount);

void count_outcome(tbl::Outcome o) { g_outcome[static_cast<size_t>(o)].fetch_add(1, std::memory_order_relaxed); }

void push_apply(tbl::KeyStats* s, uint32_t key, tbl::Outcome o, bool main, const tbl::Pose* p, const tbl::SlotView& v) {
    const uint64_t now = p8_now_us();
    const uint8_t oc = static_cast<uint8_t>(o);
    if (!tbl::apply_line_due(s->m4_last_outcome.load(std::memory_order_relaxed), oc,
                             s->m4_last_ev_us.load(std::memory_order_relaxed), now)) {
        return;
    }
    s->m4_last_outcome.store(oc, std::memory_order_relaxed);
    s->m4_last_ev_us.store(now, std::memory_order_relaxed);
    p8p::Event e;
    e.qpc_us = now;
    e.tid = GetCurrentThreadId();
    e.kind = kEvApply;
    e.flags = main ? 1 : 0;
    e.v[0] = key | (uint64_t{oc} << 32);
    e.v[1] = p ? pack2(p->amount, static_cast<float>(p->age_ms)) : 0;
    e.v[2] = p ? pack2(p->dx, p->dz) : 0;
    e.v[3] = p ? scene_lo(p->scene) : 0;
    e.v[4] = p ? scene_hi(p->scene) : 0;
    e.v[5] = v.kind | (uint64_t{v.state} << 8) | (uint64_t{v.read_ok ? 1u : 0u} << 16);
    e.v[6] = scene_lo(v.scene);
    e.v[7] = scene_hi(v.scene);
    e.v[8] = p ? (p->run | (uint64_t{p->seq} << 32)) : 0;
    e.v[9] = next_seq();
    g_ring.push(e);
}

// Mode 1's native calls (the ones 0x1190FD0 uses), under SEH (S29 guard): 0 applied, 1 no object, 2 no TreeComponent,
// -1 a fault (`code` = the exception). No C++ object with a destructor in here.
int apply_native(uint64_t comp, const float* dir, float amount, uint32_t& code) noexcept {
    const Addrs& ad = addrs();
    const auto get_target = reinterpret_cast<GetTargetFn>(g_base + ad.get_target);
    const auto find_tree = reinterpret_cast<FindTreeFn>(g_base + ad.find_tree);
    const auto set_bend = reinterpret_cast<SetBendFn>(g_base + ad.set_bend);
    int r = -1;
    __try {
        const uint64_t obj = get_target(comp, 0);
        const uint64_t tree = obj ? find_tree(obj) : 0;
        if (!obj) {
            r = 1;
        } else if (!tree) {
            r = 2;
        } else {
            t_self = true;
            set_bend(tree, dir, amount);
            t_self = false;
            r = 0;
        }
    } __except (code = GetExceptionCode(), access_filter(GetExceptionInformation())) {
        t_self = false;
        r = -1;
    }
    return r;
}

void observe(uint64_t comp) noexcept {
    const auto actor = game::fast_ptr(comp + tbl::kComp_Owner);
    uint32_t key = 0;
    uint8_t ctl = 0xFF;
    if (actor) actor_key(*actor, key, ctl);
    if (!tbl::player_key(key)) {
        g_m4_other.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (ctl != 0) {
        g_m4_own.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    tbl::KeyStats* s = keys().get(key);
    if (!s) return;
    const bool main = main_thread();
    s->ctl.store(ctl, std::memory_order_relaxed);
    s->m4_calls.fetch_add(1, std::memory_order_relaxed);
    if (main) s->m4_main.fetch_add(1, std::memory_order_relaxed);
    s->m4_tid.store(GetCurrentThreadId(), std::memory_order_relaxed);
    g_tids_m4_remote.add(GetCurrentThreadId());
    std::optional<tbl::Pose> pose;
    if (!TryAcquireSRWLockShared(&g_rx_lock)) {
        count_outcome(tbl::Outcome::Busy);
        return;
    }
    pose = g_rx.query(key, 0, now_ms());
    ReleaseSRWLockShared(&g_rx_lock);
    if (!pose) {
        count_outcome(tbl::Outcome::NoSample);
        return;
    }
    const bool client = client_comp_ok(comp);
    const tbl::SlotView v = read_slot(comp, 0);
    tbl::Outcome o = tbl::decide(client, v, *pose);
    if (o == tbl::Outcome::WouldApply) {
        // S29 guards (probe evaluates them too): the main thread only; not while this PC's own player bends the same
        // tree (its native SetBend, a consistent copy) or any tree under it (its inline bend in 0x8A30C0, review
        // B-M1); off after a fault.
        const uint64_t now = p8_now_us();
        const bool own_same = g_own_bend.same_tree_now(pose->scene, now);
        const bool own_inline = tbl::own_inline_recent(g_own_inline_us.load(std::memory_order_acquire), now);
        o = tbl::apply_gate(g_apply_off.load(std::memory_order_relaxed), main, own_same, own_inline);
    }
    if (o == tbl::Outcome::WouldApply && mode() == Mode::On) {
        const float dir[3] = {pose->dx, 0.0f, pose->dz};
        uint32_t code = 0;
        const int r = apply_native(comp, dir, pose->amount, code);
        if (r == 0) {
            o = tbl::Outcome::Applied;
            s->m4_last_apply_us.store(p8_now_us(), std::memory_order_relaxed);
        } else if (r == 1) {
            o = tbl::Outcome::NoObject;
        } else if (r == 2) {
            o = tbl::Outcome::NoTree;
        } else {
            o = tbl::Outcome::Faulted;
            if (!g_apply_off.exchange(true)) {
                p8p::Event e;
                e.qpc_us = p8_now_us();
                e.tid = GetCurrentThreadId();
                e.kind = kEvFault;
                e.v[0] = key;
                e.v[1] = code;
                e.v[2] = next_seq();
                g_ring.push(e);
            }
        }
    }
    count_outcome(o);
    push_apply(s, key, o, main, &*pose, v);
}

uint64_t m4_detour(uint64_t comp, float dt) {
    // Review B1: the depth (and the component) of the tick on this thread, for M1 / M3: does the thrower's NATIVE
    // SetBend run inside 0x59C0D0 (the tick calls [comp+0xC68]->vf+0x20(owner, slot, dt, comp+0x168+slot*0x3E0))?
    const uintptr_t prev_comp = t_tick_comp;
    ++t_tick_depth;
    t_tick_comp = static_cast<uintptr_t>(comp);
    const uint64_t r = g_m4.unsafe_call<uint64_t>(comp, dt);
    t_tick_comp = prev_comp;
    --t_tick_depth;
    if (comp) observe(comp);
    return r;
}

// ---------------------------------------------------------------- install (the module's thread, world up)

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}
bool qword_at(uintptr_t rva, uint64_t expected) {
    uint64_t v = 0;
    return game::safe_read(g_base + rva, &v, sizeof v) && v == expected;
}

bool install_hooks() {
    const Addrs& ad = addrs();
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("TreeBend: the exe's sections are unreadable; REFUSED, nothing written");
        return false;
    }
    g_code_n = 0;
    for (const auto& s : secs) {
        // Every executable section: the real code and the protected RWX one, where vtable entries may also be.
        if ((s.flags & gad::kScnExecute) && g_code_n < std::size(g_code)) {
            g_code[g_code_n++] = {g_base + s.va, g_base + s.va + s.size};
        }
    }
    const auto in_rsrc = [&](uintptr_t rva, size_t n) {
        return rva >= kCodeBegin && rva + n <= ad.code_end &&
               gad::in_real_code(secs, static_cast<uint32_t>(rva), static_cast<uint32_t>(n));
    };
    struct Check {
        uintptr_t rva;
        std::span<const uint8_t> bytes;
        const char* what;
    };
    const Check checks[] = {
        {ad.vf2, tbl::kVf2Head, "RemoteCatchFunctions vf2 0x117F7E0's entry"},
        {ad.apply, tbl::kApplyHead, "the bend's apply 0x1190FD0's entry"},
        {ad.apply_call, ad.apply_call_bytes, "vf2's call 0x117F911 (call 0x1190FD0)"},
        {ad.set_bend, tbl::kSetBendHead, "TreeComponent::SetBend 0x349EA10's entry"},
        {ad.set_bend_call, ad.set_bend_call_bytes, "the apply's call 0x1191532 (call SetBend)"},
        {ad.tick, tbl::kTickHead, "the RemoteCatch tick 0x59C0D0's entry"},
        {ad.tick_jump, ad.tick_jump_bytes, "the remote actors' job 0x8A5DA0 (jmp 0x59C0D0)"},
        {ad.get_target, tbl::kGetTargetHead, "FUN_1405b1600's entry (the slot's scene object)"},
        {ad.find_tree, tbl::kFindTreeHead, "FUN_140491ac0's entry (its TreeComponent)"},
    };
    for (const Check& c : checks) {
        if (!in_rsrc(c.rva, c.bytes.size()) || !bytes_at(c.rva, c.bytes)) {
            log::error("TreeBend: {} (exe+0x{:X}, {} bytes) is not this build's expected code; REFUSED, nothing written",
                       c.what, c.rva, c.bytes.size());
            return false;
        }
    }
    if (!qword_at(ad.vf2_slot, g_base + ad.vf2)) {
        log::error("TreeBend: the vtable slot exe+0x{:X} does not hold exe+0x{:X}; REFUSED, nothing written", ad.vf2_slot,
                   ad.vf2);
        return false;
    }
    if (!game::fast<uint32_t>(g_base + ad.main_thread_id)) {
        log::error("TreeBend: the main thread's id exe+0x{:X} is unreadable; REFUSED, nothing written", ad.main_thread_id);
        return false;
    }
    // M4 first prepared (disabled), then the three mid hooks, then M4 enabled: any failure puts everything back.
    auto h = game::prepare_inline(
        g_base + ad.tick, reinterpret_cast<void*>(&m4_detour),
        [](const std::vector<uint8_t>& o) {
            return o.size() == tbl::kTickPatch[0] && std::memcmp(o.data(), tbl::kTickHead, o.size()) == 0;
        },
        "TreeBend", "the RemoteCatch tick 0x59C0D0");
    if (!h) {
        log::error("TreeBend: the hook on the RemoteCatch tick 0x59C0D0 could not be prepared ({}); REFUSED, nothing "
                   "written",
                   game::inline_error_text(h.error()));
        return false;
    }
    if (h->original_bytes().size() != tbl::kTickPatch[0]) {
        log::error("TreeBend: the hook on 0x59C0D0 would patch {} bytes, not the 5 verified; REFUSED, nothing written",
                   h->original_bytes().size());
        return false;
    }
    const bool mids =
        p8_install_mid(g_base, secs, ad.set_bend, tbl::kSetBendPatch, tbl::kSetBendHead, m3_fn, g_m3, "TreeBend",
                       "TreeComponent::SetBend 0x349EA10 (M3)") &&
        p8_install_mid(g_base, secs, ad.apply, tbl::kApplyPatch, tbl::kApplyHead, m2_fn, g_m2, "TreeBend",
                       "the bend's apply 0x1190FD0 (M2)") &&
        p8_install_mid(g_base, secs, ad.vf2, tbl::kVf2Patch, tbl::kVf2Head, m1_fn, g_m1, "TreeBend",
                       "RemoteCatchFunctions vf2 0x117F7E0 (M1)");
    if (!mids) {
        g_m1 = {};
        g_m2 = {};
        g_m3 = {};
        log::error("TreeBend: a mid hook is not in; the others are put back; REFUSED");
        return false;
    }
    g_m4 = std::move(*h);
    if (!g_m4.enable()) {
        g_m4 = {};
        g_m1 = {};
        g_m2 = {};
        g_m3 = {};
        log::error("TreeBend: the hook on 0x59C0D0 could not be enabled; everything put back; REFUSED");
        return false;
    }
    g_hooks_on.store(true);
    log::info("TreeBend: hooked at their entries (5/7/5/5 bytes patched): exe+0x{:X} (RemoteCatchFunctions vf2, M1), "
              "exe+0x{:X} (the bend's apply, M2), exe+0x{:X} (TreeComponent::SetBend, M3: the thrower's values, "
              "sent), exe+0x{:X} (the RemoteCatch tick, M4: the observer {})",
              ad.vf2, ad.apply, ad.set_bend, ad.tick,
              mode() == Mode::On ? "APPLIES the remote thrower's bend after the original"
                                 : "logs what it would apply; nothing of the game is written");
    return true;
}

// ---------------------------------------------------------------- the module's thread

bool build_ok() {
    const game::Build b = game::current_build();
    return g_base == g2976::kImageBase && (b == game::Build::v2976 || b == game::Build::v3527 ||
                                           b == game::Build::v3576 || b == game::Build::v3663);
}

std::string ctl_text(uint8_t ctl) {
    if (ctl == 0xFF) return "control unread";
    return ctl ? std::format("controlled HERE (+0xC8 = {})", ctl) : std::string("REMOTE here");
}
std::string scene_text(uint64_t lo, uint64_t hi) { return std::format("{:016X}:{:016X}", lo, hi); }
std::string thread_text(bool main, uint32_t tid) { return std::format("tid {} ({})", tid, main ? "main" : "worker"); }

// The thrower's runs as the log sees them (the module's thread).
struct RunLog {
    uint32_t key = 0;
    bool open = false;
    uint32_t run = 0;
    uint64_t start_us = 0;
    uint32_t frames = 0, sent = 0;
    uint32_t in_tick = 0, same_comp = 0;  // review B1: frames whose native SetBend ran inside 0x59C0D0
    float first = 0, mn = 0, mx = 0, last = 0;
    float dx = 0, dz = 0;
    uintptr_t tree = 0;
    uint64_t scene_lo = 0, scene_hi = 0;
    uint32_t tid = 0;
    bool main = false;
};
struct Tail {
    bool on = false;
    uint32_t key = 0, run = 0;
    uintptr_t tree = 0;
    uint64_t start_ms = 0, next_ms = 0;
    std::string values;
    size_t n = 0;
};
struct Vf2Run {
    uint32_t key = 0;
    bool open = false;
    uint64_t start_calls = 0;
    uint64_t start_us = 0;
};

struct State {
    tbl::Sender sender;
    RunLog runs[4];
    Tail tails[4];
    Vf2Run vf2[8];
    uint64_t lines = 0, not_logged = 0;
    uint64_t bends_unmatched = 0, bends_remote = 0, bends_refused = 0;
};

bool may_log(State& st) {
    if (st.lines++ < kEventLines) return true;
    ++st.not_logged;
    return false;
}

RunLog* run_of(State& st, uint32_t key) {
    for (RunLog& r : st.runs) {
        if (r.key == key) return &r;
    }
    for (RunLog& r : st.runs) {
        if (!r.key || !r.open) {
            r = RunLog{};
            r.key = key;
            return &r;
        }
    }
    return nullptr;
}

void queue_frame(const tbl::Sample& s) {
    std::lock_guard lk(g_out_mu);
    g_out.push(s);
    c_sent.fetch_add(1, std::memory_order_relaxed);
}

// A run's END line and its tail sampling (the module's thread).
void close_run(State& st, RunLog* rl, uint64_t now_ms_v, const char* why) {
    if (!rl || !rl->open) return;
    rl->open = false;
    if (may_log(st)) {
        log::info("TreeBend bend run END {}: character 0x{:08X} | run {} | tree scene {} | frames {} (sent {}) | "
                  "amount first {:.3f} min {:.3f} max {:.3f} last {:.3f} | dir ({:.3f}, {:.3f}) | {} | native SetBend "
                  "inside this PC's RemoteCatch tick 0x59C0D0: {} of {} frames ({} in its own component's tick) | {}",
                  p8_when(now_ms_v * 1000), rl->key, rl->run, scene_text(rl->scene_lo, rl->scene_hi), rl->frames,
                  rl->sent, rl->first, rl->mn, rl->mx, rl->last, rl->dx, rl->dz, thread_text(rl->main, rl->tid),
                  rl->in_tick, rl->frames, rl->same_comp, why);
    }
    for (Tail& t : st.tails) {
        if (!t.on) {
            t = Tail{};
            t.on = true;
            t.key = rl->key;
            t.run = rl->run;
            t.tree = rl->tree;
            t.start_ms = now_ms_v;
            t.next_ms = now_ms_v;
            break;
        }
    }
}

void on_bend_event(const p8p::Event& e, State& st) {
    const bool matched = (e.flags & 1) != 0;
    const bool main = (e.flags & 2) != 0;
    const bool in_tick = (e.flags & 4) != 0;
    const bool same_comp = (e.flags & 8) != 0;
    const uint32_t key = static_cast<uint32_t>(e.v[0]);
    const uint8_t ctl = static_cast<uint8_t>(e.v[0] >> 32);
    const uint8_t flag = static_cast<uint8_t>(e.v[0] >> 40);
    if (!matched) {
        ++st.bends_unmatched;
        return;
    }
    if (ctl == 0 || ctl == 0xFF || !tbl::player_key(key)) {  // a remote character's native bend here: a fight
        ++st.bends_remote;
        return;
    }
    tbl::Bend b;
    b.key = key;
    b.slot = 0;
    b.flags = flag ? tbl::kFlagApplyFlag : 0;
    scene_from(e.v[4], e.v[5], b.scene);
    b.amount = lo_f(e.v[2]);
    b.dx = hi_f(e.v[2]);
    b.dz = hi_f(e.v[3]);
    b.t_ms = e.qpc_us / 1000;
    const auto r = st.sender.on_bend(b);
    if (r.refused) ++st.bends_refused;
    RunLog* rl = run_of(st, key);
    // Another tree while a run was active: its End goes first (lower seq), then the new run's first Sample.
    if (r.end_first) {
        queue_frame(r.end_first->end);
        close_run(st, rl, e.qpc_us / 1000, "End sent (another tree)");
    }
    if (r.out) queue_frame(*r.out);
    if (!rl) return;
    if (r.new_run || !rl->open) {
        *rl = RunLog{};
        rl->key = key;
        rl->open = true;
        rl->run = r.out ? r.out->run : 0;
        rl->start_us = e.qpc_us;
        rl->first = rl->mn = rl->mx = b.amount;
        rl->tree = static_cast<uintptr_t>(e.v[1]);
        rl->scene_lo = e.v[4];
        rl->scene_hi = e.v[5];
        rl->tid = e.tid;
        rl->main = main;
        if (may_log(st)) {
            log::info("TreeBend #{} bend run START {}: character 0x{:08X} ({}) | run {} | tree scene {}{} | amount {:.3f} "
                      "dir ({:.3f}, {:.3f}) | apply flag {} | {} | {} | {}",
                      static_cast<uint32_t>(e.v[6]), p8_when(e.qpc_us), key, ctl_text(ctl), rl->run,
                      scene_text(e.v[4], e.v[5]), tbl::scene_set(b.scene) ? "" : " (NOT SET: not sent)", b.amount, b.dx,
                      b.dz, flag, thread_text(main, e.tid),
                      in_tick ? (same_comp ? "INSIDE the RemoteCatch tick 0x59C0D0 (its own component)"
                                           : "INSIDE the RemoteCatch tick 0x59C0D0 (another component)")
                              : "OUTSIDE the RemoteCatch tick 0x59C0D0",
                      r.out ? "sent" : "NOT sent");
        }
    }
    ++rl->frames;
    if (in_tick) ++rl->in_tick;
    if (same_comp) ++rl->same_comp;
    if (r.out) ++rl->sent;
    rl->mn = std::min(rl->mn, b.amount);
    rl->mx = std::max(rl->mx, b.amount);
    rl->last = b.amount;
    rl->dx = b.dx;
    rl->dz = b.dz;
}

void end_runs(State& st, uint64_t now_ms_v) {
    tbl::Sender::Ended ended[8];
    const size_t n = st.sender.tick(now_ms_v, ended, std::size(ended));
    for (size_t i = 0; i < n; ++i) {
        queue_frame(ended[i].end);
        RunLog* rl = nullptr;
        for (RunLog& r : st.runs) {
            if (r.key == ended[i].key && r.open) rl = &r;
        }
        close_run(st, rl, now_ms_v, "End sent");
    }
}
void tail_tick(State& st, uint64_t now_ms_v) {
    for (Tail& t : st.tails) {
        if (!t.on || now_ms_v < t.next_ms) continue;
        t.next_ms += kTailStepMs;
        const auto a = game::fast<float>(t.tree + tbl::kTree_Amount);
        const auto set = game::fast<uint8_t>(t.tree + tbl::kTree_Set);
        const auto fl = game::fast<uint8_t>(t.tree + tbl::kTree_Flags);
        if (t.n < 31) {
            t.values += a ? std::format("{}{:.2f}", t.n ? " " : "", *a) : std::string(t.n ? " ?" : "?");
            if (t.n == 0 || t.n == 30) {
                t.values += std::format("[+0x2B4 {} +0x59 {:02X}]", set ? std::format("{}", *set) : std::string("?"),
                                        fl ? *fl : 0);
            }
        }
        ++t.n;
        if (now_ms_v - t.start_ms >= kTailMs) {
            if (may_log(st)) {
                log::info("TreeBend bend tail: character 0x{:08X} run {} | the tree's +0x2A4 every {} ms for {} s after "
                          "the last SetBend: {}",
                          t.key, t.run, kTailStepMs, kTailMs / 1000, t.values);
            }
            t.on = false;
        }
    }
}

void vf2_tick(State& st, uint64_t now_us) {
    for (Vf2Run& r : st.vf2) {
        if (!r.open) continue;
        tbl::KeyStats* s = keys().get(r.key);
        if (!s) continue;
        const uint64_t last = s->m1_last_us.load(std::memory_order_relaxed);
        if (now_us - last <= tbl::kRunGapUs) continue;
        r.open = false;
        if (may_log(st)) {
            log::info("TreeBend vf2 run END {}: character 0x{:08X} ({}) | {} calls in {:.2f} s", p8_when(last), r.key,
                      ctl_text(s->ctl.load()), s->m1_calls.load() - r.start_calls + 1,
                      static_cast<double>(last - r.start_us) / 1e6);
        }
    }
}

void log_event(const p8p::Event& e, State& st) {
    switch (e.kind) {
        case kEvVf2Start: {
            const uint32_t key = static_cast<uint32_t>(e.v[0]);
            const uint8_t ctl = static_cast<uint8_t>(e.v[0] >> 32);
            const uint8_t slot = static_cast<uint8_t>(e.v[0] >> 40);
            const uint8_t f6 = static_cast<uint8_t>(e.v[0] >> 48);
            const bool main = ((e.v[0] >> 56) & 1) != 0;
            Vf2Run* slotp = nullptr;
            for (Vf2Run& r : st.vf2) {
                if (r.key == key) slotp = &r;
            }
            if (!slotp) {
                for (Vf2Run& r : st.vf2) {
                    if (!r.key || !r.open) {
                        slotp = &r;
                        break;
                    }
                }
            }
            if (slotp) {
                slotp->key = key;
                slotp->open = true;
                slotp->start_calls = e.v[1];
                slotp->start_us = e.qpc_us;
            }
            if (may_log(st)) {
                log::info("TreeBend #{} vf2 run START {}: character 0x{:08X} ({}) | slot {} | f6 {} | {}",
                          static_cast<uint32_t>(e.v[2]), p8_when(e.qpc_us), key, ctl_text(ctl), slot,
                          f6 == 0xFF ? std::string("unread") : std::format("{}", f6), thread_text(main, e.tid));
            }
            return;
        }
        case kEvBend: on_bend_event(e, st); return;
        case kEvFault:
            log::error("TreeBend: mode 1's native apply for remote 0x{:08X} FAULTED (exception 0x{:08X}) {}; application "
                       "is OFF for the rest of this run, the probe goes on (gancho-cuerda.md section 14.8). Cierra el juego al "
                       "acabar esta sesion: un fallo dentro de un nativo puede haber dejado tomado un cerrojo del juego",
                       static_cast<uint32_t>(e.v[0]), static_cast<uint32_t>(e.v[1]), p8_when(e.qpc_us));
            return;
        case kEvApply: {
            if (!may_log(st)) return;
            const uint32_t key = static_cast<uint32_t>(e.v[0]);
            const auto o = static_cast<tbl::Outcome>((e.v[0] >> 32) & 0xFF);
            const uint8_t kind = static_cast<uint8_t>(e.v[5]);
            const uint8_t state = static_cast<uint8_t>(e.v[5] >> 8);
            const bool read_ok = ((e.v[5] >> 16) & 1) != 0;
            const bool scene_eq = e.v[3] == e.v[6] && e.v[4] == e.v[7];
            log::info("TreeBend #{} {} {}: remote 0x{:08X} slot 0 {} | sample scene {} ({}) | amount {:.3f} dir "
                      "({:.3f}, {:.3f}) | sample age {:.0f} ms, run {} seq {} | {}",
                      static_cast<uint32_t>(e.v[9]),
                      o == tbl::Outcome::Applied      ? "applied"
                      : o == tbl::Outcome::WouldApply ? "would apply"
                                                      : "NOT applied",
                      p8_when(e.qpc_us), key,
                      read_ok ? std::format("kind {} state {} scene {}", kind, state, scene_text(e.v[6], e.v[7]))
                              : std::string("unread"),
                      scene_text(e.v[3], e.v[4]), scene_eq ? "matches" : "MISMATCH", lo_f(e.v[1]), lo_f(e.v[2]),
                      hi_f(e.v[2]), hi_f(e.v[1]), static_cast<uint32_t>(e.v[8]), static_cast<uint32_t>(e.v[8] >> 32),
                      std::format("{} | {}", tbl::outcome_name(o), thread_text((e.flags & 1) != 0, e.tid)));
            return;
        }
        case kEvRx: {
            if (!may_log(st)) return;
            const auto rx = static_cast<tbl::Rx>((e.v[0] >> 40) & 0xFF);
            log::info("TreeBend received {}: thrower 0x{:08X} | {} | run {} seq {} | amount {:.3f} | connection {}",
                      p8_when(e.qpc_us), static_cast<uint32_t>(e.v[0]), tbl::rx_name(rx),
                      static_cast<uint32_t>(e.v[1]), static_cast<uint32_t>(e.v[1] >> 32), lo_f(e.v[2]), e.v[3]);
            return;
        }
        default: return;
    }
}

template <size_t N>
std::string tids_text(const tbl::TidSet<N>& t) {
    std::string s;
    for (size_t i = 0; i < t.capacity(); ++i) {
        if (const uint32_t v = t.at(i)) s += std::format("{}{}", s.empty() ? "" : " ", v);
    }
    if (t.over()) s += std::format(" (+{} more)", t.over());
    return s.empty() ? std::string("none") : s;
}

void log_summary(State& st, const char* when = "") {
    const tbl::KeyTable<32>& kt = keys();
    std::string players;
    for (size_t i = 0; i < kt.size(); ++i) {
        const tbl::KeyStats& s = kt.at(i);
        const uint32_t k = s.key.load();
        if (!k) continue;
        players += std::format(
            "{}0x{:08X} ({}): M1 vf2 {} (main {}, f6==1 {}, runs {}, inside the tick {}) | M2 r8b=1 {} r8b=0 {} | M3 "
            "SetBend {} (main {}, inside the tick {}, its own component's tick {}, last tid {}) | M4 tick {} (main {}, "
            "last tid {}) | 0x8A30C0 as a remote {} (timer running {}, INLINE bends {}, during an apply {})",
            players.empty() ? "" : "; ", k, ctl_text(s.ctl.load()), s.m1_calls.load(), s.m1_main.load(), s.m1_f6.load(),
            s.m1_runs.load(), s.m1_in_tick.load(), s.m2_flag1.load(), s.m2_flag0.load(), s.m3_calls.load(),
            s.m3_main.load(), s.m3_in_tick.load(), s.m3_same_comp.load(), s.m3_tid.load(), s.m4_calls.load(),
            s.m4_main.load(), s.m4_tid.load(), s.pull_calls.load(), s.pull_running.load(), s.pull_inline.load(),
            s.pull_during_apply.load());
    }
    // Review B1: the same-PC context check for mode 1.
    const std::string context = std::format(
        "this PC's own native SetBend: inside the RemoteCatch tick {} (its own component's {}), OUTSIDE {} | tids: "
        "native SetBend [{}], tick of a remote thrower [{}], in both {}",
        g_m3_in_tick.load(), g_m3_same_comp.load(), g_m3_out_tick.load(), tids_text(g_tids_m3_own),
        tids_text(g_tids_m4_remote), g_tids_m3_own.common(g_tids_m4_remote));
    // S29: 0x8A30C0's inline bend (needs rope_probe=1: its entry hook feeds tree_bend_note_pull).
    const std::string inline_text =
        rope_probe_pull_hooked()
            ? std::format("0x8A30C0 (rope_probe's hook): remote players {} calls, INLINE bends on a remote {}; this PC's "
                          "own inline bends {}{} | own-bend records skipped (another writer) {}",
                          g_pull_remote.load(), g_fights_inline.load(), g_pull_own_inline.load(),
                          g_pull_seen.load() ? "" : " (no player call yet)", g_own_bend_skipped.load())
            : std::string("0x8A30C0: NOT measured (needs rope_probe=1, whose entry hook counts it)");
    const std::string guards =
        std::format("application {}", g_apply_off.load() ? "OFF after a fault" : (mode() == Mode::On ? "on" : "probe"));
    std::string outcomes;
    for (size_t i = 0; i < static_cast<size_t>(tbl::Outcome::Count); ++i) {
        if (const uint64_t n = g_outcome[i].load()) {
            outcomes += std::format("{}{} {}", outcomes.empty() ? "" : ", ",
                                    tbl::outcome_name(static_cast<tbl::Outcome>(i)), n);
        }
    }
    std::string rx;
    for (size_t i = 0; i < static_cast<size_t>(tbl::Rx::Count); ++i) {
        rx += std::format("{}{} {}", i ? ", " : "", tbl::rx_name(static_cast<tbl::Rx>(i)), c_rx[i].load());
    }
    size_t queued = 0;
    uint64_t dropped = 0, discarded = 0;
    {
        std::lock_guard lk(g_out_mu);
        queued = g_out.size();
        dropped = g_out.dropped();
        discarded = g_out.discarded();
    }
    uint64_t epoch_resets = 0;
    AcquireSRWLockShared(&g_rx_lock);
    epoch_resets = g_rx.epoch_resets();
    ReleaseSRWLockShared(&g_rx_lock);
    log::info("TreeBend summary{} ({}, tree_bend={}): hooks {} | {} | {} | context: {} | players (table {}/{} used, full {}, "
              "switches {}): {} | other actors: M1 {} M2 {} M4 {} (own "
              "characters at M4 {}) | M3 SetBend not from the apply {} | FIGHTS {} (the native bend ran for a remote "
              "character here: M2/M3 {}, inline 0x8A30C0 {}) | thrower: bends refused {}, remote {}, unmatched {}; frames queued {} (sent to the "
              "link {}, dropped {}, no conversation {}, waiting {}, refused by the queue to the host {}) | received: {} "
              "(bad {}, ignored {}, busy {}, connection resets {}) | observer: {} | own SetBend calls {} | lines not "
              "logged {}, ring dropped {}",
              when, g_guest.load() ? "guest" : "host", tbl::mode_name(mode()), g_hooks_on.load() ? "on" : "OFF", guards,
              inline_text, context,
              kt.used(), kt.size(), kt.full(), g_keyset.switches(),
              players.empty() ? std::string("none seen yet") : players, g_m1_other.load(), g_m2_other.load(),
              g_m4_other.load(), g_m4_own.load(), g_m3_unmatched.load(), g_fights.load() + g_fights_inline.load(),
              g_fights.load(), g_fights_inline.load(), st.bends_refused,
              st.bends_remote, st.bends_unmatched, c_sent.load(), c_popped.load(), dropped, discarded, queued,
              c_unsent.load(), rx,
              c_rx_bad.load(), c_rx_ignored.load(), c_rx_busy.load(), epoch_resets,
              outcomes.empty() ? std::string("nothing yet") : outcomes, g_self_calls.load(), st.not_logged,
              g_ring.dropped());
}

DWORD WINAPI worker_thread(LPVOID) {
    try {
        game::PlayerReader reader;
        reader.init();
        uint32_t in_world = 0;
        bool hook_tried = false;
        uint64_t last_world = 0;
        uint64_t last_minute = GetTickCount64();
        uint64_t seen_conn = 0;
        State st;
        for (;;) {
            Sleep(kLoopMs);
            const uint64_t now = GetTickCount64();
            if (!hook_tried && now - last_world >= kWorldTickMs) {
                last_world = now;
                in_world = reader.read() ? in_world + 1 : 0;
                if (in_world >= kWorldTicks) {
                    hook_tried = true;
                    if (!install_hooks()) log::error("TreeBend: the hooks are not in; tree_bend does nothing this run");
                    last_minute = now;
                }
            }
            p8p::Event e;
            while (g_ring.pop(e)) log_event(e, st);
            const uint64_t qms = now_ms();
            end_runs(st, qms);
            tail_tick(st, qms);
            vf2_tick(st, qms * 1000);
            // Review L1: a new connection (or a full table): the summary of the old one, then a clean table.
            if (const uint64_t changes = g_conn_changes.load(std::memory_order_acquire);
                changes != seen_conn || keys().full() > 0) {
                const bool full = changes == seen_conn;
                seen_conn = changes;
                if (hook_tried && (keys().used() > 0 || full)) {
                    log_summary(st, full ? " (the per-character table is FULL: switched to a clean one)"
                                         : " (before a new connection: the per-character table is switched)");
                    g_keyset.switch_tables();
                    for (Vf2Run& r : st.vf2) r = Vf2Run{};
                }
            }
            if (hook_tried && now - last_minute >= kMinuteMs) {
                last_minute = now;
                log_summary(st);
            }
        }
    } catch (...) {
        log::error("TreeBend: the worker stopped (exception); nothing more is sent or logged (the hooks stay)");
    }
    return 0;
}

}  // namespace

void tree_bend_start(const std::string& raw, bool guest) {
    const auto p = tbl::parse_mode(raw);
    if (!p.known) log::warn("TreeBend: tree_bend='{}' is not 0, probe or 1; it stays off", raw);
    if (p.mode == Mode::Off) return;
    if (g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!build_ok()) {
        log::error("TreeBend: unsupported game build (not 1.0.0.2976, 1.0.0.3527, 1.0.0.3576 or 1.0.0.3663); tree_bend "
                   "stays off");
        return;
    }
    g_guest.store(guest);
    g_mode.store(static_cast<uint8_t>(p.mode));
    log::info("TreeBend ON ({}, tree_bend={}): once the world is up, hooks at the entries of RemoteCatchFunctions vf2 "
              "exe+0x{:X} (M1), the bend's apply exe+0x{:X} (M2), TreeComponent::SetBend exe+0x{:X} (M3) and the "
              "RemoteCatch tick exe+0x{:X} (M4). This client's own bends are sent through the tunnel (control state 15, "
              "<= 20 Hz, End after 150 ms); the other player's are {} (docs/research/s25/gancho-cuerda.md section 14)",
              guest ? "guest" : "host", tbl::mode_name(p.mode), addrs().vf2, addrs().apply, addrs().set_bend,
              addrs().tick,
              p.mode == Mode::On ? "APPLIED to the same tree here (FUN_1405b1600 -> FUN_140491ac0 -> SetBend)"
                                 : "logged with what would be applied (probe: nothing of the game is written)");
    if (HANDLE h = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr)) CloseHandle(h);
}

bool tree_bend_active() { return mode() != Mode::Off && g_started.load(); }

bool tree_bend_on_frame(std::span<const uint8_t> frame, uint64_t epoch) noexcept {
    if (!tbl::is_frame(frame)) return false;
    try {
        if (!tree_bend_active()) {
            c_rx_ignored.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        const auto s = tbl::decode(frame.subspan(tbl::kHeader));
        if (!s) {
            c_rx_bad.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        // Review L1: a new connection switches the module's per-character table (its thread does it).
        if (g_conn_epoch.exchange(epoch, std::memory_order_acq_rel) != epoch) {
            g_conn_changes.fetch_add(1, std::memory_order_release);
        }
        const uint64_t now = now_ms();
        AcquireSRWLockExclusive(&g_rx_lock);
        const tbl::Rx r = g_rx.on_sample(*s, epoch, now);
        ReleaseSRWLockExclusive(&g_rx_lock);
        c_rx[static_cast<size_t>(r)].fetch_add(1, std::memory_order_relaxed);
        if (r == tbl::Rx::NewRun || r == tbl::Rx::Ended || r == tbl::Rx::TableFull) {
            p8p::Event e;
            e.qpc_us = p8_now_us();
            e.tid = GetCurrentThreadId();
            e.kind = kEvRx;
            e.v[0] = s->key | (uint64_t{static_cast<uint8_t>(s->kind)} << 32) | (uint64_t{static_cast<uint8_t>(r)} << 40);
            e.v[1] = s->run | (uint64_t{s->seq} << 32);
            e.v[2] = pack2(s->amount, 0.0f);
            e.v[3] = epoch;
            g_ring.push(e);
        }
    } catch (...) {
    }
    return true;
}

bool tree_bend_pop_outbound(std::vector<uint8_t>& frame) noexcept {
    if (!tree_bend_active()) return false;
    try {
        std::optional<tbl::Sample> s;
        {
            std::lock_guard lk(g_out_mu);
            s = g_out.pop();
        }
        if (!s) return false;
        frame = tbl::frame(*s);
        c_popped.fetch_add(1, std::memory_order_relaxed);
        return true;
    } catch (...) {
        return false;
    }
}

void tree_bend_note_unsent() noexcept { c_unsent.fetch_add(1, std::memory_order_relaxed); }

void tree_bend_note_pull(uint32_t key, uint8_t ctl, bool running, bool inline_bend) noexcept {
    if (!tree_bend_active() || !tbl::player_key(key)) return;
    g_pull_seen.store(true, std::memory_order_relaxed);
    if (ctl != 0) {  // this client's own character (or unread: 0xFF)
        if (inline_bend && ctl != 0xFF) {
            g_pull_own_inline.fetch_add(1, std::memory_order_relaxed);
            g_own_inline_us.store(p8_now_us(), std::memory_order_release);  // review B-M1: guard 2b
        }
        return;
    }
    g_pull_remote.fetch_add(1, std::memory_order_relaxed);
    tbl::KeyStats* s = keys().get(key);
    if (!s) return;
    s->pull_calls.fetch_add(1, std::memory_order_relaxed);
    if (running) s->pull_running.fetch_add(1, std::memory_order_relaxed);
    if (inline_bend) {
        s->pull_inline.fetch_add(1, std::memory_order_relaxed);
        g_fights_inline.fetch_add(1, std::memory_order_relaxed);
    }
    if (tbl::during_apply(s->m4_last_apply_us.load(std::memory_order_relaxed), p8_now_us())) {
        s->pull_during_apply.fetch_add(1, std::memory_order_relaxed);
    }
}

void tree_bend_discard_outbound() noexcept {
    if (!tree_bend_active()) return;
    try {
        std::lock_guard lk(g_out_mu);
        g_out.clear();
    } catch (...) {
    }
}

}  // namespace cdmp::session2
