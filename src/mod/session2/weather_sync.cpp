#include "mod/session2/weather_sync.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <format>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/player_reader.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"
#include "mod/session2/weather_sync_logic.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using wsy::Mode;

// The build's tables (weather_sync_logic.h): 2976 or 3549. Set once by weather_sync_start before the worker starts and
// before g_mode (release); the network thread reads them through the atomics.
std::atomic<const wsy::GameAddrs*> g_game{&wsy::kGame2976};
std::atomic<const wsy::Layout*> g_layout{&wsy::kLayout2976};
const wsy::GameAddrs& G() { return *g_game.load(std::memory_order_acquire); }
const wsy::Layout& L() { return *g_layout.load(std::memory_order_acquire); }

// The rule of the task: hooks only at verified function entries inside [G().code_begin, G().code_end) and in the
// real code (executable, not writable), never in the protected RWX section.
constexpr uint32_t kTickMs = 200;           // the worker: 5 Hz
constexpr uint64_t kProbeEveryMs = 5000;
constexpr uint64_t kMinuteMs = 60000;
constexpr size_t kMaxBacklog = 256 * 1024;  // the host does not add weather to a tunnel this far behind
constexpr uint64_t kChangeLines = 200, kTargetLines = 300, kEventLines = 400;

std::atomic<uint8_t> g_mode{0};  // wsy::Mode, written once by weather_sync_start (before the thread)
std::atomic<bool> g_started{false};
bool g_guest = false;            // written before the thread starts
uint32_t g_radius_m = wsy::kDefaultRadiusM;
uintptr_t g_base = 0;

Mode mode() { return static_cast<Mode>(g_mode.load(std::memory_order_acquire)); }
const char* role() { return g_guest ? "guest" : "host"; }

// ---------------------------------------------------------------- shared state (atomics, the box, the outbox)

std::atomic<bool> g_world_ready{false};  // the worker's WorldWatch
std::atomic<uint8_t> g_gate{static_cast<uint8_t>(wsy::Gate::NotRemote)};  // guest, mode 1: the worker's decision
std::atomic<uint64_t> g_gate_epoch{0};  // guest, mode 1: bumped by the worker on each closed -> open edge
std::atomic<bool> g_hook_on{false};
// The hook's fault latch, mirrored for the worker's lines (review item 2: no longer for the whole run).
std::atomic<bool> g_faulted{false};
std::atomic<uint32_t> g_fault_count{0};
std::atomic<uint8_t> g_st_phase{static_cast<uint8_t>(wsy::StPhase::WaitWorld)};
std::atomic<uint64_t> g_st_frames{0};

// Guest, mode 1: the host's samples (network thread writes, the hook and the worker read).
wsy::DoubleBuffer<wsy::kBoxWords> g_box;
std::atomic<uint64_t> c_rx{0}, c_rx_bad{0}, c_rx_insane{0}, c_rx_ignored{0};
// Host: its own samples check() refused (never sent; review item 8: counted and logged, never silent).
std::atomic<uint64_t> c_sample_insane{0};
constexpr uint64_t kInsaneLines = 5;

// Host, mode 1: the newest sample's frame (the worker writes, the network thread reads).
SRWLOCK g_out_lock = SRWLOCK_INIT;
wsy::Frame g_out_frame{};  // under g_out_lock
uint32_t g_out_seq = 0;    // under g_out_lock (0 = none)
std::atomic<uint64_t> c_tx{0}, c_tx_refused{0}, c_tx_no_caps{0}, c_tx_not_in_world{0}, c_tx_backlog{0},
    c_tx_not_connected{0};
std::atomic<uint8_t> g_tx_peer_caps{0};

// The hook's counters (its thread writes; the worker reads).
std::atomic<uint64_t> c_calls{0}, c_applied{0}, c_released{0}, c_stale{0}, c_gated{0}, c_no_sample{0},
    c_bad_sample{0}, c_x_bad{0}, c_foreign{0}, c_full{0}, c_reasserted{0}, c_box_retry{0}, c_busy{0}, c_evicted{0},
    c_fault_frames{0}, c_words_restored{0};
std::atomic<bool> g_applying{false};
p8p::EventRing<64> g_ring;

enum EvKind : uint16_t {
    kEvApplyBegin = 1,  // v0 x, v1 sample seq, v2 age ms, v3 command bits, v4 orig flag, v5 host tick, v6 words kept,
                        // v7 X+0x88
    kEvRelease = 2,     // v0 x, v1 why, v2 frames, v3 flag written back, v4 words put back, v5 X+0x88 (~0: unread)
    kEvFault = 3,       // v0 x, v1 what, v2 address
    kEvStBegin = 4,     // v0 x, v1 orig flag, v2..v6 orig A words (wsy::restore_a: precip, out, fx, snow, rain),
                        // v7 temp
    kEvStRestored = 5,  // v0 x, v1 why (0 done, 1 aborted, 2 fault), v2 ok, v3 frames, v4 flag before, v5 precip
                        // before, v6 rain before, v7 snow before, v8 A restored too
    kEvStPending = 6,   // v0 run's x, v1 the hook's x now
    kEvForeign = 7,     // v0 x, v1 flag found
    kEvFull = 8,        // v0 x
    kEvStCheck = 9,     // v0 x, v1 flag, v2 precip, v3 rain, v4 snow, v5 fx, v6 temp (L().a / L().a_temp_sample)
    kEvEvicted = 10,    // v0 the evicted x, v1 the hook's x now, v2 flag written back, v3 vtable still the weather's
    kEvFaultCleared = 11,  // v0 x, v1 faults so far, v2 1 = a gate open edge, 0 = clean frames
    kEvFaultExhausted = 12,  // v0 x, v1 faults
};
enum Why : uint64_t { kWhyGate = 0, kWhyStale, kWhyNoSample, kWhyFault, kWhyX, kWhyBadSample, kWhyMode };
const char* why_name(uint64_t w) {
    switch (w) {
        case kWhyGate: return "a gate closed";
        case kWhyStale: return "the newest sample is 1 s old or more";
        case kWhyNoSample: return "no sample from the host";
        case kWhyFault: return "a guarded access failed";
        case kWhyX: return "X's vtable is not the weather system's";
        case kWhyBadSample: return "the sample lacks A/B/X or is not sane";
        case kWhyMode: return "mode";
    }
    return "?";
}
enum FaultWhat : uint64_t { kFaultFlagRead = 1, kFaultFlagWrite, kFaultBlocks, kFaultField, kFaultCapture };
const char* fault_name(uint64_t w) {
    switch (w) {
        case kFaultFlagRead: return "reading X+0x31";
        case kFaultFlagWrite: return "writing X+0x31";
        case kFaultBlocks: return "reading the holder / A / B";
        case kFaultField: return "writing a value";
        case kFaultCapture: return "reading what the selftest had to keep";
    }
    return "?";
}

void push_event(uint16_t kind, std::initializer_list<uint64_t> v) noexcept {
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kind;
    size_t i = 0;
    for (uint64_t x : v) {
        if (i < std::size(e.v)) e.v[i++] = x;
    }
    g_ring.push(e);
}

// ---------------------------------------------------------------- guarded access on the hook's thread

int write_filter(const EXCEPTION_POINTERS* ep) noexcept {
    const EXCEPTION_RECORD* r = ep ? ep->ExceptionRecord : nullptr;
    if (!r) return EXCEPTION_CONTINUE_SEARCH;
    return r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || r->ExceptionCode == EXCEPTION_IN_PAGE_ERROR
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}
bool plausible(uintptr_t a, size_t n) { return a >= 0x10000 && a <= 0x00007FFFFFFFFFFFull - n; }
bool seh_write32(uintptr_t a, uint32_t v) noexcept {
    if (!plausible(a, 4)) return false;
    __try {
        *reinterpret_cast<volatile uint32_t*>(a) = v;
        return true;
    } __except (write_filter(GetExceptionInformation())) {
        return false;
    }
}
bool seh_write8(uintptr_t a, uint8_t v) noexcept {
    if (!plausible(a, 1)) return false;
    __try {
        *reinterpret_cast<volatile uint8_t*>(a) = v;
        return true;
    } __except (write_filter(GetExceptionInformation())) {
        return false;
    }
}
uint32_t rd32(uintptr_t a, bool& ok) noexcept {
    uint32_t v = 0;
    ok = ok && game::fast_read(a, &v, sizeof v);
    return v;
}

bool x_valid(uintptr_t x) noexcept {
    const auto vt = game::fast<uintptr_t>(x);
    return vt && *vt == g_base + G().vt_weather_system;
}

struct Blocks {
    uintptr_t holder = 0, a = 0, b = 0, c = 0;
};
// The holder and its blocks, read on the thread that updates X (right before the game reads them itself).
bool blocks_of(uintptr_t x, Blocks& out) noexcept {
    const wsy::GameAddrs& g = G();
    const auto h = game::fast_ptr(x + g.x_holder);
    if (!h || !*h) return false;
    out.holder = *h;
    const auto a = game::fast_ptr(*h + g.holder_a), b = game::fast_ptr(*h + g.holder_b),
               c = game::fast_ptr(*h + g.holder_c);
    if (!a || !*a || !b || !*b) return false;
    out.a = *a;
    out.b = *b;
    out.c = c ? *c : 0;
    return true;
}
uintptr_t block_addr(const Blocks& bl, uintptr_t x, wsy::Block b) {
    switch (b) {
        case wsy::Block::A: return bl.a;
        case wsy::Block::B: return bl.b;
        case wsy::Block::C: return bl.c;
        case wsy::Block::X: return x;
    }
    return 0;
}

// ---------------------------------------------------------------- the hook (its thread only below)

SafetyHookInline g_hook;
std::atomic_flag g_busy = ATOMIC_FLAG_INIT;
wsy::OwnedSet<4> g_owned;
wsy::History g_hist;
wsy::Selftest g_st;
uintptr_t g_st_x = 0;
bool g_st_checked = false;
wsy::FaultLatch g_latch;  // mode 1 (the selftest has its own abort)

void fault(uintptr_t x, FaultWhat what, uintptr_t at) noexcept {
    g_latch.on_fault();
    g_faulted.store(true, std::memory_order_relaxed);
    g_fault_count.store(g_latch.faults(), std::memory_order_relaxed);
    push_event(kEvFault, {x, what, at});
    if (g_latch.exhausted()) push_event(kEvFaultExhausted, {x, g_latch.faults()});
}

size_t block_index(wsy::Block b) { return b == wsy::Block::A ? 0 : b == wsy::Block::B ? 1 : 2; }

// Mode 1: X back to what it was, the record gone. x is being updated now (alive); an x whose vtable is no longer
// the weather system's is not written at all (the record just goes). The holder words kept at the first write go
// back first (review item 1: with X+0x88 == 0 the mixer would never rewrite them; with components registered the
// mixer overwrites them again in this same frame, so nothing old is ever shown), each only into the block it came
// from; then X+0x31.
void release(uintptr_t x, wsy::Owned& o, Why why) noexcept {
    const wsy::Layout& lay = L();
    const uint64_t frames = o.frames;
    bool ok = false;
    uint64_t restored = 0, wc = ~uint64_t{0};
    if (x_valid(x)) {
        Blocks bl;
        if (o.kept.any() && blocks_of(x, bl)) {
            const wsy::Bits bits = wsy::restore_bits(lay, o.kept, o.written, o.flag_ours);
            for (size_t i = 0; i < lay.count(); ++i) {
                if (!bits.test(i)) continue;
                const uintptr_t base = block_addr(bl, x, lay[i].block);
                if (!base || base != o.blk[block_index(lay[i].block)]) continue;
                if (seh_write32(base + lay[i].off, o.orig_w[i])) ++restored;
            }
        }
        if (const auto n = game::fast<uint32_t>(x + G().x_wc_count)) wc = *n;
        ok = seh_write8(x + G().x_viewer, o.orig_flag);
    }
    c_words_restored.fetch_add(restored, std::memory_order_relaxed);
    g_owned.remove(x);
    g_applying.store(g_owned.size() != 0, std::memory_order_relaxed);
    c_released.fetch_add(1, std::memory_order_relaxed);
    push_event(kEvRelease, {x, why, frames, ok ? 1u : 0u, restored, wc});
}

// Review item 3: a record of an X the game no longer updates (this call is for another X). Its flag goes back only
// while its first word is still the weather system's vtable and the flag is still the 1 we wrote (a freed X whose
// memory was reused fails the vtable test); its holder words are not touched (the holder may be gone with it).
void evict(wsy::Owned& o, uintptr_t now_x) noexcept {
    const bool valid = x_valid(o.x);
    bool wrote = false;
    uint8_t f = 0;
    if (valid && o.flag_ours && game::fast_read(o.x + G().x_viewer, &f, 1) && f == 1) {
        wrote = seh_write8(o.x + G().x_viewer, o.orig_flag);
    }
    c_evicted.fetch_add(1, std::memory_order_relaxed);
    push_event(kEvEvicted, {o.x, now_x, wrote ? 1u : 0u, valid ? 1u : 0u});
}

// The holder words kept_for_release, read before the first write to x (bl: x's blocks now). False: a read failed.
bool keep_originals(uintptr_t x, const Blocks& bl, wsy::Owned& o) noexcept {
    const wsy::Layout& lay = L();
    o.blk[0] = bl.a;
    o.blk[1] = bl.b;
    o.blk[2] = bl.c;
    for (size_t i = 0; i < lay.count(); ++i) {
        if (!wsy::kept_for_release(lay, i)) continue;
        const uintptr_t base = block_addr(bl, x, lay[i].block);
        if (!base) continue;  // C absent here: nothing of it is kept (nor restored)
        uint32_t w = 0;
        if (!game::fast_read(base + lay[i].off, &w, sizeof w)) return false;
        o.orig_w[i] = w;
        o.kept.set(i);
    }
    return true;
}

void mirror_pre(uintptr_t x) noexcept {
    const uint64_t now = GetTickCount64();
    if (const uint64_t bs = g_box.seq(); bs != 0 && bs != g_hist.seen) {
        uint32_t w[wsy::kBoxWords];
        uint64_t s = 0;
        if (g_box.read(w, s)) {
            wsy::Timed t;
            wsy::unpack(w, t);
            g_hist.push(t, s);
        } else {
            c_box_retry.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // Review item 3: the game updates one X; records of any other go now (never let them fill the set).
    g_owned.evict_others(x, [x](wsy::Owned& old) { evict(old, x); });
    wsy::Owned* o = g_owned.find(x);
    // Review item 2: after a fault, the writes come back on a new open edge of the gate or after enough clean frames.
    const uint64_t edge = g_gate_epoch.load(std::memory_order_relaxed);
    if (g_latch.blocked()) {
        bool by_edge = g_latch.on_gate_epoch(edge), cleared = by_edge;
        if (!cleared) {
            uint8_t f = 0;
            Blocks probe;
            cleared = g_latch.on_frame(x_valid(x) && game::fast_read(x + G().x_viewer, &f, 1) && blocks_of(x, probe));
        }
        if (cleared) {
            g_faulted.store(false, std::memory_order_relaxed);
            push_event(kEvFaultCleared, {x, g_latch.faults(), by_edge ? 1u : 0u});
        } else {
            c_fault_frames.fetch_add(1, std::memory_order_relaxed);
        }
    } else {
        g_latch.on_gate_epoch(edge);  // keeps the edge seen current: only an edge AFTER a fault clears it
    }
    bool stop = true;
    Why why = kWhyMode;
    if (g_latch.blocked()) {
        why = kWhyFault;
    } else if (!x_valid(x)) {
        why = kWhyX;
        c_x_bad.fetch_add(1, std::memory_order_relaxed);
    } else if (!g_hist.has_cur) {
        why = kWhyNoSample;
        c_no_sample.fetch_add(1, std::memory_order_relaxed);
    } else if (!wsy::fresh(now, g_hist.cur.recv_ms)) {
        why = kWhyStale;
        c_stale.fetch_add(1, std::memory_order_relaxed);
    } else if (static_cast<wsy::Gate>(g_gate.load(std::memory_order_relaxed)) != wsy::Gate::Apply) {
        why = kWhyGate;
        c_gated.fetch_add(1, std::memory_order_relaxed);
    } else if (!wsy::applicable(L(), g_hist.cur.s)) {
        why = kWhyBadSample;
        c_bad_sample.fetch_add(1, std::memory_order_relaxed);
    } else {
        stop = false;
    }
    if (stop) {
        if (o) release(x, *o, why);
        return;
    }
    const wsy::Layout& lay = L();
    const uintptr_t viewer = x + G().x_viewer;
    uint8_t flag = 0;
    if (!game::fast_read(viewer, &flag, 1)) {
        fault(x, kFaultFlagRead, viewer);
        if (o) release(x, *o, kWhyFault);
        return;
    }
    Blocks bl;
    if (!blocks_of(x, bl)) {
        fault(x, kFaultBlocks, x + G().x_holder);
        if (o) release(x, *o, kWhyFault);
        return;
    }
    bool first = false;
    if (!o) {
        if (flag != 0) {
            // Viewer mode we did not set (never expected): not ours to touch.
            if (c_foreign.fetch_add(1, std::memory_order_relaxed) == 0) push_event(kEvForeign, {x, flag});
            return;
        }
        o = g_owned.add(x);
        if (!o) {
            if (c_full.fetch_add(1, std::memory_order_relaxed) == 0) push_event(kEvFull, {x});
            return;
        }
        o->orig_flag = flag;
        if (!keep_originals(x, bl, *o)) {
            fault(x, kFaultBlocks, x + G().x_holder);
            g_owned.remove(x);  // nothing written yet
            return;
        }
        first = true;
    }
    uint32_t out[wsy::kMaxFields];
    const wsy::Timed* prev = g_hist.has_prev ? &g_hist.prev : nullptr;
    wsy::blend(lay, prev, g_hist.cur, now, out);
    const uint16_t mask = g_hist.cur.s.mask;
    // The values first, the flag last: in this frame the original then runs in viewer mode on them.
    for (size_t i = 0; i < lay.count(); ++i) {
        if (!wsy::written(lay, i, mask)) continue;
        const uintptr_t base = block_addr(bl, x, lay[i].block);
        if (!base) continue;  // C absent here
        const uintptr_t at = base + lay[i].off;
        o->written.set(i);  // before the write: a half-done write is put back too
        if (!seh_write32(at, wsy::value_to_write(lay, i, out))) {
            fault(x, kFaultField, at);
            release(x, *o, kWhyFault);
            return;
        }
    }
    if (flag == 0) {
        o->flag_ours = true;
        if (!seh_write8(viewer, 1)) {
            fault(x, kFaultFlagWrite, viewer);
            release(x, *o, kWhyFault);
            return;
        }
        if (!first) {
            c_reasserted.fetch_add(1, std::memory_order_relaxed);
        } else {
            const uint64_t kept = o->kept.count();
            const auto wc = game::fast<uint32_t>(x + G().x_wc_count);
            push_event(kEvApplyBegin, {x, g_hist.cur.s.seq, wsy::age_ms(now, g_hist.cur.recv_ms),
                                       wsy::value_to_write(lay, lay.idx_precip, out), o->orig_flag, g_hist.cur.s.tick,
                                       kept, wc ? *wc : ~uint64_t{0}});
        }
    }
    ++o->frames;
    g_applying.store(true, std::memory_order_relaxed);
    c_applied.fetch_add(1, std::memory_order_relaxed);
}

// Selftest: what the run changed goes back on x (its flag; the five A words when A is still the same block). Only
// while x is still the weather system (its vtable); otherwise nothing is written and the line says so.
void st_restore(uintptr_t x, wsy::Owned& o, uint64_t why) noexcept {
    const wsy::Layout& lay = L();
    const auto ra = wsy::restore_a(lay);
    const bool valid = x_valid(x);
    bool ok = valid;
    uint32_t flag_before = 0, p_before = 0, rain_before = 0, snow_before = 0;
    uint8_t f8 = 0;
    if (valid && game::fast_read(x + G().x_viewer, &f8, 1)) flag_before = f8;
    Blocks bl;
    const bool have = valid && blocks_of(x, bl);
    bool a_back = false;
    if (have) {
        bool r = true;
        p_before = rd32(bl.a + lay.a.precip, r);
        rain_before = rd32(bl.a + lay.a.rain, r);
        snow_before = rd32(bl.a + lay.a.snow, r);
    }
    if (have && o.has_orig_a && bl.a == o.a) {
        for (size_t i = 0; i < ra.size(); ++i) ok = seh_write32(bl.a + ra[i], o.orig_a[i]) && ok;
        a_back = true;
    }
    if (valid) ok = seh_write8(x + G().x_viewer, o.orig_flag) && ok;
    push_event(kEvStRestored,
               {x, why, ok ? 1u : 0u, o.frames, flag_before, p_before, rain_before, snow_before, a_back ? 1u : 0u});
    g_owned.remove(x);
    g_applying.store(false, std::memory_order_relaxed);
}

void selftest_pre(uintptr_t x) noexcept {
    const uint64_t now = GetTickCount64();
    const bool vt_ok = x_valid(x);
    // A run's X seen again after the run ended away from it (another X was updated meanwhile): put it back now.
    if (wsy::Owned* o = g_owned.find(x); o && g_st.phase() != wsy::StPhase::Apply) {
        st_restore(x, *o, g_st.phase() == wsy::StPhase::Done ? 0u : 1u);
    }
    const bool same = vt_ok && (g_st_x == 0 || g_st_x == x);
    const wsy::StStep s = g_st.step(now, g_world_ready.load(std::memory_order_relaxed), same);
    g_st_phase.store(static_cast<uint8_t>(g_st.phase()), std::memory_order_relaxed);
    const wsy::Layout& lay = L();
    if (s.began) {
        const auto ra = wsy::restore_a(lay);
        wsy::Owned* o = g_owned.add(x);
        Blocks bl;
        uint8_t flag = 0;
        bool r = o && blocks_of(x, bl) && game::fast_read(x + G().x_viewer, &flag, 1);
        uint32_t keep[5] = {};
        for (size_t i = 0; r && i < ra.size(); ++i) keep[i] = rd32(bl.a + ra[i], r);
        bool tr = true;
        const uint32_t temp = r ? rd32(bl.a + lay.a_temp_sample, tr) : 0;
        if (!r) {
            if (o) g_owned.remove(x);
            g_st.fault(now);
            g_st_phase.store(static_cast<uint8_t>(g_st.phase()), std::memory_order_relaxed);
            fault(x, kFaultCapture, x);
            return;
        }
        o->orig_flag = flag;
        o->has_orig_a = true;
        o->a = bl.a;
        std::copy(std::begin(keep), std::end(keep), o->orig_a);
        g_st_x = x;
        push_event(kEvStBegin, {x, flag, keep[0], keep[1], keep[2], keep[3], keep[4], temp});
    }
    if (s.write) {
        wsy::Owned* o = g_owned.find(x);
        Blocks bl;
        const bool ok = o && blocks_of(x, bl) && seh_write32(bl.a + lay.a.precip, wsy::as_word(1.0f)) &&
                        seh_write8(x + G().x_viewer, 1);
        if (!ok) {
            fault(x, o ? kFaultField : kFaultCapture, x);
            if (g_st.fault(now) && o) st_restore(x, *o, 2);
            g_st_phase.store(static_cast<uint8_t>(g_st.phase()), std::memory_order_relaxed);
            return;
        }
        ++o->frames;
        g_st_frames.store(o->frames, std::memory_order_relaxed);
        g_applying.store(true, std::memory_order_relaxed);
        // One frame after the first write the original has run once in viewer mode: what 0x382A1A0 made of it.
        if (o->frames == 2 && !g_st_checked) {
            g_st_checked = true;
            uint8_t f8 = 0;
            bool r = game::fast_read(x + G().x_viewer, &f8, 1);
            const uint32_t p = rd32(bl.a + lay.a.precip, r), rain = rd32(bl.a + lay.a.rain, r),
                           snow = rd32(bl.a + lay.a.snow, r), fx = rd32(bl.a + lay.a.rain_fx, r),
                           temp = rd32(bl.a + lay.a_temp_sample, r);
            if (r) push_event(kEvStCheck, {x, f8, p, rain, snow, fx, temp});
        }
    }
    if (s.restore) {
        if (wsy::Owned* o = g_owned.find(x); o && x == g_st_x) {
            st_restore(x, *o, g_st.phase() == wsy::StPhase::Done ? 0u : 1u);
        } else {
            push_event(kEvStPending, {g_st_x, x});
        }
    }
}

void update_detour(uintptr_t x, float dt) {
    // One thread at a time in our part (the update has one caller, G().update_call; a second thread would only skip
    // it).
    if (!g_busy.test_and_set(std::memory_order_acquire)) {
        c_calls.fetch_add(1, std::memory_order_relaxed);
        const Mode m = mode();
        if (m == Mode::On) {
            mirror_pre(x);
        } else if (m == Mode::Selftest) {
            selftest_pre(x);
        }
        g_busy.clear(std::memory_order_release);
    } else {
        c_busy.fetch_add(1, std::memory_order_relaxed);
    }
    g_hook.unsafe_call<void>(x, dt);  // never inside a __try: the game's own exceptions are the game's
}
// Review item 7: X+0x31 is only ever put back from here, i.e. when the game updates that X again. While X's update
// (2976 0x3DC4730, 3549 0x40C2580) does not run for it (a menu pause, a loading screen) the holder does not change on
// this client anyway: the mixer, the only way the simulators' WeatherComponents reach it, runs inside the update (3549:
// the ocean pull of A+0x154 too, through its setter). A simulator that still runs on
// its own path meanwhile only stays frozen (its own WC untouched), which delays nothing that is shown; the getters
// keep returning the last values written (the same sky as the frame before). A write from any other thread would
// race the update thread and could reach an X freed by the loading; the next update of a live X releases it in that
// very frame, and the update of a new X evicts the old record (item 3).

// ---------------------------------------------------------------- install (the worker, once the world is up)

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

std::string hex_bytes(std::span<const uint8_t> b) {
    std::string t;
    for (uint8_t v : b) t += std::format("{}{:02X}", t.empty() ? "" : " ", v);
    return t;
}

bool install_hook() {
    const wsy::GameAddrs& g = G();
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("WeatherSync: the exe's sections are unreadable; the hook on 0x{:X} is REFUSED, nothing written",
                   g.update);
        return false;
    }
    const auto in_code = [&](uintptr_t rva, size_t n) {
        return rva >= g.code_begin && rva + n <= g.code_end &&
               gad::in_real_code(secs, static_cast<uint32_t>(rva), static_cast<uint32_t>(n));
    };
    if (!in_code(g.update, g.update_head.size()) || !bytes_at(g.update, g.update_head)) {
        log::error("WeatherSync: exe+0x{:X} is not build {}'s real-code entry {}; REFUSED, nothing written", g.update,
                   g.build, hex_bytes(g.update_head));
        return false;
    }
    if (!in_code(g.update_call, g.update_call_bytes.size()) || !bytes_at(g.update_call, g.update_call_bytes)) {
        log::error("WeatherSync: its only caller (exe+0x{:X}) is not `{}` (call 0x{:X}); REFUSED, nothing written",
                   g.update_call, hex_bytes(g.update_call_bytes), g.update);
        return false;
    }
    auto whole = [&g](const std::vector<uint8_t>& o) { return wsy::whole_head(g, o); };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    const std::string what = std::format("0x{:X}", g.update);
    auto h = game::prepare_inline(g_base + g.update, reinterpret_cast<void*>(&update_detour), whole, "WeatherSync",
                                  what.c_str());
    if (!h) {
        log::error("WeatherSync: the hook on 0x{:X} could not be prepared ({}); REFUSED", g.update,
                   game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("WeatherSync: the hook on 0x{:X} would patch {} bytes, not whole verified instructions; REFUSED, "
                   "nothing written",
                   g.update, orig.size());
        return false;
    }
    const size_t patched = orig.size();  // `orig` belongs to *h: empty once it is moved
    g_hook = std::move(*h);
    if (!g_hook.enable()) {
        log::error("WeatherSync: the hook on 0x{:X} could not be enabled; REFUSED", g.update);
        g_hook = {};
        return false;
    }
    g_hook_on.store(true);
    log::info("WeatherSync: exe+0x{:X} (X's update, build {}, one caller at exe+0x{:X}) hooked at its entry ({} bytes "
              "patched); {}",
              g.update, g.build, g.update_call + g.update_call_bytes.size() - 5, patched,
              mode() == Mode::Selftest
                  ? "selftest: 15 s from now X+0x31 = 1 and A+0x12C = 1.0 for 30 s (it should RAIN at once), then both "
                    "back (the weather returns)"
                  : "mode 1: the host's values in viewer mode while a sample is fresh and the gates pass");
    return true;
}

// ---------------------------------------------------------------- the worker's reads (guarded, read only)

struct Reading {
    uintptr_t m = 0, s = 0, xa = 0, xb = 0, x = 0;
    bool getter_ok = false;  // [[M]+0x60] is G().getter (the simulators' path really is [M+0x60])
    bool vt_ok = false, flag_ok = false, wc_ok = false, temp_ok = false, tick_ok = false;
    uint8_t flag = 0;
    uint32_t wc = 0;
    uintptr_t holder = 0, a = 0, b = 0, c = 0;
    float temp[5] = {};
    uint64_t tick = 0;
    wsy::Snapshot snap;  // mask: the blocks read
    uint8_t braw[wsy::kMaxRead] = {};  // L().read_b.size of them
};

uintptr_t ptr_at(uintptr_t a) {
    if (!a) return 0;
    const auto p = game::read_ptr(a);
    return p ? *p : 0;
}

bool server_tick(uint64_t& out) {
    const wsy::GameAddrs& g = G();
    const auto base = game::read<uint64_t>(g_base + g.clock_base);
    const auto frac = game::read<uint64_t>(g_base + g.clock_frac);
    const auto bias = game::read<int64_t>(g_base + g.clock_bias);
    if (!base || !frac || !bias) return false;
    out = *base + *frac / 1000 + static_cast<uint64_t>(*bias);
    return out != 0;
}

void read_all(Reading& r) {
    const wsy::GameAddrs& g = G();
    const wsy::Layout& lay = L();
    r.m = ptr_at(g_base + g.module_slot);
    r.s = ptr_at(r.m ? r.m + g.module_scene : 0);
    r.xa = ptr_at(r.s ? r.s + g.scene_weather : 0);
    const uintptr_t vt = ptr_at(r.m);
    r.getter_ok = vt && ptr_at(vt + g.vt_getter_slot) == g_base + g.getter;
    const uintptr_t gc = ptr_at(g_base + g.client_slot);
    const uintptr_t h1 = ptr_at(gc ? gc + g.client_hop1 : 0);
    r.xb = ptr_at(h1 ? h1 + g.client_hop2 : 0);
    r.x = r.xa ? r.xa : r.xb;
    r.tick_ok = server_tick(r.tick);
    if (!r.x) return;
    r.vt_ok = game::has_vtable(r.x, g_base + g.vt_weather_system);
    if (const auto f = game::read<uint8_t>(r.x + g.x_viewer)) {
        r.flag = *f;
        r.flag_ok = true;
    }
    if (const auto n = game::read<uint32_t>(r.x + g.x_wc_count)) {
        r.wc = *n;
        r.wc_ok = true;
    }
    if (!r.vt_ok) return;
    r.holder = ptr_at(r.x + g.x_holder);
    r.a = ptr_at(r.holder ? r.holder + g.holder_a : 0);
    r.b = ptr_at(r.holder ? r.holder + g.holder_b : 0);
    r.c = ptr_at(r.holder ? r.holder + g.holder_c : 0);
    uint8_t a[wsy::kMaxRead] = {}, c[wsy::kMaxRead] = {}, x[wsy::kMaxRead] = {};
    uint16_t mask = 0;
    if (r.a && game::safe_read(r.a + lay.read_a.off, a, lay.read_a.size)) mask |= wsy::kHasA;
    if (r.b && game::safe_read(r.b + lay.read_b.off, r.braw, lay.read_b.size)) mask |= wsy::kHasB;
    if (r.c && game::safe_read(r.c + lay.read_c.off, c, lay.read_c.size)) mask |= wsy::kHasC;
    if (game::safe_read(r.x + lay.read_x.off, x, lay.read_x.size)) mask |= wsy::kHasX;
    r.temp_ok = r.a && game::safe_read(r.a + lay.a_temp_sample, r.temp, sizeof r.temp);
    // The same object after the copy (§5.2: [X] before and after).
    if (!game::has_vtable(r.x, g_base + g.vt_weather_system) || ptr_at(r.x + g.x_holder) != r.holder) mask = 0;
    wsy::extract(lay, mask & wsy::kHasA ? a : nullptr, mask & wsy::kHasB ? r.braw : nullptr,
                 mask & wsy::kHasC ? c : nullptr, mask & wsy::kHasX ? x : nullptr, r.snap.w);
    if (r.flag_ok && r.flag) mask |= wsy::kHostViewer;
    r.snap.mask = mask;
    r.snap.tick = r.tick_ok ? r.tick : 0;
}

// ---------------------------------------------------------------- lines

std::string hex(uintptr_t p) { return p ? std::format("0x{:X}", p) : std::string("0"); }

// The 5 s line's vector. The text is the same for every build; the offsets in it come from the layout (2976's line
// reads exactly as before).
std::string vector_text(const wsy::Snapshot& s) {
    if (!(s.mask & (wsy::kHasA | wsy::kHasB))) return "vector unreadable";
    const wsy::Layout& lay = L();
    const wsy::ProbeOffsets& p = lay.probe;
    const auto f = [&](wsy::Block b, uint16_t off) {
        const size_t i = lay.index(b, off);
        return i < lay.count() ? s.f(i) : std::nanf("");
    };
    using wsy::Block;
    std::string t;
    if (s.mask & wsy::kHasA) {
        t += std::format("precipitation {:.3f} cloudiness {:.3f} humidity {:.3f} windSpeed {:.2f} | rain({:X}) {:.3f} "
                         "snow({:X}) {:.3f} {:X} {:.3f} {:X} {:.3f} | puddleRate {:.3f} snowAmount {:.3f} iceRatio {:.3f} "
                         "windDegree {:.1f} windDir ({:.3f}, {:.3f})",
                         f(Block::A, p.precip), f(Block::A, p.cloud), f(Block::A, p.humid), f(Block::A, p.wind), p.rain,
                         f(Block::A, p.rain), p.snow, f(Block::A, p.snow), p.out, f(Block::A, p.out), p.fx,
                         f(Block::A, p.fx), f(Block::A, p.puddle), f(Block::A, p.snow_amount), f(Block::A, p.ice),
                         f(Block::A, p.wind_deg), f(Block::A, p.dir_x), f(Block::A, p.dir_z));
    }
    if (s.mask & wsy::kHasB) {
        t += std::format(" | B: sunDir ({:.3f}, {:.3f}) cloudBaseDensity({:X}) {:.4f} cloudScrollMultiplier({:X}) {:.3f} "
                         "cloudAltitude({:X}) {:.1f} cloudSeed({:X}) {:.3f} heightFog({:X}..{:X}) {:.3f} {:.3f} {:.3f} "
                         "{:.3f} layers({:X}..{:X}) {:.3f} {:.3f} {:.3f} {:.3f}",
                         f(Block::B, p.sun_x), f(Block::B, p.sun_y), p.cloud_base, f(Block::B, p.cloud_base),
                         p.scroll_mul, f(Block::B, p.scroll_mul), p.cloud_alt, f(Block::B, p.cloud_alt), p.seed,
                         f(Block::B, p.seed), p.fog[0], p.fog[3], f(Block::B, p.fog[0]), f(Block::B, p.fog[1]),
                         f(Block::B, p.fog[2]), f(Block::B, p.fog[3]), p.layers[0], p.layers[3],
                         f(Block::B, p.layers[0]), f(Block::B, p.layers[1]), f(Block::B, p.layers[2]),
                         f(Block::B, p.layers[3]));
    }
    if (s.mask & wsy::kHasC) {
        t += std::format(" | C: {:X} {:.3f} {:X} {:.3f} {:X} {:.3f}", p.c[0], f(Block::C, p.c[0]), p.c[1],
                         f(Block::C, p.c[1]), p.c[2], f(Block::C, p.c[2]));
    }
    if (s.mask & wsy::kHasX) {
        t += std::format(" | scroll X+{:X}/{:X} ({:.2f}, {:.2f})", p.scroll[0], p.scroll[1], f(Block::X, p.scroll[0]),
                         f(Block::X, p.scroll[1]));
    }
    return t;
}

std::string full_vector_text(const wsy::Snapshot& s) {
    const wsy::Layout& lay = L();
    std::string t;
    for (size_t i = 0; i < lay.count(); ++i) {
        if (!(s.mask & wsy::block_bit(lay[i].block))) continue;
        const wsy::Field& f = lay[i];
        const char blk = f.block == wsy::Block::A ? 'A' : f.block == wsy::Block::B ? 'B' : f.block == wsy::Block::C ? 'C' : 'X';
        if (f.kind == wsy::Kind::Raw || f.kind == wsy::Kind::Unknown) {
            t += std::format("{}{}+{:X}={:08X} ", f.name, blk, f.off, s.w[i]);
        } else {
            t += std::format("{}{}+{:X}={:.4f} ", f.name, blk, f.off, s.f(i));
        }
    }
    return t;
}

std::string braw_text(const uint8_t* b) {
    const wsy::Range r = L().read_b;
    std::string t;
    for (size_t o = 0; o + 4 <= r.size; o += 4) {
        uint32_t w = 0;
        std::memcpy(&w, b + o, 4);
        t += std::format("{:X}:{:08X} ", r.off + o, w);
    }
    return t;
}

std::string fbits(uint64_t w) { return std::format("{:.3f}", wsy::as_float(static_cast<uint32_t>(w))); }

void drain_events(uint64_t& lines) {
    const wsy::AWords& aw = L().a;
    const uint16_t temp_at = L().a_temp_sample;
    p8p::Event e;
    while (g_ring.pop(e)) {
        if (lines++ >= kEventLines) continue;
        switch (e.kind) {
            case kEvApplyBegin:
                log::info("WeatherSync [1 guest]: X 0x{:X} -> VIEWER MODE (X+0x31 {} -> 1): the host's sample #{} (age {} "
                          "ms, host tick {}), precipitation command {}; the guest's simulators and mixer stand still; {} "
                          "holder words kept for the release (WeatherComponents X+0x88 = {})",
                          e.v[0], e.v[4], e.v[1], e.v[2], e.v[5], fbits(e.v[3]), e.v[6],
                          e.v[7] == ~uint64_t{0} ? std::string("?") : std::format("{}", e.v[7]));
                break;
            case kEvRelease:
                log::info("WeatherSync [1 guest]: X 0x{:X} back to its own weather (X+0x31 = its value {}, {} holder words "
                          "put back, WeatherComponents X+0x88 = {}): {} after {} frames",
                          e.v[0], e.v[3] ? "written" : "NOT WRITTEN (X no longer the weather system, or the write failed)",
                          e.v[4], e.v[5] == ~uint64_t{0} ? std::string("?") : std::format("{}", e.v[5]),
                          why_name(e.v[1]), e.v[2]);
                break;
            case kEvFault:
                log::error("WeatherSync [{} {}]: a guarded access FAILED in the hook ({} at 0x{:X}, X 0x{:X}); writes "
                           "stop until {} clean frames or the next opening of the gate (fault {} of at most {})",
                           wsy::mode_name(mode()), role(), fault_name(e.v[1]), e.v[2], e.v[0],
                           wsy::FaultLatch::kCleanFrames, g_fault_count.load(), wsy::FaultLatch::kMaxFaults);
                break;
            case kEvFaultCleared:
                log::warn("WeatherSync [1 guest]: writes allowed again on X 0x{:X} after fault {} ({})", e.v[0], e.v[1],
                          e.v[2] ? "the gate opened again" : "enough clean frames");
                break;
            case kEvFaultExhausted:
                log::error("WeatherSync [1 guest]: {} faults: mode 1 stays OFF for the rest of this run (X 0x{:X}); the "
                           "guest keeps its own weather",
                           e.v[1], e.v[0]);
                break;
            case kEvEvicted:
                log::warn("WeatherSync [1 guest]: X 0x{:X} is no longer the one the game updates (now 0x{:X}): its record "
                          "dropped; its X+0x31 {}",
                          e.v[0], e.v[1],
                          e.v[2]   ? "put back"
                          : e.v[3] ? "left (not ours any more, or not 1)"
                                   : "NOT touched (its vtable is gone: freed or reused)");
                break;
            case kEvStBegin:
                log::warn("WeatherSync selftest: APPLY BEGINS on X 0x{:X}: before: X+0x31 = {} precipitation({:X}) {} "
                          "{:X} {} {:X} {} snow({:X}) {} rain({:X}) {} temperature sample({:X}) {} -> now X+0x31 = 1 and "
                          "A+0x{:X} = 1.000 every frame for 30 s: it should RAIN (or snow below 0 degrees) at once",
                          e.v[0], e.v[1], aw.precip, fbits(e.v[2]), aw.rain_out, fbits(e.v[3]), aw.rain_fx,
                          fbits(e.v[4]), aw.snow, fbits(e.v[5]), aw.rain, fbits(e.v[6]), temp_at, fbits(e.v[7]),
                          aw.precip);
                break;
            case kEvStCheck:
                log::info("WeatherSync selftest: one frame later (the original ran once in viewer mode): X+0x31 = {} "
                          "precipitation({:X}) {} rain({:X}) {} snow({:X}) {} {:X} {} temperature({:X}) {} (viewer "
                          "derivation: temperature > 0 -> rain = precipitation, else snow)",
                          e.v[1], aw.precip, fbits(e.v[2]), aw.rain, fbits(e.v[3]), aw.snow, fbits(e.v[4]), aw.rain_fx,
                          fbits(e.v[5]), temp_at, fbits(e.v[6]));
                break;
            case kEvStRestored:
                log::warn("WeatherSync selftest: {} on X 0x{:X} after {} frames: X+0x31 {} -> its value{}; before the "
                          "restore precipitation({:X}) {} rain({:X}) {} snow({:X}) {}; writes {}. The rain should STOP and "
                          "the level's weather return within seconds",
                          e.v[1] == 0 ? "RESTORED (done)" : e.v[1] == 1 ? "RESTORED (aborted)" : "RESTORED (fault)",
                          e.v[0], e.v[3], e.v[4],
                          e.v[8] ? std::format(" and A+0x{:X}/{:X}/{:X}/{:X}/{:X} to the values logged before",
                                               aw.precip, aw.rain_out, aw.rain_fx, aw.snow, aw.rain)
                                 : std::string(" (A is another block now: only the flag)"),
                          aw.precip, fbits(e.v[5]), aw.rain, fbits(e.v[6]), aw.snow, fbits(e.v[7]),
                          e.v[2] ? "ok" : "FAILED");
                break;
            case kEvStPending:
                log::warn("WeatherSync selftest: the run ended while the update ran on another X (0x{:X}, the run's is "
                          "0x{:X}): the run's X is put back if the game updates it again; the new X was never touched",
                          e.v[1], e.v[0]);
                break;
            case kEvForeign:
                log::warn("WeatherSync [1 guest]: X 0x{:X} already has X+0x31 = {} (not set by the mod): left alone",
                          e.v[0], e.v[1]);
                break;
            case kEvFull:
                log::warn("WeatherSync [1 guest]: four X objects are in viewer mode already; X 0x{:X} is left alone",
                          e.v[0]);
                break;
            default: break;
        }
    }
}

// ---------------------------------------------------------------- the worker

bool build_ok_2976() {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    return g_base == g2976::kImageBase && game::safe_read(g_base, &dos, sizeof dos) &&
           game::safe_read(g_base + dos.e_lfanew, &nt, sizeof nt) && nt.FileHeader.TimeDateStamp == g2976::kPeTimestamp;
}

bool getter_bytes_ok() {
    return bytes_at(G().getter, wsy::kGetterVf60Bytes);
}

struct Last {
    uintptr_t xa = 0, xb = 0, holder = 0, a = 0, b = 0, c = 0;
    bool any = false;
    float target[3] = {};
    bool have_target = false;
};

DWORD WINAPI worker_thread(LPVOID) {
    try {
        const Mode m = mode();
        const bool want_hook = (m == Mode::Selftest && !g_guest) || (m == Mode::On && g_guest);
        game::PlayerReader reader;
        reader.init();
        wsy::WorldWatch watch;
        Last last;
        uint64_t x_changes = 0, change_lines = 0, target_lines = 0, event_lines = 0;
        uint64_t last_probe = 0, last_minute = 0;
        bool first_minute_done = false;
        uint32_t seq = 0;
        bool hook_tried = false;
        float own[3] = {};
        bool own_pos = false;
        wsy::Gate last_gate = wsy::Gate::Count;
        wsy::LineGate gate_lines(5000);
        bool last_unreadable = false;
        for (;;) {
            Sleep(kTickMs);
            const uint64_t now = GetTickCount64();
            const auto me = reader.read();
            watch.feed(now, me.has_value());
            g_world_ready.store(watch.ready(), std::memory_order_relaxed);
            if (me) {
                own[0] = me->position.x;
                own[1] = me->position.y;
                own[2] = me->position.z;
                own_pos = true;
            }
            if (want_hook && !hook_tried && watch.ready()) {
                hook_tried = true;
                if (!install_hook()) {
                    log::error("WeatherSync [{} {}]: the hook is not in; this run only logs (probe)", wsy::mode_name(m),
                               role());
                }
            }
            Reading r;
            read_all(r);
            const uint64_t tmod = r.tick_ok ? r.tick % 60000 : 0;
            // X / holder / blocks changes (5 Hz): does X survive the host's unload bursts?
            if (r.x || last.any) {
                if (last.any && (r.xa != last.xa || r.xb != last.xb || r.holder != last.holder || r.a != last.a ||
                                 r.b != last.b || r.c != last.c)) {
                    ++x_changes;
                    if (change_lines++ < kChangeLines) {
                        log::warn("WeatherSync [{} {}]: X CHANGED: X {} -> {} (path 2: {} -> {}) holder {} -> {} A {} -> "
                                  "{} B {} -> {} C {} -> {} | tick {} (%60000 = {}) | world ready {}",
                                  wsy::mode_name(m), role(), hex(last.xa), hex(r.xa), hex(last.xb), hex(r.xb),
                                  hex(last.holder), hex(r.holder), hex(last.a), hex(r.a), hex(last.b), hex(r.b),
                                  hex(last.c), hex(r.c), r.tick, tmod, watch.ready() ? "yes" : "no");
                    }
                }
                last.xa = r.xa;
                last.xb = r.xb;
                last.holder = r.holder;
                last.a = r.a;
                last.b = r.b;
                last.c = r.c;
                last.any = true;
            }
            // The targets (P0-d: the 60 s grid). On a guest in viewer mode they are ours: not logged then.
            if (r.snap.mask & wsy::kHasA) {
                const wsy::Layout& lay = L();
                const float t3[3] = {r.snap.f(lay.idx_precip), r.snap.f(lay.idx_cloud), r.snap.f(lay.idx_humid)};
                if (last.have_target && !g_applying.load(std::memory_order_relaxed) &&
                    (std::fabs(t3[0] - last.target[0]) > 1e-6f || std::fabs(t3[1] - last.target[1]) > 1e-6f ||
                     std::fabs(t3[2] - last.target[2]) > 1e-6f) &&
                    target_lines++ < kTargetLines) {
                    log::info("WeatherSync [{} {}]: target changed: precipitation {:.4f} -> {:.4f} cloudiness {:.4f} -> "
                              "{:.4f} humidity {:.4f} -> {:.4f} | tick {} (%60000 = {})",
                              wsy::mode_name(m), role(), last.target[0], t3[0], last.target[1], t3[1], last.target[2],
                              t3[2], r.tick, tmod);
                }
                std::copy(std::begin(t3), std::end(t3), last.target);
                last.have_target = true;
            }
            // Host, mode 1: the sample for the network thread.
            if (m == Mode::On && !g_guest && (r.snap.mask & (wsy::kHasA | wsy::kHasB | wsy::kHasX)) ==
                                                    (wsy::kHasA | wsy::kHasB | wsy::kHasX)) {
                wsy::Snapshot s = r.snap;
                s.seq = ++seq;
                if (me) {
                    s.pos[0] = me->position.x;
                    s.pos[1] = me->position.y;
                    s.pos[2] = me->position.z;
                    s.mask |= wsy::kHasPos;
                }
                if (const wsy::Sanity san = wsy::check(L(), s); san.ok()) {
                    const wsy::Frame f = wsy::frame(L(), s);
                    AcquireSRWLockExclusive(&g_out_lock);
                    g_out_frame = f;
                    g_out_seq = s.seq;
                    ReleaseSRWLockExclusive(&g_out_lock);
                } else if (c_sample_insane.fetch_add(1) < kInsaneLines) {
                    // Review item 8: never dropped in silence.
                    const size_t bad = static_cast<size_t>(san.first_bad);
                    log::warn("WeatherSync [1 host]: sample #{} NOT sent: {} non-finite, {} huge (first: {} = {}); "
                              "counted in the 5 s line",
                              s.seq, san.nonfinite, san.huge, wsy::field_name(L(), san.first_bad),
                              bad < L().count() ? std::format("{:08X}", s.w[bad]) : std::string("position"));
                }
            }
            // Guest, mode 1: the gates.
            wsy::Timed newest;
            bool have_newest = false;
            if (g_guest && m == Mode::On) {
                uint32_t w[wsy::kBoxWords];
                uint64_t bs = 0;
                if (g_box.read(w, bs)) {
                    wsy::unpack(w, newest);
                    have_newest = true;
                }
                wsy::GateIn in;
                in.remote_live = guest_remote_live();
                in.in_world = watch.ready();
                in.own_pos = own_pos;
                std::copy(std::begin(own), std::end(own), in.own);
                in.host_pos = have_newest && (newest.s.mask & wsy::kHasPos);
                if (in.host_pos) std::copy(std::begin(newest.s.pos), std::end(newest.s.pos), in.host);
                in.radius_m = g_radius_m;
                in.was_open = last_gate == wsy::Gate::Apply;  // review item 5: the radius' hysteresis
                const wsy::Gate g = wsy::decide_gate(in);
                g_gate.store(static_cast<uint8_t>(g), std::memory_order_relaxed);
                if (g == wsy::Gate::Apply && last_gate != wsy::Gate::Apply) g_gate_epoch.fetch_add(1);  // item 2
                if (g != last_gate && gate_lines.take(now)) {
                    double d = -1;
                    if (in.host_pos && in.own_pos) {
                        double d2 = 0;
                        for (int i = 0; i < 3; ++i) d2 += (in.own[i] - in.host[i]) * static_cast<double>(in.own[i] - in.host[i]);
                        d = std::sqrt(d2);
                    }
                    const uint64_t skipped = gate_lines.suppressed_and_reset();
                    log::info("WeatherSync [1 guest]: gate {} ({}){}{}", g == wsy::Gate::Apply ? "OPEN" : "closed",
                              wsy::gate_name(g),
                              d >= 0 ? std::format("; {:.0f} m from the host (radius {} m, margin {:.0f} m)", d,
                                                   g_radius_m, wsy::radius_margin_m(g_radius_m))
                                     : std::string(),
                              skipped ? std::format(" (+{} changes in the last 5 s not logged)", skipped) : std::string());
                }
                last_gate = g;
            }
            drain_events(event_lines);
            // Every 5 s: the probe line.
            if (now - last_probe >= kProbeEveryMs) {
                last_probe = now;
                const bool unreadable = !r.x;
                if (!(unreadable && last_unreadable)) {
                    const wsy::Sanity san = wsy::check(L(), r.snap);
                    std::string extra;
                    if (m == Mode::Selftest && !g_guest) {
                        extra = std::format(" | selftest: {}, frames written {}, hook {}",
                                            wsy::st_phase_name(static_cast<wsy::StPhase>(g_st_phase.load())),
                                            g_st_frames.load(), g_hook_on.load() ? "in" : "not in");
                    } else if (m == Mode::On && g_guest) {
                        extra = std::format(
                            " | mirror: hook {}, gate {}, newest sample {} | frames applied {} released {} (stale {} gated "
                            "{} no sample {} bad sample {}) re-asserted {} | samples in {} (bad {}, insane {}) | faulted {} "
                            "(faults {}, frames held {}) | evicted X {} | words put back {} | gate changes not logged {}",
                            g_hook_on.load() ? "in" : "NOT in",
                            wsy::gate_name(static_cast<wsy::Gate>(g_gate.load())),
                            have_newest ? std::format("#{} age {} ms host tick {}", newest.s.seq, wsy::age_ms(now, newest.recv_ms),
                                                      newest.s.tick)
                                        : std::string("none"),
                            c_applied.load(), c_released.load(), c_stale.load(), c_gated.load(), c_no_sample.load(),
                            c_bad_sample.load(), c_reasserted.load(), c_rx.load(), c_rx_bad.load(), c_rx_insane.load(),
                            g_faulted.load() ? "YES" : "no", g_fault_count.load(), c_fault_frames.load(), c_evicted.load(),
                            c_words_restored.load(), gate_lines.pending());
                    } else if (m == Mode::On) {
                        extra = std::format(" | to the guest: sent {} (guest caps 0x{:02X}; not connected {}, no caps "
                                            "0x04 {}, user 2 not in the world {}, tunnel backlog {}, refused {}, samples "
                                            "not sane {})",
                                            c_tx.load(), g_tx_peer_caps.load(), c_tx_not_connected.load(),
                                            c_tx_no_caps.load(), c_tx_not_in_world.load(), c_tx_backlog.load(),
                                            c_tx_refused.load(), c_sample_insane.load());
                    }
                    const wsy::GameAddrs& g = G();
                    log::info("WeatherSync [{} {}]: tick {} (%60000 = {}) | X {} (M+0x{:X}+0x{:X}{}) / {} "
                              "([0x{:X}]+0x{:X}+0x{:X}): {}, vtable {}, viewer X+0x31 = {} | holder {} A {} B {} C {} | "
                              "WeatherComponents X+0x88 = {} | {} | local sample A+0x{:X}.. {} | sanity: {} non-finite, "
                              "{} huge, {} outside [0,1], {} FLT_MAX (not set) | X changes {} | world ready {}{}",
                              wsy::mode_name(m), role(), r.tick_ok ? std::format("{}", r.tick) : std::string("unreadable"),
                              tmod, hex(r.xa), g.module_scene, g.scene_weather,
                              r.getter_ok ? std::string() : std::format(", getter NOT 0x{:X}", g.getter), hex(r.xb),
                              g.client_slot, g.client_hop1, g.client_hop2,
                              !r.xa || !r.xb ? "one missing" : r.xa == r.xb ? "same" : "DIFFERENT",
                              r.vt_ok ? "ok" : (r.x ? "BAD" : "-"), r.flag_ok ? std::format("{}", r.flag) : std::string("?"),
                              hex(r.holder), hex(r.a), hex(r.b), hex(r.c),
                              r.wc_ok ? std::format("{}", r.wc) : std::string("?"), vector_text(r.snap),
                              L().a_temp_sample,
                              r.temp_ok ? std::format("({:.2f}, {:.2f}, {:.2f}, {:.2f}, {:.2f})", r.temp[0], r.temp[1],
                                                      r.temp[2], r.temp[3], r.temp[4])
                                        : std::string("unreadable"),
                              san.nonfinite, san.huge, san.outside_unit, san.unset, x_changes,
                              watch.ready() ? "yes" : "no", extra);
                }
                last_unreadable = unreadable;
            }
            // Once a minute (and at the first readable sample): every field, and B's raw words (are they floats?).
            if ((r.snap.mask & wsy::kHasB) && (!first_minute_done || now - last_minute >= kMinuteMs)) {
                first_minute_done = true;
                last_minute = now;
                log::info("WeatherSync [{} {}]: full vector: {}", wsy::mode_name(m), role(), full_vector_text(r.snap));
                log::info("WeatherSync [{} {}]: B raw words +0x{:X}..+0x{:X}: {}", wsy::mode_name(m), role(),
                          L().read_b.off, L().read_b.off + L().read_b.size - 4, braw_text(r.braw));
                if (want_hook) {
                    log::info("WeatherSync [{} {}]: hook calls {} (busy {}), X not the weather system {}, foreign viewer "
                              "{}, full {}, buffer retries {}",
                              wsy::mode_name(m), role(), c_calls.load(), c_busy.load(), c_x_bad.load(), c_foreign.load(),
                              c_full.load(), c_box_retry.load());
                }
            }
        }
    } catch (...) {
        log::error("WeatherSync: the worker stopped (exception); nothing more is logged or sampled");
    }
    return 0;
}

}  // namespace

void weather_sync_start(const std::string& raw, bool guest, uint32_t radius_m) {
    const wsy::ParsedMode p = wsy::parse_mode(raw);
    if (!p.known) {
        log::warn("WeatherSync: weather_sync='{}' is not 0, probe, selftest or 1; it stays off", raw);
        return;
    }
    if (p.mode == Mode::Off || g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    // One table per build (weather_sync_logic.h). 1.0.0.3527 shares 3549's layout statically, but its PE was never
    // read for this module (only 3549's: docs/research/s25/clima-3549.md): it stays off.
    const game::Build build = game::current_build();
    if (build == game::Build::v2976 && build_ok_2976()) {
        g_game.store(&wsy::kGame2976, std::memory_order_release);
        g_layout.store(&wsy::kLayout2976, std::memory_order_release);
    } else if (build == game::Build::v3527 && game::is_3549() && g_base == g2976::kImageBase) {
        g_game.store(&wsy::kGame3549, std::memory_order_release);
        g_layout.store(&wsy::kLayout3549, std::memory_order_release);
    } else if (build == game::Build::v3576 && g_base == g2976::kImageBase) {
        // 3549's layout and wire version at 3576's addresses (weather_sync_logic.h kGame3576).
        g_game.store(&wsy::kGame3576, std::memory_order_release);
        g_layout.store(&wsy::kLayout3549, std::memory_order_release);
    } else if (build == game::Build::v3663 && g_base == g2976::kImageBase) {
        // Build 1.0.0.3663 (static, 2026-11-13; never run): 3549's layout and wire version at 3663's addresses
        // (weather_sync_logic.h kGame3663).
        g_game.store(&wsy::kGame3663, std::memory_order_release);
        g_layout.store(&wsy::kLayout3549, std::memory_order_release);
    } else if (build == game::Build::v3527) {
        log::warn("WeatherSync: 1.0.0.3527 is not verified for weather_sync (only 1.0.0.3549's PE was read, "
                  "clima-3549.md); weather_sync stays off, nothing hooked or written");
        return;
    } else {
        log::error("WeatherSync: unsupported game build (not 1.0.0.2976, 3549, 3576 or 3663); weather_sync stays off");
        return;
    }
    Mode m = p.mode;
    if (m == Mode::Selftest && guest) {
        log::warn("WeatherSync: weather_sync=selftest is for the HOST's PC alone (P1); on the guest it runs as probe");
        m = Mode::Probe;
    }
    g_guest = guest;
    g_radius_m = radius_m ? radius_m : wsy::kDefaultRadiusM;
    const wsy::GameAddrs& g = G();
    if (!getter_bytes_ok()) {
        log::warn("WeatherSync: exe+0x{:X} is not `mov rax,[rcx+0x60]; ret` (the simulators' path to X is then not "
                  "[[exe+0x{:X}]+0x{:X}]+0x{:X}); the probe says so on each line",
                  g.getter, g.module_slot, g.module_scene, g.scene_weather);
    }
    g_mode.store(static_cast<uint8_t>(m), std::memory_order_release);
    const std::string what =
        m == Mode::Probe ? std::string("READ ONLY: every 5 s the X line, X changes at once, target changes with tick % "
                                       "60000")
        : m == Mode::Selftest
            ? std::format("the probe + SELFTEST (P1, this PC alone): a hook at 0x{:X} once the world is up; 15 s later "
                          "X+0x31 = 1 and A+0x{:X} = 1.0 for 30 s, then put back",
                          g.update, L().a.precip)
        : guest ? std::format("the probe + MIRROR: caps 0x04 to the host; the host's state-12 samples (wire version {}, "
                              "{} words) written in viewer mode by a hook at 0x{:X} while fresh and the gates pass",
                              L().wire_version, L().count(), g.update)
                : std::format("the probe + SAMPLES at 5 Hz to a guest that announced caps 0x04 (tunnel control state "
                              "12, wire version {}, {} words)",
                              L().wire_version, L().count());
    log::info("WeatherSync ON (weather_sync={}, {}): {}{} | build {}", wsy::mode_name(m), role(), what,
              m == Mode::On && guest ? std::format("; weather_sync_radius_m {}", g_radius_m) : std::string(), g.build);
    if (HANDLE h = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr)) CloseHandle(h);
}

uint8_t weather_sync_guest_caps() { return g_guest && mode() == Mode::On ? wsy::kCapsWeatherSync : uint8_t{0}; }

bool weather_sync_guest_on_control(std::span<const uint8_t> packet) noexcept {
    const wsy::Layout& lay = L();
    if (!wsy::is_frame(lay, packet)) return false;
    try {
        if (!g_guest || mode() != Mode::On) {
            c_rx_ignored.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        const auto s = wsy::decode(lay, packet);
        if (!s) {
            c_rx_bad.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        if (const wsy::Sanity san = wsy::check(lay, *s); !san.ok()) {
            // Review item 8: counted, and the first few logged with the field (FLT_MAX "not set" passes).
            if (c_rx_insane.fetch_add(1, std::memory_order_relaxed) < kInsaneLines) {
                const size_t bad = static_cast<size_t>(san.first_bad);
                log::warn("WeatherSync [1 guest]: the host's sample #{} dropped: {} non-finite, {} huge (first: {} = {})",
                          s->seq, san.nonfinite, san.huge, wsy::field_name(lay, san.first_bad),
                          bad < lay.count() ? std::format("{:08X}", s->w[bad]) : std::string("position"));
            }
            return true;
        }
        wsy::Timed t;
        t.s = *s;
        t.recv_ms = GetTickCount64();
        uint32_t w[wsy::kBoxWords];
        wsy::pack(t, w);
        g_box.publish(w);
        c_rx.fetch_add(1, std::memory_order_relaxed);
    } catch (...) {
    }
    return true;
}

void weather_sync_host_tick(troc::TrocLink& link, uint32_t /*now_ms*/) {
    if (g_guest || mode() != Mode::On) return;
    try {
        static uint32_t sent_seq = 0;  // the network thread only
        static bool no_caps_logged = false;
        uint32_t seq = 0;
        AcquireSRWLockShared(&g_out_lock);
        seq = g_out_seq;
        ReleaseSRWLockShared(&g_out_lock);
        if (!seq || seq == sent_seq) return;
        sent_seq = seq;  // each sample is considered once
        if (!link.connected() || link.broken()) {
            c_tx_not_connected.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const uint8_t caps = link.peer_caps();
        g_tx_peer_caps.store(caps, std::memory_order_relaxed);
        if (!(caps & wsy::kCapsWeatherSync)) {
            c_tx_no_caps.fetch_add(1, std::memory_order_relaxed);
            if (!no_caps_logged && caps) {
                no_caps_logged = true;
                log::info("WeatherSync [1 host]: the guest announced caps 0x{:02X} without 0x04 (weather_sync is not 1 "
                          "there): no weather samples are sent",
                          caps);
            }
            return;
        }
        if (!server_user2_in_world()) {
            c_tx_not_in_world.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (link.backlog_bytes() > kMaxBacklog) {
            c_tx_backlog.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        wsy::Frame f{};
        AcquireSRWLockShared(&g_out_lock);
        f = g_out_frame;
        ReleaseSRWLockShared(&g_out_lock);
        (link.push(f.bytes()) ? c_tx : c_tx_refused).fetch_add(1, std::memory_order_relaxed);
    } catch (...) {
    }
}

}  // namespace cdmp::session2
