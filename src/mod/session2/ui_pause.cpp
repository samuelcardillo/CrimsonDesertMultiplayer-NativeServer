#include "mod/game/build_profile.h"
#include "mod/session2/ui_pause.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "mod/game/hook_prepare.h"
#include "mod/game/game_fault.h"
#include "mod/game/hook_traps.h"
#include "mod/game/offsets.h"
#include "mod/game/rtti.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/freeze_watchdog.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"
#include "mod/session2/ui_pause_logic.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using uip::Mode;
using uip::Site;

// ---------------------------------------------------------------- the site (build 2976, .rsrc)
//
// Verified with capstone on D:\RE\CrimsonDesert_2976\bin\CrimsonDesert.exe
// (p8-pausa-esc.md, "Implementado"): 0x35CD990..0x35CDAA1 (.pdata entry
// 0x35CD990-0x35CDAA1, prologue 0x24 bytes), its only callers the two
// `call rel32` below, no rel32 (E8/E9/0F8x) of .rsrc/.xtls/.text/.xtext and
// no rel8 near it lands in 0x35CD991..0x35CD9AD, no absolute pointer to it
// in the file (its RVA appears once: its .pdata entry).
//   0x35CD990 mov [rsp+8],rbx       48 89 5C 24 08
//   0x35CD995 mov [rsp+0x10],rbp    48 89 6C 24 10
//   0x35CD99A mov [rsp+0x18],rsi    48 89 74 24 18
//   0x35CD99F mov [rsp+0x20],rdi    48 89 7C 24 20
//   0x35CD9A4 push r14              41 56
//   0x35CD9A6 sub rsp,0x30          48 83 EC 30
//   0x35CD9AA mov rax,[rcx+0x38]    48 8B 41 38      (rcx: the only argument)
// None is RIP-relative; the first one is (0x35CD9B4 vmovss xmm6,[rip+..] = 1.0f).
uintptr_t kScale = 0x35CD990;  // 3527: 0x389FB30, same prologue
constexpr uint8_t kScaleHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
                                  0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20,
                                  0x41, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0x41, 0x38};
// The instruction boundaries inside those 30 bytes: SafetyHook's patch (5
// bytes with a near trampoline, 14 -> 15 with the absolute fallback) must
// end on one of them.
constexpr uint32_t kBoundaries[] = {5, 10, 15, 20, 22, 26, 30};
// The callers (0xAD1300): 0xAD143C call (vf 0x160's scale) / 0xAD14D6 call (the dt).
uintptr_t kCall1 = 0xAD143C, kCall2 = 0xAD14D6;
constexpr uint8_t kCall1Bytes[] = {0xE8, 0x4F, 0xC5, 0xAF, 0x02};
constexpr uint8_t kCall2Bytes[] = {0xE8, 0xB5, 0xC4, 0xAF, 0x02};
uintptr_t kRet1 = 0xAD1441, kRet2 = 0xAD14DB;
// 1.0.0.3527 [V capstone, 2026-11-05]: the only callers of 0x389FB30 are in 0xBDE6F0. Its view walk changed (the vf is
// +0x178, the view's fields moved), and the walk only names the view for the log, so it does not run on this build.
constexpr uint8_t kCall1Bytes3527[] = {0xE8, 0xFF, 0x12, 0xCC, 0x02};
constexpr uint8_t kCall2Bytes3527[] = {0xE8, 0x65, 0x12, 0xCC, 0x02};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the scale moved whole by +0xD00 to 0x38A0830 (the only function
// within +0x4000 of 3527's that starts with kScaleHead; .pdata 0x111 bytes, as 2976's). Its only two callers are
// 0xBDEC4C / 0xBDECE6 in 0xBDEB10 (= 0xBDE6F0 + 0x420, the calls at the same +0x13C / +0x1D6); only their rel32
// changed. The clock globals, from FrameClock_NowMs 0x15FA340 (cmp byte [local],0 ; base + frac / 1000) and the main
// loop's write at 0xBDF1D6..0xBDF1F6 (frac += dt us): local 0x70DBF2D, base 0x70DBF68, frac 0x70DBF78 (read only).
constexpr uint8_t kCall1Bytes3576[] = {0xE8, 0xDF, 0x1B, 0xCC, 0x02};
constexpr uint8_t kCall2Bytes3576[] = {0xE8, 0x45, 0x1B, 0xCC, 0x02};
// Build 1.0.0.3663 (static, 2026-11-13; never run): kScaleHead is unique in the code section, at 0x39191C0 (.pdata
// 0x39191C0..0x39192D1, 0x111 bytes as before; vmovss xmm6,[rip+..] right after it, as 2976's). Its only two callers
// (every E8 rel32 of the code section scanned) are 0xC160EC / 0xC16186 in 0xC15FB0, at the same +0x13C / +0x1D6 as in
// 3576; only their rel32 changed. The clock globals, from FrameClock_NowMs 0x163B030 (cmp byte [local],0 ; base +
// frac / 1000) and the main loop's write at 0xC1667D..0xC1669D (frac += dt us): local 0x71600AD, base 0x71600E8, frac
// 0x71600F0 (read only; frac is base + 8 here, 3576 had + 0x10).
constexpr uint8_t kCall1Bytes3663[] = {0xE8, 0xCF, 0x30, 0xD0, 0x02};
constexpr uint8_t kCall2Bytes3663[] = {0xE8, 0x35, 0x30, 0xD0, 0x02};
bool g_is_3527 = false;  // 3527's layout: 3527, 3549, 3576 and 3663
bool g_is_3576 = false;  // 3576's addresses
bool g_is_3663 = false;  // 3663's addresses
// vf 0x168 of every UI root: vmovss xmm0,[rip+..] (1.0f) ; ret.
constexpr uintptr_t kTrivialVf = 0x63DA70;
constexpr uint8_t kTrivialVfBytes[] = {0xC5, 0xFA, 0x10, 0x05, 0x3C, 0x56, 0x73, 0x05, 0xC3};
// FrameClock_NowMs 0x1416B80's globals (read only, from the drain thread).
uintptr_t kClockLocal = 0x6C8CD35;  // u8: 1 = the per-frame scaled clock for every thread
uintptr_t kClockBase = 0x6C8CD68;   // u64 ms
uintptr_t kClockFrac = 0x6C8CD70;   // u64 us (added dt * 1e6 per frame, 0xAD19D3)

constexpr uint32_t kOneBits = 0x3F800000;  // 1.0f
constexpr uint32_t kSourceCheckEvery = 30;  // first-call frames between two walks while a UI value is in force
constexpr uint64_t kMaxEventLines = 2000;   // then only counted
constexpr size_t kLinesPerDrain = 60;

// ---------------------------------------------------------------- state

std::atomic<bool> g_started{false}, g_on{false};
std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_live{false};
bool g_guest = false;
uintptr_t g_base = 0, g_ret1 = 0, g_ret2 = 0, g_trivial = 0;
uint32_t g_patch = 0;
std::vector<gad::Section> g_secs;
SafetyHookInline g_hook;
uint16_t g_mark = 0;  // freeze_watchdog's id for the detour (set before the hook is enabled)

// The game's thread (the main loop calls 0x35CD990; atomics in case another ever does).
std::atomic<uint32_t> g_last_bits{kOneBits};
std::atomic<uintptr_t> g_src_view{0};
std::atomic<uint32_t> g_tick{0};
uip::EpisodeCounter g_ep;
p8p::EventRing<1024> g_ring;
std::atomic<uint64_t> c_calls[3] = {}, c_blocked[3] = {}, c_would[3] = {};
std::atomic<uint64_t> c_transitions{0}, c_sources{0}, c_walks{0}, c_walk_bad{0};

// Drain thread only.
uip::Ledger g_ledger;
uintptr_t g_cur_vt = 0;
std::unordered_map<uintptr_t, std::string> g_names;
uint64_t g_lines = 0, g_lines_dropped = 0;

// ---------------------------------------------------------------- reads on the game's thread

// SEH-guarded loads, no VirtualQuery (hot path): a null pointer is a valid
// value, an implausible one a failed read.
struct FastMem {
    bool u8(uintptr_t a, uint8_t& v) const noexcept { return game::fast_read(a, &v, sizeof v); }
    bool u32(uintptr_t a, uint32_t& v) const noexcept { return game::fast_read(a, &v, sizeof v); }
    bool ptr(uintptr_t a, uintptr_t& v) const noexcept {
        uintptr_t p = 0;
        if (!game::fast_read(a, &p, sizeof p)) return false;
        if (p && (p < 0x10000 || p > 0x00007FFFFFFFFFFFull)) return false;
        v = p;
        return true;
    }
};

uintptr_t source_view(const uip::ViewWalk& w) {
    if (!w.ok || w.hits == 0) return 0;
    return w.hit[static_cast<size_t>(w.source >= 0 ? w.source : 0)].view;
}

// One event: closes the episode, walks the views if asked, pushes the record.
void emit(uint16_t kind, uintptr_t world, uint32_t old_bits, uint32_t new_bits, const uip::Decision& d, bool live,
          Mode mode, Site site, bool walk, const uip::ViewWalk* done) noexcept {
    uip::Note n;
    n.kind = kind;
    n.old_bits = old_bits;
    n.new_bits = new_bits;
    n.d = d;
    n.live = live;
    n.mode = mode;
    n.site = site;
    g_ep.close(n.ep_seen, n.ep_blocked);
    if (done) {
        n.walk = *done;
        n.walked = true;
    } else if (walk && !g_is_3527) {
        n.walk = uip::walk_views(FastMem{}, world, g_trivial);
        n.walked = true;
        c_walks.fetch_add(1, std::memory_order_relaxed);
        if (!n.walk.ok || n.walk.truncated) c_walk_bad.fetch_add(1, std::memory_order_relaxed);
    }
    g_src_view.store(n.walked ? source_view(n.walk) : 0, std::memory_order_relaxed);
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    uip::pack(n, g_base, e);
    g_ring.push(e);  // full: counted by the ring, never blocks
}

float on_scale(uintptr_t world, float orig, uintptr_t ret) noexcept {
    const Site site = ret == g_ret1 ? Site::First : ret == g_ret2 ? Site::Second : Site::Other;
    const auto mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    const bool live = g_live.load(std::memory_order_relaxed);
    const uip::Decision d = uip::decide(mode, live, orig);
    const size_t s = static_cast<size_t>(site);
    c_calls[s].fetch_add(1, std::memory_order_relaxed);
    if (d.blocked) c_blocked[s].fetch_add(1, std::memory_order_relaxed);
    if (d.would) c_would[s].fetch_add(1, std::memory_order_relaxed);
    if (site == Site::First && d.would) g_ep.frame(d.blocked);
    const uint32_t bits = std::bit_cast<uint32_t>(orig);
    const uint32_t prev = g_last_bits.load(std::memory_order_relaxed);
    if (bits != prev) {
        g_last_bits.store(bits, std::memory_order_relaxed);
        c_transitions.fetch_add(1, std::memory_order_relaxed);
        g_tick.store(0, std::memory_order_relaxed);
        emit(uip::kEvTransition, world, prev, bits, d, live, mode, site, bits != kOneBits, nullptr);
    } else if (!g_is_3527 && site == Site::First && bits != kOneBits &&
               g_tick.fetch_add(1, std::memory_order_relaxed) % kSourceCheckEvery == kSourceCheckEvery - 1) {
        // Same value: has another view become the one that asks for it (a menu opened from another one)?
        const uip::ViewWalk w = uip::walk_views(FastMem{}, world, g_trivial);
        c_walks.fetch_add(1, std::memory_order_relaxed);
        if (!w.ok || w.truncated) c_walk_bad.fetch_add(1, std::memory_order_relaxed);
        if (source_view(w) != g_src_view.load(std::memory_order_relaxed)) {
            c_sources.fetch_add(1, std::memory_order_relaxed);
            emit(uip::kEvSource, world, prev, bits, d, live, mode, site, true, &w);
        }
    }
    return d.value;
}

// 0x35CD990(world) -> f32 in xmm0. The original is the only game call.
float __fastcall scale_detour(void* world) noexcept {
    freeze_watchdog_frame();  // once per main loop turn: the freeze watchdog's frame source (two relaxed stores)
    const FreezeMark mark(g_mark);
    const float orig = g_hook.unsafe_call<float>(world);
    return on_scale(reinterpret_cast<uintptr_t>(world), orig, reinterpret_cast<uintptr_t>(_ReturnAddress()));
}

// ---------------------------------------------------------------- install (its own thread)

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

bool read_sections() {
    g_secs.clear();
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!peek(g_base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || !peek(g_base + dos.e_lfanew, nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
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

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

bool code_ready() {
    if (g_is_3663) {
        return bytes_at(kScale, kScaleHead) && bytes_at(kCall1, kCall1Bytes3663) && bytes_at(kCall2, kCall2Bytes3663);
    }
    if (g_is_3576) {
        return bytes_at(kScale, kScaleHead) && bytes_at(kCall1, kCall1Bytes3576) && bytes_at(kCall2, kCall2Bytes3576);
    }
    if (g_is_3527) {
        return bytes_at(kScale, kScaleHead) && bytes_at(kCall1, kCall1Bytes3527) && bytes_at(kCall2, kCall2Bytes3527);
    }
    return bytes_at(kScale, kScaleHead) && bytes_at(kCall1, kCall1Bytes) && bytes_at(kCall2, kCall2Bytes) &&
           bytes_at(kTrivialVf, kTrivialVfBytes);
}

bool install() {
    struct Ctx {
        uintptr_t rva;
        std::span<const uint8_t> bytes;
        const char* what;
    };
    const Ctx ctx_2976[] = {{kScale, kScaleHead, "the UI time scale 0x35CD990 (30-byte prologue)"},
                            {kCall1, kCall1Bytes, "its caller 0xAD143C"},
                            {kCall2, kCall2Bytes, "its caller 0xAD14D6"},
                            {kTrivialVf, kTrivialVfBytes, "the roots' vf 0x168 0x63DA70"}};
    const Ctx ctx_3527[] = {{kScale, kScaleHead, "the UI time scale 0x389FB30 (30-byte prologue)"},
                            {kCall1, kCall1Bytes3527, "its caller 0xBDE82C"},
                            {kCall2, kCall2Bytes3527, "its caller 0xBDE8C6"}};
    const Ctx ctx_3576[] = {{kScale, kScaleHead, "the UI time scale 0x38A0830 (30-byte prologue)"},
                            {kCall1, kCall1Bytes3576, "its caller 0xBDEC4C"},
                            {kCall2, kCall2Bytes3576, "its caller 0xBDECE6"}};
    const Ctx ctx_3663[] = {{kScale, kScaleHead, "the UI time scale 0x39191C0 (30-byte prologue)"},
                            {kCall1, kCall1Bytes3663, "its caller 0xC160EC"},
                            {kCall2, kCall2Bytes3663, "its caller 0xC16186"}};
    const std::span<const Ctx> sites = g_is_3663   ? std::span<const Ctx>(ctx_3663)
                                       : g_is_3576 ? std::span<const Ctx>(ctx_3576)
                                       : g_is_3527 ? std::span<const Ctx>(ctx_3527)
                                                   : std::span<const Ctx>(ctx_2976);
    for (const Ctx& c : sites) {
        if (!gad::in_real_code(g_secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size()))) {
            const gad::Section* s = gad::section_of(g_secs, static_cast<uint32_t>(c.rva));
            log::error("UiPause: {} (exe+0x{:X}) is not inside .rsrc (section {}); REFUSED, not hooked", c.what, c.rva,
                       s ? s->name : "none");
            return false;
        }
        if (!bytes_at(c.rva, c.bytes)) {
            log::error("UiPause: {} (exe+0x{:X}) is not the expected code of this build; REFUSED, not hooked", c.what,
                       c.rva);
            return false;
        }
    }
    auto whole = [](const std::vector<uint8_t>& o) {
        return std::find(std::begin(kBoundaries), std::end(kBoundaries), o.size()) != std::end(kBoundaries) &&
               o.size() <= sizeof kScaleHead && std::memcmp(o.data(), kScaleHead, o.size()) == 0;
    };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(g_base + kScale, reinterpret_cast<void*>(&scale_detour), whole, "UiPause",
                                  "scale 0x35CD990");
    if (!h) {
        log::error("UiPause: the hook at exe+0x{:X} could not be prepared ({}); REFUSED", kScale,
                   game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("UiPause: the hook at exe+0x{:X} would patch {} bytes, not a whole number of the 30 verified "
                   "instructions; REFUSED, nothing written",
                   kScale, orig.size());
        return false;  // destroyed disabled: the game's code was never touched
    }
    g_patch = static_cast<uint32_t>(orig.size());
    g_mark = freeze_watchdog_register("UiPause", "scale 0x35CD990 (detour + the game's original)");
    g_hook = std::move(*h);  // the detour calls through it: in place before enabling
    if (!g_hook.enable()) {
        log::error("UiPause: the hook at exe+0x{:X} could not be enabled; REFUSED", kScale);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- drain (the same thread)

std::string fmt_scale(uint32_t bits) {
    const float v = std::bit_cast<float>(bits);
    return std::format("{:g}", v);
}

const std::string& class_of(uintptr_t vt) {
    auto it = g_names.find(vt);
    if (it != g_names.end()) return it->second;
    std::string name = vt ? game::short_class_name(game::rtti_name_of_vtable(vt)) : std::string();
    if (name.empty()) name = vt ? std::format("vtable exe+0x{:X}", vt - g_base) : std::string("(no UI root found)");
    return g_names.emplace(vt, std::move(name)).first->second;
}

std::string fmt_hit(const uip::ViewHit& h) {
    const std::string root = h.root_vtable ? std::format("{} (vtable exe+0x{:X})", class_of(h.root_vtable),
                                                         h.root_vtable - g_base)
                                           : std::string("a view without a UI root");
    return std::format("{} view 0x{:X} index {} state {} timeScale {}{}", root, h.view, h.index, h.state,
                       fmt_scale(h.scale_bits),
                       h.custom_vf ? " [its root's vf 0x168 is not 0x63DA70: value not readable]" : "");
}

std::string fmt_decision(const uip::Note& n) {
    const uip::Kind k = uip::classify(std::bit_cast<float>(n.new_bits));
    if (n.d.blocked) return "BLOCKED: the game gets 1.0 (the world keeps running)";
    if (k == uip::Kind::Neutral) return "back to 1 (no UI view asks for a scale)";
    if (!n.d.would) return std::format("passed ({})", uip::kind_name(k));
    if (n.mode == Mode::Probe) return "would be blocked by ui_pause_block=1/force (probe: nothing changed)";
    return "passed: no live P8 session (single-player pause as usual)";
}

void format_event(const p8p::Event& e) {
    const uip::Note n = uip::unpack(e, g_base);
    // The per-UI ledger: the closing episode goes to what explained it.
    g_ledger.frames(g_cur_vt, n.ep_seen, n.ep_blocked);
    const uintptr_t vt = n.d.would ? uip::attributed_vtable(n) : 0;
    if (n.d.would && (n.kind == uip::kEvTransition || vt != g_cur_vt)) {
        g_ledger.episode(vt, std::bit_cast<float>(n.new_bits));
    }
    g_cur_vt = n.d.would ? vt : 0;
    if (g_lines >= kMaxEventLines) {
        ++g_lines_dropped;
        return;
    }
    ++g_lines;
    const uip::Kind k = uip::classify(std::bit_cast<float>(n.new_bits));
    std::string src;
    if (!n.walked) {
        src = "";
    } else if (!n.walk.ok) {
        src = " | views: the list could not be read";
    } else {
        src = std::format(" | views: {} in the list, {} open, {} asking for a scale{}", n.walk.count, n.walk.open,
                          n.walk.hits, n.walk.truncated ? " (walk incomplete)" : "");
        const size_t shown = std::min<size_t>(n.walk.hits, uip::kMaxHits);
        for (size_t i = 0; i < shown; ++i) {
            const bool is_src = static_cast<int>(i) == n.walk.source || (n.walk.source < 0 && i == 0);
            src += std::format(" | {}{}", is_src ? (n.walk.source < 0 ? "source? " : "source: ") : "also: ",
                               fmt_hit(n.walk.hit[i]));
        }
        if (n.walk.hits == 0) src += " | source: NO open view explains it";
    }
    const char* site = n.site == Site::First ? "0xAD143C" : n.site == Site::Second ? "0xAD14D6" : "other caller";
    if (n.kind == uip::kEvTransition) {
        log::info("UiPause [{}] {}: UI timeScale {} -> {} ({}) | {} | session {} | seen at {}{} | previous episode: {} "
                  "frames ({} blocked)",
                  uip::mode_name(n.mode), p8_when(e.qpc_us), fmt_scale(n.old_bits), fmt_scale(n.new_bits),
                  uip::kind_name(k), fmt_decision(n), n.live ? "LIVE" : "not live", site, src, n.ep_seen, n.ep_blocked);
    } else {
        log::info("UiPause [{}] {}: UI timeScale {} ({}), now explained by another view | {}{} | previous episode: {} "
                  "frames ({} blocked)",
                  uip::mode_name(n.mode), p8_when(e.qpc_us), fmt_scale(n.new_bits), uip::kind_name(k), fmt_decision(n),
                  src, n.ep_seen, n.ep_blocked);
    }
}

void drain() {
    p8p::Event e;
    size_t n = 0;
    while (n < kLinesPerDrain && g_ring.pop(e)) {
        format_event(e);
        ++n;
    }
}

bool live_now() {
    uip::LiveInputs in;
    in.role = g_guest ? uip::Role::Guest : uip::Role::Host;
    if (g_guest) {
        in.guest_remote = guest_remote_live();
    } else {
        in.host_user2 = server_user2_present();
    }
    return uip::session_live(in);
}

struct ClockSample {
    bool ok = false;
    uint8_t local = 0;
    uint64_t game_ms = 0;
    uint64_t wall_ms = 0;
};

ClockSample clock_now() {
    ClockSample c;
    uint64_t base = 0, frac = 0;
    c.wall_ms = GetTickCount64();
    c.ok = peek(g_base + kClockLocal, c.local) && peek(g_base + kClockBase, base) && peek(g_base + kClockFrac, frac);
    c.game_ms = base + frac / 1000;  // 0x1416BA0..0x1416BCE with the byte at 1
    return c;
}

std::string ledger_text() {
    std::string s;
    for (const auto& [vt, r] : g_ledger.rows()) {
        s += std::format(" | {}: {} episodes, {} frames with its scale ({} blocked), lowest {:g}", class_of(vt),
                         r.episodes, r.frames_seen, r.frames_blocked, r.min_scale);
    }
    return s.empty() ? std::string(" | no UI asked for a scale yet") : s;
}

// ---------------------------------------------------------------- P8 review I4: when the hook goes in

// The local player's controlled actor exists (the PlayerReader's chain, game/offsets.h,
// every hop's vtable checked): the world is up. Read only, VirtualQuery-checked reads.
bool player_in_world() {
    uintptr_t world = 0, mgr = 0, vt = 0, actor = 0, avt = 0;
    if (g_is_3663) {
        // Build 1.0.0.3663 (static, 2026-11-13; never run): world slot 0x72451C0 (profile_s2.h rva3663; 3195 RIP
        // references, 1039 of them followed by `mov rcx,[rcx+0x30]`), ClientActorManager vtable 0x59C2760 (RTTI).
        return peek(g_base + 0x72451C0, world) && world && peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr &&
               peek(mgr, vt) && vt == g_base + 0x59C2760 && peek(mgr + g2976::kActorManager_ControlledActor, actor) &&
               actor && peek(actor, avt) && avt;
    }
    if (g_is_3576) {
        // Build 1.0.0.3576 (static, 2026-11-06; not yet run): no reader profile yet. World slot 0x71C0100
        // (core_globals_3576.json; 0xC9DB6B reads it and then +0x30), ClientActorManager vtable 0x5946C40 (RTTI).
        return peek(g_base + 0x71C0100, world) && world && peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr &&
               peek(mgr, vt) && vt == g_base + 0x5946C40 && peek(mgr + g2976::kActorManager_ControlledActor, actor) &&
               actor && peek(actor, avt) && avt;
    }
    if (const auto* profile = game::reader_profile(); g_is_3527 && profile) {
        return peek(g_base + profile->world_system, world) && world &&
               peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
               vt == g_base + profile->vt_actor_manager && peek(mgr + g2976::kActorManager_ControlledActor, actor) && actor &&
               peek(actor, avt) && avt;
    }
    return peek(g_base + g2976::kWorldSystemSlot, world) && world &&
           peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
           vt == g_base + g2976::kVtClientActorManager &&
           peek(mgr + g2976::kActorManager_ControlledActor, actor) && actor && peek(actor, avt) &&
           avt == g_base + g2976::kVtControlledActor;
}

// The start-up diagnostic: is the game producing frames (its clock), and has any
// thread faulted on a page the mod patched (safetyhook's trap handler, patched copy)?
std::string startup_diag(const ClockSample& before, const ClockSample& now) {
    const game::HookTrapStats t = game::hook_trap_stats();
    std::string clock = "game clock unreadable";
    if (before.ok && now.ok) {
        clock = std::format("game clock (0x1416B80) {:+} ms in {} ms of wall time",
                            static_cast<int64_t>(now.game_ms - before.game_ms), now.wall_ms - before.wall_ms);
    }
    return std::format("{} | safetyhook trap handler: redirected {}, retried {} | passed on: execute {}, read/write {} | "
                       "patching now {} | game faults passed on {}",
                       clock, t.redirected, t.retried, t.passed_exec, t.passed_data, t.patching,
                       game::game_faults_passed());
}

// The hook goes in only once the local player has been in the world for 3 s:
// never during the game's start-up (the first start with force hung 2 min
// without frames; p8-revision-noche.md I4) nor on the title screen, where no menu
// of a P8 session can pause anything. Meanwhile one line a minute (or at once if
// a thread faulted on a patched page): whether the game clock moves.
void wait_for_world() {
    const uint64_t t0 = GetTickCount64();
    ClockSample last = clock_now();
    game::HookTrapStats last_traps = game::hook_trap_stats();
    uint64_t last_line = t0;
    log::info("UiPause: waiting for the local player in the world before hooking (never at start-up or on the "
              "title screen) | {}",
              startup_diag(last, last));
    for (int stable = 0; stable < 6;) {
        Sleep(500);
        stable = player_in_world() ? stable + 1 : 0;
        const uint64_t now = GetTickCount64();
        const game::HookTrapStats t = game::hook_trap_stats();
        const bool faults = t.passed_exec != last_traps.passed_exec || t.passed_data != last_traps.passed_data;
        if (faults || now - last_line >= 60000) {
            const ClockSample c = clock_now();
            const std::string line = std::format("UiPause start-up: still waiting for the world after {} s | {}",
                                                 (now - t0) / 1000, startup_diag(last, c));
            if (faults) {
                log::warn("{}", line);
            } else {
                log::info("{}", line);
            }
            last = c;
            last_traps = t;
            last_line = now;
        }
    }
    log::info("UiPause: the local player is in the world ({} s after the game's code was ready): installing the hook",
              (GetTickCount64() - t0) / 1000);
}

// After the install: 0x35CD990 is called every frame by the main loop. No call
// for kNoFramesMs while the hook is in: one WRN line (frames stopped, or the main
// thread is stuck; with the trap handler's numbers), and one line when they come back.
constexpr uint64_t kNoFramesMs = 10000;
struct FrameWatch {
    uint64_t last_calls = 0, last_change_ms = 0;
    bool warned = false;
    ClockSample clock_at_change;
};

void watch_frames(FrameWatch& w) {
    const uint64_t calls = c_calls[0].load(std::memory_order_relaxed) + c_calls[1].load(std::memory_order_relaxed) +
                           c_calls[2].load(std::memory_order_relaxed);
    const uint64_t now = GetTickCount64();
    if (calls != w.last_calls || !w.last_change_ms) {
        if (w.warned) {
            log::info("UiPause: frames again (0x35CD990 called) after {} s without", (now - w.last_change_ms) / 1000);
        }
        w.last_calls = calls;
        w.last_change_ms = now;
        w.warned = false;
        w.clock_at_change = clock_now();
        return;
    }
    if (!w.warned && now - w.last_change_ms >= kNoFramesMs) {
        w.warned = true;
        log::warn("UiPause: NO FRAMES for {} s (the main loop has not called exe+0x{:X} since; minimized, or the main "
                  "thread is stuck) | {} | if the game does not come back: a full dump before closing it "
                  "(procdump -ma)",
                  (now - w.last_change_ms) / 1000, kScale, startup_diag(w.clock_at_change, clock_now()));
    }
}

DWORD WINAPI ui_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto build = game::current_build();
    if (build == game::Build::unsupported ||
        !(game::legacy_layout() || build == game::Build::v3576 || build == game::Build::v3663)) {
        log::error("UiPause: unsupported game build; ui_pause_block stays off");
        return 0;
    }
    if (build == game::Build::v3663) {  // see kCall1Bytes3663
        g_is_3527 = true;
        g_is_3663 = true;
        kScale = 0x39191C0;
        kCall1 = 0xC160EC;
        kCall2 = 0xC16186;
        kRet1 = 0xC160F1;
        kRet2 = 0xC1618B;
        kClockLocal = 0x71600AD;
        kClockBase = 0x71600E8;
        kClockFrac = 0x71600F0;
    } else if (build == game::Build::v3576) {  // see kCall1Bytes3576
        g_is_3527 = true;
        g_is_3576 = true;
        kScale = 0x38A0830;
        kCall1 = 0xBDEC4C;
        kCall2 = 0xBDECE6;
        kRet1 = 0xBDEC51;
        kRet2 = 0xBDECEB;
        kClockLocal = 0x70DBF2D;
        kClockBase = 0x70DBF68;
        kClockFrac = 0x70DBF78;
    } else if (build == game::Build::v3527) {
        g_is_3527 = true;
        kScale = 0x389FB30;
        kCall1 = 0xBDE82C;
        kCall2 = 0xBDE8C6;
        kRet1 = 0xBDE831;
        kRet2 = 0xBDE8CB;
        kClockLocal = 0x70D9E3D;
        kClockBase = 0x70D9E60;
        kClockFrac = 0x70D9E70;
    }
    if (!read_sections()) {
        log::error("UiPause: the game's section table is unreadable; ui_pause_block stays off");
        return 0;
    }
    g_ret1 = g_base + kRet1;
    g_ret2 = g_base + kRet2;
    g_trivial = g_base + kTrivialVf;
    // The game's code first (up to 2 minutes, as the other P8 hooks).
    bool ready = false;
    for (int i = 0; i < 24000 && !(ready = code_ready()); ++i) Sleep(5);
    if (!ready) log::warn("UiPause: the game's code is not the expected one after 2 minutes; checking once more");
    wait_for_world();
    const Mode mode = static_cast<Mode>(g_mode.load());
    if (!install()) return 0;
    g_on.store(true);
    log::info("UiPause ON ({}, {}): inline hook at exe+0x{:X} (UI time scale; callers exe+0x{:X} / exe+0x{:X}), patch "
              "{} of the 30 verified bytes, inside .rsrc | {}",
              uip::mode_name(mode), g_guest ? "guest" : "host", kScale, kCall1, kCall2, g_patch,
              mode == Mode::Probe   ? "read only: transitions of the original value and the view behind them"
              : mode == Mode::Force ? "a UI pause/slowdown is ALWAYS replaced by 1.0"
                                    : (g_guest ? "a UI pause/slowdown is replaced by 1.0 while this guest plays on the host"
                                               : "a UI pause/slowdown is replaced by 1.0 while user 2 is logged in"));
    bool live = false;
    ClockSample last_clock = clock_now();
    bool clock_was_scaled = false;
    FrameWatch frames;
    for (uint64_t tick = 1;; ++tick) {
        Sleep(100);
        watch_frames(frames);
        const bool now_live = live_now();
        if (now_live != live) {
            live = now_live;
            g_live.store(live);
            const char* who = g_guest ? "this guest plays on the host" : "user 2 is logged in";
            if (mode == Mode::Session) {
                log::info("UiPause: P8 session {} ({}) -> menus {}", live ? "LIVE" : "over",
                          live ? who : "no other player", live ? "no longer pause the world" : "pause as in single player");
            } else {
                log::info("UiPause: P8 session {} ({}); mode {} does not depend on it", live ? "LIVE" : "over",
                          live ? who : "no other player", uip::mode_name(mode));
            }
        }
        if (tick % 10 == 0) drain();
        if (tick % 50 == 0) {
            // Is the game clock (the server's game-time wheel too, in the local mode) running?
            const ClockSample c = clock_now();
            const uint32_t bits = g_last_bits.load(std::memory_order_relaxed);
            const bool scaled = bits != kOneBits;
            if ((scaled || clock_was_scaled) && c.ok && last_clock.ok) {
                const uip::Decision d = uip::decide(mode, live, std::bit_cast<float>(bits));
                log::info("UiPause clock: game clock (0x1416B80) {:+} ms in {} ms of wall time | local clock byte {} | "
                          "UI value now {} ({})",
                          static_cast<int64_t>(c.game_ms - last_clock.game_ms), c.wall_ms - last_clock.wall_ms,
                          c.local, fmt_scale(bits),
                          d.blocked ? "blocked, the game gets 1.0"
                          : scaled  ? (d.would ? "NOT blocked" : "passed")
                                    : "back to 1");
            }
            clock_was_scaled = scaled;
            last_clock = c;
        }
        if (tick % 600 == 0) {
            drain();
            log::info("UiPause summary: {}{}", ui_pause_describe(),
                      g_lines_dropped ? std::format(" | event lines not written (budget) {}", g_lines_dropped)
                                      : std::string());
            log::info("UiPause per UI:{}", ledger_text());
        }
    }
}

}  // namespace

void ui_pause_start(const std::string& raw, bool guest) {
    const uip::ParsedMode p = uip::parse_mode(raw);
    if (!p.known) {
        log::warn("UiPause: ui_pause_block='{}' is not 0, probe, 1 or force; it stays off", raw);
        return;
    }
    if (p.mode == Mode::Off) return;
    if (g_started.exchange(true)) return;
    g_mode.store(static_cast<uint8_t>(p.mode));
    g_guest = guest;
    CloseHandle(CreateThread(nullptr, 0, ui_thread, nullptr, 0, nullptr));
}

bool ui_pause_active() { return g_on.load(); }

std::string ui_pause_describe() {
    if (!g_started.load()) return {};
    const auto mode = static_cast<Mode>(g_mode.load());
    const uint32_t bits = g_last_bits.load(std::memory_order_relaxed);
    return std::format(
        "ui_pause_block {} ({}, hook {}) | session {} | frames {} (UI scale in force {}, blocked {}) | dt calls {} "
        "(blocked {}) | other callers {} | transitions {}, source changes {}, walks {} (incomplete {}), events lost "
        "{} | UI value now {} | current episode {} frames ({} blocked)",
        uip::mode_name(mode), g_guest ? "guest" : "host", g_on.load() ? "on" : "OFF", g_live.load() ? "LIVE" : "not live",
        c_calls[1].load(), c_would[1].load(), c_blocked[1].load(), c_calls[2].load(), c_blocked[2].load(),
        c_calls[0].load(), c_transitions.load(), c_sources.load(), c_walks.load(), c_walk_bad.load(), g_ring.dropped(),
        std::format("{:g}", std::bit_cast<float>(bits)), g_ep.seen.load(), g_ep.blocked.load());
}

}  // namespace cdmp::session2
