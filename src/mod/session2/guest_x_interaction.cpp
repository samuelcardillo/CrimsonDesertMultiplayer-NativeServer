#include "mod/session2/guest_x_interaction.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <format>
#include <span>
#include <string>
#include <vector>

#include <safetyhook.hpp>

#include "mod/game/build_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_seq_route.h"
#include "mod/session2/guest_shop_branch.h"
#include "mod/session2/guest_x_interaction_logic.h"
#include "mod/session2/guest_x_veto_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/stage_lookup_logic.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;
namespace off = game::build_2976;
using gxi::Act;
using gxi::Mode;
using gxi::Verdict;

// X's character and its manager now (the same chain guest_seq_route / guest_seq_play read): [X+0x18] = the actor,
// +0x60 its key, [[[actor+0x68]+0xA8]+0x18] its ClientSequencerStageManager.
constexpr uint32_t kMgr_Actor = 0x18, kActor_Key = 0x60, kActor_Comps = 0x68, kComps_Seq = 0xA8, kSeqComp_Mgr = 0x18;
// The instance's name, best effort ([[inst+0x48]+0x1B8], the chain guest_x_veto reads from a processor's stage) and
// its +0x30 (the stage's sequencer key there): logged to cross-check with GuestXVeto's SetInteraction lines.
constexpr uint32_t kInst_Data = 0x48, kData_Name = 0x1B8, kInst_Key = 0x30;
constexpr size_t kMaxX = 4;

// Where the three points are, per build (stage_lookup_logic.h). Chosen once in install_thread, before any hook.
struct Points {
    uintptr_t a, r, f, ctx_a, ctx_lookup;
    uint32_t patch_a, patch_r, patch_f;
    std::span<const uint8_t> bytes_a, bytes_r, bytes_f, ctx_a_bytes, ctx_lookup_bytes;
    uint32_t rbp_mgr_used;
    uintptr_t vt_field, vt_mgr;
    isl::MgrLayout layout;
    const char* names;  // the log's names of the points
};
const Points kPoints2976{isl::kPointA, isl::kPointR, isl::kPointF, isl::kCtxA, isl::kCtxLookup, isl::kPatchA,
                         isl::kPatchR, isl::kPatchF, isl::kBytesA, isl::kBytesR, isl::kBytesF, isl::kCtxABytes,
                         isl::kCtxLookupBytes, isl::kRbpMgrUsed, isl::kVtClientField, isl::kVtClientStageMgr,
                         isl::kLayout2976, "A 0x2126A1F, R 0x2126AAB, F 0x2126D11 (build 2976)"};
const Points kPoints3527{isl::kPointA3527, isl::kPointR3527, isl::kPointF3527, isl::kCtxA3527, isl::kCtxLookup3527,
                         isl::kPatchA3527, isl::kPatchR3527, isl::kPatchF3527, isl::kBytesA3527, isl::kBytesR3527,
                         isl::kBytesF3527, isl::kCtxABytes3527, isl::kCtxLookupBytes3527, isl::kRbpMgrUsed3527,
                         isl::kVtClientField3527, isl::kVtClientStageMgr3527, isl::kLayout3527,
                         "A 0x22ED729, R 0x22ED7B5, F 0x22EDA49 (builds 3527 / 3549)"};
const Points kPoints3576{isl::kPointA3576, isl::kPointR3576, isl::kPointF3576, isl::kCtxA3576, isl::kCtxLookup3576,
                         isl::kPatchA3527, isl::kPatchR3527, isl::kPatchF3527, isl::kBytesA3527, isl::kBytesR3527,
                         isl::kBytesF3527, isl::kCtxABytes3527, isl::kCtxLookupBytes3576, isl::kRbpMgrUsed3527,
                         isl::kVtClientField3576, isl::kVtClientStageMgr3576, isl::kLayout3527,
                         "A 0x22EE3D9, R 0x22EE465, F 0x22EE6F9 (build 3576)"};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the same function at 0x235EB60 (.pdata 0x235EB60-0x235EFC6,
// 0x466 B; rcx = the entry (r13), [rcx+0x20] & 0x1FFFFFFF tested first, rdx = J (r15), no push in the body):
// - A 0x235EC69 (+0x109 as in 3527): kBytesA3527, unique in the code section; ctx A 0x235EC5E: kCtxABytes3527 (the
//   field [rsp+0x48], call [rax+0x48]); then vf40, the lock of [rdi+8] (0x3E5370 at 0x235ECA0), the lookup and the
//   dead check 0x21C8FD0 with rcx = [rbp+0x8F8] (0x235ED1A): RAX := X still reaches all three;
// - ctx lookup 0x235ECA6: mov r8,[r13+0x20] ; lea rdx,[rbp+0x8E0] ; mov rcx,rdi ; call 0x21C5750 (the out slot is
//   now +0x8E0, its own array below);
// - R 0x235ECF5 lea rcx,[rbp+0x8E0] (7 B): where both paths after the lookup join (je targets 0x235ECCA, 0x235ECEF),
//   rsi = the instance taken from the lookup's handle or 0, [rbp+0x8F8] the manager used;
// - F 0x235EF99 (+0x439): kBytesF3527 (mov [rsp+0x70],rdi ; lea rcx,[rsp+0x70]), every path but the two early
//   returns reaches it with BL = the result (0x235EEF3 / 0x235EEF7 / 0x235EF0A, and 0x235EBCA), movzx eax,bl after;
// - the lookup 0x21C5750 walks the manager at +0x13C count, +0x138 buckets, +0x148 bucket array, +0x150 elements
//   (every offset +8 from 3527's), the same 0x100-B buckets of {hash, index} pairs from +8, element +8 the id, +0x10
//   the instance, instance +0x15 dead; the hash 0x15864E0 is the same lookup3 (lea ebx,[rdx-0x2145E233]);
// - the vtables by RTTI name (vtable_map_3576_3663.json): pa::ClientField 0x59C97C0, pa::ClientSequencerStageManager
//   0x59D57E8 (42 slots, 3576 41; only its address is compared).
// X's chain (kMgr_Actor, kComps_Seq, kSeqComp_Mgr) is 3576's, not re-derived (36 sites in 3663 read
// [[[r+0x68]+0xA8]+0x18]; the manager's vtable has no reference in normal code to confirm it from).
constexpr isl::MgrLayout kLayout3663{0x138, 0x13C, 0x148, 0x150};
constexpr uint8_t kBytesR3663[] = {0x48, 0x8D, 0x8D, 0xE0, 0x08, 0x00, 0x00};
constexpr uint8_t kCtxLookupBytes3663[] = {0x4D, 0x8B, 0x45, 0x20, 0x48, 0x8D, 0x95, 0xE0, 0x08, 0x00, 0x00,
                                           0x48, 0x8B, 0xCF, 0xE8, 0x97, 0x6A, 0xE6, 0xFF};
const Points kPoints3663{0x235EC69, 0x235ECF5, 0x235EF99, 0x235EC5E, 0x235ECA6,
                         isl::kPatchA3527, isl::kPatchR3527, isl::kPatchF3527, isl::kBytesA3527, kBytesR3663,
                         isl::kBytesF3527, isl::kCtxABytes3527, kCtxLookupBytes3663, isl::kRbpMgrUsed3527,
                         0x59C97C0, 0x59D57E8, kLayout3663, "A 0x235EC69, R 0x235ECF5, F 0x235EF99 (build 3663)"};
const Points* g_pts = &kPoints2976;

uintptr_t g_base = 0;
std::atomic<bool> g_started{false}, g_a_on{false}, g_r_on{false}, g_f_on{false};
std::atomic<uint8_t> g_mode{0};
SafetyHookMid g_a_hook, g_r_hook, g_f_hook;
gxi::XSlots<kMaxX> g_x;
thread_local gxi::Call t_call;
// P8 re-entry (s25/reentrada.md §1.4): the X managers noted belong to one remote conversation. XSlots is atomic: the
// first of its users (the prompt hook or guest_x_veto's note) that sees a new conversation clears it.
std::atomic<uint32_t> g_x_conv{0};
void x_conversation_check() noexcept {
    const uint32_t conv = guest_conversation_id();
    if (conv == g_x_conv.load(std::memory_order_relaxed) || g_x_conv.exchange(conv) == conv) return;
    if (conv >= 2) g_x.clear();
}

std::atomic<uint64_t> g_calls{0}, g_verdicts[static_cast<size_t>(Verdict::Count)] = {};
std::atomic<uint64_t> g_redirected{0}, g_would{0}, g_followed{0}, g_r_seen{0}, g_f_seen{0};
// Results at F of the calls A followed: [act class][bl 0, 1, 2, other]. Classes: 0 redirected, 1 would redirect
// (probe: the native lookup in M), 2 an entry of nobody known (in neither / dead in X / no X).
std::atomic<uint64_t> g_results[3][4] = {};
// At R: the native lookup found an instance ([0] redirected, [1] would, [2] other).
std::atomic<uint64_t> g_r_found[3] = {}, g_r_missing[3] = {};
std::atomic<uint64_t> g_x_states[static_cast<size_t>(gxi::XState::Count)] = {};

enum Kind : uint16_t { kEA, kEF, kKindCount };
p::EventRing<256> g_ring;
p::WindowLimiter g_lim[kKindCount] = {{24, 5'000'000}, {24, 5'000'000}};
isl::IdBook<128> g_book;
std::atomic<uint64_t> g_limited{0}, g_lost{0}, g_lines{0};
constexpr uint64_t kMaxLines = 1500;
constexpr uint32_t kPerIdVerdict = 3;

// ---------------------------------------------------------------- hot path (no CRT, no allocation)

template <class T>
bool rd(uintptr_t a, T& v) noexcept {
    if (a < 0x10000) return false;
    __try {
        v = *reinterpret_cast<const volatile T*>(a);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
template <class T>
T rdv(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return rd(a, v) ? v : fallback;
}
uintptr_t rdp(uintptr_t a) noexcept { return rdv<uintptr_t>(a); }

struct SehReader {
    template <class T>
    bool rd(uintptr_t a, T& v) const noexcept {
        return ::cdmp::session2::rd(a, v);
    }
};

uint32_t key_of_mgr(uintptr_t mgr) noexcept {
    const uintptr_t actor = mgr ? rdp(mgr + kMgr_Actor) : 0;
    return actor ? rdv<uint32_t>(actor + kActor_Key) : 0;
}

gxi::XCheck read_x(uintptr_t x) noexcept {
    gxi::XCheck c;
    c.x = x;
    c.want_vt = g_base + g_pts->vt_mgr;
    c.vt = rdp(x);
    if (c.vt != c.want_vt) return c;
    const uintptr_t actor = rdp(x + kMgr_Actor);
    c.key = actor ? rdv<uint32_t>(actor + kActor_Key) : 0;
    const uintptr_t comps = actor ? rdp(actor + kActor_Comps) : 0;
    const uintptr_t seq = comps ? rdp(comps + kComps_Seq) : 0;
    c.actor_mgr = seq ? rdp(seq + kSeqComp_Mgr) : 0;
    return c;
}

void emit(Kind k, p::Event& e) noexcept {
    e.kind = k;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    if (!g_lim[k].take(e.qpc_us)) {
        g_limited.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!g_ring.push(e)) g_lost.fetch_add(1, std::memory_order_relaxed);
}

// The book's key: the stage id with the line kind and the verdict / result in the top byte.
uint64_t book_key(uint64_t id, uint8_t tag) noexcept { return (id & 0x00FFFFFFFFFFFFFFull) | static_cast<uint64_t>(tag) << 56; }

size_t act_class(Act a, Verdict v) noexcept {
    if (a == Act::Redirect) return 0;
    if (a == Act::Would) return 1;
    (void)v;
    return 2;
}

// guest_shop_branch=3: an entry carries the shop interaction 0x000F4321 in its first 0x40 bytes.
constexpr uint32_t kShopKey = 0x000F4321;
constexpr uint64_t kCopyTag = 0x1F000000ull;
std::atomic<uint64_t> g_to_copy{0}, g_back_to_host{0}, g_shop_seen{0};
bool entry_has_shop_key(uintptr_t entry) noexcept {
    uint32_t w[16] = {};
    if (!game::safe_read(entry, w, sizeof w)) return false;
    for (const uint32_t v : w) {
        if (v == kShopKey) return true;
    }
    return false;
}
bool wr_u64(uintptr_t a, uint64_t v) noexcept {
    if (a < 0x10000) return false;
    __try {
        *reinterpret_cast<volatile uint64_t*>(a) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
// Point A, before the lookup reads [entry+0x20] (0x22ED766 on 3549): the entry names this client's running copy of a
// shopkeeper's host scene instead of the host scene (then the native lookup finds it in M), or the host scene again
// once the copy is gone; and a copy is asked for a shopkeeper's scene this client looks at.
uint64_t shop_copy_at_a(uintptr_t entry, uint64_t id, uintptr_t m) noexcept {
    if ((id & 0xFF000000ull) == kCopyTag) {
        if (guest_shop_copy_alive(id)) return id;
        const uint64_t host = guest_shop_host_of(id);
        if (host && wr_u64(entry + isl::kEntry_StageId, host)) {
            if (g_back_to_host.fetch_add(1, std::memory_order_relaxed) < 10) {
                log::info("GuestXInter: entry 0x{:X}: its copy 0x{:X} is gone, the host scene 0x{:X} again", entry, id, host);
            }
            return host;
        }
        return id;
    }
    const uint64_t copy = guest_shop_ready_copy(id);
    if (copy && m && isl::find_stage(SehReader{}, m, copy, g_pts->layout).found) {
        if (wr_u64(entry + isl::kEntry_StageId, copy)) {
            if (g_to_copy.fetch_add(1, std::memory_order_relaxed) < 20) {
                log::info("GuestXInter: entry 0x{:X}: host scene 0x{:X} -> this client's copy 0x{:X} (looked up in M "
                          "natively)",
                          entry, id, copy);
            }
            return copy;
        }
        return id;
    }
    if (entry_has_shop_key(entry)) {
        if (g_shop_seen.fetch_add(1, std::memory_order_relaxed) < 5) {
            log::info("GuestXInter: entry 0x{:X} of host scene 0x{:X} carries the shop key 0x{:08X}", entry, id, kShopKey);
        }
        guest_shop_want_copy(id, "this client looks at a shopkeeper");
    }
    return id;
}

// A 0x2126A1F: RAX = the field's vf48 (M). See guest_x_interaction.h.
void on_a(safetyhook::Context& ctx) noexcept {
    if (!g_a_on.load(std::memory_order_acquire)) return;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    gxi::Facts f;
    const uintptr_t field = rdp(ctx.rsp + isl::kRspField);
    f.client_field = field && rdp(field) == g_base + g_pts->vt_field;
    if (f.client_field) f.remote = guest_remote_live();
    f.m = ctx.rax;
    f.id = f.client_field && f.remote ? rdv<uint64_t>(ctx.r13 + isl::kEntry_StageId) : 0;
    if (f.m && (f.id & 0x1FFFFFFFull) && guest_shop_proactive()) f.id = shop_copy_at_a(ctx.r13, f.id, f.m);
    uintptr_t x_inst = 0;
    uint32_t m_key = 0, x_key = 0;
    if (f.client_field && f.remote && f.m && (f.id & 0x1FFFFFFFull)) {
        const SehReader r;
        const isl::Lookup lm = isl::find_stage(r, f.m, f.id, g_pts->layout);
        f.m_read = lm.read_ok;
        f.in_m = lm.found;
        if (f.m_read && !f.in_m) {
            uintptr_t xs[kMaxX] = {};
            uint32_t keys[kMaxX] = {};
            x_conversation_check();
            f.x_known = g_x.snapshot(xs, keys, kMaxX);
            m_key = key_of_mgr(f.m);
            const uint32_t own = guest_seq_route_own_key();
            for (size_t i = 0; i < f.x_known; ++i) {
                const gxi::XCheck c = read_x(xs[i]);
                const gxi::XState s = gxi::check_x(c, f.m, m_key, own);
                g_x_states[static_cast<size_t>(s)].fetch_add(1, std::memory_order_relaxed);
                if (s != gxi::XState::Ok) continue;
                ++f.x_valid;
                const isl::Lookup lx = isl::find_stage(r, c.x, f.id, g_pts->layout);
                if (lx.read_ok) f.x_read = true;
                if (lx.found) {
                    f.x = c.x;
                    x_inst = lx.inst;
                    x_key = c.key;
                    break;
                }
                if (lx.dead) f.x_dead = true;
            }
        }
    }
    const Verdict v = gxi::decide(f);
    g_verdicts[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    if (v == Verdict::NotClient || v == Verdict::NotRemote || v == Verdict::InM || v == Verdict::NoM ||
        v == Verdict::NoId) {
        return;
    }
    const Act a = gxi::act(static_cast<Mode>(g_mode.load(std::memory_order_relaxed)), v);
    if (a == Act::Redirect) {
        ctx.rax = f.x;  // mov rdi,rax ; mov [rbp+0x8E8],rax run next (relocated): the lookup and its lock use X
        g_redirected.fetch_add(1, std::memory_order_relaxed);
    } else if (a == Act::Would) {
        g_would.fetch_add(1, std::memory_order_relaxed);
    }
    // Follow the call to R and F (same thread, same entry and rsp).
    t_call.entry = ctx.r13;
    t_call.rsp = ctx.rsp;
    t_call.id = f.id;
    t_call.m = f.m;
    t_call.x = f.x;
    t_call.verdict = static_cast<uint8_t>(v);
    t_call.act = static_cast<uint8_t>(a);
    g_followed.fetch_add(1, std::memory_order_relaxed);
    if (!gxi::worth_a_line(v) || !g_book.take(book_key(f.id, static_cast<uint8_t>(0x10 | static_cast<uint8_t>(v))),
                                              kPerIdVerdict)) {
        return;
    }
    p::Event e;
    e.v[0] = static_cast<uint64_t>(v) | static_cast<uint64_t>(a) << 8;
    e.v[1] = ctx.r13;
    e.v[2] = f.id;
    e.v[3] = f.m;
    e.v[4] = f.x;
    e.v[5] = x_inst;
    e.v[6] = m_key | static_cast<uint64_t>(x_key) << 32;
    e.v[7] = f.x_known | static_cast<uint64_t>(f.x_valid) << 16 | static_cast<uint64_t>(f.m_read) << 32 |
             static_cast<uint64_t>(f.x_read) << 33 | static_cast<uint64_t>(f.x_dead) << 34;
    if (x_inst) {
        e.v[8] = rdv<uint64_t>(x_inst + kInst_Key);
        const uintptr_t data = rdp(x_inst + kInst_Data);
        const uintptr_t name = data ? rdp(data + kData_Name) : 0;
        for (size_t k = 0; name && k < 3 && rd(name + 8 * k, e.v[9 + k]); ++k) {
        }
    }
    emit(kEA, e);
}

// R 0x2126AAB: after the native lookup. RSI = the instance found (or 0), [rbp+0x8E8] = the manager it used.
thread_local uintptr_t t_r_found = 0, t_r_used = 0;  // per call, meaningful while t_call is set
thread_local bool t_r_set = false;

void on_r(safetyhook::Context& ctx) noexcept {
    if (!g_r_on.load(std::memory_order_acquire)) return;
    if (!t_call.same(ctx.r13, ctx.rsp)) return;
    g_r_seen.fetch_add(1, std::memory_order_relaxed);
    t_r_found = ctx.rsi;
    t_r_used = rdp(ctx.rbp + g_pts->rbp_mgr_used);
    t_r_set = true;
    const size_t c = act_class(static_cast<Act>(t_call.act), static_cast<Verdict>(t_call.verdict));
    (ctx.rsi ? g_r_found[c] : g_r_missing[c]).fetch_add(1, std::memory_order_relaxed);
}

// F 0x2126D11: BL = the function's result for the call A followed.
void on_f(safetyhook::Context& ctx) noexcept {
    if (!g_f_on.load(std::memory_order_acquire)) return;
    if (!t_call.same(ctx.r13, ctx.rsp)) return;
    g_f_seen.fetch_add(1, std::memory_order_relaxed);
    const uint8_t bl = static_cast<uint8_t>(ctx.rbx & 0xFF);
    const auto a = static_cast<Act>(t_call.act);
    const auto v = static_cast<Verdict>(t_call.verdict);
    const size_t c = act_class(a, v);
    g_results[c][bl <= 2 ? bl : 3].fetch_add(1, std::memory_order_relaxed);
    const gxi::Call call = t_call;
    const uintptr_t found = t_r_set ? t_r_found : ~0ull, used = t_r_set ? t_r_used : 0;
    t_call = gxi::Call{};
    t_r_set = false;
    const auto tag = static_cast<uint8_t>(0x40u | static_cast<unsigned>(c) << 2 | (bl <= 2 ? bl : 3u));
    if (!g_book.take(book_key(call.id, tag), kPerIdVerdict)) {
        return;
    }
    p::Event e;
    e.v[0] = static_cast<uint64_t>(a) | static_cast<uint64_t>(bl) << 8 | static_cast<uint64_t>(v) << 16;
    e.v[1] = call.entry;
    e.v[2] = call.id;
    e.v[3] = used;
    e.v[4] = found;
    e.v[5] = call.m;
    e.v[6] = call.x;
    emit(kEF, e);
}

// ---------------------------------------------------------------- lines (diagnostics thread)

std::string line_of(const p::Event& e) {
    const uint64_t* v = e.v;
    const std::string when = p8_when(e.qpc_us);
    switch (e.kind) {
        case kEA: {
            const auto verdict = static_cast<Verdict>(v[0] & 0xFF);
            const auto a = static_cast<Act>((v[0] >> 8) & 0xFF);
            char name[32];
            gxv::stage_name(v + 9, 3, name, sizeof name);
            const char* what = a == Act::Redirect ? "REDIRECTED (RAX := X: the lookup at 0x2126A6A uses X)"
                               : a == Act::Would  ? "WOULD REDIRECT (probe: the native lookup in M refuses it)"
                                                  : "left native";
            return std::format(
                "GuestXInter [entry] {} T{} | stage id 0x{:X} of entry 0x{:X}: {} | M 0x{:X} (character 0x{:08X}; "
                "read {}) | X 0x{:X} (character 0x{:08X}) instance 0x{:X} (its +0x30 0x{:X}, name '{}') | X known {} "
                "valid {} (read {}{}) | {}",
                when, e.tid, v[2], v[1], gxi::verdict_name(verdict), v[3], static_cast<uint32_t>(v[6]),
                (v[7] >> 32) & 1 ? "ok" : "FAILED", v[4], static_cast<uint32_t>(v[6] >> 32), v[5], v[8], name,
                v[7] & 0xFFFF, (v[7] >> 16) & 0xFFFF, (v[7] >> 33) & 1 ? "ok" : "no", (v[7] >> 34) & 1 ? ", dead there" : "",
                what);
        }
        case kEF: {
            const auto a = static_cast<Act>(v[0] & 0xFF);
            const auto bl = static_cast<uint8_t>((v[0] >> 8) & 0xFF);
            const auto verdict = static_cast<Verdict>((v[0] >> 16) & 0xFF);
            const bool r_seen = v[4] != ~0ull;
            return std::format(
                "GuestXInter [result] {} T{} | stage id 0x{:X} of entry 0x{:X} ({}; {}): the lookup used manager 0x{:X} "
                "({}) and {} | 0x2126920 returned {}",
                when, e.tid, v[2], v[1], gxi::verdict_name(verdict),
                a == Act::Redirect ? "REDIRECTED" : a == Act::Would ? "would redirect" : "native",
                v[3], v[3] == v[6] && v[6] ? "X" : v[3] == v[5] ? "M" : "?",
                !r_seen ? "R did not run" : v[4] ? std::format("found instance 0x{:X}", v[4]) : std::string("found nothing"),
                gxi::result_name(bl));
        }
        default:
            return std::format("GuestXInter: event {}?", e.kind);
    }
}

uint64_t g_tick_n = 0;  // diagnostics thread only

std::string results_of(size_t c) {
    return std::format("0:{} 1:{} 2:{} other:{} (native lookup found {} / nothing {})", g_results[c][0].load(),
                       g_results[c][1].load(), g_results[c][2].load(), g_results[c][3].load(), g_r_found[c].load(),
                       g_r_missing[c].load());
}

void summary() {
    std::string verdicts;
    for (size_t k = 0; k < static_cast<size_t>(Verdict::Count); ++k) {
        if (const uint64_t n = g_verdicts[k].load()) {
            verdicts += std::format(" {} {};", gxi::verdict_name(static_cast<Verdict>(k)), n);
        }
    }
    std::string xs;
    uintptr_t x[kMaxX] = {};
    uint32_t keys[kMaxX] = {};
    const size_t n = g_x.snapshot(x, keys, kMaxX);
    for (size_t i = 0; i < n; ++i) xs += std::format(" 0x{:X} (0x{:08X})", x[i], keys[i]);
    std::string states;
    for (size_t k = 0; k < static_cast<size_t>(gxi::XState::Count); ++k) {
        if (const uint64_t c = g_x_states[k].load()) {
            states += std::format(" {} {};", gxi::xstate_name(static_cast<gxi::XState>(k)), c);
        }
    }
    log::info("GuestXInter summary (guest_x_interaction_stage={}): hooks A {} R {} F {} | calls at A {} | verdicts:{} | "
              "REDIRECTED {}, would {} | results of the redirected: {} | of the would-redirect: {} | of the other "
              "entries of nobody known: {} | followed {} (R seen {}, F seen {}) | X known:{} (notes {}, replaced {}; "
              "checks:{}) | ids in the book {} (full {}) | limited {} lost {}",
              gxi::mode_name(static_cast<Mode>(g_mode.load())), g_a_on.load() ? "in" : "NOT in",
              g_r_on.load() ? "in" : "NOT in", g_f_on.load() ? "in" : "NOT in", g_calls.load(),
              verdicts.empty() ? " none" : verdicts, g_redirected.load(), g_would.load(), results_of(0), results_of(1),
              results_of(2), g_followed.load(), g_r_seen.load(), g_f_seen.load(), xs.empty() ? " none" : xs,
              g_x.notes(), g_x.replaced(), states.empty() ? " none" : states, g_book.used(), g_book.full(),
              g_limited.load(), g_lost.load());
}

// ---------------------------------------------------------------- install

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

bool context_ok(std::span<const gad::Section> secs, uintptr_t rva, std::span<const uint8_t> bytes, const char* what) {
    if (gad::in_real_code(secs, static_cast<uint32_t>(rva), static_cast<uint32_t>(bytes.size())) && bytes_at(rva, bytes)) {
        return true;
    }
    log::error("GuestXInter: {} (exe+0x{:X}, {} bytes) is not this build's expected code; REFUSED", what, rva,
               bytes.size());
    return false;
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<gad::Section> secs;
    const game::Build build = game::current_build();
    if (build == game::Build::v3527) g_pts = &kPoints3527;
    if (build == game::Build::v3576) g_pts = &kPoints3576;
    if (build == game::Build::v3663) g_pts = &kPoints3663;
    if (g_base != off::kImageBase ||
        !(game::legacy_layout() || build == game::Build::v3576 || build == game::Build::v3663) ||
        !game::safe_read(g_base, &dos, sizeof dos) ||
        !game::safe_read(g_base + dos.e_lfanew, &nt, sizeof nt) || !p8_exe_sections(g_base, secs)) {
        log::error("GuestXInter: unsupported game build or unreadable sections; nothing installed");
        return 0;
    }
    const game::ReaderProfile* profile = game::reader_profile();
    // 3576: 0x71C0100 (core_globals_3576.json; no reader profile for 3576 yet). 3663: 0x72451C0 (two AOB patterns,
    // docs/research/port-3663.md).
    const uintptr_t world_slot = build == game::Build::v3576                ? uintptr_t{0x71C0100}
                                 : build == game::Build::v3663              ? uintptr_t{0x72451C0}
                                 : build == game::Build::v3527 && profile ? profile->world_system
                                                                          : off::kWorldSystemSlot;
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other guest modules
        uintptr_t world = 0;
        if (game::safe_read(g_base + world_slot, &world, sizeof world) && world) break;
        Sleep(500);
    }
    const Points& pt = *g_pts;
    // A (the decision) first. R and F only read (the lookup's result and the function's), so they go in only with
    // probe: on 3549 the memory safetyhook needs within 2 GB of the exe is scarce on the guest (live 2026-11-06: with
    // all three hooked early, RemoteInterp's hooks found none at world entry). Without R / F the record A leaves is
    // simply overwritten by the next call.
    if (context_ok(secs, pt.ctx_lookup, pt.ctx_lookup_bytes, "the lookup call") &&
        context_ok(secs, pt.ctx_a, pt.ctx_a_bytes, "the vf48 call")) {
        if (p8_install_mid(g_base, secs, pt.a, pt.patch_a, pt.bytes_a, on_a, g_a_hook, "GuestXInter",
                           "A, the manager of the lookup")) {
            g_a_on.store(true, std::memory_order_release);
        }
        if (static_cast<Mode>(g_mode.load()) == Mode::Probe) {
            if (p8_install_mid(g_base, secs, pt.r, pt.patch_r, pt.bytes_r, on_r, g_r_hook, "GuestXInter",
                               "R, after the lookup")) {
                g_r_on.store(true, std::memory_order_release);
            }
            if (p8_install_mid(g_base, secs, pt.f, pt.patch_f, pt.bytes_f, on_f, g_f_hook, "GuestXInter",
                               "F, the result")) {
                g_f_on.store(true, std::memory_order_release);
            }
        }
    }
    log::info("GuestXInter (guest_x_interaction_stage={}): {}: A {}, R {}, F {} | an entry "
              "whose stage id is not a live stage of M but is one of a known X (another character's "
              "ClientSequencerStageManager, vtable exe+0x{:X}): {}",
              gxi::mode_name(static_cast<Mode>(g_mode.load())), pt.names, g_a_on.load() ? "hooked" : "REFUSED",
              g_r_on.load() ? "hooked" : "REFUSED", g_f_on.load() ? "hooked" : "REFUSED", pt.vt_mgr,
              static_cast<Mode>(g_mode.load()) == Mode::On ? "RAX := X (the prompt check looks it up in X)"
                                                           : "decided and counted only (probe)");
    return 0;
}

}  // namespace

void guest_x_interaction_start(const std::string& mode, const std::string& route_mode) {
    bool bad = false;
    Mode m = gxi::parse_mode(mode, &bad);
    if (bad) log::warn("GuestXInter: guest_x_interaction_stage={} is not 0, probe or 1: off", mode);
    if (m != Mode::Off && gxv::parse_mode(route_mode) != gxv::Mode::On) {
        log::info("GuestXInter: guest_x_interaction_stage={} not installed: guest_seq_route is not 1, so no other "
                  "character's manager X exists on this client",
                  mode);
        m = Mode::Off;
    }
    g_mode.store(static_cast<uint8_t>(m));
    if (m == Mode::Off) return;
    if (g_started.exchange(true)) return;
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

void guest_x_interaction_tick() noexcept {
    if (!g_started.load()) return;
    try {
        ++g_tick_n;
        p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind >= kKindCount) continue;
            const bool loud = e.kind == kEA && static_cast<Act>((e.v[0] >> 8) & 0xFF) == Act::Redirect;
            if (loud) {
                log::warn("{}", line_of(e));  // every redirect (rate-limited at the source), outside the line budget
            } else if (g_lines.fetch_add(1) < kMaxLines) {
                log::info("{}", line_of(e));
            }
        }
        if (g_tick_n % 12 == 0) summary();
    } catch (...) {
    }
}

void guest_x_interaction_note_x(uintptr_t x, uint32_t key) noexcept {
    if (!x || !g_started.load(std::memory_order_relaxed)) return;
    x_conversation_check();
    g_x.note(x, key);
}

size_t guest_x_interaction_known_x(uintptr_t* xs, size_t cap) noexcept {
    if (!xs || !cap || !g_started.load(std::memory_order_relaxed)) return 0;
    x_conversation_check();
    uint32_t keys[kMaxX];
    return g_x.snapshot(xs, keys, cap < kMaxX ? cap : kMaxX);
}

}  // namespace cdmp::session2
