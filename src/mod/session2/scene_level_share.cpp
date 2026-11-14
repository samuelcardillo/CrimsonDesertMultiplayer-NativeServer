#include "mod/session2/scene_level_share.h"
#include "common/native_opcode.h"
#include "mod/game/build_profile.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/field_share.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/scene_level_share_logic.h"
#include "mod/session2/server.h"
#include "mod/session2/user2_funnels.h"
#include "mod/session2/user2_stages.h"

#pragma intrinsic(_ReturnAddress, _AddressOfReturnAddress)

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using sls::Mode;
using sls::User;

// Where everything is, per build (scene_level_share_logic.h). Every struct offset is the same in both.
struct Addrs {
    uint32_t pe_timestamp, vt_server_field;
    uint32_t gate_fn_begin, gate_fn_end, gate_rva, gate_sig_rva;
    std::span<const uint8_t> gate_sig;
    uint32_t delete_rva, delete_end, ret_2834, ret_owner_load, ret_loader;
    uint32_t frame_site_rva;
    std::span<const uint8_t> frame_site;
    uint32_t call_site_rva;
    std::span<const uint8_t> call_site;
    uintptr_t frame_name, frame_type, frame_hash;
};
const Addrs kAddrs2976{sls::kPeTimestamp, sls::kVtServerField, sls::kGateFnBegin, sls::kGateFnEnd, sls::kGateRva,
                       sls::kGateSigRva, sls::kGateSig, sls::kDeleteRva, sls::kDeleteEnd, sls::kRet2834,
                       sls::kRetOwnerLoad, sls::kRetLoader, sls::kFrameSiteRva, sls::kFrameSite, sls::kCallSiteRva,
                       sls::kCallSite, sls::kFrameName, sls::kFrameType, sls::kFrameHash};
const Addrs kAddrs3527{sls::kPeTimestamp3527, sls::kVtServerField3527, sls::kGateFnBegin3527, sls::kGateFnEnd3527,
                       sls::kGateRva3527, sls::kGateSigRva3527, sls::kGateSig3527, sls::kDeleteRva3527,
                       sls::kDeleteEnd3527, sls::kRet28343527, sls::kRetOwnerLoad3527, sls::kRetLoader3527,
                       sls::kFrameSiteRva3527, sls::kFrameSite3527, sls::kCallSiteRva3527, sls::kCallSite3527,
                       sls::kFrameName3527, sls::kFrameType3527, sls::kFrameHash3527};
// 3576: the 3527 signature, delete head and frame site bytes at their new addresses (scene_level_share_logic.h).
const Addrs kAddrs3576{sls::kPeTimestamp3576, sls::kVtServerField3576, sls::kGateFnBegin3576, sls::kGateFnEnd3576,
                       sls::kGateRva3576, sls::kGateSigRva3576, sls::kGateSig3527, sls::kDeleteRva3576,
                       sls::kDeleteEnd3576, sls::kRet28343576, sls::kRetOwnerLoad3576, sls::kRetLoader3576,
                       sls::kFrameSiteRva3576, sls::kFrameSite3527, sls::kCallSiteRva3576, sls::kCallSite3576,
                       sls::kFrameName3527, sls::kFrameType3527, sls::kFrameHash3527};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the 3527 signature and delete head at their new addresses, its own
// frame site, call site and frame name offset (scene_level_share_logic.h).
const Addrs kAddrs3663{sls::kPeTimestamp3663, sls::kVtServerField3663, sls::kGateFnBegin3663, sls::kGateFnEnd3663,
                       sls::kGateRva3663, sls::kGateSigRva3663, sls::kGateSig3527, sls::kDeleteRva3663,
                       sls::kDeleteEnd3663, sls::kRet28343663, sls::kRetOwnerLoad3663, sls::kRetLoader3663,
                       sls::kFrameSiteRva3663, sls::kFrameSite3663, sls::kCallSiteRva3663, sls::kCallSite3663,
                       sls::kFrameName3663, sls::kFrameType3663, sls::kFrameHash3663};
// Chosen by scene_level_share_start, before the module's thread exists; the hooks read it (a plain pointer: no CRT in a
// mid hook).
const Addrs* g_ad = &kAddrs2976;

std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_started{false};
std::atomic<bool> g_ingress_on{false};  // mode != 0 on the host: the sets are kept from the first packet
uintptr_t g_base = 0;

// Keys, published by the module thread every 100 ms (relaxed; the hooks read them).
std::atomic<bool> g_live{false};
std::atomic<uint32_t> g_host_user{0}, g_u2_user{0};
std::atomic<bool> g_u2_in_host_field{false};

sls::Tracker<1024> g_tracker;
std::atomic_flag g_writer = ATOMIC_FLAG_INIT;
sls::HashCheck g_hash;

// Hooks.
SafetyHookMid g_gate_hook;
SafetyHookInline g_del_hook;
std::atomic<bool> g_a_on{false}, g_b_on{false}, g_frame_ok{false};

// Counters.
std::array<std::atomic<uint64_t>, static_cast<size_t>(sls::GateWhy::Count)> g_gate{};
std::atomic<uint64_t> g_gate_faults{0};
std::array<std::array<std::atomic<uint64_t>, 3>, static_cast<size_t>(sls::Caller::Count)> g_del{};  // [caller][verdict]
std::array<std::atomic<uint64_t>, static_cast<size_t>(sls::Why::Count)> g_why{};
std::atomic<uint64_t> g_del_frame_bad{0}, g_del_name_bad{0};
constexpr size_t kApplied = static_cast<size_t>(sls::Applied::Bad) + 1;
std::array<std::array<std::atomic<uint64_t>, kApplied>, sls::kUsers> g_applied{};
std::atomic<uint64_t> g_ingress_faults{0}, g_ingress_big{0}, g_writer_busy{0};
std::array<std::atomic<uint64_t>, sls::kUsers> g_flushes{};  // requested by the module thread

// Events (hooks -> the module thread). Event kinds:
constexpr uint16_t kEvGate = 1, kEvDelete = 2, kEvSet = 3;
p8p::EventRing<1024> g_ring;
// Lines of the frequent kinds are limited where they are made (the rest counted).
p8p::WindowLimiter g_lim_owner{20, 60'000'000}, g_lim_gate_other{20, 60'000'000};

// ---------------------------------------------------------------- guarded reads (hooks)

template <class T>
bool rd(uintptr_t a, T& out) noexcept {
    return a && game::fast_read(a, &out, sizeof out);
}

// [a, a + n) in pieces that never cross a 4 KB page (a string that ends before an unmapped page is still read).
bool read_paged(uintptr_t a, uint8_t* out, size_t n) noexcept {
    while (n) {
        const size_t room = 0x1000 - (a & 0xFFF);
        const size_t k = n < room ? n : room;
        if (!game::fast_read(a, out, k)) return false;
        a += k;
        out += k;
        n -= k;
    }
    return true;
}

// The name behind &name (both 0x2830400's rdi and 0x2829E60's rdx): [holder] = S, [S] = char*, [S+8] length or -1,
// [S+0xC] the cached hash or -1. No CRT call (mid hooks): byte loops only.
struct NameRead {
    bool ok = false;
    uintptr_t obj = 0;  // the string object S
    uint32_t len = 0, cache = 0xFFFFFFFF;
    uint8_t bytes[sls::kNameMax + 1];
};
bool read_name(uintptr_t holder, NameRead& out) noexcept {
    out.ok = false;
    out.len = 0;
    out.cache = 0xFFFFFFFF;
    uintptr_t s = 0, p = 0;
    uint32_t len = 0;
    if (!rd(holder, s) || !s || !rd(s, p) || !p || !rd(s + sls::kStrLen, len)) return false;
    out.obj = s;
    rd(s + sls::kStrHash, out.cache);
    if (len != 0xFFFFFFFF) {
        if (!len || len > sls::kNameMax || !read_paged(p, out.bytes, len)) return false;
        out.len = len;
    } else {
        // Not counted yet: up to the NUL, 16 bytes at a time (never past a page in one read).
        size_t n = 0;
        bool nul = false;
        while (!nul && n < sls::kNameMax) {
            size_t k = sls::kNameMax - n < 16 ? sls::kNameMax - n : 16;
            const size_t room = 0x1000 - ((p + n) & 0xFFF);
            if (k > room) k = room;
            if (!game::fast_read(p + n, out.bytes + n, k)) return false;
            for (size_t i = 0; i < k; ++i) {
                if (!out.bytes[n + i]) {
                    nul = true;
                    k = i;
                    break;
                }
            }
            n += k;
        }
        if (!nul || !n) return false;
        out.len = static_cast<uint32_t>(n);
    }
    out.ok = true;
    return true;
}

// The first 56 bytes of the name into v[5..11] (byte loop: no memcpy in a mid hook).
void pack_name(p8p::Event& e, const NameRead& n) noexcept {
    for (size_t i = 5; i < 12; ++i) e.v[i] = 0;
    if (!n.ok) return;
    const size_t k = n.len < 56 ? n.len : 56;
    for (size_t i = 0; i < k; ++i) e.v[5 + i / 8] |= static_cast<uint64_t>(n.bytes[i]) << (8 * (i % 8));
}

// Review of a4c2661 (P2-4): the type-0 entry of this name in the registry, walked as 0x2836110 walks it (the node
// array [mgr+0x98], [mgr+0x84] nodes; the key at node+0x10, the ready byte at node+0x40), without the registry's lock:
// guarded reads only, and the answer is Unknown unless the map's count, array and stamp ([mgr+0x8C]) are the same
// before and after the walk. Yes = found and ready; No = found not ready, or not registered.
sls::Has entry_ready(uintptr_t mgr, const NameRead& n) noexcept {
    uint32_t count = 0, stamp = 0, count2 = 0, stamp2 = 0;
    uintptr_t nodes = 0, nodes2 = 0;
    if (!n.ok || !rd(mgr + sls::kMapCount, count) || !rd(mgr + sls::kMapStamp, stamp) ||
        !rd(mgr + sls::kMapNodes, nodes) || count > sls::kMapMaxWalk || (count && !nodes)) {
        return sls::Has::Unknown;
    }
    sls::Has found = sls::Has::No;
    uint8_t buf[sls::kNameMax + 1];
    for (uint32_t i = 0; i < count; ++i) {
        uintptr_t node = 0, s = 0, p = 0;
        uint32_t len = 0;
        if (!rd(nodes + size_t(i) * 8, node) || !node || !rd(node + sls::kNodeKey, s) || !s) return sls::Has::Unknown;
        bool same = s == n.obj;
        if (!same) {
            if (!rd(s, p) || !p || !rd(s + sls::kStrLen, len)) return sls::Has::Unknown;
            if (len != 0xFFFFFFFF && len != n.len) continue;
            // len -1 (not counted yet): the name's bytes and its NUL right after them.
            const size_t want = len == 0xFFFFFFFF ? size_t(n.len) + 1 : size_t(n.len);
            if (!read_paged(p, buf, want)) continue;  // a shorter string near a page end: not this name
            same = true;
            for (uint32_t k = 0; k < n.len && same; ++k) same = buf[k] == n.bytes[k];
            if (same && want > n.len) same = buf[n.len] == 0;
        }
        if (!same) continue;
        uint8_t ready = 0;
        if (!rd(node + sls::kNodeReady, ready)) return sls::Has::Unknown;
        found = ready ? sls::Has::Yes : sls::Has::No;
        break;
    }
    if (!rd(mgr + sls::kMapCount, count2) || !rd(mgr + sls::kMapStamp, stamp2) || !rd(mgr + sls::kMapNodes, nodes2) ||
        count2 != count || stamp2 != stamp || nodes2 != nodes) {
        return sls::Has::Unknown;
    }
    return found;
}

bool host_field(uintptr_t field, uint32_t& owner) noexcept {
    uintptr_t vt = 0;
    const uint32_t host = g_host_user.load(std::memory_order_relaxed);
    return field && rd(field, vt) && vt == g_base + g_ad->vt_server_field && rd(field + sls::kFieldOwner, owner) && host &&
           owner == host;
}

// ---------------------------------------------------------------- A: the owner gate 0x283044D (mid hook)

void on_gate(safetyhook::Context& ctx) noexcept {
    if (!g_a_on.load(std::memory_order_acquire)) return;
    sls::GateIn in;
    in.mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    in.eax = static_cast<uint32_t>(ctx.rax);
    uintptr_t vt = 0;
    if (!rd(ctx.r8 + sls::kFieldOwner, in.owner)) {
        g_gate_faults.fetch_add(1, std::memory_order_relaxed);
        return;  // the original compares as it would
    }
    in.field_ok = rd(ctx.r8, vt) && vt == g_base + g_ad->vt_server_field;
    in.keys_live = g_live.load(std::memory_order_relaxed);
    in.host_user = g_host_user.load(std::memory_order_relaxed);
    in.user2_user = g_u2_user.load(std::memory_order_relaxed);
    user2_funnels_subject_now(in.subject, in.opcode, in.hooked);
    in.actor = ctx.rdx;
    const sls::GateWhy why = sls::decide_gate(in);
    g_gate[static_cast<size_t>(why)].fetch_add(1, std::memory_order_relaxed);
    if (why == sls::GateWhy::Ready) ctx.rax = in.owner;  // eax := [field+0x180] (zero-extended, as a mov eax would)
    // Lines: every would ready / ready; the field owner's own pass and user 2's other rejections, limited.
    const uint64_t now = p8_now_us();
    const bool line = why == sls::GateWhy::WouldReady || why == sls::GateWhy::Ready ||
                      (why == sls::GateWhy::Owner ? g_lim_owner.take(now)
                                                  : in.eax == in.user2_user && in.eax && g_lim_gate_other.take(now));
    if (!line) return;
    NameRead n;
    read_name(ctx.rdi, n);
    p8p::Event e;
    e.qpc_us = now;
    e.tid = GetCurrentThreadId();
    e.kind = kEvGate;
    e.v[0] = static_cast<uint64_t>(why);
    e.v[1] = in.eax | (static_cast<uint64_t>(in.owner) << 32);
    uint32_t key = 0;
    rd(ctx.rdx + sls::kActorKey, key);
    e.v[2] = key | (static_cast<uint64_t>(in.opcode) << 32) | (static_cast<uint64_t>(in.subject == ctx.rdx) << 48);
    if (n.ok) {
        const sls::NameHashes h = sls::name_hashes(n.bytes, n.len);
        e.v[3] = h.raw | (static_cast<uint64_t>(h.base) << 32);
    }
    e.v[4] = n.cache | (static_cast<uint64_t>(n.len) << 32) | (static_cast<uint64_t>(n.ok) << 63);
    pack_name(e, n);
    g_ring.push(e);
}

// ---------------------------------------------------------------- B: the delete 0x2829E60 (inline hook)

__declspec(noinline) void delete_detour(uintptr_t mgr, uintptr_t name, uintptr_t type, uintptr_t a4, uintptr_t a5,
                                        uintptr_t a6, uintptr_t a7) {
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    // Entered through the hook's jump (no push): the caller's rsp at its call is the address of our return + 8.
    const uintptr_t frame = reinterpret_cast<uintptr_t>(_AddressOfReturnAddress()) + 8;
    if (!g_b_on.load(std::memory_order_acquire)) {
        g_del_hook.unsafe_call<void>(mgr, name, type, a4, a5, a6, a7);
        return;
    }
    sls::DeleteIn in;
    in.mode = static_cast<Mode>(g_mode.load(std::memory_order_relaxed));
    const uint32_t ret_rva = ret >= g_base && ret - g_base < 0x80000000ull ? static_cast<uint32_t>(ret - g_base) : 0;
    in.caller = sls::caller_of(ret_rva, g_ad->ret_2834, g_ad->ret_owner_load, g_ad->ret_loader);
    in.type_ok = rd(type, in.type);
    uintptr_t field = 0;
    uint32_t owner = 0;
    in.field_host = rd(mgr + sls::kMgrField, field) && host_field(field, owner);
    uintptr_t subject = 0;
    uint16_t opcode = 0;
    bool hooked = false;
    user2_funnels_subject_now(subject, opcode, hooked);
    in.provoker = sls::provoker_of(in.caller, hooked, subject != 0, opcode);
    NameRead n;
    in.name_ok = in.caller != sls::Caller::Other && read_name(name, n);
    if (in.caller != sls::Caller::Other && !in.name_ok) g_del_name_bad.fetch_add(1, std::memory_order_relaxed);
    sls::NameHashes h;
    if (in.name_ok) h = sls::name_hashes(n.bytes, n.len);
    uint32_t packet_hash = 0;
    if (in.caller == sls::Caller::Unload2834 && g_frame_ok.load(std::memory_order_relaxed)) {
        in.packet_hash_ok = sls::frame_matches(frame, name, type, g_ad->frame_name, g_ad->frame_type) &&
                            rd(frame + g_ad->frame_hash, packet_hash);
        if (!in.packet_hash_ok) g_del_frame_bad.fetch_add(1, std::memory_order_relaxed);
        if (in.packet_hash_ok && in.name_ok) g_hash.record(h, packet_hash);
    }
    in.variant = g_hash.usable();
    const uint32_t hash = sls::HashCheck::pick(in.variant, h);
    in.hash_matches = in.caller == sls::Caller::Unload2834 && in.packet_hash_ok && hash == packet_hash;
    if (in.field_host && in.variant != sls::Variant::None) {
        in.host = g_tracker.has(User::Host, hash);
        in.user2 = g_u2_in_host_field.load(std::memory_order_relaxed) ? g_tracker.has(User::User2, hash) : sls::Has::No;
    }
    sls::DeleteOut out = sls::decide_delete(in);
    // P2-4: a 2834 that would be kept: only if its entry is ready (read now, only for these few calls).
    if (out.why == sls::Why::ReadyUnknown) {
        in.ready = entry_ready(mgr, n);
        out = sls::decide_delete(in);
    }
    g_del[static_cast<size_t>(in.caller)][static_cast<size_t>(out.verdict)].fetch_add(1, std::memory_order_relaxed);
    g_why[static_cast<size_t>(out.why)].fetch_add(1, std::memory_order_relaxed);
    if (in.caller != sls::Caller::Other) {
        p8p::Event e;
        e.qpc_us = p8_now_us();
        e.tid = GetCurrentThreadId();
        e.kind = kEvDelete;
        e.v[0] = static_cast<uint64_t>(in.caller) | (static_cast<uint64_t>(in.type) << 8) |
                 (static_cast<uint64_t>(in.provoker) << 16) | (static_cast<uint64_t>(out.verdict) << 24) |
                 (static_cast<uint64_t>(out.why) << 32) | (static_cast<uint64_t>(out.holders) << 40) |
                 (static_cast<uint64_t>(in.name_ok) << 48) | (static_cast<uint64_t>(in.packet_hash_ok) << 49) |
                 (static_cast<uint64_t>(in.field_host) << 50) | (static_cast<uint64_t>(hooked) << 51) |
                 (static_cast<uint64_t>(in.type_ok) << 52);
        e.v[1] = ret_rva | (static_cast<uint64_t>(opcode) << 32);
        e.v[2] = h.raw | (static_cast<uint64_t>(h.base) << 32);
        e.v[3] = n.cache | (static_cast<uint64_t>(packet_hash) << 32);
        e.v[4] = static_cast<uint64_t>(in.host) | (static_cast<uint64_t>(in.user2) << 8) |
                 (static_cast<uint64_t>(in.variant) << 16) | (static_cast<uint64_t>(in.ready) << 24) |
                 (static_cast<uint64_t>(n.len) << 32);
        pack_name(e, n);
        g_ring.push(e);
    }
    if (out.verdict == sls::Verdict::Keep) return;  // void: the 2834 handler ignores it and releases the name itself
    g_del_hook.unsafe_call<void>(mgr, name, type, a4, a5, a6, a7);
}

// ---------------------------------------------------------------- install (module thread)

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

// The build (base, PE timestamp) and the .pdata entry that begins at `begin` ends at `end`.
bool build_and_pdata(uint32_t begin, uint32_t end, std::string& why) {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (g_base != sls::kImageBase || !game::safe_read(g_base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 ||
        !game::safe_read(g_base + static_cast<uint32_t>(dos.e_lfanew), &nt, sizeof nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        (nt.FileHeader.TimeDateStamp != g_ad->pe_timestamp && !(g_ad == &kAddrs3527 && game::is_3549()))) {
        why = "ni 1.0.0.2976 ni 1.0.0.3527 ni 1.0.0.3549 ni 1.0.0.3576 ni 1.0.0.3663 (base/PE)";
        return false;
    }
    const auto pd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!pd.VirtualAddress || !pd.Size || pd.Size % sizeof(RUNTIME_FUNCTION) || pd.Size > 0x1000000) {
        why = ".pdata ilegible";
        return false;
    }
    std::vector<RUNTIME_FUNCTION> entries(pd.Size / sizeof(RUNTIME_FUNCTION));
    if (!game::safe_read(g_base + pd.VirtualAddress, entries.data(), pd.Size)) {
        why = ".pdata ilegible";
        return false;
    }
    for (const auto& r : entries) {
        if (r.BeginAddress == begin) {
            if (r.EndAddress == end) return true;
            why = std::format(".pdata [0x{:X},0x{:X}) en vez de [0x{:X},0x{:X})", r.BeginAddress, r.EndAddress, begin, end);
            return false;
        }
    }
    why = std::format("sin entrada .pdata en 0x{:X}", begin);
    return false;
}

bool install_a(std::span<const gad::Section> secs) {
    const Addrs& ad = *g_ad;
    std::string why;
    if (!build_and_pdata(ad.gate_fn_begin, ad.gate_fn_end, why)) {
        log::warn("SceneLevelShare: A REFUSED en 0x{:X}: {}; A queda apagada", ad.gate_rva, why);
        return false;
    }
    if (!bytes_at(ad.gate_sig_rva, ad.gate_sig)) {
        log::warn("SceneLevelShare: A REFUSED: la firma de 40 B en 0x{:X} no es la esperada; A queda apagada",
                  ad.gate_sig_rva);
        return false;
    }
    // The cmp (7 bytes, what the hook relocates) and its jnz, from the signature.
    const std::span<const uint8_t> at(ad.gate_sig.data() + sls::kGateSigPatchAt, 13);
    if (!p8_install_mid(g_base, secs, ad.gate_rva, sls::kGatePatch, at, &on_gate, g_gate_hook, "SceneLevelShare",
                        "A, la puerta de dueno (cmp [r8+0x180],eax)")) {
        log::warn("SceneLevelShare: A REFUSED (ver el error anterior); A queda apagada");
        return false;
    }
    g_a_on.store(true, std::memory_order_release);
    return true;
}

bool install_b(std::span<const gad::Section> secs) {
    const Addrs& ad = *g_ad;
    std::string why;
    if (!build_and_pdata(ad.delete_rva, ad.delete_end, why)) {
        log::warn("SceneLevelShare: B REFUSED en 0x{:X}: {}; B queda apagada", ad.delete_rva, why);
        return false;
    }
    if (!gad::in_real_code(secs, ad.delete_rva, static_cast<uint32_t>(sls::kDeleteHead.size())) ||
        !bytes_at(ad.delete_rva, sls::kDeleteHead)) {
        log::warn("SceneLevelShare: B REFUSED: la entrada 0x{:X} no es el codigo esperado (.rsrc, 16 B); B queda apagada",
                  ad.delete_rva);
        return false;
    }
    const auto accept = [](const std::vector<uint8_t>& b) { return sls::delete_patch_ok(b); };
    auto h = game::prepare_inline(g_base + ad.delete_rva, reinterpret_cast<void*>(&delete_detour), accept,
                                  "SceneLevelShare", "B, el borrado de SceneLevel");
    if (!h || !accept(h->original_bytes())) {
        log::warn("SceneLevelShare: B REFUSED: el gancho no se pudo preparar con exactamente los 5 B verificados; B queda "
                  "apagada");
        return false;
    }
    g_del_hook = std::move(*h);
    // The 2834 handler's frame (the packet's hash): checked before the hook can read it.
    const bool frame = bytes_at(ad.frame_site_rva, ad.frame_site) && bytes_at(ad.call_site_rva, ad.call_site);
    g_frame_ok.store(frame, std::memory_order_relaxed);
    g_b_on.store(true, std::memory_order_release);
    if (!g_del_hook.enable()) {
        g_b_on.store(false);
        log::warn("SceneLevelShare: B REFUSED: el gancho no se pudo activar; B queda apagada");
        return false;
    }
    if (!frame) {
        log::warn("SceneLevelShare: B: el marco del 2834 (0x{:X} / 0x{:X}) no es el esperado: sin hash de paquete no se "
                  "verifica nada y B solo observa",
                  ad.frame_site_rva, ad.call_site_rva);
    }
    return true;
}

bool code_ready() {
    return bytes_at(g_ad->gate_sig_rva, g_ad->gate_sig) && bytes_at(g_ad->delete_rva, sls::kDeleteHead);
}

bool player_in_world() {
    uintptr_t world = 0, mgr = 0, vt = 0, actor = 0, avt = 0;
    const game::ReaderProfile* const p = game::reader_profile();  // the same values as g2976's in 2976
    // 3576 while reader_profile() is not ported there (docs/research/port-3576.md): world 0x71C0100, ClientActorManager
    // 0x5946C40 and ClientChildOnlyInGameActor 0x5914D58 by RTTI; the +0x30 / +0x50 offsets as on 3527.
    // 3663 likewise (static, 2026-11-13; never run): world 0x72451C0 (core_globals_3663.json), ClientActorManager
    // 0x59C2760 and ClientChildOnlyInGameActor 0x5990BF0 by RTTI (vtable_map_3576_3663.json); world+0x30 -> +0x50 is
    // read so at 0x3EE4C0 / 0x3EE4C4.
    const bool b3576 = !p && game::current_build() == game::Build::v3576;
    const bool b3663 = !p && game::current_build() == game::Build::v3663;
    if (!p && !b3576 && !b3663) return false;
    const uintptr_t world_slot = p ? p->world_system : b3663 ? 0x72451C0 : 0x71C0100,
                    vt_mgr = p ? p->vt_actor_manager : b3663 ? 0x59C2760 : 0x5946C40,
                    vt_actor = p ? p->vt_controlled_actor : b3663 ? 0x5990BF0 : 0x5914D58;
    return rd(g_base + world_slot, world) && world && rd(world + g2976::kWorldSystem_ActorManager, mgr) &&
           mgr && rd(mgr, vt) && vt == g_base + vt_mgr &&
           rd(mgr + g2976::kActorManager_ControlledActor, actor) && actor && rd(actor, avt) &&
           avt == g_base + vt_actor;
}

// 3527 and 3576: user2_stages is not ported (its sampling never starts there), so user 2's field is read here, the path
// server_host_field reads the host's: [user+0xD0] main character, TS = [[pj+0x68]+0x1A0], field = [TS + the build's
// FieldMover + 0x10]. Guarded reads only.
bool user2_in_host_field_3527(uint32_t host_key) {
    constexpr uintptr_t kUserMain = 0xD0, kActorComps = 0x68, kCompsTs = 0x1A0;
    uintptr_t user = 0, pj = 0, comps = 0, ts = 0, field = 0, vt = 0;
    uint32_t owner = 0;
    return host_key && server_user2(user) && user && rd(user + kUserMain, pj) && pj && rd(pj + kActorComps, comps) && comps &&
           rd(comps + kCompsTs, ts) && ts && rd(ts + runtime_field_layout().ts_field_mover + fld::kFmField, field) && field &&
           rd(field, vt) && vt == g_base + g_ad->vt_server_field && rd(field + sls::kFieldOwner, owner) && owner == host_key;
}

// ---------------------------------------------------------------- the module thread

uint32_t g_last_epoch = 0;
bool g_was_live = false, g_was_in_field = false;
sls::KeptBook g_kept;
// Line budgets (review of a4c2661, P3-3): the owner's load and the loader can delete hundreds of levels at once; their
// plain native deletes have a budget of their own so they never use up the door's lines. The essential lines (A's
// [would ready] / [ready for user 2], every [would keep] / [kept], the watched level, the sets' lines) another one.
constexpr uint64_t kBudgetBulk = 3000, kBudgetMain = 20000, kBudgetEssential = 50000;
uint64_t g_lines[3] = {}, g_lines_capped[3] = {};
bool g_first_match_said[2] = {}, g_miss_said[2] = {};
uint32_t g_out_of_field = 0;  // consecutive readings (100 ms) of user 2 out of the host's field

void refresh_keys() {
    const bool live = server_user2_present();
    uint32_t host_key = 0;
    uintptr_t host = 0;
    if (server_host_user(host) && host) rd(host + sls::kActorKey, host_key);
    g_host_user.store(host_key, std::memory_order_relaxed);
    g_u2_user.store(live ? server_user2_user_key() : 0, std::memory_order_relaxed);
    g_live.store(live, std::memory_order_relaxed);
    // user2_stages samples the field once a second; one unreadable sample is not a departure: out only after 2 s of
    // readings out (or at once when user 2 is gone).
    const bool current = game::current_build() == game::Build::v3527 || game::current_build() == game::Build::v3576 ||
                         game::current_build() == game::Build::v3663;
    const bool raw_in_field = live && (current ? user2_in_host_field_3527(host_key) : user2_stages_user2_in_host_field());
    g_out_of_field = raw_in_field ? 0 : g_out_of_field + 1;
    const bool in_field = live && (raw_in_field || (g_was_in_field && g_out_of_field < 20));
    g_u2_in_host_field.store(in_field, std::memory_order_relaxed);
    const uint32_t epoch = server_epoch();
    static bool first = true;
    if (first) g_last_epoch = epoch;  // the first reading is the baseline, not a change
    first = false;
    const char* why = nullptr;
    if (epoch != g_last_epoch) why = "epoca nueva";
    else if (g_was_live && !live) why = "el usuario 2 ya no esta";
    // Leaving the host's field (entering it comes with its load, whose 2437 already emptied the set).
    else if (g_was_in_field && !in_field) why = "sale del campo del anfitrion";
    if (why) {
        g_tracker.flush(User::User2);
        g_flushes[1].fetch_add(1, std::memory_order_relaxed);
        log::info("SceneLevelShare [conjunto] usuario2 vaciado ({}; epoca {}, vivo {}, en el campo del anfitrion {})", why,
                  epoch, live ? "si" : "no", in_field ? "si" : "no");
    }
    g_last_epoch = epoch;
    g_was_live = live;
    g_was_in_field = in_field;
}

std::string name_of(const p8p::Event& e, uint32_t len, bool ok) {
    if (!ok) return "(ilegible)";
    std::string s;
    const size_t k = len < 56 ? len : 56;
    for (size_t i = 0; i < k; ++i) {
        const char c = static_cast<char>((e.v[5 + i / 8] >> (8 * (i % 8))) & 0xFF);
        s.push_back(c >= 0x20 && c < 0x7F ? c : '?');
    }
    if (len > 56) s += std::format("... ({} B)", len);
    return "'" + s + "'";
}

std::string hex_or_none(uint32_t v) { return v == 0xFFFFFFFF ? std::string("-1") : std::format("0x{:08X}", v); }

void format_gate(const p8p::Event& e) {
    const auto why = static_cast<sls::GateWhy>(e.v[0]);
    const uint32_t eax = static_cast<uint32_t>(e.v[1]), owner = static_cast<uint32_t>(e.v[1] >> 32);
    const uint32_t key = static_cast<uint32_t>(e.v[2]);
    const auto opcode = static_cast<uint16_t>(e.v[2] >> 32);
    const bool same = (e.v[2] >> 48) & 1;
    const bool ok = (e.v[4] >> 63) & 1;
    const uint32_t len = static_cast<uint32_t>((e.v[4] >> 32) & 0x7FFFFFFF);
    const char* tag = why == sls::GateWhy::WouldReady ? "[would ready]"
                      : why == sls::GateWhy::Ready    ? "[ready for user 2]"
                      : why == sls::GateWhy::Owner    ? "[owner native]"
                                                      : "[gate]";
    log::info("SceneLevelShare {} {} nivel {} hash-nombre 0x{:08X} base 0x{:08X} cache {} | actor 0x{:08X} usuario "
              "0x{:08X} dueno-campo 0x{:08X} | troc del usuario 2 {} opcode {} ({}) [0x{:X}{}]",
              tag, p8_when(e.qpc_us), name_of(e, len, ok), static_cast<uint32_t>(e.v[3]),
              static_cast<uint32_t>(e.v[3] >> 32), hex_or_none(static_cast<uint32_t>(e.v[4])), key, eax, owner,
              same ? "sobre este actor" : "no", opcode, sls::gate_why_name(why), g_ad->gate_rva,
              why == sls::GateWhy::Ready ? ": eax := dueno" : "");
}

void note_hash(uint32_t raw, uint32_t base, uint32_t pkt, const std::string& name) {
    const uint32_t v[2] = {raw, base};
    for (size_t i = 0; i < 2; ++i) {
        const char* what = i ? "nombre-base" : "nombre";
        if (v[i] == pkt && !g_first_match_said[i]) {
            g_first_match_said[i] = true;
            log::info("SceneLevelShare [hash] primera coincidencia {} -> hash del 2834: {} = 0x{:08X}", what, name, pkt);
        } else if (v[i] != pkt && !g_miss_said[i]) {
            g_miss_said[i] = true;
            log::info("SceneLevelShare [hash] {} NO da el hash del 2834: {} -> 0x{:08X}, paquete 0x{:08X} (esa regla queda "
                      "descartada en este proceso)",
                      what, name, v[i], pkt);
        }
    }
}

void format_delete(const p8p::Event& e) {
    const auto caller = static_cast<sls::Caller>(e.v[0] & 0xFF);
    const auto type = static_cast<uint8_t>(e.v[0] >> 8);
    const auto prov = static_cast<sls::Who>((e.v[0] >> 16) & 0xFF);
    const auto verdict = static_cast<sls::Verdict>((e.v[0] >> 24) & 0xFF);
    const auto why = static_cast<sls::Why>((e.v[0] >> 32) & 0xFF);
    const auto holders = static_cast<uint8_t>(e.v[0] >> 40);
    const bool name_ok = (e.v[0] >> 48) & 1, pkt_ok = (e.v[0] >> 49) & 1, field_host = (e.v[0] >> 50) & 1,
               hooked = (e.v[0] >> 51) & 1, type_ok = (e.v[0] >> 52) & 1;
    const uint32_t ret = static_cast<uint32_t>(e.v[1]);
    const auto opcode = static_cast<uint16_t>(e.v[1] >> 32);
    const uint32_t raw = static_cast<uint32_t>(e.v[2]), base = static_cast<uint32_t>(e.v[2] >> 32);
    const uint32_t cache = static_cast<uint32_t>(e.v[3]), pkt = static_cast<uint32_t>(e.v[3] >> 32);
    const auto host = static_cast<sls::Has>(e.v[4] & 0xFF), user2 = static_cast<sls::Has>((e.v[4] >> 8) & 0xFF);
    const auto variant = static_cast<sls::Variant>((e.v[4] >> 16) & 0xFF);
    const auto ready = static_cast<sls::Has>((e.v[4] >> 24) & 0xFF);
    const uint32_t len = static_cast<uint32_t>(e.v[4] >> 32);
    const std::string name = name_of(e, len, name_ok);
    if (caller == sls::Caller::Unload2834 && pkt_ok && name_ok) note_hash(raw, base, pkt, name);
    const uint32_t hash = variant == sls::Variant::Raw ? raw : variant == sls::Variant::Base ? base : 0;
    if (verdict == sls::Verdict::Keep) {
        g_kept.kept(hash, e.qpc_us);
    } else if (verdict == sls::Verdict::Delete && hash && g_kept.deleted(hash)) {
        log::info("SceneLevelShare [kept -> borrado] {} nivel {} 0x{:08X}: el borrado nativo paso ({}, {})", p8_when(e.qpc_us),
                  name, hash, sls::caller_name(caller), sls::why_name(why));
    }
    const char* tag = verdict == sls::Verdict::Keep        ? "[kept]"
                      : verdict == sls::Verdict::WouldKeep ? "[would keep]"
                                                           : "borrado nativo";
    log::info("SceneLevelShare [delete] {} llamador {} (ret 0x{:X}) tipo {} nivel {} hash-nombre 0x{:08X} base 0x{:08X} "
              "cache {} paquete {} | provoca {} (troc {} opcode {}) | campo del anfitrion {} | lo tienen: anfitrion {} "
              "usuario2 {} (otros que lo tienen: {}) | entrada lista {} | regla {} -> {} ({})",
              p8_when(e.qpc_us), sls::caller_name(caller), ret, type_ok ? std::to_string(type) : std::string("?"), name,
              raw, base, hex_or_none(cache), pkt_ok ? std::format("0x{:08X}", pkt) : std::string("-"),
              sls::who_name(prov), hooked ? "enganchada" : "SIN gancho", opcode, field_host ? "si" : "no",
              sls::has_name(host), sls::has_name(user2),
              holders == 3 ? "ambos" : holders == 1 ? "anfitrion" : holders == 2 ? "usuario2" : "nadie",
              caller == sls::Caller::Unload2834 ? sls::has_name(ready) : "-", sls::variant_name(variant), tag,
              sls::why_name(why));
}

void format_set(const p8p::Event& e) {
    const auto user = static_cast<User>(e.v[0] & 0xFF);
    const auto applied = static_cast<sls::Applied>((e.v[0] >> 8) & 0xFF);
    const auto op = static_cast<uint16_t>(e.v[0] >> 16);
    const uint32_t hash = static_cast<uint32_t>(e.v[1]), size = static_cast<uint32_t>(e.v[1] >> 32);
    constexpr const char* names[] = {"ignorado", "anadido", "ya estaba", "quitado", "no estaba", "otro tipo",
                                     "reemplazado (lista entera)", "vaciado", "LLENO (deja de valer)", "mal formado"};
    const auto a = static_cast<size_t>(applied);
    log::info("SceneLevelShare [conjunto] {} {} {} {}-> {} (ahora {})", p8_when(e.qpc_us), sls::user_name(user), op,
              hash ? std::format("hash 0x{:08X} ", hash) : std::string(), a < std::size(names) ? names[a] : "?", size);
}

// 0 bulk, 1 main, 2 essential.
size_t budget_of(const p8p::Event& e) {
    if (e.kind == kEvSet) return 2;
    if (e.kind == kEvGate) {
        const auto why = static_cast<sls::GateWhy>(e.v[0]);
        return why == sls::GateWhy::WouldReady || why == sls::GateWhy::Ready ? 2 : 1;
    }
    const auto caller = static_cast<sls::Caller>(e.v[0] & 0xFF);
    const auto verdict = static_cast<sls::Verdict>((e.v[0] >> 24) & 0xFF);
    const uint32_t raw = static_cast<uint32_t>(e.v[2]), base = static_cast<uint32_t>(e.v[2] >> 32),
                   pkt = static_cast<uint32_t>(e.v[3] >> 32);
    if (verdict != sls::Verdict::Delete || raw == sls::kWatchedHash || base == sls::kWatchedHash ||
        pkt == sls::kWatchedHash) {
        return 2;
    }
    return caller == sls::Caller::OwnerLoad || caller == sls::Caller::Loader ? 0 : 1;
}

void drain() {
    constexpr uint64_t caps[3] = {kBudgetBulk, kBudgetMain, kBudgetEssential};
    p8p::Event e;
    while (g_ring.pop(e)) {
        const size_t b = budget_of(e);
        if (g_lines[b] >= caps[b]) {
            ++g_lines_capped[b];
            // The kept book follows every event, written or not.
            if (e.kind == kEvDelete) {
                const auto verdict = static_cast<sls::Verdict>((e.v[0] >> 24) & 0xFF);
                const auto variant = static_cast<sls::Variant>((e.v[4] >> 16) & 0xFF);
                const uint32_t h = variant == sls::Variant::Raw    ? static_cast<uint32_t>(e.v[2])
                                   : variant == sls::Variant::Base ? static_cast<uint32_t>(e.v[2] >> 32)
                                                                   : 0;
                if (verdict == sls::Verdict::Keep) g_kept.kept(h, e.qpc_us);
                else if (verdict == sls::Verdict::Delete && h) g_kept.deleted(h);
            }
            continue;
        }
        ++g_lines[b];
        if (e.kind == kEvGate) format_gate(e);
        else if (e.kind == kEvDelete) format_delete(e);
        else if (e.kind == kEvSet) format_set(e);
    }
}

void summary() {
    std::string gate;
    for (size_t i = 0; i < g_gate.size(); ++i) {
        if (const uint64_t n = g_gate[i].load()) gate += std::format(" {} {}", sls::gate_why_name(static_cast<sls::GateWhy>(i)), n);
    }
    std::string del;
    for (size_t c = 0; c < g_del.size(); ++c) {
        const uint64_t d = g_del[c][0].load(), w = g_del[c][1].load(), k = g_del[c][2].load();
        if (d + w + k) {
            del += std::format(" {}: {} (would keep {}, kept {})", sls::caller_name(static_cast<sls::Caller>(c)), d + w + k,
                               w, k);
        }
    }
    std::string why;
    for (size_t i = 0; i < g_why.size(); ++i) {
        if (const uint64_t n = g_why[i].load()) why += std::format(" {} {}", sls::why_name(static_cast<sls::Why>(i)), n);
    }
    std::string sets;
    for (size_t u = 0; u < sls::kUsers; ++u) {
        const auto& a = g_applied[u];
        sets += std::format(" | {}: {} niveles ({}), +{} ={} -{} ?{} lista {} vaciados {} (+{} del hilo) mal {} lleno {}",
                            sls::user_name(static_cast<User>(u)), g_tracker.size(static_cast<User>(u)),
                            g_tracker.valid(static_cast<User>(u)) ? "fiable" : "NO fiable",
                            a[static_cast<size_t>(sls::Applied::Added)].load(),
                            a[static_cast<size_t>(sls::Applied::AlreadyIn)].load(),
                            a[static_cast<size_t>(sls::Applied::Removed)].load(),
                            a[static_cast<size_t>(sls::Applied::NotIn)].load(),
                            a[static_cast<size_t>(sls::Applied::Replaced)].load(),
                            a[static_cast<size_t>(sls::Applied::Flushed)].load(), g_flushes[u].load(),
                            a[static_cast<size_t>(sls::Applied::Bad)].load(),
                            a[static_cast<size_t>(sls::Applied::Overflow)].load());
    }
    size_t orphans = 0;
    std::string orphan_list;
    for (const sls::KeptEntry& k : g_kept.entries()) {
        if (g_tracker.has(User::Host, k.hash) != sls::Has::Yes && g_tracker.has(User::User2, k.hash) != sls::Has::Yes) {
            ++orphans;
            if (orphans <= 5) orphan_list += std::format(" 0x{:08X}", k.hash);
        }
    }
    uintptr_t subject = 0;
    uint16_t opcode = 0;
    bool hooked = false;
    user2_funnels_subject_now(subject, opcode, hooked);
    log::info("SceneLevelShare [resumen] modo {} | A {}:{} (lecturas fallidas {}) | B {}:{} | motivos:{} | hash: nombre "
              "{}/{} base {}/{} (coinciden/distintos) regla {} | marco 2834 {} (no casa {}), nombres ilegibles {}{} | "
              "kept vivos {} (posibles huerfanos {}{}; olvidados {}) | sujeto de ExecuteTroc {} | usuario 2 {} en el "
              "campo del anfitrion {} | anillo perdidos {}, lineas omitidas {} (carga/cargador {}, esenciales {}) | "
              "ingreso: lecturas fallidas {} grandes {} "
              "escritor ocupado {}",
              sls::mode_name(static_cast<Mode>(g_mode.load())), g_a_on.load() ? "ON" : "apagada",
              gate.empty() ? " nada" : gate, g_gate_faults.load(), g_b_on.load() ? "ON" : "apagada",
              del.empty() ? " nada" : del, why.empty() ? " nada" : why, g_hash.matches(0), g_hash.misses(0),
              g_hash.matches(1), g_hash.misses(1), sls::variant_name(g_hash.usable()),
              g_frame_ok.load() ? "verificado" : "NO", g_del_frame_bad.load(), g_del_name_bad.load(), sets,
              g_kept.entries().size(), orphans, orphan_list, g_kept.forgotten(), hooked ? "enganchado" : "SIN GANCHO",
              g_live.load() ? "vivo" : "ausente", g_u2_in_host_field.load() ? "si" : "no", g_ring.dropped(),
              g_lines_capped[1], g_lines_capped[0], g_lines_capped[2], g_ingress_faults.load(), g_ingress_big.load(), g_writer_busy.load());
}

DWORD WINAPI module_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    std::vector<gad::Section> secs;
    if (g_base != sls::kImageBase || !p8_exe_sections(g_base, secs)) {
        log::warn("SceneLevelShare: imagen o tabla de secciones inesperada; A y B quedan apagadas");
        return 0;
    }
    bool ready = false;
    for (int i = 0; i < 24000 && !(ready = code_ready()); ++i) Sleep(5);
    if (!ready) log::warn("SceneLevelShare: el codigo del juego no es el esperado tras 2 minutos; se comprueba al instalar");
    log::info("SceneLevelShare: esperando al jugador en el mundo antes de enganchar");
    for (int stable = 0; stable < 6;) {
        Sleep(500);
        stable = player_in_world() ? stable + 1 : 0;
    }
    refresh_keys();
    const Mode mode = static_cast<Mode>(g_mode.load());
    const bool a = install_a(secs);
    const bool b = install_b(secs);
    uintptr_t subject = 0;
    uint16_t opcode = 0;
    bool hooked = false;
    user2_funnels_subject_now(subject, opcode, hooked);
    log::info("SceneLevelShare: modo {} | A en 0x{:X} {} | B en 0x{:X} {} | sujeto de ExecuteTroc (user2_funnels) {}{}",
              sls::mode_name(mode), g_ad->gate_rva,
              a ? std::format("(mid 7 B 41 39 80 80 01 00 00; firma 40 B en 0x{:X} y .pdata [0x{:X},0x{:X}) verificadas): "
                              "{}",
                              g_ad->gate_sig_rva, g_ad->gate_fn_begin, g_ad->gate_fn_end,
                              mode == Mode::On ? "2598/2104 del usuario 2 en el campo del anfitrion -> eax := dueno"
                                               : "solo cuenta [would ready]")
                : std::string("REFUSED"),
              g_ad->delete_rva,
              b ? std::format("(entrada 5 B 44 88 4C 24 20, .pdata [0x{:X},0x{:X}) verificada; marco del 2834 {}): {}",
                              g_ad->delete_rva, g_ad->delete_end, g_frame_ok.load() ? "verificado" : "NO verificado",
                              mode == Mode::On ? "omite SOLO el borrado del 2834 de un nivel que otro usuario tiene "
                                                 "cargado (hash verificado); la carga del dueno y el cargador solo observan"
                                               : "solo mide [would keep]")
                : std::string("REFUSED"),
              hooked ? "enganchado" : "SIN GANCHO: A nunca actua y B no sabe quien provoca (llama siempre al original)",
              game::current_build() == game::Build::v3527 || game::current_build() == game::Build::v3576 ||
                      game::current_build() == game::Build::v3663
                  ? " | el campo del usuario 2 se lee aqui (user2_stages no esta portado a 3527 / 3576)"
                  : " | el usuario 2 cuenta como 'en el campo del anfitrion' solo con user2_stages activo (si no, su "
                    "conjunto nunca protege nada)");
    if (!a && !b) return 0;
    for (uint64_t tick = 1;; ++tick) {
        Sleep(100);
        refresh_keys();
        if (tick % 10 == 0) drain();
        if (tick % 600 == 0) summary();
    }
}

}  // namespace

void scene_level_share_start(const std::string& raw, bool guest) {
    const sls::ParsedMode p = sls::parse_mode(raw);
    if (!p.known) log::warn("SceneLevelShare: scene_level_share='{}' no es 0, probe ni 1; queda apagado", raw);
    if (p.mode == Mode::Off) return;
    if (guest) {
        log::info("SceneLevelShare: scene_level_share={} es solo del anfitrion; en el invitado no hace nada", raw);
        return;
    }
    if (g_started.exchange(true)) return;
    if (game::current_build() == game::Build::v3527) g_ad = &kAddrs3527;
    if (game::current_build() == game::Build::v3576) g_ad = &kAddrs3576;
    if (game::current_build() == game::Build::v3663) g_ad = &kAddrs3663;
    g_mode.store(static_cast<uint8_t>(p.mode));
    g_ingress_on.store(true, std::memory_order_release);
    log::info("SceneLevelShare ON (scene_level_share={}): A = listo tambien para el usuario 2 en 0x{:X}, B = no borrar "
              "un SceneLevel que otro usuario sigue teniendo cargado en 0x{:X} ({})",
              sls::mode_name(p.mode), g_ad->gate_rva, g_ad->delete_rva,
              p.mode == Mode::On ? "1: A cambia eax; B omite solo borrados de 2834" : "probe: solo mide");
    CloseHandle(CreateThread(nullptr, 0, module_thread, nullptr, 0, nullptr));
}

void scene_level_share_server_ingress(uint16_t op, uintptr_t packet, uint16_t size, bool from_user2,
                                      bool from_host) noexcept {
    if (!g_ingress_on.load(std::memory_order_relaxed) || !sls::relevant(op) || (!from_user2 && !from_host)) return;
    const User u = from_user2 ? User::User2 : User::Host;
    const size_t ui = static_cast<size_t>(u);
    // A Resync list up to 512 hashes is copied; a larger one cannot be followed: that user's set stops counting.
    constexpr size_t kMax = sls::kHeader + 1 + 512 * 4;
    if (size > kMax || size < sls::kHeader) {
        g_ingress_big.fetch_add(1, std::memory_order_relaxed);
        g_tracker.invalidate(u);
        return;
    }
    uint8_t buf[kMax];  // not zeroed (no memset in a mid hook); only `size` bytes are read
    if (!game::fast_read(packet, buf, size) ||
        !native_opcode::decode_packet(game::current_build(), std::span(buf, size), troc::Dir::ToHostServer)) {
        g_ingress_faults.fetch_add(1, std::memory_order_relaxed);
        g_tracker.invalidate(u);
        return;
    }
    const sls::Packet p = sls::parse_frame(std::span<const uint8_t>(buf, size));
    if (g_writer.test_and_set(std::memory_order_acquire)) {
        g_writer_busy.fetch_add(1, std::memory_order_relaxed);
        g_tracker.invalidate(u);
        return;
    }
    const sls::Applied a = g_tracker.apply(u, p);
    const uint32_t now_size = g_tracker.size(u);
    g_writer.clear(std::memory_order_release);
    const auto ai = static_cast<size_t>(a);
    if (ai < kApplied) g_applied[ui][ai].fetch_add(1, std::memory_order_relaxed);
    // Lines: the watched door's level, every list / flush / bad packet; the rest only counted.
    const bool line = p.hash == sls::kWatchedHash || a == sls::Applied::Replaced || a == sls::Applied::Flushed ||
                      a == sls::Applied::Bad || a == sls::Applied::Overflow;
    if (!line) return;
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEvSet;
    e.v[0] = static_cast<uint64_t>(u) | (static_cast<uint64_t>(a) << 8) | (static_cast<uint64_t>(op) << 16);
    e.v[1] = p.hash | (static_cast<uint64_t>(now_size) << 32);
    g_ring.push(e);
}

void scene_level_share_on_server_replaced() noexcept {
    if (!g_ingress_on.load(std::memory_order_relaxed)) return;
    g_tracker.flush(User::Host);
    g_tracker.flush(User::User2);
}

}  // namespace cdmp::session2
