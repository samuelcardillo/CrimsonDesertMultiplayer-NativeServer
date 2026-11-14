#include "mod/session2/interact_gate.h"

#include <windows.h>
#include <intrin.h>

#include <safetyhook.hpp>

#include <atomic>
#include <charconv>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/gimmick_interact_logic.h"
#include "mod/session2/guest_seq_present.h"
#include "mod/session2/guest_shop_branch.h"
#include "mod/session2/guest_shop_branch_logic.h"
#include "mod/session2/guest_shop_window.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

// Per build: 3549 (capstone on the installed PE, 2026-11-06), 3576 (static, 2026-11-06 evening; not yet run) and 3663
// (k3663 below). The thunk's rel32 is each build's own (the protected section moves), so the module refuses any other
// build.
// 3576: the press handler 0xBCD170 (+0x420; same 10-byte head, and its call at +0x114 is to the new thunk), the thunk
// 0x22E6F50 (jmp rel32 into the protected section), the pre-check's call at the same +0x906 (0xBCDA76), the world slot
// 0x71C0100 (core_globals_3576.json); the chain +0x30 / +0x58 / +0x60 is unchanged (0xBB155A reads +0x30 and its callee
// 0x99EAB0 +0x58).
struct Addrs {
    uintptr_t gate;
    uint8_t gate_bytes[5];
    uintptr_t call_press, call_pre;
    uint8_t call_press_bytes[5], call_pre_bytes[5];
    uintptr_t press, world_slot;
    // The press handler's no-entry exit (mov eax,[rip+d] ; mov [rdx],eax) and its interaction-info call, as offsets in
    // the handler; the info function's table load (mov reg,[rip+d] at tbl_load, the next instruction at tbl_next) and
    // the table's layout: count u32 [t+tbl_count], array [t+tbl_array], entry i at array + i*tbl_stride, its record
    // pointer at entry+tbl_rec, the interaction key at [record+8]. All checked by bytes before use (install()).
    uint32_t no_entry_mov, info_call;
    uint8_t info_call_bytes[5];
    uint32_t tbl_load;
    uint8_t tbl_load_bytes[3];
    uint32_t tbl_next;
    uint8_t tbl_next_bytes[4];
    uint32_t tbl_next_len, tbl_count, tbl_array, tbl_stride, tbl_rec;
};
constexpr Addrs k3549{0x22E62A0, {0xE9, 0xAB, 0xE0, 0x80, 0x0A}, 0xBCCE64, 0xBCD656,
                      {0xE8, 0x37, 0x94, 0x71, 0x01}, {0xE8, 0x45, 0x8C, 0x71, 0x01}, 0xBCCD50, 0,
                      0x46, 0x248, {0x0F, 0xB7, 0x56, 0x10, 0xE8}, 0x15, {0x48, 0x8B, 0x1D}, 0x1C, {0x3B, 0x53, 0x08, 0},
                      3, 0x08, 0x58, 8, 0};
constexpr Addrs k3576{0x22E6F50, {0xE9, 0x3B, 0x14, 0x7F, 0x0A}, 0xBCD284, 0xBCDA76,
                      {0xE8, 0xC7, 0x9C, 0x71, 0x01}, {0xE8, 0xD5, 0x94, 0x71, 0x01}, 0xBCD170, 0x71C0100,
                      0x46, 0x248, {0x0F, 0xB7, 0x56, 0x10, 0xE8}, 0x15, {0x48, 0x8B, 0x1D}, 0x1C, {0x3B, 0x53, 0x08, 0},
                      3, 0x08, 0x58, 8, 0};
// Build 1.0.0.3663 (static, 2026-11-13; never run):
// - the press handler 0xC049F0 (.pdata 0xC049F0-0xC0527D, 0x88D B as 3527's 0x890): the same 10-byte head
//   (kPressHead), rdi = r9 = the entry, r12 = the target, r15 = rdx = the error out, returned at the end (0xC0525F
//   mov rax,r15); [entry+0x10] == 0xFFFF -> the no-entry exit now at +0x48 (lea rbx,[r9+0x10] ; mov eax,0xFFFF ;
//   cmp [rbx],ax first; mov eax,[0x71CFCCC] / mov [rdx],eax at +0x48 / +0x4E); [[world 0x72451C0]+0x30] read twice;
//   the evaluation called at +0x117 (0xC04B07) with (rcx = [[target+0x68]+0x98], rdx = target, r8 = entry, r9 = the
//   result: byte 2 / u32 0 / -1 / 0 as before) and its byte read back right after;
// - the evaluation's thunk 0x2357780: a 5-byte jmp into the protected section (-> 0xCF19F30), exactly two callers in
//   the code section: the press (0xC04B07) and 0x12A4570 (+0x1B0 of 0x12A43C0, the pre-check's role: the same argument
//   setup and the same check of 0x71AEA18 / 0x71AEA88 after the call as the press), so call_pre is 0x12A4570;
// - the interaction info call at +0x249 is now `lea rcx,[rdi+0x10] ; call 0x3DAD70` (a pointer to the index), and
//   0x3DAD70 reads t = [0x7246388] (mov rcx,[rip+d] at +0x8), count [t+0x28] (cmp r8d,[rcx+0x28] at +0xF), entries of
//   0x18 B at [t+0x20], the record at entry+8 (lazily filled; the default record when empty); the press reads
//   [record+8] as the key (0xC04C42 mov edx,[rax+8]);
// - target +0x60 key (0xC04C30), +0x90 the controller (0xCAF8CE mov eax,[actor+0x90] compared with the own user key
//   [[[world]+0x30]+0x58]+0x60, 0xCAF8D4..0xCAF8E8; the same chain at 0xAC86C5); +0x88 the type info with the type at
//   +1 (1399 `mov r,[r+0x88] ; movzx ..,byte [r+1]` in the code section).
constexpr Addrs k3663{0x2357780, {0xE9, 0xAB, 0x27, 0xBC, 0x0A}, 0xC04B07, 0x12A4570,
                      {0xE8, 0x74, 0x2C, 0x75, 0x01}, {0xE8, 0x0B, 0x32, 0x0B, 0x01}, 0xC049F0, 0x72451C0,
                      0x48, 0x249, {0x48, 0x8D, 0x4F, 0x10, 0xE8}, 0x08, {0x48, 0x8B, 0x0D}, 0x0F, {0x44, 0x3B, 0x41, 0x28},
                      4, 0x28, 0x20, 0x18, 8};
const Addrs* g_a = &k3549;  // written once by interact_gate_start, before the worker
constexpr uint32_t kActor_Key = 0x60, kActor_TypeInfo = 0x88, kActor_Controller = 0x90, kEntry_Index = 0x10;
// The press handler 0xBCCD50 (rcx a context, rdx = u32* error out, r8 = the target actor, r9 = the entry; [r9+0x10] u16
// 0xFFFF = none; and TWO stack arguments: every caller writes [rsp+0x20] and [rsp+0x28], and the handler hands the
// first, [rbp+0x120], to 0xABAE00 as its 7th argument, which it reads at 0xABB018): it evaluates (0x22E62A0 at 0xBCCE64) and, on its paths that go on, reaches the 2671 sender 0xABAE00
// in the same call (0x22E7360 -> 0xABE7B0). Head: mov [rsp+8],rbx (5 bytes) | mov [rsp+0x20],r9.
constexpr uint8_t kPressHead[10] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x4C, 0x24, 0x20};
// This client's user key: [[[[exe+WorldSystem]+0x30]+0x58]+0x60] (the chain 0x99E350's callers read).
constexpr uint32_t kWorld_Mgr = 0x30, kMgr_User = 0x58, kUser_Key = 0x60;
constexpr uint32_t kUserMask = 0xFFF00000, kUserTag = 0x90100000;
constexpr uint64_t kMaxLines = 600;

using Arg = uint64_t;
uintptr_t g_base = 0;
std::atomic<bool> g_started{false}, g_guest{false}, g_hooked{false};
std::atomic<uint8_t> g_mode{0};  // gil::Mode (Trace = probe)
gil::Events g_errors;             // written before the hook, read only after
uint8_t g_pass = 3;
// Actor types the press swap applies to (bit n = type n); default 7 only (world objects). NPCs (3, 4) are opt-in: live
// on 2026-11-06 the guest's "Shop" press on a shopkeeper went through (2671 / 2720 accepted, interaction 0x000F4321)
// but the shop window never opened (the host owns that scene) and the shopkeeper stayed turned away.
uint32_t g_types = 1u << 7;
SafetyHookInline g_hook, g_press_hook;
std::atomic<uint64_t> g_calls{0}, g_passed{0}, g_failed{0}, g_middle{0}, g_let{0}, g_lost{0};
std::atomic<uint64_t> g_press_calls{0}, g_swapped{0}, g_restored_late{0}, g_refused_short{0};
std::atomic<bool> g_press_hooked{false};
uintptr_t g_world_slot = 0;
// The press handler's own way out for an entry without an index (+0x3F: cmp word [r9+0x10],0xFFFF / jne / +0x46: mov
// eax,[rip+d] / +0x4C: mov [rdx],eax / jmp to its end, which returns rdx): the absolute address of that error code
// (3576: exe+0x714AEE8 = 0x15DBC102). A refused press ends the same way: the code in *err, err returned, nothing sent.
// 0 = not found: refused presses are then only left unswapped.
uintptr_t g_no_entry_err = 0;  // the mov is at g_a->no_entry_mov (3549 / 3576 +0x46, 3663 +0x48)
// The interaction a press is for: the handler reads its info with `movzx edx, word [rsi+0x10]` / `call` (+0x248, 3576
// 0xBCD3B8 -> 0x3DEEF0), a lazily filled global table: `mov rbx, [rip+d]` at its +0x15 (3576: exe+0x71C1098) ->
// [+8] count, [+0x58] the records; [record+8] the interaction key (0x000F4321 = Shop). 0 = not found.
// 3663: see k3663 (another call and table layout; g_a->info_call and the tbl_* fields).
uintptr_t g_interaction_slot = 0;

struct Rec {
    uint32_t key = 0, ctl = 0, err = 0, entry0 = 0, interaction = 0;
    uint16_t index = 0;
    uint8_t type = 0, code = 0, let = 0, caller = 0;  // caller: 0 press, 1 pre-check, 2 other, 3 swap, 4 refused
};
p8p::EventRing<512> g_ring;

// The caller's result slots (its own frame on this thread): an SEH-guarded write of a byte and a u32.
bool write_result(uintptr_t out, uint8_t code, uint32_t err) noexcept {
    if (out < 0x10000) return false;
    __try {
        *reinterpret_cast<volatile uint8_t*>(out) = code;
        *reinterpret_cast<volatile uint32_t*>(out + 4) = err;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template <class T>
T rd(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return game::safe_read(a, &v, sizeof v) ? v : fallback;
}

uint32_t interaction_key(uint16_t index) noexcept {
    if (!g_interaction_slot || index == 0xFFFF) return 0;
    const uintptr_t t = rd<uintptr_t>(g_interaction_slot);
    if (!t || index >= rd<uint32_t>(t + g_a->tbl_count)) return 0;
    const uintptr_t records = rd<uintptr_t>(t + g_a->tbl_array);
    const uintptr_t rec = records ? rd<uintptr_t>(records + uint64_t{g_a->tbl_stride} * index + g_a->tbl_rec) : 0;
    return rec ? rd<uint32_t>(rec + 8) : 0;
}

bool write_u32(uintptr_t a, uint32_t v) noexcept {
    if (a < 0x10000) return false;
    __try {
        *reinterpret_cast<volatile uint32_t*>(a) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uint32_t own_user() noexcept {
    const uintptr_t world = g_world_slot ? rd<uintptr_t>(g_base + g_world_slot) : 0;
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    const uintptr_t user = mgr ? rd<uintptr_t>(mgr + kMgr_User) : 0;
    return user ? rd<uint32_t>(user + kUser_Key) : 0;
}

// interact_gate=1 on the guest: for the length of one press, a world object or NPC that another user controls is
// this client's ([target+0x90] := own user), the value the server gave put back right after (live test: with the
// object's controller set to the guest's user the press sent 2671 and the server accepted it). Only the press;
// nothing is sent by this hook.
// Six arguments, all forwarded (live 2026-11-06: a 4-argument detour left the handler's 5th argument to whatever was
// on the stack, and one press crashed the guest at 0xABB018 reading 0x30000000).
Arg press_detour(Arg ctx, Arg err, Arg target, Arg entry, Arg a5, Arg a6) {
    g_press_calls.fetch_add(1, std::memory_order_relaxed);
    uint32_t saved = 0, mine = 0, short_nodes = 0;
    bool swapped = false, refused = false;
    uint8_t type = 0;
    if (g_guest.load(std::memory_order_relaxed) &&
        static_cast<gil::Mode>(g_mode.load(std::memory_order_relaxed)) == gil::Mode::On && target) {
        if (const uintptr_t ti = rd<uintptr_t>(target + kActor_TypeInfo)) type = rd<uint8_t>(ti + 1);
        const uint32_t ctl = rd<uint32_t>(target + kActor_Controller);
        mine = own_user();
        // 2026-11-12: a function NPC whose scene has no node gsb::kShopBranch (Vellua's Farm Owner selling from his
        // table: a 3-node chart, the shops have 7; the host gets no 'Shop' there). With the swap the server accepted
        // the guest's 'Shop', and the branch the guest got read past the scene's table: the 7-nov crash, or with the
        // node check a character stuck in the interaction. Without it the press fails as for anyone else's NPC.
        // Only the Shop interaction (2026-11-13: the Vellua carriage driver's scene has 5 branches; his own
        // interaction is not a shop and is left as it was). A key that cannot be read counts as Shop.
        const uint64_t scene = type == 3 || type == 4 ? rd<uint64_t>(entry + 0x20) : 0;
        const uint32_t key = scene ? interaction_key(rd<uint16_t>(entry + kEntry_Index)) : 0;
        refused = scene && (key == gsb::kShopInteraction || key == 0) &&
                  guest_seq_present_funcnpc_nodes(scene, &short_nodes) && short_nodes &&
                  short_nodes <= gsb::kShopBranch;
        if (!refused && mine && ctl && ctl != mine && (ctl & kUserMask) == kUserTag && (mine & kUserMask) == kUserTag &&
            type < 32 && ((g_types >> type) & 1u) != 0 && write_u32(target + kActor_Controller, mine)) {
            saved = ctl;
            swapped = true;
        }
    }
    if (refused) {
        g_refused_short.fetch_add(1, std::memory_order_relaxed);
        uint32_t no_entry = 0;
        const bool ended = g_no_entry_err && game::safe_read(g_no_entry_err, &no_entry, sizeof no_entry) && no_entry &&
                           write_u32(err, no_entry);
        Rec rec;
        rec.key = rd<uint32_t>(target + kActor_Key);
        rec.type = type;
        rec.index = rd<uint16_t>(entry + kEntry_Index);
        rec.entry0 = short_nodes;
        rec.interaction = interaction_key(rec.index);
        rec.err = ended ? no_entry : 0;
        rec.let = ended ? 1 : 0;
        rec.caller = 4;
        p8p::Event e;
        e.qpc_us = p8_now_us();
        e.tid = GetCurrentThreadId();
        std::memcpy(e.v, &rec, sizeof rec);
        if (!g_ring.push(e)) g_lost.fetch_add(1, std::memory_order_relaxed);
        // Live 2026-11-12: unswapped, the game still sent 'Shop' and the server accepted it (stuck again). So the
        // handler is not run at all: it ends as for an entry without an index.
        if (ended) return err;
    }
    const Arg r = g_press_hook.unsafe_call<Arg>(ctx, err, target, entry, a5, a6);
    if (swapped) {
        if (rd<uint32_t>(target + kActor_Controller) == mine) {
            (void)write_u32(target + kActor_Controller, saved);
        } else {
            g_restored_late.fetch_add(1, std::memory_order_relaxed);  // the game wrote it meanwhile: left as it is
        }
        g_swapped.fetch_add(1, std::memory_order_relaxed);
        Rec rec;
        rec.key = rd<uint32_t>(target + kActor_Key);
        rec.ctl = saved;
        rec.type = type;
        rec.err = rd<uint32_t>(err);
        rec.index = rd<uint16_t>(entry + kEntry_Index);
        rec.interaction = interaction_key(rec.index);
        rec.entry0 = mine;
        if (type == 3 || type == 4) {
            guest_shop_note_press(rec.key, rd<uint64_t>(entry + 0x20), target, mine, saved);
            guest_shop_window_note_stage(rd<uint64_t>(entry + 0x20));
            guest_shop_window_on_press(target, rec.key);
        }
        rec.caller = 3;  // the press swap
        p8p::Event e;
        e.qpc_us = p8_now_us();
        e.tid = GetCurrentThreadId();
        std::memcpy(e.v, &rec, sizeof rec);
        if (!g_ring.push(e)) g_lost.fetch_add(1, std::memory_order_relaxed);
    }
    return r;
}

Arg gate_detour(Arg comp, Arg target, Arg entry, Arg out) {
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const Arg r = g_hook.unsafe_call<Arg>(comp, target, entry, out);
    g_calls.fetch_add(1, std::memory_order_relaxed);
    uint8_t code = 0;
    uint32_t err = 0;
    if (!game::safe_read(out, &code, sizeof code) || !game::safe_read(out + 4, &err, sizeof err)) return r;
    Rec rec;
    rec.code = code;
    rec.err = err;
    rec.caller = ret == g_base + g_a->call_press + 5 ? 0 : ret == g_base + g_a->call_pre + 5 ? 1 : 2;
    if (code > 2) {
        if (g_passed.fetch_add(1, std::memory_order_relaxed) >= 8) return r;  // a few passes for comparison
    } else {
        (code == 2 ? g_middle : g_failed).fetch_add(1, std::memory_order_relaxed);
        if (code < g_pass && g_guest.load(std::memory_order_relaxed) &&
            static_cast<gil::Mode>(g_mode.load(std::memory_order_relaxed)) == gil::Mode::On && g_errors.contains(err)) {
            // The caller's own result slots (its frame): the same writes the evaluation makes.
            if (write_result(out, g_pass, 0)) {
                rec.let = 1;
                g_let.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
    rec.key = rd<uint32_t>(target + kActor_Key);
    rec.ctl = rd<uint32_t>(target + kActor_Controller);
    if (const uintptr_t ti = rd<uintptr_t>(target + kActor_TypeInfo)) rec.type = rd<uint8_t>(ti + 1);
    rec.index = rd<uint16_t>(entry + kEntry_Index);
    rec.entry0 = rd<uint32_t>(entry);
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    static_assert(sizeof(Rec) <= sizeof(e.v));
    std::memcpy(e.v, &rec, sizeof rec);
    if (!g_ring.push(e)) g_lost.fetch_add(1, std::memory_order_relaxed);
    return r;
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), actual.size()) == 0;
}

bool install() {
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("InteractGate: the exe's sections are unreadable; not installed");
        return false;
    }
    const struct {
        uintptr_t rva;
        std::span<const uint8_t> bytes;
        const char* what;
    } checks[] = {{g_a->gate, g_a->gate_bytes, "the evaluation's thunk"},
                  {g_a->call_press, g_a->call_press_bytes, "the press's call to it"},
                  {g_a->call_pre, g_a->call_pre_bytes, "the pre-check's call to it"}};
    for (const auto& c : checks) {
        if (!gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
            !bytes_at(c.rva, c.bytes)) {
            log::error("InteractGate: {} (exe+0x{:X}) is not build 3549's expected code; REFUSED, nothing written", c.what,
                       c.rva);
            return false;
        }
    }
    auto whole = [](const std::vector<uint8_t>& o) {
        return o.size() == sizeof g_a->gate_bytes && std::memcmp(o.data(), g_a->gate_bytes, o.size()) == 0;
    };
    auto h = game::prepare_inline(g_base + g_a->gate, reinterpret_cast<void*>(&gate_detour), whole, "InteractGate",
                                  "the interaction evaluation 0x22E62A0");
    if (!h) {
        log::error("InteractGate: the hook could not be prepared ({}); REFUSED", game::inline_error_text(h.error()));
        return false;
    }
    if (!whole(h->original_bytes())) {
        log::error("InteractGate: the hook would patch {} bytes, not the verified 5-byte jmp; REFUSED",
                   h->original_bytes().size());
        return false;
    }
    g_hook = std::move(*h);
    if (!g_hook.enable()) {
        log::error("InteractGate: the hook could not be enabled; REFUSED");
        g_hook = {};
        return false;
    }
    if (g_guest.load() && static_cast<gil::Mode>(g_mode.load()) == gil::Mode::On) {
        auto head5 = [](const std::vector<uint8_t>& o) {
            return o.size() == 5 && std::memcmp(o.data(), kPressHead, o.size()) == 0;
        };
        if (!gad::in_real_code(secs, static_cast<uint32_t>(g_a->press), sizeof kPressHead) || !bytes_at(g_a->press, kPressHead)) {
            log::error("InteractGate: the press handler 0xBCCD50 is not build 3549's expected code; the swap is off");
            return true;
        }
        auto ph = game::prepare_inline(g_base + g_a->press, reinterpret_cast<void*>(&press_detour), head5, "InteractGate",
                                       "the press handler 0xBCCD50");
        if (!ph || !head5(ph->original_bytes())) {
            log::error("InteractGate: the press handler's hook could not be prepared as a 5-byte patch; the swap is off");
            return true;
        }
        // The no-entry exit's error constant, read from the handler's own instruction (bytes checked).
        const uint8_t mov_eax[2] = {0x8B, 0x05}, mov_out[2] = {0x89, 0x02};
        const uint32_t no_entry = g_a->no_entry_mov;
        if (bytes_at(g_a->press + no_entry, mov_eax) && bytes_at(g_a->press + no_entry + 6, mov_out)) {
            int32_t d = 0;
            if (game::safe_read(g_base + g_a->press + no_entry + 2, &d, sizeof d)) {
                g_no_entry_err = g_base + g_a->press + no_entry + 6 + static_cast<intptr_t>(d);
            }
        }
        int32_t rel = 0;
        if (bytes_at(g_a->press + g_a->info_call, g_a->info_call_bytes) &&
            game::safe_read(g_base + g_a->press + g_a->info_call + 5, &rel, sizeof rel)) {
            const uintptr_t fn = g_a->press + g_a->info_call + 9 + static_cast<intptr_t>(rel);  // an RVA
            int32_t d = 0;
            if (bytes_at(fn + g_a->tbl_load, g_a->tbl_load_bytes) &&
                bytes_at(fn + g_a->tbl_next, std::span<const uint8_t>(g_a->tbl_next_bytes, g_a->tbl_next_len)) &&
                game::safe_read(g_base + fn + g_a->tbl_load + 3, &d, sizeof d)) {
                g_interaction_slot = g_base + fn + g_a->tbl_next + static_cast<intptr_t>(d);
            }
        }
        log::info("InteractGate: interaction table {}", g_interaction_slot
                      ? std::format("at exe+0x{:X} (only a 'Shop' press, 0x{:08X}, is refused)", g_interaction_slot - g_base,
                                    gsb::kShopInteraction)
                      : std::string("NOT found (any press on a short function-NPC scene is refused)"));
        if (g_no_entry_err) {
            log::info("InteractGate: the press handler's no-entry exit: error code at exe+0x{:X}; a 'Shop' press on a "
                      "function NPC whose scene has no shop node ends there",
                      g_no_entry_err - g_base);
        } else {
            log::warn("InteractGate: the press handler's no-entry exit was not found: a 'Shop' press on a function NPC "
                      "without a shop node is only left unswapped");
        }
        g_press_hook = std::move(*ph);
        if (!g_press_hook.enable()) {
            log::error("InteractGate: the press handler's hook could not be enabled; the swap is off");
            g_press_hook = {};
            return true;
        }
        g_press_hooked.store(true);
    }
    return true;
}

const char* caller_name(uint8_t c) {
    return c == 0 ? "press 0xBCCD50" : c == 1 ? "pre-check 0xBCD5E0" : c == 3 ? "PRESS SWAP" : "other";
}

DWORD WINAPI worker(LPVOID) {
    try {
        const game::ReaderProfile* profile = game::reader_profile();
        const uintptr_t world_slot = g_a->world_slot ? g_a->world_slot : profile ? profile->world_system : 0;
        for (int i = 0; i < 2400 && world_slot; ++i) {  // WorldSystem (up to 20 minutes), never on the title screen
            uintptr_t world = 0;
            if (game::safe_read(g_base + world_slot, &world, sizeof world) && world) break;
            Sleep(500);
        }
        Sleep(3000);
        g_world_slot = world_slot;
        g_hooked.store(install());
        if (g_hooked.load()) {
            std::string list;
            for (size_t i = 0; i < g_errors.n; ++i) list += std::format("{}0x{:08X}", list.empty() ? "" : ", ", g_errors.hash[i]);
            log::info("InteractGate ({}, interact_gate={}): hooked exe+0x{:X} (5-byte jmp, verified with its two callers) | "
                      "{}",
                      g_guest.load() ? "guest" : "host", gil::mode_name(static_cast<gil::Mode>(g_mode.load())), g_a->gate,
                      g_guest.load() && static_cast<gil::Mode>(g_mode.load()) == gil::Mode::On
                          ? std::format("a failing result with an error in [{}] becomes code {} (pass) | press handler "
                                        "0xBCCD50 {}: during a press on an object or NPC another user controls, its "
                                        "controller is this client's",
                                        list.empty() ? std::string("none listed") : list, g_pass,
                                        g_press_hooked.load() ? "hooked" : "NOT hooked")
                          : std::string("log only"));
        }
        gil::Seen<1024> seen;
        uint64_t lines = 0, not_logged = 0, tick = 0;
        for (;;) {
            Sleep(500);
            p8p::Event e;
            while (g_ring.pop(e)) {
                Rec rec;
                std::memcpy(&rec, e.v, sizeof rec);
                const uint64_t k = (uint64_t{rec.key} << 32) ^ (uint64_t{rec.index} << 16) ^ rec.err ^
                                   (uint64_t{rec.code} << 48) ^ (uint64_t{rec.caller} << 56) ^ (uint64_t{rec.let} << 60);
                const uint32_t n = seen.note(k);
                if (n != 0 && n != gil::Seen<1024>::kFull && !(rec.let && n < 3)) continue;
                if (n == gil::Seen<1024>::kFull && rec.code > 2) continue;
                if (lines++ >= kMaxLines) {
                    ++not_logged;
                    continue;
                }
                if (rec.caller == 4) {
                    log::info("InteractGate {}: press on 0x{:08X} type {} REFUSED: its scene is a function NPC's with {} "
                              "node(s), no node {} (no shop there now; the host gets none either) | entry index {} "
                              "(interaction 0x{:08X}) | {} | thread {}",
                              p8_when(e.qpc_us), rec.key, rec.type, rec.entry0, gsb::kShopBranch, rec.index, rec.interaction,
                              rec.let ? std::format("ended as an entry without an index (error 0x{:08X}): nothing sent", rec.err)
                                      : std::string("only left unswapped (the handler's no-entry exit was not found)"),
                              e.tid);
                    continue;
                }
                if (rec.caller == 3) {
                    log::info("InteractGate {}: PRESS SWAP target 0x{:08X} type {} | controller 0x{:08X} -> this "
                              "client's 0x{:08X} for the press, put back after | entry index {} (interaction 0x{:08X}) | "
                              "the press's error 0x{:08X} | thread {}",
                              p8_when(e.qpc_us), rec.key, rec.type, rec.ctl, rec.entry0, rec.index, rec.interaction, rec.err,
                              e.tid);
                    continue;
                }
                log::info("InteractGate {}: target 0x{:08X} type {} controller 0x{:08X} | entry index {} (+0 0x{:08X}) | "
                          "code {} error 0x{:08X} | {} | {} | thread {}",
                          p8_when(e.qpc_us), rec.key, rec.type, rec.ctl, rec.index, rec.entry0, rec.code, rec.err,
                          caller_name(rec.caller),
                          rec.let ? std::format("LET THROUGH (code {} written)", g_pass)
                                  : rec.code > 2 ? "passes" : rec.code == 2 ? "code 2 (the caller's other branch)"
                                                                           : "fails (the caller sends nothing)",
                          e.tid);
            }
            if (++tick % 120 == 0) {
                log::info("InteractGate summary ({}, interact_gate={}, hook {}): calls {} | passes {} | code 2 {} | fails {} "
                          "| let through {} | presses {} swapped {} (left as the game wrote them {}) | not swapped (no "
                          "shop node) {} | lines {} (not logged {}), ring lost {}",
                          g_guest.load() ? "guest" : "host", gil::mode_name(static_cast<gil::Mode>(g_mode.load())),
                          g_hooked.load() ? "in" : "NOT in", g_calls.load(), g_passed.load(), g_middle.load(),
                          g_failed.load(), g_let.load(), g_press_calls.load(), g_swapped.load(),
                          g_restored_late.load(), g_refused_short.load(), lines, not_logged, g_lost.load());
            }
        }
    } catch (...) {
        log::error("InteractGate: the worker stopped (exception)");
    }
    return 0;
}

}  // namespace

void interact_gate_start(const std::string& mode, const std::string& errors, const std::string& pass,
                         const std::string& types, bool guest) {
    const auto m = gil::parse_mode(mode);
    if (!m) {
        log::warn("InteractGate: interact_gate '{}' is not 0 | probe | 1; it stays off", mode);
        return;
    }
    if (*m == gil::Mode::Off) return;
    if (!game::is_3549() && !game::is_3576() && !game::is_3663()) {
        log::warn("InteractGate: interact_gate is for builds 3549, 3576 and 3663 only (its thunk's rel32 is each build's); "
                  "off");
        return;
    }
    g_a = game::is_3663() ? &k3663 : game::is_3576() ? &k3576 : &k3549;
    const auto ev = gil::parse_events(errors);
    if (!ev) {
        log::warn("InteractGate: interact_gate_errors '{}' is not a list of at most {} hex values; it stays off", errors,
                  gil::kMaxEvents);
        return;
    }
    unsigned p = 3;
    if (!pass.empty()) {
        const auto r = std::from_chars(pass.data(), pass.data() + pass.size(), p);
        if (r.ec != std::errc{} || p < 3 || p > 255) {
            log::warn("InteractGate: interact_gate_pass '{}' is not 3..255; 3 is used", pass);
            p = 3;
        }
    }
    if (g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_errors = *ev;
    g_pass = static_cast<uint8_t>(p);
    uint32_t mask = 0;
    for (size_t i = 0; i < types.size();) {
        size_t j = types.find(',', i);
        if (j == std::string::npos) j = types.size();
        unsigned t = 0;
        const auto r = std::from_chars(types.data() + i, types.data() + j, t);
        if (r.ec == std::errc{} && r.ptr == types.data() + j && t < 32) {
            mask |= 1u << t;
        } else if (j > i) {
            log::warn("InteractGate: interact_gate_types item '{}' is not 0..31; ignored", types.substr(i, j - i));
        }
        i = j + 1;
    }
    g_types = mask ? mask : (1u << 7);
    g_guest.store(guest);
    g_mode.store(static_cast<uint8_t>(*m));
    log::info("InteractGate ON ({}, interact_gate={}, {} error(s) listed, pass code {}, press swap for actor types "
              "mask 0x{:X}): hooked once the world is up",
              guest ? "guest" : "host", gil::mode_name(*m), ev->n, p, g_types);
    CloseHandle(CreateThread(nullptr, 0, worker, nullptr, 0, nullptr));
}

}  // namespace cdmp::session2
