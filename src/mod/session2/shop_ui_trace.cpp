#include "mod/session2/shop_ui_trace.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstring>
#include <format>
#include <map>
#include <mutex>
#include <span>
#include <string>
#include <tuple>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

// Build 3549 (capstone on the installed PE, 2026-11-06); see shop_ui_trace.h. The hooked heads below are the same on
// 3576; the addresses per build are in Addrs (k3549 / k3576, after the hooks' own comments).
struct Addrs {
    uintptr_t ui_control, set_npc, fn_ib, fn_ui, exec, node_event, stage_step;
    // StageChart_Function_* vtables (RTTI), fn_name's order.
    uintptr_t vt_keep_aggro, vt_set_battle_target, vt_set_aggro, vt_timeline_event, vt_change_phase_panel_tag,
        vt_ui_control, vt_input_block, vt_change_pivot, vt_set_variable, vt_activate_mini_game,
        vt_deactivate_camera_fade_in;
};
constexpr Addrs k3549{0x6CCA40, 0xE8BD20, 0x255C110, 0x255C800, 0x2202A60, 0x21FDE10, 0x2BA1420,
                      0x5D43058, 0x5D430C0, 0x5D43128, 0x5D43190, 0x5D431F8, 0x5D43260, 0x5D432C8, 0x5D43330,
                      0x5D43398, 0x5D43538, 0x5D444C8};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). Every head is 3549's, each address a whole function's move:
// - UIControl dispatch 0x6CD0A0 (+0x660): the same head, [rcx+0x1A] first, the refcount test at the same +0x97; its
//   caller 0x6A66D0 reads the list [[[0x71C0150]+0x28]+0xA38] (3549's 0x6A6045 + 0x660);
// - the shop window's setter 0xE8C140 (+0x420) = slot +0x498 of UIGamePlayControlRootNpcBuyStore2's vtable 0x59EEB08;
// - the InputBlock / UIControl vf8 thunks 0x255CEE0 / 0x255D5D0 (+0xDD0) = slot 8 of StageChart_Function_InputBlock
//   0x5D45A58 / _UIControl 0x5D459F0 (jmp [proc_vt+0x158] / [+0x160], as 3549's);
// - the stage step 0x2BA2090 (+0xC70; .pdata begins there) calls the node event 0x21FEA50 (+0xC40) at the same +0x1940;
// - the executor 0x22036A0 (+0xC40, as the node event): [node+0x38] -> +0x48 / +0x50, node +0x68 / +0x78, call
//   [rax+0x40] (the functions' vf8); the other function with that head nearby (0x2203AF0) is +0x1090.
// - the StageChart_Function_* vtables by RTTI (vtable_map_3549_3576.json).
constexpr Addrs k3576{0x6CD0A0, 0xE8C140, 0x255CEE0, 0x255D5D0, 0x22036A0, 0x21FEA50, 0x2BA2090,
                      0x5D457E8, 0x5D45850, 0x5D458B8, 0x5D45920, 0x5D45988, 0x5D459F0, 0x5D45A58, 0x5D45AC0,
                      0x5D45B28, 0x5D451D0, 0x5D46128};
// Build 1.0.0.3663 (static, 2026-11-13; never run). Every hooked head is 3549's (checked before each hook, as before):
// - UIControl dispatch 0x6F8D30 (kDispatchHead3576 of guest_shop_window, unique; [rcx+0x1A] first; callers read the
//   list [[[0x7245210]+0x28]+0xA38]) and the window's setter 0xEC5F40 = slot +0x498 of UIGamePlayControlRootNpcBuyStore2
//   0x5A6AE58 (RTTI);
// - the InputBlock / UIControl vf8 thunks 0x25CE760 / 0x25CEE70 = slot 8 of StageChart_Function_InputBlock 0x5DC1240 /
//   _UIControl 0x5DC11D8 (mov rax,[rdx] ; mov r8,rcx ; mov rcx,[rax+0x60] ; jmp [rax+0x158] / [+0x160]);
// - the executor 0x2272840 (.pdata, head kExecBytes): r15 = rcx the node, [node+0x38] -> +0x48 / +0x50 (0x22728C9),
//   the functions' +0x10 / +0x14 windows, call [rax+0x40] (0x2272A3E), node +0x68 / +0x78 (+0x60 / +0x70 lists), r9b
//   the timed phase; the other function with that head 0x450 after it (0x2272C90), as in 3576;
// - the node event 0x226DB80 (head kNodeEventBytes; [rcx+0x38] its definition, the event u32* at entry [rsp+0x28], the
//   u8 at [rsp+0x30], the pointer at [rsp+0x40]), called at +0x1950 (0x2C09310; 3576 +0x1940) by the stage step
//   0x2C079C0 (head kStageStepBytes, 0x1BA5 B; the only function with that head and a call to the node event there);
// - the StageChart_Function_* vtables by RTTI (vtable_map_3576_3663.json).
constexpr Addrs k3663{0x6F8D30, 0xEC5F40, 0x25CE760, 0x25CEE70, 0x2272840, 0x226DB80, 0x2C079C0,
                      0x5DC0FD0, 0x5DC1038, 0x5DC10A0, 0x5DC1108, 0x5DC1170, 0x5DC11D8, 0x5DC1240, 0x5DC12A8,
                      0x5DC1310, 0x5DC0A58, 0x5DC1B48};
Addrs g_a = k3549;
// mov r11,rsp ; mov [r11+0x18],rbx
constexpr uint8_t kUiControlBytes[7] = {0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x18};
constexpr uint32_t kUiControlPatch = 7;
// The setter: mov [rsp+8],rbx
constexpr uint8_t kSetNpcBytes[5] = {0x48, 0x89, 0x5C, 0x24, 0x08};
constexpr uint32_t kSetNpcPatch = 5;
constexpr uint32_t kDelayAfterWorldMs = 150000;
constexpr uint32_t kMaxLines = 600;
constexpr uint32_t kPerKey = 4;

uintptr_t g_base = 0, g_world_slot = 0;
std::atomic<bool> g_started{false}, g_guest{false};
SafetyHookMid g_ui_hook, g_npc_hook, g_fn_ib_hook, g_fn_ui_hook;
// The chart functions' vf8 thunks (mov rax,[rdx] ; mov r8,rcx ; ... jmp [proc_vt+slot]): InputBlock (+0x158) and
// UIControl (+0x160). Their caller is the chart's function executor. 3549: 0x255C110 / 0x255C800 (g_a.fn_ib / fn_ui).
constexpr uint8_t kFnThunkBytes[6] = {0x48, 0x8B, 0x02, 0x4C, 0x8B, 0xC1};
std::atomic<uint32_t> g_fn_lines{0};
// The chart's function executor 0x2202A60(node, ?, ctx source, u8 timed phase) (its entry; see ESTADO-3527.md, 6-nov
// afternoon): node+0x10 = the stage, [node+0x38] = the node's definition, [[node+0x38]+0x48] its functions (count
// +0x50; each: vtable, +0x10 / +0x14 its time window), node+0x68 / +0x78 the counts of executed / pending timed ones.
// Armed for 25 s on a stage by its InputBlock (the shop scene's first node): every node definition it runs is logged
// once per phase. Log only. (g_a.exec)
constexpr uint8_t kExecBytes[7] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10};  // mov rax,rsp ; mov [rax+0x10],rbx
SafetyHookMid g_exec_hook;
std::atomic<uintptr_t> g_arm_stage{0};
std::atomic<uint64_t> g_arm_until{0};
std::atomic<uint32_t> g_node_lines{0};
std::mutex g_node_mx;
std::map<std::pair<uintptr_t, uint8_t>, uint32_t> g_node_seen;
std::atomic<uint32_t> g_event_lines{0}, g_step_lines{0};
std::string node_functions(uintptr_t def);  // below
std::atomic<uint64_t> g_ui_calls{0}, g_npc_calls{0};
std::atomic<uint32_t> g_lines{0};
std::mutex g_mx;
std::map<std::tuple<uint32_t, std::string, std::string, uint32_t>, uint32_t> g_seen;

template <class T>
T rd(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return a >= 0x10000 && game::safe_read(a, &v, sizeof v) ? v : fallback;
}
// A NUL-terminated printable string at p (at most 96 characters), or "" when unreadable.
std::string cstr(uintptr_t p) {
    std::string s;
    if (p < 0x10000) return s;
    for (size_t off = 0; off < 96; off += 8) {
        char b[8];
        if (!game::safe_read(p + off, b, sizeof b)) break;
        for (char c : b) {
            if (c == 0) return s;
            if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return s + "?";
            s.push_back(c);
        }
    }
    return s;
}
// staticstringA* -> its text (*(char**)*p, the subagent's reading of 0x6CCAD7), else "".
std::string sstr(uintptr_t p) { return cstr(rd<uintptr_t>(rd<uintptr_t>(p))); }

std::string hex(uintptr_t a, size_t n) {
    if (a < 0x10000) return "-";
    std::string out;
    for (size_t off = 0; off < n; off += 8) {
        uint64_t q = 0;
        if (!game::safe_read(a + off, &q, sizeof q)) return out + " ?";
        out += std::format("{}{:016X}", off ? " " : "", q);
    }
    return out;
}
// The raw objects of one UIControl call (for building one of our own, guest_shop_window).
std::string raw_dump(uintptr_t win, uintptr_t ctl, uintptr_t stage_p, uintptr_t cmd) {
    std::string out = std::format("win@{:X}[{}] rep[{}] | ctl@{:X}[{}] rep[{}] | stage[{}] | cmd@{:X}[{}]", win, hex(win, 16),
                                  hex(rd<uintptr_t>(win), 0x28), ctl, hex(ctl, 16), hex(rd<uintptr_t>(ctl), 0x28),
                                  hex(stage_p, 8), cmd, hex(cmd, 0x30));
    const uintptr_t arr = rd<uintptr_t>(cmd + 8);
    const uint32_t n = rd<uint32_t>(cmd + 0x10);
    for (uint32_t i = 0; i < n && i < 6 && arr; ++i) {
        const uintptr_t p = arr + i * 0x18ull;
        const uint8_t tag = rd<uint8_t>(p);
        const uintptr_t q1 = rd<uintptr_t>(p + 8);
        out += std::format(" | p{}@{:X}[{}] q1[{}]", i, p, hex(p, 0x18), hex(q1, 0x28));
        if (tag == 5) {
            const uint32_t m = rd<uint32_t>(p + 0x10);
            for (uint32_t k = 0; k < m && k < 4 && q1; ++k) {
                const uintptr_t sub = q1 + k * 0x10ull;
                out += std::format(" sub{}[{}] rep[{}] '{}'", k, hex(sub, 0x10), hex(rd<uintptr_t>(sub + 8), 0x28),
                                   sstr(sub + 8));
            }
        }
    }
    return out;
}

std::string params(uintptr_t cmd) {
    std::string out;
    const uintptr_t arr = rd<uintptr_t>(cmd + 8);
    const uint32_t n = rd<uint32_t>(cmd + 0x10);
    out += std::format("{} param(s)", n);
    for (uint32_t i = 0; i < n && i < 6 && arr; ++i) {
        const uintptr_t p = arr + i * 0x18ull;
        const uint8_t tag = rd<uint8_t>(p);
        const uint64_t q1 = rd<uint64_t>(p + 8), q2 = rd<uint64_t>(p + 0x10);
        out += std::format(" | [{}] tag {} q 0x{:X} 0x{:X}", i, tag, q1, q2);
        if (tag == 4) {
            std::string s = sstr(p + 8);
            if (s.empty()) s = cstr(q1);
            out += std::format(" '{}'", s);
        } else if (tag == 5) {
            const uint32_t m = static_cast<uint32_t>(q2);
            for (uint32_t k = 0; k < m && k < 4 && q1; ++k) {
                const uintptr_t sub = q1 + k * 0x10ull;
                out += std::format(" <{} '{}'>", rd<uint8_t>(sub), sstr(sub + 8));
            }
        }
    }
    return out;
}

void ui_control_mid(safetyhook::Context& ctx) {
    g_ui_calls.fetch_add(1, std::memory_order_relaxed);
    if (g_lines.load(std::memory_order_relaxed) >= kMaxLines) return;
    try {
        const uintptr_t ret = rd<uintptr_t>(ctx.rsp);
        const uint32_t actor = static_cast<uint32_t>(ctx.rdx);
        const std::string win = sstr(ctx.r8), ctl = sstr(ctx.r9);
        const uintptr_t stage_p = rd<uintptr_t>(ctx.rsp + 0x28), cmd = rd<uintptr_t>(ctx.rsp + 0x30);
        const uint64_t stage = rd<uint64_t>(stage_p);
        const uint32_t type = rd<uint8_t>(cmd);
        {
            std::lock_guard lk(g_mx);
            auto& n = g_seen[{actor, win, ctl, type}];
            if (++n > kPerKey && (stage >> 24) != 0x1F) return;  // a copy of guest_shop_branch is always logged
        }
        g_lines.fetch_add(1, std::memory_order_relaxed);
        log::info("ShopUiTrace ({}) UIControl from exe+0x{:X}: actor 0x{:08X} | window '{}' control '{}' | scene 0x{:X} | "
                  "list 0x{:X} queued {} | command type {} (0x{:X}) {}",
                  g_guest.load() ? "guest" : "host", ret - g_base, actor, win, ctl, stage, ctx.rcx,
                  rd<uint8_t>(ctx.rcx + 0x1A), type, cmd, params(cmd));
        log::info("ShopUiTrace raw: {}", raw_dump(ctx.r8, ctx.r9, stage_p, cmd));
    } catch (...) {
    }
}

void set_npc_mid(safetyhook::Context& ctx) {
    g_npc_calls.fetch_add(1, std::memory_order_relaxed);
    if (g_lines.load(std::memory_order_relaxed) >= kMaxLines) return;
    try {
        g_lines.fetch_add(1, std::memory_order_relaxed);
        const uintptr_t lst = ctx.rdx;
        const uintptr_t h = rd<uintptr_t>(lst);
        const uint32_t n = rd<uint32_t>(lst + 8);
        const uintptr_t actor = h ? rd<uintptr_t>(h + 8) : 0;
        log::info("ShopUiTrace ({}) window 0x{:X} (vtable exe+0x{:X}) takes {} actor(s), first 0x{:08X} | r8 0x{:X} | from "
                  "exe+0x{:X}",
                  g_guest.load() ? "guest" : "host", ctx.rcx, rd<uintptr_t>(ctx.rcx) - g_base, n,
                  actor ? rd<uint32_t>(actor + 0x60) : 0, ctx.r8, rd<uintptr_t>(ctx.rsp) - g_base);
        log::info("ShopUiTrace raw window: list[{}] h[{}] window[{}]", hex(lst, 0x10), hex(h, 0x18), hex(ctx.rcx, 0x40));
    } catch (...) {
    }
}

template <bool UI>
void fn_mid(safetyhook::Context& ctx) {
    if (const uintptr_t stage = rd<uintptr_t>(ctx.rdx)) {
        if (g_arm_stage.exchange(stage, std::memory_order_relaxed) != stage) {
            {
                std::lock_guard lk(g_node_mx);
                g_node_seen.clear();
            }
            g_node_lines.store(0, std::memory_order_relaxed);  // a new stage: its own budget
            g_event_lines.store(0, std::memory_order_relaxed);
            g_step_lines.store(0, std::memory_order_relaxed);
            // The executor's node is r15 (the thunk leaves it alone): the node that armed it.
            if (rd<uintptr_t>(ctx.r15 + 0x10) == stage) {
                log::info("ShopUiTrace ({}) {} armed stage 0x{:X} from node 0x{:X} def 0x{:X} | {}",
                          g_guest.load() ? "guest" : "host", UI ? "UIControl" : "InputBlock", stage, ctx.r15,
                          rd<uintptr_t>(ctx.r15 + 0x38), node_functions(rd<uintptr_t>(ctx.r15 + 0x38)));
            }
        }
        g_arm_until.store(GetTickCount64() + 25000, std::memory_order_relaxed);
    }
    if (g_fn_lines.fetch_add(1, std::memory_order_relaxed) >= 60) return;
    try {
        const uintptr_t fn = ctx.rcx;
        // The return addresses into the exe among the first 0x400 bytes of the stack (the callers' chain, roughly).
        std::string chain;
        int found = 0;
        for (uintptr_t off = 0; off < 0x3000 && found < 40; off += 8) {
            const uintptr_t v = rd<uintptr_t>(ctx.rsp + off);
            if (v > g_base + 0x1000 && v < g_base + 0x10000000) {
                chain += std::format(" +{:X}:{:X}", off, v - g_base);
                ++found;
            }
        }
        log::info("ShopUiTrace ({}) chart function {} stack:{}", g_guest.load() ? "guest" : "host", UI ? "UIControl" : "InputBlock", chain);
        log::info("ShopUiTrace ({}) chart function {} vf8 from exe+0x{:X} | function 0x{:X} (vtable exe+0x{:X}) [{}] | ctx 0x{:X} "
                  "[{}] | stage 0x{:X} seq 0x{:X}",
                  g_guest.load() ? "guest" : "host", UI ? "UIControl" : "InputBlock", rd<uintptr_t>(ctx.rsp) - g_base, fn,
                  rd<uintptr_t>(fn) - g_base, hex(fn, 0x60), ctx.rdx, hex(ctx.rdx, 0x30), rd<uintptr_t>(ctx.rdx),
                  rd<uint64_t>(rd<uintptr_t>(ctx.rdx) + 0x60));
    } catch (...) {
    }
}

// RTTI names of the chart function vtables seen in the shop scene (3549): StageChart_Function_*.
const char* fn_name(uintptr_t vt) {
    const uintptr_t r = vt - g_base;
    if (r == g_a.vt_keep_aggro) return "KeepAggro";
    if (r == g_a.vt_set_battle_target) return "SetBattleTarget";
    if (r == g_a.vt_set_aggro) return "SetAggro";
    if (r == g_a.vt_timeline_event) return "TimelineEvent";
    if (r == g_a.vt_change_phase_panel_tag) return "ChangePhasePanelTag";
    if (r == g_a.vt_ui_control) return "UIControl";
    if (r == g_a.vt_input_block) return "InputBlock";
    if (r == g_a.vt_change_pivot) return "ChangePivot";
    if (r == g_a.vt_set_variable) return "SetVariable";
    if (r == g_a.vt_activate_mini_game) return "ActivateMiniGame";
    if (r == g_a.vt_deactivate_camera_fade_in) return "DeactivateSequencerCameraFadeIn";
    return "";
}
std::string node_functions(uintptr_t def) {
    const uintptr_t arr = rd<uintptr_t>(def + 0x48);
    const uint32_t n = rd<uint32_t>(def + 0x50);
    std::string fns = std::format("{} function(s):", n);
    for (uint32_t i = 0; i < n && i < 24; ++i) {
        const uintptr_t fn = rd<uintptr_t>(arr + 8ull * i);
        const uintptr_t vt = rd<uintptr_t>(fn);
        const char* name = fn_name(vt);
        fns += std::format(" [{} vt exe+0x{:X}{}{} t {:.2f}..{:.2f}]", i, vt ? vt - g_base : 0, *name ? " " : "", name,
                           rd<float>(fn + 0x10), rd<float>(fn + 0x14));
    }
    return fns;
}
// The node's event entry 0x21FDE10(node, rdx, r8, r9, const u32* event, u8, ?, ptr) (its entry): every event delivered
// to the armed stage's nodes, with the node's definition. (g_a.node_event)
constexpr uint8_t kNodeEventBytes[5] = {0x48, 0x89, 0x5C, 0x24, 0x08};  // mov [rsp+8],rbx
SafetyHookMid g_event_hook;
void event_mid(safetyhook::Context& ctx) {
    const uintptr_t armed = g_arm_stage.load(std::memory_order_relaxed);
    if (!armed || GetTickCount64() > g_arm_until.load(std::memory_order_relaxed)) return;
    const uintptr_t node = ctx.rcx;
    if (rd<uintptr_t>(node + 0x10) != armed) return;
    if (g_event_lines.fetch_add(1, std::memory_order_relaxed) >= 120) return;
    try {
        const uintptr_t ev_p = rd<uintptr_t>(ctx.rsp + 0x28);
        log::info("ShopUiTrace ({}) node event 0x{:08X} (rdx 0x{:X} r8 0x{:X} r9 0x{:X} a6 {} a8 0x{:X}) to node 0x{:X} def "
                  "0x{:X} (stage 0x{:X}) from exe+0x{:X} | {}",
                  g_guest.load() ? "guest" : "host", rd<uint32_t>(ev_p), ctx.rdx, ctx.r8, ctx.r9,
                  rd<uint8_t>(ctx.rsp + 0x30), rd<uintptr_t>(ctx.rsp + 0x40), node, rd<uintptr_t>(node + 0x38), armed,
                  rd<uintptr_t>(ctx.rsp) - g_base, node_functions(rd<uintptr_t>(node + 0x38)));
    } catch (...) {
    }
}

// 0x2BA1420(stage, u32* result, r8, r9d, ...) (its entry): on the host it is the caller of the node step 0x21FDE10
// (return address 0x2BA2D65) when the shop scene goes from its first node to the menu node, 2 s after branch 6. Every
// call for the armed stage is logged with its caller. (g_a.stage_step)
constexpr uint8_t kStageStepBytes[7] = {0x48, 0x8B, 0xC4, 0x44, 0x89, 0x48, 0x20};  // mov rax,rsp ; mov [rax+0x20],r9d
SafetyHookMid g_step_hook;
void step_mid(safetyhook::Context& ctx) {
    const uintptr_t armed = g_arm_stage.load(std::memory_order_relaxed);
    if (!armed || GetTickCount64() > g_arm_until.load(std::memory_order_relaxed) || ctx.rcx != armed) return;
    if (g_step_lines.fetch_add(1, std::memory_order_relaxed) >= 60) return;
    try {
        std::string chain;
        int found = 0;
        for (uintptr_t off = 0; off < 0x800 && found < 16; off += 8) {
            const uintptr_t v = rd<uintptr_t>(ctx.rsp + off);
            if (v > g_base + 0x1000 && v < g_base + 0x10000000) {
                chain += std::format(" +{:X}:{:X}", off, v - g_base);
                ++found;
            }
        }
        log::info("ShopUiTrace ({}) stage step exe+0x{:X} for stage 0x{:X} (r8 0x{:X} r9 0x{:X} a5 0x{:X} a6 0x{:X}) T{} "
                  "| stack:{}",
                  g_guest.load() ? "guest" : "host", g_a.stage_step, ctx.rcx, ctx.r8, ctx.r9, rd<uint64_t>(ctx.rsp + 0x28),
                  rd<uint64_t>(ctx.rsp + 0x30), GetCurrentThreadId(), chain);
    } catch (...) {
    }
}

void exec_mid(safetyhook::Context& ctx) {
    const uintptr_t armed = g_arm_stage.load(std::memory_order_relaxed);
    if (!armed || GetTickCount64() > g_arm_until.load(std::memory_order_relaxed)) return;
    const uintptr_t node = ctx.rcx;
    if (rd<uintptr_t>(node + 0x10) != armed) return;
    try {
        const uintptr_t def = rd<uintptr_t>(node + 0x38);
        const uint8_t phase = static_cast<uint8_t>(ctx.r9);
        {
            std::lock_guard lk(g_node_mx);
            if (g_node_seen[{def, phase}]++ != 0) return;
        }
        if (g_node_lines.fetch_add(1, std::memory_order_relaxed) >= 150) return;
        log::info("ShopUiTrace ({}) node def 0x{:X} (node 0x{:X}, stage 0x{:X}, timed phase {}) from exe+0x{:X}: executed {} "
                  "pending {} | {}",
                  g_guest.load() ? "guest" : "host", def, node, armed, phase, rd<uintptr_t>(ctx.rsp) - g_base,
                  rd<uint32_t>(node + 0x68), rd<uint32_t>(node + 0x78), node_functions(def));
    } catch (...) {
    }
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), actual.size()) == 0;
}

DWORD WINAPI worker(LPVOID) {
    try {
        for (int i = 0; i < 2400 && g_world_slot; ++i) {
            uintptr_t world = 0;
            if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
            Sleep(500);
        }
        Sleep(kDelayAfterWorldMs);
        std::vector<gad::Section> secs;
        if (!p8_exe_sections(g_base, secs) || !bytes_at(g_a.ui_control, kUiControlBytes) ||
            !bytes_at(g_a.set_npc, kSetNpcBytes)) {
            log::error("ShopUiTrace: exe+0x{:X} / exe+0x{:X} are not this build's expected code; not installed",
                       g_a.ui_control, g_a.set_npc);
            return 0;
        }
        const bool a = p8_install_mid(g_base, secs, g_a.ui_control, kUiControlPatch, kUiControlBytes, &ui_control_mid,
                                      g_ui_hook, "ShopUiTrace", "the StageChartUIControl dispatch");
        const bool b = p8_install_mid(g_base, secs, g_a.set_npc, kSetNpcPatch, kSetNpcBytes, &set_npc_mid, g_npc_hook,
                                      "ShopUiTrace", "the shop window's shopkeeper setter");
        log::info("ShopUiTrace ({}): UIControl hook {} | shop window hook {} | log only", g_guest.load() ? "guest" : "host",
                  a ? "in" : "NOT in", b ? "in" : "NOT in");
        const bool c = bytes_at(g_a.fn_ib, kFnThunkBytes) &&
                       p8_install_mid(g_base, secs, g_a.fn_ib, 6, kFnThunkBytes, &fn_mid<false>, g_fn_ib_hook,
                                      "ShopUiTrace", "the InputBlock chart function's vf8");
        const bool d = bytes_at(g_a.fn_ui, kFnThunkBytes) &&
                       p8_install_mid(g_base, secs, g_a.fn_ui, 6, kFnThunkBytes, &fn_mid<true>, g_fn_ui_hook,
                                      "ShopUiTrace", "the UIControl chart function's vf8");
        const bool e = bytes_at(g_a.exec, kExecBytes) &&
                       p8_install_mid(g_base, secs, g_a.exec, 7, kExecBytes, &exec_mid, g_exec_hook, "ShopUiTrace",
                                      "the chart's function executor (its entry)");
        const bool f = bytes_at(g_a.node_event, kNodeEventBytes) &&
                       p8_install_mid(g_base, secs, g_a.node_event, 5, kNodeEventBytes, &event_mid, g_event_hook,
                                      "ShopUiTrace", "the chart node's event entry");
        const bool g = bytes_at(g_a.stage_step, kStageStepBytes) &&
                       p8_install_mid(g_base, secs, g_a.stage_step, 7, kStageStepBytes, &step_mid, g_step_hook,
                                      "ShopUiTrace", "the stage step (its entry)");
        log::info("ShopUiTrace: chart function hooks: InputBlock {} | UIControl {} | executor (node trace) {} | node events {} "
                  "| stage step {}",
                  c ? "in" : "NOT in", d ? "in" : "NOT in", e ? "in" : "NOT in", f ? "in" : "NOT in", g ? "in" : "NOT in");
        uint64_t last = 0;
        for (;;) {
            Sleep(60000);
            const uint64_t now = g_ui_calls.load() + g_npc_calls.load();
            if (now == last) continue;
            last = now;
            log::info("ShopUiTrace summary ({}): UIControl calls {} | shop window calls {} | lines {}",
                      g_guest.load() ? "guest" : "host", g_ui_calls.load(), g_npc_calls.load(), g_lines.load());
        }
    } catch (...) {
        log::error("ShopUiTrace: the worker stopped (exception)");
    }
    return 0;
}

}  // namespace

void shop_ui_trace_start(const std::string& mode, bool guest) {
    if (mode != "1") return;
    if (!game::is_3549() && !game::is_3576() && !game::is_3663()) {
        log::warn("ShopUiTrace: shop_ui_trace is for builds 3549, 3576 and 3663 only; off");
        return;
    }
    if (g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (game::is_3663()) {
        g_a = k3663;
        g_world_slot = 0x72451C0;  // docs/research/port-3663.md (two AOB patterns)
    } else if (game::is_3576()) {
        g_a = k3576;
        g_world_slot = 0x71C0100;  // core_globals_3576.json (no reader profile for 3576 yet)
    } else if (const auto* profile = game::reader_profile()) {
        g_world_slot = profile->world_system;
    }
    g_guest.store(guest);
    log::info("ShopUiTrace ON ({}, shop_ui_trace=1): log-only hooks {} s after the world is up", guest ? "guest" : "host",
              kDelayAfterWorldMs / 1000);
    CloseHandle(CreateThread(nullptr, 0, worker, nullptr, 0, nullptr));
}

}  // namespace cdmp::session2
