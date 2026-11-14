#include "mod/session2/guest_shop_window.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_seq_route.h"

namespace cdmp::session2 {
namespace {

// Build 3549 (capstone + live reads on the host, 2026-11-06); see guest_shop_window.h.
struct Addrs {
    uintptr_t vt_buy_store, set_npc, show, handle, dispatch, ui_hub;
};
constexpr Addrs k3549{0x59ECA30, 0xE8BD20, 0xE8C020, 0x71C0E0, 0x6CCA40, 0x71BDF40};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run):
// - the window's vtable 0x59EEB08 (RTTI UIGamePlayControlRootNpcBuyStore2); its +0x498 = 0xE8C140 (writes +0x2F0 /
//   +0x2F4 as 3549's), +0x490 = 0xE8C440 (both +0x420);
// - the dispatcher 0x6CD0A0 (+0x660; the same head, [rcx+0x1A] first, the refcount test at the same +0x97), called at
//   0x6A66D0 with the list [[[0x71C0150]+0x28]+0xA38] read at 0x6A66A5 (3549's 0x6A6045 + 0x660);
// - the handle 0x71C740 (+0x660; (0, out, key): key 0 = an empty 0x20-byte handle, else through [[0x71C0100]+0x30];
//   called by the subscriber 0xFFAF70 = 3549's 0xFFAB10 + 0x460, as 3549's was).
// The two functions this module calls directly are checked by their heads below before the first call (kHandleHead3576,
// kDispatchHead3576; 3549 calls them unchecked, as before).
constexpr Addrs k3576{0x59EEB08, 0xE8C140, 0xE8C440, 0x71C740, 0x6CD0A0, 0x71C0150};
// Build 1.0.0.3663 (static, 2026-11-13; never run):
// - the window's vtable 0x5A6AE58 (RTTI UIGamePlayControlRootNpcBuyStore2, 172 slots as in 3576); its +0x498 =
//   0xEC5F40 (mov [rbx+0x2F0],ecx at 0xEC5F88, lea rdi,[rcx+0x2F4] at 0xEC5F64), +0x490 = 0xEC6210 (the show: command type
//   [r9], 0x15 with its kind-0xE parameters at 0xEC6242..0xEC6265);
// - the dispatcher 0x6F8D30: kDispatchHead3576's 42 bytes, unique in the code section; its five callers pass (rdx =
//   [actor+0x60], r8 / r9 window / control, [rsp+0x20] stage*, [rsp+0x28] cmd*), three of them with the list
//   [[[0x7245210]+0x28]+0xA38] (0x6CCBA2..0x6CCBC3, 0x6CD139..0x6CD15D, 0x6D2505..0x6D2529);
// - the handle 0x748890: kHandleHead3576's 27 bytes, unique; key 0 = the empty handle (0x7488A8..0x7488DF), else
//   through [[0x72451C0]+0x30] (0x7488F2).
// The heads of both are 3576's, checked the same way before the first call. The window's +0x130 (shown) and its node
// +0x08 / +0x100 (the body's name) are 3549's live values, not re-derived.
constexpr Addrs k3663{0x5A6AE58, 0xEC5F40, 0xEC6210, 0x748890, 0x6F8D30, 0x7245210};
constexpr uint8_t kHandleHead3576[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
                                       0x50, 0x48, 0x8B, 0xDA, 0x33, 0xFF, 0x89, 0x7C, 0x24, 0x20, 0x45, 0x85, 0xC0};
constexpr uint8_t kDispatchHead3576[] = {0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x18, 0x49, 0x89, 0x73, 0x20, 0x89, 0x54, 0x24,
                                         0x10, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x4D,
                                         0x8B, 0xF1, 0x4D, 0x8B, 0xF8, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x80, 0x79, 0x1A, 0x00};
Addrs g_a = k3549;
constexpr uint32_t kSlotShow = 0x490, kSlotSetNpc = 0x498;
constexpr uint32_t kW_Node = 0x08, kNode_Body = 0x100, kW_NpcKey = 0x2F0, kW_Shown = 0x130;
constexpr char kBody[] = "NpcStoreBuyBody";
constexpr uint32_t kDelayAfterWorldMs = 90000;

uintptr_t g_base = 0, g_world_slot = 0;
std::atomic<bool> g_started{false}, g_dispatch{false};
// The functions called directly are the expected code (3549: not checked, as before; 3576: their heads, by the worker).
std::atomic<bool> g_code_ok{false};
std::atomic<uint64_t> g_press_stage{0};
std::atomic<uintptr_t> g_window{0};
std::atomic<uint64_t> g_presses{0}, g_opened{0}, g_not_store{0}, g_faults{0}, g_reshown{0};
std::atomic<uint64_t> g_reshow_until{0};  // ms tick: a re-show is due at the next own-scene InputBlock before this
std::atomic<uint32_t> g_reshow_key{0};

template <class T>
T rd(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return a >= 0x10000 && game::safe_read(a, &v, sizeof v) ? v : fallback;
}

bool body_is(uintptr_t w, const char* name, size_t n) noexcept {
    const uintptr_t node = rd<uintptr_t>(w + kW_Node);
    const uintptr_t body = node ? rd<uintptr_t>(node + kNode_Body) : 0;
    char buf[32] = {};
    if (!body || n >= sizeof buf || !game::safe_read(body, buf, n + 1)) return false;
    return std::memcmp(buf, name, n + 1) == 0;
}

bool head_is(uintptr_t rva, const uint8_t* bytes, size_t n) noexcept {
    uint8_t buf[64] = {};
    return n <= sizeof buf && game::safe_read(g_base + rva, buf, n) && std::memcmp(buf, bytes, n) == 0;
}

// Every 8-aligned qword of the private RW memory equal to the window's vtable.
void scan(std::vector<uintptr_t>& out) {
    const uint64_t needle = g_base + g_a.vt_buy_store;
    uintptr_t a = 0x10000;
    MEMORY_BASIC_INFORMATION m{};
    while (a < 0x7FFFFFFF0000ull && VirtualQuery(reinterpret_cast<void*>(a), &m, sizeof m) == sizeof m) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(m.BaseAddress);
        if (m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && m.Protect == PAGE_READWRITE) {
            for (uintptr_t p = base; p + 8 <= base + m.RegionSize; p += 0x10000) {
                uint64_t chunk[0x2000];
                const size_t n = static_cast<size_t>(std::min<uintptr_t>(sizeof chunk, base + m.RegionSize - p));
                if (!game::safe_read(p, chunk, n)) continue;
                for (size_t i = 0; i < n / 8; ++i) {
                    if (chunk[i] == needle && out.size() < 64) out.push_back(p + i * 8);
                }
            }
        }
        a = base + m.RegionSize;
    }
}

DWORD WINAPI worker(LPVOID) {
    try {
        for (int i = 0; i < 2400 && g_world_slot; ++i) {
            uintptr_t world = 0;
            if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
            Sleep(500);
        }
        Sleep(kDelayAfterWorldMs);
        if (game::is_3576() || game::is_3663()) {  // 3663: the same heads (k3663)
            const bool ok = head_is(g_a.handle, kHandleHead3576, sizeof kHandleHead3576) &&
                            head_is(g_a.dispatch, kDispatchHead3576, sizeof kDispatchHead3576);
            if (!ok) {
                log::error("GuestShopWindow: 0x{:X} / 0x{:X} are not this build's expected code; off", g_a.handle,
                           g_a.dispatch);
                return 0;
            }
        }
        g_code_ok.store(true);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        // The windows are made some time after the world is up (live 08:50: none 90 s after the world pointer, three a
        // few minutes later): scanned every 30 s until the one is found, and again if it goes away.
        uint64_t last = 0;
        int scans = 0;
        for (;;) {
            const uintptr_t cur = g_window.load();
            if (!cur || rd<uintptr_t>(cur) != g_base + g_a.vt_buy_store) {
                const uint64_t t0 = GetTickCount64();
                std::vector<uintptr_t> hits;
                scan(hits);
                uintptr_t pick = 0;
                for (const uintptr_t w : hits) {
                    if (!pick && body_is(w, kBody, sizeof kBody - 1)) pick = w;
                }
                g_window.store(pick);
                if (pick || ++scans <= 2 || scans % 10 == 0) {
                    log::info("GuestShopWindow: {} object(s) with the buy window's vtable (scan {} ms); the '{}' one: 0x{:X}{}",
                              hits.size(), GetTickCount64() - t0, kBody, pick, pick ? "" : " (none yet: scanned again in 30 s)");
                }
                Sleep(30000);
                continue;
            }
            Sleep(60000);
            const uint64_t now = g_presses.load();
            if (now == last) continue;
            last = now;
            log::info("GuestShopWindow summary: presses on NPCs {} | windows opened {} | not a store NPC {} | faults {}", now,
                      g_opened.load(), g_not_store.load(), g_faults.load());
        }
    } catch (...) {
        log::error("GuestShopWindow: the worker stopped (exception)");
    }
    return 0;
}

using FnHandle = void*(__fastcall*)(void*, void*, uint32_t);
using FnSetNpc = void(__fastcall*)(void*, void*, void*);
using FnShow = void(__fastcall*)(void*, void*, void*, void*);
struct HandleList {
    void* p;
    uint32_t n, cap;
};
struct Cmd {
    uint8_t type;
    uint8_t pad[7];
    void* params;
    uint32_t n, cap;
    uint64_t spare[3];
};

// The game's staticstringA representation: char* to +0x18, length, -1, refcount (negative = static: never counted nor
// freed, 0x521740 / 0x6CCAD7), then the text. Ours live forever.
struct StaticRep {
    const char* data;
    uint32_t len;
    uint32_t hash;
    int32_t refs;
    uint32_t flags;
    char text[32];
};
StaticRep g_prefab_store{nullptr, 16, 0xFFFFFFFFu, -1, 0, "PrefabTag(Store)"};
struct Variant {
    uint8_t type;
    uint8_t pad[7];
    StaticRep* rep;
};
struct Param {
    uint8_t kind;
    uint8_t pad[7];
    Variant* v;
    uint32_t n, cap;
};
Variant g_tab_variant{5, {}, &g_prefab_store};
Param g_tab_param{0x0E, {}, &g_tab_variant, 1, 1};

// Command 21 (0x15) as the host's scene sends it after the show (live 08:37): the window's tab 'PrefabTag(Store)'
// (0xE8C020: a kind-0xE parameter, its type-5 variant's text).
void select_tab(uintptr_t w, FnShow show) {
    g_prefab_store.data = g_prefab_store.text;
    Cmd c{};
    c.type = 0x15;
    c.params = &g_tab_param;
    c.n = 1;
    c.cap = 1;
    show(reinterpret_cast<void*>(w), nullptr, nullptr, &c);
}

// guest_shop_window=2: the same commands as StageChartUIControl events through the dispatcher 0x6CCA40(list, u32
// actor, staticstringA* win, staticstringA* ctrl, u64* stage, cmd*), list [[[0x71BDF40]+0x28]+0xA38] (0x6A6045..),
// as the host's scene sends them (live 08:37): every subscriber of the event sees them, not only the window.
// (3549's dispatcher and hub; 3576's in k3576: g_a.dispatch / g_a.ui_hub.)
StaticRep g_rep_win{nullptr, 15, 0xFFFFFFFFu, -1, 0, "NpcStoreBuyView"};
StaticRep g_rep_ctl{nullptr, 24, 0xFFFFFFFFu, -1, 0, "selector-stagechart-self"};
StaticRep g_rep_zero{nullptr, 1, 0xFFFFFFFFu, -1, 0, "0"};
StaticRep g_rep_key{nullptr, 0, 0xFFFFFFFFu, -1, 0, ""};
StaticRep g_rep_menu{nullptr, 15, 0xFFFFFFFFu, -1, 0, "ButtonListPanel"};
StaticRep* g_obj_win = &g_rep_win;
StaticRep* g_obj_menu = &g_rep_menu;
StaticRep* g_obj_ctl = &g_rep_ctl;
Variant g_v_zero{5, {}, &g_rep_zero};
Variant g_v_target[3] = {{4, {}, &g_rep_key}, {5, {}, &g_rep_zero}, {7, {}, &g_rep_zero}};
Param g_p9[2] = {{0, {}, &g_v_zero, 1, 1}, {5, {}, g_v_target, 3, 3}};
Param g_p14[1] = {{0, {}, &g_v_zero, 1, 1}};
Param g_p21[2] = {{0, {}, &g_v_zero, 1, 1}, {0x0E, {}, &g_tab_variant, 1, 1}};
using FnDispatch = void(__fastcall*)(void*, uint32_t, void*, void*, uint64_t*, Cmd*);

void reps_ready() {
    for (StaticRep* r : {&g_rep_win, &g_rep_ctl, &g_rep_zero, &g_rep_key, &g_prefab_store, &g_rep_menu}) r->data = r->text;
}
// One event; false = no list or a fault (caught).
bool dispatch_seh(uint32_t actor, uint64_t stage, uint8_t type, Param* params, uint32_t n, StaticRep** win = &g_obj_win) noexcept {
    __try {
        const uintptr_t hub = *reinterpret_cast<uintptr_t*>(g_base + g_a.ui_hub);
        const uintptr_t h28 = hub ? *reinterpret_cast<uintptr_t*>(hub + 0x28) : 0;
        void* list = h28 ? *reinterpret_cast<void**>(h28 + 0xA38) : nullptr;
        if (!list) return false;
        Cmd c{};
        c.type = type;
        c.params = params;
        c.n = n;
        c.cap = n;
        uint64_t st = stage;
        reinterpret_cast<FnDispatch>(g_base + g_a.dispatch)(list, actor, win, &g_obj_ctl, &st, &c);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
// 9 (the shopkeeper, by its key as text), 14 (show), 21 (the Store tab): the host scene's 'Buy' minus the key guide.
int dispatch_open(uint32_t npc_key, uint64_t stage, bool with_npc) {
    const uint32_t actor = guest_seq_route_own_key();
    if (!actor) return -2;
    reps_ready();
    const int n = std::snprintf(g_rep_key.text, sizeof g_rep_key.text, "%u ", npc_key);
    g_rep_key.len = n > 0 ? static_cast<uint32_t>(n) : 0;
    int ok = 0;
    if (with_npc) ok += dispatch_seh(actor, stage, 9, g_p9, 2);
    ok += dispatch_seh(actor, stage, 0x0E, g_p14, 1);
    ok += dispatch_seh(actor, stage, 0x15, g_p21, 2);
    return ok;
}

// Hide (0xF) then show (0xE) again: the window's element is re-evaluated under the scene's UI phase.
bool reshow_seh(uintptr_t w) noexcept {
    __try {
        const uintptr_t vt = *reinterpret_cast<uintptr_t*>(w);
        const auto show = reinterpret_cast<FnShow>(*reinterpret_cast<uintptr_t*>(vt + kSlotShow));
        Cmd cf{};
        cf.type = 0x0F;
        show(reinterpret_cast<void*>(w), nullptr, nullptr, &cf);
        Cmd ce{};
        ce.type = 0x0E;
        show(reinterpret_cast<void*>(w), nullptr, nullptr, &ce);
        select_tab(w, show);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 0 = opened, 1 = the NPC is not a store NPC (the window did not take it), 2 = no handle, -1 = fault.
int open_seh(uintptr_t w, uint32_t key) noexcept {
    alignas(16) uint8_t h[0x40] = {};
    __try {
        reinterpret_cast<FnHandle>(g_base + g_a.handle)(nullptr, h, key);
        uintptr_t actor = 0;
        std::memcpy(&actor, h + 8, 8);
        if (!actor) return 2;
        HandleList lst{h, 1, 1};
        Cmd c9{};
        c9.type = 9;
        const uintptr_t vt = *reinterpret_cast<uintptr_t*>(w);
        reinterpret_cast<FnSetNpc>(*reinterpret_cast<uintptr_t*>(vt + kSlotSetNpc))(reinterpret_cast<void*>(w), &lst, &c9);
        void** hv = *reinterpret_cast<void***>(h);
        if (hv) reinterpret_cast<void(__fastcall*)(void*, int)>(hv[0])(h, 0);
        if (*reinterpret_cast<uint32_t*>(w + kW_NpcKey) != key) return 1;
        Cmd ce{};
        ce.type = 0x0E;
        const auto show = reinterpret_cast<FnShow>(*reinterpret_cast<uintptr_t*>(vt + kSlotShow));
        show(reinterpret_cast<void*>(w), nullptr, nullptr, &ce);
        select_tab(w, show);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

}  // namespace

void guest_shop_window_start(const std::string& mode, bool guest) {
    if (mode != "1" && mode != "2") return;
    g_dispatch.store(mode == "2");
    if (!guest) {
        log::info("GuestShopWindow: guest_shop_window is a guest key; ignored on the host");
        return;
    }
    if (!game::is_3549() && !game::is_3576() && !game::is_3663()) {
        log::warn("GuestShopWindow: guest_shop_window is for builds 3549, 3576 and 3663 only; off");
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
    log::info("GuestShopWindow ON (guest_shop_window=1): this client's own press on a shopkeeper opens its buy window "
              "(exe+0x{:X} + show), as the host's scene does on 'Buy'; the window is looked up {} s after the world is up",
              g_a.set_npc, kDelayAfterWorldMs / 1000);
    CloseHandle(CreateThread(nullptr, 0, worker, nullptr, 0, nullptr));
}

void guest_shop_window_on_press(uintptr_t npc_actor, uint32_t npc_key) noexcept {
    if (!g_started.load(std::memory_order_relaxed) || !npc_actor || !npc_key || !guest_remote_live()) return;
    g_presses.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t w = g_window.load(std::memory_order_relaxed);
    if (!g_code_ok.load() || !w || rd<uintptr_t>(w) != g_base + g_a.vt_buy_store) {
        log::warn("GuestShopWindow: press on 0x{:08X} but no buy window known", npc_key);
        return;
    }
    if (rd<uint8_t>(w + kW_Shown)) return;  // already open
    if (g_dispatch.load(std::memory_order_relaxed)) {
        const int sent = dispatch_open(npc_key, g_press_stage.load(), true);
        g_reshow_key.store(npc_key, std::memory_order_relaxed);
        g_reshow_until.store(GetTickCount64() + 8000, std::memory_order_relaxed);
        log::info("GuestShopWindow: shopkeeper 0x{:08X}: {} StageChartUIControl event(s) dispatched to 'NpcStoreBuyView' "
                  "(9, 14, 21; actor 0x{:08X}) | the window now names 0x{:08X}, shown {}",
                  npc_key, sent, guest_seq_route_own_key(), rd<uint32_t>(w + kW_NpcKey), rd<uint8_t>(w + kW_Shown));
        return;
    }
    if (rd<uintptr_t>(rd<uintptr_t>(w) + kSlotSetNpc) != g_base + g_a.set_npc ||
        rd<uintptr_t>(rd<uintptr_t>(w) + kSlotShow) != g_base + g_a.show) {
        log::error("GuestShopWindow: the window's slots are not this build's expected ones; nothing done");
        return;
    }
    const int r = open_seh(w, npc_key);
    if (r == 0) {
        g_opened.fetch_add(1, std::memory_order_relaxed);
        g_reshow_key.store(npc_key, std::memory_order_relaxed);
        g_reshow_until.store(GetTickCount64() + 8000, std::memory_order_relaxed);
        log::info("GuestShopWindow: shopkeeper 0x{:08X}: its buy window opened on this client (window 0x{:X}, CharacterKey "
                  "0x{:X}, thread {})",
                  npc_key, w, rd<uint16_t>(w + 0x2F4), GetCurrentThreadId());
    } else if (r == 1) {
        g_not_store.fetch_add(1, std::memory_order_relaxed);
        log::info("GuestShopWindow: 0x{:08X} is not a store NPC for this window; nothing shown", npc_key);
    } else {
        g_faults.fetch_add(1, std::memory_order_relaxed);
        log::error("GuestShopWindow: 0x{:08X}: {} (nothing more is tried for this press)", npc_key,
                   r == 2 ? "no actor handle" : "a game call faulted (caught)");
    }
}

void guest_shop_window_note_stage(uint64_t stage) noexcept { g_press_stage.store(stage, std::memory_order_relaxed); }

void guest_shop_window_on_scene() noexcept {
    uint64_t until = g_reshow_until.load(std::memory_order_relaxed);
    if (!until || GetTickCount64() > until) return;
    if (!g_reshow_until.compare_exchange_strong(until, 0)) return;  // once
    const uintptr_t w = g_window.load(std::memory_order_relaxed);
    if (!g_code_ok.load() || !w || rd<uintptr_t>(w) != g_base + g_a.vt_buy_store ||
        rd<uint32_t>(w + kW_NpcKey) != g_reshow_key.load()) {
        return;
    }
    if (g_dispatch.load(std::memory_order_relaxed)) {
        // Now under the copy's own id (guest_shop_branch: 0x1F000000 | scene), the scene that plays this UI here.
        const uint64_t copy = 0x1F000000ull | (g_press_stage.load() & 0xFFFFFFull);
        const int sent = dispatch_open(g_reshow_key.load(), copy, true);
        // Probe: the scene menu's own show (ButtonListPanel 14, as the host's scene sends first): does any of the
        // scene's UI show on this client?
        const int menu = dispatch_seh(guest_seq_route_own_key(), copy, 0x0E, g_p14, 1, &g_obj_menu) ? 1 : 0;
        log::info("GuestShopWindow: the shop scene's UI phase began: 9, 14 and 21 dispatched again under the copy 0x{:X} "
                  "({} ok), the menu's show too ({}) | shown {}",
                  copy, sent, menu, rd<uint8_t>(w + kW_Shown));
        return;
    }
    const bool ok = reshow_seh(w);
    if (ok) g_reshown.fetch_add(1, std::memory_order_relaxed);
    log::info("GuestShopWindow: the shop scene's UI phase began: window 0x{:X} {}", w,
              ok ? "hidden and shown again" : "re-show FAULTED (caught)");
}

}  // namespace cdmp::session2
