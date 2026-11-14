#include "mod/session2/manager_probe.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/fast_travel_logic.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

constexpr uintptr_t kVtManager = 0x5EDE980;  // pa::ServerSequencerStageManager (RTTI, unchanged in 3549)
constexpr uint32_t kState = 0x6D0, kPrepareFlag = 0x6BA, kManagerActor = 0x18, kActorKey = 0x60;
constexpr uint32_t kUserCharacter = 0xD0;
constexpr uintptr_t kImageSize = 0x13CFF000;
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the vtable by RTTI (vtable_map_3549_3576.json), the image size of
// build_profile.h, and the five points at 3549's +0xC50: state 0 is the vtable's +0x18 (0x2AD4D00, .pdata, the same
// 5 bytes), the preparation 0x2ADBCE0 (.pdata, the same 5 bytes), and the three thunks (reset = the vtable's +0x8) whose
// rel32 into the protected section are 3576's own.
constexpr uintptr_t kVtManager3576 = 0x5EE0B88;
// Build 1.0.0.3663 (static, 2026-11-13; never run): the vtable 0x5F5A758 by RTTI (vtable_map_3576_3663.json). The
// manager grew by 8 bytes: state 0 (the vtable's +0x18, 0x2B391F0, .pdata, the same 5 bytes) writes [rdi+0x6D8] = 0
// (0x2B39244); the three thunks' protected targets write it too: "unload asked" 0x2B3E530 -> 0xE8AD010 writes 1
// (0xE8AD055), "armed" 0x2B3FF00 -> 0xE8B3A30 writes 2 (0xE8B3D45), reset = the vtable's +0x8 (0x2B3F500 ->
// 0xE8AD380); the preparation 0x2B3F9B0 (.pdata, the same 5 bytes; reset +0x4B0 as in 3576) sets its flag at +0x6C2
// (0x2B3FC58; 3527's +0x6BA, the same 0x16 below the state). The manager's +0x18 (actor) is 3527's, not re-derived.
constexpr uintptr_t kVtManager3663 = 0x5F5A758;
constexpr uint32_t kState3663 = 0x6D8, kPrepareFlag3663 = 0x6C2;
constexpr int kLinesPerPoint = 24, kStackPointers = 8;
constexpr size_t kStackScan = 0x400;
constexpr DWORD kSampleMs = 100;

uintptr_t g_base = 0;

struct SafeMem {
    bool ptr(uintptr_t a, uintptr_t& v) const {
        uintptr_t p = 0;
        if (!game::safe_read(a, &p, sizeof p)) return false;
        if (p && (p < 0x10000 || p > 0x00007FFFFFFFFFFFull)) return false;
        v = p;
        return true;
    }
};

enum PointId : uint8_t { kAskUnload, kReset, kArm, kStateZero, kPrepare, kPoints };
constexpr uint8_t kAskUnloadBytes[] = {0xE9, 0xAB, 0x9B, 0x76, 0x0B};
constexpr uint8_t kResetBytes[] = {0xE9, 0xDB, 0x90, 0x76, 0x0B};
constexpr uint8_t kArmBytes[] = {0xE9, 0xCB, 0x9C, 0x76, 0x0B};
constexpr uint8_t kStateZeroBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10};
constexpr uint8_t kPrepareBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10};
// 3576's three thunks (their jmp targets: 0xE2790D0, 0xE27C6A0, 0xE2825D0).
constexpr uint8_t kAskUnloadBytes3576[] = {0xE9, 0x7B, 0xE8, 0x79, 0x0B};
constexpr uint8_t kResetBytes3576[] = {0xE9, 0x6B, 0x0E, 0x7A, 0x0B};
constexpr uint8_t kArmBytes3576[] = {0xE9, 0x9B, 0x63, 0x7A, 0x0B};
// 3663's three thunks (their jmp targets: 0xE8AD010, 0xE8AD380, 0xE8B3A30).
constexpr uint8_t kAskUnloadBytes3663[] = {0xE9, 0xDB, 0xEA, 0xD6, 0x0B};
constexpr uint8_t kResetBytes3663[] = {0xE9, 0x7B, 0xDE, 0xD6, 0x0B};
constexpr uint8_t kArmBytes3663[] = {0xE9, 0x2B, 0x3B, 0xD7, 0x0B};
struct Point {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* name;
};
const Point kPointList[kPoints] = {
    {0x2AD9C00, kAskUnloadBytes, "state 1, unload asked"},
    {0x2ADABE0, kResetBytes, "state 0, reset"},
    {0x2ADB5E0, kArmBytes, "state 2, armed"},
    {0x2AD40B0, kStateZeroBytes, "state 0"},
    {0x2ADB090, kPrepareBytes, "preparation"},
};
const Point kPointList3576[kPoints] = {
    {0x2ADA850, kAskUnloadBytes3576, "state 1, unload asked"},
    {0x2ADB830, kResetBytes3576, "state 0, reset"},
    {0x2ADC230, kArmBytes3576, "state 2, armed"},
    {0x2AD4D00, kStateZeroBytes, "state 0"},
    {0x2ADBCE0, kPrepareBytes, "preparation"},
};
const Point kPointList3663[kPoints] = {
    {0x2B3E530, kAskUnloadBytes3663, "state 1, unload asked"},
    {0x2B3F500, kResetBytes3663, "state 0, reset"},
    {0x2B3FF00, kArmBytes3663, "state 2, armed"},
    {0x2B391F0, kStateZeroBytes, "state 0"},
    {0x2B3F9B0, kPrepareBytes, "preparation"},
};
// Set by probe_thread before any hook goes in, then read only.
const Point* g_points = kPointList;
uintptr_t g_vt_manager = kVtManager, g_image_size = kImageSize;
uint32_t g_state = kState, g_prepare_flag = kPrepareFlag;
SafetyHookMid g_hooks[kPoints];
std::atomic<int> g_lines[kPoints] = {};

void report(PointId id, safetyhook::Context& ctx) noexcept {
    const uintptr_t mgr = ctx.rcx;
    uintptr_t vt = 0, actor = 0, ret = 0;
    if (!game::safe_read(mgr, &vt, sizeof vt) || vt != g_base + g_vt_manager) return;  // only this class
    if (g_lines[id].fetch_add(1, std::memory_order_relaxed) >= kLinesPerPoint) return;
    uint32_t key = 0;
    uint8_t state = 0xFF, flag = 0xFF;
    if (game::safe_read(mgr + kManagerActor, &actor, sizeof actor) && actor) game::safe_read(actor + kActorKey, &key, sizeof key);
    game::safe_read(mgr + g_state, &state, sizeof state);
    game::safe_read(mgr + g_prepare_flag, &flag, sizeof flag);
    game::safe_read(ctx.rsp, &ret, sizeof ret);
    // Candidates, not an unwind: what on the stack points into the game's code, the return address first.
    std::string stack;
    int found = 0;
    for (size_t off = 8; off < kStackScan && found < kStackPointers; off += 8) {
        uintptr_t v = 0;
        if (!game::safe_read(ctx.rsp + off, &v, sizeof v)) break;
        if (v >= g_base + 0x1000 && v < g_base + g_image_size) {
            stack += std::format(" 0x{:X}", v - g_base);
            ++found;
        }
    }
    log::info("ManagerProbe [{}] T{} | manager 0x{:X} of actor 0x{:08X}, state {} flag {} | return exe+0x{:X} | stack{}",
              g_points[id].name, GetCurrentThreadId(), mgr, key, state, flag, ret >= g_base ? ret - g_base : ret, stack);
}

void on_ask_unload(safetyhook::Context& c) noexcept { report(kAskUnload, c); }
void on_reset(safetyhook::Context& c) noexcept { report(kReset, c); }
void on_arm(safetyhook::Context& c) noexcept { report(kArm, c); }
void on_state_zero(safetyhook::Context& c) noexcept { report(kStateZero, c); }
void on_prepare(safetyhook::Context& c) noexcept { report(kPrepare, c); }

struct Watched {
    const char* name;
    uintptr_t manager = 0;
    int state = -1, flag = -1;
};

void sample(Watched& w, uintptr_t user) {
    const SafeMem m;
    uintptr_t actor = 0, mgr = 0;
    if (user && m.ptr(user + kUserCharacter, actor) && actor) {
        if (const auto found = ftl::seq_manager_of(m, actor, g_base + g_vt_manager)) mgr = *found;
    }
    uint8_t state = 0xFF, flag = 0xFF;
    const bool ok = mgr && game::safe_read(mgr + g_state, &state, sizeof state) &&
                    game::safe_read(mgr + g_prepare_flag, &flag, sizeof flag);
    const int s = ok ? state : -1, f = ok ? flag : -1;
    if (mgr == w.manager && s == w.state && f == w.flag) return;
    log::info("ManagerProbe: {}'s manager 0x{:X}: state {} -> {}, flag {} -> {}", w.name, mgr, w.state, s, w.flag, f);
    w.manager = mgr;
    w.state = s;
    w.flag = f;
}

DWORD WINAPI probe_thread(void*) {
    const bool v3576 = game::is_3576();
    const bool v3663 = game::is_3663();
    if (!game::is_3549() && !v3576 && !v3663) {
        log::info("ManagerProbe: only for builds 3549, 3576 and 3663, off");
        return 0;
    }
    if (v3576) {
        g_points = kPointList3576;
        g_vt_manager = kVtManager3576;
        g_image_size = game::kImageSize3576;
    }
    if (v3663) {
        g_points = kPointList3663;
        g_vt_manager = kVtManager3663;
        g_image_size = game::kImageSize3663;
        g_state = kState3663;
        g_prepare_flag = kPrepareFlag3663;
    }
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* profile = game::reader_profile();
    // 3576: the world slot from core_globals_3576.json (reader_profile() is null on 3576). 3663: 0x72451C0
    // (profile_s2.h; two AOB patterns).
    const uintptr_t world_slot = v3663 ? 0x72451C0 : v3576 ? 0x71C0100 : profile ? profile->world_system : 0;
    uintptr_t world = 0;
    while (!world_slot || !game::safe_read(g_base + world_slot, &world, sizeof world) || !world) Sleep(500);
    std::vector<gad::Section> secs;
    int hooked = 0;
    if (p8_exe_sections(g_base, secs)) {
        const safetyhook::MidHookFn fns[kPoints] = {&on_ask_unload, &on_reset, &on_arm, &on_state_zero, &on_prepare};
        for (int i = 0; i < kPoints; ++i) {
            const Point& p = g_points[i];
            if (p8_install_mid(g_base, secs, p.rva, 5, p.bytes, fns[i], g_hooks[i], "ManagerProbe", p.name)) ++hooked;
        }
    }
    log::info("ManagerProbe ON (log only): {} of {} entry points hooked; sampling the managers every {} ms", hooked,
              static_cast<int>(kPoints), kSampleMs);
    Watched host{"the host"}, guest{"user 2"};
    for (;;) {
        uintptr_t u = 0;
        sample(host, server_host_user(u) ? u : 0);
        u = 0;
        sample(guest, server_user2(u) ? u : 0);
        Sleep(kSampleMs);
    }
}

}  // namespace

void manager_probe_start(bool enabled) {
    if (!enabled) return;
    if (const HANDLE t = CreateThread(nullptr, 0, probe_thread, nullptr, 0, nullptr)) {
        CloseHandle(t);
    } else {
        log::error("ManagerProbe: no thread ({})", GetLastError());
    }
}

}  // namespace cdmp::session2
