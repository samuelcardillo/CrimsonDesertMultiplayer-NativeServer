#include "mod/session2/housing_trace.h"
#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <safetyhook.hpp>
#include <string>
#include <utility>
#include <vector>
#include <windows.h>

namespace cdmp::session2 {
namespace {

// Build 3576 (PE 0x6AED2E85), análisis estático del 7-nov: inicios de función (tras relleno int3).
// Mgr<n> = ranura n de la vtable de pa::VHousingManager (0x5905500).
struct Target {
    uint32_t rva;
    const char* name;
    uint32_t events;  // cuántas llamadas se registran con detalle; el resto solo se cuenta
};
constexpr Target kTargets[] = {
    {0x4578F0, "Store2733 (records of a SyncHousingPlacedSceneObjectListAck)", 48},
    {0x17BFA90, "RecordIndexRebuild", 24},
    {0x44FFA0, "Mgr1", 16},
    {0x47A8C0, "Mgr4", 16},
    {0x47A990, "Mgr5", 16},
    {0x47AA80, "Mgr8", 16},
    {0x450C70, "Mgr10", 16},
    {0x451C20, "Mgr11", 24},
    {0x4509D0, "Mgr12", 16},
    {0x451FA0, "Mgr13", 16},
    {0x4520D0, "Mgr14", 24},
    {0x4682F0, "Mgr22", 16},
    {0x4683E0, "Mgr23", 24},
    {0x468B20, "Mgr24", 16},
    {0x452480, "Mgr26", 16},
    {0x452940, "Mgr27", 16},
    {0x459800, "Mgr31 (stage list)", 32},
    {0x45F430, "Mgr32", 32},
    {0x461610, "Mgr33", 32},
    {0x462730, "Mgr34 (gimmick record)", 32},
    {0x462DD0, "Mgr35", 32},
    {0x45EFA0, "LeaveEditStage", 32},
    {0x461740, "SyncStage", 32},
    {0x45A6C0, "CommitEdit", 24},
    {0xA57E90, "EditAction", 24},
    {0xA6A9C0, "SetStageState", 48},
    {0xA52790, "HouseList", 24},
    {0xA49010, "HouseListCaller", 24},
    {0x460AA0, "PlaceObject", 48},
    {0x464170, "Validate", 16},
    {0x469970, "Fn469970", 24},
    {0x45CE80, "Fn45CE80", 24},
    {0x453000, "Fn453000", 24},
    // Session 9 (host): approaching the house ran 0x45EB60 -> Mgr32 -> PlaceObject once per record (282).
    {0x45EB60, "EnterStage", 24},
    {0x461A60, "RebuildActiveStage", 24},
    {0x45F110, "ClearAndBuild", 24},
    {0x465E20, "ResetContext", 24},
    {0xA600C0, "RebuildCaller", 24},
    {0xA65080, "ProximityTick", 4},
};
constexpr size_t kN = std::size(kTargets);
// Build 1.0.0.3663 (static, 2026-11-13): NOT ported; housing_trace stays 3576-only. Found so far (see housing_redraw.cpp
// for the evidence of the first three): Store2733 0x475BB0, RebuildActiveStage 0x480E90, RebuildCaller 0xA94860,
// RecordIndexRebuild 0x1828F00 (the store's call with flags 3 or 4), the VHousingManager 0x5981808 slots (Mgr1 0x46E330,
// Mgr4 0x4ACC20, Mgr5 0x4ACDC0, Mgr8 0x4ACF40, Mgr10 0x46F000, Mgr11 0x46FFB0, Mgr12 0x46ED60, Mgr13 0x470370, Mgr14
// 0x470490, Mgr22 0x499140, Mgr23 0x499230, Mgr24 0x499970, Mgr26 0x4709D0, Mgr27 0x470E90, Mgr31 0x477B40, Mgr32
// 0x47D770 (a byte 00 before it, not int3: this file's start check would skip it), Mgr33 0x480470, Mgr34 0x4909B0, Mgr35
// 0x490FC0), EnterStage 0x47CDE0 (adds to +0xA8, sets +0xA0, then Mgr32), LeaveEditStage 0x47D220 (+0x440 after it as
// in 3576: removes from +0xA8, +0xA0 = -1, then Mgr33), ClearAndBuild 0x47D390 (+0x5B0 as in 3576: the nearest active
// stage, Mgr33 on the old, Mgr32 on the new), SyncStage 0x480B80 (bumps +0xA4, calls the sender 0xCD3220; Mgr33's last
// call). In 3663 Mgr32 is a 0xF9-byte wrapper around 0x484F40 and no per-record PlaceObject call was found (inlined?);
// ResetContext, PlaceObject, Validate, CommitEdit, EditAction, SetStageState, HouseList, HouseListCaller, ProximityTick
// (0xA9A190 calls EnterStage / LeaveEditStage / ClearAndBuild: a candidate), Fn469970, Fn45CE80 and Fn453000 are not
// resolved.

struct Event {
    uint64_t ms = 0;
    uint64_t rcx = 0, rdx = 0, r8 = 0, r9 = 0, ret = 0;
    uint32_t tid = 0;
    uint16_t target = 0;
};

uintptr_t g_base = 0;
uint64_t g_t0 = 0;
std::array<std::atomic<uint64_t>, kN> g_count{};
std::array<SafetyHookMid, kN> g_hooks;
std::atomic<uint64_t> g_lost{0};
SRWLOCK g_lock = SRWLOCK_INIT;
std::array<Event, 512> g_ring{};
size_t g_read = 0, g_write = 0, g_size = 0;

void push(const Event& e) noexcept {
    // Never wait inside the game's code: a contended or full ring loses the event (counted).
    if (!TryAcquireSRWLockExclusive(&g_lock)) {
        g_lost.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (g_size == g_ring.size()) {
        g_lost.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_ring[g_write] = e;
        g_write = (g_write + 1) % g_ring.size();
        ++g_size;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void hit(size_t i, SafetyHookContext& c) noexcept {
    const uint64_t n = g_count[i].fetch_add(1, std::memory_order_relaxed);
    if (n >= kTargets[i].events) return;
    Event e;
    e.ms = GetTickCount64() - g_t0;
    e.rcx = c.rcx;
    e.rdx = c.rdx;
    e.r8 = c.r8;
    e.r9 = c.r9;
    game::fast_read(c.rsp, &e.ret, sizeof e.ret);  // at the first instruction [rsp] is the return address
    e.tid = GetCurrentThreadId();
    e.target = static_cast<uint16_t>(i);
    push(e);
}

template <size_t I>
void on_hit(SafetyHookContext& c) {
    hit(I, c);
}
template <size_t... I>
constexpr std::array<safetyhook::MidHookFn, kN> make_fns(std::index_sequence<I...>) {
    return {&on_hit<I>...};
}
constexpr auto kFns = make_fns(std::make_index_sequence<kN>{});

std::string where(uint64_t a) {
    if (a >= g_base && a < g_base + 0x20000000) return std::format("exe+0x{:X}", a - g_base);
    return std::format("0x{:X}", a);
}

DWORD WINAPI flush_thread(LPVOID) {
    std::array<uint64_t, kN> shown{};
    uint64_t last_summary = 0;
    for (;;) {
        Sleep(250);
        std::vector<Event> out;
        AcquireSRWLockExclusive(&g_lock);
        while (g_size) {
            out.push_back(g_ring[g_read]);
            g_read = (g_read + 1) % g_ring.size();
            --g_size;
        }
        ReleaseSRWLockExclusive(&g_lock);
        for (const Event& e : out) {
            log::info("HousingTrace +{}.{:03} T{} {} | rcx 0x{:X} rdx 0x{:X} r8 0x{:X} r9 0x{:X} | from {}", e.ms / 1000,
                      e.ms % 1000, e.tid, kTargets[e.target].name, e.rcx, e.rdx, e.r8, e.r9, where(e.ret));
        }
        const uint64_t now = GetTickCount64();
        if (now - last_summary < 10000) continue;
        last_summary = now;
        std::string s;
        for (size_t i = 0; i < kN; ++i) {
            const uint64_t c = g_count[i].load(std::memory_order_relaxed);
            if (c == shown[i]) continue;
            s += std::format(" | {} {} (+{})", kTargets[i].name, c, c - shown[i]);
            shown[i] = c;
        }
        if (!s.empty()) log::info("HousingTrace counts{}{}", s, g_lost.load() ? std::format(" | lost {}", g_lost.load()) : "");
    }
}

}  // namespace

namespace {
void install(uintptr_t base) {
    g_base = base;
    g_t0 = GetTickCount64();
    size_t on = 0;
    for (size_t i = 0; i < kN; ++i) {
        // A function start: int3 padding before it, real code at it.
        uint8_t b[2] = {};
        if (!game::safe_read(base + kTargets[i].rva - 1, b, 2) || b[0] != 0xCC || b[1] == 0xCC) {
            log::warn("HousingTrace: {} (exe+0x{:X}) is not a function start in this build; skipped", kTargets[i].name,
                      kTargets[i].rva);
            continue;
        }
        g_hooks[i] = safetyhook::create_mid(reinterpret_cast<void*>(base + kTargets[i].rva), kFns[i]);
        if (!g_hooks[i]) {
            log::warn("HousingTrace: cannot hook {} (exe+0x{:X}); skipped", kTargets[i].name, kTargets[i].rva);
            continue;
        }
        ++on;
    }
    if (!on) return;
    if (HANDLE t = CreateThread(nullptr, 0, flush_thread, nullptr, 0, nullptr)) CloseHandle(t);
    log::info("HousingTrace ON (housing_trace=1): {} of {} housing functions counted, the first calls of each logged "
              "with their arguments (observation only)",
              on, kN);
}

// Both roles: the guest does not take the host's late-init path, so this waits for the game itself.
DWORD WINAPI install_thread(LPVOID) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    constexpr uintptr_t kWorldSlot3576 = 0x71C0100;
    uintptr_t world = 0;
    while (!game::safe_read(base + kWorldSlot3576, &world, sizeof world) || !world) Sleep(500);
    install(base);
    return 0;
}
}  // namespace

void housing_trace_start(bool on) {
    if (!on) return;
    if (!game::is_3576()) {
        log::warn("HousingTrace: housing_trace is for build 3576 only; off");
        return;
    }
    if (HANDLE t = CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr)) CloseHandle(t);
}

}  // namespace cdmp::session2
