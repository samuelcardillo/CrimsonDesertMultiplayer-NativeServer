#include "mod/session2/housing_redraw.h"
#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <span>
#include <safetyhook.hpp>
#include <windows.h>

namespace cdmp::session2 {
namespace {

// Build 3576 (PE 0x6AED2E85), 7-nov, housing_trace on both copies:
// - 0x4578F0(manager, flags u8, stage key u32, records): the data of a SyncHousingPlacedSceneObjectListAck part (the
//   2733 handler 0xCBF0B0 calls it); flags 1 = first of several, 3 = last, 4 = only part.
// - 0x461A60(manager, stage index): rebuilds the active stage (its bounds from the active list +0xA8, the entry's object
//   count +0x70 to 0, 0x465E20, then 0x45F430 = Mgr32, which places every record with 0x460AA0). The client calls it
//   from 0xA600C0. Approaching the house runs 0x45EB60 -> 0x45F430 the same way.
// - [manager+0xA0]: the active stage index, -1 when none.
constexpr uintptr_t kActiveStage = 0xA0;
// The build's addresses (chosen once by housing_redraw_start, before the install thread): the 2733 store, the active
// stage's rebuild, the world slot, slot 35 and its head.
struct Addrs {
    uintptr_t store, rebuild, world_slot, mgr35;
    std::span<const uint8_t> mgr35_head;
};

using RebuildFn = void(__fastcall*)(uintptr_t manager, uint32_t stage);

// housing_gimmick_guard: pa::VHousingManager slot 35, 0x462DD0(manager, gimmick actor), the owner's update of a gimmick
// placed by its house (called from 0x9F1181 for every gimmick with a housing sync id, [+0x41C] != -1). With the host's
// house re-keyed to the guest and its gimmick records kept, the guest's client is the owner of gimmicks it never
// spawned (its own spawn requests 2492/2446 are dropped): their elements in the stage entry's list (+0x68) lack what
// the owner's spawn fills in, and slot 35 read them as null (0x46313D [+0x28], 0x4632EA [+0x68]; 7-nov sessions 2 and 4,
// when the host opened the construction mode). The guest skips it: those gimmicks are the host's.
constexpr uint8_t kMgr35Head[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x50, 0x10, 0x55, 0x56, 0x57};
constexpr Addrs k3576{0x4578F0, 0x461A60, 0x71C0100, 0x462DD0, kMgr35Head};
// Build 1.0.0.3663 (static, 2026-11-13; never run):
// - the store 0x475BB0 (int3 before it; .pdata 0x475BB0-0x476169): its only caller is 0xCF7B86 in
//   TrocTrSyncHousingPlacedSceneObjectListAck's entry 2 0xCF7740 (vtable 0x5A16498 by RTTI) (rcx the housing manager
//   [[[[0x72451B8]+0x30]+0x1230]+0x90]+0x230, dl the flags, r8d the stage key, r9 the records), after the same owner
//   test ([owner+0x88]+1 == 1, [owner+0x96] != 0); it copies 0xAC-B records and, with flags 3 or 4 (sub al,3 ; cmp al,1
//   at 0x4760FC), calls 0x1828F00 (the index rebuild, 3576 0x17BFA90);
// - the rebuild 0x480E90 (int3 before it): (manager, stage): it requires a non-empty active list (+0xA8, 0x2C-B
//   entries, count +0xB0) and stage == [manager+0xA0], takes the bounds from the list, zeroes the stage entry's +0x70,
//   then rebuilds through 0x484F40 (the body that Mgr32 0x47D770 runs under its lock); its only caller is 0xA948BA
//   (0xA94860, 3576's 0xA600C0, with [rbx+0x230]); EnterStage 0x47CDE0 also writes +0xA0 (0x47D183) and the
//   proximity selection 0x47D390 rewrites it (0x47D5A7): +0xA0 is the active stage index, -1 none;
// - slot 35 of pa::VHousingManager 0x5981808 (RTTI) = 0x490FC0, called at 0xA21192 under the same test
//   [gimmick+0x41C] != -1 with (the housing manager [[[[0x72451C0]+0x20]+0x1230]+0x90]+0x230, [gimmick+8]); the caller
//   ignores its result (rax overwritten at 0xA21197). Its head is another encoding of 3576's (mov [rsp+8],rbx ;
//   mov [rsp+0x10],rdx ; push rbp/rsi/rdi/r12); the hook patches the first instruction (5 bytes);
// - the world slot 0x72451C0.
constexpr uint8_t kMgr35Head3663[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54};
constexpr Addrs k3663{0x475BB0, 0x480E90, 0x72451C0, 0x490FC0, kMgr35Head3663};
const Addrs* g_a = &k3576;  // written once by housing_redraw_start, before the install thread
SafetyHookInline g_mgr35;
std::atomic<uint64_t> g_mgr35_skipped{0};

uintptr_t __fastcall mgr35_detour(uintptr_t manager, uintptr_t gimmick, uintptr_t, uintptr_t) {
    const uint64_t n = g_mgr35_skipped.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n <= 3 || n % 100 == 0) {
        log::info("HousingGimmickGuard: the owner's update of a housing gimmick (slot 35) skipped on the guest "
                  "(gimmick 0x{:X}, manager 0x{:X}) (#{})", gimmick, manager, n);
    }
    return 0;
}

uintptr_t g_base = 0;
SafetyHookInline g_store;
std::atomic<bool> g_live{true};
std::atomic<uint64_t> g_rebuilds{0}, g_faults{0};

bool rebuild(uintptr_t manager, uint32_t stage) noexcept {
    __try {
        reinterpret_cast<RebuildFn>(g_base + g_a->rebuild)(manager, stage);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uintptr_t __fastcall store_detour(uintptr_t manager, uint32_t flags, uint32_t stage_key, uintptr_t records) {
    const uintptr_t r = g_store.call<uintptr_t>(manager, flags, stage_key, records);
    const uint8_t f = static_cast<uint8_t>(flags);
    if ((f != 3 && f != 4) || !g_live.load(std::memory_order_relaxed)) return r;
    int32_t active = -1;
    if (!game::fast_read(manager + kActiveStage, &active, sizeof active) || active < 0) return r;
    if (rebuild(manager, static_cast<uint32_t>(active))) {
        const uint64_t n = g_rebuilds.fetch_add(1) + 1;
        log::info("HousingRedraw: house stage {} rebuilt after a 2733 (stage key 0x{:X}, flags {}) (#{})", active,
                  stage_key, f, n);
    } else {
        g_faults.fetch_add(1);
        g_live.store(false);
        log::error("HousingRedraw: the rebuild of stage {} faulted; housing_redraw is off for this session", active);
    }
    return r;
}

bool g_want_redraw = false, g_want_guard = false;

void install_guard() {
    uint8_t head[32] = {};
    const std::span<const uint8_t> want = g_a->mgr35_head;
    if (want.size() > sizeof head || !game::safe_read(g_base + g_a->mgr35, head, want.size()) ||
        std::memcmp(head, want.data(), want.size()) != 0) {
        log::warn("HousingGimmickGuard: exe+0x{:X} is not the expected code; off", g_a->mgr35);
        return;
    }
    g_mgr35 = safetyhook::create_inline(reinterpret_cast<void*>(g_base + g_a->mgr35), reinterpret_cast<void*>(&mgr35_detour));
    if (!g_mgr35) {
        log::warn("HousingGimmickGuard: cannot hook exe+0x{:X}; off", g_a->mgr35);
        return;
    }
    log::info("HousingGimmickGuard ON (housing_gimmick_guard=1, guest): the owner's update of the house's gimmicks "
              "(slot 35) is skipped here: with the host's house as this client's own, those gimmicks are the host's");
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uintptr_t world = 0;
    while (!game::safe_read(g_base + g_a->world_slot, &world, sizeof world) || !world) Sleep(500);
    if (g_want_guard) install_guard();
    if (!g_want_redraw) return 0;
    for (const uintptr_t at : {g_a->store, g_a->rebuild}) {
        uint8_t b[2] = {};
        if (!game::safe_read(g_base + at - 1, b, 2) || b[0] != 0xCC || b[1] == 0xCC) {
            log::warn("HousingRedraw: exe+0x{:X} is not the expected function start; off", at);
            return 0;
        }
    }
    g_store = safetyhook::create_inline(reinterpret_cast<void*>(g_base + g_a->store), reinterpret_cast<void*>(&store_detour));
    if (!g_store) {
        log::warn("HousingRedraw: cannot hook exe+0x{:X}; off", g_a->store);
        return 0;
    }
    log::info("HousingRedraw ON (housing_redraw=1, experimental): after the last part of a house list (2733) the active "
              "house stage is rebuilt, so the host's edits show without joining again");
    return 0;
}

}  // namespace

void housing_redraw_start(bool redraw, bool gimmick_guard) {
    if (!redraw && !gimmick_guard) return;
    if (!game::is_3576() && !game::is_3663()) {
        log::warn("HousingRedraw: housing_redraw and housing_gimmick_guard are for builds 3576 and 3663 only; off");
        return;
    }
    g_a = game::is_3663() ? &k3663 : &k3576;
    g_want_redraw = redraw;
    g_want_guard = gimmick_guard;
    if (HANDLE t = CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr)) CloseHandle(t);
}

}  // namespace cdmp::session2
