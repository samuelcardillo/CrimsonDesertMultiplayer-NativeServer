#include "mod/session2/seq_marker.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <format>
#include <string>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest.h"
#include "mod/session2/seq_marker_logic.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

constexpr DWORD kLookMs = 50;
constexpr int kDetailedRestores = 20;
constexpr uint64_t kSummaryMs = 60'000;
// Build 1.0.0.3527: pa::ClientSequencerStageManager's vtable and the fields read here (guest.cpp read_preload_facts).
constexpr uintptr_t kVtManager3527 = 0x59572E0;
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the same class's vtable by RTTI (vtable_map_3549_3576.json, 41
// slots as on 3527). The marker is still +0x259: the load machine writes 0 / 1 / 2 there at 0x856DB7 / 0x85741E /
// 0xC9CFBB and 0xBA340B compares it with 2 (3527's sites + 0x250 / + 0x250 / + 0x420 / in 0xBA2F70 + 0x420), and the
// machine's P+0x15C still takes 0x11 (0x8562D3) and 0x18 (0x8565ED, 0x859754). World slot 0x71C0100.
constexpr uintptr_t kVtManager3576 = 0x5959438;
constexpr uintptr_t kWorldSlot3576 = 0x71C0100;
constexpr uintptr_t kMarker = 0x259;
constexpr uintptr_t kLoadState = 0x15C;  // [world+0x60] -> u8 load state
// Build 1.0.0.3663 (static, 2026-11-13; never run). The class's vtable by RTTI: 0x5959438 -> 0x59D57E8
// (vtable_map_3576_3663.json). The marker MOVED to +0x261: the load machine 0x8825B0 writes 0 / 1 there at 0x883807 /
// 0x883E61, the 2322 handler 2 at 0xCD563B, the bind 1 at 0x9C9674C and the protected code 3 at 0x9C9CE89, and
// 0x882D87 / 0xBDA308 / 0xBDAF8B compare it with 2; no code writes or compares +0x259 any more. The load machine's
// state MOVED to +0x24C ([[world 0x72451C0]+0x60]+0x24C: read so at 0x3EF4B4, 0x569223, 0x57425D, 0x5DAFA1) and gained
// a state: its jump table covers 1..0x18 (`lea eax,[r14-1] ; cmp al,0x17` at 0x8826A8), 0x19 is idle (written last at
// 0x883070; 0x6C9409 compares with 0x19), and the wait for the marker is state 0x12 (0x882D87; it goes on to 0x13). The
// chain world+0x30 -> +0x50 is the client's own actor (0x3EE4C0 / 0x3F1D94 / 0x55DF6C); components +0xA8 is still
// pa::ClientSelfSequencerActorComponent (the client component factory 0x9C3100 registers vtable 0x59CFE18 with index
// 0x15 at 0x9C31DB, stored at table + index * 8 by 0x2297192); its +0x18 (the manager) is 3527's, not re-derived on
// the client (the server side keeps it: observer_milestone region 17), and the vtable check refuses any other object.
// World slot 0x72451C0.
constexpr uintptr_t kVtManager3663 = 0x59D57E8;
constexpr uintptr_t kWorldSlot3663 = 0x72451C0;
constexpr uintptr_t kMarker3663 = 0x261;
constexpr uintptr_t kLoadState3663 = 0x24C;
constexpr uint8_t kIdleState3663 = 0x19, kWaitState3663 = 0x12;

std::atomic<bool> g_started{false};
bool g_guest = false;
uintptr_t g_vt_manager = kVtManager3527;  // set by marker_thread before the first read
uintptr_t g_marker = kMarker;             // likewise
uintptr_t g_load_state = kLoadState;      // likewise
bool g_states_3663 = false;               // likewise

// 3663's load states in 3527's numbering for the guard (seq_marker_logic.h): only idle and the marker wait matter
// there; every other 3663 state is one that is neither (0xFE).
uint8_t guard_state(uint8_t raw) noexcept {
    if (!g_states_3663) return raw;
    return raw == kIdleState3663 ? smk::kIdleState : raw == kWaitState3663 ? smk::kWaitState : uint8_t{0xFE};
}

// ---------------------------------------------------------------- seq_marker_trace=1: who calls the manager's vf+0x20
//
// Reached only through the `jmp` at 0xB9FD80, slot 4 of the manager's vtable (the same thunk on both builds). It stores
// the field in +0x20 and leaves the marker at 1.
// 3576 (static): slot 4 of 0x5959438 is the thunk 0xBA01A0 (3527's 0xB9FD80 + 0x420), jmp 0x9AC7F90 in the protected
// section; there the same 15-byte head, `mov [rbp+0x20],rbx` and `mov byte [rbp+0x259],1` (0x9AC7FD0 / 0x9AC8034).
// 3663 (static, 2026-11-13; never run): slot 4 of 0x59D57E8 is the thunk 0xBD7D00, jmp 0x9C966B0 in the protected
// section; there the same 15-byte head, `mov [rbp+0x20],rbx` (0x9C966F0) and `mov byte [rbp+0x261],1` (0x9C9674C).
constexpr uintptr_t kBind3527 = 0x9A7F860, kBind3549 = 0x99BADC0, kBind3576 = 0x9AC7F90, kBind3663 = 0x9C966B0;
constexpr uint8_t kBindHead[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20};
constexpr int kTraceCalls = 40;
safetyhook::InlineHook g_bind_hook;
std::atomic<int> g_bind_calls{0};
bool g_trace = false;
uintptr_t g_base = 0;

void* __fastcall on_bind(uintptr_t manager, void* result, uintptr_t field) {
    const int n = g_bind_calls.fetch_add(1, std::memory_order_relaxed);
    uint8_t before = 0xFF;
    game::safe_read(manager + g_marker, &before, sizeof before);
    if (n < kTraceCalls) {
        void* frames[14]{};
        const USHORT count = RtlCaptureStackBackTrace(1, 14, frames, nullptr);
        std::string stack;
        for (USHORT i = 0; i < count; ++i) {
            const auto a = reinterpret_cast<uintptr_t>(frames[i]);
            stack += a >= g_base && a < g_base + 0x20000000 ? std::format(" exe+0x{:X}", a - g_base)
                                                            : std::format(" 0x{:X}", a);
        }
        log::info("SeqMarker trace: bind #{} manager 0x{:X} field 0x{:X} marker {} thread {} |{}", n + 1, manager, field,
                  before, GetCurrentThreadId(), stack);
    }
    return g_bind_hook.fastcall<void*>(manager, result, field);
}

void install_trace(uintptr_t base) {
    g_base = base;
    const uintptr_t bind = game::is_3663()   ? kBind3663
                           : game::is_3576() ? kBind3576
                           : game::is_3549() ? kBind3549
                                             : kBind3527;
    uint8_t head[sizeof kBindHead]{};
    if (!game::safe_read(base + bind, head, sizeof head) || std::memcmp(head, kBindHead, sizeof head) != 0) {
        log::warn("SeqMarker trace: exe+0x{:X} is not the expected code; no trace", bind);
        return;
    }
    auto h = game::prepare_inline(base + bind, reinterpret_cast<void*>(&on_bind), {}, "SeqMarker", "manager bind");
    if (!h) {
        log::warn("SeqMarker trace: no hook: {}", game::inline_error_text(h.error()));
        return;
    }
    g_bind_hook = std::move(*h);
    if (!g_bind_hook.enable()) {
        log::warn("SeqMarker trace: the hook could not be enabled");
        return;
    }
    log::info("SeqMarker trace ON at exe+0x{:X}", bind);
}

template <class T>
bool peek(uintptr_t address, T& out) noexcept {
    return game::safe_read(address, &out, sizeof out);
}

bool store_byte(uintptr_t address, uint8_t value) noexcept {
    __try {
        *reinterpret_cast<volatile uint8_t*>(address) = value;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

smk::Facts read_facts(uintptr_t base, uintptr_t world_system) noexcept {
    smk::Facts f;
    uintptr_t world = 0, loader = 0, manager = 0, actor = 0, components = 0, component = 0, sequencer = 0, vt = 0;
    if (!peek(base + world_system, world) || !world) return f;
    uint8_t raw_state = 0;
    if (!peek(world + 0x60, loader) || !loader || !peek(loader + g_load_state, raw_state)) return f;
    f.state = guard_state(raw_state);
    if (!peek(world + 0x30, manager) || !manager) return f;
    if (!peek(manager + 0x50, actor) || !actor) return f;
    if (!peek(actor + 0x68, components) || !components) return f;
    if (!peek(components + 0xA8, component) || !component) return f;
    if (!peek(component + 0x18, sequencer) || !sequencer) return f;
    if (!peek(sequencer, vt) || vt != base + g_vt_manager) return f;
    if (!peek(sequencer + g_marker, f.marker)) return f;
    f.manager = sequencer;
    f.readable = true;
    return f;
}

DWORD WINAPI marker_thread(void*) {
    const bool b3576 = game::current_build() == game::Build::v3576;
    const bool b3663 = game::current_build() == game::Build::v3663;
    const auto* profile = game::reader_profile();
    if (!b3576 && !b3663 && (!profile || game::current_build() != game::Build::v3527)) {
        log::info("SeqMarker: only for builds 3527, 3549, 3576 and 3663, off");
        return 0;
    }
    // 3576 / 3663: their own vtable and world slot (reader_profile() may have no entry for them yet); 3663 also its
    // own marker and load-state offsets and state numbers.
    const uintptr_t world_slot = b3663 ? kWorldSlot3663 : b3576 ? kWorldSlot3576 : profile->world_system;
    g_vt_manager = b3663 ? kVtManager3663 : b3576 ? kVtManager3576 : kVtManager3527;
    g_marker = b3663 ? kMarker3663 : kMarker;
    g_load_state = b3663 ? kLoadState3663 : kLoadState;
    g_states_3663 = b3663;
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    log::info("SeqMarker ON ({}): the own sequencer manager's load marker is put back if it falls with no load running",
              g_guest ? "guest" : "host");
    if (g_trace) install_trace(base);
    smk::Guard guard;
    uint64_t restores = 0, failed = 0, summarized = 0, next_summary = GetTickCount64() + kSummaryMs;
    for (;;) {
        Sleep(kLookMs);
        smk::Facts f = read_facts(base, world_slot);
        f.live = g_guest ? guest_remote_live() : server_user2_present();
        const smk::Decision d = guard.look(f);
        if (d.restore) {
            // Again, right before the write: the trip may have moved on since the look.
            const smk::Facts now = read_facts(base, world_slot);
            const bool still = now.readable && now.manager == f.manager && now.marker == smk::kMarkerFallen &&
                               (now.state == smk::kIdleState || now.state == smk::kWaitState);
            if (still) {
                const bool ok = store_byte(now.manager + g_marker, d.value);
                ok ? ++restores : ++failed;
                if (restores + failed <= kDetailedRestores) {
                    log::warn("SeqMarker: the own manager 0x{:X} fell to marker {} in load state 0x{:X} (another player "
                              "{}): put back to {}{}",
                              now.manager, now.marker, now.state, f.live ? "connected" : "gone", d.value,
                              ok ? "" : " FAULTED");
                }
            }
        }
        const uint64_t tick = GetTickCount64();
        if (tick >= next_summary) {
            next_summary = tick + kSummaryMs;
            if (restores != summarized) {
                summarized = restores;
                log::info("SeqMarker: {} put back so far, {} faulted", restores, failed);
            }
        }
    }
}

}  // namespace

void seq_marker_start(bool enabled, bool guest, bool trace) {
    if (!enabled || g_started.exchange(true)) return;
    g_guest = guest;
    g_trace = trace;
    CloseHandle(CreateThread(nullptr, 0, marker_thread, nullptr, 0, nullptr));
}

}  // namespace cdmp::session2
