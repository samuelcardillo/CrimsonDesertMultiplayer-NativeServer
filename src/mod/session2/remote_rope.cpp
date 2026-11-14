#include "mod/session2/remote_rope.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/actor_lookup.h"
#include "mod/game/offsets.h"
#include "mod/game/player_reader.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/remote_rope_logic.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using rrp::Mode;

// Hooks only at verified function entries inside [0x1000, code_end) (.rsrc, never .xtls).
constexpr uintptr_t kCodeBegin = 0x1000;
// Where everything is, per build (remote_rope_logic.h). Log lines and comments keep the 2976 names (the research is
// written against that build); the addresses they print are this build's.
struct Addrs {
    uintptr_t code_end;
    uintptr_t apply, apply_call, apply_return, info_copy, map_site;
    uintptr_t world_system, resolve, att_dtor, scope_attacher_vtbl;
    uint32_t physics_vf_transform, state_base, flight_base, data_slot;
    uintptr_t release, release_thread_check, main_thread_id, client_vtbl, apply_failed_err;
    uintptr_t h2471, h2471_slot, h2471_release;
    uintptr_t srv_release, srv_release_slot, srv_args;
    uintptr_t writer, writer_site, to_near_vtbl, to_near_vf1, ts_owner_call;
    uintptr_t act_release, server_vtbl, act_release_slot, srv_vf158_slot, slot_reset;
    uintptr_t act_client_call, act_dispatch, act_keep_test, act_notify, act_self_release;
    std::span<const uint8_t> apply_call_bytes, map_site_bytes, release_check_bytes, h2471_head, h2471_release_bytes;
    std::span<const uint32_t> h2471_boundaries;
    std::span<const uint8_t> srv_args_bytes, writer_site_bytes, act_client_call_bytes, act_dispatch_bytes;
};
const Addrs kAddrs2976{0x51EB000,
                       rrp::kApply, rrp::kApplyCall, rrp::kApplyReturn, rrp::kInfoCopy, rrp::kMapSite,
                       rrp::kWorldSystem, rrp::kResolve, rrp::kAttDtor, rrp::kScopeAttacherBaseVtbl,
                       rrp::kPhysics_vfTransform, rrp::kStateBase, rrp::kFlightBase, rrp::kData_Slot,
                       rrp::kRelease, rrp::kReleaseThreadCheck, rrp::kMainThreadId, rrp::kClientRemoteCatchVtbl,
                       rrp::kApplyFailedErr,
                       rrp::k2471Handler, rrp::k2471HandlerSlot, rrp::k2471Release,
                       rrp::kSrvRelease, rrp::kSrvReleaseSlot, rrp::kSrvArgs,
                       rrp::kWriter, rrp::kWriterSite, rrp::kToNearVtbl, rrp::kToNearVf1, rrp::kTsOwnerCall,
                       rrp::kActRelease, rrp::kServerRemoteCatchVtbl, rrp::kActReleaseSlot, rrp::kSrvCompVf158Slot,
                       rrp::kSlotReset,
                       rrp::kActClientCall, rrp::kActDispatch, rrp::kActKeepTest, rrp::kActNotify, rrp::kActSelfRelease,
                       rrp::kApplyCallBytes, rrp::kMapSiteBytes, rrp::kReleaseThreadCheckBytes, rrp::k2471HandlerHead,
                       rrp::k2471ReleaseBytes, rrp::k2471HandlerBoundaries,
                       rrp::kSrvArgsBytes, rrp::kWriterSiteBytes, rrp::kActClientCallBytes, rrp::kActDispatchBytes};
const Addrs kAddrs3527{rrp::kCodeEnd3527,
                       rrp::kApply3527, rrp::kApplyCall3527, rrp::kApplyReturn3527, rrp::kInfoCopy3527, rrp::kMapSite3527,
                       rrp::kWorldSystem3527, rrp::kResolve3527, rrp::kAttDtor3527, rrp::kScopeAttacherBaseVtbl3527,
                       rrp::kPhysics_vfTransform3527, rrp::kStateBase3527, rrp::kFlightBase3527, rrp::kData_Slot3527,
                       rrp::kRelease3527, rrp::kReleaseThreadCheck3527, rrp::kMainThreadId3527,
                       rrp::kClientRemoteCatchVtbl3527, rrp::kApplyFailedErr3527,
                       rrp::k2471Handler3527, rrp::k2471HandlerSlot3527, rrp::k2471Release3527,
                       rrp::kSrvRelease3527, rrp::kSrvReleaseSlot3527, rrp::kSrvArgs3527,
                       rrp::kWriter3527, rrp::kWriterSite3527, rrp::kToNearVtbl3527, rrp::kToNearVf13527,
                       rrp::kTsOwnerCall3527,
                       rrp::kActRelease3527, rrp::kServerRemoteCatchVtbl3527, rrp::kActReleaseSlot3527,
                       rrp::kSrvCompVf158Slot3527, rrp::kSlotReset3527,
                       rrp::kActClientCall3527, rrp::kActDispatch3527, rrp::kActKeepTest3527, rrp::kActNotify3527,
                       rrp::kActSelfRelease3527,
                       rrp::kApplyCallBytes3527, rrp::kMapSiteBytes3527, rrp::kReleaseThreadCheckBytes3527,
                       rrp::k2471HandlerHead3527, rrp::k2471ReleaseBytes3527, rrp::k2471HandlerBoundaries3527,
                       rrp::kSrvArgsBytes3527, rrp::kWriterSiteBytes3527, rrp::kActClientCallBytes3527,
                       rrp::kActDispatchBytes3527};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): remote_rope_logic.h's 3576 table; 3527's data offsets and the 3527
// arrays that are byte-identical there (the 2471 head and boundaries, the server's argument reads, the dispatch).
const Addrs kAddrs3576{rrp::kCodeEnd3576,
                       rrp::kApply3576, rrp::kApplyCall3576, rrp::kApplyReturn3576, rrp::kInfoCopy3576, rrp::kMapSite3576,
                       rrp::kWorldSystem3576, rrp::kResolve3576, rrp::kAttDtor3576, rrp::kScopeAttacherBaseVtbl3576,
                       rrp::kPhysics_vfTransform3527, rrp::kStateBase3527, rrp::kFlightBase3527, rrp::kData_Slot3527,
                       rrp::kRelease3576, rrp::kReleaseThreadCheck3576, rrp::kMainThreadId3576,
                       rrp::kClientRemoteCatchVtbl3576, rrp::kApplyFailedErr3576,
                       rrp::k2471Handler3576, rrp::k2471HandlerSlot3576, rrp::k2471Release3576,
                       rrp::kSrvRelease3576, rrp::kSrvReleaseSlot3576, rrp::kSrvArgs3576,
                       rrp::kWriter3576, rrp::kWriterSite3576, rrp::kToNearVtbl3576, rrp::kToNearVf13576,
                       rrp::kTsOwnerCall3576,
                       rrp::kActRelease3576, rrp::kServerRemoteCatchVtbl3576, rrp::kActReleaseSlot3576,
                       rrp::kSrvCompVf158Slot3576, rrp::kSlotReset3576,
                       rrp::kActClientCall3576, rrp::kActDispatch3576, rrp::kActKeepTest3576, rrp::kActNotify3576,
                       rrp::kActSelfRelease3576,
                       rrp::kApplyCallBytes3576, rrp::kMapSiteBytes3576, rrp::kReleaseThreadCheckBytes3576,
                       rrp::k2471HandlerHead3527, rrp::k2471ReleaseBytes3576, rrp::k2471HandlerBoundaries3527,
                       rrp::kSrvArgsBytes3527, rrp::kWriterSiteBytes3576, rrp::kActClientCallBytes3576,
                       rrp::kActDispatchBytes3527};
// Build 1.0.0.3663 (static, 2026-11-13; never run): remote_rope_logic.h's 3663 table; 3527's data offsets (re-read in the
// 3663 code, see there) and the 3527 arrays that are byte-identical there (the 2471 head and boundaries, the server's
// argument reads, the dispatch).
const Addrs kAddrs3663{rrp::kCodeEnd3663,
                       rrp::kApply3663, rrp::kApplyCall3663, rrp::kApplyReturn3663, rrp::kInfoCopy3663, rrp::kMapSite3663,
                       rrp::kWorldSystem3663, rrp::kResolve3663, rrp::kAttDtor3663, rrp::kScopeAttacherBaseVtbl3663,
                       rrp::kPhysics_vfTransform3527, rrp::kStateBase3527, rrp::kFlightBase3527, rrp::kData_Slot3527,
                       rrp::kRelease3663, rrp::kReleaseThreadCheck3663, rrp::kMainThreadId3663,
                       rrp::kClientRemoteCatchVtbl3663, rrp::kApplyFailedErr3663,
                       rrp::k2471Handler3663, rrp::k2471HandlerSlot3663, rrp::k2471Release3663,
                       rrp::kSrvRelease3663, rrp::kSrvReleaseSlot3663, rrp::kSrvArgs3663,
                       rrp::kWriter3663, rrp::kWriterSite3663, rrp::kToNearVtbl3663, rrp::kToNearVf13663,
                       rrp::kTsOwnerCall3663,
                       rrp::kActRelease3663, rrp::kServerRemoteCatchVtbl3663, rrp::kActReleaseSlot3663,
                       rrp::kSrvCompVf158Slot3663, rrp::kSlotReset3663,
                       rrp::kActClientCall3663, rrp::kActDispatch3663, rrp::kActKeepTest3663, rrp::kActNotify3663,
                       rrp::kActSelfRelease3663,
                       rrp::kApplyCallBytes3663, rrp::kMapSiteBytes3663, rrp::kReleaseThreadCheckBytes3663,
                       rrp::k2471HandlerHead3527, rrp::k2471ReleaseBytes3663, rrp::k2471HandlerBoundaries3527,
                       rrp::kSrvArgsBytes3527, rrp::kWriterSiteBytes3663, rrp::kActClientCallBytes3663,
                       rrp::kActDispatchBytes3527};
const Addrs& addrs() noexcept {
    static const Addrs& a = game::current_build() == game::Build::v3663   ? kAddrs3663
                            : game::current_build() == game::Build::v3576 ? kAddrs3576
                            : game::current_build() == game::Build::v3527 ? kAddrs3527
                                                                          : kAddrs2976;
    return a;
}
// rrp::slot_state / rrp::slot_flight with this build's bases.
uintptr_t slot_state(uintptr_t comp, uint8_t slot) noexcept {
    return comp + addrs().state_base + slot * rrp::kStateStride;
}
uintptr_t slot_flight(uintptr_t comp, uint8_t slot) noexcept {
    return comp + addrs().flight_base + slot * rrp::kStateStride;
}
constexpr uint32_t kTickMs = 500;
constexpr uint32_t kWorldTicks = 6;  // the local player read 6 ticks in a row (3 s) before the hooks go in
constexpr uint64_t kMinuteMs = 60000;
constexpr uint64_t kEventLines = 400;  // per run; after that only counted

enum EventKind : uint16_t { kEvApply = 1, kEvBody = 2, kEvServer = 3, kEv2471 = 4, kEvAction = 5 };
enum F3Result : uint8_t { kF3None, kF3Released, kF3Deferred, kF3LeftBusy, kF3Faulted, kF3Skipped, kF3Unsafe };
enum WriteResult : uint8_t { kWriteNone, kWriteOk, kWriteFailed, kWriteUnsafe };

std::atomic<uint8_t> g_mode{0};  // rrp::Mode, written once by remote_rope_start (before the thread)
std::atomic<bool> g_started{false};
std::atomic<bool> g_guest{false};
std::atomic<bool> g_hooks_on{false};
uintptr_t g_base = 0;
SafetyHookInline g_apply_hook, g_h2471_hook, g_srv_hook, g_act_hook;

// A fault inside a game call stops that call for the rest of the run (no retry: the game's state may be damaged).
std::atomic<bool> g_f1_faulted{false}, g_release_faulted{false}, g_writer_faulted{false}, g_diag_faulted{false};
// The own-throw check: consecutive 'handle match' (game thread only) and done after rrp::kOwnChecks of them.
std::atomic<uint32_t> g_own_run{0};
std::atomic<bool> g_own_check_done{false};

// The exe's executable sections ([va, va + size) pairs, written by the installer BEFORE any hook is enabled).
struct Range {
    uintptr_t lo = 0, hi = 0;
};
Range g_code[4];
size_t g_code_n = 0;

rrp::Tally g_tally;
p8p::EventRing<256> g_ring;
std::atomic<uint32_t> g_seq{0};

Mode mode() { return static_cast<Mode>(g_mode.load(std::memory_order_acquire)); }

bool in_code(uintptr_t a) {
    for (size_t i = 0; i < g_code_n; ++i) {
        if (a >= g_code[i].lo && a < g_code[i].hi) return true;
    }
    return false;
}

// ---------------------------------------------------------------- guarded access on the game's threads

int access_filter(const EXCEPTION_POINTERS* ep) noexcept {
    const EXCEPTION_RECORD* r = ep ? ep->ExceptionRecord : nullptr;
    if (!r) return EXCEPTION_CONTINUE_SEARCH;
    return r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || r->ExceptionCode == EXCEPTION_IN_PAGE_ERROR
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}
bool plausible(uintptr_t a, size_t n) { return a >= 0x10000 && a <= 0x00007FFFFFFFFFFFull - n; }
// The handlers' own locals (arguments that point into their frames): plain SEH reads / writes (never game::fast_read,
// which is not meant for thread stacks).
bool seh_copy(uintptr_t a, void* out, size_t n) noexcept {
    if (!plausible(a, n)) return false;
    __try {
        const volatile uint8_t* s = reinterpret_cast<const volatile uint8_t*>(a);
        uint8_t* d = static_cast<uint8_t*>(out);
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
template <class T>
bool seh_get(uintptr_t a, T& out) noexcept {
    return seh_copy(a, &out, sizeof out);
}
bool seh_write32(uintptr_t a, uint32_t v) noexcept {
    if (!plausible(a, 4)) return false;
    __try {
        *reinterpret_cast<volatile uint32_t*>(a) = v;
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool seh_write64(uintptr_t a, uint64_t v) noexcept {
    if (!plausible(a, 8)) return false;
    __try {
        *reinterpret_cast<volatile uint64_t*>(a) = v;
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}

// ---------------------------------------------------------------- game calls (each only where the game calls it)

using ResolveFn = void* (*)(uintptr_t mgr, void* att, const void* uuid);
using DtorFn = void (*)(void* att);
using HandleFn = uint64_t (*)(uintptr_t self);
using XfFn = uint8_t (*)(uintptr_t self, uint64_t handle, void* xf);
using ReleaseFn = void (*)(uintptr_t comp, uint8_t slot, uint8_t reason, uint8_t p4, uint8_t p5);
using WriterFn = void (*)(uintptr_t actor, void* finder, const uint8_t* slot, const uint8_t* reason);

bool call_resolve(uintptr_t fn, uintptr_t mgr, void* att, const void* uuid) noexcept {
    __try {
        reinterpret_cast<ResolveFn>(fn)(mgr, att, uuid);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool call_dtor(uintptr_t fn, void* att) noexcept {
    __try {
        reinterpret_cast<DtorFn>(fn)(att);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool call_handle(uintptr_t fn, uintptr_t self, uint64_t& out) noexcept {
    __try {
        out = reinterpret_cast<HandleFn>(fn)(self);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool call_xf(uintptr_t fn, uintptr_t self, uint64_t handle, void* xf, uint8_t& ok) noexcept {
    __try {
        ok = reinterpret_cast<XfFn>(fn)(self, handle, xf);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool call_release(uintptr_t fn, uintptr_t comp, uint8_t slot, uint8_t reason) noexcept {
    __try {
        reinterpret_cast<ReleaseFn>(fn)(comp, slot, reason, 0, 1);  // as the 2471 handler (0xB5BF44..0xB5BF5D)
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool call_writer(uintptr_t fn, uintptr_t actor, void* finder, const uint8_t* slot, const uint8_t* reason) noexcept {
    __try {
        reinterpret_cast<WriterFn>(fn)(actor, finder, slot, reason);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}

std::optional<uintptr_t> world_system() { return game::fast_ptr(g_base + addrs().world_system); }

// This PC's handle of a scene object, by the thrower's own mapping (0x5947C7..0x59484E). The lookup's checks are
// 0x5A5370's: a reference taken ([att+0x10]) and an object ([att+8]); every pointer is checked BEFORE it is used, and
// the reference the lookup took is always given back by the attacher's dtor (no SEH as control flow).
rrp::Resolve resolve_local_handle(const uint8_t (&scene)[16], uint64_t& out, bool& fault_now) noexcept {
    out = rrp::kNoHandle;
    if (g_f1_faulted.load(std::memory_order_relaxed)) return rrp::Resolve::Faulted;
    const auto ws = world_system();
    if (!ws) return rrp::Resolve::NoManager;
    const auto root = game::fast_ptr(*ws + rrp::kWs_SceneRoot);
    if (!root) return rrp::Resolve::NoManager;
    const auto root2 = game::fast_ptr(*root);
    if (!root2) return rrp::Resolve::NoManager;
    const auto mgr = game::fast_ptr(*root2 + rrp::kSceneRoot_Mgr);
    if (!mgr) return rrp::Resolve::NoManager;
    // 0x1851010 locks through the object at mgr+0x10 (its vf18 / vf20 / vf38): its vtable must be the game's.
    const auto lock_vt = game::fast_ptr(*mgr + 0x10);
    if (!lock_vt) return rrp::Resolve::NoManager;
    for (const uint32_t slot : {0x18u, 0x20u, 0x38u}) {
        const auto f = game::fast_ptr(*lock_vt + slot);
        if (!f || !in_code(*f)) return rrp::Resolve::BadCode;
    }
    alignas(16) uint8_t att[0x40] = {};
    alignas(16) uint8_t id[16];
    std::memcpy(id, scene, sizeof id);
    if (!call_resolve(g_base + addrs().resolve, *mgr, att, id)) {
        g_f1_faulted.store(true);
        fault_now = true;
        return rrp::Resolve::Faulted;
    }
    const uint8_t ref = att[rrp::kAtt_Ref];
    uintptr_t obj = 0;
    std::memcpy(&obj, att + rrp::kAtt_Obj, sizeof obj);
    rrp::Resolve r = rrp::Resolve::NotFound;
    if (ref != 0 && obj != 0) {
        r = rrp::Resolve::NoBody;
        const auto body = game::fast_ptr(obj + rrp::kObj_Body);
        const auto gone = body ? game::fast<uint8_t>(*body + rrp::kBody_Gone) : std::nullopt;
        const auto phys = body ? game::fast_ptr(*body + rrp::kBody_Phys) : std::nullopt;
        if (body && gone && *gone != 1 && phys) {
            const auto vt = game::fast_ptr(*phys);
            const auto fn = vt ? game::fast_ptr(*vt + rrp::kPhys_vfHandle) : std::nullopt;
            if (!fn || !in_code(*fn)) {
                r = rrp::Resolve::BadCode;
            } else {
                uint64_t h = rrp::kNoHandle;
                if (!call_handle(*fn, *phys, h)) {
                    g_f1_faulted.store(true);
                    fault_now = true;
                    r = rrp::Resolve::Faulted;
                } else {
                    out = h;
                    r = h == rrp::kNoHandle ? rrp::Resolve::NoHandle : rrp::Resolve::Ok;
                }
            }
        }
    }
    if (ref != 0) {
        // As the native does (0x594840..0x59484F): ScopeAttacherBase's vtable, then the dtor gives the reference back.
        const uintptr_t vt = g_base + addrs().scope_attacher_vtbl;
        std::memcpy(att, &vt, sizeof vt);
        if (!call_dtor(g_base + addrs().att_dtor, att)) {
            g_f1_faulted.store(true);
            fault_now = true;
            return rrp::Resolve::Faulted;
        }
    }
    return r;
}

// The transform of a physics body here ([WorldSystem+0xE8]->vf3B0, as 0x5A5370 calls it in the same apply).
bool body_xf(uint64_t handle, rrp::Xf& xf, bool& fault_now) noexcept {
    if (g_diag_faulted.load(std::memory_order_relaxed)) return false;
    const auto ws = world_system();
    const auto pw = ws ? game::fast_ptr(*ws + rrp::kWs_Physics) : std::nullopt;
    const auto vt = pw ? game::fast_ptr(*pw) : std::nullopt;
    const auto fn = vt ? game::fast_ptr(*vt + addrs().physics_vf_transform) : std::nullopt;
    if (!fn || !in_code(*fn)) return false;
    xf = rrp::Xf{};
    alignas(16) uint8_t buf[64] = {};
    std::memcpy(buf, &xf, sizeof xf);
    uint8_t ok = 0;
    if (!call_xf(*fn, *pw, handle, buf, ok)) {
        g_diag_faulted.store(true);
        fault_now = true;
        return false;
    }
    std::memcpy(&xf, buf, sizeof xf);
    return ok != 0;
}

bool main_thread() {
    const auto id = game::fast<uint32_t>(g_base + addrs().main_thread_id);
    return id && *id == GetCurrentThreadId();
}

uint32_t next_seq() { return g_seq.fetch_add(1, std::memory_order_relaxed) + 1; }

// Before F3 calls 0x5A7A10 (cdmp_Actor_Lock of [[comp+8]+8], then 0x5A7BC0): the component is the client's and the
// thrower's lock object has a vtable whose lock / unlock entries are the game's code. Checked first, never by SEH.
bool release_safe(uintptr_t comp) noexcept {
    const auto vt = game::fast<uint64_t>(comp);
    if (!vt || *vt != g_base + addrs().client_vtbl) return false;
    const auto actor = game::fast_ptr(comp + rrp::kComp_Owner);
    const auto lock = actor ? game::fast_ptr(*actor + rrp::kActor_LockObj) : std::nullopt;
    const auto lvt = lock ? game::fast_ptr(*lock) : std::nullopt;
    if (!lvt) return false;
    for (const uint32_t slot : rrp::kLockVf) {
        const auto f = game::fast_ptr(*lvt + slot);
        if (!f || !in_code(*f)) return false;
    }
    return true;
}

void push_body(uint32_t key, uint32_t seq, uint8_t which, uint64_t handle, bool ok, const rrp::Xf& xf,
               const rrp::Vec3& point) noexcept {
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEvBody;
    const rrp::Vec3 w = rrp::world_point(xf, point);
    e.v[0] = key | (uint64_t{which} << 32) | (uint64_t{ok ? 1u : 0u} << 40);
    e.v[1] = handle;
    e.v[2] = rrp::pack2(xf.trans[0], xf.trans[1]);
    e.v[3] = rrp::pack2(xf.trans[2], xf.quat[0]);
    e.v[4] = rrp::pack2(xf.quat[1], xf.quat[2]);
    e.v[5] = rrp::pack2(xf.quat[3], xf.scale[0]);
    e.v[6] = rrp::pack2(xf.scale[1], xf.scale[2]);
    e.v[7] = rrp::pack2(w.x, w.y);
    e.v[8] = rrp::pack2(w.z, 0.0f);
    e.v[9] = seq;
    g_ring.push(e);
}

// ---------------------------------------------------------------- F1 + F3: RemoteCatchComponent_Apply's entry

struct ApplyCtx {
    rrp::ApplyInputs in;
    rrp::ApplyDecision d;
    uint32_t key = 0;
    uint32_t seq = 0;
    bool state_before_ok = false;
    uint8_t state_before = 0;
    uint8_t f3 = kF3None;
    bool type_after_f3_ok = false;
    uint8_t type_after_f3 = 0;
    uint8_t write = kWriteNone;
    bool main = false;
    bool point_ok = false;
    rrp::Vec3 point;
    bool expected_caller = false;
    bool fault_now = false;  // a fault inside a game call in this 2763: the original is not called
};

void before_apply(ApplyCtx& c, uintptr_t comp, uintptr_t p_slot, uintptr_t p_kind, uintptr_t p_target,
                  uintptr_t ret) noexcept {
    rrp::ApplyInputs& in = c.in;
    c.seq = next_seq();
    c.main = main_thread();
    c.expected_caller = ret == g_base + addrs().apply_return;
    if (const auto actor = game::fast_ptr(comp + rrp::kComp_Owner)) {
        if (const auto k = game::fast<uint32_t>(*actor + rrp::kActor_Key)) c.key = *k;
        if (const auto ctl = game::fast<uint8_t>(*actor + rrp::kActor_Control)) {
            in.ctl_ok = true;
            in.ctl = *ctl;
        }
    }
    in.slot_ok = seh_get(p_slot, in.slot);
    in.kind_ok = seh_get(p_kind, in.kind);
    if (in.slot_ok && in.slot < rrp::kSlots) {
        if (const auto t = game::fast<uint8_t>(rrp::slot_target(comp, in.slot) + rrp::kSlot_Kind)) {
            in.slot_type_ok = true;
            in.slot_type = *t;
        }
        if (in.slot_type_ok && in.slot_type != rrp::kSlotEmpty) {
            // The busy slot's stored target (0x1808100's copy): F3 releases only a tree.
            if (const auto k = game::fast<uint8_t>(rrp::slot_target(comp, in.slot) + rrp::kSlot_Class)) {
                in.stale_cls_ok = true;
                in.stale_cls = *k;
            }
            if (const auto a = game::fast<uint32_t>(rrp::slot_target(comp, in.slot) + rrp::kSlot_Actor)) {
                in.stale_actor_ok = true;
                in.stale_actor = *a;
            }
        }
        if (const auto s = game::fast<uint8_t>(slot_state(comp, in.slot))) {
            c.state_before_ok = true;
            c.state_before = *s;
        }
    }
    uint8_t block[0x30] = {};
    if (seh_copy(p_target, block, sizeof block)) {
        in.target_ok = true;
        in.cls = block[rrp::kInfo_Class];
        std::memcpy(&in.target_actor, block + rrp::kInfo_Actor, 4);
        std::memcpy(in.scene, block + rrp::kInfo_Scene, 16);
        std::memcpy(&in.handle, block + rrp::kInfo_Handle, 8);
        float p[3];
        std::memcpy(p, block + rrp::kInfo_Point, sizeof p);
        c.point = {p[0], p[1], p[2]};
        c.point_ok = true;
    }
    in.own_check_done = g_own_check_done.load(std::memory_order_relaxed);
    if (rrp::wants_resolve(in)) in.resolve = resolve_local_handle(in.scene, in.local_handle, c.fault_now);
    c.d = rrp::decide_apply(mode(), in);
    if (c.d.target == rrp::Target::OwnMatch) {
        if (g_own_run.fetch_add(1, std::memory_order_relaxed) + 1 >= rrp::kOwnChecks) g_own_check_done.store(true);
    } else if (c.d.target == rrp::Target::OwnMismatch || c.d.target == rrp::Target::OwnUnresolved) {
        g_own_run.store(0, std::memory_order_relaxed);
    }

    // F3: a stale slot of a remote thrower, released as the 2471 handler would (main thread: at once, 0x5A7BC0).
    if (c.d.release && !c.fault_now) {
        if (g_release_faulted.load(std::memory_order_relaxed)) {
            c.f3 = kF3Skipped;
        } else if (!release_safe(comp)) {
            c.f3 = kF3Unsafe;
        } else if (!call_release(g_base + addrs().release, comp, in.slot, rrp::kStaleReason)) {
            g_release_faulted.store(true);
            c.fault_now = true;
            c.f3 = kF3Faulted;
        } else {
            const auto t = game::fast<uint8_t>(rrp::slot_target(comp, in.slot) + rrp::kSlot_Kind);
            c.type_after_f3_ok = t.has_value();
            c.type_after_f3 = t.value_or(0);
            c.f3 = !c.main ? kF3Deferred : (t && *t == rrp::kSlotEmpty ? kF3Released : kF3LeftBusy);
        }
    }
    // F1: this PC's handle into the handler's local target block (+0x18, the copy 0x5923AD reads).
    if (c.d.write && !c.fault_now) {
        c.write = !g_f1_faulted.load(std::memory_order_relaxed) && seh_write64(p_target + rrp::kInfo_Handle, c.d.value)
                      ? kWriteOk
                      : kWriteFailed;
    }
    // The bodies' transforms (measure): the packet's handle here, and this PC's when it differs.
    if (rrp::wants_resolve(in) && c.point_ok && !c.fault_now) {
        rrp::Xf xf;
        const bool ok = body_xf(in.handle, xf, c.fault_now);
        push_body(c.key, c.seq, 0, in.handle, ok, xf, c.point);
        if (in.resolve == rrp::Resolve::Ok && in.local_handle != in.handle && !c.fault_now) {
            rrp::Xf xl;
            const bool okl = body_xf(in.local_handle, xl, c.fault_now);
            push_body(c.key, c.seq, 1, in.local_handle, okl, xl, c.point);
        }
    }
}

void after_apply(const ApplyCtx& c, uintptr_t comp, uintptr_t p_err, uintptr_t p_speed) noexcept {
    const rrp::ApplyInputs& in = c.in;
    uint32_t err = 0;
    const bool err_ok = seh_get(p_err, err);
    float speed = 0;
    seh_get(p_speed, speed);
    // The flight (+0xA94) is set by 0x5A12A0 after this returns (state 1 here): the worker reads it later.
    std::optional<uint8_t> type_after, state_after;
    if (in.slot_ok && in.slot < rrp::kSlots) {
        type_after = game::fast<uint8_t>(rrp::slot_target(comp, in.slot) + rrp::kSlot_Kind);
        state_after = game::fast<uint8_t>(slot_state(comp, in.slot));
    }
    g_tally.note_apply(in, c.d, c.write == kWriteOk, c.expected_caller);
    if (c.f3 == kF3Released) rrp::Tally::add(g_tally.stale_released);
    if (c.f3 == kF3Deferred) rrp::Tally::add(g_tally.stale_deferred);
    if (c.f3 == kF3LeftBusy) rrp::Tally::add(g_tally.stale_left);
    if (c.f3 == kF3Faulted || c.f3 == kF3Skipped) rrp::Tally::add(g_tally.release_faulted);
    if (c.f3 == kF3Unsafe) rrp::Tally::add(g_tally.release_unsafe);
    if (c.fault_now) rrp::Tally::add(g_tally.not_applied_after_fault);
    if (err_ok && err != 0) {
        rrp::Tally::add(g_tally.apply_failed);
        if (type_after && *type_after != rrp::kSlotEmpty) rrp::Tally::add(g_tally.failed_dirty);
    }
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEvApply;
    e.flags = static_cast<uint16_t>((c.expected_caller ? 1u : 0u) | (c.main ? 2u : 0u) | (c.point_ok ? 4u : 0u) |
                                    (err_ok ? 8u : 0u) | (in.target_ok ? 16u : 0u) | (type_after ? 32u : 0u) |
                                    (c.fault_now ? 64u : 0u));
    e.v[0] = c.key | (uint64_t{rrp::opt8(in.ctl_ok, in.ctl)} << 32) | (uint64_t{rrp::opt8(in.slot_ok, in.slot)} << 48);
    e.v[1] = rrp::opt8(in.kind_ok, in.kind) | (uint64_t{rrp::opt8(in.target_ok, in.cls)} << 16) |
             (uint64_t{rrp::opt8(in.slot_type_ok, in.slot_type)} << 32) |
             (uint64_t{rrp::opt8(c.state_before_ok, c.state_before)} << 48);
    uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, in.scene, 8);
    std::memcpy(&hi, in.scene + 8, 8);
    e.v[2] = lo;
    e.v[3] = hi;
    e.v[4] = in.handle;
    e.v[5] = in.local_handle;
    e.v[6] = static_cast<uint64_t>(c.d.target) | (uint64_t{static_cast<uint8_t>(c.d.stale)} << 8) |
             (uint64_t{static_cast<uint8_t>(in.resolve)} << 16) | (uint64_t{c.f3} << 24) |
             (uint64_t{c.write} << 32) | (uint64_t{rrp::opt8(c.type_after_f3_ok, c.type_after_f3)} << 40);
    e.v[7] = err | (uint64_t{rrp::opt8(type_after.has_value(), type_after.value_or(0))} << 32) |
             (uint64_t{rrp::opt8(state_after.has_value(), state_after.value_or(0))} << 48);
    e.v[8] = c.seq | (uint64_t{in.target_actor} << 32);
    e.v[9] = rrp::pack2(0.0f, speed);
    e.v[10] = rrp::pack2(c.point.x, c.point.y);
    e.v[11] = rrp::pack2(c.point.z, 0.0f);
    g_ring.push(e);
}

// RemoteCatchComponent_Apply(comp, &err, &slot, &kind, &3 bytes, &target, &hash, &speed, u32, &name).
using Arg = uint64_t;
Arg apply_detour(Arg comp, Arg err, Arg p_slot, Arg p_kind, Arg p3, Arg p_target, Arg p_hash, Arg p_speed, Arg a9,
                 Arg p_name) {
    ApplyCtx c;
    before_apply(c, comp, p_slot, p_kind, p_target, reinterpret_cast<uintptr_t>(_ReturnAddress()));
    if (c.fault_now) {
        // A fault inside one of this module's game calls: a lock may still be held, so this stack does not go into the
        // apply (which locks the same objects again). The 2763 fails as the native code fails it: its error in *err,
        // and 0x592340's return value (the error pointer).
        const auto code = game::fast<uint32_t>(g_base + addrs().apply_failed_err);
        const uint32_t v = code && *code ? *code : rrp::kApplyFailedErrSeen;
        (void)seh_write32(err, v);
        after_apply(c, comp, err, p_speed);
        return err;
    }
    // Never inside a __try: the game's own exceptions are the game's.
    const Arg r = g_apply_hook.unsafe_call<Arg>(comp, err, p_slot, p_kind, p3, p_target, p_hash, p_speed, a9, p_name);
    after_apply(c, comp, err, p_speed);
    return r;
}

// ---------------------------------------------------------------- the 2471 handler (log only)

struct H2471Ctx {
    uint32_t seq = 0;
    bool parsed = false;
    rrp::Payload2471 p;
    bool found = false;
    uintptr_t comp = 0;
    bool ctl_ok = false;
    uint8_t ctl = 0;
    bool type_ok = false, state_ok = false;
    uint8_t type = 0, state = 0;
    bool main = false;
};

void before_2471(H2471Ctx& c, uintptr_t pkt) noexcept {
    c.seq = next_seq();
    c.main = main_thread();
    uint16_t total = 0;
    uint64_t buf = 0;
    uint8_t bytes[rrp::kBuf_Payload + rrp::k2471Payload] = {};
    if (seh_get(pkt + rrp::kPkt_Total, total) && seh_get(pkt + rrp::kPkt_Buffer, buf) &&
        seh_copy(buf, bytes, sizeof bytes)) {
        c.parsed = rrp::parse_2471(total, bytes, sizeof bytes, c.p);
    }
    if (!c.parsed) return;
    const auto actor = game::find_actor(c.p.key);
    if (!actor) return;
    c.found = true;
    if (const auto ctl = game::fast<uint8_t>(*actor + rrp::kActor_Control)) {
        c.ctl_ok = true;
        c.ctl = *ctl;
    }
    const auto comps = game::fast_ptr(*actor + rrp::kActor_Comps);
    const auto comp = comps ? game::fast_ptr(*comps + rrp::kComps_RemoteCatch) : std::nullopt;
    if (!comp || c.p.slot >= rrp::kSlots) return;
    c.comp = *comp;
    if (const auto t = game::fast<uint8_t>(rrp::slot_target(c.comp, c.p.slot) + rrp::kSlot_Kind)) {
        c.type_ok = true;
        c.type = *t;
    }
    if (const auto s = game::fast<uint8_t>(slot_state(c.comp, c.p.slot))) {
        c.state_ok = true;
        c.state = *s;
    }
}

void after_2471(const H2471Ctx& c) noexcept {
    rrp::Tally::add(g_tally.h2471);
    if (!c.parsed) rrp::Tally::add(g_tally.h2471_unparsed);
    if (c.ctl_ok) rrp::Tally::add(c.ctl ? g_tally.h2471_own : g_tally.h2471_remote);
    if (c.type_ok && c.type != rrp::kSlotEmpty) rrp::Tally::add(g_tally.h2471_busy_before);
    std::optional<uint8_t> type_after, state_after;
    if (c.comp) {
        type_after = game::fast<uint8_t>(rrp::slot_target(c.comp, c.p.slot) + rrp::kSlot_Kind);
        state_after = game::fast<uint8_t>(slot_state(c.comp, c.p.slot));
    }
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEv2471;
    e.flags = static_cast<uint16_t>((c.parsed ? 1u : 0u) | (c.found ? 2u : 0u) | (c.main ? 4u : 0u));
    e.v[0] = c.p.key | (uint64_t{c.p.slot} << 32) | (uint64_t{c.p.reason} << 40);
    e.v[1] = rrp::opt8(c.ctl_ok, c.ctl) | (uint64_t{rrp::opt8(c.type_ok, c.type)} << 16) |
             (uint64_t{rrp::opt8(c.state_ok, c.state)} << 32) |
             (uint64_t{rrp::opt8(type_after.has_value(), type_after.value_or(0))} << 48);
    e.v[2] = rrp::opt8(state_after.has_value(), state_after.value_or(0));
    e.v[3] = c.seq;
    g_ring.push(e);
}

// ReleaseRemoteCatchResultAck::vf2(this, &err, packet).
Arg h2471_detour(Arg self, Arg err, Arg pkt) {
    H2471Ctx c;
    before_2471(c, pkt);
    const Arg r = g_h2471_hook.unsafe_call<Arg>(self, err, pkt);
    after_2471(c);
    return r;
}

// ---------------------------------------------------------------- F2: the server's release (host)

struct SrvCtx {
    uint32_t seq = 0;
    uintptr_t actor = 0;
    uint32_t key = 0;
    rrp::ReleaseInputs in;
    uint8_t extra = 0;
    uint8_t scene[16] = {};
    uint64_t handle = 0;
};

void before_srv(SrvCtx& c, uintptr_t ev, uintptr_t holder) noexcept {
    c.seq = next_seq();
    uint64_t actor = 0, data = 0;
    if (!seh_get(holder, actor) || !seh_get(ev + rrp::kEv_Data, data) || !plausible(actor, 0x100) ||
        !plausible(data, 0x10)) {
        return;
    }
    c.actor = actor;
    if (const auto k = game::fast<uint32_t>(actor + rrp::kActor_Key)) c.key = *k;
    uint8_t d[3] = {};
    if (!seh_copy(data + addrs().data_slot, d, sizeof d)) return;
    c.in.slot = d[0];
    c.in.reason = d[1];
    c.extra = d[2];
    if (c.in.slot >= rrp::kSlots) {
        c.in.pre_ok = true;  // decide_release says NoSlot
        return;
    }
    const auto comps = game::fast_ptr(actor + rrp::kActor_Comps);
    const auto comp = comps ? game::fast_ptr(*comps + rrp::kComps_RemoteCatch) : std::nullopt;
    if (!comp) return;
    const uintptr_t t = rrp::slot_target(*comp, c.in.slot);
    const auto kind = game::fast<uint8_t>(t + rrp::kSlot_Kind);
    const auto cls = game::fast<uint8_t>(t + rrp::kSlot_Class);
    const auto target = game::fast<uint32_t>(t + rrp::kSlot_Actor);
    if (!kind || !cls || !target) return;
    c.in.kind = *kind;
    c.in.cls = *cls;
    c.in.target_actor = *target;
    (void)game::fast_read(t + rrp::kSlot_Scene, c.scene, sizeof c.scene);
    if (const auto h = game::fast<uint64_t>(t + rrp::kSlot_Handle)) c.handle = *h;
    c.in.pre_ok = true;
}

// The native 2471 writer with a ToNear(thrower) finder, exactly as 0x2903950 builds it (0x2903A79..0x2903AAD). Called
// only on the server's thread, right after an original that frees the slot (0x27D9110, 0x1807390), where the game
// itself calls it for an actor target. A fault switches it off for the run (F2 off).
// Before the writer: the thrower's TransformSync ([[actor+0x68]+0x1A0], what ToNear::vf1 0x2A75860 reads) and its
// owner [ts+8] are readable and their vtables' entries the finder calls (ts vf0; owner vfE8 / vf160 / vf1D8) are in
// the exe's code. Checked first, never by SEH.
bool writer_safe(uintptr_t actor) noexcept {
    const auto comps = game::fast_ptr(actor + rrp::kActor_Comps);
    const auto ts = comps ? game::fast_ptr(*comps + rrp::kComps_TransformSync) : std::nullopt;
    const auto tvt = ts ? game::fast_ptr(*ts) : std::nullopt;
    const auto tf = tvt ? game::fast_ptr(*tvt) : std::nullopt;
    if (!tf || !in_code(*tf)) return false;
    const auto owner = game::fast_ptr(*ts + rrp::kTs_Owner);
    const auto ovt = owner ? game::fast_ptr(*owner) : std::nullopt;
    if (!ovt) return false;
    for (const uint32_t slot : rrp::kOwnerVf) {
        const auto f = game::fast_ptr(*ovt + slot);
        if (!f || !in_code(*f)) return false;
    }
    return true;
}

uint8_t send_2471(uintptr_t actor, uint8_t slot, uint8_t reason) noexcept {
    if (g_writer_faulted.load(std::memory_order_relaxed)) return kWriteFailed;
    if (!writer_safe(actor)) {
        rrp::Tally::add(g_tally.writer_unsafe);
        return kWriteUnsafe;
    }
    alignas(16) uint8_t finder[0x20] = {};
    const uintptr_t vt = g_base + addrs().to_near_vtbl;
    std::memcpy(finder, &vt, sizeof vt);
    finder[rrp::kFinder_Flag] = 1;
    std::memcpy(finder + rrp::kFinder_Actor, &actor, sizeof actor);
    if (call_writer(g_base + addrs().writer, actor, finder, &slot, &reason)) return kWriteOk;
    g_writer_faulted.store(true);
    return kWriteFailed;
}

void after_srv(SrvCtx& c, uintptr_t p_err) noexcept {
    c.in.err_ok = seh_get(p_err, c.in.err);
    const rrp::Send s = rrp::decide_release(mode(), c.in);
    uint8_t writer = kWriteNone;
    if (s == rrp::Send::Sent) writer = send_2471(c.actor, c.in.slot, c.in.reason);
    rrp::Tally::add(g_tally.srv_releases);
    if (s == rrp::Send::Sent && writer == kWriteOk) rrp::Tally::add(g_tally.srv_sent);
    if (s == rrp::Send::Sent && writer != kWriteOk) rrp::Tally::add(g_tally.srv_faulted);
    if (s == rrp::Send::WouldSend) rrp::Tally::add(g_tally.srv_would);
    if (s == rrp::Send::ActorTarget) rrp::Tally::add(g_tally.srv_actor);
    if (s != rrp::Send::Sent && s != rrp::Send::WouldSend && s != rrp::Send::ActorTarget) {
        rrp::Tally::add(g_tally.srv_other);
    }
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEvServer;
    e.flags = static_cast<uint16_t>((c.in.pre_ok ? 1u : 0u) | (c.in.err_ok ? 2u : 0u));
    e.v[0] = c.key | (uint64_t{c.in.slot} << 32) | (uint64_t{c.in.reason} << 40) | (uint64_t{c.extra} << 48);
    e.v[1] = c.in.kind | (uint64_t{c.in.cls} << 16);
    e.v[2] = c.in.target_actor;
    e.v[3] = c.in.err;
    e.v[4] = static_cast<uint64_t>(s) | (uint64_t{writer} << 8);
    uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, c.scene, 8);
    std::memcpy(&hi, c.scene + 8, 8);
    e.v[5] = lo;
    e.v[6] = hi;
    e.v[7] = c.handle;
    e.v[8] = c.seq;
    g_ring.push(e);
}

// ServerFrameEventReleaseRemoteCatch::vf1(this, &err, event, ?, &actor holder).
Arg srv_detour(Arg self, Arg err, Arg ev, Arg a4, Arg holder) {
    SrvCtx c;
    before_srv(c, ev, holder);
    const Arg r = g_srv_hook.unsafe_call<Arg>(self, err, ev, a4, holder);
    after_srv(c, err);
    return r;
}

// ---------------------------------------------------------------- F2 at the launch: the server's action change (host)

struct ActCtx {
    bool server = false;  // the server's component (its vtable): the client's calls pass straight through
    bool any = false;     // a slot was busy before the original
    uintptr_t actor = 0;
    uint32_t key = 0;
    rrp::ActionSlot s[rrp::kSlots];
    bool kind_ok[rrp::kSlots] = {};  // the kind read: a slot whose kind is unreadable is left alone (no event)
    uint8_t scene[rrp::kSlots][16] = {};
    uint64_t handle[rrp::kSlots] = {};
};

void before_act(ActCtx& c, uintptr_t comp) noexcept {
    const auto vt = game::fast<uint64_t>(comp);
    if (!vt || *vt != g_base + addrs().server_vtbl) return;
    c.server = true;
    for (uint8_t i = 0; i < rrp::kSlots; ++i) {
        rrp::ActionSlot& s = c.s[i];
        const uintptr_t t = rrp::slot_target(comp, i);
        const auto kind = game::fast<uint8_t>(t + rrp::kSlot_Kind);
        if (!kind) continue;
        c.kind_ok[i] = true;
        s.kind = *kind;
        if (s.kind == rrp::kSlotEmpty) {
            s.before_ok = true;
            continue;
        }
        c.any = true;
        const auto cls = game::fast<uint8_t>(t + rrp::kSlot_Class);
        const auto target = game::fast<uint32_t>(t + rrp::kSlot_Actor);
        if (!cls || !target) continue;
        s.cls = *cls;
        s.target_actor = *target;
        s.before_ok = true;
        (void)game::fast_read(t + rrp::kSlot_Scene, c.scene[i], sizeof c.scene[i]);
        if (const auto h = game::fast<uint64_t>(t + rrp::kSlot_Handle)) c.handle[i] = *h;
    }
    if (!c.any) return;
    if (const auto actor = game::fast_ptr(comp + rrp::kComp_Owner)) {
        c.actor = *actor;
        if (const auto k = game::fast<uint32_t>(*actor + rrp::kActor_Key)) c.key = *k;
    }
}

void after_act(ActCtx& c, uintptr_t comp) noexcept {
    for (uint8_t i = 0; i < rrp::kSlots; ++i) {
        rrp::ActionSlot& s = c.s[i];
        if (!c.kind_ok[i] || s.kind == rrp::kSlotEmpty) continue;
        if (s.before_ok) {
            if (const auto k = game::fast<uint8_t>(rrp::slot_target(comp, i) + rrp::kSlot_Kind)) {
                s.after_ok = true;
                s.after_kind = *k;
            }
        }
        const rrp::ActRelease r = rrp::decide_action_release(mode(), s);
        if (r == rrp::ActRelease::NotHeld || r == rrp::ActRelease::Kept) continue;
        uint8_t writer = kWriteNone;
        if (r == rrp::ActRelease::Sent) writer = c.actor ? send_2471(c.actor, i, rrp::kActReason) : kWriteFailed;
        rrp::Tally::add(g_tally.act_freed);
        if (r == rrp::ActRelease::Sent && writer == kWriteOk) rrp::Tally::add(g_tally.act_sent);
        if (r == rrp::ActRelease::Sent && writer != kWriteOk) rrp::Tally::add(g_tally.act_faulted);
        if (r == rrp::ActRelease::WouldSend) rrp::Tally::add(g_tally.act_would);
        if (r == rrp::ActRelease::ActorTarget) rrp::Tally::add(g_tally.act_actor);
        if (r == rrp::ActRelease::OutOfScope || r == rrp::ActRelease::Unreadable) rrp::Tally::add(g_tally.act_other);
        // Every freed slot goes to the worker (the launch fold needs the actor targets too); it logs act_logged() ones.
        p8p::Event e;
        e.qpc_us = p8_now_us();
        e.tid = GetCurrentThreadId();
        e.kind = kEvAction;
        e.v[0] = c.key | (uint64_t{i} << 32) | (uint64_t{rrp::kActReason} << 40);
        e.v[1] = rrp::opt8(s.before_ok, s.kind) | (uint64_t{rrp::opt8(s.before_ok, s.cls)} << 16) |
                 (uint64_t{rrp::opt8(s.after_ok, s.after_kind)} << 32);
        e.v[2] = s.target_actor;
        e.v[4] = static_cast<uint64_t>(r) | (uint64_t{writer} << 8);
        uint64_t lo = 0, hi = 0;
        std::memcpy(&lo, c.scene[i], 8);
        std::memcpy(&hi, c.scene[i] + 8, 8);
        e.v[5] = lo;
        e.v[6] = hi;
        e.v[7] = c.handle[i];
        e.v[8] = next_seq();
        g_ring.push(e);
    }
}

// The remote catch component's vf140 0x1807390 (comp, &flag, &new action, &old action): the action change. Called for
// the server's component by 0x2327320 (virtual) and for the client's by 0x58B380 (direct): only the server's is read.
void act_detour(Arg comp, Arg p_flag, Arg p_new, Arg p_old) {
    ActCtx c;
    before_act(c, comp);
    g_act_hook.unsafe_call<void>(comp, p_flag, p_new, p_old);
    if (c.server && c.any) after_act(c, comp);
}

// ---------------------------------------------------------------- install (the module's thread, world up)

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

bool qword_at(uintptr_t rva, uint64_t expected) {
    uint64_t v = 0;
    return game::safe_read(g_base + rva, &v, sizeof v) && v == expected;
}

struct Prepared {
    SafetyHookInline* slot = nullptr;
    std::optional<SafetyHookInline> hook;
};

bool prepare(uintptr_t rva, void* detour, std::span<const uint8_t> head, std::span<const uint32_t> bounds,
             const char* what, SafetyHookInline& slot, std::vector<Prepared>& out) {
    auto whole = [&](const std::vector<uint8_t>& o) {
        return std::find(bounds.begin(), bounds.end(), static_cast<uint32_t>(o.size())) != bounds.end() &&
               o.size() <= head.size() && std::memcmp(o.data(), head.data(), o.size()) == 0;
    };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(g_base + rva, detour, whole, "RemoteRope", what);
    if (!h) {
        log::error("RemoteRope: the hook on {} (exe+0x{:X}) could not be prepared ({}); REFUSED, nothing written", what,
                   rva, game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("RemoteRope: the hook on {} (exe+0x{:X}) would patch {} bytes, not whole verified instructions; "
                   "REFUSED, nothing written",
                   what, rva, orig.size());
        return false;
    }
    Prepared p;
    p.slot = &slot;
    p.hook = std::move(*h);
    out.push_back(std::move(p));
    return true;
}

bool install_hooks(bool host) {
    const Addrs& ad = addrs();
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("RemoteRope: the exe's sections are unreadable; REFUSED, nothing written");
        return false;
    }
    g_code_n = 0;
    for (const auto& s : secs) {
        // Every executable section: the real code and the protected RWX one, where vtable entries may also be.
        if ((s.flags & gad::kScnExecute) && g_code_n < std::size(g_code)) {
            g_code[g_code_n++] = {g_base + s.va, g_base + s.va + s.size};
        }
    }
    const auto in_rsrc = [&](uintptr_t rva, size_t n) {
        return rva >= kCodeBegin && rva + n <= ad.code_end &&
               gad::in_real_code(secs, static_cast<uint32_t>(rva), static_cast<uint32_t>(n));
    };
    struct Check {
        uintptr_t rva;
        std::span<const uint8_t> bytes;
        const char* what;
    };
    std::vector<Check> checks = {
        {ad.apply, rrp::kApplyHead, "RemoteCatchComponent_Apply 0x592340's entry"},
        {ad.apply_call, ad.apply_call_bytes, "its only caller 0xB5BB7B (call 0x592340)"},
        {ad.info_copy, rrp::kInfoCopyBytes, "the target block's copy 0x59238F..0x5923B4 (+0x18 = the handle)"},
        {ad.map_site, ad.map_site_bytes, "the thrower's mapping 0x5947C7..0x59484E (scene id -> handle)"},
        {ad.resolve, rrp::kResolveHead, "ResolveUuidLookup 0x1851010"},
        {ad.att_dtor, rrp::kAttDtorHead, "the attacher dtor 0x1434880"},
        {ad.release, rrp::kReleaseHead, "the release request 0x5A7A10"},
        {ad.release_thread_check, ad.release_check_bytes, "its main-thread check 0x5A7A7D"},
        {ad.h2471, ad.h2471_head, "ReleaseRemoteCatchResultAck::vf2 0xB5BD60's entry"},
        {ad.h2471_release, ad.h2471_release_bytes, "its release call 0xB5BF44..0xB5BF61"},
    };
    if (host) {
        checks.push_back({ad.srv_release, rrp::kSrvReleaseHead, "ServerFrameEventReleaseRemoteCatch::vf1 0x27D9110"});
        checks.push_back({ad.srv_args, ad.srv_args_bytes, "its argument reads 0x27D9134..0x27D914B"});
        checks.push_back({ad.writer, rrp::kWriterHead, "the 2471 writer 0x29688C0"});
        checks.push_back({ad.writer_site, ad.writer_site_bytes, "0x2903950's ToNear call 0x2903A79..0x2903AB1"});
        checks.push_back({ad.to_near_vf1, rrp::kToNearVf1Bytes, "ToNear::vf1 0x2A75860 ([[actor+0x68]+0x1A0])"});
        checks.push_back({ad.ts_owner_call, rrp::kTsOwnerCallBytes, "0x2BC4F70's owner call 0x2BC4F92 ([ts+8]->vfE8)"});
        checks.push_back({ad.act_release, rrp::kActReleaseHead, "the remote catch component's vf140 0x1807390"});
        checks.push_back({ad.act_dispatch, ad.act_dispatch_bytes,
                          "the action change's vf140 call 0x2328EE4..0x2328F02 ([[actor+0x68]+0x78])"});
        checks.push_back(
            {ad.act_client_call, ad.act_client_call_bytes, "the client's vf140 call 0x58B3D9 (call 0x1807390)"});
        checks.push_back({ad.act_keep_test, rrp::kActKeepTestBytes, "0x1807390's keep-flag test 0x1807610"});
        checks.push_back({ad.act_notify, rrp::kActNotifyBytes, "0x1807390's target vf148 call 0x1807646"});
        checks.push_back({ad.act_self_release, rrp::kActSelfReleaseBytes, "0x1807390's own vf158 call 0x18076DF"});
    }
    for (const Check& c : checks) {
        if (!in_rsrc(c.rva, c.bytes.size()) || !bytes_at(c.rva, c.bytes)) {
            log::error("RemoteRope: {} (exe+0x{:X}, {} bytes) is not this build's expected code; REFUSED, nothing written",
                       c.what, c.rva, c.bytes.size());
            return false;
        }
    }
    if (!qword_at(ad.h2471_slot, g_base + ad.h2471)) {
        log::error("RemoteRope: the vtable slot exe+0x{:X} does not hold exe+0x{:X}; REFUSED, nothing written", ad.h2471_slot,
                   ad.h2471);
        return false;
    }
    if (host && !qword_at(ad.srv_release_slot, g_base + ad.srv_release)) {
        log::error("RemoteRope: the vtable slot exe+0x{:X} does not hold exe+0x{:X}; REFUSED, nothing written",
                   ad.srv_release_slot, ad.srv_release);
        return false;
    }
    if (host && (!qword_at(ad.act_release_slot, g_base + ad.act_release) ||
                 !qword_at(ad.srv_vf158_slot, g_base + ad.slot_reset))) {
        log::error("RemoteRope: ServerRemoteCatchActorComponent's vtable exe+0x{:X} does not hold exe+0x{:X} (vf140) and "
                   "exe+0x{:X} (vf158); REFUSED, nothing written",
                   ad.server_vtbl, ad.act_release, ad.slot_reset);
        return false;
    }
    uint64_t tonear = 0;
    if (host && (!game::safe_read(g_base + ad.to_near_vtbl, &tonear, sizeof tonear) || !in_code(tonear) ||
                 !qword_at(ad.to_near_vtbl + 8, g_base + ad.to_near_vf1))) {
        log::error("RemoteRope: ToNearSendTargetFinder's vtable exe+0x{:X} does not point at code / its vf1 is not "
                   "exe+0x{:X}; REFUSED",
                   ad.to_near_vtbl, ad.to_near_vf1);
        return false;
    }
    if (!game::fast<uint32_t>(g_base + ad.main_thread_id)) {
        log::error("RemoteRope: the main thread's id exe+0x{:X} is unreadable; REFUSED, nothing written",
                   ad.main_thread_id);
        return false;
    }

    std::vector<Prepared> ready;
    if (!prepare(ad.apply, reinterpret_cast<void*>(&apply_detour), rrp::kApplyHead, rrp::kApplyBoundaries,
                 "RemoteCatchComponent_Apply 0x592340", g_apply_hook, ready) ||
        !prepare(ad.h2471, reinterpret_cast<void*>(&h2471_detour), ad.h2471_head, ad.h2471_boundaries,
                 "ReleaseRemoteCatchResultAck::vf2 0xB5BD60", g_h2471_hook, ready) ||
        (host && !prepare(ad.srv_release, reinterpret_cast<void*>(&srv_detour), rrp::kSrvReleaseHead,
                          rrp::kSrvReleaseBoundaries, "ServerFrameEventReleaseRemoteCatch::vf1 0x27D9110", g_srv_hook,
                          ready)) ||
        (host && !prepare(ad.act_release, reinterpret_cast<void*>(&act_detour), rrp::kActReleaseHead,
                          rrp::kActReleaseBoundaries, "the remote catch component's vf140 0x1807390", g_act_hook,
                          ready))) {
        return false;
    }
    std::string patched;
    for (Prepared& p : ready) {
        patched += std::format("{}{}", patched.empty() ? "" : "/", p.hook->original_bytes().size());
        *p.slot = std::move(*p.hook);
    }
    std::vector<SafetyHookInline*> enabled;
    for (Prepared& p : ready) {
        if (!p.slot->enable()) {
            log::error("RemoteRope: a hook could not be enabled; the others are put back; REFUSED");
            for (SafetyHookInline* h : enabled) (void)h->disable();
            return false;
        }
        enabled.push_back(p.slot);
    }
    g_hooks_on.store(true);
    log::info("RemoteRope: hooked at their entries ({} bytes patched): exe+0x{:X} (RemoteCatchComponent_Apply, the "
              "2763 apply; one caller exe+0x{:X}), exe+0x{:X} (the 2471 handler, log only){}; {}",
              patched, ad.apply, ad.apply_call, ad.h2471,
              host ? std::format(", exe+0x{:X} (the server's release frame event), exe+0x{:X} (the remote catch "
                                 "component's vf140: the action change that frees the slot on a launch; the server's "
                                 "component only)",
                                 ad.srv_release, ad.act_release)
                   : std::string(),
              mode() == Mode::On
                  ? "remote_rope=1: a remote thrower's tree handle translated, its stale slot released first; the host's "
                    "server sends the 2471 the tree release lacks"
                  : "remote_rope=probe: computed and logged with native-equivalent reads, no game state written");
    return true;
}

// ---------------------------------------------------------------- the module's thread

bool build_ok() {
    const game::Build b = game::current_build();
    return g_base == g2976::kImageBase && (b == game::Build::v2976 || b == game::Build::v3527 || b == game::Build::v3576 ||
                                           b == game::Build::v3663);
}

std::string b8(uint64_t f) { return rrp::opt8_ok(f) ? std::format("{}", rrp::opt8_val(f)) : std::string("?"); }
std::string ctl_text(uint64_t f) {
    if (!rrp::opt8_ok(f)) return "control unreadable";
    return rrp::opt8_val(f) ? std::format("controlled HERE (+0xC8 = {})", rrp::opt8_val(f)) : "REMOTE (+0xC8 = 0)";
}
// Who an actor key is on THIS client (read on the module's thread, for the server lines).
std::string who_here(uint32_t key) {
    const auto actor = game::find_actor(key);
    if (!actor) return "not found on this client";
    const auto ctl = game::fast<uint8_t>(*actor + rrp::kActor_Control);
    if (!ctl) return "control unreadable";
    return *ctl ? "controlled by this client (the host or its NPCs)" : "REMOTE here (user 2's)";
}
std::string handle_text(uint64_t h) { return h == rrp::kNoHandle ? std::string("-1") : std::format("0x{:016X}", h); }
const char* f3_text(uint64_t v) {
    switch (v) {
        case kF3Released: return " -> RELEASED (slot empty now)";
        case kF3Deferred: return " -> release DEFERRED (not the main thread: the update will run it)";
        case kF3LeftBusy: return " -> release called, slot STILL busy";
        case kF3Faulted: return " -> release FAULTED (F3 off)";
        case kF3Skipped: return " -> release skipped (F3 off after a fault)";
        case kF3Unsafe: return " -> release NOT called (component / lock object not the expected ones)";
        default: return "";
    }
}

// The rope's flight after an apply, read on the module's thread (game::read: VirtualQuery + SEH) through the thrower's
// key, never a pointer kept from the hook.
struct FlightRead {
    bool found = false;
    bool state_ok = false;
    uint8_t state = 0;
    bool flight_ok = false;
    float flight = 0;
};
FlightRead read_flight(uint32_t key, uint8_t slot) {
    FlightRead r;
    if (slot >= rrp::kSlots) return r;
    const auto actor = game::find_actor(key);
    if (!actor) return r;
    r.found = true;
    const auto comps = game::read_ptr(*actor + rrp::kActor_Comps);
    const auto comp = comps ? game::read_ptr(*comps + rrp::kComps_RemoteCatch) : std::nullopt;
    if (!comp) return r;
    if (const auto st = game::read<uint8_t>(slot_state(*comp, slot))) {
        r.state_ok = true;
        r.state = *st;
    }
    if (const auto f = game::read<float>(slot_flight(*comp, slot))) {
        r.flight_ok = true;
        r.flight = *f;
    }
    return r;
}
uint64_t ms_since(uint64_t qpc_us) {
    const uint64_t now = p8_now_us();
    return now > qpc_us ? (now - qpc_us) / 1000 : 0;
}
std::string flight_text(const FlightRead& r, float speed, uint64_t after_ms) {
    if (!r.found) return std::format("flight not measured (the thrower is not on this client at +{} ms)", after_ms);
    if (!r.state_ok || !r.flight_ok) return std::format("flight not measured (slot unreadable at +{} ms)", after_ms);
    if (!rrp::flight_ready(r.state)) return std::format("flight not seen (state {} at +{} ms)", r.state, after_ms);
    return std::format("flight {:.3f} s x speed {:.1f} = {:.1f} m (state {} at +{} ms)", r.flight, speed,
                       r.flight * speed, r.state, after_ms);
}

const char* writer_text(uint64_t w) {
    switch (w) {
        case kWriteOk: return " (writer 0x29688C0 returned)";
        case kWriteUnsafe:
            return " (writer NOT called: the thrower's TransformSync or its owner's vtable is not the expected one)";
        default: return " (writer FAULTED, or off after a fault: F2 off)";
    }
}

// At a launch the server frees: the thrower's slot on THIS client, read on the module's thread by key (<= one tick,
// 500 ms, after the server freed it). For a thrower controlled here it is the thrower's OWN client: a busy slot (state
// 4: 0x58B380 kept it, 0x59F760) is the case where a 2471 would cut its rope mid-air (0xB5BD60 -> 0x5A7A10 -> 0x5A7BC0
// -> 0x5A0C60 retract + 0x1807C80). For a remote thrower it is this client's copy (the observer: busy is expected).
struct ClientSlot {
    bool found = false;
    bool ctl_ok = false;
    uint8_t ctl = 0;
    bool kind_ok = false;
    uint8_t kind = 0;
    bool state_ok = false;
    uint8_t state = 0;
};
ClientSlot read_client_slot(uint32_t key, uint8_t slot) {
    ClientSlot r;
    if (slot >= rrp::kSlots) return r;
    const auto actor = game::find_actor(key);
    if (!actor) return r;
    r.found = true;
    if (const auto c = game::read<uint8_t>(*actor + rrp::kActor_Control)) {
        r.ctl_ok = true;
        r.ctl = *c;
    }
    const auto comps = game::read_ptr(*actor + rrp::kActor_Comps);
    const auto comp = comps ? game::read_ptr(*comps + rrp::kComps_RemoteCatch) : std::nullopt;
    if (!comp) return r;
    if (const auto k = game::read<uint8_t>(rrp::slot_target(*comp, slot) + rrp::kSlot_Kind)) {
        r.kind_ok = true;
        r.kind = *k;
    }
    if (const auto st = game::read<uint8_t>(slot_state(*comp, slot))) {
        r.state_ok = true;
        r.state = *st;
    }
    return r;
}
std::string thrower_slot_text(const ClientSlot& c, uint64_t after_ms, bool sent) {
    if (!c.found) return " | the thrower is not on this client";
    const std::string ks = c.kind_ok ? std::format("{}", c.kind) : std::string("?");
    const std::string ss = c.state_ok ? std::format("{}", c.state) : std::string("?");
    if (!c.ctl_ok || !c.kind_ok) return std::format(" | the thrower's slot here unreadable (kind {} state {})", ks, ss);
    if (c.ctl == 0) {
        return std::format(" | this client's copy (observer) of the thrower's slot: kind {} state {} (+{} ms)", ks, ss,
                           after_ms);
    }
    return std::format(" | the thrower's OWN client slot when the server freed it: kind {} state {} (+{} ms){}{}", ks,
                       ss, after_ms,
                       c.kind == rrp::kSlotEmpty ? " -> free: the 2471 meets an empty slot"
                                                 : " -> BUSY: a 2471 would cut its rope (keep remote_rope=probe)",
                       sent ? " [read after this 2471: its '2471 applied ... slot before' line is the measure]" : "");
}

void log_apply(const p8p::Event& e, const std::string& flight) {
    const char* m = rrp::mode_name(mode());
    const auto key = static_cast<uint32_t>(e.v[0]);
    const auto target = static_cast<rrp::Target>(e.v[6] & 0xFF);
    const auto stale = static_cast<rrp::Stale>((e.v[6] >> 8) & 0xFF);
    const auto resolve = static_cast<rrp::Resolve>((e.v[6] >> 16) & 0xFF);
    const uint64_t f3 = (e.v[6] >> 24) & 0xFF;
    const uint64_t write = (e.v[6] >> 32) & 0xFF;
    std::string action;
    if (target == rrp::Target::RemoteTranslate) {
        action = write == kWriteOk ? std::string(" -> WRITTEN")
                 : write == kWriteFailed ? std::string(" -> the write FAILED (passed through)")
                                         : std::string(" -> WOULD WRITE with remote_rope=1");
    }
    const bool err_ok = (e.flags & 8) != 0;
    log::info("RemoteRope [{}] #{} apply {}: thrower 0x{:08X} {} | slot {} kind {} class {} target actor 0x{:08X} | "
              "scene {:016X}:{:016X} | packet handle {} | this PC's {} ({}) | {}{} | slot before {} state {} | "
              "{}{} | after: err {} slot {} state {} | {} | point ({:.2f}, {:.2f}, {:.2f}) | {}{}{}",
              m, static_cast<uint32_t>(e.v[8]), p8_when(e.qpc_us), key, ctl_text(e.v[0] >> 32), b8(e.v[0] >> 48),
              b8(e.v[1]), b8(e.v[1] >> 16), static_cast<uint32_t>(e.v[8] >> 32), e.v[2], e.v[3],
              handle_text(e.v[4]), handle_text(e.v[5]), rrp::resolve_name(resolve), rrp::target_name(target), action,
              b8(e.v[1] >> 32), b8(e.v[1] >> 48), rrp::stale_name(stale), f3_text(f3),
              err_ok ? std::format("0x{:X}", static_cast<uint32_t>(e.v[7])) : std::string("?"), b8(e.v[7] >> 32),
              b8(e.v[7] >> 48), flight, rrp::unpack_lo(e.v[10]), rrp::unpack_hi(e.v[10]),
              rrp::unpack_lo(e.v[11]), (e.flags & 2) ? "main thread" : "NOT the main thread",
              (e.flags & 1) ? "" : " | UNEXPECTED caller",
              (e.flags & 64) ? " | a FAULT in a game call: this 2763 NOT applied (native error), that call off" : "");
}

// `empty_note`: a release event that found the server slot already empty and was not folded.
void log_event(const p8p::Event& e, bool empty_note = false) {
    const char* m = rrp::mode_name(mode());
    if (e.kind == kEvBody) {
        const auto key = static_cast<uint32_t>(e.v[0]);
        const bool ok = ((e.v[0] >> 40) & 1) != 0;
        const bool local = ((e.v[0] >> 32) & 0xFF) == 1;
        if (!ok) {
            log::info("RemoteRope [{}] #{} body: thrower 0x{:08X}, {} handle {}: NO body here (vf3B0 false)", m,
                      static_cast<uint32_t>(e.v[9]), key, local ? "this PC's" : "the packet's", handle_text(e.v[1]));
            return;
        }
        log::info("RemoteRope [{}] #{} body: thrower 0x{:08X}, {} handle {}: translation ({:.2f}, {:.2f}, {:.2f}) "
                  "rotation ({:.3f}, {:.3f}, {:.3f}, {:.3f}) scale ({:.2f}, {:.2f}, {:.2f}) -> hook point in the world "
                  "({:.2f}, {:.2f}, {:.2f})",
                  m, static_cast<uint32_t>(e.v[9]), key, local ? "this PC's" : "the packet's", handle_text(e.v[1]),
                  rrp::unpack_lo(e.v[2]), rrp::unpack_hi(e.v[2]), rrp::unpack_lo(e.v[3]), rrp::unpack_hi(e.v[3]),
                  rrp::unpack_lo(e.v[4]), rrp::unpack_hi(e.v[4]), rrp::unpack_lo(e.v[5]), rrp::unpack_hi(e.v[5]),
                  rrp::unpack_lo(e.v[6]), rrp::unpack_hi(e.v[6]), rrp::unpack_lo(e.v[7]), rrp::unpack_hi(e.v[7]),
                  rrp::unpack_lo(e.v[8]));
    } else if (e.kind == kEvServer) {
        const auto key = static_cast<uint32_t>(e.v[0]);
        const auto s = static_cast<rrp::Send>(e.v[4] & 0xFF);
        const uint64_t writer = (e.v[4] >> 8) & 0xFF;
        log::info("RemoteRope [{}] #{} server release {}: thrower 0x{:08X} ({}) slot {} reason {} b10 {} | server slot "
                  "kind {} class {} target actor 0x{:08X} scene {:016X}:{:016X} handle {} | err 0x{:X} | {}{} | "
                  "server thread {}{}",
                  m, static_cast<uint32_t>(e.v[8]), p8_when(e.qpc_us), key, who_here(key), (e.v[0] >> 32) & 0xFF,
                  (e.v[0] >> 40) & 0xFF, (e.v[0] >> 48) & 0xFF, e.v[1] & 0xFF, (e.v[1] >> 16) & 0xFF,
                  static_cast<uint32_t>(e.v[2]), e.v[5], e.v[6], handle_text(e.v[7]), static_cast<uint32_t>(e.v[3]),
                  rrp::send_name(s),
                  s == rrp::Send::Sent ? writer_text(writer) : "",
                  e.tid,
                  empty_note ? " | the server slot was ALREADY EMPTY (freed before this release event by a path not "
                               "hooked; the next ones for this slot are counted, not logged)"
                             : "");
    } else if (e.kind == kEv2471) {
        const bool parsed = (e.flags & 1) != 0, found = (e.flags & 2) != 0;
        if (!parsed) {
            log::info("RemoteRope [{}] #{} 2471 applied {}: payload not the 6-byte {{key, slot, reason}} (unparsed)", m,
                      static_cast<uint32_t>(e.v[3]), p8_when(e.qpc_us));
            return;
        }
        log::info("RemoteRope [{}] #{} 2471 applied {}: thrower 0x{:08X} slot {} reason {} | {} | slot before {} state "
                  "{} -> after {} state {} | {}",
                  m, static_cast<uint32_t>(e.v[3]), p8_when(e.qpc_us), static_cast<uint32_t>(e.v[0]),
                  (e.v[0] >> 32) & 0xFF, (e.v[0] >> 40) & 0xFF, found ? ctl_text(e.v[1]) : "actor NOT FOUND here",
                  b8(e.v[1] >> 16), b8(e.v[1] >> 32), b8(e.v[1] >> 48), b8(e.v[2]),
                  (e.flags & 4) ? "main thread" : "NOT the main thread");
    }
}

// The launch's line (F2 at 0x1807390); `thrower`: the thrower's slot on this client (thrower_slot_text).
void log_action(const p8p::Event& e, const std::string& thrower) {
    const auto key = static_cast<uint32_t>(e.v[0]);
    const auto r = static_cast<rrp::ActRelease>(e.v[4] & 0xFF);
    const uint64_t writer = (e.v[4] >> 8) & 0xFF;
    log::info("RemoteRope [{}] #{} server release on an ACTION CHANGE {}: thrower 0x{:08X} ({}) slot {} reason {} | "
              "server slot kind {} class {} target actor 0x{:08X} scene {:016X}:{:016X} handle {} -> kind {} after "
              "vf140 0x1807390 (the launch path: no release frame event, and the native code sends a 2471 only for an "
              "actor target) | {}{}{} | server thread {}",
              rrp::mode_name(mode()), static_cast<uint32_t>(e.v[8]), p8_when(e.qpc_us), key, who_here(key),
              (e.v[0] >> 32) & 0xFF, (e.v[0] >> 40) & 0xFF, b8(e.v[1]), b8(e.v[1] >> 16),
              static_cast<uint32_t>(e.v[2]), e.v[5], e.v[6], handle_text(e.v[7]), b8(e.v[1] >> 32),
              rrp::act_release_name(r), r == rrp::ActRelease::Sent ? writer_text(writer) : "", thrower, e.tid);
}

void log_summary(uint64_t not_logged) {
    const rrp::Tally& t = g_tally;
    const auto n = [](const std::atomic<uint64_t>& c) { return c.load(std::memory_order_relaxed); };
    const bool on = mode() == Mode::On;
    log::info("RemoteRope summary (remote_rope={}, {}): hooks {} | 2763 applies {} (unexpected caller {}): own {}, remote "
              "{}, not a body target {}, unreadable {} | own: handle match {}, MISMATCH {}, unresolved {} | remote: same "
              "handle {}, to translate {} -> {} {}{}, unresolved {} | stale slots {} -> released {}, deferred {}, still "
              "busy {}, release off {}, lock check failed {}, non-tree stale slots logged only {} | own throws not "
              "computed (check done) {} | applies failed {} (slot left dirty {}, not applied after a fault {}) | server "
              "releases {}: {} {}, actor targets {}, other {}, writer faults {} | slots freed by an action change (the "
              "launch) {}: trees {} {}, actor targets {} (their native 2471), other {}, writer faults {} | the "
              "thrower's own client slot then: free {}, BUSY {}, unreadable {} | release events on a slot already freed "
              "{} (folded, not logged) | writer not called (TransformSync check) {} | 2471 applied {} (own {}, remote "
              "{}, slot busy before {}, unparsed {}) | faults: F1 {} release {} writer {} body {} | lines not logged {}, "
              "ring dropped {}",
              rrp::mode_name(mode()), g_guest.load() ? "guest" : "host", g_hooks_on.load() ? "on" : "OFF", n(t.applies),
              n(t.unexpected_caller), n(t.own), n(t.remote), n(t.not_tree), n(t.unreadable), n(t.own_match),
              n(t.own_mismatch), n(t.own_unresolved), n(t.remote_same), n(t.remote_translate),
              on ? "written" : "would be written with remote_rope=1", on ? n(t.translated) : n(t.remote_translate),
              on ? std::format(" (write failed {})", n(t.write_failed)) : std::string(), n(t.remote_unresolved),
              n(t.stale), n(t.stale_released), n(t.stale_deferred), n(t.stale_left), n(t.release_faulted),
              n(t.release_unsafe), n(t.stale_out_of_scope), n(t.own_skipped), n(t.apply_failed), n(t.failed_dirty),
              n(t.not_applied_after_fault), n(t.srv_releases), on ? "2471 sent" : "2471 would be sent",
              on ? n(t.srv_sent) : n(t.srv_would), n(t.srv_actor), n(t.srv_other), n(t.srv_faulted), n(t.act_freed),
              on ? "2471 sent" : "2471 would be sent", on ? n(t.act_sent) : n(t.act_would), n(t.act_actor),
              n(t.act_other), n(t.act_faulted), n(t.act_thrower_free), n(t.act_thrower_busy), n(t.act_thrower_unread),
              n(t.srv_folded), n(t.writer_unsafe), n(t.h2471),
              n(t.h2471_own), n(t.h2471_remote), n(t.h2471_busy_before), n(t.h2471_unparsed),
              g_f1_faulted.load() ? 1 : 0, g_release_faulted.load() ? 1 : 0, g_writer_faulted.load() ? 1 : 0,
              g_diag_faulted.load() ? 1 : 0, not_logged, g_ring.dropped());
}

DWORD WINAPI worker_thread(LPVOID) {
    try {
        game::PlayerReader reader;
        reader.init();
        uint32_t in_world = 0;
        bool hook_tried = false;
        bool own_done_logged = false;
        uint64_t lines = 0, not_logged = 0;
        uint64_t last_minute = GetTickCount64();
        const auto may_log = [&] {
            if (lines++ < kEventLines) return true;
            ++not_logged;
            return false;
        };
        rrp::LaunchFold fold;
        // The applies waiting for their rope's flight (0x5A12A0 sets it after the apply): logged when it is there.
        constexpr size_t kPendingMax = 16;
        std::vector<p8p::Event> pending;
        for (;;) {
            Sleep(kTickMs);
            const uint64_t now = GetTickCount64();
            if (!hook_tried) {
                in_world = reader.read() ? in_world + 1 : 0;
                if (in_world < kWorldTicks) continue;
                hook_tried = true;
                if (!install_hooks(!g_guest.load())) {
                    log::error("RemoteRope [{}]: the hooks are not in; remote_rope does nothing this run",
                               rrp::mode_name(mode()));
                    return 0;
                }
                last_minute = now;
            }
            p8p::Event e;
            while (g_ring.pop(e)) {
                const auto key = static_cast<uint32_t>(e.v[0]);
                if (e.kind == kEvApply) {
                    const uint64_t slot_f = e.v[0] >> 48, type_f = e.v[7] >> 32;
                    const bool applied = (e.flags & 8) && static_cast<uint32_t>(e.v[7]) == 0 && rrp::opt8_ok(slot_f) &&
                                         rrp::opt8_ok(type_f) && rrp::opt8_val(type_f) != rrp::kSlotEmpty;
                    if (applied) fold.on_apply(key, rrp::opt8_val(slot_f));
                    if (applied && pending.size() < kPendingMax) {
                        pending.push_back(e);
                    } else if (may_log()) {
                        log_apply(e, applied ? "flight not measured (too many applies waiting)"
                                             : "flight not measured (the apply did not fill the slot)");
                    }
                    continue;
                }
                if (e.kind == kEvAction) {
                    const auto r = static_cast<rrp::ActRelease>(e.v[4] & 0xFF);
                    const uint8_t slot = (e.v[0] >> 32) & 0xFF;
                    if (r != rrp::ActRelease::Unreadable) fold.on_action_free(key, slot);
                    std::string thrower;
                    if (r == rrp::ActRelease::Sent || r == rrp::ActRelease::WouldSend) {
                        const ClientSlot cs = read_client_slot(key, slot);
                        if (cs.found && cs.ctl_ok && cs.ctl != 0) {
                            rrp::Tally::add(!cs.kind_ok                     ? g_tally.act_thrower_unread
                                            : cs.kind == rrp::kSlotEmpty ? g_tally.act_thrower_free
                                                                         : g_tally.act_thrower_busy);
                        }
                        thrower = thrower_slot_text(cs, ms_since(e.qpc_us), r == rrp::ActRelease::Sent);
                    }
                    if (rrp::act_logged(r) && may_log()) log_action(e, thrower);
                    continue;
                }
                bool empty_note = false;
                if (e.kind == kEvServer && (e.flags & 1)) {
                    const uint8_t slot = (e.v[0] >> 32) & 0xFF;
                    if ((e.v[1] & 0xFF) == rrp::kSlotEmpty) {
                        if (fold.on_empty_release(key, slot)) {
                            rrp::Tally::add(g_tally.srv_folded);
                            continue;
                        }
                        empty_note = true;
                    } else {
                        fold.on_release(key, slot);
                    }
                }
                if (may_log()) log_event(e, empty_note);
            }
            for (auto it = pending.begin(); it != pending.end();) {
                const uint64_t after_ms = ms_since(it->qpc_us);
                const FlightRead r = read_flight(static_cast<uint32_t>(it->v[0]), rrp::opt8_val(it->v[0] >> 48));
                if (!r.found || (r.state_ok && rrp::flight_ready(r.state)) || after_ms >= rrp::kFlightWaitMs) {
                    if (may_log()) log_apply(*it, flight_text(r, rrp::unpack_hi(it->v[9]), after_ms));
                    it = pending.erase(it);
                } else {
                    ++it;
                }
            }
            if (!own_done_logged && g_own_check_done.load()) {
                own_done_logged = true;
                log::info("RemoteRope: own-throw check done ({} consecutive 'own throw, handle match'): this PC's own "
                          "throws are no longer computed",
                          rrp::kOwnChecks);
            }
            if (now - last_minute >= kMinuteMs) {
                last_minute = now;
                log_summary(not_logged);
            }
        }
    } catch (...) {
        log::error("RemoteRope: the worker stopped (exception); nothing more is logged (the hooks stay as they are)");
    }
    return 0;
}

}  // namespace

void remote_rope_start(const std::string& raw, bool guest) {
    const auto p = rrp::parse_mode(raw);
    if (!p.known) {
        log::warn("RemoteRope: remote_rope='{}' is not 0, probe or 1; it stays off", raw);
        return;
    }
    if (p.mode == Mode::Off) return;
    if (g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!build_ok()) {
        log::error("RemoteRope: unsupported game build (not 1.0.0.2976, 1.0.0.3527, 1.0.0.3576 or 1.0.0.3663); remote_rope "
                   "stays off");
        return;
    }
    g_guest.store(guest);
    g_mode.store(static_cast<uint8_t>(p.mode), std::memory_order_release);
    log::info("RemoteRope ON (remote_rope={}, {}): hooks at the entries of RemoteCatchComponent_Apply exe+0x{:X} and the "
              "2471 handler exe+0x{:X}{} once the world is up; {} (docs/research/s25/gancho-cuerda.md)",
              rrp::mode_name(p.mode), guest ? "guest" : "host", addrs().apply, addrs().h2471,
              guest ? std::string()
                    : std::format(", of the server's ServerFrameEventReleaseRemoteCatch::vf1 exe+0x{:X} and of the remote "
                                  "catch component's vf140 exe+0x{:X} (the action change: the launch)",
                                  addrs().srv_release, addrs().act_release),
              p.mode == Mode::On ? "a remote thrower's tree handle is translated to this PC's and its stale slot "
                                   "released; the host's server sends the release 2471 for trees"
                                 : "every rope computed, logged and counted with native-equivalent reads (the "
                                   "lookup's lock and reference, vf70 / vf3B0 calls), no game state written");
    if (HANDLE h = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr)) CloseHandle(h);
}

}  // namespace cdmp::session2
