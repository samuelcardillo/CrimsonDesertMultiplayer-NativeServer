#include "mod/session2/mount_sync.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cmath>
#include <cstring>
#include <format>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/game_fault.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/focus_follow.h"
#include "mod/session2/freeze_watchdog.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/mount_sync_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/ride_filter.h"
#include "mod/session2/ride_filter_logic.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

namespace off = game::build_2976;
using msl::Mode;

// ---------------------------------------------------------------- build 1.0.0.2976 [V, PE + mounts-20261011 PUNTOS-VERIFICADOS]

struct Point {
    uintptr_t rva;
    uint32_t patch;                 // the whole instructions safetyhook may move
    const uint8_t* bytes;           // verified at rva (context included)
    uint32_t len;
    const char* what;
};
constexpr uint8_t kEntry7[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x44, 0x88, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x55};
constexpr uint8_t kRideEnter[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70, 0x18, 0x55, 0x57, 0x41, 0x54, 0x41};
constexpr uint8_t kHandler[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
constexpr uint8_t kVf54[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57};

// Where everything is, per build. The function heads above are byte-identical in both; the jmp thunks carry their
// target. Log lines and comments keep the 2976 names (the research is written against that build).
struct Addrs {
    uintptr_t common_vf53, client_vf53, rideoff_thunk, client_vf54, ride_on, ride_off, h2663, h2916, h2991, code_end;
    uintptr_t gate, gate_ret, gate_site, gate_or, hold, action_req;
    uint8_t thunk_vf53[5], thunk_rideoff[5];
    const uint8_t* gate_head;
    uint32_t gate_head_len;
    uint8_t gate_site_bytes[16];
    uint32_t mc_method, mc_methods, rideoff_key, vf178_actor, vf178_user;
};
constexpr uint8_t kGateThunk2976[] = {0xE9, 0xAB, 0xEF, 0xB2, 0x0C};  // jmp 0xEE58A40 (.xtls, never touched)
// 3527: the gate is no longer a thunk. Its first instruction (mov [rsp+10h],rbx) is the 5 bytes patched.
constexpr uint8_t kGateHead3527[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57, 0x41, 0x56, 0x48, 0x8D};
constexpr Addrs kAddrs2976{0x2228260, 0xA45740, 0x2228E40, 0xA45760, 0x681C80, 0x682C20, 0xBB4130, 0xBB4AC0, 0xB57720, 0x51EB000,
                           0x2329A90, 0x8639CD, 0x8639C0, 0x1EC9C26, 0x88E6A0, 0xA45AC0,
                           {0xE9, 0x5B, 0x39, 0x38, 0x09},  // jmp 0x9DC90A0 (.xtls body: calls 0x2228260)
                           {0xE9, 0x1B, 0xA0, 0x4C, 0x0C},  // jmp 0xE6F2E60 (.xtls body)
                           kGateThunk2976, sizeof kGateThunk2976,
                           {0x48, 0x8D, 0x54, 0x24, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0xC3, 0x60, 0xAC, 0x01, 0x45, 0x89, 0x26},
                           0xF0, 0xF8, 0xD4, 0x4FE260, 0x8A67D0};
// 1.0.0.3527 [V capstone on the PE; live on 2026-11-05]: vtables ClientVehicle 0x5944B90 slots 53/54, CommonVehicle
// 0x5CEFC28 slot 53, RideOn/RideOff slot 7. RideOff thunk = vf53's own call at 0x23FD276. mc+0x60 = CC unchanged; the
// live movement component holds its 23 methods from +0x140 (6 RideOn, 7 RideOff), current index at +0x13C (0x965CCC). RideOff's
// cached horse key is written at 0x750DA3 (+0xD0).
constexpr Addrs kAddrs3527{0x23FD080, 0xB4D8D0, 0x23FDCC0, 0xB4D8F0, 0x74FBB0, 0x750B80, 0xCD89E0, 0xCD94B0, 0xC64250, 0x5595000,
                           0x251A350, 0x948E73, 0x948E66, 0x207A756, 0x976320, 0xB4DD20,
                           {0xE9, 0x5B, 0xC9, 0xE2, 0x08},  // jmp 0x997A230
                           {0xE9, 0x9B, 0xF8, 0x98, 0x0A},  // jmp 0xCD8D560
                           kGateHead3527, sizeof kGateHead3527,
                           {0x48, 0x8D, 0x54, 0x24, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0xDD, 0x14, 0xBD, 0x01, 0x45, 0x89, 0x26},
                           0x13C, 0x140, 0xD0, 0x5B3440, 0x98F8A0};
// 1.0.0.3549: the same table; only the two thunks' rel32 moved with the protected section.
constexpr Addrs kAddrs3549{0x23FD080, 0xB4D8D0, 0x23FDCC0, 0xB4D8F0, 0x74FBB0, 0x750B80, 0xCD89E0, 0xCD94B0, 0xC64250, 0x5595000,
                           0x251A350, 0x948E73, 0x948E66, 0x207A756, 0x976320, 0xB4DD20,
                           {0xE9, 0x7B, 0x20, 0xD5, 0x08},  // jmp 0x989F950
                           {0xE9, 0x5B, 0x2A, 0x94, 0x0A},  // jmp 0xCD40720
                           kGateHead3527, sizeof kGateHead3527,
                           {0x48, 0x8D, 0x54, 0x24, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0xDD, 0x14, 0xBD, 0x01, 0x45, 0x89, 0x26},
                           0x13C, 0x140, 0xD0, 0x5B3440, 0x98F8A0};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). Vtables by RTTI name (vtable_map_3549_3576.json): ClientVehicle
// 0x5946C98 slots 53/54 = the thunk 0xB4DCF0 (`jmp 0x99BB920`, protected) and 0xB4DD10 (+0x420), CommonVehicle 0x5CF1D38
// slot 53 = 0x23FDDC0 (+0xD40), RideOn 0x59268E8 / RideOff 0x5926940 slot 7 = 0x750210 / 0x7511E0 (+0x660); the three
// handlers are slot 2 of their Troc singletons' vtables (StartActionAck 0x599BCB0, InteractionPreemptionStepSuccessAck
// 0x59996B0, InteractionDoStepSuccessAck 0x59996F0): 0xC64670 / 0xCD8E00 / 0xCD98D0 (+0x420). Every head above is the
// same bytes. The RideOff thunk: vf53's call `lea rcx,[rsp+40h]; ... mov byte [rsp+20h],0Eh; call` at 0x23FDFCA ->
// 0x23FEA20 (`jmp 0xCD5F320`; 13 callers). NOTE: in 3527 that call was vf53+0x1F6 and the thunk vf53+0xC40; here
// +0x20A and +0xC60, so vf53's body is 0x14 bytes longer before it (not byte-compared: the 3527 exe is gone; its head,
// its arguments and that call's arguments are 3527's). Gate (fix B) 0x251B120 (+0xDD0, same 16-byte head), its call
// site 0x9491D6 (+0x370; `call` lands on 0x251B120, return 0x9491E3), the network mark 0x207B396 (+0xC40, the only
// match in the code); the mode-2 update 0x976690 (+0x370) and the action request 0xB4E140 (+0x420), same heads.
// vf178 (slot +0x178): 0x5B3AA0 of ClientActor / ClientNormalInGameActor / ClientChildOnlyInGameActor (reads
// [[0x71C0100]+0x30]+0x58 vs [this+0xA0], then [this+0x94]) and 0x98FC10 of ClientUserActor (`movzx eax,[rcx+94h]`).
// RideOff::Enter still writes the horse key at +0xD0 (0x751403 = 3527's 0x750DA3 + 0x660); the movement controller's
// method byte +0x13C and table +0x140 are in remote_motion's verified gate bytes (+0x13C, +0x168 = slot 5).
constexpr Addrs kAddrs3576{0x23FDDC0, 0xB4DCF0, 0x23FEA20, 0xB4DD10, 0x750210, 0x7511E0, 0xCD8E00, 0xCD98D0, 0xC64670, 0x5597000,
                           0x251B120, 0x9491E3, 0x9491D6, 0x207B396, 0x976690, 0xB4E140,
                           {0xE9, 0x2B, 0xDC, 0xE6, 0x08},  // jmp 0x99BB920
                           {0xE9, 0xFB, 0x08, 0x96, 0x0A},  // jmp 0xCD5F320
                           kGateHead3527, sizeof kGateHead3527,
                           {0x48, 0x8D, 0x54, 0x24, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0x3D, 0x1F, 0xBD, 0x01, 0x45, 0x89, 0x26},
                           0x13C, 0x140, 0xD0, 0x5B3AA0, 0x98FC10};
// Build 1.0.0.3663 (static, 2026-11-13; never run). 3663 is a recompile (some frames and struct offsets changed); every
// address found again and every byte compared before hooking, as always:
// - vtables by RTTI name (vtable_map_3576_3663.json): ClientVehicle 0x59C2910 slots 53/54 = the thunk 0xB84E80
//   (`jmp 0x9B6C550`, protected) and 0xB84EA0 (kVf54, .pdata start); CommonVehicle 0x5D6D7A8 slot 53 = 0x246F6C0 (kEntry7,
//   .pdata start); RideOn 0x59A2D08 / RideOff 0x59A2C58 slot 7 = 0x77C3A0 / 0x77D370 (kRideEnter); the three handlers
//   are slot 2 of their Troc singletons' vtables (InteractionPreemptionStepSuccessAck 0x5A15598,
//   InteractionDoStepSuccessAck 0x5A155D8, StartActionAck 0x5A177F8; troc_mapping_3576_3663.json): 0xD11830 / 0xD12300 /
//   0xC9CA10 (kHandler). StartActionAck's handler is 3527's instruction for instruction (game::wire_build()).
// - the RideOff thunk: vf53's `lea rcx,[rsp+48h]; ... mov byte [rsp+20h],0Eh; xor r9d,r9d; lea r8,[rsp+58h];
//   mov rdx,[rbp-38h]; call` at 0x246F8C9 (+0x209; 3576 +0x20A) -> 0x2470330 (`jmp 0xD1BAF70`; 13 callers, as in
//   3576). vf53 is recompiled (its frame moved 8 bytes); its head and that call's arguments are 3527's.
// - gate (fix B) 0x258CAA0 (kGateHead3527, .pdata start; 3527's 0x251A350 + 0x72750, the application's own shift);
//   its call site 0x976BD6 (the only match of 3527's array but for the call's rel32; it calls 0x258CAA0, return
//   0x976BE3); the network mark 0x20DFF86 (the only match); the gate reads CC+0x80 / +0xA8.
// - the mode-2 update 0x9A50D0 (kHoldEntry, .pdata start; the mode function 0x9A5310 moved by the same +0x2EDB0) and the
//   action request 0xB852D0 (kActionReqBytes, .pdata start; 2 callers, one vf54's own at +0x333).
// - vf178 (slot +0x178): 0x5DF1C0 of ClientActor / ClientNormalInGameActor / ClientChildOnlyInGameActor
//   ([[0x72451C0]+0x30]+0x58 vs [this+0xA0], then [this+0x94]) and 0x9BE630 of ClientUserActor (`movzx eax,[rcx+94h]`).
// - RideOff::Enter still writes the horse key at +0xD0 at its +0x223 (0x77D593, as 3576's); the controller's method
//   byte +0x13C and table +0x140 are in remote_motion's 3663 gate bytes; CC+0xC8 = the controller and mc+0x60 = CC
//   (the CC's constructor 0x96FB30, remote_interp.cpp); [actor+0x88]+1 type, actor+0x90 and vc+0xEB are in the 3663
//   mode function (3527's bytes). NOT re-derived: the link (+0x08/+0x0C/+0x10/+0x14), the seat tables (vc+0x48/+0x88/
//   +0xC8), CC+0x100 / +0x228 and the attach type +0x08, the hierarchy comps+0x1B8 (+0x18/+0x1C), TransformSync
//   +0xA4/+0xB4/+0xC0 (its load reader 0x23DCEA0 is 3527's 0x236BF20 instruction for instruction).
constexpr Addrs kAddrs3663{0x246F6C0, 0xB84E80, 0x2470330, 0xB84EA0, 0x77C3A0, 0x77D370, 0xD11830, 0xD12300, 0xC9CA10, 0x5613000,
                           0x258CAA0, 0x976BE3, 0x976BD6, 0x20DFF86, 0x9A50D0, 0xB852D0,
                           {0xE9, 0xCB, 0x76, 0xFE, 0x08},  // jmp 0x9B6C550
                           {0xE9, 0x3B, 0xAC, 0xD4, 0x0A},  // jmp 0xD1BAF70
                           kGateHead3527, sizeof kGateHead3527,
                           {0x48, 0x8D, 0x54, 0x24, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0xBD, 0x5E, 0xC1, 0x01, 0x45, 0x89, 0x26},
                           0x13C, 0x140, 0xD0, 0x5DF1C0, 0x9BE630};
const Addrs& addrs() noexcept {
    static const Addrs& a = game::current_build() == game::Build::v3663 ? kAddrs3663
                            : game::current_build() == game::Build::v3576 ? kAddrs3576
                            : game::is_3549()                           ? kAddrs3549
                            : game::current_build() == game::Build::v3527 ? kAddrs3527
                                                                          : kAddrs2976;
    return a;
}

// P8 S18 fix B (pendientes/p8-s18-desmontar-nativo.md §6, mount_sync_logic.h "the request gate") [V, capstone on the
// installed PE]: the thunk 0x2329A90 `jmp 0xEE58A40` (5 B, a function start in .rsrc; no E8/E9 lands in +1..+4); its
// network caller 0x863880 calls it at 0x8639C8 (`lea rdx,[rsp+0x20]; mov rcx,r15; call 0x2329A90; mov [r14],r12d`),
// so the detour's return address is exe+0x8639CD; 0x1EC9C26 `or r8b,2; or [rcx+0x50],r8b` marks every received entry.
constexpr uint8_t kGateNetOrBytes[] = {0x41, 0x80, 0xC8, 0x02, 0x44, 0x08, 0x41, 0x50};
// CC fields the gate reads [V 0xEE58A40]: [CC+8] actor, [CC+0x80] pending entries, CC+0xA8 "pending taken" flag.
constexpr uint32_t kCcActor = 0x08, kCcPending = 0x80, kCcPendingBusy = 0xA8;
constexpr uint32_t kActorChartGate = 0x96;  // 0x85FBA0: a player-type actor runs its chart only if != 0

// Offsets [V, mounts-20261011 native/INFORME.txt §2-§6; remote_motion.cpp].
constexpr uint32_t kActorKey = 0x60, kActorComps = 0x68, kActorCtrl = 0x90, kActorC8 = 0xC8;
constexpr uint32_t kCompsCC = 0x40, kCompsVehicle = 0x48;
constexpr uint32_t kVcActor = 0x08, kVcLink = 0x18, kVcSeats = 0x48, kVcReserves = 0x88, kVcCount = 0xC8, kVcHasSeats = 0xEB;
constexpr uint32_t kLinkResVehicle = 0x08, kLinkResSeat = 0x0C, kLinkVehicle = 0x10, kLinkSeat = 0x14;
constexpr uint32_t kMethodActor = 0x20;
constexpr uint32_t kCcMc = 0xC8, kCcLayer0 = 0x88, kCcLayer1 = 0x90, kLayerCurrent = 0x10, kActionHash = 0x18;
constexpr uint32_t kPktBuffer = 0x18;  // the handlers' R8: [R8+0x18] = header (u16 op, i8 slot, u16 len) + payload
// ClientActorManager hash table (game/actor_lookup.cpp).
constexpr uint32_t kMgrTable = 0x08, kTableBucketCount = 0x88, kTableBuckets = 0x98, kTableNodes = 0xA0;
constexpr uint32_t kBucketStride = 0x100, kBucketMaxEntries = (kBucketStride - 8) / 8, kNodeKey = 0x04, kNodeActor = 0x08;

// P8 S21 (pendientes/p8-impl-monturas.md §13, mount_sync_logic.h "seat the remote rider" / "hold the remote rider's
// pose") [V capstone on the installed PE]: the rider's attach struct [CC+0x100] (type at +8), CC+0x228 [H], the
// hierarchy component comps+0x1B8 (parent key at +0x1C), the actor type [[actor+0x88]+1]; the mode-2 movement update
// 0x88E6A0's entry (7 B patched: mov rax,rsp; mov [rax+0x10],rbx; no branch lands in +1..+6) and mc+0x60 = CC.
constexpr uint32_t kCcAttach = 0x100, kAttachType = 0x08, kCc228 = 0x228, kCompsHier = 0x1B8, kHierParent = 0x1C,
                   kActorTypeTab = 0x88, kMcCc = 0x60, kHierType = 0x18, kActorLocalCtl = 0x94;
// TransformSync (+0xB4 sector-local position, +0xC0 sector x/z, +0xA4 rotation; read_world, hold_after).
constexpr uint32_t kCompsTs = 0x1A0, kTsQuat = 0xA4, kTsPos = 0xB4, kTsSector = 0xC0;
// P8 S22 [V Ghidra + capstone]: vf54 ends with `if (rider->vf178()) 0xA45AC0(rider vc, horse key, 1)`, an action
// request launched on the LOCAL player's components (vf42's tail does the same with 0 on dismount, .xtls 0x9DCF13B).
// Every client in-game actor class has vf178 = 0x4FE260: `[this+0xA0] == [[WorldSystem+0x30]+0x58] && [this+0x94]`
// (the remote player's character reads +0x94 = 1, but its +0xA0 is the other user). Judged by msl::seat_local_user;
// a veto at 0xA45AC0's entry (2 callers, cold) drops any such request for the remote player's character (expected 0).
constexpr uint8_t kActionReqBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x20, 0x55, 0x57, 0x41, 0x56};
constexpr uint32_t kActorUser = 0xA0, kMgrLocalUser = 0x58;
constexpr uint8_t kHoldEntry[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70,
                                  0x18, 0x57, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00};

using Vf53Fn = uintptr_t(__fastcall*)(uintptr_t vc, int32_t* res, uintptr_t rider, uint8_t seat, uint8_t fifth);
using RideOffFn = uintptr_t(__fastcall*)(int32_t* res, uintptr_t horse, uint32_t* rider_key, uint64_t p4, uint8_t flag);

// ---------------------------------------------------------------- state

std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_guest{false}, g_code_ok{false}, g_apply_off{false};
uintptr_t g_base = 0;
std::atomic<uint32_t> g_local_key{0}, g_remote_key{0}, g_main_tid{0};
uint32_t g_nonce = 0;
std::atomic<uint32_t> g_transition{0};
// The controller's committed pair (msl::arm_pack(horse, transition), 0 = none): armed by an ok Commit, disarmed
// exactly once (compare-exchange) by the Detach that reports its end (0x2228E40 hook or the link watch).
std::atomic<uint64_t> g_ctl_arm{0};
std::atomic<uint64_t> g_local_rideoff_ms{0};  // the local rider's last RideOff::Enter (GetTickCount64)
std::atomic<uint64_t> g_ctl_watch_ms{0};      // the link watch's last read (main thread)
std::atomic<uint64_t> g_ctl_arm_ms{0};        // when the pair was armed (its ok Commit)
uint64_t g_ctl_gone_ms = 0;                   // main thread: since when the watch sees the armed link gone
// The remote rider's last StartActionAck at the dispatch named an 0xB parent (its actions say "mounted").
std::atomic<bool> g_remote_mounted{false};
// S40 carts (review §4): the horse key the remote rider's last StartActionAck names as its parent (0 = on foot or
// none seen); read by user2_stages before a Logout of a caravan vehicle (mount_sync_rides).
std::atomic<uint32_t> g_remote_parent{0};
msl::RideGeo g_geo;  // written by the client main thread (dispatch), read by the summary
struct GeoPrev {
    uint64_t ms = 0;
    uint32_t horse = 0;
    float pos[3] = {};
    float rider[3] = {};  // P8 S21: the frozen counter (seated at both ticks)
    bool seated = false;
};
GeoPrev g_geo_prev;  // main thread only
std::atomic<uint64_t> g_geo_ms{0};

SRWLOCK g_lock = SRWLOCK_INIT;
msl::Table g_table;         // under g_lock
uint64_t g_table_epoch = 0; // under g_lock
std::atomic<bool> g_has_work{false};
std::atomic<uint8_t> g_remote_phase{0};
std::atomic<uint32_t> g_remote_horse{0};  // the remote rider's last transaction's horse (0 = none)
std::atomic<uint32_t> g_rideoff_seen{0};  // RideOff::Enter of the remote rider, consumed under the lock
std::atomic<uint32_t> g_rideon_seen{0};   // P8 S26: RideOn::Enter of the remote rider, consumed under the lock
// P8 S26 (montura-regresion.md section 7.1): this PC's controller cannot publish (its 0x2228260 hook is not
// installed with mount_sync on): ERR in every summary, the overlay, and a Status to the other PC every 15 s.
std::atomic<bool> g_ctl_no_publish{false};
// The other PC's last Status saying it publishes no mount (GetTickCount64, 0 = none), its epoch's line logged.
std::atomic<uint64_t> g_peer_no_publish_ms{0};
uint64_t g_peer_status_epoch = 0;  // under g_lock

Vf53Fn g_vf53 = nullptr;
RideOffFn g_rideoff = nullptr;

SafetyHookInline g_h_common, g_h_thunk, g_h_rideoff, g_h_vf54, g_h_on, g_h_off, g_h_2663, g_h_2916, g_h_2991, g_h_gate,
    g_h_hold, g_h_actreq;
std::atomic<bool> g_on_common{false}, g_on_thunk{false}, g_on_rideoff{false}, g_on_vf54{false}, g_on_enter_on{false},
    g_on_enter_off{false}, g_on_2663{false}, g_on_2916{false}, g_on_2991{false}, g_on_gate{false}, g_on_hold{false},
    g_on_actreq{false};
uint16_t g_mark[12] = {};
// P8 S21: [session2] mount_seat / ride_hold_pos (msl::Mode; the effective modes, see mount_sync_start).
std::atomic<uint8_t> g_seat_mode{0}, g_hold_mode{0};
std::atomic<bool> g_seat_off{false};          // a seat failed its postconditions: no more vf54 calls this session
msl::SeatWatch g_seat;                        // client main thread only (do_commit / do_detach / on_dispatch)
uint64_t g_seat_tick_ms = 0;                  // client main thread only
std::atomic<uint64_t> g_seat_rideoff_ms{0};   // the remote rider's ok RideOff::Enter (any thread), consumed at a dispatch
// P8 S18 fix B: the gate detour acts (mount_sync=1, ride_dismount=native, hooked, no fault so far).
std::atomic<bool> g_gate_off{false};
std::atomic<uint8_t> g_gate_off_why{0};       // 1 an exception passed on (OFF); 2 the self-check (DEGRADED)
// Review (1): the rider's actions kept being dropped, or (review of 458cf49 (2)) the self-check saw a 2223 for the
// remote rider / horse: ride_filter rewrites new dismounts, the detour still frees an already stuck rider.
std::atomic<bool> g_gate_degraded{false};
msl::GateStreak g_gate_streak;                // client main thread only (the detour)
std::atomic<bool> g_native_policy{false};  // ride_dismount native/partial: msl::DetachPolicy::Native

thread_local int t_thunk = 0;
thread_local uintptr_t t_thunk_caller = 0;
thread_local int t_vf53_depth = 0;
thread_local bool t_applying = false;
thread_local bool t_gate_unlocked = false;  // the gate detour unlocked a request on this thread (this dispatch)

// Rings: diagnostics (formatted by this module's thread) and the controller's outbound events.
p8p::EventRing<1024> g_diag;
p8p::EventRing<64> g_out;
p8p::WindowLimiter g_lim_ack{48, 10'000'000}, g_lim_inter{32, 60'000'000};
std::atomic<uint64_t> g_lines{0}, g_lines_dropped{0}, g_limited{0};
constexpr uint64_t kMaxLines = 4000;

enum Kind : uint16_t {
    kBegin = 1, kCommit, kRideOffCall, kVf54Call, kEnter, kInter, kObs, kApply, kArgs, kFallback, kRiderAck, kCancel,
    kCtlDetach, kGate, kProbe, kLearn, kSelfReq, kGateDegraded, kSeat, kSeatRelease, kRelink, kPeerStatus
};

// Counters (relaxed atomics; describe() reads them).
std::atomic<uint64_t> c_vf53{0}, c_vf53_client{0}, c_vf53_other{0}, c_vf53_direct{0}, c_pub[5] = {}, c_out_full{0},
    c_rideoff{0}, c_vf54{0}, c_enter_on{0}, c_enter_on_fail{0}, c_enter_off{0}, c_enter_off_fail{0}, c_inter{0},
    c_dispatch{0}, c_accept[static_cast<size_t>(msl::Accept::Count)] = {}, c_judge[static_cast<size_t>(msl::Judge::Count)] = {},
    c_outcome[6] = {}, c_post_fail{0}, c_detach_ok{0}, c_detach_fail{0}, c_fallback{0}, c_fallback_fail{0},
    c_defer{0}, c_defer_busy{0}, c_cancel{0}, c_hold_guest{0}, c_hold_host{0}, c_rel_guest{0}, c_rel_host{0},
    c_epoch_reset{0}, c_faults{0}, c_ctl_observed{0}, c_ctl_watch_reads{0}, c_ctl_watch_unknown{0}, c_no_event{0};
// P8 S18: the gate detour's verdicts; the dispatch probe of the remote rider; the self-check.
std::atomic<uint64_t> c_gate_verdict[static_cast<size_t>(msl::GateVerdict::Count)] = {}, c_gate_drop{0}, c_gate_force_bit{0},
    c_m7_2991{0}, c_m7_rejected{0}, c_m7_taken{0}, c_m7_unlocked{0}, c_probe_lines{0}, c_gate_lines{0}, c_learned{0},
    c_self_req_rider{0}, c_self_req_horse{0}, c_self_req_withheld{0}, c_native_gone{0}, c_native_fallback{0},
    c_native_lost{0};
// P8 S21: the seat (mount_seat) and its release; the empty-buffer hold (ride_hold_pos, ParallelTaskWorker threads).
std::atomic<uint64_t> c_seat_seated{0}, c_seat_already{0}, c_seat_refused{0}, c_seat_failed{0}, c_seat_probe{0},
    c_seat_released{0}, c_seat_retired{0}, c_seat_stuck{0}, c_seat_lost{0}, c_enter_unseated{0}, c_actreq_veto{0}, c_hold_remote{0}, c_hold_filled{0},
    c_hold_unreadable{0}, c_hold_other{0};
// P8 S26: relinks (montura-regresion.md section 7.2) and the controllers' Status (section 7.1).
std::atomic<uint64_t> c_relink{0}, c_relink_probe{0}, c_status_sent{0}, c_status_recv{0};
// [session2] mount_relink (review of bf255bb (2)): the effective mode (Off without mount_sync=1's apply point or
// without the RideOn::Enter / RideOff::Enter hooks, its stop conditions: review (1)).
std::atomic<uint8_t> g_relink_mode{0};
Mode relink_mode() { return static_cast<Mode>(g_relink_mode.load(std::memory_order_acquire)); }
constexpr uint64_t kRelinkLines = 20;
constexpr uint64_t kMaxGateLines = 200, kMaxProbeLines = 200, kMaxSelfReqLines = 8;

uint64_t now_ms() { return GetTickCount64(); }
Mode mode() { return static_cast<Mode>(g_mode.load(std::memory_order_relaxed)); }
Mode seat_mode() { return static_cast<Mode>(g_seat_mode.load(std::memory_order_relaxed)); }
Mode hold_mode() { return static_cast<Mode>(g_hold_mode.load(std::memory_order_relaxed)); }

// ---------------------------------------------------------------- guarded reads (no CRT, no allocation)

template <class T>
T rdv(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return (a >= 0x10000 && game::fast_read(a, &v, sizeof v)) ? v : fallback;
}
uintptr_t rdp(uintptr_t a) noexcept { return rdv<uintptr_t>(a); }
uint32_t key_of(uintptr_t actor) noexcept { return actor ? rdv<uint32_t>(actor + kActorKey) : 0; }
uintptr_t vc_of(uintptr_t actor) noexcept {
    const uintptr_t comps = actor ? rdp(actor + kActorComps) : 0;
    return comps ? rdp(comps + kCompsVehicle) : 0;
}

uintptr_t world_slot() noexcept {
    const auto* profile = game::reader_profile();
    return g_base + (profile ? profile->world_system : off::kWorldSystemSlot);
}

uintptr_t find_actor(uint32_t key) noexcept {
    if (!key) return 0;
    const uintptr_t world = rdp(world_slot());
    const uintptr_t mgr = world ? rdp(world + off::kWorldSystem_ActorManager) : 0;
    const uintptr_t table = mgr ? rdp(mgr + kMgrTable) : 0;
    const uint32_t buckets = table ? rdv<uint32_t>(table + kTableBucketCount) : 0;
    if (!buckets || buckets > (1u << 24)) return 0;
    const uintptr_t base = rdp(table + kTableBuckets), nodes = rdp(table + kTableNodes);
    if (!base || !nodes) return 0;
    const uintptr_t bucket = base + static_cast<uintptr_t>(key % buckets) * kBucketStride;
    const uint32_t count = rdv<uint32_t>(bucket);
    for (uint32_t i = 0; i < count && i < kBucketMaxEntries; ++i) {
        if (rdv<uint32_t>(bucket + 8 + i * 8) != key) continue;
        const uint32_t idx = rdv<uint32_t>(bucket + 0xC + i * 8);
        const uintptr_t node = idx ? rdp(nodes + static_cast<uintptr_t>(idx) * 8) : 0;
        if (!node || rdv<uint32_t>(node + kNodeKey) != key) return 0;
        const uintptr_t actor = rdp(node + kNodeActor);
        return key_of(actor) == key ? actor : 0;
    }
    return 0;
}

// Session 18 review (2): the hops 0x2228260 dereferences without a check (2228260.c), each read under SEH; a set
// bit = null or unreadable (msl::kDep*). Only the observer's commit judges on it (NoVehicle: not ready).
uint32_t vf53_deps_missing(uintptr_t rider, uintptr_t horse) noexcept {
    uint32_t m = 0;
    const uintptr_t rc = rdp(rider + kActorComps);
    if (!rc) {
        m |= msl::kDepRiderComps;
    } else {
        const uintptr_t cc = rdp(rc + kCompsCC);
        uint8_t flag = 0;
        if (!cc || !game::fast_read(cc + 0xA8, &flag, 1)) {
            m |= msl::kDepRiderCC;
        } else if (flag == 0) {
            const uintptr_t def = rdp(cc + 0x30);
            uint8_t idx = 0;
            if (!def || !game::fast_read(def + 0x1B, &idx, 1) || !rdp(cc + 0x88 + 8ull * idx)) m |= msl::kDepRiderCCSlot;
        }
        if (!rdp(rc + 0x50)) m |= msl::kDepRiderComps50;
    }
    const uintptr_t hc = rdp(horse + kActorComps);
    if (!hc) {
        m |= msl::kDepHorseComps;
    } else {
        if (!rdp(hc + 0x1A0)) m |= msl::kDepHorseComps1A0;
        if (!rdp(hc + 0x90)) m |= msl::kDepHorseComps90;
        if (!rdp(hc + kCompsCC)) m |= msl::kDepHorseCC;
        if (!rdp(hc + 0xB0)) m |= msl::kDepHorseCompsB0;
    }
    uint8_t type = 0;
    const uintptr_t h88 = rdp(horse + 0x88);
    if (!h88 || !game::fast_read(h88 + 1, &type, 1)) m |= msl::kDepHorse88;
    return m;
}

// The pair as it is now (pointers already resolved; 0 = missing).
msl::PairState read_pair(uintptr_t rider, uintptr_t horse, uintptr_t horse_vc, uint8_t seat) noexcept {
    msl::PairState s;
    s.rider_found = rider != 0;
    s.horse_found = horse != 0;
    if (rider) {
        s.rider_ctrl = rdv<uint32_t>(rider + kActorCtrl);
        s.rider_c8 = rdv<uint8_t>(rider + kActorC8);
        const uintptr_t rvc = vc_of(rider);
        s.rider_vc = rvc != 0;
        const uintptr_t link = rvc ? rdp(rvc + kVcLink) : 0;
        s.link = link != 0;
        if (link) {
            s.res_vehicle = rdv<uint32_t>(link + kLinkResVehicle);
            s.res_seat = rdv<int8_t>(link + kLinkResSeat, -1);
            s.cur_vehicle = rdv<uint32_t>(link + kLinkVehicle);
            s.cur_seat = rdv<int8_t>(link + kLinkSeat, -1);
        }
        // P8 S18: the rider's movement method and, in RideOff, the horse key its Enter cached (+0xD4).
        const uintptr_t rcomps = rdp(rider + kActorComps);
        const uintptr_t rcc = rcomps ? rdp(rcomps + kCompsCC) : 0;
        const uintptr_t mc = rcc ? rdp(rcc + kCcMc) : 0;
        if (mc) {
            s.rider_method = rdv<uint8_t>(mc + addrs().mc_method, 0xFF);
            if (s.rider_method == msl::kMethodRideOff) {
                const uintptr_t m7 = rdp(mc + addrs().mc_methods + 8ull * msl::kMethodRideOff);
                s.rideoff_key = m7 ? rdv<uint32_t>(m7 + addrs().rideoff_key) : 0;
            }
        }
    }
    if (horse) {
        s.horse_ctrl = rdv<uint32_t>(horse + kActorCtrl);
        s.horse_c8 = rdv<uint8_t>(horse + kActorC8);
    }
    s.horse_vc = horse_vc != 0;
    if (horse_vc) {
        s.horse_has_seats = rdv<uint8_t>(horse_vc + kVcHasSeats);
        if (seat < msl::kMaxSeats) {
            s.occupant = rdv<uint32_t>(horse_vc + kVcSeats + 4u * seat);
            s.reserve = rdv<uint32_t>(horse_vc + kVcReserves + 4u * seat);
        }
        s.count = rdv<uint8_t>(horse_vc + kVcCount);
    }
    if (rider && horse) s.deps_missing = vf53_deps_missing(rider, horse);
    return s;
}

// The actor's movement method and both layers' current action hashes.
void read_actions(uintptr_t actor, uint8_t& method, uint32_t& a0, uint32_t& a1) noexcept {
    method = 0xFF;
    a0 = a1 = 0;
    const uintptr_t comps = actor ? rdp(actor + kActorComps) : 0;
    const uintptr_t cc = comps ? rdp(comps + kCompsCC) : 0;
    if (!cc) return;
    const uintptr_t mc = rdp(cc + kCcMc);
    if (mc) method = rdv<uint8_t>(mc + addrs().mc_method, 0xFF);
    for (int i = 0; i < 2; ++i) {
        const uintptr_t layer = rdp(cc + (i ? kCcLayer1 : kCcLayer0));
        const uintptr_t cur = layer ? rdp(layer + kLayerCurrent) : 0;
        if (cur) (i ? a1 : a0) = rdv<uint32_t>(cur + kActionHash);
    }
}

// P8 S18: what the gate reads of an actor's CC (read only, SEH): its movement method, both layers' current action
// hash and def+0xA flags, whether a pending [CC+0x80] entry has 0x40, CC+0xA8, actor+0x96 and RideOff's +0xD4.
struct RiderProbe {
    bool ok = false;
    uint8_t method = 0xFF;
    uint32_t hash[2] = {};
    uint8_t flags[2] = {};
    bool pend40 = false;
    uint8_t busy = 0xFF;     // CC+0xA8
    uint8_t chart = 0xFF;    // actor+0x96
    uint32_t rideoff_key = 0;
    bool gate() const { return ((flags[0] | flags[1]) & msl::kDefDismount) != 0 || pend40; }
};
// The definition the gate reads for a layer: [layer+0x10] when [layer] and [layer+8] are set (0xEE58C47..C87).
uintptr_t layer_def(uintptr_t cc, int i) noexcept {
    const uintptr_t layer = rdp(cc + (i ? kCcLayer1 : kCcLayer0));
    if (!layer || !rdp(layer) || !rdp(layer + 8)) return 0;
    return rdp(layer + kLayerCurrent);
}
// A pending / new entry's definition as the gate reads it: +0x18 when +0x08, +0x10 and +0x18 are set (0xEE58BF5).
uintptr_t entry_def(uintptr_t e) noexcept {
    if (!rdp(e + 0x08) || !rdp(e + 0x10)) return 0;
    return rdp(e + msl::kEntryDef);
}
bool pending40(uintptr_t cc) noexcept {
    const uintptr_t pend = rdp(cc + kCcPending);
    if (!pend) return false;
    for (uint32_t i = 0; i < msl::kGateEntries; ++i) {
        const uintptr_t d = entry_def(pend + i * msl::kGateEntrySize);
        if (d && (rdv<uint8_t>(d + msl::kDefFlags) & msl::kDefDismount)) return true;
    }
    return false;
}
uintptr_t cc_of(uintptr_t actor) noexcept {
    const uintptr_t comps = actor ? rdp(actor + kActorComps) : 0;
    return comps ? rdp(comps + kCompsCC) : 0;
}
RiderProbe probe_cc(uintptr_t cc, uintptr_t actor) noexcept {
    RiderProbe p;
    const uintptr_t mc = cc ? rdp(cc + kCcMc) : 0;
    if (!mc) return p;
    p.ok = true;
    p.method = rdv<uint8_t>(mc + addrs().mc_method, 0xFF);
    for (int i = 0; i < 2; ++i) {
        if (const uintptr_t d = layer_def(cc, i)) {
            p.hash[i] = rdv<uint32_t>(d + kActionHash);
            p.flags[i] = rdv<uint8_t>(d + msl::kDefFlags);
        }
    }
    p.pend40 = pending40(cc);
    p.busy = rdv<uint8_t>(cc + kCcPendingBusy, 0xFF);
    p.chart = rdv<uint8_t>(actor + kActorChartGate, 0xFF);
    if (p.method == msl::kMethodRideOff) {
        const uintptr_t m7 = rdp(mc + addrs().mc_methods + 8ull * msl::kMethodRideOff);
        p.rideoff_key = m7 ? rdv<uint32_t>(m7 + addrs().rideoff_key) : 0;
    }
    return p;
}
RiderProbe probe_rider(uintptr_t actor) noexcept { return probe_cc(cc_of(actor), actor); }

// P8 S21: the actor type [[actor+0x88]+1] (0xFF unreadable) and the rider as vf54 / 0xA651E0 see it.
uint8_t actor_type(uintptr_t actor) noexcept {
    const uintptr_t t = actor ? rdp(actor + kActorTypeTab) : 0;
    return t ? rdv<uint8_t>(t + 1, 0xFF) : 0xFF;
}
uint8_t attach_type_of(uintptr_t actor) noexcept {
    const uintptr_t cc = cc_of(actor);
    const uintptr_t at = cc ? rdp(cc + kCcAttach) : 0;
    return at ? rdv<uint8_t>(at + kAttachType, 0xFF) : 0xFF;
}
uint32_t rva_of(uintptr_t va);
msl::SeatState read_seat(uintptr_t rider, uintptr_t horse) noexcept {
    msl::SeatState s;
    const uintptr_t comps = rider ? rdp(rider + kActorComps) : 0;
    const uintptr_t cc = comps ? rdp(comps + kCompsCC) : 0;
    s.has_cc = cc != 0;
    if (cc) {
        s.has_mc = rdp(cc + kCcMc) != 0;
        const uintptr_t at = rdp(cc + kCcAttach);
        uint8_t type = 0;
        if (at && game::fast_read(at + kAttachType, &type, 1)) {
            s.has_cc100 = true;
            s.attach_type = type;
        }
        s.cc228 = rdv<uint8_t>(cc + kCc228, 0xFF);
    }
    const uintptr_t hier = comps ? rdp(comps + kCompsHier) : 0;
    uint32_t parent = 0;
    if (hier && game::fast_read(hier + kHierParent, &parent, sizeof parent)) {
        s.has_parent = true;
        s.parent_key = parent;
        s.parent_type = rdv<uint8_t>(hier + kHierType, 0xFF);
    }
    s.rider_type = actor_type(rider);
    s.horse_type = actor_type(horse);
    s.rider_local = rider ? rdv<uint8_t>(rider + kActorLocalCtl, 0xFF) : 0xFF;
    s.horse_cc = cc_of(horse) != 0;
    // P8 S22: the rider's vf178 and what it would answer (msl::seat_local_user): vf54's local action request.
    const uintptr_t vt = rider ? rdp(rider) : 0;
    s.vf178 = vt ? rva_of(rdp(vt + 0x178)) : 0;
    // msl::seat_local_user speaks the 2976 addresses.
    if (s.vf178 == addrs().vf178_actor) s.vf178 = msl::kVf178Actor;
    else if (s.vf178 == addrs().vf178_user) s.vf178 = msl::kVf178User;
    s.rider_user = rider ? rdv<uint64_t>(rider + kActorUser) : 0;
    const uintptr_t world = rdp(world_slot());
    const uintptr_t mgr = world ? rdp(world + off::kWorldSystem_ActorManager) : 0;
    s.local_user = mgr ? rdv<uint64_t>(mgr + kMgrLocalUser) : 0;
    s.rider_c8 = rider ? rdv<uint8_t>(rider + kActorC8, 0xFF) : 0xFF;
    s.horse_c8 = horse ? rdv<uint8_t>(horse + kActorC8, 0xFF) : 0xFF;
    return s;
}

// Under g_lock: what the hooks may read without it.
void publish_phase(const msl::Txn* cur) noexcept {
    g_remote_phase.store(static_cast<uint8_t>(cur ? cur->phase : msl::Phase::Idle), std::memory_order_relaxed);
    g_remote_horse.store(cur ? cur->horse : 0, std::memory_order_relaxed);
}

uint32_t rva_of(uintptr_t va) { return va >= g_base && va < g_base + 0x13EB2000 ? static_cast<uint32_t>(va - g_base) : 0; }

void diag(uint16_t kind, p8p::Event& e) noexcept {
    e.kind = kind;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    g_diag.push(e);
}

// The remote rider's key. Guest: only while it plays live on the host (review of 458cf49 (1): after end_remote the
// key may be learned again from a late control state 4, and a local save may give this client's own character
// 0xA0100001); otherwise 0 = no remote rider, nothing applied, rewritten or unlocked.
uint32_t remote_key() noexcept {
    if (!g_guest.load(std::memory_order_relaxed)) return server_user2_player_key();
    return guest_remote_live() ? g_remote_key.load(std::memory_order_relaxed) : 0;
}

void publish(const msl::Event& ev) noexcept {
    p8p::Event e;
    e.kind = static_cast<uint16_t>(ev.kind);
    e.flags = static_cast<uint16_t>(ev.seat | (ev.fifth << 8));
    e.v[0] = ev.rider;
    e.v[1] = ev.horse;
    e.v[2] = ev.transition;
    e.v[3] = ev.result;
    e.v[4] = ev.caller_rva;
    e.v[5] = ev.aux;
    e.v[6] = ev.flags;
    e.v[7] = ev.tick_ms;
    if (!g_out.push(e)) {
        c_out_full.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    c_pub[static_cast<size_t>(ev.kind)].fetch_add(1, std::memory_order_relaxed);
}

// Session 17: the controller's own link of an armed pair is gone (a player's dismount never calls 0x2228E40):
// disarm exactly once and publish the observed Detach (flag 12, p4 0: the client's own retirement of a remote
// rider). `where`: 1 the link watch at a dispatch, 2 just before a new mount's Begin.
void publish_observed_detach(uint64_t armed, const msl::PairState& s, uint8_t where) noexcept {
    uint64_t expected = armed;
    if (!armed || !g_ctl_arm.compare_exchange_strong(expected, 0, std::memory_order_acq_rel)) return;
    const uint32_t rider = g_local_key.load(std::memory_order_relaxed);
    const uint64_t now = now_ms();
    publish(msl::observed_detach(rider, armed, g_nonce, now));
    c_ctl_observed.fetch_add(1, std::memory_order_relaxed);
    const uint64_t off_ms = g_local_rideoff_ms.load(std::memory_order_relaxed);
    p8p::Event e;
    e.flags = where;
    e.v[0] = rider;
    e.v[1] = msl::arm_horse(armed);
    e.v[2] = msl::arm_transition(armed);
    e.v[3] = s.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(s.cur_seat)) << 32);
    e.v[4] = off_ms && now >= off_ms ? now - off_ms : ~0ull;
    diag(kCtlDetach, e);
}

// ---------------------------------------------------------------- controller: CommonVehicle::vf53 and its thunk

uintptr_t __fastcall common_detour(uintptr_t vc, int32_t* res, uintptr_t rider, uint64_t r9, uint64_t fifth_slot) {
    const FreezeMark mark(g_mark[0]);
    c_vf53.fetch_add(1, std::memory_order_relaxed);
    const uint8_t seat = static_cast<uint8_t>(r9), fifth = static_cast<uint8_t>(fifth_slot);
    const bool applying = t_applying, via_thunk = t_thunk > 0;
    const bool client = via_thunk || GetCurrentThreadId() == g_main_tid.load(std::memory_order_relaxed);
    (client ? c_vf53_client : c_vf53_other).fetch_add(1, std::memory_order_relaxed);
    if (client && !via_thunk && !applying) c_vf53_direct.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t horse = rdp(vc + kVcActor);
    const uint32_t rk = key_of(rider), hk = key_of(horse);
    const msl::PairState before = read_pair(rider, horse, vc, seat);
    const uintptr_t caller = via_thunk ? t_thunk_caller : reinterpret_cast<uintptr_t>(_ReturnAddress());
    const bool pub = !applying && client && mode() != Mode::Off &&
                     msl::publishable(rk, hk, seat, g_local_key.load(std::memory_order_relaxed));
    const uint32_t tr = pub ? g_transition.fetch_add(1, std::memory_order_relaxed) + 1 : 0;
    const uint64_t t0 = p8_now_us();
    uint8_t method = 0xFF;
    uint32_t a0 = 0, a1 = 0;
    read_actions(rider, method, a0, a1);
    msl::Event ev;
    ev.rider = rk;
    ev.horse = hk;
    ev.seat = seat;
    ev.fifth = fifth;
    ev.transition = tr;
    ev.nonce = g_nonce;
    ev.caller_rva = rva_of(caller);
    ev.tick_ms = now_ms();
    if (pub) {
        // The previous committed pair ended without the watch seeing it (a fast remount): its Detach goes first.
        const uint64_t armed = g_ctl_arm.load(std::memory_order_acquire);
        if (armed && msl::ctl_link(before, msl::arm_horse(armed)) == msl::CtlLink::Gone) {
            publish_observed_detach(armed, before, 2);
        }
        ev.kind = msl::EvKind::Begin;
        ev.flags = static_cast<uint8_t>((before.cur_vehicle ? msl::kFlagRiderWasLinked : 0) |
                                        (before.occupant ? msl::kFlagSeatWasTaken : 0));
        publish(ev);
    }
    {
        p8p::Event e;
        e.flags = method;
        e.v[0] = rk;
        e.v[1] = hk;
        e.v[2] = seat | (static_cast<uint64_t>(fifth) << 8) | (static_cast<uint64_t>(pub) << 16) |
                 (static_cast<uint64_t>(client) << 17) | (static_cast<uint64_t>(applying) << 18) |
                 (static_cast<uint64_t>(via_thunk) << 19) | (static_cast<uint64_t>(before.rider_c8) << 24) |
                 (static_cast<uint64_t>(before.horse_c8) << 32);
        e.v[3] = rva_of(caller);
        e.v[4] = tr;
        e.v[5] = before.cur_vehicle;
        e.v[6] = static_cast<uint8_t>(before.cur_seat) | (static_cast<uint64_t>(static_cast<uint8_t>(before.res_seat)) << 8);
        e.v[7] = before.res_vehicle;
        e.v[8] = before.occupant;
        e.v[9] = before.count | (static_cast<uint64_t>(before.reserve) << 32);
        e.v[10] = (static_cast<uint64_t>(a0) << 32) | a1;
        e.v[11] = (static_cast<uint64_t>(before.rider_ctrl) << 32) | before.horse_ctrl;
        diag(kBegin, e);
    }
    ++t_vf53_depth;
    const uintptr_t ret = g_h_common.unsafe_call<uintptr_t>(vc, res, rider, r9, fifth_slot);
    --t_vf53_depth;
    const int32_t r = res ? rdv<int32_t>(reinterpret_cast<uintptr_t>(res), -1) : -1;
    const msl::PairState after = read_pair(rider, horse, vc, seat);
    const bool ok = msl::controller_commit_ok(before, after, rk, hk, seat, r);
    if (pub) {
        ev.kind = msl::EvKind::Commit;
        ev.result = static_cast<uint32_t>(r);
        ev.flags = ok ? msl::kFlagOk : 0;
        ev.aux = after.count;
        ev.tick_ms = now_ms();
        publish(ev);
        if (ok) {
            g_ctl_arm_ms.store(now_ms(), std::memory_order_relaxed);
            g_ctl_gone_ms = 0;  // vf53 of the local rider: the client main thread, as the watch
            g_ctl_arm.store(msl::arm_pack(hk, tr), std::memory_order_release);
        }
    }
    p8p::Event e;
    e.v[0] = rk;
    e.v[1] = hk;
    e.v[2] = seat | (static_cast<uint64_t>(fifth) << 8) | (static_cast<uint64_t>(pub) << 16) |
             (static_cast<uint64_t>(client) << 17) | (static_cast<uint64_t>(applying) << 18) |
             (static_cast<uint64_t>(ok) << 19) | (static_cast<uint64_t>(after.rider_c8) << 24) |
             (static_cast<uint64_t>(after.horse_c8) << 32);
    e.v[3] = static_cast<uint32_t>(r);
    e.v[4] = tr;
    e.v[5] = after.cur_vehicle;
    e.v[6] = static_cast<uint8_t>(after.cur_seat) | (static_cast<uint64_t>(static_cast<uint8_t>(after.res_seat)) << 8);
    e.v[7] = after.res_vehicle;
    e.v[8] = after.occupant;
    e.v[9] = after.count | (static_cast<uint64_t>(after.reserve) << 32);
    e.v[10] = (static_cast<uint64_t>(after.rider_ctrl) << 32) | after.horse_ctrl;
    e.v[11] = p8_now_us() - t0;
    diag(kCommit, e);
    return ret;
}

uintptr_t __fastcall thunk_detour(uintptr_t vc, int32_t* res, uintptr_t rider, uint64_t r9, uint64_t fifth_slot) {
    const FreezeMark mark(g_mark[1]);
    const uintptr_t prev = t_thunk_caller;
    t_thunk_caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    ++t_thunk;
    const uintptr_t ret = g_h_thunk.unsafe_call<uintptr_t>(vc, res, rider, r9, fifth_slot);
    --t_thunk;
    t_thunk_caller = prev;
    return ret;
}

// ---------------------------------------------------------------- 0x2228E40 RideOff (res, horse actor, &rider key, p4, flag)

uintptr_t __fastcall rideoff_detour(int32_t* res, uintptr_t horse, uint32_t* rider_key, uint64_t p4, uint64_t flag_slot) {
    const FreezeMark mark(g_mark[2]);
    c_rideoff.fetch_add(1, std::memory_order_relaxed);
    const bool applying = t_applying, in_vf53 = t_vf53_depth > 0;
    const bool client = GetCurrentThreadId() == g_main_tid.load(std::memory_order_relaxed);
    const uint32_t rk = rider_key ? rdv<uint32_t>(reinterpret_cast<uintptr_t>(rider_key)) : 0;
    const uint32_t hk = key_of(horse);
    const uintptr_t rider = client ? find_actor(rk) : 0;
    const msl::PairState before = client ? read_pair(rider, horse, vc_of(horse), 0) : msl::PairState{};
    uint64_t armed = g_ctl_arm.load(std::memory_order_acquire);
    const bool pub = !applying && client && mode() != Mode::Off && rk != 0 &&
                     rk == g_local_key.load(std::memory_order_relaxed) && hk != 0 && hk == msl::arm_horse(armed);
    const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const uintptr_t ret = g_h_rideoff.unsafe_call<uintptr_t>(res, horse, rider_key, p4, flag_slot);
    const int32_t r = res ? rdv<int32_t>(reinterpret_cast<uintptr_t>(res), -1) : -1;
    const msl::PairState after = client ? read_pair(rider, horse, vc_of(horse), 0) : msl::PairState{};
    uint32_t tr = 0;
    if (pub) {
        tr = msl::arm_transition(armed);
        msl::Event ev;
        ev.kind = msl::EvKind::Detach;
        ev.rider = rk;
        ev.horse = hk;
        ev.transition = tr;
        ev.nonce = g_nonce;
        ev.result = static_cast<uint32_t>(r);
        ev.fifth = static_cast<uint8_t>(flag_slot);
        ev.aux = static_cast<uint32_t>(p4);
        ev.flags = (r == 0 && after.cur_vehicle != hk) ? msl::kFlagOk : 0;
        ev.caller_rva = rva_of(caller);
        ev.tick_ms = now_ms();
        // An ok retirement disarms exactly once (the link watch may not publish it again); a failed one is reported
        // as such and leaves the pair armed.
        if (!(ev.flags & msl::kFlagOk) || g_ctl_arm.compare_exchange_strong(armed, 0, std::memory_order_acq_rel)) {
            publish(ev);
        }
    }
    p8p::Event e;
    e.v[0] = rk;
    e.v[1] = hk;
    e.v[2] = p4;
    e.v[3] = static_cast<uint8_t>(flag_slot) | (static_cast<uint64_t>(client) << 8) |
             (static_cast<uint64_t>(applying) << 9) | (static_cast<uint64_t>(in_vf53) << 10) |
             (static_cast<uint64_t>(pub) << 11);
    e.v[4] = static_cast<uint32_t>(r);
    e.v[5] = before.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(before.cur_seat)) << 32);
    e.v[6] = after.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(after.cur_seat)) << 32);
    e.v[7] = rva_of(caller);
    e.v[8] = tr;
    diag(kRideOffCall, e);
    return ret;
}

// ---------------------------------------------------------------- 0xA45760 ClientVehicle vf54 (vc, res, actor, r9b, ...)

uintptr_t __fastcall vf54_detour(uintptr_t vc, int32_t* res, uintptr_t actor, uint64_t r9, uint64_t a5, uint64_t a6) {
    const FreezeMark mark(g_mark[3]);
    c_vf54.fetch_add(1, std::memory_order_relaxed);
    const bool client = GetCurrentThreadId() == g_main_tid.load(std::memory_order_relaxed);
    const uint32_t vk = key_of(rdp(vc + kVcActor)), ak = key_of(actor);
    const msl::PairState before = read_pair(actor, 0, 0, 0);
    const uint8_t type_before = attach_type_of(actor);  // S22: the live 9 -> 4 of every native seat (local and NPC)
    const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const uintptr_t ret = g_h_vf54.unsafe_call<uintptr_t>(vc, res, actor, r9, a5, a6);
    const int32_t r = res ? rdv<int32_t>(reinterpret_cast<uintptr_t>(res), -1) : -1;
    const msl::PairState after = read_pair(actor, 0, 0, 0);
    p8p::Event e;
    e.v[0] = vk;
    e.v[1] = ak;
    e.v[2] = static_cast<uint8_t>(r9);
    e.v[3] = static_cast<uint32_t>(r);
    e.v[4] = before.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(before.cur_seat)) << 32);
    e.v[5] = after.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(after.cur_seat)) << 32);
    e.v[6] = rva_of(caller);
    e.v[7] = client;
    e.v[8] = t_vf53_depth > 0;
    e.v[9] = type_before | (static_cast<uint64_t>(attach_type_of(actor)) << 8);
    diag(kVf54Call, e);
    return ret;
}

// ---------------------------------------------------------------- P8 S18 fix B: the thunk 0x2329A90 (CC, entries)

int gate_fault(EXCEPTION_POINTERS* ep) noexcept {
    g_gate_off.store(true);
    g_gate_off_why.store(1);
    c_faults.fetch_add(1);
    // Review (5): an outer frame of the game may still handle it (a C++ throw/catch): this is not by itself a crash.
    return game::game_fault_continue(ep, "MountSync",
                                     "0xEE58A40 (the CC request gate behind 0x2329A90) ran with the mod's copy of the "
                                     "remote rider's entries; the exception is passed on to the game's handlers and "
                                     "fix B is off from now on (a crash only if nothing handles it)");
}
// The original with the mod's copy. An exception inside the game's code is the game's: fix B switches off and the
// exception is passed on (never swallowed).
uintptr_t gate_call(uintptr_t cc, uint8_t* copy, uint64_t r8, uint64_t r9) noexcept {
    __try {
        return g_h_gate.unsafe_call<uintptr_t>(cc, reinterpret_cast<uintptr_t>(copy), r8, r9);
    } __except (gate_fault(GetExceptionInformation())) {
        return 0;
    }
}

// The view of one call (SEH reads only). `copy` receives the two entries (kGateBytes) when they could be read.
msl::GateView gate_view(uintptr_t cc, uintptr_t entries, uint8_t* copy, uint32_t& key, RiderProbe& rp) noexcept {
    msl::GateView v;
    v.network_call = true;
    const uintptr_t actor = rdp(cc + kCcActor);
    key = key_of(actor);
    const uint32_t remote = remote_key(), local = g_local_key.load(std::memory_order_relaxed);
    // The CC the gate got must be that actor's own ([[actor+0x68]+0x40] == CC, and [CC+8] == actor above).
    v.remote_rider = key != 0 && key == remote && key != local && cc_of(actor) == cc;
    if (!v.remote_rider) return v;
    v.c8 = rdv<uint8_t>(actor + kActorC8, 0xFF);
    rp = probe_cc(cc, actor);
    v.chart = rp.chart;
    v.method = rp.method;
    v.pending_busy = rp.busy != 0;
    v.cur40 = ((rp.flags[0] | rp.flags[1]) & msl::kDefDismount) != 0;
    v.pend40 = rp.pend40;
    if (!rp.ok || !entries || !game::fast_read(entries, copy, msl::kGateBytes)) return v;
    v.readable = true;
    for (uint32_t i = 0; i < msl::kGateEntries; ++i) {
        const uint8_t* e = copy + i * msl::kGateEntrySize;
        if (msl::get32(e + msl::kEntryHash)) {
            v.any_new = true;
            (i ? v.hash1 : v.hash0) = true;
        }
        if ((e[msl::kEntryNet] & msl::kEntryNetBit) || (e[msl::kEntryForce] & msl::kEntryForceBit)) v.net_bits = true;
        if (e[msl::kEntryLocal] & msl::kEntryLocalBit) v.new52 = true;
        uint64_t p8 = 0, p10 = 0, def = 0;
        std::memcpy(&p8, e + 0x08, 8);
        std::memcpy(&p10, e + 0x10, 8);
        std::memcpy(&def, e + msl::kEntryDef, 8);
        if (p8 && p10 && def && (rdv<uint8_t>(static_cast<uintptr_t>(def) + msl::kDefFlags) & msl::kDefDismount)) {
            v.new40 = true;
        }
    }
    return v;
}

// The network path only (0x863880's call): every received 2991/2723 and RestoreActionsFromLoadData.
__declspec(noinline) uintptr_t gate_network(uintptr_t cc, uintptr_t entries, uint64_t r8, uint64_t r9) {
    const FreezeMark mark(g_mark[9]);
    alignas(16) uint8_t copy[msl::kGateBytes];
    uint32_t key = 0;
    RiderProbe rp;
    const msl::GateView v = gate_view(cc, entries, copy, key, rp);
    const msl::GateVerdict verdict = msl::gate_decide(v);
    c_gate_verdict[static_cast<size_t>(verdict)].fetch_add(1, std::memory_order_relaxed);
    if (verdict == msl::GateVerdict::NotRider) return g_h_gate.unsafe_call<uintptr_t>(cc, entries, r8, r9);
    const bool drop = msl::gate_would_drop(v);
    if (drop) c_gate_drop.fetch_add(1, std::memory_order_relaxed);
    if (g_gate_streak.on(verdict, drop)) {
        g_gate_degraded.store(true);
        p8p::Event d;
        d.v[0] = key;
        d.v[1] = msl::kGateDegradeAfter;
        d.v[2] = static_cast<uint8_t>(verdict);
        diag(kGateDegraded, d);
    }
    bool force = false;
    for (uint32_t i = 0; v.readable && i < msl::kGateEntries; ++i) {
        force = force || (copy[i * msl::kGateEntrySize + msl::kEntryForce] & msl::kEntryForceBit) != 0;
    }
    if ((drop || verdict == msl::GateVerdict::Unlock) && c_gate_lines.fetch_add(1, std::memory_order_relaxed) < kMaxGateLines) {
        p8p::Event e;
        e.flags = static_cast<uint16_t>(verdict);
        e.v[0] = key;
        e.v[1] = v.readable ? msl::get32(copy) : 0;
        e.v[2] = v.readable ? msl::get32(copy + msl::kGateEntrySize) : 0;
        e.v[3] = rp.method;
        e.v[4] = (static_cast<uint64_t>(rp.hash[0]) << 32) | rp.hash[1];
        e.v[5] = rp.flags[0] | (static_cast<uint64_t>(rp.flags[1]) << 8) | (static_cast<uint64_t>(rp.pend40) << 16) |
                 (static_cast<uint64_t>(rp.busy) << 24) | (static_cast<uint64_t>(rp.chart) << 32) |
                 (static_cast<uint64_t>(v.new40) << 40) | (static_cast<uint64_t>(v.new52) << 41) |
                 (static_cast<uint64_t>(force) << 42) | (static_cast<uint64_t>(v.c8) << 48);
        e.v[6] = rp.rideoff_key;
        e.v[7] = c_gate_verdict[static_cast<size_t>(msl::GateVerdict::Unlock)].load(std::memory_order_relaxed);
        diag(kGate, e);
    }
    if (verdict != msl::GateVerdict::Unlock) return g_h_gate.unsafe_call<uintptr_t>(cc, entries, r8, r9);
    if (force) c_gate_force_bit.fetch_add(1, std::memory_order_relaxed);
    msl::gate_clear_bits(copy);
    t_gate_unlocked = true;
    return gate_call(cc, copy, r8, r9);
}

uintptr_t __fastcall gate_detour(uintptr_t cc, uintptr_t entries, uint64_t r8, uint64_t r9) {
    // Review (9): every other caller (the local chart 0x232D4C1 of every actor, 0xA7A10E, .xtls) leaves at once,
    // untouched, before anything else (no freeze mark).
    if (reinterpret_cast<uintptr_t>(_ReturnAddress()) != g_base + addrs().gate_ret || mode() != Mode::On ||
        g_gate_off.load(std::memory_order_relaxed)) {
        return g_h_gate.unsafe_call<uintptr_t>(cc, entries, r8, r9);
    }
    return gate_network(cc, entries, r8, r9);
}

// ---------------------------------------------------------------- RideOn / RideOff ::Enter (method, same_method)

uint64_t enter_common(SafetyHookInline& h, bool off_method, uintptr_t m, uint64_t a2, uint64_t a3, uint64_t a4) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const uint64_t ret = h.unsafe_call<uint64_t>(m, a2, a3, a4);
    const uintptr_t actor = rdp(m + kMethodActor);
    const uint32_t key = key_of(actor);
    const bool ok = static_cast<uint8_t>(ret) != 0;
    if (off_method) {
        c_enter_off.fetch_add(1, std::memory_order_relaxed);
        if (!ok) c_enter_off_fail.fetch_add(1, std::memory_order_relaxed);
    } else {
        c_enter_on.fetch_add(1, std::memory_order_relaxed);
        if (!ok) c_enter_on_fail.fetch_add(1, std::memory_order_relaxed);
    }
    if (!msl::is_char(key)) return ret;
    const uint32_t remote = remote_key(), local = g_local_key.load(std::memory_order_relaxed);
    if (off_method && key == remote) g_rideoff_seen.store(key, std::memory_order_relaxed);
    // P8 S26: from the remote rider's RideOn::Enter on (ok or not) its link is never applied again (relink_due).
    if (!off_method && key == remote) g_rideon_seen.store(key, std::memory_order_relaxed);
    // P8 S21: a seat's release is expected from the remote rider's (ok) RideOff::Enter on (consumed at a dispatch).
    if (off_method && key == remote && ok) g_seat_rideoff_ms.store(now_ms(), std::memory_order_relaxed);
    if (off_method && key == local && ok) g_local_rideoff_ms.store(now_ms(), std::memory_order_relaxed);
    // P8 S18: the local player's own RideOff: which of its current actions carry def+0xA & 0x40 (ride_filter's
    // partial list learns them; the remote rider's dispatch probe does the same).
    if (off_method && key == local) {
        const RiderProbe lp = probe_rider(actor);
        for (int i = 0; i < 2 && lp.ok; ++i) {
            if ((lp.flags[i] & msl::kDefDismount) && ride_filter_learn_gate_hash(lp.hash[i])) {
                c_learned.fetch_add(1, std::memory_order_relaxed);
                p8p::Event l;
                l.flags = 2;
                l.v[0] = key;
                l.v[1] = lp.hash[i];
                l.v[2] = lp.flags[i];
                l.v[3] = i;
                diag(kLearn, l);
            }
        }
    }
    const msl::PairState s = read_pair(actor, 0, 0, 0);
    uint8_t method = 0xFF;
    uint32_t a0 = 0, a1 = 0;
    read_actions(actor, method, a0, a1);
    p8p::Event e;
    e.flags = off_method ? 1 : 0;
    e.v[0] = key;
    e.v[1] = static_cast<uint8_t>(ret);
    e.v[2] = s.cur_vehicle;
    e.v[3] = static_cast<uint8_t>(s.cur_seat);
    e.v[4] = key == remote ? 1 : key == local ? 2 : 0;
    e.v[5] = (static_cast<uint64_t>(a0) << 32) | a1;
    e.v[6] = rva_of(caller);
    e.v[7] = method;
    e.v[8] = g_remote_phase.load(std::memory_order_relaxed);
    // P8 S22 [V Ghidra]: RideOn::Enter starts its warp at [[CC+0x100]+0x24], which stays the identity (the world
    // origin) unless vf54 seated the rider first (0xA651E0 writes its current transform): an unseated remote rider
    // here is the mount blink.
    e.v[9] = attach_type_of(actor);
    if (!off_method && key == remote && e.v[9] == msl::kAttachNone && seat_mode() == Mode::On) {
        c_enter_unseated.fetch_add(1, std::memory_order_relaxed);
    }
    diag(kEnter, e);
    return ret;
}
uint64_t __fastcall enter_on_detour(uintptr_t m, uint64_t a2, uint64_t a3, uint64_t a4) {
    const FreezeMark mark(g_mark[4]);
    return enter_common(g_h_on, false, m, a2, a3, a4);
}
uint64_t __fastcall enter_off_detour(uintptr_t m, uint64_t a2, uint64_t a3, uint64_t a4) {
    const FreezeMark mark(g_mark[5]);
    return enter_common(g_h_off, true, m, a2, a3, a4);
}

// ---------------------------------------------------------------- P8 S21: 0x88E6A0 the mode-2 update (mc, XMM1 dt, out)

// `out` is the caller's own stack struct (0x88EB70's frame, zero-filled): an access violation of this copy is ours.
bool write_out(uint8_t* out, const uint8_t* pose) noexcept {
    __try {
        std::memcpy(out, pose, 16);
        return true;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}

// The original returned early (its buffer was empty): whose actor, and in mode 1 the remote player's current pose
// (TS+0xB4..+0xC3, what 0x4F8220's fast path returns) into `out` instead of the zeroed one. Relaxed counters only.
__declspec(noinline) void hold_after(uintptr_t mc, uint8_t* out) noexcept {
    const uintptr_t cc = rdp(mc + kMcCc);
    const uintptr_t actor = cc ? rdp(cc + kCcActor) : 0;
    const msl::HoldWho who = msl::hold_who(true, key_of(actor), remote_key(), g_local_key.load(std::memory_order_relaxed));
    if (who == msl::HoldWho::None) return;
    const Mode m = hold_mode();
    alignas(8) uint8_t pose[16] = {};
    bool read = false;
    if (who == msl::HoldWho::Remote && m == Mode::On) {
        const uintptr_t comps = rdp(actor + kActorComps);
        const uintptr_t ts = comps ? rdp(comps + kCompsTs) : 0;
        // +0xB4..+0xC3: pos, sector x, z. Read twice: the main thread may be writing it (a torn pose is not used).
        alignas(8) uint8_t again[16] = {};
        read = ts && game::fast_read(ts + kTsPos, pose, sizeof pose) && game::fast_read(ts + kTsPos, again, sizeof again) &&
               std::memcmp(pose, again, sizeof pose) == 0;
    }
    float pos[3];
    int16_t sector[2];
    std::memcpy(pos, pose, sizeof pos);
    std::memcpy(sector, pose + 0xC, sizeof sector);
    switch (msl::hold_decide(m, who, read, pos, sector[0], sector[1])) {
        case msl::HoldAct::None: break;
        case msl::HoldAct::CountOther: c_hold_other.fetch_add(1, std::memory_order_relaxed); break;
        case msl::HoldAct::CountRemote: c_hold_remote.fetch_add(1, std::memory_order_relaxed); break;
        case msl::HoldAct::Unreadable:
            c_hold_remote.fetch_add(1, std::memory_order_relaxed);
            c_hold_unreadable.fetch_add(1, std::memory_order_relaxed);
            break;
        case msl::HoldAct::Fill:
            c_hold_remote.fetch_add(1, std::memory_order_relaxed);
            (out && write_out(out, pose) ? c_hold_filled : c_hold_unreadable).fetch_add(1, std::memory_order_relaxed);
            break;
    }
}

// Every remote actor, every frame, on ParallelTaskWorker threads: one guarded byte read and the original; no lock,
// no allocation, no log (no freeze mark either: its first use per thread registers the thread).
void __fastcall hold_detour(uintptr_t mc, float dt, uint8_t* out) {
    uint8_t flag = 0;
    const bool early = game::fast_read(mc + msl::kMcEmptyFlag, &flag, 1) && flag == 1;
    g_h_hold.unsafe_call<void>(mc, dt, out);
    // S21 review: the main thread may set a sample (flag -> 0) between the read above and the original's own test;
    // then the original wrote a real pose. Only a flag still 1 after it means it returned early.
    if (early && game::fast_read(mc + msl::kMcEmptyFlag, &flag, 1) && flag == 1) hold_after(mc, out);
}

// ---------------------------------------------------------------- P8 S22: 0xA45AC0 the riding action request (vc, key, on)

// Its callers are vf54 (on 1) and vf42's tail (0), both behind the rider's vf178. Never for the other player's
// character: dropped and counted (the judge already keeps vf54 from reaching it; expected 0).
void __fastcall actreq_detour(uintptr_t vc, uint32_t horse_key, uint8_t on, uint64_t a4) {
    const uint32_t key = key_of(vc ? rdp(vc + kVcActor) : 0);
    const uint32_t remote = remote_key();
    if (key != 0 && key == remote && key != g_local_key.load(std::memory_order_relaxed)) {
        c_actreq_veto.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_h_actreq.unsafe_call<void>(vc, horse_key, on, a4);
}

// ---------------------------------------------------------------- 2663 / 2916 handlers (self, res, pkt)

bool read_payload(uintptr_t pkt, uint8_t* out, size_t want, uint16_t& len) noexcept {
    const uintptr_t buf = rdp(pkt + kPktBuffer);
    if (!buf) return false;
    len = rdv<uint16_t>(buf + 3);
    if (len < want) return false;
    return game::fast_read(buf + 5, out, want);
}

uintptr_t inter_common(SafetyHookInline& h, uint16_t op, uintptr_t self, int32_t* res, uintptr_t pkt, uint64_t a4) {
    uint8_t p[20] = {};
    uint16_t len = 0;
    const bool have = read_payload(pkt, p, sizeof p, len);
    const uint32_t requester = have ? msl::get32(p + 4) : 0, target = have ? msl::get32(p + 8) : 0;
    const bool watch = have && msl::is_b(target) && msl::is_char(requester);
    const uintptr_t actor = watch ? find_actor(requester) : 0;
    const msl::PairState before = watch ? read_pair(actor, 0, 0, 0) : msl::PairState{};
    const uintptr_t ret = h.unsafe_call<uintptr_t>(self, res, pkt, a4);
    if (!watch) return ret;
    c_inter.fetch_add(1, std::memory_order_relaxed);
    if (!g_lim_inter.take(p8_now_us())) {
        g_limited.fetch_add(1, std::memory_order_relaxed);
        return ret;
    }
    const msl::PairState after = read_pair(actor, 0, 0, 0);
    p8p::Event e;
    e.flags = op;
    for (int i = 0; i < 5; ++i) e.v[i] = msl::get32(p + 4 * i);
    e.v[5] = before.res_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(before.res_seat)) << 32);
    e.v[6] = after.res_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(after.res_seat)) << 32);
    e.v[7] = before.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(before.cur_seat)) << 32);
    e.v[8] = after.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(after.cur_seat)) << 32);
    e.v[9] = res ? static_cast<uint32_t>(rdv<int32_t>(reinterpret_cast<uintptr_t>(res), -1)) : 0xFFFFFFFFu;
    e.v[10] = len;
    diag(kInter, e);
    return ret;
}
uintptr_t __fastcall h2663_detour(uintptr_t self, int32_t* res, uintptr_t pkt, uint64_t a4) {
    const FreezeMark mark(g_mark[6]);
    return inter_common(g_h_2663, 2663, self, res, pkt, a4);
}
uintptr_t __fastcall h2916_detour(uintptr_t self, int32_t* res, uintptr_t pkt, uint64_t a4) {
    const FreezeMark mark(g_mark[7]);
    return inter_common(g_h_2916, 2916, self, res, pkt, a4);
}

// ---------------------------------------------------------------- the observer's native calls (client main thread)

// P8 review I1: an exception inside the game's code we called is the game's: the native calls switch off, one
// line goes straight to the log and the exception is passed on (never swallowed).
int apply_fault(EXCEPTION_POINTERS* ep, const char* where) noexcept {
    t_applying = false;
    g_apply_off.store(true);
    c_faults.fetch_add(1);
    return game::game_fault_continue(ep, "MountSync", where);
}
bool guarded_vf53(uintptr_t vc, int32_t* res, uintptr_t rider, uint8_t seat, uint8_t fifth) noexcept {
    __try {
        g_vf53(vc, res, rider, seat, fifth);
        return true;
    } __except (apply_fault(GetExceptionInformation(), "0x2228260 (CommonVehicle::vf53) replayed the other player's mount")) {
        return false;
    }
}
bool guarded_rideoff(int32_t* res, uintptr_t horse, uint32_t* rider_key, uint64_t p4, uint8_t flag) noexcept {
    __try {
        g_rideoff(res, horse, rider_key, p4, flag);
        return true;
    } __except (apply_fault(GetExceptionInformation(), "0x2228E40 (CommonVehicle RideOff) replayed the other player's dismount")) {
        return false;
    }
}
// P8 S21: ClientVehicle vf54 0xA45760 as its native callers call it right after vf53 (0xA469FA..0xA46A08: RCX vc,
// RDX &res, R8 rider, R9 = movzx seat; no stack argument), through the vf54 hook's original (vf54_detour does not see
// the mod's own call).
bool guarded_vf54(uintptr_t vc, int32_t* res, uintptr_t rider, uint8_t seat) noexcept {
    __try {
        g_h_vf54.unsafe_call<uintptr_t>(vc, res, rider, static_cast<uint64_t>(seat));
        return true;
    } __except (apply_fault(GetExceptionInformation(), "0xA45760 (ClientVehicle vf54) seated the other player's rider")) {
        return false;
    }
}

void record_args(uint16_t plan, uintptr_t vc, uintptr_t rider, uintptr_t horse, const msl::Txn& t) noexcept {
    p8p::Event e;
    e.flags = plan;
    e.v[0] = vc;
    e.v[1] = rider;
    e.v[2] = horse;
    e.v[3] = t.seat;
    e.v[4] = t.fifth;
    e.v[5] = t.detach_aux;
    e.v[6] = t.detach_flag;
    e.v[7] = t.rider;
    e.v[8] = t.horse;
    e.v[9] = t.transition;
    e.v[10] = t.no_event;
    e.v[11] = (t.native_gone ? 1u : 0u) | (t.native_fallback ? 2u : 0u) |
              (g_native_policy.load(std::memory_order_relaxed) ? 4u : 0u) | (t.native_lost ? 8u : 0u);
    diag(kArgs, e);
}

void record_apply(uint16_t plan, const msl::Txn& t, msl::Judge j, msl::Outcome o, msl::Post post, int32_t r,
                  const msl::PairState& b, const msl::PairState& a) noexcept {
    p8p::Event e;
    e.flags = plan;
    e.v[0] = t.rider;
    e.v[1] = t.horse;
    e.v[2] = t.seat | (static_cast<uint64_t>(t.fifth) << 8);
    e.v[3] = t.transition;
    e.v[4] = static_cast<uint8_t>(j);
    e.v[5] = static_cast<uint8_t>(o);
    e.v[6] = static_cast<uint8_t>(post);
    e.v[7] = static_cast<uint32_t>(r);
    e.v[8] = b.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(b.cur_seat)) << 32);
    e.v[9] = a.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(a.cur_seat)) << 32);
    e.v[10] = b.occupant | (static_cast<uint64_t>(a.occupant) << 32);
    e.v[11] = b.count | (static_cast<uint64_t>(a.count) << 8) | (static_cast<uint64_t>(g_mode.load()) << 16) |
              (static_cast<uint64_t>(b.rider_c8) << 24) | (static_cast<uint64_t>(b.horse_c8) << 32) |
              (static_cast<uint64_t>(b.rider_ctrl == b.horse_ctrl) << 40) | (static_cast<uint64_t>(t.attempts) << 48);
    diag(kApply, e);
}

void finish(bool commit, const msl::Txn& t, msl::Outcome o, bool retired_old = false) noexcept {
    c_outcome[static_cast<size_t>(o)].fetch_add(1, std::memory_order_relaxed);
    AcquireSRWLockExclusive(&g_lock);
    if (commit) {
        g_table.finish_commit(t.rider, t.transition, o, retired_old);
    } else {
        g_table.finish_detach(t.rider, t.transition, o);
    }
    g_has_work.store(g_table.has_work(), std::memory_order_relaxed);
    const msl::Txn* cur = g_table.find(t.rider);
    publish_phase(cur);
    ReleaseSRWLockExclusive(&g_lock);
}

// One native retirement of `rider` from `horse` here (0x2228E40, the client's own flag/p4), only when
// msl::detach_decide says Call (session 18 review (1): 0xE6F2E60 dereferences the horse's comps and vc unchecked).
// Returns the outcome; `after`/`post`/`r` filled when it ran.
msl::Outcome retire_native(uintptr_t rider, uint32_t rider_key, uintptr_t horse, uint32_t horse_key,
                           const msl::PairState& before, uint64_t p4, uint8_t flag, int32_t& r,
                           msl::PairState& after, msl::Post& post) noexcept {
    switch (msl::detach_decide(before, horse_key)) {
        case msl::DetachCall::AlreadyGone: return msl::Outcome::AlreadyApplied;  // nothing of this pair here
        case msl::DetachCall::Refused: return msl::Outcome::Refused;
        case msl::DetachCall::Call: break;
    }
    if (g_apply_off.load() || !g_rideoff) return msl::Outcome::Refused;
    uint32_t key = rider_key;
    t_applying = true;
    const bool ran = guarded_rideoff(&r, horse, &key, p4, flag);
    t_applying = false;
    after = read_pair(rider, horse, vc_of(horse), 0);
    post = ran ? msl::verify_detach(before, after, rider_key, horse_key, r) : msl::Post::Result;
    const msl::Outcome o = post == msl::Post::Ok ? msl::Outcome::Applied : msl::Outcome::Failed;
    (o == msl::Outcome::Applied ? c_detach_ok : c_detach_fail).fetch_add(1, std::memory_order_relaxed);
    return o;
}

// P8 S21 (mount_seat): after the observer's vf53 left (or found) the rider's Link, the native seat with vf54, judged
// first (msl::seat_judge) and checked after (msl::seat_verify, read back). A seat (type 4) is watched until released.
enum SeatOut : uint16_t { kSeatSeated, kSeatFailed, kSeatAlready, kSeatRefused, kSeatProbe, kSeatFault };
void seat_rider(const msl::Txn& t, msl::Outcome commit, uintptr_t rider, uintptr_t horse, uintptr_t vc) noexcept {
    const msl::PairState p = read_pair(rider, horse, vc, t.seat);
    const msl::SeatState pre = read_seat(rider, horse);
    msl::SeatJudge j = msl::seat_judge(seat_mode(), p, pre, t.horse, t.seat, t.rider,
                                         g_local_key.load(std::memory_order_relaxed));
    if (j.verdict == msl::SeatVerdict::Apply && (g_apply_off.load() || g_seat_off.load() || !g_on_vf54.load())) {
        j = {msl::SeatVerdict::Refused, msl::SeatWhy::Off};
    }
    msl::SeatState post = pre;
    msl::SeatPost sp = msl::SeatPost::Ok;
    int32_t r = -1;
    uint16_t out = kSeatRefused;
    const uint64_t t0 = p8_now_us();
    switch (j.verdict) {
        case msl::SeatVerdict::AlreadySeated:
            out = kSeatAlready;
            c_seat_already.fetch_add(1, std::memory_order_relaxed);
            if (seat_mode() == Mode::On) g_seat.seat(t.rider, t.horse, now_ms());
            break;
        case msl::SeatVerdict::Probe:
            out = kSeatProbe;
            c_seat_probe.fetch_add(1, std::memory_order_relaxed);
            break;
        case msl::SeatVerdict::Refused:
        case msl::SeatVerdict::Count: c_seat_refused.fetch_add(1, std::memory_order_relaxed); break;
        case msl::SeatVerdict::Apply: {
            t_applying = true;
            const bool ran = guarded_vf54(vc, &r, rider, t.seat);
            t_applying = false;
            post = read_seat(rider, horse);
            sp = ran ? msl::seat_verify(pre, post, r, t.horse) : msl::SeatPost::Result;
            out = !ran ? kSeatFault : sp == msl::SeatPost::Ok ? kSeatSeated : kSeatFailed;
            if (out == kSeatSeated) {
                c_seat_seated.fetch_add(1, std::memory_order_relaxed);
            } else {
                // Never a second try this session (abort criterion, §13); a fault already turned every native call off.
                // Review of bf255bb (2): a relink's seat failed in a state no session captured: this mount only.
                c_seat_failed.fetch_add(1, std::memory_order_relaxed);
                if (!t.relinking) g_seat_off.store(true);
            }
            // Whatever the verdict, a rider left attached (type 4) is watched until its release.
            if (post.attach_type == msl::kAttachSeat) g_seat.seat(t.rider, t.horse, now_ms());
            break;
        }
    }
    p8p::Event e;
    e.flags = out;
    e.v[0] = t.rider;
    e.v[1] = t.horse;
    e.v[2] = t.seat | (static_cast<uint64_t>(j.why) << 8) | (static_cast<uint64_t>(sp) << 16) |
             (static_cast<uint64_t>(commit) << 24) | (static_cast<uint64_t>(seat_mode()) << 32);
    e.v[3] = static_cast<uint32_t>(r);
    e.v[4] = pre.attach_type | (static_cast<uint64_t>(post.attach_type) << 8) | (static_cast<uint64_t>(pre.cc228) << 16) |
             (static_cast<uint64_t>(post.cc228) << 24) | (static_cast<uint64_t>(pre.rider_type) << 32) |
             (static_cast<uint64_t>(pre.horse_type) << 40) | (static_cast<uint64_t>(pre.has_parent) << 48) |
             (static_cast<uint64_t>(post.has_parent) << 49);
    e.v[5] = pre.parent_key | (static_cast<uint64_t>(post.parent_key) << 32);
    e.v[6] = vc;
    e.v[7] = rider;
    e.v[8] = p8_now_us() - t0;
    e.v[9] = t.transition;
    e.v[10] = pre.parent_type | (static_cast<uint64_t>(post.parent_type) << 8) |
              (static_cast<uint64_t>(pre.rider_local) << 16) | (static_cast<uint64_t>(pre.horse_cc) << 24) |
              (static_cast<uint64_t>(msl::seat_local_user(pre)) << 25) | (static_cast<uint64_t>(pre.vf178) << 32);
    e.v[11] = (pre.rider_user && pre.rider_user == pre.local_user ? 1u : 0u) |
              (static_cast<uint64_t>(pre.rider_c8) << 8) | (static_cast<uint64_t>(pre.horse_c8) << 16);
    diag(kSeat, e);
}

void do_commit(const msl::Txn& t) noexcept {
    const uintptr_t rider = find_actor(t.rider), horse = find_actor(t.horse);
    const uintptr_t vc = vc_of(horse);
    msl::PairState before = read_pair(rider, horse, vc, t.seat);
    msl::Judge j = msl::judge_commit(before, t.rider, t.horse, t.seat, t.fifth, t.linked_here);
    record_args(1, vc, rider, horse, t);
    bool retired_old = false;
    if (j == msl::Judge::RetireFirst && mode() == Mode::On) {
        // Session 18 review (3): a new horse while the rider is still linked HERE to the previous one this client
        // linked it to: that link is retired first (guarded like any retirement), then the commit is judged again.
        c_judge[static_cast<size_t>(j)].fetch_add(1, std::memory_order_relaxed);
        const uint32_t old_key = before.cur_vehicle;
        const uintptr_t old_horse = find_actor(old_key);
        const msl::PairState ob = read_pair(rider, old_horse, vc_of(old_horse), static_cast<uint8_t>(before.cur_seat));
        int32_t orr = -1;
        msl::PairState oa = ob;
        msl::Post op = msl::Post::Ok;
        const msl::Outcome oo = retire_native(rider, t.rider, old_horse, old_key, ob, 0, msl::kClientDetachFlag,
                                              orr, oa, op);
        msl::Txn old = t;
        old.horse = old_key;
        old.detach_flag = msl::kClientDetachFlag;
        old.detach_aux = 0;
        record_apply(2, old, msl::Judge::RetireFirst, oo, op, orr, ob, oa);
        retired_old = oo == msl::Outcome::Applied || oo == msl::Outcome::AlreadyApplied;
        if (retired_old) g_seat.expect(t.rider, msl::SeatCause::Detach, now_ms());  // P8 S21: a seat on the old horse
        before = read_pair(rider, horse, vc, t.seat);
        j = msl::judge_commit(before, t.rider, t.horse, t.seat, t.fifth, retired_old ? 0 : t.linked_here);
    }
    c_judge[static_cast<size_t>(j)].fetch_add(1, std::memory_order_relaxed);
    msl::Outcome o;
    msl::Post post = msl::Post::Ok;
    int32_t r = -1;
    msl::PairState after = before;
    if (mode() != Mode::On) {
        o = msl::Outcome::ProbeOnly;
    } else if (j == msl::Judge::AlreadyApplied) {
        o = msl::Outcome::AlreadyApplied;
    } else if (msl::judge_retry(j)) {
        o = msl::Outcome::NotReady;
    } else if (j != msl::Judge::Apply || g_apply_off.load() || !g_vf53) {
        o = msl::Outcome::Refused;
    } else {
        t_applying = true;
        const bool ran = guarded_vf53(vc, &r, rider, t.seat, t.fifth);
        t_applying = false;
        after = read_pair(rider, horse, vc, t.seat);
        post = ran ? msl::verify_commit(before, after, t.rider, t.horse, t.seat, r) : msl::Post::Result;
        o = post == msl::Post::Ok ? msl::Outcome::Applied : msl::Outcome::Failed;
        if (o == msl::Outcome::Failed) c_post_fail.fetch_add(1, std::memory_order_relaxed);
    }
    record_apply(1, t, j, o, post, r, before, after);
    // P8 S21: the native seat (vf54) once the link is there; AlreadyApplied too (the judge sees an existing seat).
    if (seat_mode() != Mode::Off && (o == msl::Outcome::Applied || o == msl::Outcome::AlreadyApplied)) {
        seat_rider(t, o, rider, horse, vc);
    }
    finish(true, t, o, retired_old);
}

void do_detach(const msl::Txn& t) noexcept {
    const uintptr_t rider = find_actor(t.rider), horse = find_actor(t.horse);
    const uintptr_t vc = vc_of(horse);
    const msl::PairState before = read_pair(rider, horse, vc, t.seat);
    record_args(2, vc, rider, horse, t);
    msl::Outcome o;
    msl::Post post = msl::Post::Ok;
    int32_t r = -1;
    msl::PairState after = before;
    const msl::Judge j = !rider ? msl::Judge::NoRider : !horse ? msl::Judge::NoHorse : msl::Judge::Apply;
    if (t.no_event) c_no_event.fetch_add(1, std::memory_order_relaxed);
    if (t.native_gone) c_native_gone.fetch_add(1, std::memory_order_relaxed);
    if (t.native_fallback) c_native_fallback.fetch_add(1, std::memory_order_relaxed);
    if (t.native_lost) c_native_lost.fetch_add(1, std::memory_order_relaxed);
    if (mode() != Mode::On) {
        o = msl::Outcome::ProbeOnly;
    } else if (t.native_lost) {
        o = msl::Outcome::Refused;  // review (3): the rider is unreadable here: forgotten, nothing is called
    } else {
        o = retire_native(rider, t.rider, horse, t.horse, before, t.detach_aux, t.detach_flag, r, after, post);
    }
    record_apply(2, t, j, o, post, r, before, after);
    // P8 S21: the link of that rider is gone here (retired now, or natively before): its seat's release is due.
    if (o == msl::Outcome::Applied || o == msl::Outcome::AlreadyApplied) {
        g_seat.expect(t.rider, msl::SeatCause::Detach, now_ms());
    }
    finish(false, t, o);
}

// ---------------------------------------------------------------- 0xB57720 StartActionAck 2991 handler (self, res, pkt)

// The native payload layout: 3576's and 3663's are 3527's (game::wire_build()).
size_t ack_size() noexcept { return movement::payload_size(game::wire_build(), 2991); }

bool guarded_rewrite(uintptr_t payload, rfl::Kind kind) noexcept {
    __try {
        return rfl::rewrite(reinterpret_cast<uint8_t*>(payload), ack_size(), kind, game::wire_build());
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Session 17, controller: the link watch. A player's dismount clears its Link+0x10 by a route that never reaches
// 0x2228E40 (S17: 0 thunk calls for 8 player dismounts); at most every 30 ms of dispatches (client main thread,
// the thread that writes the link), an armed pair whose link is gone publishes its observed Detach.
void ctl_watch(uint64_t now) noexcept {
    const uint64_t armed = g_ctl_arm.load(std::memory_order_acquire);
    if (!armed) return;
    if (now - g_ctl_watch_ms.load(std::memory_order_relaxed) < msl::kGeoEveryMs) return;
    g_ctl_watch_ms.store(now, std::memory_order_relaxed);
    c_ctl_watch_reads.fetch_add(1, std::memory_order_relaxed);
    const msl::PairState s = read_pair(find_actor(g_local_key.load(std::memory_order_relaxed)), 0, 0, 0);
    switch (msl::ctl_link(s, msl::arm_horse(armed))) {
        case msl::CtlLink::Gone: {
            // Debounced: at once after this rider's RideOff::Enter since the commit (every S17 dismount), else
            // only once the link stayed gone for kCtlGoneMs (death, a fall, a teleport: no RideOff::Enter), so a
            // transient clear in the middle of a ride is never reported.
            if (!g_ctl_gone_ms) g_ctl_gone_ms = now;
            const bool after_rideoff = g_local_rideoff_ms.load(std::memory_order_relaxed) >=
                                       g_ctl_arm_ms.load(std::memory_order_relaxed);
            if (after_rideoff || now - g_ctl_gone_ms >= msl::kCtlGoneMs) publish_observed_detach(armed, s, 1);
            break;
        }
        case msl::CtlLink::Unknown: c_ctl_watch_unknown.fetch_add(1, std::memory_order_relaxed); break;
        case msl::CtlLink::Riding: g_ctl_gone_ms = 0; break;
    }
}

// An actor's world position (TransformSync +0xB4 sector-local + sector * 1000 m) and, optionally, its rotation
// (+0xA4, x y z w) [V: remote_motion.cpp, combat_follow.cpp, actor_lookup.cpp].
bool read_world(uintptr_t actor, float pos[3], float* quat) noexcept {
    const uintptr_t comps = actor ? rdp(actor + kActorComps) : 0;
    const uintptr_t ts = comps ? rdp(comps + kCompsTs) : 0;
    float p[3] = {};
    int16_t sector[2] = {};
    if (!ts || !game::fast_read(ts + kTsPos, p, sizeof p) || !game::fast_read(ts + kTsSector, sector, sizeof sector) ||
        (quat && !game::fast_read(ts + kTsQuat, quat, 16))) {
        return false;
    }
    if (!std::isfinite(p[0]) || !std::isfinite(p[1]) || !std::isfinite(p[2])) return false;
    pos[0] = p[0] + sector[0] * 1000.0f;
    pos[1] = p[1];
    pos[2] = p[2] + sector[1] * 1000.0f;
    return true;
}

// Session 17, observers (probe and 1): where the remote rider is shown relative to its horse here, while its
// actions say mounted and its transaction rides. Read only, at most every 30 ms of dispatches.
void geo_sample(uint64_t now) noexcept {
    if (g_remote_phase.load(std::memory_order_relaxed) != static_cast<uint8_t>(msl::Phase::Riding) ||
        !g_remote_mounted.load(std::memory_order_relaxed)) {
        g_geo_prev.ms = 0;
        return;
    }
    if (now - g_geo_ms.load(std::memory_order_relaxed) < msl::kGeoEveryMs) return;
    g_geo_ms.store(now, std::memory_order_relaxed);
    const uint32_t rk = remote_key(), hk = g_remote_horse.load(std::memory_order_relaxed);
    if (!rk || !hk) return;
    const uintptr_t rider = find_actor(rk), horse = find_actor(hk);
    float rp[3], hp[3], hq[4];
    if (!read_world(rider, rp, nullptr) || !read_world(horse, hp, hq)) {
        g_geo.unreadable.fetch_add(1, std::memory_order_relaxed);
        g_geo_prev.ms = 0;
        return;
    }
    // P8 S21: seated here (attach type 4), linked here, or neither.
    const bool seated = attach_type_of(rider) == msl::kAttachSeat;
    const GeoPrev prev = g_geo_prev;
    g_geo_prev.ms = now;
    g_geo_prev.horse = hk;
    g_geo_prev.seated = seated;
    for (int i = 0; i < 3; ++i) {
        g_geo_prev.pos[i] = hp[i];
        g_geo_prev.rider[i] = rp[i];
    }
    if (!prev.ms || prev.horse != hk || now <= prev.ms || now - prev.ms > 500) return;
    const float dx = hp[0] - prev.pos[0], dy = hp[1] - prev.pos[1], dz = hp[2] - prev.pos[2];
    const float speed = std::sqrt(dx * dx + dy * dy + dz * dz) / (static_cast<float>(now - prev.ms) / 1000.0f);
    const msl::PairState s = read_pair(rider, 0, 0, 0);
    if (seated && prev.seated && msl::geo_frozen(prev.rider, rp, prev.pos, hp)) {
        g_geo.frozen.fetch_add(1, std::memory_order_relaxed);
    }
    g_geo.add(msl::geo_link(s.cur_vehicle == hk, seated ? msl::kAttachSeat : msl::kAttachNone), rp, hp, hq, speed);
}

// P8 S21: the release watch of a seat this client made (msl::SeatWatch), at most every 30 ms of dispatches. Only for
// the remote rider it was made for (a key that is no longer the remote one, or became the local one, is forgotten:
// the guest's own character may take the host's key after a reset).
void seat_tick(uint64_t now, uint32_t remote) noexcept {
    if (!g_seat.rider()) return;
    if (now - g_seat_tick_ms < msl::kGeoEveryMs) return;
    g_seat_tick_ms = now;
    const uint32_t rk = g_seat.rider(), hk = g_seat.horse();
    const bool still_remote = rk == remote && rk != g_local_key.load(std::memory_order_relaxed);
    const uintptr_t rider = still_remote ? find_actor(rk) : 0;
    const msl::PairState s = read_pair(rider, 0, 0, 0);
    msl::SeatStep st;
    if (still_remote) {
        st = g_seat.step(rider ? attach_type_of(rider) : 0xFF, s.cur_vehicle, msl::ride_method(s.rider_method), now);
    } else {
        g_seat.forget();
        st.rel = msl::SeatRel::Lost;
    }
    if (st.rel == msl::SeatRel::None) return;
    p8p::Event e;
    e.flags = static_cast<uint16_t>(st.rel);
    e.v[0] = rk;
    e.v[1] = hk;
    e.v[2] = static_cast<uint8_t>(st.cause);
    e.v[3] = st.after_ms;
    e.v[4] = st.seated_ms;
    e.v[5] = st.type;
    e.v[6] = s.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(s.cur_seat)) << 32);
    e.v[7] = s.rider_method;
    switch (st.rel) {
        case msl::SeatRel::Released: c_seat_released.fetch_add(1, std::memory_order_relaxed); break;
        case msl::SeatRel::Stuck: c_seat_stuck.fetch_add(1, std::memory_order_relaxed); break;
        case msl::SeatRel::Lost: c_seat_lost.fetch_add(1, std::memory_order_relaxed); break;
        case msl::SeatRel::Retire: {
            // Once: the client's own retirement of a remote rider (flag 12, p4 0), guarded as every retirement here.
            c_seat_retired.fetch_add(1, std::memory_order_relaxed);
            const uintptr_t horse = find_actor(hk);
            const msl::PairState before = read_pair(rider, horse, vc_of(horse), 0);
            int32_t r = -1;
            msl::PairState after = before;
            msl::Post post = msl::Post::Ok;
            const msl::Outcome o = retire_native(rider, rk, horse, hk, before, 0, msl::kClientDetachFlag, r, after, post);
            e.v[8] = static_cast<uint8_t>(o) | (static_cast<uint64_t>(post) << 8);
            e.v[9] = static_cast<uint32_t>(r);
            e.v[10] = after.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(after.cur_seat)) << 32);
            break;
        }
        case msl::SeatRel::None: break;
    }
    diag(kSeatRelease, e);
}

// The remote rider's own 2991 at this dispatch, for the probe after its handler (h2991_detour).
struct DispatchNote {
    bool mine = false;
    uint32_t key = 0;
    uintptr_t actor = 0;
    uint32_t a0 = 0, a1 = 0;
    RiderProbe pre;
};

// The remote rider as the native retirement policy needs it (msl::DetachPolicy::Native).
msl::RiderNow rider_now(uint32_t remote) noexcept {
    msl::RiderNow rn;
    rn.rider = remote;
    const msl::PairState s = read_pair(find_actor(remote), 0, 0, 0);
    rn.known = s.rider_found && s.rider_vc && s.link && s.rider_method != 0xFF;
    rn.link_vehicle = s.cur_vehicle;
    rn.method = s.rider_method;
    return rn;
}

DispatchNote on_dispatch(uintptr_t pkt) noexcept {
    DispatchNote dn;
    c_dispatch.fetch_add(1, std::memory_order_relaxed);
    const uint64_t now = now_ms();
    ctl_watch(now);
    geo_sample(now);
    const uintptr_t buf = rdp(pkt + kPktBuffer);
    const size_t ack_len = ack_size();
    if (!buf || ack_len > 1024 || rdv<uint16_t>(buf + 3) != ack_len) return dn;
    const uintptr_t payload = buf + rfl::kHeader;
    const uint32_t key = rdv<uint32_t>(payload);
    const uint32_t remote = remote_key();
    // The remote rider's own action: read first, so that its on-foot / mounted state counts at THIS dispatch,
    // before its handler (an observed Detach is retired before the first on-foot action runs, review (4)).
    uint8_t copy[1024];
    const bool mine = remote && key == remote && game::fast_read(payload, copy, ack_len);
    const rfl::Ack ack = mine ? rfl::read_ack(copy, ack_len, game::wire_build()) : rfl::Ack{};
    const bool on_foot = ack.parent == ~0ull;
    if (mine) {
        const bool mounted = !on_foot && msl::is_b(static_cast<uint32_t>(ack.parent));
        g_remote_mounted.store(mounted, std::memory_order_relaxed);
        g_remote_parent.store(mounted ? static_cast<uint32_t>(ack.parent) : 0, std::memory_order_relaxed);
        // P8 S21: an on-foot action (not the mount's own, which names its horse) = the seat's release is due; a
        // mounted one cancels such an expectation (a stale action).
        if (on_foot && ack.target != g_seat.horse()) g_seat.expect(key, msl::SeatCause::OnFoot, now);
        if (mounted) g_seat.mounted(key);
    }
    // The observer's native work, claimed under the lock (never held during a game call: blocking is safe,
    // review (5)), run outside it.
    const uint8_t phase0 = g_remote_phase.load(std::memory_order_relaxed);
    const bool note = mine && (phase0 == static_cast<uint8_t>(msl::Phase::Riding) ||
                               phase0 == static_cast<uint8_t>(msl::Phase::DetachPending));
    if (note || g_has_work.load(std::memory_order_relaxed) || g_rideoff_seen.load(std::memory_order_relaxed) ||
        g_rideon_seen.load(std::memory_order_relaxed)) {
        msl::Table::Work w;
        // P8 S18 (DetachPolicy::Native): the remote rider's link and method, read before the lock. P8 S26: also at
        // each of its own actions (the relink needs its link before the handler).
        const msl::RiderNow rn = (g_native_policy.load(std::memory_order_relaxed) || mine) && remote
                                     ? rider_now(remote)
                                     : msl::RiderNow{};
        msl::RiderAction act;
        // Review of bf255bb (1): the relink stops at this client's RideOn::Enter / RideOff::Enter of the rider; without
        // those hooks it must never run (install_thread turns mount_relink off and says so).
        act.own = mine && g_on_enter_on.load(std::memory_order_acquire) &&
                  g_on_enter_off.load(std::memory_order_acquire);
        act.parent = ack.parent;
        act.target = ack.target;
        AcquireSRWLockExclusive(&g_lock);
        if (const uint32_t k = g_rideoff_seen.exchange(0, std::memory_order_relaxed)) g_table.note_ride_off_enter(k);
        if (const uint32_t k = g_rideon_seen.exchange(0, std::memory_order_relaxed)) g_table.note_ride_on_enter(k);
        if (note) g_table.note_rider_parent(key, ack.parent, ack.target, now);
        w = g_table.plan(key, now, rn, act);
        g_has_work.store(g_table.has_work(), std::memory_order_relaxed);
        publish_phase(g_table.find(remote));
        ReleaseSRWLockExclusive(&g_lock);
        if (w.relink_probe) {
            // mount_relink=probe: once per transaction, what a relink would find and how it would be judged.
            const uint64_t n = c_relink_probe.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n <= kRelinkLines) {
                p8p::Event e;
                e.flags = 1;
                e.v[0] = w.txn.rider;
                e.v[1] = w.txn.horse;
                e.v[2] = w.txn.transition;
                e.v[3] = w.txn.attempts;
                e.v[4] = w.txn.relinks;
                e.v[5] = w.txn.committed_ms && now >= w.txn.committed_ms ? now - w.txn.committed_ms : 0;
                e.v[6] = (static_cast<uint64_t>(ack.a0) << 32) | ack.a1;
                e.v[7] = ack.parent;
                e.v[8] = ack.target;
                e.v[9] = rn.link_vehicle;
                e.v[10] = n;
                diag(kRelink, e);
                // The pair as the relink would find it (record_apply's format: "MountApply ... probe: nothing called").
                const uintptr_t rider = find_actor(w.txn.rider), horse = find_actor(w.txn.horse);
                const msl::PairState b = read_pair(rider, horse, vc_of(horse), w.txn.seat);
                const msl::Judge j =
                    msl::judge_commit(b, w.txn.rider, w.txn.horse, w.txn.seat, w.txn.fifth, w.txn.linked_here);
                record_apply(1, w.txn, j, msl::Outcome::ProbeOnly, msl::Post::Ok, -1, b, b);
            }
        }
        if (w.relink) {
            // P8 S26 (montura-regresion.md section 7.2): the game retired the link applied here before the rider's
            // RideOn; applied again (and seated) before this action's handler, as the first time.
            const uint64_t n = c_relink.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n <= kRelinkLines) {
                p8p::Event e;
                e.v[0] = w.txn.rider;
                e.v[1] = w.txn.horse;
                e.v[2] = w.txn.transition;
                e.v[3] = w.txn.attempts;
                e.v[4] = w.txn.relinks;
                e.v[5] = w.txn.committed_ms && now >= w.txn.committed_ms ? now - w.txn.committed_ms : 0;
                e.v[6] = (static_cast<uint64_t>(ack.a0) << 32) | ack.a1;
                e.v[7] = ack.parent;
                e.v[8] = ack.target;
                e.v[9] = rn.link_vehicle;
                e.v[10] = n;
                diag(kRelink, e);
            }
        }
        if (w.plan == msl::Plan::Commit) do_commit(w.txn);
        if (w.plan == msl::Plan::Detach) do_detach(w.txn);
    }
    // P8 S21: the remote rider's RideOff::Enter since the last dispatch, then the seat's release watch.
    if (const uint64_t off_ms = g_seat_rideoff_ms.exchange(0, std::memory_order_relaxed)) {
        g_seat.expect(remote, msl::SeatCause::RideOff, off_ms);
    }
    seat_tick(now, remote);
    if (!mine) return dn;
    const rfl::Kind kind = rfl::classify(ack);
    const uintptr_t rider_actor = find_actor(key);
    const msl::PairState s = read_pair(rider_actor, 0, 0, 0);
    // P8 S18 probe (probe and 1): the gate's view of the remote rider before its handler.
    dn.mine = true;
    dn.key = key;
    dn.actor = rider_actor;
    dn.a0 = ack.a0;
    dn.a1 = ack.a1;
    dn.pre = probe_rider(rider_actor);
    const uint8_t phase = g_remote_phase.load(std::memory_order_relaxed);
    bool rewritten = false, tried = false;
    // The link this action needs: present, and (when a transaction of this rider is known) to ITS horse; a stale
    // link to another horse never lets RideOn/RideOff run.
    const uint32_t want_horse = g_remote_horse.load(std::memory_order_relaxed);
    const bool link_ok = s.cur_vehicle != 0 && (want_horse == 0 || s.cur_vehicle == want_horse);
    // §12: a dismount deferred while fix B was ready, fix B lost since (the guest decides before its inbound queue).
    const bool gate_lost = mode() == Mode::On &&
                           msl::dismount_gate_lost(kind == rfl::Kind::Dismount,
                                                   ride_dismount_mode() == rfl::Dismount::Native, mount_sync_gate_ready());
    if (mode() == Mode::On && msl::fallback_rewrite(ride_filter_rewrites(), kind != rfl::Kind::None, link_ok, gate_lost)) {
        tried = true;
        // The game's receive buffer, before its handler reads it (what ride_filter would have written earlier).
        rewritten = guarded_rewrite(payload, kind);
        (rewritten ? c_fallback : c_fallback_fail).fetch_add(1, std::memory_order_relaxed);
    }
    const bool interesting = kind != rfl::Kind::None || tried ||
                             (phase != static_cast<uint8_t>(msl::Phase::Idle) &&
                              phase != static_cast<uint8_t>(msl::Phase::Detached) &&
                              phase != static_cast<uint8_t>(msl::Phase::Cancelled));
    if (!interesting) return dn;
    if (!tried && !g_lim_ack.take(p8_now_us())) {
        g_limited.fetch_add(1, std::memory_order_relaxed);
        return dn;
    }
    p8p::Event e;
    e.flags = tried ? 1 : 0;
    e.v[0] = key;
    e.v[1] = ack.a0;
    e.v[2] = ack.a1;
    e.v[3] = ack.parent;
    e.v[4] = static_cast<uint8_t>(kind);
    e.v[5] = s.cur_vehicle | (static_cast<uint64_t>(static_cast<uint8_t>(s.cur_seat)) << 32);
    e.v[6] = phase;
    e.v[7] = ack.target;
    e.v[8] = rewritten;
    e.v[9] = tried && link_ok && gate_lost;  // the reason: fix B lost (else: no link)
    diag(tried ? kFallback : kRiderAck, e);
    return dn;
}

// P8 S18 probe, after the remote rider's 2991 handler: did the gate drop it while the copy was in RideOff with a 0x40
// action current (the S18 stuck state), was it taken, or did fix B unlock it? And a line whenever the gate's view of
// the rider changes (method, 0x40 on a layer, actor+0x96), so the next session sees the flags of c9356ceb in vivo.
struct ProbeLast {
    uint8_t method = 0xFE, f0 = 0, f1 = 0, chart = 0xFE;
};
ProbeLast g_probe_last;  // client main thread only

void after_dispatch(const DispatchNote& dn) noexcept {
    const RiderProbe& pre = dn.pre;
    if (!pre.ok) return;
    for (int i = 0; i < 2; ++i) {
        if ((pre.flags[i] & msl::kDefDismount) && ride_filter_learn_gate_hash(pre.hash[i])) {
            c_learned.fetch_add(1, std::memory_order_relaxed);
            p8p::Event l;
            l.flags = 1;
            l.v[0] = dn.key;
            l.v[1] = pre.hash[i];
            l.v[2] = pre.flags[i];
            l.v[3] = i;
            diag(kLearn, l);
        }
    }
    const RiderProbe post = probe_rider(dn.actor);
    const bool stuck = pre.method == msl::kMethodRideOff && pre.gate();
    const bool changed = post.method != pre.method || post.hash[0] != pre.hash[0] || post.hash[1] != pre.hash[1] ||
                         (post.busy != 0 && post.busy != 0xFF);
    uint8_t outcome = 0;  // 0 not stuck, 1 rejected, 2 taken, 3 unlocked by fix B
    if (stuck) {
        c_m7_2991.fetch_add(1, std::memory_order_relaxed);
        outcome = t_gate_unlocked ? 3 : changed ? 2 : 1;
        (outcome == 3 ? c_m7_unlocked : outcome == 2 ? c_m7_taken : c_m7_rejected).fetch_add(1, std::memory_order_relaxed);
    }
    const uint8_t f0 = pre.flags[0] & msl::kDefDismount, f1 = pre.flags[1] & msl::kDefDismount;
    const bool view_changed = pre.method != g_probe_last.method || f0 != g_probe_last.f0 || f1 != g_probe_last.f1 ||
                              pre.chart != g_probe_last.chart;
    g_probe_last = {pre.method, f0, f1, pre.chart};
    if (!stuck && !view_changed) return;
    if (c_probe_lines.fetch_add(1, std::memory_order_relaxed) >= kMaxProbeLines) return;
    const uintptr_t local = find_actor(g_local_key.load(std::memory_order_relaxed));
    p8p::Event e;
    e.flags = outcome;
    e.v[0] = dn.key;
    e.v[1] = (static_cast<uint64_t>(dn.a0) << 32) | dn.a1;
    e.v[2] = pre.method | (static_cast<uint64_t>(post.method) << 8) | (static_cast<uint64_t>(pre.busy) << 16) |
             (static_cast<uint64_t>(post.busy) << 24) | (static_cast<uint64_t>(pre.chart) << 32) |
             (static_cast<uint64_t>(local ? rdv<uint8_t>(local + kActorChartGate, 0xFF) : 0xFF) << 40) |
             (static_cast<uint64_t>(pre.pend40) << 48);
    e.v[3] = (static_cast<uint64_t>(pre.hash[0]) << 32) | pre.hash[1];
    e.v[4] = pre.flags[0] | (static_cast<uint64_t>(pre.flags[1]) << 8);
    e.v[5] = (static_cast<uint64_t>(post.hash[0]) << 32) | post.hash[1];
    e.v[6] = pre.rideoff_key;
    diag(kProbe, e);
}

uintptr_t __fastcall h2991_detour(uintptr_t self, int32_t* res, uintptr_t pkt, uint64_t a4) {
    const FreezeMark mark(g_mark[8]);
    if (!g_main_tid.load(std::memory_order_relaxed)) g_main_tid.store(GetCurrentThreadId(), std::memory_order_relaxed);
    focus_follow_on_dispatch();  // the client's main thread: the other player's character (focus_follow.h)
    DispatchNote dn;
    if (mode() != Mode::Off && g_code_ok.load(std::memory_order_acquire)) dn = on_dispatch(pkt);
    t_gate_unlocked = false;
    const uintptr_t ret = g_h_2991.unsafe_call<uintptr_t>(self, res, pkt, a4);
    if (dn.mine) after_dispatch(dn);
    t_gate_unlocked = false;
    return ret;
}

// ---------------------------------------------------------------- install (its own thread)

bool bytes_at(uintptr_t rva, const uint8_t* bytes, size_t len) {
    std::vector<uint8_t> actual(len);
    return game::safe_read(g_base + rva, actual.data(), len) && std::memcmp(actual.data(), bytes, len) == 0;
}

bool install_one(std::span<const gad::Section> secs, const Point& pt, void* detour, SafetyHookInline& out,
                 std::atomic<bool>& on, uint16_t& mark) {
    if (pt.rva < 0x1000 || pt.rva + pt.len > addrs().code_end ||
        !gad::in_real_code(secs, static_cast<uint32_t>(pt.rva), pt.len) || !bytes_at(pt.rva, pt.bytes, pt.len)) {
        log::error("MountSync: {} (exe+0x{:X}, {} bytes) is not this build's .rsrc code; REFUSED, nothing written",
                   pt.what, pt.rva, pt.len);
        return false;
    }
    // P8 S26 (montura-regresion.md section 7.1): a refused attempt (safetyhook's 14-byte fallback, or not prepared)
    // is logged and tried again a bounded number of times on this thread; nothing is written before it is accepted.
    auto h = game::prepare_inline(
        g_base + pt.rva, detour,
        [&](const std::vector<uint8_t>& o) {
            return o.size() == pt.patch && std::memcmp(o.data(), pt.bytes, pt.patch) == 0;
        },
        "MountSync", pt.what);
    if (!h) {
        log::error("MountSync: {} (exe+0x{:X}): the inline hook could not be prepared ({}); REFUSED", pt.what, pt.rva,
                   game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (orig.size() != pt.patch || std::memcmp(orig.data(), pt.bytes, pt.patch) != 0) {
        log::error("MountSync: {} (exe+0x{:X}): the hook would patch {} bytes, {} were verified; REFUSED, nothing "
                   "written",
                   pt.what, pt.rva, orig.size(), pt.patch);
        return false;
    }
    mark = freeze_watchdog_register("MountSync", pt.what);
    out = std::move(*h);  // the detour calls through it: in place before enabling
    if (!out.enable()) {
        log::error("MountSync: {} (exe+0x{:X}): the hook could not be enabled; REFUSED", pt.what, pt.rva);
        return false;
    }
    on.store(true, std::memory_order_release);
    return true;
}

std::string phase_text(uint64_t p) {
    return p < static_cast<uint64_t>(msl::Phase::Count) ? msl::phase_name(static_cast<msl::Phase>(p)) : "?";
}
std::string link_text(uint64_t v) {
    const auto veh = static_cast<uint32_t>(v);
    return veh ? std::format("0x{:08X}/{}", veh, static_cast<int8_t>(v >> 32)) : std::string("0");
}
const char* outcome_name(uint64_t o) {
    switch (static_cast<msl::Outcome>(o)) {
        case msl::Outcome::Applied: return "APPLIED";
        case msl::Outcome::AlreadyApplied: return "already applied";
        case msl::Outcome::NotReady: return "not ready (retry at its next action)";
        case msl::Outcome::Refused: return "REFUSED (fallback: ride_filter)";
        case msl::Outcome::Failed: return "FAILED postconditions (pair quarantined)";
        case msl::Outcome::ProbeOnly: return "probe: nothing called";
    }
    return "?";
}

std::string line_of(const p8p::Event& e) {
    const uint64_t* v = e.v;
    const std::string when = p8_when(e.qpc_us);
    switch (e.kind) {
        case kBegin:
            return std::format(
                "MountSync MountBegin {} T{} | vf53 0x2228260 rider 0x{:08X} horse 0x{:08X} seat(R9b) {} fifth {} | "
                "caller exe+0x{:X}{} | {}{}{} | transition {} | rider Link before: cur {} res 0x{:08X}/{} | seat "
                "occupant 0x{:08X} reserve 0x{:08X} count {} | C8 rider {} horse {} | ctrl rider 0x{:08X} horse "
                "0x{:08X} | rider method {} A0 0x{:08X} A1 0x{:08X}",
                when, e.tid, v[0], v[1], v[2] & 0xFF, (v[2] >> 8) & 0xFF, v[3], (v[2] >> 19) & 1 ? " (vtable call, client thunk)" : "",
                (v[2] >> 17) & 1 ? "client" : "OTHER thread (server realm?)", (v[2] >> 18) & 1 ? ", observer apply" : "",
                (v[2] >> 16) & 1 ? ", PUBLISHED" : "", v[4], link_text(v[5] | ((v[6] & 0xFF) << 32)), v[7],
                static_cast<int8_t>(v[6] >> 8), v[8], v[9] >> 32, v[9] & 0xFF, (v[2] >> 24) & 0xFF, (v[2] >> 32) & 0xFF,
                v[11] >> 32, v[11] & 0xFFFFFFFF, e.flags & 0xFF, v[10] >> 32, v[10] & 0xFFFFFFFF);
        case kCommit:
            return std::format(
                "MountSync MountCommit {} T{} | rider 0x{:08X} horse 0x{:08X} seat {} fifth {} | *result 0x{:08X} | "
                "after: Link cur {} res 0x{:08X}/{} | occupant 0x{:08X} reserve 0x{:08X} count {} | C8 rider {} horse "
                "{} | ctrl rider 0x{:08X} horse 0x{:08X} | {} | {}{}{} | transition {} | {} us",
                when, e.tid, v[0], v[1], v[2] & 0xFF, (v[2] >> 8) & 0xFF, v[3], link_text(v[5] | ((v[6] & 0xFF) << 32)),
                v[7], static_cast<int8_t>(v[6] >> 8), v[8], v[9] >> 32, v[9] & 0xFF, (v[2] >> 24) & 0xFF,
                (v[2] >> 32) & 0xFF, v[10] >> 32, v[10] & 0xFFFFFFFF,
                (v[2] >> 19) & 1 ? "postconditions OK" : "postconditions NOT met",
                (v[2] >> 17) & 1 ? "client" : "OTHER thread", (v[2] >> 18) & 1 ? ", observer apply" : "",
                (v[2] >> 16) & 1 ? ", PUBLISHED" : "", v[4], v[11]);
        case kRideOffCall:
            return std::format(
                "MountSync MountDetach {} T{} | 0x2228E40 RideOff rider 0x{:08X} horse 0x{:08X} p4 0x{:X} flag {} | "
                "*result 0x{:08X} | rider Link {} -> {} | caller exe+0x{:X} | {}{}{}{} | transition {}",
                when, e.tid, v[0], v[1], v[2], v[3] & 0xFF, v[4], link_text(v[5]), link_text(v[6]), v[7],
                (v[3] >> 8) & 1 ? "client" : "other thread", (v[3] >> 9) & 1 ? ", observer apply" : "",
                (v[3] >> 10) & 1 ? ", inside vf53" : "", (v[3] >> 11) & 1 ? ", PUBLISHED" : "", v[8]);
        case kVf54Call:
            return std::format("MountSync vf54 {} T{} | 0xA45760 vc of 0x{:08X} actor 0x{:08X} r9b {} | *result 0x{:08X} "
                               "| actor Link {} -> {} | attach type {} -> {} | caller exe+0x{:X} | {}{}",
                               when, e.tid, v[0], v[1], v[2], v[3], link_text(v[4]), link_text(v[5]), v[9] & 0xFF,
                               (v[9] >> 8) & 0xFF, v[6], v[7] ? "client" : "other thread", v[8] ? ", inside vf53" : "");
        case kEnter:
            return std::format("MountSync {}::Enter {} T{} | 0x{:08X} ({}) -> {} | Link {} | method {} A0 0x{:08X} A1 "
                               "0x{:08X} | caller exe+0x{:X} | remote txn {} | attach type {}{}",
                               e.flags ? "RideOff" : "RideOn", when, e.tid, v[0],
                               v[4] == 1 ? "remote player" : v[4] == 2 ? "local player" : "other", v[1],
                               link_text(v[2] | (v[3] << 32)), v[7], v[5] >> 32, v[5] & 0xFFFFFFFF, v[6],
                               phase_text(v[8]), v[9],
                               !e.flags && v[4] == 1 && v[9] == msl::kAttachNone
                                   ? " | NOT SEATED: its warp starts at the world origin (the mount blink)"
                                   : "");
        case kInter:
            return std::format("MountSync MountReserve {} T{} | {} actor 0x{:08X} requester 0x{:08X} target 0x{:08X} "
                               "interaction 0x{:X} step {} (len {}) | requester Link res {} -> {} cur {} -> {} | "
                               "*result 0x{:08X}",
                               when, e.tid, e.flags, v[0], v[1], v[2], v[3], v[4], v[10], link_text(v[5]),
                               link_text(v[6]), link_text(v[7]), link_text(v[8]), v[9]);
        case kObs:
            return std::format(
                "MountSync observer {} T{} | {} rider 0x{:08X} horse 0x{:08X} transition {} seat {} fifth {} flags 0x{:X} "
                "result 0x{:08X} nonce 0x{:08X} caller exe+0x{:X} aux 0x{:X} | controller tick {} | -> {} (epoch {})",
                when, e.tid, msl::ev_name(static_cast<msl::EvKind>(v[0])), v[1], v[2], v[3], v[5] & 0xFF,
                (v[5] >> 8) & 0xFF, (v[5] >> 16) & 0xFF, v[6], v[7], v[10], v[11], v[8],
                v[4] < static_cast<uint64_t>(msl::Accept::Count) ? msl::accept_name(static_cast<msl::Accept>(v[4])) : "?",
                v[9]);
        case kArgs:
            return std::format("MountSync {} args {} T{} | {} | rider 0x{:08X} horse 0x{:08X} transition {}",
                               e.flags == 1 ? "commit" : "detach", when, e.tid,
                               e.flags == 1 ? std::format("0x2228260(RCX vc=0x{:X}, RDX &result, R8 rider=0x{:X}, R9b "
                                                          "seat={}, [rsp+0x28] fifth={}) (horse actor 0x{:X})",
                                                          v[0], v[1], v[3], v[4], v[2])
                                            : std::format("0x2228E40(&result, horse=0x{:X}, &rider key, p4=0x{:X}, "
                                                          "flag={}) (rider actor 0x{:X}){}{}",
                                                          v[2], v[5], v[6], v[1],
                                                          v[10] ? " - WITHOUT the controller's Detach: its actions "
                                                                  "are on foot here for 6 s"
                                                                : "",
                                                          (v[11] & 8)   ? " - the rider has been unreadable here for "
                                                                          "15 s: the transaction is FORGOTTEN, nothing "
                                                                          "is called"
                                                          : (v[11] & 1) ? " - the native retirement already ran here "
                                                                          "(RideOff / 0x397F40): nothing is called"
                                                          : (v[11] & 2) ? " - native FALLBACK: the link this client made "
                                                                          "is still there 2 s after the Detach and the "
                                                                          "rider is not in RideOn/RideOff (flag 0)"
                                                                        : ""),
                               v[7], v[8], v[9]);
        case kCtlDetach:
            return std::format("MountSync MountDetach (observed) {} T{} | the controller's own link: rider 0x{:08X} "
                               "left horse 0x{:08X} (Link+0x10 now {}) by a route that is not 0x2228E40 | "
                               "transition {} | {} | {} | PUBLISHED as a Detach (flag {}, p4 0)",
                               when, e.tid, v[0], v[1], link_text(v[3]), v[2],
                               v[4] == ~0ull ? std::string("no RideOff::Enter of it seen")
                                             : std::format("{} ms after its last RideOff::Enter", v[4]),
                               e.flags == 2 ? "seen at its next mount's vf53 entry" : "link watch",
                               msl::kClientDetachFlag);
        case kApply: {
            const uint16_t plan = e.flags;
            return std::format(
                "MountSync MountApply [{}] {} T{} | {} rider 0x{:08X} horse 0x{:08X} seat {} fifth {} transition {} "
                "(attempt {}) | judge: {} -> {} | post: {} | *result 0x{:08X} | Link {} -> {} | occupant 0x{:08X} -> "
                "0x{:08X} count {} -> {} | C8 rider {} horse {} | same controller {}",
                msl::mode_name(static_cast<Mode>((v[11] >> 16) & 0xFF)), when, e.tid, plan == 1 ? "commit" : "detach", v[0],
                v[1], v[2] & 0xFF, (v[2] >> 8) & 0xFF, v[3], v[11] >> 48,
                v[4] < static_cast<uint64_t>(msl::Judge::Count) ? msl::judge_name(static_cast<msl::Judge>(v[4])) : "?",
                outcome_name(v[5]), msl::post_name(static_cast<msl::Post>(v[6])), v[7], link_text(v[8]),
                link_text(v[9]), v[10] & 0xFFFFFFFF, v[10] >> 32, v[11] & 0xFF, (v[11] >> 8) & 0xFF,
                (v[11] >> 24) & 0xFF, (v[11] >> 32) & 0xFF, (v[11] >> 40) & 1 ? "yes" : "NO");
        }
        case kFallback:
        case kRiderAck:
            return std::format("MountSync {} {} T{} | remote 0x{:08X} 2991 A0 0x{:08X} A1 0x{:08X} parent {} target "
                               "0x{:08X} | ride kind {} | its Link here {} | txn {}{}",
                               e.kind == kFallback ? "FALLBACK" : "rider action", when, e.tid, v[0], v[1], v[2],
                               v[3] == ~0ull ? std::string("-1") : std::format("0x{:X}", v[3]), v[7],
                               rfl::kind_name(static_cast<rfl::Kind>(v[4])), link_text(v[5]), phase_text(v[6]),
                               e.kind == kFallback
                                   ? (!v[8]  ? " -> rewrite FAILED"
                                      : v[9] ? " -> rewritten as ride_filter would (fix B not ready any more: "
                                               "the copy would stay in RideOff)"
                                             : " -> rewritten as ride_filter would (no link)")
                                   : "");
        case kGate:
            return std::format(
                "MountSync gate [fix B] {} T{} | 0x2329A90 from exe+0x8639CD (a received action) | remote 0x{:08X} new "
                "A0 0x{:08X} A1 0x{:08X} | method {} | current L0 0x{:08X} flags 0x{:02X} L1 0x{:08X} flags 0x{:02X} | "
                "pending 0x40 {} CC+0xA8 {} | actor+0x96 {} C8 {} | new 0x40 {} +0x52 {} +0x51 bit 3 {} | RideOff "
                "+0xD4 0x{:08X} | -> {} (unlocks so far {})",
                when, e.tid, v[0], v[1], v[2], v[3], v[4] >> 32, v[5] & 0xFF, v[4] & 0xFFFFFFFF, (v[5] >> 8) & 0xFF,
                (v[5] >> 16) & 1, (v[5] >> 24) & 0xFF, (v[5] >> 32) & 0xFF, (v[5] >> 48) & 0xFF, (v[5] >> 40) & 1,
                (v[5] >> 41) & 1, (v[5] >> 42) & 1, v[6],
                e.flags < static_cast<uint16_t>(msl::GateVerdict::Count)
                    ? msl::gate_verdict_name(static_cast<msl::GateVerdict>(e.flags))
                    : "?",
                v[7]);
        case kProbe:
            return std::format(
                "MountSync gate probe {} T{} | remote 0x{:08X} 2991 A0 0x{:08X} A1 0x{:08X} | before: method {} L0 "
                "0x{:08X} def+0xA 0x{:02X} L1 0x{:08X} def+0xA 0x{:02X} pending 0x40 {} CC+0xA8 {} RideOff +0xD4 "
                "0x{:08X} | actor+0x96 remote {} local {} | after: method {} L0 0x{:08X} L1 0x{:08X} CC+0xA8 {} | {}",
                when, e.tid, v[0], v[1] >> 32, v[1] & 0xFFFFFFFF, v[2] & 0xFF, v[3] >> 32, v[4] & 0xFF,
                v[3] & 0xFFFFFFFF, (v[4] >> 8) & 0xFF, (v[2] >> 48) & 1, (v[2] >> 16) & 0xFF, v[6], (v[2] >> 32) & 0xFF,
                (v[2] >> 40) & 0xFF, (v[2] >> 8) & 0xFF, v[5] >> 32, v[5] & 0xFFFFFFFF, (v[2] >> 24) & 0xFF,
                e.flags == 1   ? "in RideOff with a 0x40 action: REJECTED (dropped by the gate)"
                : e.flags == 2 ? "in RideOff with a 0x40 action: taken"
                : e.flags == 3 ? "in RideOff with a 0x40 action: UNLOCKED by fix B"
                               : "the gate's view of the rider changed");
        case kLearn:
            return std::format("MountSync gate {} T{} | 0x{:08X} ({}) layer {} action 0x{:08X} def+0xA 0x{:02X}: a 0x40 "
                               "(get off the vehicle) action, LEARNED for ride_dismount=partial",
                               when, e.tid, v[0], e.flags == 2 ? "local player, its RideOff::Enter" : "remote rider",
                               v[3], v[1], v[2]);
        case kGateDegraded:
            return std::format("MountSync gate [fix B] {} T{} | remote 0x{:08X}: {} network actions in a row dropped by "
                               "the gate without an unlock (last verdict: {}) -> DEGRADED: ride_filter rewrites the "
                               "dismount actions again (as S17); the detour still tries to unlock",
                               when, e.tid, v[0], v[1],
                               v[2] < static_cast<uint64_t>(msl::GateVerdict::Count)
                                   ? msl::gate_verdict_name(static_cast<msl::GateVerdict>(v[2]))
                                   : "?");
        case kSelfReq:
            return std::format("MountSync self-check {} | this client {} a StartActionReq 2223 for the remote {} "
                               "0x{:08X} ({}): an observer must never request actions of the other player's {} (count "
                               "{}) - abort criterion; fix B DEGRADED from now on (ride_filter rewrites new dismounts, the "
                               "detour only frees an already stuck rider)",
                               when, (e.flags & 2) ? "tried to send" : "SENT", (e.flags & 1) ? "horse" : "rider", v[0],
                               (e.flags & 2) ? "guest_send, WITHHELD: not sent to the host" : "C>S",
                               (e.flags & 1) ? "horse" : "rider", v[1]);
        case kSeat: {
            const auto why = static_cast<msl::SeatWhy>((v[2] >> 8) & 0xFF);
            const auto sp = static_cast<msl::SeatPost>((v[2] >> 16) & 0xFF);
            const std::string head = std::format(
                "MountSeat [{}] {} T{} | 0x{:08X} on 0x{:08X} seat {} (vf53 {}, transition {})",
                msl::mode_name(static_cast<Mode>((v[2] >> 32) & 0xFF)), when, e.tid, v[0], v[1], v[2] & 0xFF,
                outcome_name((v[2] >> 24) & 0xFF), v[9]);
            const std::string types =
                std::format("rider type {} horse type {} | hierarchy type {} -> {}, rider+0x94 {}, horse CC {} | rider "
                            "vf178 exe+0x{:X} -> {} (its +0xA0 {} the local user) | C8 rider {} horse {}",
                            (v[4] >> 32) & 0xFF, (v[4] >> 40) & 0xFF, v[10] & 0xFF, (v[10] >> 8) & 0xFF,
                            (v[10] >> 16) & 0xFF, (v[10] >> 24) & 1 ? "yes" : "no", v[10] >> 32,
                            (v[10] >> 25) & 1 ? "LOCAL USER" : "not the local user", v[11] & 1 ? "IS" : "is not",
                            (v[11] >> 8) & 0xFF, (v[11] >> 16) & 0xFF);
            const auto parent = [](uint64_t key, bool ok) {
                return ok ? std::format("0x{:08X}", static_cast<uint32_t>(key)) : std::string("?");
            };
            if (e.flags == kSeatSeated || e.flags == kSeatFailed || e.flags == kSeatFault) {
                return std::format(
                    "{}: vf54 0xA45760(vc=0x{:X},&res,rider=0x{:X},{}) -> *res 0x{:08X} | attach type {} -> {}, hierarchy "
                    "parent {} -> {}, CC+0x228 {} -> {} | {} | {} us | {}",
                    head, v[6], v[7], v[2] & 0xFF, v[3], v[4] & 0xFF, (v[4] >> 8) & 0xFF,
                    parent(v[5], (v[4] >> 48) & 1), parent(v[5] >> 32, (v[4] >> 49) & 1), (v[4] >> 16) & 0xFF,
                    (v[4] >> 24) & 0xFF, types, v[8],
                    e.flags == kSeatSeated ? "SEATED"
                    : e.flags == kSeatFault
                        ? "FAULT (passed on to the game; native calls OFF)"
                        : std::format("FAILED ({}): no more vf54 calls this session", msl::seat_post_name(sp)));
            }
            return std::format("{}: {} | attach type {}, hierarchy parent {}, CC+0x228 {} | {}", head,
                               e.flags == kSeatAlready ? std::string("already seated here (attach type 4 under this horse)")
                               : e.flags == kSeatProbe
                                   ? std::format("probe: would call vf54 0xA45760(vc=0x{:X},&res,rider=0x{:X},{})", v[6],
                                                 v[7], v[2] & 0xFF)
                                   : std::format("REFUSED ({})", msl::seat_why_name(why)),
                               v[4] & 0xFF, parent(v[5], (v[4] >> 48) & 1), (v[4] >> 16) & 0xFF, types);
        }
        case kSeatRelease: {
            const auto cause = static_cast<msl::SeatCause>(v[2]);
            const std::string after = v[3] == ~0ull ? std::string("with no dismount seen")
                                                    : std::format("{} ms after {}", v[3], msl::seat_cause_name(cause));
            switch (static_cast<msl::SeatRel>(e.flags)) {
                case msl::SeatRel::Released:
                    return std::format("MountSeat release {} T{} | 0x{:08X} off 0x{:08X}: attach type 4 -> {} {} ({} ms "
                                       "seated) | Link {} method {}",
                                       when, e.tid, v[0], v[1], v[5], after, v[4], link_text(v[6]), v[7]);
                case msl::SeatRel::Retire:
                    return std::format(
                        "MountSeat release {} T{} | 0x{:08X} still seated on 0x{:08X} {} and its Link still names the horse: "
                        "0x2228E40(&res, horse, &key, p4 0, flag {}) once -> {} (post {}) *res 0x{:08X} | Link {} -> {}",
                        when, e.tid, v[0], v[1], after, msl::kClientDetachFlag, outcome_name(v[8] & 0xFF),
                        msl::post_name(static_cast<msl::Post>((v[8] >> 8) & 0xFF)), v[9], link_text(v[6]),
                        link_text(v[10]));
                case msl::SeatRel::Stuck:
                    return std::format("MountSeat STUCK SEATED {} T{} | 0x{:08X} on 0x{:08X}: attach type still 4 {} | "
                                       "Link {} method {} | nothing called (0xA65960 is not used in this version)",
                                       when, e.tid, v[0], v[1], after, link_text(v[6]), v[7]);
                case msl::SeatRel::Lost:
                    return std::format("MountSeat release {} T{} | 0x{:08X} on 0x{:08X}: the rider is unreadable here "
                                       "(its actor is gone) or no longer the remote player: no longer watched",
                                       when, e.tid, v[0], v[1]);
                case msl::SeatRel::None: break;
            }
            return std::format("MountSeat release {} ?", when);
        }
        case kCancel:
            return std::format("MountSync {} T{} | {} transaction(s) cancelled ({}): the old behaviour (ride_filter) "
                               "for them",
                               when, e.tid, v[0],
                               v[1] == 1   ? "timeout: no Commit in 500 ms / not applied in 3 s"
                               : v[1] == 2 ? "the guest's held stream reached its bound"
                               : v[1] == 3 ? "user 2's held Req reached their bound"
                                           : "a new connection");
        case kRelink:
            return std::format(
                "MountSync RELINK{} [{}] {} T{} | rider 0x{:08X} horse 0x{:08X} transition {} | its link applied here "
                "was retired by the game before its RideOn (Link+0x10 now 0x{:08X}), {} ms after the Commit | at its "
                "own pre-mount 2991 A0 0x{:08X} A1 0x{:08X} parent {} target 0x{:08X} (its horse): {} (claim {}, "
                "relink {} of this mount){}",
                e.flags == 1 ? " (probe: would relink)" : "", v[10], when, e.tid, v[0], v[1], v[2], v[9], v[5],
                v[6] >> 32, v[6] & 0xFFFFFFFF, v[7] == ~0ull ? std::string("-1") : std::format("0x{:X}", v[7]), v[8],
                e.flags == 1 ? "mount_relink=probe: NOTHING called, the next MountApply line shows the pair as found"
                             : "vf53 + vf54 again before this action's handler",
                v[3], v[4], v[10] == kRelinkLines ? " | further ones are only counted" : "");
        case kPeerStatus:
            return std::format(
                "MountSync: the other PC publishes NO mount (its controller's 0x2228260 hook is not installed; Status "
                "from 0x{:08X}, nonce 0x{:08X}, connection {}): the other player's mounts will not be seated here (its "
                "rider is shown off the saddle, as before session 21) {}",
                v[0], v[1], v[2], when);
    }
    return std::format("MountSync event {} {}", e.kind, when);
}

void drain() {
    p8p::Event e;
    while (g_diag.pop(e)) {
        if (g_lines.load() >= kMaxLines) {
            g_lines_dropped.fetch_add(1);
            continue;
        }
        g_lines.fetch_add(1);
        if ((e.kind == kSeatRelease && e.flags == static_cast<uint16_t>(msl::SeatRel::Stuck)) ||
            e.kind == kPeerStatus) {
            log::error("{}", line_of(e));
        } else if (e.kind == kSelfReq || (e.kind == kSeat && (e.flags == kSeatFailed || e.flags == kSeatFault))) {
            log::warn("{}", line_of(e));
        } else {
            log::info("{}", line_of(e));
        }
    }
}

void expire_tick() {
    AcquireSRWLockExclusive(&g_lock);
    const size_t n = g_table.expire(now_ms());
    g_has_work.store(g_table.has_work(), std::memory_order_relaxed);
    const msl::Txn* cur = g_table.find(remote_key());
    publish_phase(cur);
    ReleaseSRWLockExclusive(&g_lock);
    if (n) {
        c_cancel.fetch_add(n);
        p8p::Event e;
        e.v[0] = n;
        e.v[1] = 1;
        diag(kCancel, e);
    }
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    std::vector<gad::Section> secs;
    if ((!game::legacy_layout() && game::current_build() != game::Build::v3576 &&
         game::current_build() != game::Build::v3663) ||
        !p8_exe_sections(g_base, secs)) {
        log::error("MountSync: unsupported game build or unreadable sections; nothing installed");
        return 0;
    }
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other P8 modules
        uintptr_t world = 0;
        if (game::safe_read(world_slot(), &world, sizeof world) && world) break;
        Sleep(500);
    }
    g_vf53 = reinterpret_cast<Vf53Fn>(g_base + addrs().common_vf53);
    g_rideoff = reinterpret_cast<RideOffFn>(g_base + addrs().rideoff_thunk);
    const Point pts[] = {
        {addrs().common_vf53, 7, kEntry7, sizeof kEntry7, "CommonVehicle::vf53 0x2228260 (MountBegin/MountCommit)"},
        {addrs().client_vf53, 5, addrs().thunk_vf53, sizeof addrs().thunk_vf53, "the ClientVehicle vf53 thunk 0xA45740 (jmp 0x9DC90A0)"},
        {addrs().rideoff_thunk, 5, addrs().thunk_rideoff, sizeof addrs().thunk_rideoff, "the CommonVehicle RideOff thunk 0x2228E40 (MountDetach)"},
        {addrs().client_vf54, 5, kVf54, sizeof kVf54, "ClientVehicle vf54 0xA45760"},
        {addrs().ride_on, 7, kRideEnter, sizeof kRideEnter, "RideOn::Enter 0x681C80"},
        {addrs().ride_off, 7, kRideEnter, sizeof kRideEnter, "RideOff::Enter 0x682C20"},
        {addrs().h2663, 5, kHandler, sizeof kHandler, "the 2663 InteractionPreemptionStepSuccessAck handler 0xBB4130"},
        {addrs().h2916, 5, kHandler, sizeof kHandler, "the 2916 InteractionDoStepSuccessAck handler 0xBB4AC0"},
        {addrs().h2991, 5, kHandler, sizeof kHandler, "the 2991 StartActionAck handler 0xB57720 (apply point)"},
    };
    void* detours[] = {reinterpret_cast<void*>(&common_detour),  reinterpret_cast<void*>(&thunk_detour),
                       reinterpret_cast<void*>(&rideoff_detour), reinterpret_cast<void*>(&vf54_detour),
                       reinterpret_cast<void*>(&enter_on_detour), reinterpret_cast<void*>(&enter_off_detour),
                       reinterpret_cast<void*>(&h2663_detour),   reinterpret_cast<void*>(&h2916_detour),
                       reinterpret_cast<void*>(&h2991_detour)};
    std::atomic<bool>* ons[] = {&g_on_common, &g_on_thunk, &g_on_rideoff, &g_on_vf54, &g_on_enter_on,
                                &g_on_enter_off, &g_on_2663, &g_on_2916, &g_on_2991};
    SafetyHookInline* order[] = {&g_h_common, &g_h_thunk, &g_h_rideoff, &g_h_vf54, &g_h_on,
                                 &g_h_off,    &g_h_2663,  &g_h_2916,    &g_h_2991};
    std::string summary;
    // The thunk only with the Common hook (it only marks the client call for it).
    for (size_t i = 0; i < std::size(pts); ++i) {
        if (i == 1 && !g_on_common.load()) {
            summary += std::format("{}{} SKIPPED (needs 0x2228260)", summary.empty() ? "" : ", ", pts[i].what);
            continue;
        }
        const bool ok = install_one(secs, pts[i], detours[i], *order[i], *ons[i], g_mark[i]);
        // The names carry 2976's addresses; the address actually used is this build's (exe+...).
        summary += std::format("{}{} [this build: exe+0x{:X}] {}", summary.empty() ? "" : ", ", pts[i].what, pts[i].rva,
                               ok ? "hooked" : "REFUSED");
    }
    // P8 S18 fix B: only with mount_sync=1 and ride_dismount=native; the call site and the network mark verified too.
    std::string gate_text;
    if (mode() == Mode::On && ride_dismount_mode() == rfl::Dismount::Native) {
        if (!bytes_at(addrs().gate_site, addrs().gate_site_bytes, sizeof addrs().gate_site_bytes) ||
            !bytes_at(addrs().gate_or, kGateNetOrBytes, sizeof kGateNetOrBytes)) {
            log::error("MountSync: the 0x863880 call site (exe+0x8639C0) or the network mark (exe+0x1EC9C26) is not build "
                       "2976's; the gate detour (fix B) is REFUSED, nothing written");
            gate_text = "gate detour 0x2329A90 REFUSED (context bytes)";
        } else {
            const Point gp{addrs().gate, 5, addrs().gate_head, addrs().gate_head_len,
                           "the CC request gate thunk 0x2329A90 (jmp 0xEE58A40; fix B)"};
            const bool ok = install_one(secs, gp, reinterpret_cast<void*>(&gate_detour), g_h_gate, g_on_gate, g_mark[9]);
            gate_text = std::format("{} {}", gp.what, ok ? "hooked" : "REFUSED");
        }
    } else {
        gate_text = std::format("gate detour 0x2329A90 not installed (ride_dismount={}, mount_sync={})",
                                rfl::dismount_name(ride_dismount_mode()), msl::mode_name(mode()));
    }
    summary += ", " + gate_text;
    // P8 S21 ride_hold_pos (probe or 1): the mode-2 movement update's entry, its bytes verified like every point.
    if (hold_mode() != Mode::Off) {
        const Point hp{addrs().hold, 7, kHoldEntry, sizeof kHoldEntry,
                       "the mode-2 movement update 0x88E6A0 (ride_hold_pos)"};
        const bool ok = install_one(secs, hp, reinterpret_cast<void*>(&hold_detour), g_h_hold, g_on_hold, g_mark[10]);
        summary += std::format(", {} {} ({})", hp.what, ok ? "hooked" : "REFUSED", msl::mode_name(hold_mode()));
    } else {
        summary += ", 0x88E6A0 not installed (ride_hold_pos=0)";
    }
    // P8 S23 mount_seat=1 only: the riding action request's entry (14 verified bytes, 5 patched).
    if (seat_mode() == Mode::On) {
        const Point ap{addrs().action_req, 5, kActionReqBytes, sizeof kActionReqBytes,
                       "the riding action request 0xA45AC0 (mount_seat: never for the other player's character)"};
        const bool ok = install_one(secs, ap, reinterpret_cast<void*>(&actreq_detour), g_h_actreq, g_on_actreq, g_mark[11]);
        summary += std::format(", {} {}", ap.what, ok ? "hooked" : "REFUSED");
    }
    g_code_ok.store(true, std::memory_order_release);
    const Mode m = mode();
    log::info("MountSync {} (mount_sync, {}): {} | controller: publishes MountBegin/MountCommit/MountDetach of its own "
              "character (tunnel control state 5, nonce 0x{:08X}){} | observer: {}",
              msl::mode_name(m), g_guest.load() ? "guest" : "host", summary, g_nonce,
              g_on_common.load() ? "" : " - NOT POSSIBLE without the 0x2228260 hook",
              m == Mode::On ? (g_on_2991.load() ? "holds the stream from a Begin until its Commit (<= 500 ms), replays "
                                                   "0x2228260 at the dispatch of the rider's next StartActionAck, checks "
                                                   "the postconditions, defers ride_filter for that transaction; "
                                                   "retires: native (wait for RideOff's own, fallback flag 0 after 2 s "
                                                   "outside 6/7) or S18 (first on-foot dispatch, flag 12) by ride_dismount"
                                                 : "NOTHING (no apply point: 0xB57720 refused)")
                            : "probe: logs what it would call, with the arguments; holds, calls and writes nothing");
    // P8 S26, mount_relink (review of bf255bb (1)): its stop conditions are this client's RideOn::Enter / RideOff::Enter
    // of the rider; without both hooks (or without the apply point) it is off, said once.
    if (relink_mode() != Mode::Off) {
        const bool hooks = g_on_enter_on.load() && g_on_enter_off.load() && g_on_2991.load();
        if (!hooks) {
            log::warn("MountSync: mount_relink={} is OFF: it needs RideOn::Enter 0x681C80, RideOff::Enter 0x682C20 and "
                      "the 2991 handler 0xB57720 hooked (its stop conditions and its apply point)",
                      msl::mode_name(relink_mode()));
            g_relink_mode.store(static_cast<uint8_t>(Mode::Off), std::memory_order_release);
        }
        AcquireSRWLockExclusive(&g_lock);
        g_table.set_relink(relink_mode());
        ReleaseSRWLockExclusive(&g_lock);
    }
    // P8 S26 (montura-regresion.md section 7.1): without 0x2228260 this PC publishes none of its own mounts.
    g_ctl_no_publish.store(!g_on_common.load());
    if (g_ctl_no_publish.load()) {
        log::error("MountSync: this PC's CommonVehicle::vf53 0x2228260 is NOT hooked: none of its own mounts is "
                   "published, so the other PC will show this character OFF THE SADDLE on every horse (as before "
                   "session 21). The other PC is told (Status every {} s) and the overlay says so",
                   msl::kStatusEveryMs / 1000);
    }
    uint64_t last_summary = now_ms(), last_status = 0;
    for (;;) {
        Sleep(100);
        try {
            expire_tick();
            drain();
            const uint64_t now = now_ms();
            if (g_ctl_no_publish.load() && (!last_status || now - last_status >= msl::kStatusEveryMs)) {
                last_status = now;
                publish(msl::status_event(g_local_key.load(), g_nonce, now, true));
                c_status_sent.fetch_add(1, std::memory_order_relaxed);
            }
            if (now - last_summary >= 60000) {
                last_summary = now;
                log::info("{}", mount_sync_describe());
                if (g_ctl_no_publish.load()) {
                    log::error("MountSync: this PC still publishes NO mount (0x2228260 not hooked; Status sent {})",
                               c_status_sent.load());
                }
            }
        } catch (...) {
        }
    }
}

}  // namespace

// ---------------------------------------------------------------- public

void mount_sync_start(const std::string& raw, bool guest, const std::string& seat_raw, const std::string& hold_raw,
                      const std::string& relink_raw) {
    const auto p = msl::parse_mode(raw);
    if (!p.known) {
        log::warn("MountSync: mount_sync='{}' is not 0, probe or 1; it stays off", raw);
        return;
    }
    // P8 S21 (§13): mount_seat acts only with mount_sync=1 (it needs the observer's vf53); ride_hold_pos is installed
    // with mount_sync and writes only with mount_sync=1 (probe otherwise).
    const auto ps = msl::parse_mode(seat_raw), ph = msl::parse_mode(hold_raw);
    if (p.mode == Mode::Off) {
        if (ps.mode != Mode::Off || ph.mode != Mode::Off) {
            log::info("MountSync: mount_seat='{}' ride_hold_pos='{}' ignored: mount_sync=0", seat_raw, hold_raw);
        }
        return;
    }
    if (!ps.known) log::warn("MountSync: mount_seat='{}' is not 0, probe or 1; it stays off", seat_raw);
    if (!ph.known) log::warn("MountSync: ride_hold_pos='{}' is not 0, probe or 1; it stays off", hold_raw);
    const Mode seat = !ps.known || p.mode != Mode::On ? Mode::Off : ps.mode;
    const Mode hold = !ph.known ? Mode::Off : (ph.mode == Mode::On && p.mode != Mode::On) ? Mode::Probe : ph.mode;
    g_seat_mode.store(static_cast<uint8_t>(seat));
    // P8 S26 (montura-regresion.md sections 7.2 and 10.2): mount_relink acts only with mount_sync=1 (probe otherwise).
    const auto pr = msl::parse_mode(relink_raw);
    if (!pr.known) log::warn("MountSync: mount_relink='{}' is not 0, probe or 1; it stays off", relink_raw);
    const Mode relink = !pr.known ? Mode::Off : (pr.mode == Mode::On && p.mode != Mode::On) ? Mode::Probe : pr.mode;
    g_relink_mode.store(static_cast<uint8_t>(relink), std::memory_order_release);
    log::info("MountSync: mount_relink={}{}", msl::mode_name(relink),
              relink == Mode::On ? ": a link the game retires before the remote rider's RideOn is applied again (vf53 + "
                                   "vf54) at its next pre-mount action (parent -1, target its horse); a failure stays "
                                   "with that mount"
              : relink == Mode::Probe ? ": 'MountSync RELINK (probe: would relink)' once per mount, nothing called"
                                      : "");
    g_hold_mode.store(static_cast<uint8_t>(hold));
    log::info("MountSync: mount_seat={}{} | ride_hold_pos={}{}", msl::mode_name(seat),
              ps.known && ps.mode != Mode::Off && seat == Mode::Off ? " (asked for, but only with mount_sync=1)"
              : seat == Mode::On   ? ": vf54 0xA45760 seats the remote rider after the observer's vf53, release watched"
              : seat == Mode::Probe ? ": judged and logged ('would call vf54'), nothing called"
                                    : "",
              msl::mode_name(hold),
              ph.known && ph.mode == Mode::On && hold == Mode::Probe ? " (1 asked for: probe without mount_sync=1)"
              : hold == Mode::On   ? ": the remote player's empty-buffer pose at 0x88E6A0 is its current TransformSync"
              : hold == Mode::Probe ? ": 0x88E6A0's early returns counted, nothing written"
                                    : "");
    g_guest.store(guest);
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    g_nonce = static_cast<uint32_t>(q.QuadPart ^ (q.QuadPart >> 32) ^ GetCurrentProcessId() ^ GetTickCount());
    if (!g_nonce) g_nonce = 1;
    g_mode.store(static_cast<uint8_t>(p.mode));
    // P8 S18 (nativo §5): with ride_dismount native / partial the dismount reaches this client natively (RideOff or
    // the first unmounted action retires the link here): wait for that, fallback flag 0 outside 6/7.
    const rfl::Dismount d = ride_dismount_mode();
    g_native_policy.store(d != rfl::Dismount::Rewrite);
    g_seat.set_retire(d != rfl::Dismount::Rewrite);  // S21 review: the seat watch retires only under the native policy
    g_table.set_policy(d != rfl::Dismount::Rewrite ? msl::DetachPolicy::Native : msl::DetachPolicy::S18);
    log::info("MountSync: mount_sync={} on the {} (installing once the world exists) | ride_dismount={}: {}",
              msl::mode_name(p.mode), guest ? "guest" : "host", rfl::dismount_name(d),
              d == rfl::Dismount::Native    ? "fix B (the gate detour 0x2329A90 with mount_sync=1), native retirement"
              : d == rfl::Dismount::Partial ? "fix A (ride_filter rewrites only the 0x40 dismount actions), native retirement"
                                            : "every dismount rewritten (S17), retirement at the first on-foot dispatch");
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

bool mount_sync_active() { return mode() != Mode::Off; }
uintptr_t mount_sync_find_actor(uint32_t key) noexcept { return find_actor(key); }
bool mount_sync_live() { return mode() == Mode::On; }
bool mount_sync_rides(uint32_t key) noexcept {
    if (!key || mode() == Mode::Off) return false;
    if (msl::arm_horse(g_ctl_arm.load(std::memory_order_acquire)) == key) return true;
    if (g_remote_parent.load(std::memory_order_relaxed) == key) return true;
    return g_remote_mounted.load(std::memory_order_relaxed) && g_remote_horse.load(std::memory_order_relaxed) == key;
}

std::string mount_sync_hud_problem() {
    if (mode() == Mode::Off) return {};
    if (g_ctl_no_publish.load(std::memory_order_relaxed)) {
        return "Mounts: this PC does not publish its own (hook 0x2228260 not installed): the other player will see you "
               "out of the saddle";
    }
    const uint64_t peer = g_peer_no_publish_ms.load(std::memory_order_relaxed);
    if (peer && now_ms() - peer < msl::kStatusShowMs) {
        return "Mounts: the other PC does not publish its own: its rider will not sit on your screen";
    }
    return {};
}

void mount_sync_set_local_key(uint32_t key) noexcept {
    if (msl::is_char(key)) g_local_key.store(key, std::memory_order_relaxed);
}
void mount_sync_set_remote_key(uint32_t key) noexcept {
    if (msl::is_char(key)) g_remote_key.store(key, std::memory_order_relaxed);
}

bool mount_sync_on_frame(std::span<const uint8_t> frame, uint64_t epoch) noexcept {
    if (!msl::is_frame(frame)) return false;
    if (mode() == Mode::Off) return true;  // ours, ignored
    const auto ev = msl::decode(frame.subspan(msl::kHeader));
    p8p::Event e;
    if (!ev) {
        e.v[4] = static_cast<uint64_t>(msl::Accept::Count);
        diag(kObs, e);
        return true;
    }
    if (ev->kind == msl::EvKind::Status) {
        // P8 S26 (montura-regresion.md section 7.1): the other PC's controller publishes no mount (its 0x2228260 hook
        // is not installed): its rider will not be seated here. One line per connection, the overlay while it lasts.
        c_status_recv.fetch_add(1, std::memory_order_relaxed);
        const bool no_publish = (ev->flags & msl::kFlagNoPublish) != 0;
        g_peer_no_publish_ms.store(no_publish ? now_ms() : 0, std::memory_order_relaxed);
        AcquireSRWLockExclusive(&g_lock);
        const bool first = g_peer_status_epoch != epoch;
        g_peer_status_epoch = epoch;
        ReleaseSRWLockExclusive(&g_lock);
        if (first && no_publish) {
            e.v[0] = ev->rider;
            e.v[1] = ev->nonce;
            e.v[2] = epoch;
            diag(kPeerStatus, e);
        }
        return true;
    }
    const uint32_t remote = remote_key();
    AcquireSRWLockExclusive(&g_lock);
    if (epoch != g_table_epoch) {
        if (g_table_epoch) c_epoch_reset.fetch_add(1, std::memory_order_relaxed);
        g_table.reset();
        g_table_epoch = epoch;
    }
    const msl::Accept a = g_table.on_event(*ev, now_ms(), remote);
    g_has_work.store(g_table.has_work(), std::memory_order_relaxed);
    const msl::Txn* cur = g_table.find(remote);
    publish_phase(cur);
    ReleaseSRWLockExclusive(&g_lock);
    c_accept[static_cast<size_t>(a)].fetch_add(1, std::memory_order_relaxed);
    e.v[0] = static_cast<uint64_t>(ev->kind);
    e.v[1] = ev->rider;
    e.v[2] = ev->horse;
    e.v[3] = ev->transition;
    e.v[4] = static_cast<uint64_t>(a);
    e.v[5] = ev->seat | (static_cast<uint64_t>(ev->fifth) << 8) | (static_cast<uint64_t>(ev->flags) << 16);
    e.v[6] = ev->result;
    e.v[7] = ev->nonce;
    e.v[8] = ev->tick_ms;
    e.v[9] = epoch;
    e.v[10] = ev->caller_rva;
    e.v[11] = ev->aux;
    diag(kObs, e);
    return true;
}

bool mount_sync_pop_outbound(std::vector<uint8_t>& frame) noexcept {
    p8p::Event e;
    if (!g_out.pop(e)) return false;
    msl::Event ev;
    ev.kind = static_cast<msl::EvKind>(e.kind);
    ev.seat = static_cast<uint8_t>(e.flags);
    ev.fifth = static_cast<uint8_t>(e.flags >> 8);
    ev.rider = static_cast<uint32_t>(e.v[0]);
    ev.horse = static_cast<uint32_t>(e.v[1]);
    ev.transition = static_cast<uint32_t>(e.v[2]);
    ev.result = static_cast<uint32_t>(e.v[3]);
    ev.caller_rva = static_cast<uint32_t>(e.v[4]);
    ev.aux = static_cast<uint32_t>(e.v[5]);
    ev.flags = static_cast<uint8_t>(e.v[6]);
    ev.tick_ms = e.v[7];
    ev.nonce = g_nonce;
    try {
        frame = msl::frame(ev);
    } catch (...) {
        return false;
    }
    return true;
}

namespace {
bool holding_now() noexcept {
    if (mode() != Mode::On) return false;
    AcquireSRWLockShared(&g_lock);  // review (5): a reader
    const bool h = g_table.holding(now_ms());
    ReleaseSRWLockShared(&g_lock);
    return h;
}
}  // namespace

bool mount_sync_guest_holding() noexcept { return holding_now(); }

bool mount_sync_host_holding(size_t queued) noexcept {
    if (mode() != Mode::On) return false;
    if (queued >= msl::kHoldMaxReq) {
        if (holding_now()) mount_sync_cancel_holds("host");
        return false;
    }
    return holding_now();
}

void mount_sync_cancel_holds(const char* why) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    const size_t n = g_table.cancel_holds();
    g_has_work.store(g_table.has_work(), std::memory_order_relaxed);
    ReleaseSRWLockExclusive(&g_lock);
    if (!n) return;
    c_cancel.fetch_add(n, std::memory_order_relaxed);
    p8p::Event e;
    e.v[0] = n;
    e.v[1] = (why && why[0] == 'h') ? 3 : 2;
    diag(kCancel, e);
}

void mount_sync_reset(const char* why) noexcept {
    if (mode() == Mode::Off) return;
    AcquireSRWLockExclusive(&g_lock);
    g_table.reset();
    g_has_work.store(false, std::memory_order_relaxed);
    publish_phase(nullptr);
    ReleaseSRWLockExclusive(&g_lock);
    g_remote_mounted.store(false, std::memory_order_relaxed);
    g_remote_parent.store(0, std::memory_order_relaxed);
    g_rideoff_seen.store(0, std::memory_order_relaxed);
    // §12, guest: the host's character key is forgotten with the remote session. A save loaded afterwards on this PC's
    // own server may give this client's OWN character the same key (0xA0100001: the first user of any server), which
    // must never be taken for the remote rider (the dispatch fallback would rewrite its own actions). guest.cpp only
    // learns it again from the host's control state 4 while playing on the host.
    if (g_guest.load(std::memory_order_relaxed)) g_remote_key.store(0, std::memory_order_relaxed);
    c_epoch_reset.fetch_add(1, std::memory_order_relaxed);
    try {
        log::info("MountSync: the observer's transactions cleared ({}); a link this client applied stays with its "
                  "actors",
                  why ? why : "?");
    } catch (...) {
    }
}

void mount_sync_forget_local_key() noexcept {
    // P8 re-entry (s25/reentrada.md §1.1 B9): this client's own character key on the host goes with the remote session
    // (the next remote conversation's MainPlayerDataStartAck 2756 sets it again); while it plays locally its rider
    // publishes nothing to the host. Guest only (the host learns its own key from its user every second).
    if (mode() == Mode::Off || !g_guest.load(std::memory_order_relaxed)) return;
    g_local_key.store(0, std::memory_order_relaxed);
}

void mount_sync_note_hold(bool host, size_t released) noexcept {    if (released == 0) {
        (host ? c_hold_host : c_hold_guest).fetch_add(1, std::memory_order_relaxed);
    } else {
        (host ? c_rel_host : c_rel_guest).fetch_add(released, std::memory_order_relaxed);
    }
}

bool mount_sync_gate_ready() noexcept {
    return mode() == Mode::On && g_on_gate.load(std::memory_order_acquire) && !g_gate_off.load(std::memory_order_relaxed) &&
           !g_gate_degraded.load(std::memory_order_relaxed);
}

namespace {
// The self-check of one C>S packet of this client (msl::self_check_hit): counted, fix B degraded at the first one, a line.
// `withheld`: the guest (mode 1) does not forward it to the host. True: it named the remote rider or its horse.
bool self_check(const uint8_t* packet, size_t size, bool withheld) noexcept {
    if (mode() == Mode::Off) return false;
    const uint8_t hit = msl::self_check_hit(packet, size, remote_key(), g_remote_horse.load(std::memory_order_relaxed));
    if (!hit) return false;
    const bool is_horse = hit == 2;
    const uint64_t n = (is_horse ? c_self_req_horse : c_self_req_rider).fetch_add(1, std::memory_order_relaxed) + 1;
    if (withheld) c_self_req_withheld.fetch_add(1, std::memory_order_relaxed);
    // Review (4): not only detected: fix B reacts at the first one (ride_filter rewrites the dismounts again).
    // Review of 458cf49 (2): degraded, not off - ride_filter rewrites every NEW dismount (no new RideOff here), while the
    // detour keeps freeing a rider already stuck in RideOff (off, it would stay stuck for ever). Only a fault turns the
    // detour fully off.
    if (!g_gate_degraded.exchange(true)) g_gate_off_why.store(2);
    if (c_self_req_rider.load() + c_self_req_horse.load() > kMaxSelfReqLines) return true;
    p8p::Event e;
    e.flags = static_cast<uint16_t>((is_horse ? 1 : 0) | (withheld ? 2 : 0));
    e.v[0] = msl::get32(packet + msl::kHeader);
    e.v[1] = n;
    diag(kSelfReq, e);
    return true;
}
}  // namespace

void mount_sync_sniffed(const uint8_t* packet, size_t size, bool server_to_client) noexcept {
    if (server_to_client) return;
    self_check(packet, size, false);
}

bool mount_sync_guest_outgoing(const uint8_t* packet, size_t size) noexcept {
    if (!g_guest.load(std::memory_order_relaxed)) return false;
    // Probe: counted and warned only (nothing of the stream changes); 1: also withheld.
    const bool live = mode() == Mode::On;
    return self_check(packet, size, live) && live;
}

bool mount_sync_ride_filter_defers(uint32_t key) noexcept {
    if (mode() != Mode::On || !g_code_ok.load(std::memory_order_acquire) || !g_on_2991.load()) return false;
    // Review (5): blocking (the lock is never held during a game call); a busy try-lock used to let a mount
    // action through without its link.
    AcquireSRWLockShared(&g_lock);
    const bool d = g_table.defers(key, now_ms());
    ReleaseSRWLockShared(&g_lock);
    if (d) c_defer.fetch_add(1, std::memory_order_relaxed);
    return d;
}

namespace {
// "seated here [...] | linked here [<1 m/s: n 12, local (+0.05,+1.56,+0.55) m, |off the seat| 10/2/0/0/0/0 max
// 0.31 m; ...] | NOT linked here [...]"
std::string geo_text() {
    static constexpr const char* kSpeed[msl::kGeoSpeeds] = {"<1", "1-3", "3-6", "6-10", ">=10"};
    static constexpr const char* kLink[msl::kGeoLinks] = {"NOT linked here", "linked here", "seated here"};
    std::string out;
    for (int l = static_cast<int>(msl::kGeoLinks) - 1; l >= 0; --l) {
        std::string part;
        for (size_t s = 0; s < msl::kGeoSpeeds; ++s) {
            const uint64_t n = g_geo.n[l][s].load(std::memory_order_relaxed);
            if (!n) continue;
            const double k = 1.0 / (1000.0 * static_cast<double>(n));
            std::string errs;
            for (size_t e = 0; e < msl::kGeoErrs; ++e) {
                errs += std::format("{}{}", e ? "/" : "", g_geo.err[l][s][e].load(std::memory_order_relaxed));
            }
            part += std::format("{}{} m/s: n {}, local ({:+.2f},{:+.2f},{:+.2f}) m, |off the seat| {} max {:.2f} m",
                                part.empty() ? "" : "; ", kSpeed[s], n,
                                static_cast<double>(g_geo.sum_mm[l][s][0].load(std::memory_order_relaxed)) * k,
                                static_cast<double>(g_geo.sum_mm[l][s][1].load(std::memory_order_relaxed)) * k,
                                static_cast<double>(g_geo.sum_mm[l][s][2].load(std::memory_order_relaxed)) * k, errs,
                                g_geo.max_mm[l][s].load(std::memory_order_relaxed) / 1000.0);
        }
        out += std::format("{}{} [{}]", out.empty() ? "" : " | ", kLink[l], part.empty() ? "none" : part);
    }
    return std::format("{} | not counted: unreadable {}, > 10 m off {} | frozen (seated, rider < 1 cm while its horse > "
                       "0.5 m between two ticks) {}",
                       out, g_geo.unreadable.load(), g_geo.off_far.load(), g_geo.frozen.load());
}

// P8 S21: "| P8 S21 mount_seat 1: seat [...] | ride_hold_pos 1 (hooked): hold [...]"
// P8 S22: the judge's "local user" test on this client's own character, which must answer yes (vf178 0x4FE260, its
// +0xA0 the local user, +0x94 1): the same reads that must answer no for the other player's character.
std::string local_user_selftest() {
    // Without a peer the host learns its key only with the tunnel (push_host_character): its first character then.
    const uint32_t known = g_local_key.load(std::memory_order_relaxed);
    const uint32_t lk = known ? known : 0xA0100001u;
    const uintptr_t me = find_actor(lk);
    if (!me) return " | local-user self-test: the local character not found yet";
    const msl::SeatState s = read_seat(me, 0);
    // S23 review: a positive proof (every read made and matching), not the judge's fail-closed answer.
    const bool proven = s.vf178 == msl::kVf178Actor && s.local_user && s.rider_user == s.local_user && s.rider_local != 0;
    return std::format(" | local-user self-test (0x{:08X}): vf178 exe+0x{:X}, +0xA0 {} the local user, +0x94 {} -> {}", lk,
                       s.vf178, s.rider_user && s.rider_user == s.local_user ? "IS" : "is NOT", s.rider_local,
                       proven ? "local user (ok)" : "NOT PROVEN (the reads disagree with 0x4FE260)");
}
// P8 S26 (montura-regresion.md sections 7.1 and 7.2): relinks, and whether each controller publishes.
std::string s26_text() {
    const uint64_t peer = g_peer_no_publish_ms.load();
    const uint64_t now = now_ms();
    return std::format(
        " | P8 S26: mount_relink {}: relinks {}, would relink (probe) {} (the link the game retired before the "
        "rider's RideOn, applied again) | this PC's mounts published: {} | the other PC's: {}",
        msl::mode_name(relink_mode()), c_relink.load(), c_relink_probe.load(),
        g_ctl_no_publish.load() ? std::format("NO (0x2228260 not hooked; Status sent {})", c_status_sent.load())
                                : std::string("yes"),
        peer && now - peer < msl::kStatusShowMs
            ? std::format("NONE (its Status {} s ago; received {})", (now - peer) / 1000, c_status_recv.load())
            : std::format("no Status saying otherwise (received {})", c_status_recv.load()));
}

std::string seat_hold_text() {
    return std::format(
        " | P8 S21 mount_seat {}{}: seat [seated {}, already {}, refused {}, failed {}, released {}, retired {}, stuck {}, "
        "RideOn::Enter of the remote rider NOT seated {} (must be 0), its riding action requests vetoed {} (expected "
        "0)]{} | ride_hold_pos {} ({}): hold [remote early returns {}, filled {}, unreadable {}, other 0xA early returns {}]",
        msl::mode_name(seat_mode()), g_seat_off.load() ? " (OFF after a failed seat)" : "", c_seat_seated.load(),
        c_seat_already.load(), c_seat_refused.load(), c_seat_failed.load(), c_seat_released.load(),
        c_seat_retired.load(), c_seat_stuck.load(), c_enter_unseated.load(), c_actreq_veto.load(),
        c_seat_probe.load() || c_seat_lost.load()
            ? std::format(" (would call {}, unreadable riders forgotten {})", c_seat_probe.load(), c_seat_lost.load())
            : std::string(),
        msl::mode_name(hold_mode()), g_on_hold.load() ? "hooked" : "not installed", c_hold_remote.load(),
        c_hold_filled.load(), c_hold_unreadable.load(), c_hold_other.load()) + local_user_selftest() + s26_text();
}
}  // namespace

static std::string gate_verdicts_text() {
    std::string s;
    for (size_t i = 1; i < static_cast<size_t>(msl::GateVerdict::Count); ++i) {  // NotNetwork: every chart call
        if (const uint64_t n = c_gate_verdict[i].load()) {
            s += std::format("{}{} {}", s.empty() ? "" : ", ", msl::gate_verdict_name(static_cast<msl::GateVerdict>(i)), n);
        }
    }
    return s.empty() ? std::string("none") : s;
}

std::string mount_sync_describe() {
    const Mode m = mode();
    if (m == Mode::Off) return {};
    std::string acc, jud, out;
    for (size_t i = 0; i < static_cast<size_t>(msl::Accept::Count); ++i) {
        if (const uint64_t n = c_accept[i].load()) acc += std::format("{}{} {}", acc.empty() ? "" : ", ", msl::accept_name(static_cast<msl::Accept>(i)), n);
    }
    for (size_t i = 0; i < static_cast<size_t>(msl::Judge::Count); ++i) {
        if (const uint64_t n = c_judge[i].load()) jud += std::format("{}{} {}", jud.empty() ? "" : ", ", msl::judge_name(static_cast<msl::Judge>(i)), n);
    }
    for (size_t i = 0; i < 6; ++i) {
        if (const uint64_t n = c_outcome[i].load()) out += std::format("{}{} {}", out.empty() ? "" : ", ", outcome_name(i), n);
    }
    return std::format(
        "MountSync summary [{}] ({}): hooks common {} thunk {} rideoff {} vf54 {} RideOn {} RideOff {} 2663 {} 2916 {} "
        "2991 {} | keys local 0x{:08X} remote 0x{:08X} | controller: vf53 {} (client {}, other thread {}, client "
        "without the thunk {}), RideOff {}, vf54 {}, interactions {} | published Begin {} Commit {} Detach {} (ring "
        "full {}) | Enter RideOn {} (failed {}) RideOff {} (failed {}) | observer events [{}] | judges [{}] | "
        "outcomes [{}] (post failures {}, detach ok {} failed {}) | ride_filter deferred {} (busy {}) | fallback "
        "rewrites {} (failed {}) | holds guest {} (released {}) host {} (released {}) | cancelled {} | connection "
        "resets {} | dispatches {} | game faults {}{} | lines {} (not logged {}, ring dropped {}, limited {}) | "
        "controller link watch: observed Detach published {} (reads {}, unreadable {}), armed now {} | observer "
        "retirements without the controller's Detach {} | ride geometry (the remote rider vs its horse here, "
        "TransformSync, |off the seat| buckets <=0.25/<=0.5/<=1/<=2/<=5/>5 m against the seat offset "
        "(+0.05,+1.56,+0.55) its controller sends): {} | P8 S18 ride_dismount {} (retirement policy {}): gate "
        "detour {}{} [{}] (would drop {}, +0x51 bit 3 seen {}) | remote rider 2991 in RideOff with a 0x40 action {}: "
        "rejected {} taken {} UNLOCKED {} | native retirement already done {} fallback {} forgotten (rider unreadable "
        "15 s) {} | 0x40 hashes learned {} | "
        "self-check: this client's StartActionReq 2223 for the remote rider {} horse {} (must be 0; withheld {})",
        msl::mode_name(m), g_guest.load() ? "guest" : "host", g_on_common.load(), g_on_thunk.load(), g_on_rideoff.load(),
        g_on_vf54.load(), g_on_enter_on.load(), g_on_enter_off.load(), g_on_2663.load(), g_on_2916.load(),
        g_on_2991.load(), g_local_key.load(), remote_key(), c_vf53.load(), c_vf53_client.load(), c_vf53_other.load(),
        c_vf53_direct.load(), c_rideoff.load(), c_vf54.load(), c_inter.load(), c_pub[1].load(), c_pub[2].load(),
        c_pub[3].load(), c_out_full.load(), c_enter_on.load(), c_enter_on_fail.load(), c_enter_off.load(),
        c_enter_off_fail.load(), acc.empty() ? "none" : acc, jud.empty() ? "none" : jud, out.empty() ? "none" : out,
        c_post_fail.load(), c_detach_ok.load(), c_detach_fail.load(), c_defer.load(), c_defer_busy.load(),
        c_fallback.load(), c_fallback_fail.load(), c_hold_guest.load(), c_rel_guest.load(), c_hold_host.load(),
        c_rel_host.load(), c_cancel.load(), c_epoch_reset.load(), c_dispatch.load(), c_faults.load(),
        g_apply_off.load() ? " (native calls OFF after a fault)" : "", g_lines.load(), g_lines_dropped.load(),
        g_diag.dropped(), g_limited.load(), c_ctl_observed.load(), c_ctl_watch_reads.load(),
        c_ctl_watch_unknown.load(),
        g_ctl_arm.load() ? std::format("0x{:08X} transition {}", msl::arm_horse(g_ctl_arm.load()),
                                       msl::arm_transition(g_ctl_arm.load()))
                         : std::string("no"),
        c_no_event.load(), geo_text(), rfl::dismount_name(ride_dismount_mode()),
        g_native_policy.load() ? "native" : "S18", g_on_gate.load() ? "hooked" : "not installed",
        g_gate_off.load()        ? " (OFF after an exception passed on)"
        : g_gate_degraded.load() ? (g_gate_off_why.load() == 2
                                        ? " (DEGRADED by the self-check (a 2223 for the remote rider/horse): ride_filter "
                                          "rewrites new dismounts; the detour only frees an already stuck rider)"
                                        : " (DEGRADED: ride_filter rewrites)")
                                 : "", gate_verdicts_text(), c_gate_drop.load(), c_gate_force_bit.load(),
        c_m7_2991.load(), c_m7_rejected.load(), c_m7_taken.load(), c_m7_unlocked.load(), c_native_gone.load(),
        c_native_fallback.load(), c_native_lost.load(), c_learned.load(), c_self_req_rider.load(), c_self_req_horse.load(),
        c_self_req_withheld.load()) + seat_hold_text();
}

}  // namespace cdmp::session2
