#pragma once
// P8 session 29, the tree bend of the grappling rope (docs/research/s25/gancho-cuerda.md section 14): the pure logic
// of tree_bend.cpp, with no game access, so the tests can run it. Builds 1.0.0.2976, 1.0.0.3527 and 1.0.0.3576 (the
// addresses named below are 2976's; 3527's and 3576's tables follow them).
//
// The bend of a pulled tree is client-local and input-driven (section 14.3 [V code]): the client script's
// pa::gameClientScript::RemoteCatchFunctions vf2 0x117F7E0 calls 0x1190FD0 every frame for the THROWER, which reads the
// thrower's own input ("Key_RemoteCatchTreePulling" / "RemoteCatch_ControlPosition_Pull") and the rope's stretch and
// calls TreeComponent::SetBend 0x349EA10 (its only caller) on the tree resolved from catch slot 0's scene id. No packet
// carries it. tree_bend publishes the thrower's SetBend values through the Troc tunnel (control state 15, both ways)
// and the observer replays them with the same natives at the remote thrower's RemoteCatch tick 0x59C0D0.
//
// [session2] tree_bend = 0 | probe | 1, on BOTH PCs (symmetric: each client is the thrower of its own character and
// the observer of the other player's):
//   probe: the four measurement points (M1 vf2, M2 0x1190FD0, M3 SetBend, M4 the tick), the thrower SENDS (nothing of
//          the game is touched by a frame) and the observer logs what it would apply.
//   1:     the same, and the observer applies (FUN_1405b1600 -> FUN_140491ac0 -> SetBend) after the tick's original.

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <optional>
#include <span>
#include <vector>

#include "mod/session2/user2_funnels_logic.h"

namespace cdmp::session2::tbl {

using u2f::Mode;
using u2f::mode_name;
using u2f::parse_mode;

inline bool player_key(uint32_t k) { return (k >> 28) == 0xA; }

// ---------------------------------------------------------------- build 1.0.0.2976 (section 14.4)

// M1: pa::gameClientScript::RemoteCatchFunctions vf2 (p1, float dt xmm1, actor r8, slot r9b, state [rsp+0x28]).
// Referenced only by its vtable slot 0x56FFB58 (and .pdata).
inline constexpr uintptr_t kVf2 = 0x117F7E0;
inline constexpr uint8_t kVf2Head[15] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C,
                                         0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x20};
inline constexpr uint32_t kVf2Patch = 5;  // mov [rsp+8],rbx
inline constexpr uintptr_t kVf2Slot = 0x56FFB58;
// M2: the bend's apply 0x1190FD0 (rcx unused, float dt xmm1, r8b f6==1, r9 actor, state [rsp+0x28]); one caller.
inline constexpr uintptr_t kApply = 0x1190FD0;
inline constexpr uint8_t kApplyHead[11] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x68, 0x18};
inline constexpr uint32_t kApplyPatch = 7;  // mov rax,rsp | mov [rax+0x10],rbx
inline constexpr uintptr_t kApplyCall = 0x117F911;  // in 0x117F7E0: call 0x1190FD0
inline constexpr uint8_t kApplyCallBytes[5] = {0xE8, 0xBA, 0x16, 0x01, 0x00};
// M3: TreeComponent::SetBend 0x349EA10 (tree rcx, const float dir[3] rdx, float amount xmm2); one caller.
inline constexpr uintptr_t kSetBend = 0x349EA10;
inline constexpr uint8_t kSetBendHead[10] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30};
inline constexpr uint32_t kSetBendPatch = 5;  // mov [rsp+8],rbx
inline constexpr uintptr_t kSetBendCall = 0x1191532;  // in 0x1190FD0: call SetBend (rdx = state+0x380, xmm2 = state+0x378)
inline constexpr uint8_t kSetBendCallBytes[5] = {0xE8, 0xD9, 0xD4, 0x30, 0x02};
// M4: the RemoteCatch tick 0x59C0D0 (comp rcx, float dt xmm1); rdx / r8 / r9 are written before any read. Reached
// by call 0x8A1697 (0x8A1640, the controlled actors' job) and jmp 0x8A5DA0 (the job 0x8A0FC0 schedules for an actor
// NOT controlled here while one of its slots is not idle).
inline constexpr uintptr_t kTick = 0x59C0D0;
inline constexpr uint8_t kTickHead[9] = {0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55};
inline constexpr uint32_t kTickBoundaries[] = {2, 3, 4, 5, 7, 9};
inline constexpr uint32_t kTickPatch[] = {5};  // push rbp | push rbx | push rsi | push rdi
inline constexpr uintptr_t kTickJump = 0x8A5DA0;
inline constexpr uint8_t kTickJumpBytes[5] = {0xE9, 0x2B, 0x63, 0xCF, 0xFF};
// The natives the observer calls in mode 1 (the ones 0x1190FD0 uses), checked by their first bytes:
//   FUN_1405b1600(catch comp, u8 slot) -> the scene object of the slot's target (by its scene id) or null;
//   FUN_140491ac0(object) -> its TreeComponent or null.
inline constexpr uintptr_t kGetTarget = 0x5B1600;
inline constexpr uint8_t kGetTargetHead[11] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57};
inline constexpr uintptr_t kFindTree = 0x491AC0;
inline constexpr uint8_t kFindTreeHead[15] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74,
                                              0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18};

// Offsets (the same as remote_rope_logic.h).
inline constexpr uint32_t kActor_Key = 0x60;
inline constexpr uint32_t kActor_Control = 0xC8;  // u8, != 0: controlled by this client
inline constexpr uint32_t kActor_Comps = 0x68;
inline constexpr uint32_t kActor_LockObj = 0x08;
inline constexpr uint32_t kComps_RemoteCatch = 0x78;
inline constexpr uint32_t kComps_Control = 0x40;  // f6 = [[[[actor+0x68]+0x40]+0x88]+0x10]+0xF6 (0x117F850..0x117F873)
inline constexpr uint32_t kControl_F6a = 0x88;
inline constexpr uint32_t kControl_F6b = 0x10;
inline constexpr uint32_t kControl_F6 = 0xF6;
inline constexpr uint32_t kComp_Owner = 0x08;
inline constexpr uintptr_t kClientRemoteCatchVtbl = 0x55890D8;  // pa::ClientRemoteCatchActorComponent
inline constexpr uint32_t kLockVf[] = {0x18, 0x20, 0x30, 0x40};
inline constexpr uint32_t kSlotBase = 0x20;
inline constexpr uint32_t kSlotStride = 0x58;
inline constexpr uint32_t kSlot_Kind = 0x00;   // u8, 6 = empty
inline constexpr uint32_t kSlot_Scene = 0x10;  // 16 bytes (u64 object id, u64 level id)
inline constexpr uint8_t kSlotEmpty = 6;
inline constexpr uint32_t kStateBase = 0x9BC;  // u8 per slot: 2 flight, 3 attached, 7 idle ...
inline constexpr uint32_t kStateStride = 0x1A0;
inline constexpr uint8_t kStateAttached = 3;
inline constexpr int kSlots = 2;
inline constexpr uintptr_t slot_target(uintptr_t comp, uint8_t slot) { return comp + kSlotBase + slot * kSlotStride; }
inline constexpr uintptr_t slot_state(uintptr_t comp, uint8_t slot) { return comp + kStateBase + slot * kStateStride; }
// 0x1190FD0's state (the 5th argument of vf2): +0x378 the amount, +0x380 the direction (x, y, z).
inline constexpr uint32_t kState_Amount = 0x378;
inline constexpr uint32_t kState_Dir = 0x380;
// The TreeComponent (SetBend's writes): +0x2A4 amount, +0x2A8 / +0x2AC / +0x2B0 direction, +0x2B4 set, +0x59 bit 8.
inline constexpr uint32_t kTree_Amount = 0x2A4;
inline constexpr uint32_t kTree_Set = 0x2B4;
inline constexpr uint32_t kTree_Flags = 0x59;
inline constexpr uintptr_t kMainThreadId = 0x6A652D4;  // dword: the client's main thread

// ---------------------------------------------------------------- build 1.0.0.3527 [V capstone on the installed PE]

// From RTTI, not from similar bytes: pa::gameClientScript::RemoteCatchFunctions vtable 0x5A9C838, slot 2 = 0x134CB80 (same
// size 0x15C and shape as 0x117F7E0; it calls the release 0x663130 at 0x134CC7C, remote_rope_logic.h). Its calls give the
// apply 0x1360CC0 (size 0x5B4, as 0x1190FD0; only caller 0x134CCB1), FUN_1405b1600 = 0x66D150, FUN_140491ac0 = 0x53A700
// ([obj+0x210] walk). The apply's last call is SetBend 0x376C6A0 (0x1361222, its only caller; the same writes +0x2A8,
// +0x2AC, +0x2A4, +0x2B4, +0x59). The tick 0x658550 calls [comp+0xCF8]->vf(owner, slot, dt, comp+0x168+slot*0x428), has
// callers 0x98A697 and the job's jmp 0x98F160. Heads kVf2Head, kApplyHead, kSetBendHead, kTickHead, kGetTargetHead and
// kFindTreeHead are byte-identical in 3527. What moved in the data: the script's state (+0x48: 0x13611D5 amount, 0x13611FF
// direction), the action's f6 byte (+0xFA: 0x134CC13), the component's slot state (see remote_rope_logic.h).
inline constexpr uintptr_t kCodeEnd3527 = 0x5595000;
inline constexpr uintptr_t kVf23527 = 0x134CB80;
inline constexpr uintptr_t kVf2Slot3527 = 0x5A9C848;  // vtable 0x5A9C838 slot 2
inline constexpr uintptr_t kApply3527 = 0x1360CC0;
inline constexpr uintptr_t kApplyCall3527 = 0x134CCB1;
inline constexpr uint8_t kApplyCallBytes3527[5] = {0xE8, 0x0A, 0x40, 0x01, 0x00};
inline constexpr uintptr_t kSetBend3527 = 0x376C6A0;
inline constexpr uintptr_t kSetBendCall3527 = 0x1361222;  // rdx = state+0x3C8, xmm2 = state+0x3C0
inline constexpr uint8_t kSetBendCallBytes3527[5] = {0xE8, 0x79, 0xB4, 0x40, 0x02};
inline constexpr uintptr_t kTick3527 = 0x658550;
inline constexpr uintptr_t kTickJump3527 = 0x98F160;
inline constexpr uint8_t kTickJumpBytes3527[5] = {0xE9, 0xEB, 0x93, 0xCC, 0xFF};
inline constexpr uintptr_t kGetTarget3527 = 0x66D150;
inline constexpr uintptr_t kFindTree3527 = 0x53A700;
inline constexpr uintptr_t kClientRemoteCatchVtbl3527 = 0x5916888;
inline constexpr uint32_t kControl_F63527 = 0xFA;
inline constexpr uint32_t kStateBase3527 = 0xA4C;
inline constexpr uint32_t kState_Dir3527 = 0x3C8;
inline constexpr uintptr_t kMainThreadId3527 = 0x6EA3C78;

// ---------------------------------------------------------------- build 1.0.0.3576 (static, 2026-11-06; not yet run)

// From RTTI again: RemoteCatchFunctions vtable 0x5A9E970, slot 2 = 0x134D340 (+0x7C0; kVf2Head, 0x15C bytes, the release
// call 0x134D43C -> 0x663790). Its call 0x134D471 (the same 5 bytes as 3527's: the apply moved with it) -> the apply
// 0x1361480 (+0x7C0, kApplyHead, 0x5B4 bytes, only caller), whose calls give FUN_1405b1600 = 0x66D7B0 (+0x83) and
// FUN_140491ac0 = 0x53AD60 (+0x97) (both +0x660, their heads) and, last, SetBend 0x376D3A0 (+0xD00, kSetBendHead; its
// only caller 0x13619E2, rdx = state+0x3C8, xmm2 = state+0x3C0 as 3527's). The tick 0x658BB0 (+0x660, kTickHead): the
// only function with that head within +0x2000; its callers call 0x98AA07 and jmp 0x98F4D0 (3527's + 0x370).
// ClientRemoteCatchActorComponent 0x59188F0 (RTTI; vf158 = the release 0x663790). The main thread's id 0x6EA5C78: the
// release's `cmp [rip],eax` at 0x6637FD (3527's 0x66319D + 0x660). The data offsets are 3527's: f6 +0xFA (0x134D3D3), the
// slot state +0xA4C (0x65DEB4), the state's +0x3C0 / +0x3C8 (0x1361995 / 0x13619BF).
inline constexpr uintptr_t kCodeEnd3576 = 0x5597000;
inline constexpr uintptr_t kVf23576 = 0x134D340;
inline constexpr uintptr_t kVf2Slot3576 = 0x5A9E980;  // vtable 0x5A9E970 slot 2
inline constexpr uintptr_t kApply3576 = 0x1361480;
inline constexpr uintptr_t kApplyCall3576 = 0x134D471;  // kApplyCallBytes3527
inline constexpr uintptr_t kSetBend3576 = 0x376D3A0;
inline constexpr uintptr_t kSetBendCall3576 = 0x13619E2;
inline constexpr uint8_t kSetBendCallBytes3576[5] = {0xE8, 0xB9, 0xB9, 0x40, 0x02};
inline constexpr uintptr_t kTick3576 = 0x658BB0;
inline constexpr uintptr_t kTickJump3576 = 0x98F4D0;
inline constexpr uint8_t kTickJumpBytes3576[5] = {0xE9, 0xDB, 0x96, 0xCC, 0xFF};
inline constexpr uintptr_t kGetTarget3576 = 0x66D7B0;
inline constexpr uintptr_t kFindTree3576 = 0x53AD60;
inline constexpr uintptr_t kClientRemoteCatchVtbl3576 = 0x59188F0;
inline constexpr uintptr_t kMainThreadId3576 = 0x6EA5C78;

// ---------------------------------------------------------------- build 1.0.0.3663 (static, 2026-11-13; never run)

// From RTTI: RemoteCatchFunctions vtable 0x5B19188 (vtable_map_3576_3663.json), slot 2 = 0x138B170 (kVf2Head, .pdata 0x15C
// bytes; the release call 0x138B26C -> 0x68F130, remote_rope_logic.h; f6 still +0xFA, 0x138B203 after [+0x40] / [+0x88]).
// Its call 0x138B2A1 (+0x131 as before; only its rel32 differs) -> the apply 0x139F550 (kApplyHead, 0x5B4 bytes, only
// caller), whose calls give FUN_1405b1600 = 0x699130 (+0x83, kGetTargetHead) and FUN_140491ac0 = 0x566360 (+0x97,
// kFindTreeHead; its [obj+0x210] walk 0x56637D) and, last, SetBend 0x37E33D0 (kSetBendHead; its only caller 0x139FAB2,
// rdx = state+0x3C8, xmm2 = state+0x3C0 (0x139FAA0 / 0x139FAA8); the same writes +0x2A8 / +0x2B0, +0x2AC, +0x2A4, +0x2B4,
// +0x59). The tick 0x6845E0 (kTickHead; of the three functions with that head in 0x660000..0x6A0000 the only one that
// reads [comp+0xCF8], 0x68471A): its callers are call 0x9B9437 and jmp 0x9BDEF0, as before. ClientRemoteCatchActorComponent
// 0x5994CC8 (RTTI; vf158 = the release 0x68F130). The main thread's id 0x6F29B54: the release's `cmp [rip],eax` at
// 0x68F19D (231 RIP references). The slot state +0xA4C (remote_rope_logic.h's 3663 evidence).
inline constexpr uintptr_t kCodeEnd3663 = 0x5613000;
inline constexpr uintptr_t kVf23663 = 0x138B170;
inline constexpr uintptr_t kVf2Slot3663 = 0x5B19198;  // vtable 0x5B19188 slot 2
inline constexpr uintptr_t kApply3663 = 0x139F550;
inline constexpr uintptr_t kApplyCall3663 = 0x138B2A1;
inline constexpr uint8_t kApplyCallBytes3663[5] = {0xE8, 0xAA, 0x42, 0x01, 0x00};
inline constexpr uintptr_t kSetBend3663 = 0x37E33D0;
inline constexpr uintptr_t kSetBendCall3663 = 0x139FAB2;
inline constexpr uint8_t kSetBendCallBytes3663[5] = {0xE8, 0x19, 0x39, 0x44, 0x02};
inline constexpr uintptr_t kTick3663 = 0x6845E0;
inline constexpr uintptr_t kTickJump3663 = 0x9BDEF0;
inline constexpr uint8_t kTickJumpBytes3663[5] = {0xE9, 0xEB, 0x66, 0xCC, 0xFF};
inline constexpr uintptr_t kGetTarget3663 = 0x699130;
inline constexpr uintptr_t kFindTree3663 = 0x566360;
inline constexpr uintptr_t kClientRemoteCatchVtbl3663 = 0x5994CC8;
inline constexpr uintptr_t kMainThreadId3663 = 0x6F29B54;

// As the natives (0x5947B4, 0x5A5370, FUN_1405b1600): a scene id is set when one of its first three dwords is.
inline bool scene_set(const uint8_t* s) {
    uint32_t d[3];
    std::memcpy(d, s, sizeof d);
    return d[0] || d[1] || d[2];
}

// ---------------------------------------------------------------- wire: tunnel control packet, state 15

inline constexpr uint16_t kControlOpcode = 1;  // troc_frame.h kControlOpcode
inline constexpr uint8_t kControlTreeBend = 15;  // troc_frame.h: 1-14 taken (5 mount_sync, 12 weather, 13-14 rejoin)
inline constexpr uint8_t kVersion = 1;
inline constexpr size_t kHeader = 5;  // u16 opcode | i8 slot | u16 len
inline constexpr size_t kPayloadSize = 52;
inline constexpr size_t kFrameSize = kHeader + kPayloadSize;

enum class Kind : uint8_t { Sample = 1, End = 2 };
inline constexpr uint8_t kFlagApplyFlag = 0x01;  // 0x1190FD0's r8b (f6 == 1) on that call

struct Sample {
    Kind kind = Kind::Sample;
    uint8_t slot = 0;
    uint8_t flags = 0;
    uint32_t key = 0;   // the thrower, 0xA...
    uint32_t seq = 0;   // per sender, increasing (never 0)
    uint32_t run = 0;   // the sender's bend run (never 0)
    uint8_t scene[16] = {};
    float amount = 0.0f;  // [-1, 1]
    float dx = 0.0f, dz = 0.0f;
    uint32_t tick_ms = 0;  // the sender's clock (QPC ms, low 32 bits)
};

inline void put32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
inline uint32_t get32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}
inline void putf(uint8_t* p, float f) {
    uint32_t v = 0;
    std::memcpy(&v, &f, 4);
    put32(p, v);
}
inline float getf(const uint8_t* p) {
    const uint32_t v = get32(p);
    float f = 0.0f;
    std::memcpy(&f, &v, 4);
    return f;
}

// u8 15 | u8 version | u8 kind | u8 slot | u8 flags | u8 0 | u16 0 | u32 key | u32 seq | u32 run | 16 B scene id |
// f32 amount | f32 dir.x | f32 dir.z | u32 tick_ms
inline std::array<uint8_t, kPayloadSize> encode(const Sample& s) {
    std::array<uint8_t, kPayloadSize> p{};
    p[0] = kControlTreeBend;
    p[1] = kVersion;
    p[2] = static_cast<uint8_t>(s.kind);
    p[3] = s.slot;
    p[4] = s.flags;
    put32(&p[8], s.key);
    put32(&p[12], s.seq);
    put32(&p[16], s.run);
    std::memcpy(&p[20], s.scene, 16);
    putf(&p[36], s.amount);
    putf(&p[40], s.dx);
    putf(&p[44], s.dz);
    put32(&p[48], s.tick_ms);
    return p;
}

// Exactly kPayloadSize bytes, state 15, this version, a known kind, a 0xA key, a slot in range, seq and run set, a set
// scene id, finite values, |amount| <= 1 (a Sample's direction not null).
inline std::optional<Sample> decode(std::span<const uint8_t> p) {
    if (p.size() != kPayloadSize || p[0] != kControlTreeBend || p[1] != kVersion) return std::nullopt;
    if ((p[2] != 1 && p[2] != 2) || p[5] != 0 || p[6] != 0 || p[7] != 0) return std::nullopt;
    Sample s;
    s.kind = static_cast<Kind>(p[2]);
    s.slot = p[3];
    s.flags = p[4];
    s.key = get32(&p[8]);
    s.seq = get32(&p[12]);
    s.run = get32(&p[16]);
    std::memcpy(s.scene, &p[20], 16);
    s.amount = getf(&p[36]);
    s.dx = getf(&p[40]);
    s.dz = getf(&p[44]);
    s.tick_ms = get32(&p[48]);
    if (!player_key(s.key) || s.slot >= kSlots || s.seq == 0 || s.run == 0 || !scene_set(s.scene)) return std::nullopt;
    if (!std::isfinite(s.amount) || !std::isfinite(s.dx) || !std::isfinite(s.dz)) return std::nullopt;
    if (s.amount < -1.0f || s.amount > 1.0f) return std::nullopt;
    if (s.kind == Kind::Sample && s.dx * s.dx + s.dz * s.dz < 1e-6f) return std::nullopt;
    return s;
}

// The whole troc frame: u16 opcode 1 | i8 -1 | u16 52 | payload.
inline std::vector<uint8_t> frame(const Sample& s) {
    const auto p = encode(s);
    std::vector<uint8_t> f(kFrameSize);
    f[0] = kControlOpcode & 0xFF;
    f[1] = kControlOpcode >> 8;
    f[2] = 0xFF;
    f[3] = kPayloadSize & 0xFF;
    f[4] = kPayloadSize >> 8;
    for (size_t i = 0; i < kPayloadSize; ++i) f[kHeader + i] = p[i];
    return f;
}

// A frame of this exact form (opcode 1, slot -1, 52-byte payload starting with state 15). Nothing else is ours.
inline bool is_frame(std::span<const uint8_t> f) {
    return f.size() == kFrameSize && f[0] == (kControlOpcode & 0xFF) && f[1] == (kControlOpcode >> 8) && f[2] == 0xFF &&
           f[3] == (kPayloadSize & 0xFF) && f[4] == (kPayloadSize >> 8) && f[kHeader] == kControlTreeBend;
}

// ---------------------------------------------------------------- the thrower: what to send (the module's thread)

// The rate limits (section 14.5).
inline constexpr uint32_t kMinGapMs = 25;      // never more than 40 Hz per channel
inline constexpr uint32_t kPeriodMs = 50;      // 20 Hz while it changes
inline constexpr float kJump = 0.15f;          // a change this big goes at once (after kMinGapMs)
inline constexpr float kStill = 0.01f;         // below this it counts as still
inline constexpr uint32_t kKeepAliveMs = 250;  // 4 Hz while still
inline constexpr uint32_t kEndIdleMs = 150;    // no SetBend this long: the run ended (End sent)

// One SetBend of this client's own character (M3), as the module's thread sees it.
struct Bend {
    uint32_t key = 0;
    uint8_t slot = 0;
    uint8_t flags = 0;
    uint8_t scene[16] = {};
    float amount = 0.0f;
    float dx = 0.0f, dz = 0.0f;
    uint64_t t_ms = 0;
};

inline float clamp1(float v) { return v < -1.0f ? -1.0f : v > 1.0f ? 1.0f : v; }

class Sender {
public:
    static constexpr size_t kChannels = 4;
    struct Ended {
        uint32_t key = 0;
        uint8_t slot = 0;
        uint32_t run = 0;
        Sample end;
    };
    struct Result {
        bool new_run = false;      // this SetBend started a run (a line for the log)
        bool refused = false;      // not sendable (no scene id, not finite, null direction)
        std::optional<Sample> out; // send this
        // The End of this thrower's previous run when this SetBend is on ANOTHER tree and that run was still active:
        // to queue BEFORE `out` (its seq is lower; after the new run's first Sample the receiver would drop it).
        std::optional<Ended> end_first;
    };

    Result on_bend(const Bend& b) {
        Result r;
        if (!player_key(b.key) || b.slot >= kSlots || !scene_set(b.scene) || !std::isfinite(b.amount) ||
            !std::isfinite(b.dx) || !std::isfinite(b.dz) || b.dx * b.dx + b.dz * b.dz < 1e-6f) {
            r.refused = true;
            return r;
        }
        Channel* c = find(b.key, b.slot);
        if (c && std::memcmp(c->scene, b.scene, 16) != 0) {
            // Another tree: an active run ends now (its End in end_first, queued before out) and a new one starts.
            // An inactive channel already sent its End (tick): nothing more.
            if (c->active) r.end_first = make_end(*c);
            c->active = false;
        }
        if (!c) c = alloc(b.key, b.slot);
        if (!c) {
            r.refused = true;
            ++full_;
            return r;
        }
        const float amount = clamp1(b.amount);
        c->last_bend_ms = b.t_ms;
        if (!c->active) {
            c->active = true;
            c->run = ++run_;
            std::memcpy(c->scene, b.scene, 16);
            r.new_run = true;
            r.out = emit(*c, b, amount);
            return r;
        }
        const uint64_t gap = b.t_ms - c->last_sent_ms;
        const float delta = std::fabs(amount - c->last_amount);
        bool send = false;
        if (gap >= kMinGapMs) {
            if (delta > kJump) send = true;
            else if (gap >= kPeriodMs && delta >= kStill) send = true;
            else if (gap >= kKeepAliveMs) send = true;
        }
        if (send) r.out = emit(*c, b, amount);
        return r;
    }

    // Runs idle for kEndIdleMs end (their End to send).
    size_t tick(uint64_t now_ms, Ended* out, size_t max) {
        size_t n = 0;
        for (Channel& c : ch_) {
            if (n >= max) break;
            if (c.key && c.active && now_ms - c.last_bend_ms >= kEndIdleMs) {
                out[n++] = make_end(c);
                c.active = false;
            }
        }
        return n;
    }
    bool active(uint32_t key, uint8_t slot) const {
        for (const Channel& c : ch_) {
            if (c.key == key && c.slot == slot) return c.active;
        }
        return false;
    }
    uint64_t full() const { return full_; }
    uint32_t seq() const { return seq_; }

private:
    struct Channel {
        uint32_t key = 0;
        uint8_t slot = 0;
        bool active = false;
        uint32_t run = 0;
        uint8_t scene[16] = {};
        uint64_t last_bend_ms = 0;
        uint64_t last_sent_ms = 0;
        float last_amount = 0.0f;
        float last_dx = 1.0f, last_dz = 0.0f;
        uint8_t last_flags = 0;
    };
    Channel* find(uint32_t key, uint8_t slot) {
        for (Channel& c : ch_) {
            if (c.key == key && c.slot == slot) return &c;
        }
        return nullptr;
    }
    Channel* alloc(uint32_t key, uint8_t slot) {
        for (Channel& c : ch_) {
            if (!c.key || !c.active) {
                c = Channel{};
                c.key = key;
                c.slot = slot;
                return &c;
            }
        }
        return nullptr;
    }
    Sample emit(Channel& c, const Bend& b, float amount) {
        Sample s;
        s.kind = Kind::Sample;
        s.slot = c.slot;
        s.flags = b.flags;
        s.key = c.key;
        s.seq = ++seq_;
        s.run = c.run;
        std::memcpy(s.scene, c.scene, 16);
        s.amount = amount;
        s.dx = b.dx;
        s.dz = b.dz;
        s.tick_ms = static_cast<uint32_t>(b.t_ms);
        c.last_sent_ms = b.t_ms;
        c.last_amount = amount;
        c.last_dx = b.dx;
        c.last_dz = b.dz;
        c.last_flags = b.flags;
        return s;
    }
    Ended make_end(Channel& c) {
        Ended e;
        e.key = c.key;
        e.slot = c.slot;
        e.run = c.run;
        e.end.kind = Kind::End;
        e.end.slot = c.slot;
        e.end.flags = c.last_flags;
        e.end.key = c.key;
        e.end.seq = ++seq_;
        e.end.run = c.run;
        std::memcpy(e.end.scene, c.scene, 16);
        e.end.amount = c.last_amount;
        e.end.dx = c.last_dx;
        e.end.dz = c.last_dz;
        e.end.tick_ms = static_cast<uint32_t>(c.last_bend_ms);
        return e;
    }
    Channel ch_[kChannels];
    uint32_t seq_ = 0;
    uint32_t run_ = 0;
    uint64_t full_ = 0;
};

// The frames waiting for the network thread: bounded, the oldest dropped (only the newest bend matters; an End is
// never dropped for a Sample: when full, the oldest Sample goes first).
class OutQueue {
public:
    static constexpr size_t kMax = 8;
    void push(const Sample& s) {
        if (q_.size() >= kMax) {
            auto it = std::find_if(q_.begin(), q_.end(), [](const Sample& x) { return x.kind == Kind::Sample; });
            q_.erase(it != q_.end() ? it : q_.begin());
            ++dropped_;
        }
        q_.push_back(s);
    }
    std::optional<Sample> pop() {
        if (q_.empty()) return std::nullopt;
        Sample s = q_.front();
        q_.pop_front();
        return s;
    }
    void clear() {
        discarded_ += q_.size();
        q_.clear();
    }
    size_t size() const { return q_.size(); }
    uint64_t dropped() const { return dropped_; }
    uint64_t discarded() const { return discarded_; }

private:
    std::deque<Sample> q_;
    uint64_t dropped_ = 0;
    uint64_t discarded_ = 0;
};

// ---------------------------------------------------------------- the observer: what was received (network threads)

inline constexpr uint32_t kMaxAgeMs = 500;     // an older sample is not applied (a lost End)
inline constexpr uint32_t kRestartMs = 2000;   // an older seq after this long of silence: the sender restarted
inline constexpr uint32_t kDelayMs = 100;      // the observer renders this far behind the newest sample
inline constexpr uint32_t kMaxSpanMs = 1000;   // two samples further apart than this are not interpolated

enum class Rx : uint8_t { Accepted, NewRun, Ended, OldSeq, TableFull, Count };
inline const char* rx_name(Rx r) {
    switch (r) {
        case Rx::Accepted: return "accepted";
        case Rx::NewRun: return "new run";
        case Rx::Ended: return "end";
        case Rx::OldSeq: return "old seq";
        case Rx::TableFull: return "table full";
        case Rx::Count: break;
    }
    return "?";
}

struct Pose {
    float amount = 0.0f;
    float dx = 1.0f, dz = 0.0f;
    uint8_t scene[16] = {};
    uint32_t age_ms = 0;  // since the newest sample was received
    uint32_t run = 0;
    uint32_t seq = 0;
};

class Receiver {
public:
    static constexpr size_t kEntries = 4;

    // `epoch`: the connection the frame came on; a new one forgets everything first.
    Rx on_sample(const Sample& s, uint64_t epoch, uint64_t now_ms) {
        if (epoch != epoch_) {
            if (epoch_set_) ++epoch_resets_;
            reset();
            epoch_ = epoch;
            epoch_set_ = true;
        }
        Entry* e = find(s.key, s.slot);
        if (e && s.seq <= e->last_seq) {
            if (now_ms - e->last_recv_ms < kRestartMs) return Rx::OldSeq;
            *e = Entry{};  // the sender started again (a new process on the same connection)
            e->key = s.key;
            e->slot = s.slot;
        }
        if (!e) {
            e = alloc(s.key, s.slot);
            if (!e) return Rx::TableFull;
        }
        e->last_seq = s.seq;
        e->last_recv_ms = now_ms;
        if (s.kind == Kind::End) {
            e->ended = true;
            return Rx::Ended;
        }
        const bool new_run = e->run != s.run || e->n == 0;
        if (new_run) {
            e->run = s.run;
            e->n = 0;
        }
        e->ended = false;
        e->prev = e->last;
        e->prev_recv_ms = e->last_recv_sample_ms;
        e->last = s;
        e->last_recv_sample_ms = now_ms;
        e->n = std::min<uint32_t>(e->n + 1, 2);
        return new_run ? Rx::NewRun : Rx::Accepted;
    }

    // What to apply now for this thrower and slot; none when nothing live (no entry, ended, older than kMaxAgeMs).
    std::optional<Pose> query(uint32_t key, uint8_t slot, uint64_t now_ms) const {
        const Entry* e = find(key, slot);
        if (!e || e->ended || e->n == 0) return std::nullopt;
        const uint64_t age = now_ms - e->last_recv_sample_ms;
        if (age > kMaxAgeMs) return std::nullopt;
        Pose p;
        p.age_ms = static_cast<uint32_t>(age);
        p.run = e->last.run;
        p.seq = e->last.seq;
        std::memcpy(p.scene, e->last.scene, 16);
        float a = e->last.amount, x = e->last.dx, z = e->last.dz;
        if (e->n >= 2) {
            // In the sender's clock: the newest sample's tick maps to its receive time.
            const uint32_t t0 = e->prev.tick_ms, t1 = e->last.tick_ms;
            const uint32_t span = t1 - t0;
            if (span > 0 && span <= kMaxSpanMs) {
                const int64_t render = static_cast<int64_t>(now_ms) - kDelayMs - static_cast<int64_t>(e->last_recv_sample_ms);
                // render (relative to t1) in [-span, 0] -> alpha in [0, 1]
                float alpha = 1.0f + static_cast<float>(render) / static_cast<float>(span);
                alpha = alpha < 0.0f ? 0.0f : alpha > 1.0f ? 1.0f : alpha;
                a = e->prev.amount + (e->last.amount - e->prev.amount) * alpha;
                x = e->prev.dx + (e->last.dx - e->prev.dx) * alpha;
                z = e->prev.dz + (e->last.dz - e->prev.dz) * alpha;
            }
        }
        const float len = std::sqrt(x * x + z * z);
        if (len > 1e-4f) {
            x /= len;
            z /= len;
        } else {
            x = e->last.dx;
            z = e->last.dz;
            const float l2 = std::sqrt(x * x + z * z);
            if (l2 > 1e-4f) {
                x /= l2;
                z /= l2;
            }
        }
        p.amount = clamp1(a);
        p.dx = x;
        p.dz = z;
        return p;
    }

    void reset() {
        for (Entry& e : e_) e = Entry{};
    }
    uint64_t epoch_resets() const { return epoch_resets_; }

private:
    struct Entry {
        uint32_t key = 0;
        uint8_t slot = 0;
        uint32_t last_seq = 0;
        uint64_t last_recv_ms = 0;  // any frame
        bool ended = false;
        uint32_t run = 0;
        uint32_t n = 0;  // samples of this run kept (0..2)
        Sample prev, last;
        uint64_t prev_recv_ms = 0, last_recv_sample_ms = 0;
    };
    Entry* find(uint32_t key, uint8_t slot) {
        for (Entry& e : e_) {
            if (e.key == key && e.slot == slot) return &e;
        }
        return nullptr;
    }
    const Entry* find(uint32_t key, uint8_t slot) const {
        for (const Entry& e : e_) {
            if (e.key == key && e.slot == slot) return &e;
        }
        return nullptr;
    }
    Entry* alloc(uint32_t key, uint8_t slot) {
        for (Entry& e : e_) {
            if (!e.key) {
                e = Entry{};
                e.key = key;
                e.slot = slot;
                return &e;
            }
        }
        // Reuse the stalest ended or silent entry (only two players: rarely reached).
        Entry* best = nullptr;
        for (Entry& e : e_) {
            if (e.ended && (!best || e.last_recv_ms < best->last_recv_ms)) best = &e;
        }
        if (!best) return nullptr;
        *best = Entry{};
        best->key = key;
        best->slot = slot;
        return best;
    }
    Entry e_[kEntries];
    uint64_t epoch_ = 0;
    bool epoch_set_ = false;
    uint64_t epoch_resets_ = 0;
};

// ---------------------------------------------------------------- the observer's decision at M4

enum class Outcome : uint8_t {
    NoSample,      // nothing live received for this thrower
    NotClient,     // the component is not the client's (vtable) or its lock is not the game's
    Unreadable,    // the slot could not be read
    SlotEmpty,     // slot 0 empty here
    NotAttached,   // slot 0 not in state 3 here
    SceneMismatch, // slot 0's scene id here differs from the thrower's
    WouldApply,    // probe: everything matches
    Applied,       // 1: SetBend called
    NoObject,      // 1: FUN_1405b1600 gave null
    NoTree,        // 1: FUN_140491ac0 gave null
    Busy,          // the receiver's table was being written (try-lock)
    SkippedNotMain,  // S29 guard: not the game's main thread (the native SetBend's own context is not unique)
    SkippedOwnBend,  // S29 guard: this PC's own player bends the same tree right now (its native SetBend wins)
    SkippedOwnInline,  // review B-M1: this PC's own player's inline bend (0x8A30C0) ran in the last 150 ms (any tree)
    Faulted,         // 1: a native call faulted (SEH): application is off for the rest of the run
    Disabled,        // 1: application off after an earlier fault (the probe goes on)
    Count
};
inline const char* outcome_name(Outcome o) {
    switch (o) {
        case Outcome::NoSample: return "no sample";
        case Outcome::NotClient: return "not the client's component";
        case Outcome::Unreadable: return "slot unreadable";
        case Outcome::SlotEmpty: return "slot 0 empty";
        case Outcome::NotAttached: return "slot 0 not attached (state != 3)";
        case Outcome::SceneMismatch: return "scene id MISMATCH";
        case Outcome::WouldApply: return "would apply";
        case Outcome::Applied: return "applied";
        case Outcome::NoObject: return "no object for the scene id";
        case Outcome::NoTree: return "no TreeComponent";
        case Outcome::Busy: return "busy";
        case Outcome::SkippedNotMain: return "skipped (not main thread)";
        case Outcome::SkippedOwnBend: return "skipped (own bend on the same tree)";
        case Outcome::SkippedOwnInline: return "skipped (own inline bend)";
        case Outcome::Faulted: return "FAULTED (application off)";
        case Outcome::Disabled: return "disabled after a fault";
        case Outcome::Count: break;
    }
    return "?";
}

struct SlotView {
    bool read_ok = false;
    uint8_t kind = kSlotEmpty;
    uint8_t state = 0;
    uint8_t scene[16] = {};
};
// Before any native call (probe and 1). Ready = WouldApply.
inline Outcome decide(bool client_ok, const SlotView& v, const Pose& p) {
    if (!client_ok) return Outcome::NotClient;
    if (!v.read_ok) return Outcome::Unreadable;
    if (v.kind == kSlotEmpty) return Outcome::SlotEmpty;
    if (v.state != kStateAttached) return Outcome::NotAttached;
    if (std::memcmp(v.scene, p.scene, 16) != 0) return Outcome::SceneMismatch;
    return Outcome::WouldApply;
}

// ---------------------------------------------------------------- per player character counts (lock-free)

inline constexpr uint64_t kRunGapUs = 200000;  // M1: calls further apart than this start a new run

struct KeyStats {
    std::atomic<uint32_t> key{0};
    std::atomic<uint8_t> ctl{0xFF};  // [actor+0xC8] at the last M1 / M2 / M4 call (0xFF unread)
    std::atomic<uint64_t> m1_calls{0}, m1_main{0}, m1_f6{0};
    std::atomic<uint64_t> m1_last_us{0};
    std::atomic<uint32_t> m1_runs{0};
    std::atomic<uint64_t> m2_flag1{0}, m2_flag0{0};
    std::atomic<uint64_t> m3_calls{0}, m3_main{0};
    std::atomic<uint64_t> m4_calls{0}, m4_main{0};
    std::atomic<uint64_t> m4_last_ev_us{0};
    std::atomic<uint8_t> m4_last_outcome{0xFF};
    std::atomic<uint32_t> m4_tid{0};
    std::atomic<uint32_t> m3_tid{0};
    // Review B1: whether the native vf2 / SetBend of this character ran INSIDE this client's RemoteCatch tick 0x59C0D0
    // (M4's depth counter on the thread), and inside the tick of this character's own component.
    std::atomic<uint64_t> m1_in_tick{0};
    std::atomic<uint64_t> m3_in_tick{0}, m3_same_comp{0};
    // S29: 0x8A30C0 (rope_probe's entry hook, tree_bend_note_pull): calls, with the timer running, inline SetBend copies
    // (+0x638 written: the bend of the tree under the character), and calls while this PC applied a bend for it.
    std::atomic<uint64_t> pull_calls{0}, pull_running{0}, pull_inline{0}, pull_during_apply{0};
    std::atomic<uint64_t> m4_last_apply_us{0};

    void clear() {
        ctl.store(0xFF, std::memory_order_relaxed);
        for (auto* a : {&m1_calls, &m1_main, &m1_f6, &m1_last_us, &m2_flag1, &m2_flag0, &m3_calls, &m3_main, &m4_calls,
                        &m4_main, &m4_last_ev_us, &m1_in_tick, &m3_in_tick, &m3_same_comp, &pull_calls, &pull_running,
                        &pull_inline, &pull_during_apply, &m4_last_apply_us}) {
            a->store(0, std::memory_order_relaxed);
        }
        m1_runs.store(0, std::memory_order_relaxed);
        m4_last_outcome.store(0xFF, std::memory_order_relaxed);
        m4_tid.store(0, std::memory_order_relaxed);
        m3_tid.store(0, std::memory_order_relaxed);
        key.store(0, std::memory_order_release);
    }
};

template <size_t N>
class KeyTable {
public:
    KeyStats* get(uint32_t key) {
        if (!player_key(key)) return nullptr;
        size_t i = hash(key) & (N - 1);
        for (size_t n = 0; n < N; ++n, i = (i + 1) & (N - 1)) {
            uint32_t k = e_[i].key.load(std::memory_order_acquire);
            if (k == key) return &e_[i];
            if (k == 0) {
                uint32_t expect = 0;
                if (e_[i].key.compare_exchange_strong(expect, key, std::memory_order_acq_rel)) return &e_[i];
                if (expect == key) return &e_[i];
            }
        }
        full_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    const KeyStats& at(size_t i) const { return e_[i]; }
    KeyStats& at(size_t i) { return e_[i]; }
    uint64_t full() const { return full_.load(std::memory_order_relaxed); }
    size_t used() const {
        size_t n = 0;
        for (const KeyStats& e : e_) n += e.key.load(std::memory_order_relaxed) != 0;
        return n;
    }
    // The module's thread, on a table no hook uses any more (KeySwitch): every entry back to empty.
    void clear() {
        for (KeyStats& e : e_) e.clear();
        full_.store(0, std::memory_order_relaxed);
    }
    static constexpr size_t size() { return N; }

private:
    static_assert(N >= 2 && (N & (N - 1)) == 0, "N must be a power of two");
    static size_t hash(uint32_t k) { return static_cast<size_t>((k * 2654435761u) >> 7); }
    KeyStats e_[N];
    std::atomic<uint64_t> full_{0};
};

// Review L1: two tables, the hooks use the active one; a new connection (or a full table) switches to the other one,
// cleared first, so the keys of earlier conversations (each re-entry brings new 0xA keys) never fill it for good. A hook
// that still holds an entry of the old table only adds to counts that are no longer printed.
template <size_t N>
class KeySwitch {
public:
    KeyTable<N>& active() { return t_[idx_.load(std::memory_order_acquire) & 1]; }
    const KeyTable<N>& active() const { return t_[idx_.load(std::memory_order_acquire) & 1]; }
    // The module's thread only.
    void switch_tables() {
        const unsigned next = (idx_.load(std::memory_order_relaxed) + 1) & 1;
        t_[next].clear();
        idx_.store(next, std::memory_order_release);
        ++switches_;
    }
    uint64_t switches() const { return switches_; }

private:
    KeyTable<N> t_[2];
    std::atomic<unsigned> idx_{0};
    uint64_t switches_ = 0;
};

// Review B1: the thread ids seen at a point (bounded, lock-free insert), to compare on the SAME PC the native SetBend
// (M3, this client's own thrower) with the tick that would apply (M4, a remote thrower).
template <size_t N>
class TidSet {
public:
    void add(uint32_t tid) {
        if (!tid) return;
        for (auto& t : t_) {
            uint32_t cur = t.load(std::memory_order_relaxed);
            if (cur == tid) return;
            if (cur == 0 && t.compare_exchange_strong(cur, tid, std::memory_order_relaxed)) return;
            if (cur == tid) return;
        }
        over_.fetch_add(1, std::memory_order_relaxed);
    }
    bool has(uint32_t tid) const {
        for (const auto& t : t_) {
            if (tid && t.load(std::memory_order_relaxed) == tid) return true;
        }
        return false;
    }
    size_t size() const {
        size_t n = 0;
        for (const auto& t : t_) n += t.load(std::memory_order_relaxed) != 0;
        return n;
    }
    uint32_t at(size_t i) const { return t_[i].load(std::memory_order_relaxed); }
    uint64_t over() const { return over_.load(std::memory_order_relaxed); }
    static constexpr size_t capacity() { return N; }
    template <size_t M>
    size_t common(const TidSet<M>& o) const {
        size_t n = 0;
        for (const auto& t : t_) {
            const uint32_t v = t.load(std::memory_order_relaxed);
            if (v && o.has(v)) ++n;
        }
        return n;
    }

private:
    std::atomic<uint32_t> t_[N] = {};
    std::atomic<uint64_t> over_{0};
};

// M4 lines: one when the outcome changes, else at most one a second per thrower.
// S29 guards of mode 1 (gancho-cuerda.md section 14.7), after decide() said WouldApply. Probe evaluates them too, so
// its "would apply" lines are what 1 would do.
inline constexpr uint64_t kOwnBendUs = kEndIdleMs * 1000ull;  // this PC's own bend run counts as open this long
inline bool own_bend_same_tree(uint64_t own_lo, uint64_t own_hi, uint64_t own_us, const uint8_t* scene, uint64_t now_us) {
    if (!own_us || now_us < own_us || now_us - own_us >= kOwnBendUs) return false;
    uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, scene, 8);
    std::memcpy(&hi, scene + 8, 8);
    return lo == own_lo && hi == own_hi;
}
// Review B-M1: the local player's inline SetBend copy in 0x8A30C0 (the tree under it; its scene id is not at hand
// there): ANY application is skipped while one ran in the last kOwnBendUs.
inline bool own_inline_recent(uint64_t own_inline_us, uint64_t now_us) {
    return own_inline_us && now_us >= own_inline_us && now_us - own_inline_us < kOwnBendUs;
}
inline Outcome apply_gate(bool disabled, bool main, bool own_same_tree, bool own_inline = false) {
    if (disabled) return Outcome::Disabled;
    if (!main) return Outcome::SkippedNotMain;
    if (own_same_tree) return Outcome::SkippedOwnBend;
    if (own_inline) return Outcome::SkippedOwnInline;
    return Outcome::WouldApply;
}

// Review B-L1: this PC's own last native SetBend (scene id + time), written by up to a dozen game threads (M3) and
// read on the main thread (M4). A seqlock: one writer at a time (a writer that finds another one writing skips its
// record: the other one is just as fresh); a reader that cannot get a stable copy in kReadTries answers "busy" and the
// caller treats it as an own bend on the same tree (skips: the conservative side).
class OwnBend {
public:
    static constexpr int kReadTries = 4;
    // False: another writer was writing (nothing recorded by this one).
    bool record(uint64_t lo, uint64_t hi, uint64_t us) {
        uint32_t s = seq_.load(std::memory_order_relaxed);
        if ((s & 1) || !seq_.compare_exchange_strong(s, s + 1, std::memory_order_acquire, std::memory_order_relaxed)) {
            return false;
        }
        std::atomic_thread_fence(std::memory_order_release);  // the odd seq is seen before any of the new data
        lo_.store(lo, std::memory_order_relaxed);
        hi_.store(hi, std::memory_order_relaxed);
        us_.store(us, std::memory_order_relaxed);
        seq_.store(s + 2, std::memory_order_release);
        return true;
    }
    enum class Read : uint8_t { Ok, Busy };
    Read read(uint64_t& lo, uint64_t& hi, uint64_t& us) const {
        for (int i = 0; i < kReadTries; ++i) {
            const uint32_t s1 = seq_.load(std::memory_order_acquire);
            if (s1 & 1) continue;
            lo = lo_.load(std::memory_order_relaxed);
            hi = hi_.load(std::memory_order_relaxed);
            us = us_.load(std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_acquire);
            if (seq_.load(std::memory_order_relaxed) == s1) return Read::Ok;
        }
        return Read::Busy;
    }
    // Guard 2 on a stable copy; a busy seqlock counts as the same tree (skip).
    bool same_tree_now(const uint8_t* scene, uint64_t now_us) const {
        uint64_t lo = 0, hi = 0, us = 0;
        if (read(lo, hi, us) == Read::Busy) return true;
        return own_bend_same_tree(lo, hi, us, scene, now_us);
    }

private:
    std::atomic<uint32_t> seq_{0};
    std::atomic<uint64_t> lo_{0}, hi_{0}, us_{0};
};
// A 0x8A30C0 call for a remote player "during an apply": this PC applied a bend for it this recently.
inline constexpr uint64_t kDuringApplyUs = 200000;
inline bool during_apply(uint64_t last_apply_us, uint64_t now_us) {
    return last_apply_us && now_us >= last_apply_us && now_us - last_apply_us < kDuringApplyUs;
}

inline constexpr uint64_t kApplyLineUs = 1000000;
inline bool apply_line_due(uint8_t last_outcome, uint8_t outcome, uint64_t last_us, uint64_t now_us) {
    return last_outcome != outcome || now_us - last_us >= kApplyLineUs;
}

}  // namespace cdmp::session2::tbl
