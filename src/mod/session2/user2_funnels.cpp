#include "mod/session2/user2_funnels.h"
#include "common/native_opcode.h"
#include "mod/game/build_profile.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/game/hook_prepare.h"
#include "mod/game/hook_traps.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/config.h"
#include "mod/log.h"
#include "mod/session2/fast_travel_logic.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/observer_milestone.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/session2.h"
#include "mod/session2/server.h"
#include "mod/session2/travel_probe.h"
#include "mod/session2/travel_probe_logic.h"
#include "mod/session2/user2_funnels_logic.h"
#include "mod/session2/user2_shops.h"
#include "mod/session2/user2_shops_logic.h"
#include "mod/session2/user2_stages.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using u2f::FunnelOut;
using u2f::Mode;

// ---------------------------------------------------------------- the sites (build 2976, .rsrc)
//
// Verified with capstone on D:\RE\CrimsonDesert_2976\bin\CrimsonDesert.exe
// (p8-impl-rango-embudos.md §2). Every byte array is compared with the running
// game before anything is written; any difference leaves that piece off.

// A: the two vf188(5) calls. Context = mov rax,[rX] ; mov dl,5 ; mov rcx,rX ;
// call [rax+0x188] ; movzx ebx,al. The call is at context + 8.
uintptr_t kRankCtx1 = 0x221E279;  // 0x221E110 (AddAggro path), before GrantRankPermit 0x2220850
constexpr uint8_t kRankCtx1Bytes[] = {0x48, 0x8B, 0x03, 0xB2, 0x05, 0x48, 0x8B, 0xCB, 0xFF,
                                      0x90, 0x88, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0xD8};
uintptr_t kRankCtx2 = 0x221F297;  // 0x221EF50, before the permit's removal 0x2220370
constexpr uint8_t kRankCtx2Bytes[] = {0x48, 0x8B, 0x06, 0xB2, 0x05, 0x48, 0x8B, 0xCE, 0xFF,
                                      0x90, 0x88, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0xD8};
constexpr uint32_t kRankCallAt = 8;      // 0x221E281 / 0x221F29F
constexpr uint32_t kRankCallLen = 6;     // FF 90 88 01 00 00
constexpr uint8_t kRankCallBytes[] = {0xFF, 0x90, 0x88, 0x01, 0x00, 0x00};
constexpr uint32_t kVf188 = 0x188;
constexpr uint32_t kActorTargetComp = 0x90;  // [[X+0x68]+0x90] = C_X (0x221E2B0..0x221E2B4)

// The subject: ExecuteTroc, the whole function (0x2774B20..0x2774B57; the
// try/catch continuation 0x2774B4A is past the patch).
uintptr_t kExecuteTroc = 0x2774B20;
constexpr uint8_t kExecuteTrocBytes[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8B, 0xCA, 0x48, 0x8B, 0xD9,
    0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x02, 0x48, 0x8D, 0x54, 0x24, 0x48, 0x49, 0x8B,
    0xC9, 0xFF, 0x50, 0x10, 0x8B, 0x08, 0x89, 0x0B, 0xEB, 0x05, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48,
    0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3};
constexpr uint32_t kExecuteTrocBoundaries[] = {5, 6, 10, 13, 16, 22};

// ServerField::vf40 / vf48, whole functions (0x67 bytes each): the field is
// read once, [rcx+0x180], then rcx is reloaded.
uintptr_t kVf40 = 0x2B00C70;
constexpr uint8_t kVf40Bytes[] = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54,
    0x24, 0x20, 0x48, 0x8B, 0x0D, 0x2F, 0x8A, 0x26, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0xFF, 0x18, 0xF8,
    0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44,
    0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88,
    0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0x89, 0x51, 0xC2, 0x02, 0x48,
    0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xB2, 0x3B, 0x93, 0xFE, 0x48, 0x8B,
    0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
uintptr_t kVf48 = 0x2B00CE0;
constexpr uint8_t kVf48Bytes[] = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54,
    0x24, 0x20, 0x48, 0x8B, 0x0D, 0xBF, 0x89, 0x26, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x8F, 0x18, 0xF8,
    0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44,
    0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88,
    0xA8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0x19, 0x51, 0xC2, 0x02, 0x48,
    0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0x42, 0x3B, 0x93, 0xFE, 0x48, 0x8B,
    0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
constexpr uint32_t kVfBoundaries[] = {6, 13, 18};

// quest_policy's probe (S34, politica-misiones.md): the quest component's game-event callback 0x290DBD0(component,
// event), checked up to its vf40 call (0x290DC08, returning to 0x290DC0B); an entry hook that only reads and counts.
uintptr_t kQuestEventCb = 0x290DBD0;
constexpr uint8_t kQuestEventCbBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57,
    0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48,
    0x8B, 0x49, 0x08, 0xE8, 0xC8, 0xCA, 0xEE, 0xFE, 0x90, 0x80, 0x7C, 0x24, 0x38, 0x00, 0x74, 0x60,
    0x48, 0x8B, 0x4C, 0x24, 0x30, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x40};
constexpr uint32_t kQuestEventCbBoundaries[] = {5, 10, 15, 16, 20};
// The policy's vf40 callers in .rsrc reached through the vtable (`call [rax+0x40]`, FF 50 40, right before the
// return address): checked at install, so a return address means what quest_policy assumes (an ERR line if not).
constexpr uint32_t kPolicyVtableCallRets[] = {0x290DC0B, 0x2A49183, 0x2A4A03B, 0x2A4A32B, 0x2C3409D, 0x2C4A36F,
                                              0x2C4A0AD};

// 0x2AFFF50(field, out): the owner's character in a lock handle. The whole
// function (0x164 bytes): the field (rcx) is read once (0x2AFFF78 mov r8d,
// [rcx+0x180]) and never kept; out (rdx) is saved and filled.
uintptr_t kOwnerChar = 0x2AFFF50;
constexpr uint8_t kOwnerCharBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55,
    0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B,
    0xFA, 0x45, 0x33, 0xFF, 0x44, 0x89, 0x7D, 0xB0, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48,
    0x8D, 0x55, 0xD8, 0x48, 0x8B, 0x0D, 0x2E, 0x97, 0x26, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x3E, 0x2A,
    0xF8, 0xFF, 0x90, 0x4C, 0x8D, 0x35, 0xAE, 0x5E, 0xC2, 0x02, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8B,
    0x70, 0x08, 0x48, 0x89, 0x75, 0xC0, 0x0F, 0xB6, 0x58, 0x10, 0x88, 0x5D, 0xC8, 0x0F, 0xB6, 0x48,
    0x11, 0x88, 0x4D, 0xC9, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x89, 0x4D, 0xD0, 0x4C, 0x89, 0x78, 0x08,
    0x44, 0x88, 0x78, 0x10, 0x4C, 0x8D, 0x25, 0xBD, 0x3A, 0xA7, 0x02, 0x4C, 0x89, 0x65, 0xB8, 0x48,
    0x8D, 0x05, 0x7A, 0x5E, 0xAB, 0x02, 0x48, 0x89, 0x45, 0xB8, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x8D,
    0x4D, 0xD8, 0xE8, 0x99, 0x48, 0x93, 0xFE, 0x84, 0xDB, 0x75, 0x26, 0x4C, 0x89, 0x37, 0x4C, 0x89,
    0x7F, 0x08, 0x66, 0x44, 0x89, 0x7F, 0x10, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x27, 0x48, 0x8D,
    0x05, 0x2B, 0x6A, 0xB4, 0x02, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0xEB,
    0x7A, 0x48, 0x8B, 0x9E, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x74, 0x1F, 0xBA, 0x04, 0x00,
    0x00, 0x00, 0x41, 0xB8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x03, 0x48, 0x8B, 0xCB, 0xFF, 0x90,
    0xC0, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x04, 0xB1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 0x4C, 0x89,
    0x75, 0xD8, 0x48, 0x89, 0x5D, 0xE0, 0x88, 0x4D, 0xE8, 0xC6, 0x45, 0xE9, 0x00, 0x4C, 0x89, 0x7D,
    0xF0, 0x4C, 0x89, 0x65, 0xD8, 0x48, 0x8D, 0x05, 0xD4, 0x69, 0xB4, 0x02, 0x48, 0x89, 0x45, 0xD8,
    0x4C, 0x89, 0x37, 0x48, 0x89, 0x5F, 0x08, 0x88, 0x4F, 0x10, 0xC6, 0x47, 0x11, 0x00, 0x4C, 0x89,
    0x7F, 0x18, 0x4C, 0x89, 0x7D, 0xE0, 0xC6, 0x45, 0xE8, 0x00, 0x4C, 0x89, 0x27, 0x48, 0x89, 0x07,
    0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x75, 0xD8, 0x4C, 0x89, 0x75, 0xB8, 0x48,
    0x8D, 0x4D, 0xB8, 0xE8, 0xE8, 0x47, 0x93, 0xFE, 0x48, 0x8B, 0xC7, 0x4C, 0x8D, 0x5C, 0x24, 0x70,
    0x49, 0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73, 0x40, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41,
    0x5C, 0x5F, 0x5D, 0xC3};
constexpr uint32_t kOwnerCharBoundaries[] = {5, 10, 15, 16, 17, 19, 21, 23, 26};
// Its DeadActor caller: lea rdx,[rsp+0x78] ; mov rcx,[rbp+0x98] ; call 0x2AFFF50 ; nop ; cmp byte [rbp-0x78],0.
uintptr_t kDeadCallCtx = 0x29432D2;
constexpr uint8_t kDeadCallCtxBytes[] = {0x48, 0x8D, 0x54, 0x24, 0x78, 0x48, 0x8B, 0x8D, 0x98, 0x00, 0x00,
                                         0x00, 0xE8, 0x6D, 0xCC, 0x1B, 0x00, 0x90, 0x80, 0x7D, 0x88, 0x00};
uintptr_t kDeadRet = 0x29432E3;

// 0x20DEE60: `jmp .xtls 0xE2BF850` (5 bytes, the whole stub in .rsrc). The
// patch must be exactly these 5 bytes (the bytes after them are not its own).
uintptr_t kOwnerUserStub = 0x20DEE60;
constexpr uint8_t kOwnerUserStubBytes[] = {0xE9, 0xEB, 0x09, 0x1E, 0x0C};
constexpr uint32_t kStubBoundaries[] = {5};
// Its loot caller (0x2B83960): lea rdx,[rbp+0x40] ; mov rcx,[rbp-0x10] ; call 0x20DEE60 ; nop ; cmp [rbp+0x50],dil.
uintptr_t kLootCallCtx = 0x2B83D1C;
constexpr uint8_t kLootCallCtxBytes[] = {0x48, 0x8D, 0x55, 0x40, 0x48, 0x8B, 0x4D, 0xF0, 0xE8,
                                         0x37, 0xB1, 0x55, 0xFF, 0x90, 0x40, 0x38, 0x7D, 0x50};
uintptr_t kLootRet = 0x2B83D29;

// FindUser 0x2A82590(user manager, out, u32 key) -> out (a lock handle, the
// layout the loot caller reads: +8 user, +0x10 locked). Its first argument:
// [[exe+0x6D696B8]] (vf40 0x2B00C82 and 0x2AFFF83, both verified above).
uintptr_t kFindUser = 0x2A82590;
constexpr uint8_t kFindUserBytes[] = {0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x53,
                                      0x55, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B,
                                      0xFA, 0x48, 0x8B, 0xF1, 0x45, 0x33, 0xF6};
constexpr uint32_t kFindUserBoundaries[] = {5, 10, 11, 12, 13, 14, 16, 20};
uintptr_t kUserManagerSlot = 0x6D696B8;

// F3 (p8-impl-viaje-rapido.md §2): the 2283 handler's vf48 call and what follows it, never patched, only checked so
// that the return address 0x2A5F7FC means what F3 assumes: mov rcx,[rbp-0x28] ; mov rax,[rcx] ; call [rax+0x48] ;
// (0x2A5F7FC) lea rcx,[rbp+0x90] ... mov rcx,rax ; call 0x2896120.
uintptr_t kReloadCallCtx = 0x2A5F7F2;
constexpr uint8_t kReloadCallCtxBytes[] = {
    0x48, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8D, 0x8D, 0x90, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x4C, 0x24, 0x30, 0x48, 0x8D, 0x4D, 0x08, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48,
    0x8D, 0x4D, 0xA0, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x8D, 0x98, 0x00, 0x00, 0x00, 0x4C,
    0x8D, 0x45, 0xA8, 0x48, 0x8D, 0x55, 0xB0, 0x48, 0x8B, 0xC8, 0xE8, 0xEF, 0x68, 0xE3, 0xFF};
// 0x2896120's head up to `mov r13,[rcx+0x18]` (0x2896155): the manager is used only through its +0x18.
uintptr_t kApplyReload = 0x2896120;
constexpr uint8_t kApplyReloadBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x40, 0xFF, 0xFF, 0xFF,
    0x48, 0x81, 0xEC, 0xC0, 0x01, 0x00, 0x00, 0x49, 0x8B, 0xF1, 0x49, 0x8B, 0xD8, 0x4C, 0x8B, 0xE2,
    0x33, 0xFF, 0x89, 0x7D, 0xA8, 0x4C, 0x8B, 0x69, 0x18};
uintptr_t kVtServerSequencerStageManager = 0x5B17A58;  // .?AVServerSequencerStageManager@pa@@
// The second vf48 of the same 2283 (fast_travel_logic.h kApplyVf48Ret), inside 0x2BC4950: mov rcx,[rbp-0x21] ;
// mov rax,[rcx] ; call [rax+0x48] ; (0x2BC4C53) mov rbx,rax ; lea rdx,[rax+8] ; ... ; call 0x393650 ; nop ;
// mov [rbp+0x1F],rbx ; or esi,1 ; mov [rbp-0x69],esi ; mov byte [rbx+0x6A0],0 (0x2BC4C49..0x2BC4C87).
uintptr_t kApplyCallCtx = 0x2BC4C49;
constexpr uint8_t kApplyCallCtxBytes[] = {
    0x48, 0x8B, 0x4D, 0xDF, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8B, 0xD8, 0x48, 0x8D, 0x50,
    0x08, 0x48, 0x85, 0xC0, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x0F, 0x44, 0xD0, 0x41, 0xB0, 0x01,
    0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4D, 0x0F, 0xE8, 0xDB, 0xE9, 0x7C, 0xFD, 0x90, 0x48, 0x89, 0x5D,
    0x1F, 0x83, 0xCE, 0x01, 0x89, 0x75, 0x97, 0xC6, 0x83, 0xA0, 0x06, 0x00, 0x00, 0x00};

// 1.0.0.3527 [V capstone on the PE, 2026-11-05]. The 2283 handler is 0x2CED5E0 (vtable 0x5EE8E58 slot 2), its first vf48
// call returns to 0x2CED885, then 0x2AF3A40; the second vf48 returns to 0x2E6767D inside 0x2E67480 and the store is
// +0x6D0. ServerField vtable 0x5EF0908 slots 8/9 are vf40/vf48; vf48's own call is FindUser 0x2D11050 and its global
// the user manager slot 0x71BE418.
constexpr uint8_t kExecuteTroc3527Bytes[] = {0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8B, 0xCA, 0x48, 0x8B, 0xD9, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x02, 0x48, 0x8D, 0x54, 0x24, 0x48, 0x49, 0x8B, 0xC9, 0xFF, 0x50, 0x10, 0x8B, 0x08, 0x89, 0x0B, 0xEB, 0x05, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B};
constexpr uint8_t kVf483527Bytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0x0D, 0xBF, 0x6B, 0x42, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0xEF, 0x97, 0xF7, 0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0x21, 0xBF, 0xD2, 0x02, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xA2, 0x05, 0x88, 0xFE, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
constexpr uint8_t kReload3527CtxBytes[] = {0x48, 0x8B, 0x4D, 0xE8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8D, 0x8D, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x30, 0x48, 0x8D, 0x4D, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x8D, 0x4D, 0xB0, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45, 0xB8, 0x48, 0x8D, 0x55, 0xC0, 0x48, 0x8B, 0xC8, 0xE8, 0x86, 0x61, 0xE0, 0xFF};
constexpr uint8_t kApplyReload3527Bytes[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x4C, 0x89, 0x48, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x08, 0xFF, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC0, 0x01, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0x70, 0xB8, 0x49, 0x8B, 0xD9, 0x4D, 0x8B, 0xF0, 0x4C, 0x8B, 0xE2, 0x33, 0xFF, 0x89, 0x7D, 0xA8, 0x4C, 0x8B, 0x69, 0x18, 0x48};
constexpr uint8_t kApplyCtx3527Bytes[] = {0x48, 0x8B, 0x4D, 0x07, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8B, 0xD8, 0x48, 0x8D, 0x50, 0x08, 0x48, 0x85, 0xC0, 0x49, 0x0F, 0x44, 0xD5, 0x41, 0xB0, 0x01, 0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4D, 0xE7, 0xE8, 0x96, 0xC2, 0x57, 0xFD, 0x90, 0x48, 0x89, 0x5D, 0xF7, 0x83, 0xCF, 0x02, 0x89, 0x7D, 0xB7, 0xC6, 0x83, 0xD0, 0x06, 0x00, 0x00, 0x00, 0x83, 0xE7, 0xFD, 0x89, 0x7D};
constexpr uint32_t kReloadVf48Ret3527 = 0x2CED885, kApplyVf48Ret3527 = 0x2E6767D;
// 1.0.0.3527 rank_permit, quest_per_user, kill_loot_per_user and quest_policy [V capstone on the PE, 2026-11-05].
// rank: 0x23F2CE0 (only caller 0x23F2460, the 0x221D8A0 of 2976) tests vf188(5) of the target, then its only
// GrantRankPermit call 0x23F2E8B (stub 0x23F54C0 -> .text); 0x23F3B60 tests the same before removal 0x23F3EF3 (stub
// 0x23F4FE0; 0x4E0 below the grant stub, as in 2976). Client vf188 0x5AEEA0 = byte [actor+0xC8]; 0x5AEDB0 clears it
// when [actor+0x90] is not the local user. The contexts run from the vf188 call to those calls.
constexpr uint8_t kRankCtx13527Bytes[] = {0x48, 0x8B, 0x03, 0xB2, 0x05, 0x48, 0x8B, 0xCB, 0xFF, 0x90, 0x88, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0xD8, 0x48, 0x8B, 0x4D, 0x48, 0x48, 0x8B, 0x11, 0x4C, 0x8B, 0x42, 0x20, 0xB2, 0x01, 0x41, 0xFF, 0xD0, 0x48, 0x8B, 0x47, 0x08, 0x48, 0x8D, 0x55, 0x48, 0x8B, 0x48, 0x60, 0x89, 0x4D, 0x48, 0x84, 0xDB, 0x74, 0x16, 0x49, 0x8B, 0x46, 0x08, 0x48, 0x8B, 0x48, 0x68, 0x48, 0x8B, 0x89, 0x90, 0x00, 0x00, 0x00, 0xE8, 0x30, 0x26, 0x00, 0x00};
constexpr uint8_t kRankCtx23527Bytes[] = {0x48, 0x8B, 0x06, 0xB2, 0x05, 0x48, 0x8B, 0xCE, 0xFF, 0x90, 0x88, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0xD8, 0x48, 0x8B, 0x4D, 0x67, 0x48, 0x8B, 0x11, 0x4C, 0x8B, 0x42, 0x20, 0xB2, 0x01, 0x41, 0xFF, 0xD0, 0x84, 0xDB, 0x74, 0x6D, 0x48, 0x8B, 0x46, 0x68, 0x48, 0x8B, 0x88, 0x90, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x13, 0x48, 0x8B, 0x47, 0x08, 0x8B, 0x50, 0x60, 0x89, 0x55, 0x67, 0x48, 0x8D, 0x55, 0x67, 0xE8, 0xE8, 0x10, 0x00, 0x00};
// vf40: ServerField vtable 0x5EF0908 slot 8, [[[[u+0xD0]+0x68]+0x138]+0x18] behind FindUser 0x2D11050.
constexpr uint8_t kVf403527Bytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0x0D, 0x2F, 0x6C, 0x42, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x5F, 0x98, 0xF7, 0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0x91, 0xBF, 0xD2, 0x02, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0x12, 0x06, 0x88, 0xFE, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
// The event callback: ServerQuestActorComponent (vtable 0x5EE6A68) vfB0 0x2B73840 registers the thunk 0x2B9B9F0,
// `jmp 0x2B79B30`; up to its vf40 call. The event: type +8 (0x2BB2F72), key +0x68 (0x194352C in the emit 0x19434D0).
constexpr uint8_t kQuestEventCb3527Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x49, 0x08, 0xE8, 0xC8, 0xF5, 0xDB, 0xFE, 0x90, 0x80, 0x7C, 0x24, 0x38, 0x00, 0x74, 0x60, 0x48, 0x8B, 0x4C, 0x24, 0x30, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x40};
// The owner's character 0x2D96A40, the whole function: rcx is read once (0x2D96A68 [rcx+0x180]) and overwritten.
constexpr uint8_t kOwnerChar3527Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0xFA, 0x45, 0x33, 0xFF, 0x44, 0x89, 0x7D, 0xB0, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x55, 0xD8, 0x48, 0x8B, 0x0D, 0x9E, 0x79, 0x42, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x0E, 0xAA, 0xF7, 0xFF, 0x90, 0x4C, 0x8D, 0x35, 0x26, 0xCD, 0xD2, 0x02, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8B, 0x70, 0x08, 0x48, 0x89, 0x75, 0xC0, 0x0F, 0xB6, 0x58, 0x10, 0x88, 0x5D, 0xC8, 0x0F, 0xB6, 0x48, 0x11, 0x88, 0x4D, 0xC9, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x89, 0x4D, 0xD0, 0x4C, 0x89, 0x78, 0x08, 0x44, 0x88, 0x78, 0x10, 0x4C, 0x8D, 0x25, 0x35, 0x79, 0xB6, 0x02, 0x4C, 0x89, 0x65, 0xB8, 0x48, 0x8D, 0x05, 0x3A, 0xDD, 0xBA, 0x02, 0x48, 0x89, 0x45, 0xB8, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x8D, 0x4D, 0xD8, 0xE8, 0x69, 0x13, 0x88, 0xFE, 0x84, 0xDB, 0x75, 0x26, 0x4C, 0x89, 0x37, 0x4C, 0x89, 0x7F, 0x08, 0x66, 0x44, 0x89, 0x7F, 0x10, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x27, 0x48, 0x8D, 0x05, 0xBB, 0xF9, 0xC3, 0x02, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x7A, 0x48, 0x8B, 0x9E, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x74, 0x1F, 0xBA, 0x04, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x03, 0x48, 0x8B, 0xCB, 0xFF, 0x90, 0xC0, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x04, 0xB1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x89, 0x5D, 0xE0, 0x88, 0x4D, 0xE8, 0xC6, 0x45, 0xE9, 0x00, 0x4C, 0x89, 0x7D, 0xF0, 0x4C, 0x89, 0x65, 0xD8, 0x48, 0x8D, 0x05, 0x64, 0xF9, 0xC3, 0x02, 0x48, 0x89, 0x45, 0xD8, 0x4C, 0x89, 0x37, 0x48, 0x89, 0x5F, 0x08, 0x88, 0x4F, 0x10, 0xC6, 0x47, 0x11, 0x00, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x7D, 0xE0, 0xC6, 0x45, 0xE8, 0x00, 0x4C, 0x89, 0x27, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x75, 0xD8, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8D, 0x4D, 0xB8, 0xE8, 0xB8, 0x12, 0x88, 0xFE, 0x48, 0x8B, 0xC7, 0x4C, 0x8D, 0x5C, 0x24, 0x70, 0x49, 0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73, 0x40, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0x5F, 0x5D, 0xC3};
// DeadActor's caller, inside 0x2BB2E20: its event right after (0x2BB2F72) is type 0x6B, DeadActor on this build.
constexpr uint8_t kDeadCallCtx3527Bytes[] = {0x48, 0x8D, 0x54, 0x24, 0x78, 0x48, 0x8B, 0x8D, 0x98, 0x00, 0x00, 0x00, 0xE8, 0xDD, 0x3A, 0x1E, 0x00, 0x90, 0x80, 0x7D, 0x88, 0x00};
// 0x22A2880: `jmp .text 0xCA26A10`, whose body is [field+0x180] -> ServerActorManager vf30 (vtable 0x5EECE88 + 0x30 =
// FindUser 0x2D11050), handing `out` the same handle vtable 0x5944800 FindUser writes.
constexpr uint8_t kOwnerUserStub3527Bytes[] = {0xE9, 0x8B, 0x41, 0x78, 0x0A};
constexpr uint8_t kOwnerUserStub3549Bytes[] = {0xE9, 0x5B, 0x44, 0x75, 0x0A};  // jmp 0xC9F6CE0
// Its loot caller, inside 0x2E23E30 (reads +0x10, then the user's +0xD8 / +0xD0).
constexpr uint8_t kLootCallCtx3527Bytes[] = {0x48, 0x8D, 0x55, 0x40, 0x48, 0x8B, 0x4D, 0xF0, 0xE8, 0x77, 0xE6, 0x47, 0xFF, 0x90, 0x40, 0x38, 0x7D, 0x50};
// kPolicyVtableCallRets of this build, same order (u2f::kVf40Rets3527 says which is which).
constexpr uint32_t kPolicyVtableCallRets3527[] = {0x2B79B6B, 0x2CD4CB3, 0x2CD5CA1, 0x2EEEA20, 0x2ED751D, 0x2EEE85F, 0x2EEE59D};

// Build 1.0.0.3576 (static, 2026-11-06; not yet run). Every function moved whole: +0xC70 for the server's pieces, +0xC50
// for ExecuteTroc / 0x2AF3A40, +0xD50 for the two rank functions, +0xC40 for the owner's user stub; only rel32 / RIP
// fields differ (the arrays below), the rest is 3527's bytes. Evidence:
// - ServerField vtable 0x5EF2B10 (RTTI, was 0x5EF0908) slots 8/9 = vf40 0x2D98440 / vf48 0x2D984B0; vf48's call is
//   FindUser 0x2D11CC0 (= ServerActorManager vtable 0x5EEF0A8 + 0x30) and both read the user manager slot 0x71C0628
//   (0x2D98452 / 0x2D984C2, the 0x71Bxxxx block's +0x2210).
// - The 2283 handler 0x2CEE250 (TrocTrReloadStageStartReq vtable 0x5EEB478 slot 2): its vf48 call 0x2CEE4F2 calls
//   0x2AF4690 (its rel32 resolves there), return 0x2CEE4F5; the setter's vf48 returns to 0x2E682ED, its store +0x6D0.
// - ExecuteTroc 0x29AD450 (.pdata begins there, 0x38 bytes); rank contexts 0x23F3B99 / 0x23F4C00 (functions 0x23F3A30 /
//   0x23F48B0; their permit calls reach 0x23F6210 / 0x23F5D30, 3527's stubs + 0xD50).
// - The quest event callback 0x2B7A7A0: ServerQuestActorComponent (0x5EE8C80) vfB0 0x2B744B0 registers the thunk
//   0x2B9C660 = `jmp 0x2B7A7A0`. The owner's character 0x2D976B0 (.pdata 0x165 bytes), its DeadActor caller 0x2BB3BC2
//   (same bytes, ret 0x2BB3BD3; the event after it is still 0x6B at 0x2BB3BE2).
// - The owner's user stub 0x22A34C0 (from the loot caller 0x2E24E6C's rel32, ret 0x2E24E79) = `jmp 0xC9C7CA0`, whose
//   body still reads [field+0x180] and calls vf30 of the manager.
// - The event numbers of event_type_name: 0x11 / 0x12 (0x2EEF540 / 0x2EEF589), 0x6B (0x2BB3BE2), 0x6A (0x2BB447A),
//   0x74 (0x2BB3B1E): 3527's.
constexpr uint8_t kVf483576Bytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0x0D, 0x5F, 0x81, 0x42, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0xEF, 0x97, 0xF7, 0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0xE1, 0xD3, 0xD2, 0x02, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0x52, 0x01, 0x88, 0xFE, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
constexpr uint8_t kReload3576CtxBytes[] = {0x48, 0x8B, 0x4D, 0xE8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8D, 0x8D, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x30, 0x48, 0x8D, 0x4D, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x8D, 0x4D, 0xB0, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45, 0xB8, 0x48, 0x8D, 0x55, 0xC0, 0x48, 0x8B, 0xC8, 0xE8, 0x66, 0x61, 0xE0, 0xFF};
constexpr uint8_t kApplyCtx3576Bytes[] = {0x48, 0x8B, 0x4D, 0x07, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8B, 0xD8, 0x48, 0x8D, 0x50, 0x08, 0x48, 0x85, 0xC0, 0x49, 0x0F, 0x44, 0xD5, 0x41, 0xB0, 0x01, 0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4D, 0xE7, 0xE8, 0x06, 0xB9, 0x57, 0xFD, 0x90, 0x48, 0x89, 0x5D, 0xF7, 0x83, 0xCF, 0x02, 0x89, 0x7D, 0xB7, 0xC6, 0x83, 0xD0, 0x06, 0x00, 0x00, 0x00, 0x83, 0xE7, 0xFD, 0x89, 0x7D};
constexpr uint8_t kVf403576Bytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0x0D, 0xCF, 0x81, 0x42, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x5F, 0x98, 0xF7, 0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0x51, 0xD4, 0xD2, 0x02, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xC2, 0x01, 0x88, 0xFE, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
constexpr uint8_t kQuestEventCb3576Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x49, 0x08, 0xE8, 0x98, 0xF5, 0xDB, 0xFE, 0x90, 0x80, 0x7C, 0x24, 0x38, 0x00, 0x74, 0x60, 0x48, 0x8B, 0x4C, 0x24, 0x30, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x40};
constexpr uint8_t kOwnerChar3576Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0xFA, 0x45, 0x33, 0xFF, 0x44, 0x89, 0x7D, 0xB0, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x55, 0xD8, 0x48, 0x8B, 0x0D, 0x3E, 0x8F, 0x42, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x0E, 0xAA, 0xF7, 0xFF, 0x90, 0x4C, 0x8D, 0x35, 0xE6, 0xE1, 0xD2, 0x02, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8B, 0x70, 0x08, 0x48, 0x89, 0x75, 0xC0, 0x0F, 0xB6, 0x58, 0x10, 0x88, 0x5D, 0xC8, 0x0F, 0xB6, 0x48, 0x11, 0x88, 0x4D, 0xC9, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x89, 0x4D, 0xD0, 0x4C, 0x89, 0x78, 0x08, 0x44, 0x88, 0x78, 0x10, 0x4C, 0x8D, 0x25, 0x5D, 0x8D, 0xB6, 0x02, 0x4C, 0x89, 0x65, 0xB8, 0x48, 0x8D, 0x05, 0x42, 0xF2, 0xBA, 0x02, 0x48, 0x89, 0x45, 0xB8, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x8D, 0x4D, 0xD8, 0xE8, 0x19, 0x0F, 0x88, 0xFE, 0x84, 0xDB, 0x75, 0x26, 0x4C, 0x89, 0x37, 0x4C, 0x89, 0x7F, 0x08, 0x66, 0x44, 0x89, 0x7F, 0x10, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x27, 0x48, 0x8D, 0x05, 0x0B, 0x0E, 0xC4, 0x02, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x7A, 0x48, 0x8B, 0x9E, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x74, 0x1F, 0xBA, 0x04, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x03, 0x48, 0x8B, 0xCB, 0xFF, 0x90, 0xC0, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x04, 0xB1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x89, 0x5D, 0xE0, 0x88, 0x4D, 0xE8, 0xC6, 0x45, 0xE9, 0x00, 0x4C, 0x89, 0x7D, 0xF0, 0x4C, 0x89, 0x65, 0xD8, 0x48, 0x8D, 0x05, 0xB4, 0x0D, 0xC4, 0x02, 0x48, 0x89, 0x45, 0xD8, 0x4C, 0x89, 0x37, 0x48, 0x89, 0x5F, 0x08, 0x88, 0x4F, 0x10, 0xC6, 0x47, 0x11, 0x00, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x7D, 0xE0, 0xC6, 0x45, 0xE8, 0x00, 0x4C, 0x89, 0x27, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x75, 0xD8, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8D, 0x4D, 0xB8, 0xE8, 0x68, 0x0E, 0x88, 0xFE, 0x48, 0x8B, 0xC7, 0x4C, 0x8D, 0x5C, 0x24, 0x70, 0x49, 0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73, 0x40, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0x5F, 0x5D, 0xC3};
constexpr uint8_t kOwnerUserStub3576Bytes[] = {0xE9, 0xDB, 0x47, 0x72, 0x0A};  // jmp 0xC9C7CA0
constexpr uint8_t kLootCallCtx3576Bytes[] = {0x48, 0x8D, 0x55, 0x40, 0x48, 0x8B, 0x4D, 0xF0, 0xE8, 0x47, 0xE6, 0x47, 0xFF, 0x90, 0x40, 0x38, 0x7D, 0x50};
// kPolicyVtableCallRets3527 + 0xC70 each, same order: every one is `call [rax+0x40]` at the same offset of its function,
// whose start is its Troc's vtable slot 2 (2477 0x2CD55E0, 2354 0x2CD67D0, 2051 0x2ED8110) or is called from it (2369
// 0x2CD6AA0 -> 0x2EEF640, 2112 0x2CD5E90 -> 0x2EEF470, 2372 0x2CD5BD0 -> 0x2EEF1B0).
constexpr uint32_t kPolicyVtableCallRets3576[] = {0x2B7A7DB, 0x2CD5923, 0x2CD6911, 0x2EEF690, 0x2ED818D, 0x2EEF4CF, 0x2EEF20D};
constexpr uint32_t kReloadVf48Ret3576 = 0x2CEE4F5, kApplyVf48Ret3576 = 0x2E682ED;
// Build 1.0.0.3663 (static, 2026-11-13; never run). Each piece found by its 3527/3576 bytes (relative fields masked) searched
// over the whole code section: one hit each, at the same offset inside its function as in 3576. Only rel32 / RIP fields
// differ, EXCEPT the setter's store: `mov byte [rbx+0x6D8],0` (3576 +0x6D0; kApplyCtx3663Bytes, kMgrApplyByte). Evidence:
// - ServerField vtable 0x5F6C7E8 (RTTI, 3576 0x5EF2B10) slots 8/9 = vf40 0x2DFF2F0 / vf48 0x2DFF360; both call FindUser
//   0x2D78C20 (= ServerActorManager vtable 0x5F69100 slot 6, kFindUserBytes identical) and read the user manager slot
//   0x72456F0 (0x2DFF302 / 0x2DFF372; 3576 +0x850C8, like the server net slot). [[[[u+0xD0]+0x68]+0x138/+0xA8]+0x18] same.
// - ReloadStageStartReq vtable 0x5F650F8 slot 2 = the 2283 handler 0x2D55170; its vf48 call 0x2D55412 (ctx 0x2D5540B,
//   +0x29B as in 3576) returns to 0x2D55415, then calls 0x2B586B0 (kApplyReload3527Bytes identical there). The setter
//   0x2ED00D0's vf48 returns to 0x2ED02CD (ctx 0x2ED02C3, +0x1F3 as in 3576); the setter takes TS+0x508 (0x2ED02B0).
// - ExecuteTroc 0x2A0FA80 (kExecuteTroc3527Bytes identical, .pdata starts there); rank contexts 0x2465449 / 0x24664B0
//   (functions 0x24652E0 / 0x2466160, the same +0x169 / +0x350; kRankCtx1/2 3527 bytes identical, rel32 included).
// - The quest event callback 0x2BE0710: ServerQuestActorComponent (0x5F62888) vfB0 0x2BDA410 registers the thunk
//   0x2C021A0 = `jmp 0x2BE0710`. The owner's character 0x2DFE560 (.pdata 0x165 bytes), its DeadActor caller 0x2C19612
//   (function 0x2C194E0, +0x132 as in 3576; ret 0x2C19623).
// - The owner's user stub 0x2313BE0 (from the loot caller 0x2E8C61C's rel32, ret 0x2E8C629) = `jmp 0xCE17140`, whose body
//   still reads [field+0x180] (0xCE17186) and calls vf30 of the manager (0xCE17192).
// - The event numbers moved by one from 0x6A: DeadActor 0x6C (0x2C19632, after the DeadActor caller), PlayerDead 0x75
//   (0x2C1956E), KillActor 0x6B (0x2C19ECA), each at its 3576 offset in 0x2C194E0; 0x11 / 0x12 unchanged (0x2F57780 /
//   0x2F577C9 in 0x2F576B0). The event's actor key is still +0x68 (the emit 0x19A9BDC, +0x5C as in 3527's 0x194352C).
// - Troc instances 0x6F14E10..0x6F48840 (troc_mapping_3576_3663.json); u16 opcode +0x0C (0x6F43980 holds 3018, the
//   ReloadStageStartReq native id). The opcodes the logic speaks are logical (native_opcode::decode).
constexpr uint8_t kVf483663Bytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0x0D, 0x77, 0x63, 0x44, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x9F, 0x98, 0xF7, 0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0x51, 0x0C, 0xD4, 0x02, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xC2, 0x9F, 0x85, 0xFE, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
constexpr uint8_t kReload3663CtxBytes[] = {0x48, 0x8B, 0x4D, 0xE8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8D, 0x8D, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x30, 0x48, 0x8D, 0x4D, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x8D, 0x4D, 0xB0, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45, 0xB8, 0x48, 0x8D, 0x55, 0xC0, 0x48, 0x8B, 0xC8, 0xE8, 0x66, 0x32, 0xE0, 0xFF};
constexpr uint8_t kApplyCtx3663Bytes[] = {0x48, 0x8B, 0x4D, 0x07, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48, 0x8B, 0xD8, 0x48, 0x8D, 0x50, 0x08, 0x48, 0x85, 0xC0, 0x49, 0x0F, 0x44, 0xD5, 0x41, 0xB0, 0x01, 0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4D, 0xE7, 0xE8, 0xB6, 0x48, 0x51, 0xFD, 0x90, 0x48, 0x89, 0x5D, 0xF7, 0x83, 0xCF, 0x02, 0x89, 0x7D, 0xB7, 0xC6, 0x83, 0xD8, 0x06, 0x00, 0x00, 0x00, 0x83, 0xE7, 0xFD, 0x89, 0x7D};
constexpr uint8_t kVf403663Bytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0x0D, 0xE7, 0x63, 0x44, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0x0F, 0x99, 0xF7, 0xFF, 0x90, 0x80, 0x7C, 0x24, 0x30, 0x00, 0x75, 0x04, 0x33, 0xDB, 0xEB, 0x1B, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x88, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18, 0x48, 0x8D, 0x05, 0xC1, 0x0C, 0xD4, 0x02, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0x32, 0xA0, 0x85, 0xFE, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3};
constexpr uint8_t kQuestEventCb3663Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x49, 0x08, 0xE8, 0x08, 0xF1, 0xDB, 0xFE, 0x90, 0x80, 0x7C, 0x24, 0x38, 0x00, 0x74, 0x60, 0x48, 0x8B, 0x4C, 0x24, 0x30, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x40};
constexpr uint8_t kOwnerChar3663Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0xFA, 0x45, 0x33, 0xFF, 0x44, 0x89, 0x7D, 0xB0, 0x44, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x55, 0xD8, 0x48, 0x8B, 0x0D, 0x56, 0x71, 0x44, 0x04, 0x48, 0x8B, 0x09, 0xE8, 0xBE, 0xAA, 0xF7, 0xFF, 0x90, 0x4C, 0x8D, 0x35, 0x56, 0x1A, 0xD4, 0x02, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8B, 0x70, 0x08, 0x48, 0x89, 0x75, 0xC0, 0x0F, 0xB6, 0x58, 0x10, 0x88, 0x5D, 0xC8, 0x0F, 0xB6, 0x48, 0x11, 0x88, 0x4D, 0xC9, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x89, 0x4D, 0xD0, 0x4C, 0x89, 0x78, 0x08, 0x44, 0x88, 0x78, 0x10, 0x4C, 0x8D, 0x25, 0x85, 0xDC, 0xB7, 0x02, 0x4C, 0x89, 0x65, 0xB8, 0x48, 0x8D, 0x05, 0x9A, 0x3F, 0xBC, 0x02, 0x48, 0x89, 0x45, 0xB8, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x8D, 0x4D, 0xD8, 0xE8, 0x89, 0xAD, 0x85, 0xFE, 0x84, 0xDB, 0x75, 0x26, 0x4C, 0x89, 0x37, 0x4C, 0x89, 0x7F, 0x08, 0x66, 0x44, 0x89, 0x7F, 0x10, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x27, 0x48, 0x8D, 0x05, 0xFB, 0x5C, 0xC5, 0x02, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x7A, 0x48, 0x8B, 0x9E, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x74, 0x1F, 0xBA, 0x04, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x03, 0x48, 0x8B, 0xCB, 0xFF, 0x90, 0xC0, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x04, 0xB1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 0x4C, 0x89, 0x75, 0xD8, 0x48, 0x89, 0x5D, 0xE0, 0x88, 0x4D, 0xE8, 0xC6, 0x45, 0xE9, 0x00, 0x4C, 0x89, 0x7D, 0xF0, 0x4C, 0x89, 0x65, 0xD8, 0x48, 0x8D, 0x05, 0xA4, 0x5C, 0xC5, 0x02, 0x48, 0x89, 0x45, 0xD8, 0x4C, 0x89, 0x37, 0x48, 0x89, 0x5F, 0x08, 0x88, 0x4F, 0x10, 0xC6, 0x47, 0x11, 0x00, 0x4C, 0x89, 0x7F, 0x18, 0x4C, 0x89, 0x7D, 0xE0, 0xC6, 0x45, 0xE8, 0x00, 0x4C, 0x89, 0x27, 0x48, 0x89, 0x07, 0xC7, 0x45, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x75, 0xD8, 0x4C, 0x89, 0x75, 0xB8, 0x48, 0x8D, 0x4D, 0xB8, 0xE8, 0xD8, 0xAC, 0x85, 0xFE, 0x48, 0x8B, 0xC7, 0x4C, 0x8D, 0x5C, 0x24, 0x70, 0x49, 0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73, 0x40, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0x5F, 0x5D, 0xC3};
constexpr uint8_t kDeadCallCtx3663Bytes[] = {0x48, 0x8D, 0x54, 0x24, 0x78, 0x48, 0x8B, 0x8D, 0x98, 0x00, 0x00, 0x00, 0xE8, 0x3D, 0x4F, 0x1E, 0x00, 0x90, 0x80, 0x7D, 0x88, 0x00};
constexpr uint8_t kOwnerUserStub3663Bytes[] = {0xE9, 0x5B, 0x35, 0xB0, 0x0A};
constexpr uint8_t kLootCallCtx3663Bytes[] = {0x48, 0x8D, 0x55, 0x40, 0x48, 0x8B, 0x4D, 0xF0, 0xE8, 0xB7, 0x75, 0x48, 0xFF, 0x90, 0x40, 0x38, 0x7D, 0x50};
// kPolicyVtableCallRets3576's callers on 3663, same order, each `call [rax+0x40]` at the same offset of its function as
// in 3576: the quest event callback 0x2BE0710 +0x3B; the handlers by their Troc's vtable slot 2: 2477 0x2D3C060 +0x343,
// 2354 0x2D3D250 +0x141, 2051 0x2F40530 +0x7D; called from them: 2369 0x2D3D520 -> 0x2F57880 +0x50, 2112 0x2D3C910 ->
// 0x2F576B0 +0x5F, 2372 0x2D3C650 -> 0x2F573F0 +0x5D.
constexpr uint32_t kPolicyVtableCallRets3663[] = {0x2BE074B, 0x2D3C3A3, 0x2D3D391, 0x2F578D0, 0x2F405AD, 0x2F5770F, 0x2F5744D};
constexpr uint32_t kReloadVf48Ret3663 = 0x2D55415, kApplyVf48Ret3663 = 0x2ED02CD;
std::span<const uint8_t> g_exec_troc_bytes{kExecuteTrocBytes}, g_vf48_bytes{kVf48Bytes}, g_reload_ctx_bytes{kReloadCallCtxBytes},
    g_apply_reload_bytes{kApplyReloadBytes}, g_apply_ctx_bytes{kApplyCallCtxBytes}, g_rank_ctx1_bytes{kRankCtx1Bytes},
    g_rank_ctx2_bytes{kRankCtx2Bytes}, g_vf40_bytes{kVf40Bytes}, g_quest_event_bytes{kQuestEventCbBytes},
    g_owner_char_bytes{kOwnerCharBytes}, g_dead_ctx_bytes{kDeadCallCtxBytes}, g_owner_stub_bytes{kOwnerUserStubBytes},
    g_loot_ctx_bytes{kLootCallCtxBytes};
std::span<const uint32_t> g_policy_vtable_rets{kPolicyVtableCallRets};

// RTTI (p8-sistemas-juego.md §2.1, §11.5).
uintptr_t kVtServerNormalInGameActor = 0x5B1DE20;
// The users' characters ([user+0xD0/+0xD8/+0xE0]) are ServerChildOnlyInGameActor (measured: user 2's Reqs carry it).
uintptr_t kVtServerChildOnlyInGameActor = 0x5B1E2B0;
uintptr_t kVtServerQuestActorComponent = 0x5B1F8F8;
uintptr_t kVtServerQuestManager = 0x5B1FA48;
// Troc handler instances (offsets_s2.h): u16 opcode +0x0C.
uintptr_t kTrocInstancesBegin = 0x6A51AE0;
uintptr_t kTrocInstancesEnd = 0x6A82C80;
constexpr uint32_t kTrocOpcode = 0x0C;

constexpr uint32_t kActorKey = 0x60;
constexpr uint32_t kActorController = 0x90;
constexpr uint32_t kFieldOwner = 0x180;
constexpr uint32_t kHandleObject = 0x08;
constexpr uint32_t kHandleLocked = 0x10;

constexpr uint64_t kEventsPerFunnel = 40;  // detailed lines per funnel/site, then counts only
constexpr uint64_t kEventsPerRankSite = 20;

// ---------------------------------------------------------------- state

std::atomic<bool> g_started{false}, g_on{false};
std::atomic<uint8_t> g_rank_mode{0}, g_quest_mode{0}, g_kill_mode{0};
// quest_policy (user2_funnels_logic.h): its decisions per vf40 caller, its ingress drops and what it measures.
std::atomic<uint8_t> g_policy_mode{0};
constexpr size_t kPolicyCallers = static_cast<size_t>(u2f::PolicyCaller::Count);
constexpr size_t kPolicyOuts = static_cast<size_t>(u2f::PolicyOut::Count);
std::atomic<uint64_t> g_policy_outs[kPolicyCallers][kPolicyOuts] = {};
// The ingress, per Req (counted once, on its final disposition): [0] in the host's field, [1] anywhere else.
std::atomic<uint64_t> g_trigger_reqs[2] = {}, g_trigger_own{0}, g_trigger_host{0};
u2f::SiteCounts<64> g_trigger_ids;  // the 2112's first u32 (log only: its meaning is not read yet)
// 2372 / 2477 / 2354 (index 0 / 1 / 2): seen [where], dropped, would drop, route failures.
constexpr uint16_t kOwnReqOps[3] = {u2f::kOpTraceMission, u2f::kOpMissionUiState, u2f::kOpMissionNewAlarm};
std::atomic<uint64_t> g_own_reqs[3][2] = {}, g_own_dropped[3] = {}, g_own_would_drop[3] = {};
std::atomic<uint64_t> g_own_route_fail[3][static_cast<size_t>(u2f::RouteFail::Count)] = {};
// 2369: seen [where], dropped, would drop.
std::atomic<uint64_t> g_change_reqs[2] = {}, g_change_dropped{0}, g_change_would_drop{0};
// 2342 / 2857 / 2436 / 2591 of user 2 (measured only): [op][where][handed].
constexpr uint16_t kMeasuredOps[4] = {u2f::kOpQuestDialogEnd, u2f::kOpSetQuestDialog, u2f::kOpStageBranchState,
                                      u2f::kOpUpdateStageChartEvent};
std::atomic<uint64_t> g_measured[4][2][2] = {};
// DeadActor kept native by quest_policy=1 (kill_loot_per_user would have given it to user 2) / would (probe).
std::atomic<uint64_t> g_dead_policy_kept{0}, g_dead_policy_would{0};
// The probe at the quest component's event callback 0x290DBD0 (quest_policy probe/1): user 2's character's events.
std::atomic<bool> g_qevent_on{false};
std::atomic<uint64_t> g_qevent_types[256] = {};
std::atomic<uint64_t> g_qevent_actor[static_cast<size_t>(u2f::EventActor::Count)] = {};
std::atomic<uint64_t> g_qevent_subject[2] = {};  // [0] outside a Req of user 2, [1] inside one (its 2052 usually)
std::atomic<uint64_t> g_qevent_host{0}, g_qevent_unreadable{0};
std::atomic<uint32_t> g_host_char{0};  // the host's main character key (the thread, every 100 ms)
// The host client's quest Acks (sniffer, S>C): 3009 / 3088 / 2738 / 2346.
std::atomic<uint64_t> g_host_acks[4] = {};
// F3: the mode (ftl::Mode) and whether its pieces are in place (vf48 and the subject hooked, the call site checked).
std::atomic<uint8_t> g_ft_mode{0};
std::atomic<bool> g_ft_on{false};
// F4 (P8 S28): user 2's 2362 at the reload setter's vf48. g_f4_on: vf48 hooked, the subject in, the setter's call
// site verified.
std::atomic<uint8_t> g_f4_mode{0};
std::atomic<bool> g_f4_on{false};
std::array<std::atomic<uint64_t>, static_cast<size_t>(ftl::F4Out::Count)> g_f4_outs{};
std::atomic<uint64_t> g_f4_events{0};
constexpr uint64_t kReviveEvents = 64;
uintptr_t g_vt_seqmgr = 0;
std::array<std::atomic<uint64_t>, static_cast<size_t>(ftl::F3Out::Count)> g_ft_outs{};
std::array<std::atomic<uint64_t>, static_cast<size_t>(ftl::MgrFail::Count)> g_ft_fails{};
std::atomic<uint64_t> g_ft_events{0};
// The thunk changes nothing until BOTH call sites are patched (a site left patched by a failed install answers as the original).
std::atomic<bool> g_rank_live{false};
// The last vtable seen on an actor with user 2's keys that is not a character class (for the summary).
std::atomic<uintptr_t> g_wrong_class_vt{0};
bool g_rank_on = false, g_subject_on = false, g_vf40_on = false, g_vf48_on = false, g_finduser_on = false,
     g_dead_on = false, g_loot_on = false;
uintptr_t g_base = 0;
std::vector<gad::Section> g_secs;

// The keys (written by the thread every 100 ms, read by the hooks).
std::atomic<bool> g_live{false};
std::atomic<uint32_t> g_u2_user{0}, g_u2_char{0}, g_host_user{0};

// C, DeadActor: the field the original 0x2AFFF50 is given instead of the shared
// one. It reads only u32 +0x180 (verified above); zero elsewhere. Written by the
// thread (an aligned 4-byte store) when user 2's user key changes.
alignas(64) volatile uint32_t g_fake_field[0x200 / 4] = {};
constexpr size_t kFakeOwnerIndex = kFieldOwner / 4;

uintptr_t g_ret_dead = 0, g_ret_loot = 0, g_ret_rank[2] = {}, g_vt_actor = 0, g_vt_actor2 = 0, g_vt_qcomp = 0, g_vt_qmgr = 0,
          g_trocs_begin = 0, g_trocs_end = 0, g_find_user = 0, g_user_mgr_slot = 0;
uint32_t g_patch[u2f::kFunnels + 1] = {};

SafetyHookInline g_troc, g_vf40, g_vf48, g_finduser, g_dead, g_loot, g_qevent;
safetyhook::Allocation g_rank_stub;
bool g_rank_patched[2] = {};

// The Req of user 2 this server thread is inside (0 = none). F3 arms the last two when it answers the 2283's first
// vf48 (0x2A5F7FC); the Troc's Restore puts the outer frame back, so they never outlive that Req.
struct Frame {
    uintptr_t actor = 0;
    uint16_t opcode = 0;
    uintptr_t ft_mgr = 0;   // F3 returned user 2's real manager: the second vf48 (0x2BC4C53) gets it too
    bool ft_block = false;  // F3 returned the substitute block: the second vf48 keeps the original (ERR)
    bool ft_applied = false;  // the second vf48 (inside the setter 0x2BC4950) was reached in this Troc (travel probe)
    uint8_t f4 = 0;           // F4 (P8 S28): 1 + ftl::F4Out of the setter's vf48 in this Troc (0 = not reached)
    // U2 (user2_shops.h): a scene Req / the 2044 timer, any subject: its opcode and the packet's sequencer id.
    uint16_t scene_op = 0;
    uint64_t scene_id = 0;
    bool scene_mine = false;  // its site found the id in user 2's manager (routed, or would in probe)
};
thread_local Frame t_frame{};
// F3's substitute block (fast_travel_logic.h kSubstituteBlock): +0x18 = the subject, the rest zero. Per thread, used
// only while that thread runs the 2283's 0x2896120 (synchronous).
thread_local alignas(16) uintptr_t t_ft_block[ftl::kSubstituteBlock / sizeof(uintptr_t)] = {};
// F3, the second vf48 and any other vf48 seen while a 2283 of user 2 is applied (diagnostics).
std::array<std::atomic<uint64_t>, static_cast<size_t>(ftl::ApplyOut::Count)> g_ft_apply{};
u2f::SiteCounts<16> g_ft_other_vf48;

// Counters.
struct RankSite {
    std::atomic<uint64_t> calls{0}, other_arg{0}, not_user2{0}, reached{0}, orig_true{0}, would{0}, no_comp{0},
        overrides{0}, events{0};
};
RankSite g_rank_site[2];
std::atomic<uint64_t> g_rank_other_site{0};

std::atomic<uint64_t> g_reqs_total{0}, g_reqs_user2{0};
std::array<std::atomic<uint64_t>, 7> g_subject_verdicts{};
u2f::OpCounts g_req_ops;
u2f::FunnelCounters g_fc[u2f::kFunnels];
std::atomic<uint64_t> g_fc_events[u2f::kFunnels] = {};
u2f::SiteCounts<64> g_vf40_callers, g_vf48_callers, g_finduser_callers, g_dead_other_callers, g_loot_other_callers;
std::atomic<uint64_t> g_fu_host{0}, g_fu_user2{0}, g_fu_other{0};
std::array<std::atomic<uint64_t>, 6> g_chain_fail{};

p8p::EventRing<512> g_ring;
constexpr uint16_t kEvRank = 1, kEvFunnel = 2, kEvFastTravel = 3, kEvFastApply = 4, kEvRevive = 5, kEvPolicy = 6;
constexpr uint64_t kFastTravelEvents = 64;  // F3 lines (each one is a fast travel of user 2: rare)

// ---------------------------------------------------------------- reads on the game's threads

struct FastMem {
    bool u32(uintptr_t a, uint32_t& v) const noexcept { return game::fast_read(a, &v, sizeof v); }
    bool ptr(uintptr_t a, uintptr_t& v) const noexcept {
        uintptr_t p = 0;
        if (!game::fast_read(a, &p, sizeof p)) return false;
        if (p && (p < 0x10000 || p > 0x00007FFFFFFFFFFFull)) return false;
        v = p;
        return true;
    }
};

u2f::Keys keys_now() noexcept {
    u2f::Keys k;
    k.live = g_live.load(std::memory_order_relaxed);
    k.user2_user = g_u2_user.load(std::memory_order_relaxed);
    k.user2_char = g_u2_char.load(std::memory_order_relaxed);
    k.host_user = g_host_user.load(std::memory_order_relaxed);
    return k;
}

bool g_is_3527 = false;  // 3527's layout: 3527, 3549, 3576 and 3663 (3663: the setter's store +0x6D8, kMgrApplyByte)
bool g_is_3576 = false;  // 3576's addresses
bool g_is_3663 = false;  // 3663's addresses

uint32_t rva_of(uintptr_t a) noexcept {
    const uint32_t r = a >= g_base && a - g_base < 0x80000000ull ? static_cast<uint32_t>(a - g_base) : 0;
    if (g_is_3663) {  // the same mapping from this build's return addresses
        if (r == kReloadVf48Ret3663) return ftl::kReloadVf48Ret;
        if (r == kApplyVf48Ret3663) return ftl::kApplyVf48Ret;
        return u2f::vf40_ret_of_3663(r);
    }
    if (g_is_3576) {  // the same mapping from this build's return addresses
        if (r == kReloadVf48Ret3576) return ftl::kReloadVf48Ret;
        if (r == kApplyVf48Ret3576) return ftl::kApplyVf48Ret;
        return u2f::vf40_ret_of_3576(r);
    }
    if (g_is_3527) {  // the logic and the lines speak the 2976 return addresses
        if (r == kReloadVf48Ret3527) return ftl::kReloadVf48Ret;
        if (r == kApplyVf48Ret3527) return ftl::kApplyVf48Ret;
        return u2f::vf40_ret_of_3527(r);
    }
    return r;
}

uint32_t key_at(uintptr_t actor) noexcept {
    uint32_t k = 0;
    return actor && game::fast_read(actor + kActorKey, &k, sizeof k) ? k : 0;
}

void push_event(uint16_t kind, std::initializer_list<uint64_t> v) noexcept {
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kind;
    size_t i = 0;
    for (uint64_t x : v) {
        if (i < 12) e.v[i++] = x;
    }
    g_ring.push(e);  // full: counted by the ring, never blocks
}

// ---------------------------------------------------------------- A: the vf188 thunk (host's client)

uint8_t rank_after(uintptr_t actor, uint64_t rdx, uint8_t orig_raw, uintptr_t ret) noexcept {
    const bool orig = orig_raw != 0;
    const int site = ret == g_ret_rank[0] ? 0 : ret == g_ret_rank[1] ? 1 : -1;
    if (site < 0) {
        g_rank_other_site.fetch_add(1, std::memory_order_relaxed);
        return orig ? 1 : 0;
    }
    RankSite& s = g_rank_site[site];
    s.calls.fetch_add(1, std::memory_order_relaxed);
    u2f::RankIn in;
    in.mode = g_rank_live.load(std::memory_order_acquire) ? static_cast<Mode>(g_rank_mode.load(std::memory_order_relaxed))
                                                          : Mode::Off;
    in.keys = keys_now();
    in.arg = static_cast<uint8_t>(rdx & 0xFF);
    in.orig = orig;
    if (in.arg != 5) s.other_arg.fetch_add(1, std::memory_order_relaxed);
    if (in.arg == 5 && u2f::keys_for_rank(in.keys)) {
        // The key first: the controller only for user 2's character.
        in.read_ok = game::fast_read(actor + kActorKey, &in.key, sizeof in.key);
        if (in.read_ok && in.key == in.keys.user2_char) {
            in.read_ok = game::fast_read(actor + kActorController, &in.controller, sizeof in.controller);
        }
        if (in.read_ok && in.mode == Mode::On && !orig && u2f::is_user2_character(in.keys, in.key, in.controller)) {
            uintptr_t comps = 0, comp = 0;
            const FastMem m;
            in.target_comp = m.ptr(actor + u2f::kActorComponents, comps) && comps &&
                             m.ptr(comps + kActorTargetComp, comp) && comp;
        }
    }
    const u2f::RankDecision d = u2f::decide_rank(in);
    switch (d.what) {
        case u2f::RankOut::NotUser2: s.not_user2.fetch_add(1, std::memory_order_relaxed); break;
        case u2f::RankOut::OrigTrue: s.orig_true.fetch_add(1, std::memory_order_relaxed); break;
        case u2f::RankOut::Would: s.would.fetch_add(1, std::memory_order_relaxed); break;
        case u2f::RankOut::NoComp: s.no_comp.fetch_add(1, std::memory_order_relaxed); break;
        case u2f::RankOut::Override: s.overrides.fetch_add(1, std::memory_order_relaxed); break;
        case u2f::RankOut::Pass: break;
    }
    if (d.user2) {
        s.reached.fetch_add(1, std::memory_order_relaxed);
        if (s.events.fetch_add(1, std::memory_order_relaxed) < kEventsPerRankSite) {
            push_event(kEvRank, {static_cast<uint64_t>(site), orig ? 1u : 0u, d.result ? 1u : 0u, in.key,
                                 static_cast<uint64_t>(d.what), static_cast<uint64_t>(in.mode)});
        }
    }
    return d.result ? 1 : 0;
}

// Reached through `call rel32` (0x221E281 / 0x221F29F) and the stub's `jmp [rip]`:
// rcx = X, dl = 5, the caller's frame untouched (the same stack as its own
// `call [rax+0x188]`). Calls the original virtual exactly as the caller did.
uint8_t rank_vf188_thunk(uintptr_t actor, uint64_t rdx) {
    using Vf188 = uint8_t (*)(uintptr_t, uint64_t);
    const uintptr_t vt = *reinterpret_cast<const uintptr_t*>(actor);  // the caller's own `mov rax,[rX]`
    const auto fn = *reinterpret_cast<const Vf188*>(vt + kVf188);
    const uint8_t orig = fn(actor, rdx);
    return rank_after(actor, rdx, orig, reinterpret_cast<uintptr_t>(_ReturnAddress()));
}

// ---------------------------------------------------------------- the subject (host's server)

void subject_enter(uintptr_t troc, uintptr_t params, Frame& now) noexcept {
    const u2f::Keys k = keys_now();
    if (!k.live) return;  // nobody to look for: no reads, no counts
    g_reqs_total.fetch_add(1, std::memory_order_relaxed);
    u2f::SubjectIn in;
    in.on = true;
    in.keys = k;
    in.expected_vtable = g_vt_actor;
    in.expected_vtable2 = g_vt_actor2;
    in.params_ok = params && game::fast_read(params, &in.actor, sizeof in.actor);
    if (in.params_ok && in.actor) {
        in.read_ok = game::fast_read(in.actor + kActorKey, &in.key, sizeof in.key);
        if (in.read_ok && in.key == k.user2_char) {
            in.read_ok = game::fast_read(in.actor + kActorController, &in.controller, sizeof in.controller) &&
                         game::fast_read(in.actor, &in.vtable, sizeof in.vtable);
        }
    }
    const u2f::SubjectVerdict v = u2f::decide_subject(in);
    g_subject_verdicts[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    if (v == u2f::SubjectVerdict::WrongClass) g_wrong_class_vt.store(in.vtable, std::memory_order_relaxed);
    if (v != u2f::SubjectVerdict::Subject) return;
    uint16_t op = 0;
    if (troc >= g_trocs_begin && troc < g_trocs_end) game::fast_read(troc + kTrocOpcode, &op, sizeof op);
    op = native_opcode::decode(game::current_build(), op).value_or(0);
    now.actor = in.actor;
    now.opcode = op;
    g_reqs_user2.fetch_add(1, std::memory_order_relaxed);
    g_req_ops.add(op);
}

// U2 (user2_shops.h, user2_shops_logic.h kSites): a scene Req or the 2044 timer, whoever the subject is: the Troc's
// opcode (its static instance) and the u64 sequencer id from its packet (TrocParams +0x18, its u16 size at +0x10),
// guarded reads. Nothing else is read for any other Troc.
void scene_enter(uintptr_t troc, uintptr_t params, Frame& now) noexcept {
    if (!user2_shops_wanted() || troc < g_trocs_begin || troc >= g_trocs_end) return;
    uint16_t op = 0;
    if (!game::fast_read(troc + kTrocOpcode, &op, sizeof op)) return;
    op = native_opcode::decode(game::current_build(), op).value_or(0);
    if (!u2sh::site_of(op)) return;
    uintptr_t packet = 0;
    uint16_t size = 0;
    uint8_t head[16] = {};
    if (!params || !game::fast_read(params + 0x18, &packet, sizeof packet) || !packet ||
        !game::fast_read(params + 0x10, &size, sizeof size)) {
        return;
    }
    const size_t n = std::min<size_t>(size, sizeof head);
    if (n < 11 || !game::fast_read(packet, head, n)) return;
    uint64_t id = 0;
    if (!u2sh::scene_id(op, std::span<const uint8_t>(head, n), id)) return;
    now.scene_op = op;
    now.scene_id = id;
}

// ---------------------------------------------------------------- the travel probe (travel_probe.h), read only

constexpr uint32_t kUserMainCharacter = 0xD0;
constexpr uint32_t kComponentsTransformSync = 0x1A0;
uint32_t kTsPending = 0x550, kTsBranch18 = 0x568, kTsBranch19 = 0x569, kTsArmed = 0x591;  // 3527: FieldMover + 0x18
uint32_t kMgrApplyByte = 0x6A0;  // 0x2BC4C80 mov byte [rbx+0x6A0],0 (3527: 0x2E676A5, +0x6D0)

tpl::TsSnap ts_snap(uintptr_t actor) noexcept {
    tpl::TsSnap s;
    const FastMem m;
    uintptr_t comps = 0, ts = 0;
    if (!actor || !m.ptr(actor + u2f::kActorComponents, comps) || !comps || !m.ptr(comps + kComponentsTransformSync, ts) ||
        !ts) {
        return s;
    }
    s.ok = game::fast_read(ts + kTsPending, &s.pending, sizeof s.pending) &&
           game::fast_read(ts + kTsBranch18, &s.f568, 1) && game::fast_read(ts + kTsBranch19, &s.f569, 1) &&
           game::fast_read(ts + kTsArmed, &s.armed, 1);
    return s;
}

// The host's main character, by reads only ([session 1's user +0xD0]).
uintptr_t host_character() noexcept {
    uintptr_t host = 0, pj = 0;
    const FastMem m;
    return server_host_user(host) && host && m.ptr(host + kUserMainCharacter, pj) ? pj : 0;
}

// The field owner's sequencer manager, by reads only (never FindUser, never the original vf48): only when the owner
// is the host's user, through the host's character.
uintptr_t owners_manager_read(uint32_t owner) noexcept {
    if (!owner || owner != g_host_user.load(std::memory_order_relaxed)) return 0;
    return ftl::seq_manager_of(FastMem{}, host_character(), g_vt_seqmgr).value_or(0);
}

void travel_context(const Frame& fr, uint32_t ret_rva, uint32_t owner, uintptr_t selected, uint64_t what) noexcept {
    if (!travel_probe_on()) return;
    const uintptr_t owners = owners_manager_read(owner);
    uintptr_t sel_actor = 0, own_actor = 0;
    if (selected) game::fast_read(selected + ftl::kManagerActor, &sel_actor, sizeof sel_actor);
    if (owners) game::fast_read(owners + ftl::kManagerActor, &own_actor, sizeof own_actor);
    const uint64_t v[] = {travel_probe_trip(), ret_rva, key_at(fr.actor), owner, owners, selected,
                          key_at(sel_actor), what, key_at(own_actor)};
    travel_probe_push(kTravelContext, v);
}

// Around ExecuteTroc of user 2's 2283 (TravelPrepared) or 2437 (TravelConsume): snapshots before and after, the
// Troc's result (*res, ExecuteTroc 0x2774B36 `mov [rbx],ecx`). Nothing is written.
uintptr_t troc_travel(uintptr_t res, uintptr_t troc, uintptr_t params, uintptr_t r9, const Frame& now) {
    // P8 S27: a revive's ReviveLoadingReq 2362 is read like a 2283 (both arm user 2's TS before its 2437).
    const bool revive = now.opcode == tpl::kOpReviveLoadingReq;
    const bool reload = now.opcode == tpl::kOpReloadStageStartReq || revive;
    const uint32_t trip = travel_probe_open_window(now.opcode);
    const uintptr_t host_pj = reload ? host_character() : 0;
    const uintptr_t host_mgr = host_pj ? ftl::seq_manager_of(FastMem{}, host_pj, g_vt_seqmgr).value_or(0) : 0;
    uint8_t b6a0 = 0, a6a0 = 0;
    const bool mgr_before = host_mgr && game::fast_read(host_mgr + kMgrApplyByte, &b6a0, 1);
    const tpl::TsSnap u2_before = ts_snap(now.actor);
    const tpl::TsSnap host_before = reload ? ts_snap(host_pj) : tpl::TsSnap{};
    const uintptr_t r = g_troc.unsafe_call<uintptr_t>(res, troc, params, r9);
    const Frame after = t_frame;  // F3 armed it during the call; the Restore puts the outer frame back on return
    const tpl::TsSnap u2_after = ts_snap(now.actor);
    uint32_t result = 0;
    const bool result_ok = res && game::fast_read(res, &result, sizeof result);
    if (revive) {
        // P8 S27 (read only): what the revive's 2362 set - user 2's TS, and whether the host's TS or manager moved.
        const tpl::TsSnap host_after = ts_snap(host_pj);
        const bool mgr_ok = mgr_before && game::fast_read(host_mgr + kMgrApplyByte, &a6a0, 1);
        const uint64_t v[] = {trip,
                              key_at(now.actor),
                              tpl::pack(u2_before),
                              tpl::pack(u2_after),
                              tpl::pack(host_before),
                              tpl::pack(host_after),
                              (mgr_ok ? 1u : 0u) | (static_cast<uint64_t>(b6a0) << 8) | (static_cast<uint64_t>(a6a0) << 16),
                              result,
                              result_ok ? 1u : 0u,
                              after.f4};  // F4 (P8 S28): 1 + ftl::F4Out at the setter's vf48, 0 = not reached
        travel_probe_push(kTravelRevive, v);
    } else if (reload) {
        const tpl::TsSnap host_after = ts_snap(host_pj);
        const bool mgr_ok = mgr_before && game::fast_read(host_mgr + kMgrApplyByte, &a6a0, 1);
        const uint64_t v[] = {trip,
                              key_at(now.actor),
                              tpl::pack(u2_before),
                              tpl::pack(u2_after),
                              tpl::pack(host_before),
                              tpl::pack(host_after),
                              (mgr_ok ? 1u : 0u) | (static_cast<uint64_t>(b6a0) << 8) | (static_cast<uint64_t>(a6a0) << 16),
                              after.ft_applied ? 1u : 0u,
                              result,
                              after.ft_mgr,
                              after.ft_block ? 1u : 0u,
                              result_ok ? 1u : 0u};
        travel_probe_push(kTravelPrepared, v);
    } else {
        const uint64_t v[] = {trip, key_at(now.actor), tpl::pack(u2_before), tpl::pack(u2_after), result,
                              result_ok ? 1u : 0u};
        travel_probe_push(kTravelConsume, v);
    }
    return r;
}

// ExecuteTroc's nesting on this thread (P8 S16: the reload's 2322 only at the exit of an OUTERMOST Req).
thread_local int t_troc_depth = 0;
// P8 option U, review 1 of ae14ab6 (user2_stages.h): the Trocs of user 2 running now, on every thread (nested ones
// counted each). The host's preparation drains user 2's manager only while this is 0.
std::atomic<int32_t> g_u2_trocs{0};

// P8 S27 (observer_milestone_reload_any's lines): the Req of user 2 that starts a load (2283 / 2362) is noted for its
// next 2437 (observer_milestone keeps it and forgets it at a new epoch / a logout).
void before_2437(const Frame& now) noexcept {
    if (now.opcode == tpl::kOpReloadStageStartReq || now.opcode == tpl::kOpReviveLoadingReq) {
        observer_milestone_reload_note_load_req(now.opcode);
        return;
    }
    if (now.opcode != tpl::kOpGameLoadingStartReq || observer_milestone_reload_mode() == omr::Mode::Off) return;
    // User 2's TS before its 2437 (four guarded reads, once per 2437): which branch 0x2BC9200 will take, for the line.
    observer_milestone_reload_before(now.opcode, tpl::pack(ts_snap(now.actor)));
}

uintptr_t troc_detour(uintptr_t res, uintptr_t troc, uintptr_t params, uintptr_t r9) {
    struct Restore {
        Frame f;
        ~Restore() {
            t_frame = f;
            --t_troc_depth;
            // S46 review B5: the thread's outermost Troc is over: no T1 trade prepare can still be running on it.
            if (t_troc_depth == 0) user2_stages_clear_trade_mark();
        }
    } restore{t_frame};
    ++t_troc_depth;
    Frame now;
    subject_enter(troc, params, now);
    scene_enter(troc, params, now);  // U2: any subject
    t_frame = now;  // a nested ExecuteTroc decides its own; the outer one is back on return
    if (!now.actor) {
        const uintptr_t r = g_troc.unsafe_call<uintptr_t>(res, troc, params, r9);
        // S38 fase C: another subject's outermost Troc (server thread): a pending retirement of user 2's travellers
        // continues here too (user2_stages_any_troc_exit: one atomic load when nothing is pending).
        if (t_troc_depth == 1) user2_stages_any_troc_exit();
        return r;
    }
    // Review 1: counted while it runs; user2_stages_troc_begin waits (bounded) while the host's preparation drains user
    // 2's manager on another thread.
    struct InFlight {
        InFlight() {
            g_u2_trocs.fetch_add(1, std::memory_order_seq_cst);
            user2_stages_troc_begin();
        }
        ~InFlight() {
            user2_stages_troc_end();
            g_u2_trocs.fetch_sub(1, std::memory_order_seq_cst);
        }
    } in_flight;
    // P8 S16 (observer_milestone_reload_logic.h): user 2's 2437 enters (its 2643/3066 go out inside it). P8 S27: with
    // the last 2283 / 2362 that started the load (observer_milestone_reload_any's trips at the 2437).
    before_2437(now);
    // P8 option U, U-1 (user2_stages.h): its 2283/2362/2437/2001 drain its own armed manager before the game sees them.
    user2_stages_troc_enter(now.actor, now.opcode);
    // S38 fase C (revisión §2): its AutoSpawnRoadReq's road classes, for the provenance of the births of this Troc.
    if (now.opcode == 2550 && params) {
        uintptr_t packet = 0;
        uint16_t size = 0;
        if (game::fast_read(params + 0x18, &packet, sizeof packet) && game::fast_read(params + 0x10, &size, sizeof size)) {
            user2_stages_road_request(packet, size);
        }
    }
    uintptr_t r = 0;
    if ((now.opcode == tpl::kOpReloadStageStartReq || now.opcode == tpl::kOpGameLoadingStartReq ||
         now.opcode == tpl::kOpReviveLoadingReq) &&
        travel_probe_on()) {
        r = troc_travel(res, troc, params, r9, now);
    } else {
        r = g_troc.unsafe_call<uintptr_t>(res, troc, params, r9);
    }
    // P8 S16: its 2283 was accepted by F3 (t_frame is still this Troc's: the Restore runs on return), then, after ANY
    // Req of user 2, the reload's 2322 when one is armed (an atomic test otherwise).
    if (now.opcode == tpl::kOpReloadStageStartReq && (t_frame.ft_mgr || t_frame.ft_block)) {
        observer_milestone_reload_on_f3();
    }
    if (t_troc_depth == 1) {  // never inside another Req's handler
        observer_milestone_reload_at_exit(now.actor);
        user2_stages_troc_exit(now.actor, now.opcode);  // U-1: a pending arm / drain of its manager
    }
    return r;
}

// ---------------------------------------------------------------- B/C: the funnels

u2f::FunnelIn funnel_in(Mode mode, uintptr_t field, bool caller_ok) noexcept {
    u2f::FunnelIn in;
    in.mode = mode;
    in.subject = true;
    in.caller_ok = caller_ok;
    in.keys = keys_now();
    in.owner_ok = field && game::fast_read(field + kFieldOwner, &in.owner, sizeof in.owner);
    return in;
}

void count_out(u2f::FunnelCounters& c, FunnelOut o) noexcept {
    c.out[static_cast<size_t>(o)].fetch_add(1, std::memory_order_relaxed);
}

void funnel_event(uint8_t f, const Frame& fr, uint32_t owner, uint64_t orig, uint64_t ours, uintptr_t ret,
                  FunnelOut o, uint64_t extra) noexcept {
    if (g_fc_events[f].fetch_add(1, std::memory_order_relaxed) >= kEventsPerFunnel) return;
    push_event(kEvFunnel, {f, fr.opcode, key_at(fr.actor), owner, orig, ours, rva_of(ret), static_cast<uint64_t>(o),
                           extra});
}

// B: ServerField::vf40(field) -> ServerQuestManager*.
uintptr_t vf40_detour(uintptr_t field) {
    const Frame fr = t_frame;
    if (!fr.actor) return g_vf40.unsafe_call<uintptr_t>(field);
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    u2f::FunnelCounters& c = g_fc[u2f::kVf40];
    c.calls.fetch_add(1, std::memory_order_relaxed);
    c.under_subject.fetch_add(1, std::memory_order_relaxed);
    c.ops.add(fr.opcode);
    g_vf40_callers.add(rva_of(ret));
    // P8 option U, U-1 (user2_stages.h): counted only. By the rule of 2026-10-13 (the guest follows the host's
    // progress) every vf40 of user 2's armed tick keeps the owner's (the host's) ServerQuestManager.
    (void)user2_stages_tick_vf40(fr.opcode, fr.actor, field, rva_of(ret));
    // quest_policy (user2_funnels_logic.h, the rules of 2026-10-13 / S34): before quest_per_user's decision.
    const auto policy = static_cast<Mode>(g_policy_mode.load(std::memory_order_relaxed));
    const uint32_t ret_rva = rva_of(ret);
    const u2f::PolicyCaller caller = policy != Mode::Off ? u2f::policy_caller(ret_rva) : u2f::PolicyCaller::None;
    const bool trigger = caller == u2f::PolicyCaller::Trigger;
    if (caller != u2f::PolicyCaller::None) {
        uint32_t owner = 0;
        const bool host_field = field && game::fast_read(field + kFieldOwner, &owner, sizeof owner) && owner &&
                                owner == keys_now().host_user;
        u2f::ChainFail why = u2f::ChainFail::None;
        const auto own = policy == Mode::On && host_field && u2f::caller_answers_own(caller)
                             ? u2f::quest_manager_of(FastMem{}, fr.actor, g_vt_qcomp, g_vt_qmgr, &why)
                             : std::optional<uintptr_t>{};
        const u2f::PolicyOut po = u2f::decide_quest_policy(policy, caller, host_field, own.has_value());
        g_policy_outs[static_cast<size_t>(caller)][static_cast<size_t>(po)].fetch_add(1, std::memory_order_relaxed);
        if (po == u2f::PolicyOut::HostKept) {
            if (trigger) g_trigger_host.fetch_add(1, std::memory_order_relaxed);
            return g_vf40.unsafe_call<uintptr_t>(field);
        }
        if (po == u2f::PolicyOut::OwnAnswered) {
            count_out(c, FunnelOut::Substitute);  // in the summary's 'vf40 … (user 2's N)' too
            return *own;
        }
        // OwnUnreadable: the ingress let it through, but its own cannot be read now (a race between threads): as
        // before the policy (quest_per_user, else the original) - an ERR line (the host's state may change).
        if (po == u2f::PolicyOut::OwnUnreadable) {
            push_event(kEvPolicy, {static_cast<uint64_t>(po), fr.opcode, key_at(fr.actor), owner,
                                   static_cast<uint64_t>(why), static_cast<uint64_t>(caller)});
        }
    }
    const auto mode = static_cast<Mode>(g_quest_mode.load(std::memory_order_relaxed));
    // Only the quest-zone, quest-trace and respawn-point callers take user 2's manager; the trip end (0x2BC7670,
    // the 2322 path), revive and the stage callers keep the owner's until a probe shows what they do. With
    // quest_policy=1 the callers it keeps for the host never reach here (returned above).
    const u2f::FunnelIn in = funnel_in(mode, field,
                                       u2f::vf40_caller_allowed(ret_rva) &&
                                           u2f::quest_per_user_may_substitute(policy, caller));
    const FunnelOut o = u2f::decide_funnel(in);
    count_out(c, o);
    // quest_policy: which quest manager user 2's 2112 reaches (substituted by quest_per_user = its own).
    if (trigger) (o == FunnelOut::Substitute ? g_trigger_own : g_trigger_host).fetch_add(1, std::memory_order_relaxed);
    if (o != FunnelOut::Substitute && o != FunnelOut::Probe) return g_vf40.unsafe_call<uintptr_t>(field);
    u2f::ChainFail why = u2f::ChainFail::None;
    const auto mine = u2f::quest_manager_of(FastMem{}, fr.actor, g_vt_qcomp, g_vt_qmgr, &why);
    if (!mine) {
        c.unreadable.fetch_add(1, std::memory_order_relaxed);
        g_chain_fail[static_cast<size_t>(why)].fetch_add(1, std::memory_order_relaxed);
        const uintptr_t orig = g_vf40.unsafe_call<uintptr_t>(field);
        funnel_event(u2f::kVf40, fr, in.owner, orig, 0, ret, o, 100 + static_cast<uint64_t>(why));
        return orig;
    }
    if (o == FunnelOut::Substitute) {
        funnel_event(u2f::kVf40, fr, in.owner, 0, *mine, ret, o, 0);
        return *mine;
    }
    const uintptr_t orig = g_vf40.unsafe_call<uintptr_t>(field);
    (orig == *mine ? c.same : c.differ).fetch_add(1, std::memory_order_relaxed);
    funnel_event(u2f::kVf40, fr, in.owner, orig, *mine, ret, o, 0);
    return orig;
}

// F3: the first vf48 of user 2's 2283 (return address 0x2A5F7FC). With 1 the original is never called (it only looks
// the owner up: FindUser + the same chain, no side effect): user 2's own manager, or the substitute block when that
// cannot be read (0x2896120 reads only its +0x18). Off/probe (F2 should have dropped the 2283): the original, ERR.
uintptr_t fast_travel_vf48(uintptr_t field, const Frame& fr, uintptr_t ret) {
    ftl::F3In in;
    // Without its verified call sites F3 never substitutes: logged as Off.
    in.mode = g_ft_on.load(std::memory_order_acquire) ? static_cast<ftl::Mode>(g_ft_mode.load(std::memory_order_relaxed))
                                                      : ftl::Mode::Off;
    in.subject = fr.actor != 0;
    in.opcode = fr.opcode;
    in.ret_rva = rva_of(ret);
    uint32_t owner = 0;
    if (field) game::fast_read(field + kFieldOwner, &owner, sizeof owner);
    ftl::MgrFail why = ftl::MgrFail::None;
    const auto mine = ftl::seq_manager_of(FastMem{}, fr.actor, g_vt_seqmgr, &why);
    in.mgr_ok = mine.has_value();
    const ftl::F3Out o = ftl::decide_f3(in);
    g_ft_outs[static_cast<size_t>(o)].fetch_add(1, std::memory_order_relaxed);
    if (!mine) g_ft_fails[static_cast<size_t>(why)].fetch_add(1, std::memory_order_relaxed);
    const bool line = g_ft_events.fetch_add(1, std::memory_order_relaxed) < kFastTravelEvents;
    if (o == ftl::F3Out::Substitute) {
        t_frame.ft_mgr = *mine;  // the second vf48 of this Troc (0x2BC4C53) gets it too
        t_frame.ft_block = false;
        if (line) push_event(kEvFastTravel, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), owner, 0, *mine, 0, 0});
        travel_context(fr, in.ret_rva, owner, *mine, static_cast<uint64_t>(o));
        return *mine;
    }
    if (o == ftl::F3Out::SubstituteBlock) {
        for (uintptr_t& w : t_ft_block) w = 0;
        t_ft_block[ftl::kManagerActor / sizeof(uintptr_t)] = fr.actor;
        t_frame.ft_mgr = 0;
        t_frame.ft_block = true;
        const auto block = reinterpret_cast<uintptr_t>(&t_ft_block[0]);
        if (line) {
            push_event(kEvFastTravel, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), owner, 0, block, 0,
                                       static_cast<uint64_t>(why)});
        }
        travel_context(fr, in.ret_rva, owner, block, static_cast<uint64_t>(o));
        return block;
    }
    const uintptr_t orig = g_vf48.unsafe_call<uintptr_t>(field);
    if (line) {
        uintptr_t orig_actor = 0;
        if (orig) game::fast_read(orig + ftl::kManagerActor, &orig_actor, sizeof orig_actor);
        push_event(kEvFastTravel, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), owner, orig,
                                   mine.value_or(0), key_at(orig_actor), static_cast<uint64_t>(why)});
    }
    travel_context(fr, in.ret_rva, owner, orig, static_cast<uint64_t>(o));
    return orig;
}

// F3: the second vf48 of the same 2283 (0x2BC4C53, inside 0x2BC4950): user 2's real manager when F3 returned it to
// the first one (its [mgr+8] reference and its +0x6A0, never the block); else the original.
uintptr_t fast_travel_apply_vf48(uintptr_t field, const Frame& fr, uintptr_t ret) {
    const ftl::ApplyOut o = ftl::decide_apply(rva_of(ret), fr.ft_mgr, fr.ft_block);
    g_ft_apply[static_cast<size_t>(o)].fetch_add(1, std::memory_order_relaxed);
    const bool line = g_ft_events.fetch_add(1, std::memory_order_relaxed) < kFastTravelEvents;
    t_frame.ft_applied = true;  // the setter 0x2BC4950 ran in this Troc (travel probe)
    uint32_t owner = 0;
    if (field && travel_probe_on()) game::fast_read(field + kFieldOwner, &owner, sizeof owner);
    if (o == ftl::ApplyOut::Real) {
        if (line) push_event(kEvFastApply, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), fr.ft_mgr, 0});
        travel_context(fr, rva_of(ret), owner, fr.ft_mgr, 100 + static_cast<uint64_t>(o));
        return fr.ft_mgr;
    }
    const uintptr_t orig = g_vf48.unsafe_call<uintptr_t>(field);
    if (line) push_event(kEvFastApply, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), 0, orig});
    travel_context(fr, rva_of(ret), owner, orig, 100 + static_cast<uint64_t>(o));
    return orig;
}

// F4 (P8 S28): the reload setter 0x2BC4950's vf48 (return 0x2BC4C53) inside a Req of user 2 that F3 did not arm:
// for its ReviveLoadingReq 2362 in the shared field, user 2's own manager with 1 (the setter only references it and
// zeroes its +0x6A0); anything else, the original - counted, and the first kReviveEvents logged.
uintptr_t revive_apply_vf48(uintptr_t field, const Frame& fr, uintptr_t ret) {
    ftl::F4In in;
    in.mode = g_f4_on.load(std::memory_order_acquire) ? static_cast<ftl::Mode>(g_f4_mode.load(std::memory_order_relaxed))
                                                      : ftl::Mode::Off;
    in.subject = fr.actor != 0;
    in.opcode = fr.opcode;
    in.ret_rva = rva_of(ret);
    in.f3_armed = fr.ft_mgr || fr.ft_block;
    uint32_t owner = 0;
    if (field) game::fast_read(field + kFieldOwner, &owner, sizeof owner);
    const uint32_t u2_user = g_u2_user.load(std::memory_order_relaxed);
    in.own_field = owner && u2_user && owner == u2_user;
    ftl::MgrFail why = ftl::MgrFail::None;
    const auto mine = ftl::seq_manager_of(FastMem{}, fr.actor, g_vt_seqmgr, &why);
    in.mgr_ok = mine.has_value();
    const ftl::F4Out o = ftl::decide_f4(in);
    g_f4_outs[static_cast<size_t>(o)].fetch_add(1, std::memory_order_relaxed);
    t_frame.f4 = static_cast<uint8_t>(1 + static_cast<uint8_t>(o));
    const bool line = g_f4_events.fetch_add(1, std::memory_order_relaxed) < kReviveEvents;
    if (o == ftl::F4Out::Substitute || o == ftl::F4Out::OtherSubstitute) {
        if (line) push_event(kEvRevive, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), owner, 0, *mine, 0, 0});
        return *mine;
    }
    const uintptr_t orig = g_vf48.unsafe_call<uintptr_t>(field);
    if (line) {
        uintptr_t orig_actor = 0;
        if (orig) game::fast_read(orig + ftl::kManagerActor, &orig_actor, sizeof orig_actor);
        push_event(kEvRevive, {static_cast<uint64_t>(o), fr.opcode, key_at(fr.actor), owner, orig, mine.value_or(0),
                               key_at(orig_actor), static_cast<uint64_t>(why)});
    }
    return orig;
}

// P8 option U (S28, Ghidra): the timer handlers' vf48 calls return to .xtls 0x1082F96A (2043 UpdateStageOnceTimer ->
// 0x287DBB0), 0x10830A0F (2045 -> 0x2822D00([mgr+0x148])) and 0x10835A8F (2046 -> 0x27FBD60([mgr+0x10])).
bool timer_vf48_ret(uint32_t rva, uint16_t opcode) noexcept {
    return (rva == 0x1082F96A && opcode == 2043) || (rva == 0x10830A0F && opcode == 2045) ||
           (rva == 0x10835A8F && opcode == 2046);
}

// vf48: counted under a subject; changed only by F3 (the 2283's two calls) and F4 (the 2362's setter call).
uintptr_t vf48_detour(uintptr_t field) {
    const Frame fr = t_frame;
    if (fr.actor) {
        const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
        const uint32_t rva = rva_of(ret);
        u2f::FunnelCounters& c = g_fc[u2f::kVf48];
        c.calls.fetch_add(1, std::memory_order_relaxed);
        c.under_subject.fetch_add(1, std::memory_order_relaxed);
        c.ops.add(fr.opcode);
        g_vf48_callers.add(rva);
        // Classified as if it were redirected (probe semantics): the shared field or not.
        count_out(c, u2f::decide_funnel(funnel_in(Mode::Probe, field, true)));
        // F3 decides (and logs) every 2283 of user 2 at 0x2A5F7FC, live or not: one reaching the original is an ERR.
        if (rva == ftl::kReloadVf48Ret) {
            return fast_travel_vf48(field, fr, ret);
        }
        if (fr.ft_mgr || fr.ft_block) {
            if (rva == ftl::kApplyVf48Ret) return fast_travel_apply_vf48(field, fr, ret);
            g_ft_other_vf48.add(rva);  // another vf48 while user 2's 2283 is applied: the owner's (counted)
        }
        // F4 (P8 S28): the setter's vf48 in a Troc F3 did not arm (a 2362 of user 2, or any other Req).
        if (rva == ftl::kApplyVf48Ret && !fr.ft_mgr && !fr.ft_block) return revive_apply_vf48(field, fr, ret);
        // P8 option U, U-b (user2_stages.h): the vf48 of its own 2043 / 2045 / 2046 timer handler (each its return
        // address in .xtls) -> its own manager while U-1 routes; 0 = the original.
        if (timer_vf48_ret(rva, fr.opcode)) {
            if (const uintptr_t mine = user2_stages_route(fr.opcode, fr.actor, field)) return mine;
        } else if (fr.opcode == 2043 || fr.opcode == 2045 || fr.opcode == 2046) {
            // Review M3: counted by caller; inside its armed 2043 tick, its own manager (user2_stages.h).
            if (const uintptr_t mine = user2_stages_timer_vf48(fr.opcode, rva, fr.actor, field)) return mine;
        }
    }
    // U2-a (user2_shops.h): inside a scene Req / the 2044 timer (any subject), the handler's own vf48: the manager that
    // has the Troc's sequencer id when that is user 2's; any other vf48 of the Troc is counted and keeps the original.
    if (fr.scene_op) {
        const uint32_t rva = rva_of(reinterpret_cast<uintptr_t>(_ReturnAddress()));
        const uintptr_t orig = g_vf48.unsafe_call<uintptr_t>(field);
        bool mine_site = false;
        const uintptr_t mine = user2_shops_vf48(fr.scene_op, fr.scene_id, rva, field, orig, fr.scene_mine, mine_site);
        if (mine_site) t_frame.scene_mine = true;
        return mine ? mine : orig;
    }
    return g_vf48.unsafe_call<uintptr_t>(field);
}

// FindUser: counted under a subject (probe only), never changed.
uintptr_t finduser_detour(uintptr_t mgr, uintptr_t out, uint64_t key, uintptr_t r9) {
    const Frame fr = t_frame;
    if (fr.actor) {
        u2f::FunnelCounters& c = g_fc[u2f::kFindUser];
        c.calls.fetch_add(1, std::memory_order_relaxed);
        c.under_subject.fetch_add(1, std::memory_order_relaxed);
        c.ops.add(fr.opcode);
        g_finduser_callers.add(rva_of(reinterpret_cast<uintptr_t>(_ReturnAddress())));
        const uint32_t k = static_cast<uint32_t>(key);
        if (k && k == g_host_user.load(std::memory_order_relaxed)) {
            g_fu_host.fetch_add(1, std::memory_order_relaxed);
        } else if (k && k == g_u2_user.load(std::memory_order_relaxed)) {
            g_fu_user2.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_fu_other.fetch_add(1, std::memory_order_relaxed);
        }
    }
    return g_finduser.unsafe_call<uintptr_t>(mgr, out, key, r9);
}

// What a lock handle holds: the object's key and the locked byte (the caller's
// stack, just written by the original; the object through a guarded read).
void read_handle(uintptr_t out, uint32_t& key, uint8_t& locked) noexcept {
    uintptr_t obj = 0;
    key = 0;
    locked = 0;
    if (!out || !game::fast_read(out + kHandleObject, &obj, sizeof obj) ||
        !game::fast_read(out + kHandleLocked, &locked, sizeof locked)) {
        return;
    }
    key = key_at(obj);
}

// C: 0x2AFFF50(field, out) -> out (the owner's character, locked).
uintptr_t dead_detour(uintptr_t field, uintptr_t out, uintptr_t r8, uintptr_t r9) {
    const Frame fr = t_frame;
    if (!fr.actor) return g_dead.unsafe_call<uintptr_t>(field, out, r8, r9);
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    u2f::FunnelCounters& c = g_fc[u2f::kDead];
    c.under_subject.fetch_add(1, std::memory_order_relaxed);
    const auto mode = static_cast<Mode>(g_kill_mode.load(std::memory_order_relaxed));
    const u2f::FunnelIn in = funnel_in(mode, field, ret == g_ret_dead);
    const FunnelOut o = u2f::decide_funnel(in);
    count_out(c, o);
    if (o == FunnelOut::OtherCaller) {
        g_dead_other_callers.add(rva_of(ret));
        return g_dead.unsafe_call<uintptr_t>(field, out, r8, r9);
    }
    c.calls.fetch_add(1, std::memory_order_relaxed);
    c.ops.add(fr.opcode);
    // quest_policy (S34): DeadActor is quest progress (camp / kill counters): with 1 it stays the field owner's
    // character, as natively; the loot recipient (loot_detour) stays per user.
    if (o == FunnelOut::Substitute || o == FunnelOut::Probe) {
        const auto policy = static_cast<Mode>(g_policy_mode.load(std::memory_order_relaxed));
        if (u2f::policy_keeps_dead_native(policy)) {
            g_dead_policy_kept.fetch_add(1, std::memory_order_relaxed);
            return g_dead.unsafe_call<uintptr_t>(field, out, r8, r9);
        }
        if (policy == Mode::Probe && o == FunnelOut::Substitute) {
            g_dead_policy_would.fetch_add(1, std::memory_order_relaxed);
        }
    }
    uint32_t key = 0;
    uint8_t locked = 0;
    if (o == FunnelOut::Substitute) {
        if (g_fake_field[kFakeOwnerIndex] != in.keys.user2_user) {
            c.unreadable.fetch_add(1, std::memory_order_relaxed);  // the thread has not caught up: as the game
            return g_dead.unsafe_call<uintptr_t>(field, out, r8, r9);
        }
        const uintptr_t r = g_dead.unsafe_call<uintptr_t>(reinterpret_cast<uintptr_t>(&g_fake_field[0]), out, r8, r9);
        read_handle(out, key, locked);
        funnel_event(u2f::kDead, fr, in.owner, 0, key, ret, o, locked);
        return r;
    }
    const uintptr_t r = g_dead.unsafe_call<uintptr_t>(field, out, r8, r9);
    if (o == FunnelOut::Probe) {
        read_handle(out, key, locked);
        (key == in.keys.user2_char ? c.same : c.differ).fetch_add(1, std::memory_order_relaxed);
        funnel_event(u2f::kDead, fr, in.owner, key, in.keys.user2_char, ret, o, locked);
    }
    return r;
}

// C: 0x20DEE60(field, out) -> out (the owner's user, locked; body in .xtls).
uintptr_t loot_detour(uintptr_t field, uintptr_t out, uintptr_t r8, uintptr_t r9) {
    const Frame fr = t_frame;
    if (!fr.actor) return g_loot.unsafe_call<uintptr_t>(field, out, r8, r9);
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    u2f::FunnelCounters& c = g_fc[u2f::kLoot];
    c.under_subject.fetch_add(1, std::memory_order_relaxed);
    const auto mode = static_cast<Mode>(g_kill_mode.load(std::memory_order_relaxed));
    const u2f::FunnelIn in = funnel_in(mode, field, ret == g_ret_loot);
    const FunnelOut o = u2f::decide_funnel(in);
    count_out(c, o);
    if (o == FunnelOut::OtherCaller) {
        g_loot_other_callers.add(rva_of(ret));
        return g_loot.unsafe_call<uintptr_t>(field, out, r8, r9);
    }
    c.calls.fetch_add(1, std::memory_order_relaxed);
    c.ops.add(fr.opcode);
    uint32_t key = 0;
    uint8_t locked = 0;
    if (o == FunnelOut::Substitute) {
        uintptr_t slot = 0, mgr = 0;
        const FastMem m;
        if (!m.ptr(g_user_mgr_slot, slot) || !slot || !m.ptr(slot, mgr) || !mgr) {
            c.unreadable.fetch_add(1, std::memory_order_relaxed);
            return g_loot.unsafe_call<uintptr_t>(field, out, r8, r9);
        }
        using FindUserFn = uintptr_t (*)(uintptr_t, uintptr_t, uint64_t);
        reinterpret_cast<FindUserFn>(g_find_user)(mgr, out, in.keys.user2_user);
        read_handle(out, key, locked);
        funnel_event(u2f::kLoot, fr, in.owner, 0, key, ret, o, locked);
        return out;
    }
    const uintptr_t r = g_loot.unsafe_call<uintptr_t>(field, out, r8, r9);
    if (o == FunnelOut::Probe) {
        read_handle(out, key, locked);
        (key == in.keys.user2_user ? c.same : c.differ).fetch_add(1, std::memory_order_relaxed);
        funnel_event(u2f::kLoot, fr, in.owner, key, in.keys.user2_user, ret, o, locked);
    }
    return r;
}

// quest_policy's probe (S34): 0x290DBD0(component, event), the quest component's game-event callback (its vf40 gives
// the field owner's quest manager the event). Counted when [component+8] is user 2's main character: the event's type
// byte +8, its actor key +0x68, and whether a Req of user 2 is running (its 2052 usually). Read only; then the original.
void qevent_count(uintptr_t comp, uintptr_t ev) noexcept {
    const u2f::Keys k = keys_now();
    if (!k.live || !u2f::is_character_key(k.user2_char)) return;
    uintptr_t actor = 0;
    uint32_t key = 0, controller = 0;
    if (!comp || !game::fast_read(comp + u2f::kQuestCompActor, &actor, sizeof actor) || !actor ||
        !game::fast_read(actor + kActorKey, &key, sizeof key)) {
        g_qevent_unreadable.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const uint32_t host_char = g_host_char.load(std::memory_order_relaxed);
    if (key != k.user2_char) {
        if (host_char && key == host_char) g_qevent_host.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!game::fast_read(actor + kActorController, &controller, sizeof controller) ||
        !u2f::is_user2_character(k, key, controller)) {
        return;
    }
    uint8_t type = 0;
    uint32_t ev_key = 0;
    if (!ev || !game::fast_read(ev + u2f::kEventType, &type, sizeof type) ||
        !game::fast_read(ev + u2f::kEventActorKey, &ev_key, sizeof ev_key)) {
        g_qevent_unreadable.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_qevent_types[type].fetch_add(1, std::memory_order_relaxed);
    g_qevent_actor[static_cast<size_t>(u2f::classify_event_actor(ev_key, k.user2_char, host_char))].fetch_add(
        1, std::memory_order_relaxed);
    g_qevent_subject[t_frame.actor ? 1 : 0].fetch_add(1, std::memory_order_relaxed);
}

void qevent_detour(uintptr_t comp, uintptr_t ev, uintptr_t r8, uintptr_t r9) {
    qevent_count(comp, ev);
    g_qevent.unsafe_call<void>(comp, ev, r8, r9);
}

// ---------------------------------------------------------------- install (its own thread)

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

struct Site {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* what;
};

// In .rsrc and byte for byte the build's code; else an error line and false.
bool verify(const Site& s) {
    if (!gad::in_real_code(g_secs, static_cast<uint32_t>(s.rva), static_cast<uint32_t>(s.bytes.size()))) {
        const gad::Section* sec = gad::section_of(g_secs, static_cast<uint32_t>(s.rva));
        log::error("User2Funnels: {} (exe+0x{:X}) is not inside .rsrc (section {}); REFUSED", s.what, s.rva,
                   sec ? sec->name : "none");
        return false;
    }
    if (!bytes_at(s.rva, s.bytes)) {
        log::error("User2Funnels: {} (exe+0x{:X}) is not the expected code of build {}; REFUSED", s.what, s.rva,
                   g_is_3663 ? 3663 : g_is_3576 ? 3576 : g_is_3527 ? 3527 : 2976);
        return false;
    }
    return true;
}

// A disabled inline hook whose relocated bytes are a whole number of the
// verified instructions (a prefix of `bytes`), then enabled.
bool install_inline(const Site& s, std::span<const uint32_t> boundaries, void* detour, SafetyHookInline& out,
                    uint32_t& patch) {
    if (!verify(s)) return false;
    auto whole = [&](const std::vector<uint8_t>& o) {
        return std::find(boundaries.begin(), boundaries.end(), o.size()) != boundaries.end() &&
               o.size() <= s.bytes.size() && std::memcmp(o.data(), s.bytes.data(), o.size()) == 0;
    };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(g_base + s.rva, detour, whole, "User2Funnels", s.what);
    if (!h) {
        log::error("User2Funnels: the hook on {} (exe+0x{:X}) could not be prepared ({}); REFUSED", s.what, s.rva,
                   game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("User2Funnels: the hook on {} (exe+0x{:X}) would patch {} bytes, not a whole number of the "
                   "verified instructions; REFUSED, nothing written",
                   s.what, s.rva, orig.size());
        return false;  // destroyed disabled: nothing was written
    }
    patch = static_cast<uint32_t>(orig.size());
    out = std::move(*h);  // the detour calls through it: in place before enabling
    if (!out.enable()) {
        log::error("User2Funnels: the hook on {} (exe+0x{:X}) could not be enabled; REFUSED", s.what, s.rva);
        out = {};
        return false;
    }
    return true;
}

// Writes `len` bytes at exe+rva with every thread kept out of the page
// (safetyhook::trap_threads: the page is not executable while it changes).
bool write_code(uintptr_t rva, const uint8_t* bytes, size_t len) {
    auto* target = reinterpret_cast<uint8_t*>(g_base + rva);
    bool written = false;
    safetyhook::trap_threads(target, target, len, [&] {
        DWORD old = 0;
        if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old)) return;
        std::memcpy(target, bytes, len);
        VirtualProtect(target, len, old, &old);
        FlushInstructionCache(GetCurrentProcess(), target, len);
        written = true;
    });
    if (!written) return false;
    std::vector<uint8_t> back(len);
    return game::safe_read(g_base + rva, back.data(), len) && std::memcmp(back.data(), bytes, len) == 0;
}

// A: both sites verified, a stub near them (`jmp [rip+0]` + the thunk's
// address), then `call stub ; nop` over each `call [rax+0x188]`.
bool install_rank() {
    const Site ctx[2] = {{kRankCtx1, g_rank_ctx1_bytes,
                          g_is_3663   ? "the rank permit's vf188(5) call 0x2465451 (0x24652E0)"
                          : g_is_3576 ? "the rank permit's vf188(5) call 0x23F3BA1 (0x23F3A30)"
                          : g_is_3527 ? "the rank permit's vf188(5) call 0x23F2E51 (0x23F2CE0)"
                                      : "the rank permit's vf188(5) call 0x221E281 (0x221E110)"},
                         {kRankCtx2, g_rank_ctx2_bytes,
                          g_is_3663   ? "the permit removal's vf188(5) call 0x24664B8 (0x2466160)"
                          : g_is_3576 ? "the permit removal's vf188(5) call 0x23F4C08 (0x23F48B0)"
                          : g_is_3527 ? "the permit removal's vf188(5) call 0x23F3EB8 (0x23F3B60)"
                                      : "the permit removal's vf188(5) call 0x221F29F (0x221EF50)"}};
    for (const Site& s : ctx) {
        if (!verify(s)) return false;
    }
    auto* site0 = reinterpret_cast<uint8_t*>(g_base + kRankCtx1 + kRankCallAt);
    auto* site1 = reinterpret_cast<uint8_t*>(g_base + kRankCtx2 + kRankCallAt);
    auto alloc = safetyhook::Allocator::global()->allocate_near({site0, site1}, 16);
    if (!alloc) {
        log::error("User2Funnels: no memory within 2 GB of the rank sites for the stub; rank_permit REFUSED");
        return false;
    }
    g_rank_stub = std::move(*alloc);
    uint8_t* stub = g_rank_stub.data();
    std::memset(stub, 0xCC, 16);
    stub[0] = 0xFF;  // jmp qword ptr [rip+0]: FF 25 00 00 00 00, then the 8-byte target
    stub[1] = 0x25;
    std::memset(stub + 2, 0, 4);
    const uintptr_t thunk = reinterpret_cast<uintptr_t>(&rank_vf188_thunk);
    std::memcpy(stub + 6, &thunk, sizeof thunk);
    FlushInstructionCache(GetCurrentProcess(), stub, 16);
    {
        const uint8_t want[6] = {0xFF, 0x25, 0, 0, 0, 0};
        uintptr_t target = 0;
        std::memcpy(&target, stub + 6, sizeof target);
        if (std::memcmp(stub, want, sizeof want) != 0 || target != thunk) {
            log::error("User2Funnels: the rank stub at 0x{:X} does not read back as jmp [rip] -> thunk; rank_permit REFUSED",
                       reinterpret_cast<uintptr_t>(stub));
            return false;
        }
    }
    uint8_t patch[2][kRankCallLen] = {};
    uint8_t* sites[2] = {site0, site1};
    for (int i = 0; i < 2; ++i) {
        const int64_t rel = reinterpret_cast<intptr_t>(stub) - reinterpret_cast<intptr_t>(sites[i] + 5);
        if (rel != static_cast<int32_t>(rel)) {
            log::error("User2Funnels: the stub is out of rel32 range of site {}; rank_permit REFUSED", i + 1);
            return false;
        }
        const int32_t r = static_cast<int32_t>(rel);
        patch[i][0] = 0xE8;
        std::memcpy(&patch[i][1], &r, 4);
        patch[i][5] = 0x90;
    }
    const uintptr_t rvas[2] = {kRankCtx1 + kRankCallAt, kRankCtx2 + kRankCallAt};
    if (!write_code(rvas[0], patch[0], kRankCallLen)) {
        log::error("User2Funnels: exe+0x{:X} could not be written; rank_permit REFUSED", rvas[0]);
        return false;
    }
    g_rank_patched[0] = true;
    if (!write_code(rvas[1], patch[1], kRankCallLen)) {
        // A permit could be granted and never removed: put the first site back.
        const bool back = write_code(rvas[0], kRankCallBytes, kRankCallLen);
        g_rank_patched[0] = !back;
        log::error("User2Funnels: exe+0x{:X} could not be written; rank_permit REFUSED (exe+0x{:X} {})", rvas[1],
                   rvas[0], back ? "restored" : "COULD NOT BE RESTORED");
        return false;
    }
    g_rank_patched[1] = true;
    g_rank_live.store(true, std::memory_order_release);
    return true;
}

bool code_ready() {
    if (g_is_3527) {
        const Site sites[] = {{kExecuteTroc, g_exec_troc_bytes, ""}, {kVf48, g_vf48_bytes, ""},
                              {kReloadCallCtx, g_reload_ctx_bytes, ""}, {kApplyReload, g_apply_reload_bytes, ""},
                              {kApplyCallCtx, g_apply_ctx_bytes, ""}};
        for (const Site& site : sites) {
            if (!bytes_at(site.rva, site.bytes)) return false;
        }
        return true;
    }
    const Site all[] = {{kRankCtx1, kRankCtx1Bytes, ""},       {kRankCtx2, kRankCtx2Bytes, ""},
                        {kExecuteTroc, kExecuteTrocBytes, ""}, {kVf40, kVf40Bytes, ""},
                        {kVf48, kVf48Bytes, ""},               {kOwnerChar, kOwnerCharBytes, ""},
                        {kDeadCallCtx, kDeadCallCtxBytes, ""}, {kOwnerUserStub, kOwnerUserStubBytes, ""},
                        {kLootCallCtx, kLootCallCtxBytes, ""}, {kFindUser, kFindUserBytes, ""},
                        {kReloadCallCtx, kReloadCallCtxBytes, ""}, {kApplyReload, kApplyReloadBytes, ""},
                        {kApplyCallCtx, kApplyCallCtxBytes, ""}};
    for (const Site& s : all) {
        if (!bytes_at(s.rva, s.bytes)) return false;
    }
    return true;
}

// The local player's controlled actor exists (ui_pause's check): the world is up.
bool player_in_world() {
    uintptr_t world = 0, mgr = 0, vt = 0, actor = 0, avt = 0;
    if (g_is_3663) {
        // Build 1.0.0.3663 (static, 2026-11-13; never run): world slot 0x72451C0 (profile_s2.h rva3663; 3195 RIP
        // references, 1039 of them followed by `mov rcx,[rcx+0x30]`), ClientActorManager vtable 0x59C2760 (RTTI).
        return peek(g_base + 0x72451C0, world) && world && peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr &&
               peek(mgr, vt) && vt == g_base + 0x59C2760 && peek(mgr + g2976::kActorManager_ControlledActor, actor) &&
               actor && peek(actor, avt) && avt;
    }
    if (g_is_3576) {
        // Build 1.0.0.3576 (static, 2026-11-06; not yet run): no reader profile yet. World slot 0x71C0100
        // (core_globals_3576.json; 0xC9DB6B reads it and then +0x30), ClientActorManager vtable 0x5946C40 (RTTI).
        return peek(g_base + 0x71C0100, world) && world && peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr &&
               peek(mgr, vt) && vt == g_base + 0x5946C40 && peek(mgr + g2976::kActorManager_ControlledActor, actor) &&
               actor && peek(actor, avt) && avt;
    }
    if (const auto* profile = game::reader_profile(); g_is_3527 && profile) {
        return peek(g_base + profile->world_system, world) && world &&
               peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
               vt == g_base + profile->vt_actor_manager && peek(mgr + g2976::kActorManager_ControlledActor, actor) && actor &&
               peek(actor, avt) && avt;
    }
    return peek(g_base + g2976::kWorldSystemSlot, world) && world &&
           peek(world + g2976::kWorldSystem_ActorManager, mgr) && mgr && peek(mgr, vt) &&
           vt == g_base + g2976::kVtClientActorManager &&
           peek(mgr + g2976::kActorManager_ControlledActor, actor) && actor && peek(actor, avt) &&
           avt == g_base + g2976::kVtControlledActor;
}

void wait_for_world() {
    const uint64_t t0 = GetTickCount64();
    uint64_t last_line = t0;
    log::info("User2Funnels: waiting for the local player in the world before hooking (never at start-up or on the "
              "title screen)");
    for (int stable = 0; stable < 6;) {
        Sleep(500);
        stable = player_in_world() ? stable + 1 : 0;
        const uint64_t now = GetTickCount64();
        if (now - last_line >= 60000) {
            log::info("User2Funnels start-up: still waiting for the world after {} s", (now - t0) / 1000);
            last_line = now;
        }
    }
}

// ---------------------------------------------------------------- the thread

void refresh_keys(bool& was_live) {
    const bool live = server_user2_present();
    uint32_t host_key = 0;
    uintptr_t host = 0;
    if (server_host_user(host) && host) peek(host + kActorKey, host_key);
    const uint32_t u2 = server_user2_user_key(), ch = server_user2_player_key();
    g_u2_user.store(u2, std::memory_order_relaxed);
    g_u2_char.store(ch, std::memory_order_relaxed);
    g_host_user.store(host_key, std::memory_order_relaxed);
    uint32_t host_char = 0;
    if (const uintptr_t hc = host_character()) peek(hc + kActorKey, host_char);
    g_host_char.store(host_char, std::memory_order_relaxed);
    if (g_fake_field[kFakeOwnerIndex] != u2) g_fake_field[kFakeOwnerIndex] = u2;  // aligned 4-byte store
    g_live.store(live, std::memory_order_release);
    if (live != was_live) {
        was_live = live;
        log::info("User2Funnels: user 2 {} (user 0x{:08X}, character 0x{:08X}; host user 0x{:08X}){}",
                  live ? "LIVE" : "gone", u2, ch, host_key,
                  live && !(u2f::is_user_key(u2) && u2f::is_character_key(ch) && u2f::is_user_key(host_key))
                      ? " - a key is still unknown: nothing changes until it is"
                      : "");
    }
}

std::string fmt_key(uint64_t k) { return k ? std::format("0x{:08X}", k) : std::string("none"); }

void format_event(const p8p::Event& e) {
    if (e.kind == kEvRank) {
        const auto what = static_cast<u2f::RankOut>(e.v[4]);
        log::info("User2Funnels rank [{}] {}: vf188(5) of user 2's character {} at exe+0x{:X}: original {} -> {} ({})",
                  u2f::mode_name(static_cast<Mode>(e.v[5])), p8_when(e.qpc_us), fmt_key(e.v[3]),
                  e.v[0] == 0 ? kRankCtx1 + kRankCallAt : kRankCtx2 + kRankCallAt, e.v[1], e.v[2],
                  u2f::rank_out_name(what));
        return;
    }
    if (e.kind == kEvFastTravel) {
        const auto o = static_cast<ftl::F3Out>(e.v[0]);
        std::string what;
        if (o == ftl::F3Out::Substitute) {
            what = std::format("returned user 2's ServerSequencerStageManager 0x{:X}: the destination goes to ITS "
                               "TransformSync+0x550",
                               e.v[5]);
        } else if (o == ftl::F3Out::SubstituteBlock) {
            what = std::format("user 2's manager not readable ({}): returned the block 0x{:X} (+0x18 = user 2's "
                               "character): the destination still goes to ITS TransformSync+0x550; the second vf48 "
                               "(0x2BC4C53) keeps the owner's",
                               ftl::mgr_fail_name(static_cast<ftl::MgrFail>(e.v[7])), e.v[5]);
        } else {
            what = std::format("the ORIGINAL 0x{:X} (its character {}){}", e.v[4], fmt_key(e.v[6]),
                               e.v[5] ? std::format("; user 2's would be 0x{:X}", e.v[5])
                                      : std::format("; user 2's not readable ({})",
                                                    ftl::mgr_fail_name(static_cast<ftl::MgrFail>(e.v[7]))));
        }
        const auto line = std::format("User2Funnels fast travel (user2_fast_travel={}, {}) {}: Req {} of user 2 ({}) | "
                                      "field owner {} | {} | {} | from exe+0x{:X}",
                                      ftl::mode_name(static_cast<ftl::Mode>(g_ft_mode.load())),
                                      g_ft_on.load() ? "live" : "NOT live", p8_when(e.qpc_us), e.v[1], fmt_key(e.v[2]),
                                      fmt_key(e.v[3]), ftl::f3_out_name(o), what, ftl::kReloadVf48Ret);
        // In user 2's own field (owner = user 2) the original IS user 2's manager: not an error.
        const bool own_field = e.v[3] && e.v[3] == g_u2_user.load();
        if ((o == ftl::F3Out::Off || o == ftl::F3Out::Probe) && !own_field) {
            log::error("{} - a 2283 of user 2 reached the original vf48: its destination went to the field OWNER's "
                       "character (the host's Kliff +0x550 if the field is shared)",
                       line);
        } else if (o == ftl::F3Out::SubstituteBlock) {
            log::warn("{}", line);
        } else {
            log::info("{}", line);
        }
        return;
    }
    if (e.kind == kEvFastApply) {
        const auto o = static_cast<ftl::ApplyOut>(e.v[0]);
        const std::string head = std::format("User2Funnels fast travel {}: Req {} of user 2 ({}) | 0x2BC4950's vf48 "
                                             "from exe+0x{:X}",
                                             p8_when(e.qpc_us), e.v[1], fmt_key(e.v[2]), ftl::kApplyVf48Ret);
        if (o == ftl::ApplyOut::Real) {
            log::info("{} | returned user 2's manager 0x{:X} (its +0x6A0 is zeroed, not the host's)", head, e.v[3]);
        } else {
            log::error("{} | the ORIGINAL 0x{:X} (F3 used the block): the field owner's manager +0x6A0 is zeroed", head,
                       e.v[4]);
        }
        return;
    }
    if (e.kind == kEvRevive) {
        const auto o = static_cast<ftl::F4Out>(e.v[0]);
        std::string what;
        if (o == ftl::F4Out::Substitute || o == ftl::F4Out::OtherSubstitute) {
            what = std::format("returned user 2's ServerSequencerStageManager 0x{:X}", e.v[5]);
        } else {
            what = std::format("the ORIGINAL 0x{:X} (its character {}){}", e.v[4], fmt_key(e.v[6]),
                               e.v[5] ? std::format("; user 2's would be 0x{:X}", e.v[5])
                                      : std::format("; user 2's not readable ({})",
                                                    ftl::mgr_fail_name(static_cast<ftl::MgrFail>(e.v[7]))));
        }
        const auto line = std::format("User2Funnels revive F4 (user2_revive_manager={}, {}) {}: Req {} of user 2 ({}) | "
                                      "field owner {} | 0x2BC4950's vf48 from exe+0x{:X} | {} | {}",
                                      ftl::mode_name(static_cast<ftl::Mode>(g_f4_mode.load())),
                                      g_f4_on.load() ? "live" : "NOT live", p8_when(e.qpc_us), e.v[1], fmt_key(e.v[2]),
                                      fmt_key(e.v[3]), ftl::kApplyVf48Ret, ftl::f4_out_name(o), what);
        if (o == ftl::F4Out::Substitute || o == ftl::F4Out::OtherSubstitute || o == ftl::F4Out::OwnField) {
            log::info("{}", line);
        } else if (o == ftl::F4Out::NoManager || o == ftl::F4Out::Off || o == ftl::F4Out::OtherReq) {
            log::error("{} - the field owner's manager +0x6A0 is reset by a Req of user 2", line);
        } else {
            log::warn("{}", line);
        }
        return;
    }
    if (e.kind == kEvPolicy) {
        log::error("User2Funnels quest_policy {}: Req {} of user 2 ({}) | field owner {} | {} at {}: its own quest "
                   "manager could not be read at the vf40 ({}): as without the policy (quest_per_user, else the "
                   "ORIGINAL) - the host's mission state may have changed",
                   p8_when(e.qpc_us), e.v[1], fmt_key(e.v[2]), fmt_key(e.v[3]),
                   u2f::policy_out_name(static_cast<u2f::PolicyOut>(e.v[0])),
                   u2f::policy_caller_name(static_cast<u2f::PolicyCaller>(e.v[5])),
                   u2f::chain_fail_name(static_cast<u2f::ChainFail>(e.v[4])));
        return;
    }
    if (e.kind != kEvFunnel) return;
    const auto f = static_cast<uint8_t>(e.v[0]);
    const auto o = static_cast<FunnelOut>(e.v[7]);
    const uint16_t op = static_cast<uint16_t>(e.v[1]);
    std::string body;
    if (f == u2f::kVf40) {
        if (e.v[8] >= 100) {
            body = std::format("user 2's quest manager NOT readable ({}): the original 0x{:X}",
                               u2f::chain_fail_name(static_cast<u2f::ChainFail>(e.v[8] - 100)), e.v[4]);
        } else if (o == FunnelOut::Substitute) {
            body = std::format("returned user 2's ServerQuestManager 0x{:X}", e.v[5]);
        } else {
            body = std::format("the original 0x{:X} (the owner's), user 2's would be 0x{:X}{}", e.v[4], e.v[5],
                               e.v[4] == e.v[5] ? " (the same)" : "");
        }
    } else if (f == u2f::kDead) {
        body = o == FunnelOut::Substitute
                   ? std::format("DeadActor goes to character {} (locked {})", fmt_key(e.v[5]), e.v[8])
                   : std::format("DeadActor goes to character {} (locked {}); with 1: user 2's {}", fmt_key(e.v[4]),
                                 e.v[8], fmt_key(e.v[5]));
    } else if (f == u2f::kLoot) {
        body = o == FunnelOut::Substitute
                   ? std::format("the loot recipient is user {} (locked {})", fmt_key(e.v[5]), e.v[8])
                   : std::format("the loot recipient is user {} (locked {}); with 1: user 2 {}", fmt_key(e.v[4]),
                                 e.v[8], fmt_key(e.v[5]));
    }
    log::info("User2Funnels {} {}: Req {} of user 2 ({}) | field owner {} | {} | {} | from exe+0x{:X}",
              f == u2f::kVf40 ? "vf40" : f == u2f::kDead ? "dead" : "loot", p8_when(e.qpc_us), op,
              fmt_key(e.v[2]), fmt_key(e.v[3]), u2f::funnel_out_name(o), body, e.v[6]);
}

void drain() {
    p8p::Event e;
    for (size_t n = 0; n < 60 && g_ring.pop(e); ++n) format_event(e);
}

std::string ops_text(const u2f::OpCounts& c) {
    std::string s;
    for (const auto& [op, n] : c.top(8)) s += std::format("{}{}x{}", s.empty() ? "" : " ", op, n);
    return s.empty() ? std::string("none") : s;
}

template <size_t N>
std::string sites_text(const u2f::SiteCounts<N>& c) {
    std::string s;
    size_t shown = 0;
    for (const auto& [rva, n] : c.rows()) {
        if (shown++ == 8) break;
        s += std::format("{}exe+0x{:X}x{}", s.empty() ? "" : " ", rva, n);
    }
    if (c.overflow()) s += std::format(" (+{} not tabled)", c.overflow());
    return s.empty() ? std::string("none") : s;
}

std::string outs_text(const u2f::FunnelCounters& c) {
    std::string s;
    for (size_t i = 0; i < c.out.size(); ++i) {
        const uint64_t n = c.out[i].load(std::memory_order_relaxed);
        if (n) s += std::format("{}{} {}", s.empty() ? "" : ", ", u2f::funnel_out_name(static_cast<FunnelOut>(i)), n);
    }
    return s.empty() ? std::string("nothing") : s;
}

// quest_policy's part of the summary line ("" when off): the totals; the details are policy_summary()'s line.
std::string policy_text() {
    const auto policy = static_cast<Mode>(g_policy_mode.load());
    if (policy == Mode::Off) return {};
    uint64_t out[kPolicyOuts] = {};
    for (size_t c = 1; c < kPolicyCallers; ++c) {
        for (size_t o = 0; o < kPolicyOuts; ++o) out[o] += g_policy_outs[c][o].load();
    }
    uint64_t dropped = g_change_dropped.load(), would = g_change_would_drop.load();
    for (size_t i = 0; i < 3; ++i) {
        dropped += g_own_dropped[i].load();
        would += g_own_would_drop[i].load();
    }
    const auto n = [&](u2f::PolicyOut o) { return out[static_cast<size_t>(o)]; };
    return std::format(" | quest_policy {}: vf40 the host's {} (would {}), its own {} (would {}), its own unreadable {} "
                       "| dropped at the ingress {} (would {}) | DeadActor kept native {} (would {})",
                       u2f::mode_name(policy), n(u2f::PolicyOut::HostKept), n(u2f::PolicyOut::HostWould),
                       n(u2f::PolicyOut::OwnAnswered), n(u2f::PolicyOut::OwnWould), n(u2f::PolicyOut::OwnUnreadable),
                       dropped, would, g_dead_policy_kept.load(), g_dead_policy_would.load());
}

const char* event_type_name(size_t t) {
    if (g_is_3663) {
        // Build 1.0.0.3663 (static): 0x2F57780 / 0x2F577C9 (2112), 0x2C19632 (DeadActor), 0x2C19ECA (KillActor),
        // 0x2C1956E (PlayerDead): one more than 3527's from 0x6A on.
        switch (t) {
            case 0x11: return "MissionTriggerIn";
            case 0x12: return "MissionTriggerOut";
            case 0x6B: return "KillActor";
            case 0x6C: return "DeadActor";
            case 0x75: return "PlayerDead";
            default: return "";
        }
    }
    if (g_is_3527) {
        // 0x2EEE8D0 / 0x2EEE919 (2112), 0x2BB2F72 (DeadActor), 0x2BB380A (KillActor), 0x2BB2EAE (the dying player's,
        // 0x6B in 2976). The interaction events were not read on this build: their numbers print without a name.
        switch (t) {
            case 0x11: return "MissionTriggerIn";
            case 0x12: return "MissionTriggerOut";
            case 0x6A: return "KillActor";
            case 0x6B: return "DeadActor";
            case 0x74: return "PlayerDead";
            default: return "";
        }
    }
    switch (t) {
        case 0x11: return "MissionTriggerIn";
        case 0x12: return "MissionTriggerOut";
        case 0x3D: return "InteractionStart";
        case 0x3E: return "Interaction";
        case 0x61: return "KillActor";
        case 0x62: return "DeadActor";
        case 0x6B: return "PlayerDead";
        default: return "";
    }
}

// quest_policy's detailed line (every 60 s, "" when off).
void policy_summary() {
    const auto policy = static_cast<Mode>(g_policy_mode.load());
    if (policy == Mode::Off) return;
    std::string callers;
    for (size_t c = 1; c < kPolicyCallers; ++c) {
        std::string outs;
        for (size_t o = 1; o < kPolicyOuts; ++o) {
            if (const uint64_t v = g_policy_outs[c][o].load()) {
                outs += std::format("{}{} {}", outs.empty() ? "" : ", ", u2f::policy_out_name(static_cast<u2f::PolicyOut>(o)), v);
            }
        }
        if (const uint64_t none = g_policy_outs[c][0].load()) {
            outs += std::format("{}not the host's field {}", outs.empty() ? "" : ", ", none);
        }
        if (!outs.empty()) callers += std::format(" {}: {};", u2f::policy_caller_name(static_cast<u2f::PolicyCaller>(c)), outs);
    }
    std::string own;
    for (size_t i = 0; i < 3; ++i) {
        std::string fails;
        for (size_t f = 1; f < static_cast<size_t>(u2f::RouteFail::Count); ++f) {
            if (const uint64_t v = g_own_route_fail[i][f].load()) {
                fails += std::format(" {} {};", u2f::route_fail_name(static_cast<u2f::RouteFail>(f)), v);
            }
        }
        own += std::format(" {} host's field {} / elsewhere {}, dropped {} (would {}){};", kOwnReqOps[i],
                           g_own_reqs[i][0].load(), g_own_reqs[i][1].load(), g_own_dropped[i].load(),
                           g_own_would_drop[i].load(), fails.empty() ? std::string() : " route failures:" + fails);
    }
    std::string measured;
    for (size_t i = 0; i < 4; ++i) {
        measured += std::format(" {} host's field {} (handed {}) / elsewhere {} (handed {});", kMeasuredOps[i],
                                g_measured[i][0][0].load() + g_measured[i][0][1].load(), g_measured[i][0][1].load(),
                                g_measured[i][1][0].load() + g_measured[i][1][1].load(), g_measured[i][1][1].load());
    }
    std::string ids;
    const auto rows = g_trigger_ids.rows();
    for (size_t i = 0; i < rows.size() && i < 12; ++i) ids += std::format(" 0x{:X}x{}", rows[i].first, rows[i].second);
    std::string types;
    for (size_t t = 0; t < 256; ++t) {
        if (const uint64_t v = g_qevent_types[t].load()) {
            const char* nm = event_type_name(t);
            types += std::format(" 0x{:02X}{}{}x{}", t, *nm ? " " : "", nm, v);
        }
    }
    const auto ea = [](u2f::EventActor a) { return g_qevent_actor[static_cast<size_t>(a)].load(); };
    log::info("User2Funnels quest_policy {} summary | vf40 callers under user 2:{} | own-manager Reqs:{} | 2369 host's "
              "field {} / elsewhere {}, dropped {} (would {}) | measured only:{} | 2112 host's field {} / elsewhere {} "
              "(first u32:{}): at its vf40 user 2's {} / the host's {} | DeadActor kept native {} (would {}) | events "
              "of user 2's character at 0x290DBD0 ({}): types{} | ev+0x68 user 2's {} / the host's {} / other {} / 0 {} "
              "| in a Req of user 2 {} / outside {} | the host's character's events {} | unreadable {} | the host "
              "client got 3009 {} / 3088 {} / 2738 {} / 2346 {}",
              u2f::mode_name(policy), callers.empty() ? " none" : callers, own, g_change_reqs[0].load(),
              g_change_reqs[1].load(), g_change_dropped.load(), g_change_would_drop.load(), measured,
              g_trigger_reqs[0].load(), g_trigger_reqs[1].load(), ids.empty() ? " none" : ids, g_trigger_own.load(),
              g_trigger_host.load(), g_dead_policy_kept.load(), g_dead_policy_would.load(),
              g_qevent_on.load() ? "hooked" : "NOT hooked", types.empty() ? " none" : types, ea(u2f::EventActor::User2),
              ea(u2f::EventActor::Host), ea(u2f::EventActor::Other), ea(u2f::EventActor::Zero), g_qevent_subject[1].load(),
              g_qevent_subject[0].load(), g_qevent_host.load(), g_qevent_unreadable.load(), g_host_acks[0].load(),
              g_host_acks[1].load(), g_host_acks[2].load(), g_host_acks[3].load());
}

void summary() {
    log::info("User2Funnels summary: {}", user2_funnels_describe());
    policy_summary();
    if (g_ft_mode.load() != 0) {
        std::string outs, fails;
        for (size_t i = 0; i < g_ft_outs.size(); ++i) {
            if (const uint64_t n = g_ft_outs[i].load()) {
                outs += std::format("{}{} {}", outs.empty() ? "" : ", ", ftl::f3_out_name(static_cast<ftl::F3Out>(i)), n);
            }
        }
        for (size_t i = 1; i < g_ft_fails.size(); ++i) {
            if (const uint64_t n = g_ft_fails[i].load()) {
                fails += std::format("{}{} {}", fails.empty() ? "" : ", ", ftl::mgr_fail_name(static_cast<ftl::MgrFail>(i)), n);
            }
        }
        log::info("User2Funnels fast travel (user2_fast_travel={}, {}): the 2283's vf48 under user 2: {} | user 2's "
                  "manager not readable: {} | 0x2BC4950's vf48: user 2's {}, the owner's after a block {} | other vf48 "
                  "while a 2283 of user 2 is applied (the owner's): {}",
                  ftl::mode_name(static_cast<ftl::Mode>(g_ft_mode.load())), g_ft_on.load() ? "live" : "NOT live",
                  outs.empty() ? "none yet" : outs, fails.empty() ? "never" : fails,
                  g_ft_apply[static_cast<size_t>(ftl::ApplyOut::Real)].load(),
                  g_ft_apply[static_cast<size_t>(ftl::ApplyOut::Original)].load(), sites_text(g_ft_other_vf48));
    }
    if (g_f4_mode.load() != 0 || g_f4_events.load() != 0) {
        std::string outs;
        for (size_t i = 1; i < g_f4_outs.size(); ++i) {
            if (const uint64_t n = g_f4_outs[i].load()) {
                outs += std::format("{}{} {}", outs.empty() ? "" : ", ", ftl::f4_out_name(static_cast<ftl::F4Out>(i)), n);
            }
        }
        log::info("User2Funnels revive F4 (user2_revive_manager={}, {}): 0x2BC4950's vf48 under user 2 without F3: {}",
                  ftl::mode_name(static_cast<ftl::Mode>(g_f4_mode.load())), g_f4_on.load() ? "live" : "NOT live",
                  outs.empty() ? "none yet" : outs);
    }
    if (g_rank_on) {
        for (int i = 0; i < 2; ++i) {
            const RankSite& s = g_rank_site[i];
            log::info("User2Funnels rank exe+0x{:X}: calls {} | user 2's character {} (original 1: {}, original 0: "
                      "{}) | answered 1 {} | would (probe) {} | no target component {} | not user 2 {} | other dl {}",
                      i == 0 ? kRankCtx1 + kRankCallAt : kRankCtx2 + kRankCallAt, s.calls.load(), s.reached.load(),
                      s.orig_true.load(), s.reached.load() - s.orig_true.load(), s.overrides.load(), s.would.load(),
                      s.no_comp.load(), s.not_user2.load(), s.other_arg.load());
        }
    }
    if (!g_subject_on) return;
    std::string verdicts;
    for (size_t i = 0; i < g_subject_verdicts.size(); ++i) {
        if (const uint64_t n = g_subject_verdicts[i].load()) {
            verdicts += std::format("{}{} {}", verdicts.empty() ? "" : ", ",
                                    u2f::subject_name(static_cast<u2f::SubjectVerdict>(i)), n);
        }
    }
    const uintptr_t wrong_vt = g_wrong_class_vt.load();
    log::info("User2Funnels subject: Reqs while user 2 is live {} | of user 2 {} ({}) | top Req opcodes of user 2: {}{}",
              g_reqs_total.load(), g_reqs_user2.load(), verdicts.empty() ? "none" : verdicts, ops_text(g_req_ops),
              wrong_vt ? std::format(" | last other class: vtable exe+0x{:X}", wrong_vt - g_base) : std::string{});
    struct Row {
        uint8_t f;
        bool on;
        const u2f::SiteCounts<64>* callers;
    };
    const Row rows[] = {{u2f::kVf40, g_vf40_on, &g_vf40_callers},
                        {u2f::kVf48, g_vf48_on, &g_vf48_callers},
                        {u2f::kFindUser, g_finduser_on, &g_finduser_callers},
                        {u2f::kDead, g_dead_on, &g_dead_other_callers},
                        {u2f::kLoot, g_loot_on, &g_loot_other_callers}};
    for (const Row& r : rows) {
        if (!r.on) continue;
        const u2f::FunnelCounters& c = g_fc[r.f];
        std::string extra;
        if (r.f == u2f::kVf40) {
            extra = std::format(" | probe: the same {}, different {} | user 2's not readable {} (no table {}, no "
                                "component {}, component class {}, no manager {}, manager class {})",
                                c.same.load(), c.differ.load(), c.unreadable.load(), g_chain_fail[1].load(),
                                g_chain_fail[2].load(), g_chain_fail[3].load(), g_chain_fail[4].load(),
                                g_chain_fail[5].load());
        } else if (r.f == u2f::kFindUser) {
            extra = std::format(" | key: the host's {}, user 2's {}, other {}", g_fu_host.load(), g_fu_user2.load(),
                                g_fu_other.load());
        } else if (r.f == u2f::kDead || r.f == u2f::kLoot) {
            extra = std::format(" | probe: already user 2's {}, the owner's {} | not done {}", c.same.load(),
                                c.differ.load(), c.unreadable.load());
        }
        log::info("User2Funnels {}: under user 2's Reqs {}, at the filtered caller {} | {}{} | Req opcodes {} | {} {}",
                  u2f::funnel_name(r.f), c.under_subject.load(), c.calls.load(), outs_text(c), extra, ops_text(c.ops),
                  r.f == u2f::kDead || r.f == u2f::kLoot ? "other callers under user 2's Reqs" : "callers",
                  sites_text(*r.callers));
    }
}

DWORD WINAPI funnels_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto build = game::current_build();
    if (build == game::Build::unsupported ||
        !(game::legacy_layout() || build == game::Build::v3576 || build == game::Build::v3663)) {
        log::error("User2Funnels: unsupported game build; rank_permit / quest_per_user / kill_loot_per_user stay off");
        return 0;
    }
    if (build == game::Build::v3663) {
        // Build 1.0.0.3663 (static, 2026-11-13; never run): the addresses and arrays above kPolicyVtableCallRets3663.
        // 3527's layout and offsets (the vf40/vf48 chains, the handle, [field+0x180], +0x0C of a Troc: same bytes),
        // except the sequencer manager's store +0x6D8 (kApplyCtx3663Bytes). TransformSync: FieldMover TS+0x508 still
        // (EnterField 0x2ECB4DC..0x2ECB4E3: [[actor+0x68]+0x1A0] + 0x508); the FieldMover's own fields read by the
        // travel probe (+0x60 / +0x78 / +0x79 / +0xA1) are 3527's, not re-derived. vtables by RTTI
        // (vtable_map_3576_3663.json).
        g_is_3527 = true;
        g_is_3663 = true;
        kExecuteTroc = 0x2A0FA80;
        kRankCtx1 = 0x2465449;
        kRankCtx2 = 0x24664B0;
        kVf40 = 0x2DFF2F0;
        kVf48 = 0x2DFF360;
        kQuestEventCb = 0x2BE0710;
        kOwnerChar = 0x2DFE560;
        kDeadCallCtx = 0x2C19612;
        kDeadRet = 0x2C19623;
        kOwnerUserStub = 0x2313BE0;
        kLootCallCtx = 0x2E8C61C;
        kLootRet = 0x2E8C629;
        kFindUser = 0x2D78C20;
        kUserManagerSlot = 0x72456F0;
        kReloadCallCtx = 0x2D5540B;
        kApplyReload = 0x2B586B0;
        kApplyCallCtx = 0x2ED02C3;
        kVtServerSequencerStageManager = 0x5F5A758;
        kVtServerNormalInGameActor = 0x5F60BB0;
        kVtServerChildOnlyInGameActor = 0x5F610C8;
        kVtServerQuestActorComponent = 0x5F62888;
        kVtServerQuestManager = 0x5F629D8;
        kTrocInstancesBegin = 0x6F14E10;
        kTrocInstancesEnd = 0x6F48840;
        kTsPending = 0x568;
        kTsBranch18 = 0x580;
        kTsBranch19 = 0x581;
        kTsArmed = 0x5A9;
        kMgrApplyByte = 0x6D8;  // 0x2ED02F5 mov byte [rbx+0x6D8],0 (3576 +0x6D0)
        g_exec_troc_bytes = kExecuteTroc3527Bytes;  // the same bytes
        g_vf48_bytes = kVf483663Bytes;
        g_reload_ctx_bytes = kReload3663CtxBytes;
        g_apply_reload_bytes = kApplyReload3527Bytes;  // the same bytes
        g_apply_ctx_bytes = kApplyCtx3663Bytes;
        g_rank_ctx1_bytes = kRankCtx13527Bytes;  // the same bytes, the permit calls' rel32 included
        g_rank_ctx2_bytes = kRankCtx23527Bytes;
        g_vf40_bytes = kVf403663Bytes;
        g_quest_event_bytes = kQuestEventCb3663Bytes;
        g_owner_char_bytes = kOwnerChar3663Bytes;
        g_dead_ctx_bytes = kDeadCallCtx3663Bytes;
        g_owner_stub_bytes = kOwnerUserStub3663Bytes;
        g_loot_ctx_bytes = kLootCallCtx3663Bytes;
        g_policy_vtable_rets = kPolicyVtableCallRets3663;
        // kFindUserBytes (29 bytes) is the same at 0x2D78C20.
    } else if (build == game::Build::v3576) {
        // Build 1.0.0.3576 (static, 2026-11-06; not yet run): 3527's layout and offsets at the addresses above the
        // 3576 arrays (TS +0x568.. : FieldMover TS+0x508 holds, field_share.h; the setter's store +0x6D0 is in
        // kApplyCtx3576Bytes). vtables by RTTI (vtable_map_3549_3576.json).
        g_is_3527 = true;
        g_is_3576 = true;
        kExecuteTroc = 0x29AD450;
        kRankCtx1 = 0x23F3B99;
        kRankCtx2 = 0x23F4C00;
        kVf40 = 0x2D98440;
        kVf48 = 0x2D984B0;
        kQuestEventCb = 0x2B7A7A0;
        kOwnerChar = 0x2D976B0;
        kDeadCallCtx = 0x2BB3BC2;
        kDeadRet = 0x2BB3BD3;
        kOwnerUserStub = 0x22A34C0;
        kLootCallCtx = 0x2E24E6C;
        kLootRet = 0x2E24E79;
        kFindUser = 0x2D11CC0;
        kUserManagerSlot = 0x71C0628;
        kReloadCallCtx = 0x2CEE4EB;
        kApplyReload = 0x2AF4690;
        kApplyCallCtx = 0x2E682E3;
        kVtServerSequencerStageManager = 0x5EE0B88;
        kVtServerNormalInGameActor = 0x5EE6FC0;
        kVtServerChildOnlyInGameActor = 0x5EE74D0;
        kVtServerQuestActorComponent = 0x5EE8C80;
        kVtServerQuestManager = 0x5EE8DD0;
        kTrocInstancesBegin = 0x6E90D10;
        kTrocInstancesEnd = 0x6EC4400;
        kTsPending = 0x568;
        kTsBranch18 = 0x580;
        kTsBranch19 = 0x581;
        kTsArmed = 0x5A9;
        kMgrApplyByte = 0x6D0;
        g_exec_troc_bytes = kExecuteTroc3527Bytes;  // the same bytes
        g_vf48_bytes = kVf483576Bytes;
        g_reload_ctx_bytes = kReload3576CtxBytes;
        g_apply_reload_bytes = kApplyReload3527Bytes;  // the same bytes
        g_apply_ctx_bytes = kApplyCtx3576Bytes;
        g_rank_ctx1_bytes = kRankCtx13527Bytes;  // the same bytes (the permit call's target moved with them)
        g_rank_ctx2_bytes = kRankCtx23527Bytes;
        g_vf40_bytes = kVf403576Bytes;
        g_quest_event_bytes = kQuestEventCb3576Bytes;
        g_owner_char_bytes = kOwnerChar3576Bytes;
        g_dead_ctx_bytes = kDeadCallCtx3527Bytes;  // the same bytes
        g_owner_stub_bytes = kOwnerUserStub3576Bytes;
        g_loot_ctx_bytes = kLootCallCtx3576Bytes;
        g_policy_vtable_rets = kPolicyVtableCallRets3576;
        // kFindUserBytes (29 bytes) is the same at 0x2D11CC0.
    } else if (build == game::Build::v3527) {
        g_is_3527 = true;
        kExecuteTroc = 0x29AC800;
        kRankCtx1 = 0x23F2E49;
        kRankCtx2 = 0x23F3EB0;
        kVf40 = 0x2D977D0;
        kVf48 = 0x2D97840;
        kQuestEventCb = 0x2B79B30;
        kOwnerChar = 0x2D96A40;
        kDeadCallCtx = 0x2BB2F52;
        kDeadRet = 0x2BB2F63;
        kOwnerUserStub = 0x22A2880;
        kLootCallCtx = 0x2E241FC;
        kLootRet = 0x2E24209;
        kFindUser = 0x2D11050;
        kUserManagerSlot = 0x71BE418;
        kReloadCallCtx = 0x2CED87B;
        kApplyReload = 0x2AF3A40;
        kApplyCallCtx = 0x2E67673;
        kVtServerSequencerStageManager = 0x5EDE980;
        kVtServerNormalInGameActor = 0x5EE52B8;
        kVtServerChildOnlyInGameActor = 0x5EE4DA8;
        kVtServerQuestActorComponent = 0x5EE6A68;
        kVtServerQuestManager = 0x5EE6BB8;
        kTrocInstancesBegin = 0x6E8ED10;
        kTrocInstancesEnd = 0x6EC2400;
        kTsPending = 0x568;
        kTsBranch18 = 0x580;
        kTsBranch19 = 0x581;
        kTsArmed = 0x5A9;
        kMgrApplyByte = 0x6D0;
        g_exec_troc_bytes = kExecuteTroc3527Bytes;
        g_vf48_bytes = kVf483527Bytes;
        g_reload_ctx_bytes = kReload3527CtxBytes;
        g_apply_reload_bytes = kApplyReload3527Bytes;
        g_apply_ctx_bytes = kApplyCtx3527Bytes;
        g_rank_ctx1_bytes = kRankCtx13527Bytes;
        g_rank_ctx2_bytes = kRankCtx23527Bytes;
        g_vf40_bytes = kVf403527Bytes;
        g_quest_event_bytes = kQuestEventCb3527Bytes;
        g_owner_char_bytes = kOwnerChar3527Bytes;
        g_dead_ctx_bytes = kDeadCallCtx3527Bytes;
        g_owner_stub_bytes = game::is_3549() ? std::span<const uint8_t>(kOwnerUserStub3549Bytes)
                                             : std::span<const uint8_t>(kOwnerUserStub3527Bytes);
        g_loot_ctx_bytes = kLootCallCtx3527Bytes;
        g_policy_vtable_rets = kPolicyVtableCallRets3527;
        // kFindUserBytes (29 bytes) is the same at 0x2D11050.
    }
    if (!p8_exe_sections(g_base, g_secs)) {
        log::error("User2Funnels: the game's section table is unreadable; everything stays off");
        return 0;
    }
    g_ret_rank[0] = g_base + kRankCtx1 + kRankCallAt + 5;  // after `call rel32`, on the nop
    g_ret_rank[1] = g_base + kRankCtx2 + kRankCallAt + 5;
    g_ret_dead = g_base + kDeadRet;
    g_ret_loot = g_base + kLootRet;
    g_vt_actor = g_base + kVtServerChildOnlyInGameActor;
    g_vt_actor2 = g_base + kVtServerNormalInGameActor;
    g_vt_qcomp = g_base + kVtServerQuestActorComponent;
    g_vt_qmgr = g_base + kVtServerQuestManager;
    g_trocs_begin = g_base + kTrocInstancesBegin;
    g_trocs_end = g_base + kTrocInstancesEnd;
    g_find_user = g_base + kFindUser;
    g_user_mgr_slot = g_base + kUserManagerSlot;
    bool ready = false;
    for (int i = 0; i < 24000 && !(ready = code_ready()); ++i) Sleep(5);
    if (!ready) log::warn("User2Funnels: the game's code is not the expected one after 2 minutes; checking once more");
    wait_for_world();

    const auto rank = static_cast<Mode>(g_rank_mode.load());
    const auto quest = static_cast<Mode>(g_quest_mode.load());
    const auto kill = static_cast<Mode>(g_kill_mode.load());
    const auto ft = static_cast<ftl::Mode>(g_ft_mode.load());
    const auto f4 = static_cast<ftl::Mode>(g_f4_mode.load());
    const bool any_probe = quest == Mode::Probe || kill == Mode::Probe;
    g_vt_seqmgr = g_base + kVtServerSequencerStageManager;
    bool was_live = false;
    refresh_keys(was_live);

    if (rank != Mode::Off) {
        g_rank_on = install_rank();
        log::info("User2Funnels: rank_permit {} {}", u2f::mode_name(rank),
                  g_rank_on ? std::format("ON: exe+0x{:X} and exe+0x{:X} call the thunk through the stub at 0x{:X} "
                                          "(FF 90 88 01 00 00 -> E8 rel32 90); {}",
                                          kRankCtx1 + kRankCallAt, kRankCtx2 + kRankCallAt, g_rank_stub.address(),
                                          rank == Mode::On ? "vf188(5) of user 2's main character answers 1"
                                                           : "read only: counts what vf188(5) answers for it")
                            : std::string("OFF (see the error above)"));
    }
    const auto policy = static_cast<Mode>(g_policy_mode.load());
    if (quest != Mode::Off || kill != Mode::Off || ft != ftl::Mode::Off || f4 != ftl::Mode::Off ||
        policy != Mode::Off) {
        // The funnels first (without a subject they only call the original), the subject last.
        if (quest != Mode::Off || policy != Mode::Off) {
            g_vf40_on = install_inline({kVf40, g_vf40_bytes, "ServerField::vf40 0x2B00C70"}, kVfBoundaries,
                                       reinterpret_cast<void*>(&vf40_detour), g_vf40, g_patch[u2f::kVf40]);
        }
        g_vf48_on = install_inline({kVf48, g_vf48_bytes, "ServerField::vf48 0x2B00CE0 (count only)"}, kVfBoundaries,
                                   reinterpret_cast<void*>(&vf48_detour), g_vf48, g_patch[u2f::kVf48]);
        if (any_probe) {
            g_finduser_on = install_inline({kFindUser, kFindUserBytes, "FindUser 0x2A82590 (count only)"},
                                           kFindUserBoundaries, reinterpret_cast<void*>(&finduser_detour), g_finduser,
                                           g_patch[u2f::kFindUser]);
        }
        if (kill != Mode::Off) {
            const bool callers = verify({kDeadCallCtx, g_dead_ctx_bytes, "DeadActor's call 0x29432DE"}) &&
                                 verify({kLootCallCtx, g_loot_ctx_bytes, "the loot recipient's call 0x2B83D24"});
            if (callers) {
                g_dead_on = install_inline({kOwnerChar, g_owner_char_bytes, "the owner's character 0x2AFFF50"},
                                           kOwnerCharBoundaries, reinterpret_cast<void*>(&dead_detour), g_dead,
                                           g_patch[u2f::kDead]);
                // The loot substitution calls FindUser itself: its bytes too.
                if (verify({kFindUser, kFindUserBytes, "FindUser 0x2A82590 (the loot substitution calls it)"})) {
                    g_loot_on = install_inline({kOwnerUserStub, g_owner_stub_bytes,
                                                "the owner's user stub 0x20DEE60 (jmp .xtls; only the stub)"},
                                               kStubBoundaries, reinterpret_cast<void*>(&loot_detour), g_loot,
                                               g_patch[u2f::kLoot]);
                }
            }
        }
        // F3: never patched there, only checked: the 2283 handler's vf48 call and 0x2896120's use of the manager.
        const bool ft_sites = ft != ftl::Mode::Off && g_vf48_on &&
                              verify({kReloadCallCtx, g_reload_ctx_bytes,
                                      "the 2283 handler's vf48 call 0x2A5F7F9 and its call 0x2896120"}) &&
                              verify({kApplyReload, g_apply_reload_bytes, "0x2896120's head (mov r13,[rcx+0x18])"}) &&
                              verify({kApplyCallCtx, g_apply_ctx_bytes,
                                      "0x2BC4950's vf48 call 0x2BC4C50 and its +0x6A0 write 0x2BC4C80"});
        // F4: the same vf48 hook; only the setter's call site is checked (0x2BC4C49 .. 0x2BC4C80).
        const bool f4_sites = f4 != ftl::Mode::Off && g_vf48_on &&
                              verify({kApplyCallCtx, g_apply_ctx_bytes,
                                      "0x2BC4950's vf48 call 0x2BC4C50 and its +0x6A0 write 0x2BC4C80 (F4)"});
        const bool funnels = g_vf40_on || g_dead_on || g_loot_on || ft_sites || f4_sites;
        if (funnels) {
            g_subject_on = install_inline({kExecuteTroc, g_exec_troc_bytes, "ExecuteTroc 0x2774B20"},
                                          kExecuteTrocBoundaries, reinterpret_cast<void*>(&troc_detour), g_troc,
                                          g_patch[u2f::kFunnels]);
        }
        g_ft_on.store(ft_sites && g_subject_on, std::memory_order_release);
        g_f4_on.store(f4_sites && g_subject_on, std::memory_order_release);
        if (f4 != ftl::Mode::Off) {
            log::info("User2Funnels: user2_revive_manager {} {}", ftl::mode_name(f4),
                      g_f4_on.load() ? std::format("LIVE: user 2's ReviveLoadingReq 2362 -> the reload setter's vf48 "
                                                   "returning to exe+0x{:X} {}",
                                                   ftl::kApplyVf48Ret,
                                                   f4 == ftl::Mode::On
                                                       ? "answers user 2's own ServerSequencerStageManager (the "
                                                         "host's +0x6A0 is never reset by user 2's revive)"
                                                       : "logs what it would answer (the owner's is kept)")
                                     : std::string("NOT live (see the errors above)"));
        }
        if (ft != ftl::Mode::Off) {
            log::info("User2Funnels: user2_fast_travel {} {}", ftl::mode_name(ft),
                      g_ft_on.load() ? std::format("LIVE: user 2's ReloadStageStartReq 2283 -> vf48 returning to "
                                                   "exe+0x{:X} {}",
                                                   ftl::kReloadVf48Ret,
                                                   ft == ftl::Mode::On
                                                       ? "answers user 2's own ServerSequencerStageManager (its "
                                                         "vtable and +0x18 checked)"
                                                       : "logs what it would answer (the owner's is kept)")
                                     : std::string("NOT live (see the errors above): user 2's 2283 is dropped by F2"));
        }
        log::info("User2Funnels: quest_per_user {} (vf40 {}), kill_loot_per_user {} (DeadActor 0x2AFFF50 {}, loot "
                  "0x20DEE60 {}) | subject at ExecuteTroc {} | counters: vf48 {}, FindUser {} | patches {} / {} / {} "
                  "/ {} / {} / {} bytes{}",
                  u2f::mode_name(quest), g_vf40_on ? "hooked" : "off", u2f::mode_name(kill),
                  g_dead_on ? "hooked" : "off", g_loot_on ? "hooked" : "off", g_subject_on ? "hooked" : "OFF",
                  g_vf48_on ? "hooked" : "off", g_finduser_on ? "hooked" : "off", g_patch[u2f::kVf40],
                  g_patch[u2f::kVf48], g_patch[u2f::kFindUser], g_patch[u2f::kDead], g_patch[u2f::kLoot],
                  g_patch[u2f::kFunnels],
                  funnels && !g_subject_on ? " | WITHOUT the subject nothing is counted or changed" : "");
        if (g_is_3527 && (quest != Mode::Off || kill != Mode::Off || policy != Mode::Off)) {
            // The lines above and below name the functions by their 2976 addresses, as the logic does.
            log::info("User2Funnels: on this build vf40 is exe+0x{:X}, 0x2AFFF50 exe+0x{:X} (from exe+0x{:X}), 0x20DEE60 "
                      "exe+0x{:X} (from exe+0x{:X}), FindUser exe+0x{:X}; the vf40 return addresses are mapped to 2976's",
                      kVf40, kOwnerChar, kDeadRet, kOwnerUserStub, kLootRet, kFindUser);
        }
        if (policy != Mode::Off) {
            // quest_policy (S34): its vtable callers of vf40 must be what it assumes; then its read-only probe.
            static constexpr uint8_t kCallVf40[] = {0xFF, 0x50, 0x40};
            int bad = 0;
            for (const uint32_t r : g_policy_vtable_rets) {
                if (!verify({r - 3, kCallVf40, "a vf40 call of quest_policy (call [rax+0x40])"})) ++bad;
            }
            uint32_t patch = 0;
            g_qevent_on.store(install_inline({kQuestEventCb, g_quest_event_bytes,
                                              "the quest component's event callback 0x290DBD0 (count only)"},
                                             kQuestEventCbBoundaries, reinterpret_cast<void*>(&qevent_detour), g_qevent,
                                             patch));
            log::info("User2Funnels: quest_policy {} | vf40: the host's at 0x290DC0B / 0x2C4A36F / 0x104C4B3D / "
                      "0x2C3409D / 0x2B03AA7 / 0x2A4A32B, its own at 0x2C4A0AD / 0x2A49183 / 0x2A4A03B ({}) | "
                      "DeadActor {} | probe 0x290DBD0 {}{}",
                      u2f::mode_name(policy), policy == Mode::On ? "applied" : "counted only",
                      policy == Mode::On ? "kept native (the field owner's)" : "as kill_loot_per_user says",
                      g_qevent_on.load() ? std::format("hooked ({} bytes)", patch) : std::string("OFF"),
                      bad ? std::format(" | {} call site(s) NOT as expected (see the errors above)", bad)
                          : std::string());
        }
    }
    g_on.store(g_rank_on || g_subject_on);
    if (!g_on.load()) {
        log::warn("User2Funnels: nothing installed");
        return 0;
    }
    for (uint64_t tick = 1;; ++tick) {
        Sleep(100);
        refresh_keys(was_live);
        if (tick % 10 == 0) drain();
        if (tick % 600 == 0) {
            drain();
            summary();
        }
    }
}

}  // namespace

void user2_funnels_start(const User2FunnelOptions& opt) {
    const u2f::ParsedMode r = u2f::parse_mode(opt.rank_permit), q = u2f::parse_mode(opt.quest_per_user),
                          k = u2f::parse_mode(opt.kill_loot_per_user);
    if (!r.known) log::warn("User2Funnels: rank_permit='{}' is not 0, probe or 1; it stays off", opt.rank_permit);
    if (!q.known) log::warn("User2Funnels: quest_per_user='{}' is not 0, probe or 1; it stays off", opt.quest_per_user);
    if (!k.known) {
        log::warn("User2Funnels: kill_loot_per_user='{}' is not 0, probe or 1; it stays off", opt.kill_loot_per_user);
    }
    const u2f::ParsedMode qp = u2f::parse_mode(opt.quest_policy);
    if (!qp.known) log::warn("User2Funnels: quest_policy='{}' is not 0, probe or 1; it stays off", opt.quest_policy);
    const ftl::ParsedMode f = ftl::parse_mode(opt.user2_fast_travel);
    const ftl::ParsedMode f4 = ftl::parse_mode(opt.user2_revive_manager);
    if (!f4.known) {
        log::warn("User2Funnels: user2_revive_manager='{}' is not 0, probe or 1; it stays off", opt.user2_revive_manager);
    }
    if (!f.known) {
        log::warn("User2Funnels: user2_fast_travel='{}' is not 0, probe or 1; it stays off (user 2's 2283 is dropped "
                  "by F2)",
                  opt.user2_fast_travel);
    }
    if (r.mode == Mode::Off && q.mode == Mode::Off && k.mode == Mode::Off && f.mode == ftl::Mode::Off &&
        f4.mode == ftl::Mode::Off && qp.mode == Mode::Off) {
        return;
    }
    if (!opt.create_session) {
        log::warn("User2Funnels: rank_permit / quest_per_user / kill_loot_per_user / user2_fast_travel / "
                  "user2_revive_manager need create_session=1 (the host); off");
        return;
    }
    if (g_started.exchange(true)) return;
    g_rank_mode.store(static_cast<uint8_t>(r.mode));
    g_quest_mode.store(static_cast<uint8_t>(q.mode));
    g_policy_mode.store(static_cast<uint8_t>(qp.mode));
    g_kill_mode.store(static_cast<uint8_t>(k.mode));
    g_ft_mode.store(static_cast<uint8_t>(f.mode));
    g_f4_mode.store(static_cast<uint8_t>(f4.mode));
    // quest_policy's probe (S34): the host client's quest Acks come from the sniffer's capture.
    if (qp.mode != Mode::Off) {
        if (loaded_config().sniffer_enabled) {
            sniffer_tap_quest_policy();
        } else {
            log::warn("User2Funnels: quest_policy {}: [sniffer] enabled=0, the host client's 3009/3088/2738/2346 are "
                      "not counted",
                      u2f::mode_name(qp.mode));
        }
    }
    CloseHandle(CreateThread(nullptr, 0, funnels_thread, nullptr, 0, nullptr));
}

bool user2_funnels_active() { return g_on.load(); }

bool user2_funnels_vf48_live() noexcept { return g_on.load() && g_subject_on && g_vf48_on; }

int32_t user2_funnels_trocs_in_flight() noexcept { return g_u2_trocs.load(std::memory_order_seq_cst); }

bool user2_funnels_vf40_live() noexcept { return g_on.load() && g_subject_on && g_vf40_on; }

void user2_funnels_subject_now(uintptr_t& actor, uint16_t& opcode, bool& hooked) noexcept {
    // g_subject_on is written before g_on's store (install), read after its load here.
    hooked = g_on.load() && g_subject_on;
    actor = hooked ? t_frame.actor : 0;
    opcode = hooked ? t_frame.opcode : 0;
}

bool user2_funnels_subject_ready(uintptr_t actor) noexcept {
    // g_ft_on (release after the subject hook and the vtables are in place) implies the subject is installed.
    if (!g_ft_on.load(std::memory_order_acquire) || !actor) return false;
    u2f::SubjectIn in;
    in.on = true;
    in.keys = keys_now();
    in.expected_vtable = g_vt_actor;
    in.expected_vtable2 = g_vt_actor2;
    in.params_ok = true;
    in.actor = actor;
    // The same reads subject_enter does at ExecuteTroc, guarded (any thread).
    in.read_ok = game::safe_read(actor + kActorKey, &in.key, sizeof in.key) &&
                 game::safe_read(actor + kActorController, &in.controller, sizeof in.controller) &&
                 game::safe_read(actor, &in.vtable, sizeof in.vtable);
    return u2f::decide_subject(in) == u2f::SubjectVerdict::Subject;
}

bool user2_funnels_fast_travel_live() noexcept {
    return g_ft_on.load(std::memory_order_acquire) &&
           static_cast<ftl::Mode>(g_ft_mode.load(std::memory_order_relaxed)) == ftl::Mode::On;
}

std::string user2_funnels_describe() {
    if (!g_started.load()) return {};
    uint64_t rank_reached = 0, rank_over = 0, rank_would = 0;
    for (const RankSite& s : g_rank_site) {
        rank_reached += s.reached.load();
        rank_over += s.overrides.load();
        rank_would += s.would.load();
    }
    return std::format(
        "rank_permit {} ({}): user 2 reached {}, answered 1 {}, would {} | quest_per_user {} / kill_loot_per_user {} "
        "(subject {}): user 2 Reqs {}, vf40 {} (user 2's {}), DeadActor {} (user 2's {}), loot {} (user 2's {}) | "
        "user 2 {} | events lost {}{}",
        u2f::mode_name(static_cast<Mode>(g_rank_mode.load())), g_rank_on ? "on" : "off", rank_reached, rank_over,
        rank_would, u2f::mode_name(static_cast<Mode>(g_quest_mode.load())),
        u2f::mode_name(static_cast<Mode>(g_kill_mode.load())), g_subject_on ? "on" : "off", g_reqs_user2.load(),
        g_fc[u2f::kVf40].under_subject.load(), g_fc[u2f::kVf40].out[static_cast<size_t>(FunnelOut::Substitute)].load(),
        g_fc[u2f::kDead].calls.load(), g_fc[u2f::kDead].out[static_cast<size_t>(FunnelOut::Substitute)].load(),
        g_fc[u2f::kLoot].calls.load(), g_fc[u2f::kLoot].out[static_cast<size_t>(FunnelOut::Substitute)].load(),
        g_live.load() ? "LIVE" : "not live", g_ring.dropped(), policy_text());
}

QuestPolicyVerdict user2_funnels_policy_judge(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    QuestPolicyVerdict v;
    const auto policy = static_cast<Mode>(g_policy_mode.load(std::memory_order_relaxed));
    if (policy == Mode::Off || !g_started.load(std::memory_order_relaxed)) return v;
    if (!u2f::policy_relevant_req(opcode)) return v;
    v.relevant = true;
    v.opcode = opcode;
    v.size = static_cast<uint16_t>(std::min<size_t>(payload.size(), 0xFFFF));
    if (payload.size() >= 4) std::memcpy(&v.first_u32, payload.data(), 4);
    for (size_t i = 0; i < payload.size() && i < sizeof v.head; ++i) v.head[i] = payload[i];
    // User 2's main character and the field it stands in (guarded reads; the network thread).
    const u2f::Keys k = keys_now();
    uintptr_t user = 0, chr = 0, comps = 0, ts = 0, field = 0;
    uint32_t char_key = 0, owner = 0;
    // [TS + FieldMover + 0x10] (field_share.h: FieldMover TS+0x4F0, 3527, 3576 and 3663 TS+0x508; 3663: EnterField
    // 0x2ECB4DC..0x2ECB4E3, static; FM+0x10 is 3527's, not re-derived).
    const uint32_t ts_field = game::current_build() == game::Build::v3527 || game::current_build() == game::Build::v3576 ||
                                      game::current_build() == game::Build::v3663
                                  ? 0x518
                                  : 0x500;
    if (server_user2(user) && user && game::fast_read(user + 0xD0, &chr, sizeof chr) && chr) {
        game::fast_read(chr + kActorKey, &char_key, sizeof char_key);
        if (game::fast_read(chr + u2f::kActorComponents, &comps, sizeof comps) && comps &&
            game::fast_read(comps + kComponentsTransformSync, &ts, sizeof ts) && ts &&
            game::fast_read(ts + ts_field, &field, sizeof field) && field &&
            game::fast_read(field + kFieldOwner, &owner, sizeof owner) && owner) {
            v.field = owner == k.host_user ? 1 : owner == k.user2_user ? 2 : 3;
        }
    }
    if (opcode == u2f::kOpChangePlayable) {
        v.drop = u2f::policy_drops_req(policy, opcode, u2f::RouteFail::None, v.field == 2);
        return v;
    }
    if (!u2f::policy_own_req(opcode)) return v;  // 2112 and the measured ones: never dropped
    // M1: the route its vf40 will take. vf40_live first: g_vt_qcomp / g_vt_qmgr are written before g_on's (seq_cst)
    // store, so they are read only once it says live (B2).
    u2f::RouteIn ri;
    ri.vf40_live = user2_funnels_vf40_live();
    ri.keys_live = k.live;
    ri.char_key = char_key;
    ri.user2_char = k.user2_char;
    if (ri.vf40_live && chr) {
        // The subject test subject_enter makes at ExecuteTroc (the same guarded reads as user2_funnels_subject_ready).
        u2f::SubjectIn si;
        si.on = true;
        si.keys = k;
        si.expected_vtable = g_vt_actor;
        si.expected_vtable2 = g_vt_actor2;
        si.params_ok = true;
        si.actor = chr;
        si.read_ok = game::fast_read(chr + kActorKey, &si.key, sizeof si.key) &&
                     game::fast_read(chr + kActorController, &si.controller, sizeof si.controller) &&
                     game::fast_read(chr, &si.vtable, sizeof si.vtable);
        ri.subject_ok = u2f::decide_subject(si) == u2f::SubjectVerdict::Subject;
        u2f::ChainFail why = u2f::ChainFail::None;
        ri.own_ok = u2f::quest_manager_of(FastMem{}, chr, g_vt_qcomp, g_vt_qmgr, &why).has_value();
    }
    const u2f::RouteFail route = u2f::trace_route(ri);
    v.route = static_cast<uint8_t>(route);
    v.drop = u2f::policy_drops_req(policy, opcode, route, v.field == 2);
    return v;
}

void user2_funnels_policy_record(const QuestPolicyVerdict& v, bool handed) noexcept {
    if (!v.relevant) return;
    try {
        const size_t where = v.field == 1 ? 0 : 1;  // the host's field / anywhere else (its own, another, unknown)
        const auto policy = static_cast<Mode>(g_policy_mode.load());
        if (v.opcode == u2f::kOpMissionTrigger) {
            const uint64_t n = g_trigger_reqs[where].fetch_add(1, std::memory_order_relaxed);
            g_trigger_ids.add(v.first_u32);
            if (n < 12 && where == 0) {
                std::string hex;
                for (size_t i = 0; i < v.size && i < sizeof v.head; ++i) hex += std::format("{:02X} ", v.head[i]);
                log::info("User2Funnels quest_policy: user 2's MissionTriggerInOutReq 2112 #{} in the host's field ({} "
                          "bytes): {}| {} | {}",
                          n + 1, v.size, hex, handed ? "handed to the server" : "not handed",
                          policy == Mode::On ? "its vf40 keeps the host's quest manager (its event goes to the host's "
                                               "character)"
                                             : "measured only: it reaches the quest manager quest_per_user gives");
            }
            return;
        }
        if (v.opcode == u2f::kOpChangePlayable) {
            g_change_reqs[where].fetch_add(1, std::memory_order_relaxed);
            if (v.drop) {
                if (g_change_dropped.fetch_add(1, std::memory_order_relaxed) < 4) {
                    log::warn("User2Funnels quest_policy: user 2's ChangePlayerbleCharacterReq 2369 dropped before the "
                              "server (a reload trip; its vf40 is the host's quest manager) - the guest's switch of "
                              "character does not happen");
                }
            } else if (u2f::policy_would_drop_req(policy, v.opcode, u2f::RouteFail::None, v.field == 2)) {
                g_change_would_drop.fetch_add(1, std::memory_order_relaxed);
            }
            return;
        }
        for (size_t i = 0; i < 4; ++i) {
            if (kMeasuredOps[i] == v.opcode) {
                g_measured[i][where][handed ? 1 : 0].fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        size_t i = 0;
        while (i < 3 && kOwnReqOps[i] != v.opcode) ++i;
        if (i == 3) return;
        g_own_reqs[i][where].fetch_add(1, std::memory_order_relaxed);
        const auto route = static_cast<u2f::RouteFail>(v.route);
        if (route != u2f::RouteFail::None && v.route < static_cast<uint8_t>(u2f::RouteFail::Count)) {
            g_own_route_fail[i][v.route].fetch_add(1, std::memory_order_relaxed);
        }
        if (v.drop) {
            if (g_own_dropped[i].fetch_add(1, std::memory_order_relaxed) < 4) {
                log::warn("User2Funnels quest_policy: user 2's Req {} dropped before the server: {} (it must never "
                          "reach the host's quest manager)",
                          v.opcode, u2f::route_fail_name(route));
            }
        } else if (u2f::policy_would_drop_req(policy, v.opcode, route, v.field == 2)) {
            g_own_would_drop[i].fetch_add(1, std::memory_order_relaxed);
        }
    } catch (...) {
    }
}

// quest_policy's probe: the host client's quest Acks (the sniffer's writer thread; counts only).
void user2_funnels_sniffed(const uint8_t* packet, size_t size, bool server_to_client) noexcept {
    if (!server_to_client || !packet || size < 2) return;
    uint16_t op = 0;
    std::memcpy(&op, packet, 2);
    if (const int i = u2f::host_quest_ack_index(op); i >= 0) g_host_acks[i].fetch_add(1, std::memory_order_relaxed);
}

}  // namespace cdmp::session2
