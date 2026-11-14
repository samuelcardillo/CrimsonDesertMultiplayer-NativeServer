#include "mod/session2/guest_seq_foreign.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <format>
#include <intrin.h>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_seq_foreign_logic.h"
#include "mod/session2/guest_seq_present.h"
#include "mod/session2/guest_seq_route.h"
#include "mod/session2/guest_seq_route_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;
namespace off = game::build_2976;

// ---------------------------------------------------------------- verified code (build 2976, capstone)
//
// The fix: 0xC05BB0's binding vector and its consumer 0xA9CA40 (guest_seq_foreign_logic.h has the walk-through).
struct Ctx {
    uint32_t rva;
    std::span<const uint8_t> bytes;
};
constexpr uint8_t kVecZero[] = {0x4C, 0x89, 0x7D, 0x80, 0x4C, 0x89, 0x7D, 0x88};  // 0xC05C79 mov [rbp-0x80],r15 ; [rbp-0x78]
constexpr uint8_t kVecStore[] = {0x4C, 0x89, 0x75, 0x80, 0x89, 0x5D, 0x8C, 0x49, 0x8D, 0x46, 0x08};  // 0xC05E44
constexpr uint8_t kVecInit[] = {0xC7, 0x40, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x50, 0xFC, 0x66,
                                0xC7, 0x00, 0x07, 0x00, 0x88, 0x50, 0x02, 0x48, 0x8D, 0x40, 0x0C};  // 0xC05E60
constexpr uint8_t kVecCount[] = {0x89, 0x5D, 0x88};                                              // 0xC05E84
constexpr uint8_t kVecStride[] = {0x41, 0x8B, 0xC7, 0x48, 0x8D, 0x0C, 0x40, 0x48, 0x8D, 0x1C, 0x8E};  // 0xC05EA0
constexpr uint8_t kVecActor[] = {0x48, 0x8D, 0x53, 0x04};                                         // 0xC05EE9
constexpr uint8_t kVecType[] = {0x48, 0x8D, 0x53, 0x08};                                          // 0xC05F1D
constexpr uint8_t kPlayData[] = {0x44, 0x89, 0x7D, 0x00};                                         // 0xC05C26 [rbp] = pd
constexpr uint8_t kCreateCall[] = {0x4C, 0x8D, 0x4D, 0x80, 0x4C, 0x8D, 0x45, 0x00, 0x48, 0x8D, 0x55, 0xB0,
                                   0x48, 0x8B, 0xC8, 0xE8, 0xB3, 0x68, 0xE9, 0xFF, 0x48, 0x8B, 0x75, 0x80};  // 0xC06179
constexpr uint8_t kVecFree[] = {0x48, 0x85, 0xF6, 0x74, 0x33, 0xBA, 0xFD, 0x01, 0x00, 0x00};               // 0xC061EF
constexpr uint8_t kCreateArg[] = {0x49, 0x8B, 0xF1};                                                       // 0xA9CA6A
constexpr uint8_t kCreateWalk[] = {0x4C, 0x8B, 0x36, 0x8B, 0x46, 0x08, 0x48, 0x8D, 0x0C, 0x40, 0x4D, 0x8D, 0x2C, 0x8E};  // 0xA9CB2E
constexpr uint8_t kCreateType[] = {0x41, 0x0F, 0xB6, 0x46, 0x08, 0x3C, 0x04, 0x74, 0x08,
                                   0x3C, 0x05, 0x0F, 0x85, 0x88, 0x00, 0x00, 0x00};  // 0xA9CB87
constexpr uint8_t kCreateCopy[] = {0xC4, 0xC1, 0x7B, 0x10, 0x06, 0xC5, 0xFB, 0x11, 0x45, 0x30, 0x41, 0x8B, 0x46, 0x08};  // 0xA9CC28
// guest_seq_route's own point (its bytes are checked by that module; here only that it is the same code).
constexpr uint8_t kRoutePoint[] = {0x80, 0xFB, 0x04, 0x74, 0x4A};  // 0xC0612A cmp bl,4 ; je 0xC06179
const Ctx kFixCode[] = {{0xC05C79, kVecZero},   {0xC05E44, kVecStore},   {0xC05E60, kVecInit},    {0xC05E84, kVecCount},
                        {0xC05EA0, kVecStride}, {0xC05EE9, kVecActor},   {0xC05F1D, kVecType},    {0xC05C26, kPlayData},
                        {0xC06179, kCreateCall}, {0xC061EF, kVecFree},   {0xA9CA6A, kCreateArg},  {0xA9CB2E, kCreateWalk},
                        {0xA9CB87, kCreateType}, {0xA9CC28, kCreateCopy}, {0xC0612A, kRoutePoint}};
// The .pdata of the two functions the fix relies on.
constexpr uint32_t kHandlerBegin = 0xC05BB0, kHandlerEnd = 0xC0632F, kCreateBegin = 0xA9CA40, kCreateEnd = 0xA9D47E;

// The probes: 40-byte signatures (each unique in .rsrc of the 2976 exe, checked offline with capstone) at whole
// instructions, no RIP-relative operand and no branch into the patched bytes (the whole RUNTIME_FUNCTION scanned).
constexpr uint8_t kP1Sig[] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x53, 0x56, 0x57,
                              0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x98, 0xEF,
                              0xFF, 0xFF, 0xB8, 0x68, 0x11, 0x00, 0x00, 0xE8, 0x58, 0x39, 0x29, 0x04};  // 0x602940
constexpr uint8_t kP21Sig[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41,
                               0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xE0, 0x48, 0x81,
                               0xEC, 0x20, 0x01, 0x00, 0x00, 0x4D, 0x8B, 0xF8, 0x48, 0x8B, 0xF2, 0x48};  // 0x601470
constexpr uint8_t kP22Sig[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24,
                               0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D,
                               0x6C, 0x24, 0xD0, 0x48, 0x81, 0xEC, 0x30, 0x01, 0x00, 0x00, 0x4D, 0x8B};  // 0x601C10
// 0x6034FA mov rax,[rbx] ; mov rcx,[rax+0x68] (7 bytes, two whole instructions) ... 0x603522 call [rax+0x1A0]
// (TransformSync vf1A0(pos, rot, 4, 5, 0)). [rbx] = the actor 0x205DC30 resolved (rbx = entry + 8 from 0x603368, + 0x20
// per entry at 0x603538), r15 = the stage (0x603120 mov r15,rcx; never written again). Reaching it means the game's own
// vf178 (0x603379) said "not the local user" and the actor is farther than the threshold from the section's mark.
constexpr uint8_t kP3Sig[] = {0x48, 0x8B, 0x03, 0x48, 0x8B, 0x48, 0x68, 0x48, 0x8B, 0x89, 0xA0, 0x01, 0x00, 0x00,
                              0x48, 0x8B, 0x01, 0xC6, 0x44, 0x24, 0x28, 0x00, 0xC6, 0x44, 0x24, 0x20, 0x05, 0x41,
                              0xB1, 0x04, 0x4C, 0x8D, 0x44, 0x24, 0x7C, 0x48, 0x8D, 0x54, 0x24, 0x40};
constexpr uint8_t kP3R15[] = {0x4C, 0x8B, 0xF9};                                                        // 0x603120
constexpr uint8_t kP3Rbx[] = {0x49, 0x8D, 0x5E, 0x08};                                                  // 0x603368
constexpr uint8_t kP3Next[] = {0x48, 0x83, 0xC3, 0x20};                                                 // 0x603538
constexpr uint8_t kP3Vf178[] = {0x48, 0x8B, 0x0B, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0x78, 0x01, 0x00, 0x00, 0x84, 0xC0};  // 0x603373
// ClientActor::vf178 0x4FE260: [[WorldSystem]+0x30]+0x58 == [actor+0xA0] && byte [actor+0x94] (P3 replicates it).
constexpr uint8_t kVf178[] = {0x48, 0x8B, 0x05, 0x29, 0xAF, 0x86, 0x06, 0x48, 0x8B, 0x50, 0x30, 0x48, 0x8B,
                              0x81, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x39, 0x42, 0x58};  // 0x4FE260 (rip -> 0x6D69190)
// P4 (review H-1 c): the entry of 0x5EB310 (.pdata 0x5EB310-0x5EC372, its only caller 0x5EB2C0 from .xdata 0x558C398):
// RCX = the order's owner (its stage at [rcx+0x10], 0x5EB34F / 0x5EB38F), R8 = the order ([r8] = the node, 0x5EB3AD).
constexpr uint8_t kP4Sig[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24,
                              0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D,
                              0xAC, 0x24, 0x00, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x00, 0x03, 0x00};
constexpr uint8_t kP4Stage[] = {0x48, 0x8B, 0x46, 0x10, 0x48, 0x8B, 0x90, 0x20, 0x01, 0x00, 0x00, 0x8B, 0x80, 0x28, 0x01,
                                0x00, 0x00, 0x48, 0x8D, 0x0C, 0x80};  // 0x5EB38F
constexpr uint8_t kP4Match[] = {0x49, 0x8B, 0x45, 0x00, 0x8B, 0x48, 0x30, 0x48, 0x8B, 0x02, 0x39, 0x48, 0x30};  // 0x5EB3AD
constexpr uint8_t kP4Type[] = {0x0F, 0xB6, 0x42, 0x0C, 0x3C, 0x07, 0x77, 0x0A, 0xB9, 0xC9, 0x00, 0x00, 0x00};  // 0x5EB41F
constexpr uint32_t kOrder_Stage = 0x10;
// Status bit 0x200 of the copy (review H-3) [V capstone]: 0x602C8E mov rcx,[rcx+0x68] ; 0x602C9F mov rcx,[rcx+0x20] ;
// call 0x1795490(Status, 0x200, 0, ...) ; 0x17954E4 mov ebx,[r14+0x390] (the flags it changes).
constexpr uint32_t kActor_Comps = 0x68, kComps_Status = 0x20, kStatus_Flags = 0x390, kStatusHidden = 0x200;
constexpr uint32_t kActor_Key = 0x60, kActor_User = 0xA0, kActor_Local = 0x94, kMgr_LocalUser = 0x58;

// ---------------------------------------------------------------- verified code (build 1.0.0.3527, capstone 2026-11-05)
//
// The handler 0xD33880 (.pdata 0xD33880-0xD33F91) and its create 0xBA7D00 (.pdata 0xBA7D00-0xBA888E):
//   0xD3394C mov [rbp-0x80],rbx ; mov [rbp-0x78],r14   (the vector zeroed: the same slots as 2976)
//   0xD33B3B mov [rbp-0x80],rbx ; mov [rbp-0x74],r15d ; lea rax,[r12+8]   (the pointer and the capacity)
//   0xD33B50 each entry initialized {u32 -1, u32 0, u16 7, u8 0}, stride 0xC (the very bytes of 2976)
//   0xD33B77 mov [rbp-0x78],r15d (the count)
//   0xD33B90 mov eax,r14d ; lea rcx,[rax+rax*2] ; lea rdx,[rbx+rcx*4] ; ... call 0x2643930: entry i, filled by a reader in
//            .text this time (its order comes from the wire: the captures show u32 node | u32 actor | u8 type | 2 x u8
//            at @92, and 0xBA7EC8 reads the type at +8, 0xBA7ED9 the actor at +4)
//   0xD338F8 mov [rbp+0x10],r14d: the play data is at [rbp+0x10] (0xD33A53 lea rdx,[rbp+0x10]), not [rbp]
//   0xD33D7B lea r9,[rbp-0x80] ; lea r8,[rbp+0x10] ; lea rdx,[rbp+0x100] ; mov rcx,rax ; call 0xBA7D00
//   0xD33E35 test rbx,rbx ; je ...  (the vector freed in this call)
//   0xBA7D29 mov rsi,r9 ; 0xBA7E75 mov r14,[rsi] ; mov eax,[rsi+8] ; ...  (the walk: the same 14 bytes as 2976)
//   0xBA7EC8 movzx eax,byte [r14+8] ; cmp al,4 ; je ; cmp al,5 ; jne 0xBA7F5B: only 4 / 5 get an actor reference
//   0xBA7F63 vmovsd xmm0,[r14] ; vmovsd [rbp-0x78],xmm0 ; mov eax,[r14+8]: each entry copied
// P1: 0x6C02C0 (.pdata 0x6C02C0-0x6C0A70), its only call 0xBA908A in 0xBA8FD0 (rcx = [rbx], the stage). P2, P3 and P4 are not
// ported to this build: their points are not re-derived, the keys that want them log that and go on without them.
constexpr uint8_t kVecZero3527[] = {0x48, 0x89, 0x5D, 0x80, 0x4C, 0x89, 0x75, 0x88};
constexpr uint8_t kVecStore3527[] = {0x48, 0x89, 0x5D, 0x80, 0x44, 0x89, 0x7D, 0x8C, 0x49, 0x8D, 0x44, 0x24, 0x08};
constexpr uint8_t kVecInit3527[] = {0xC7, 0x40, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x50, 0xFC, 0x66,
                                    0xC7, 0x00, 0x07, 0x00, 0x88, 0x50, 0x02, 0x48, 0x8D, 0x40, 0x0C};
constexpr uint8_t kVecCount3527[] = {0x44, 0x89, 0x7D, 0x88};
constexpr uint8_t kVecStride3527[] = {0x41, 0x8B, 0xC6, 0x48, 0x8D, 0x0C, 0x40, 0x48, 0x8D, 0x14, 0x8B};
constexpr uint8_t kPlayData3527[] = {0x44, 0x89, 0x75, 0x10};
constexpr uint8_t kCreateCall3527[] = {0x4C, 0x8D, 0x4D, 0x80, 0x4C, 0x8D, 0x45, 0x10, 0x48, 0x8D, 0x95, 0x00,
                                       0x01, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0xE8, 0x6E, 0x3F, 0xE7, 0xFF};
constexpr uint8_t kVecFree3527[] = {0x48, 0x85, 0xDB, 0x74, 0x35};
constexpr uint8_t kCreateArg3527[] = {0x49, 0x8B, 0xF1};
constexpr uint8_t kCreateWalk3527[] = {0x4C, 0x8B, 0x36, 0x8B, 0x46, 0x08, 0x48, 0x8D, 0x0C, 0x40, 0x4D, 0x8D, 0x2C, 0x8E};
constexpr uint8_t kCreateType3527[] = {0x41, 0x0F, 0xB6, 0x46, 0x08, 0x3C, 0x04, 0x74, 0x08,
                                       0x3C, 0x05, 0x0F, 0x85, 0x82, 0x00, 0x00, 0x00};
constexpr uint8_t kCreateCopy3527[] = {0xC4, 0xC1, 0x7B, 0x10, 0x06, 0xC5, 0xFB, 0x11, 0x45, 0x88, 0x41, 0x8B, 0x46, 0x08};
constexpr uint8_t kRoutePoint3527[] = {0x41, 0x80, 0xFE, 0x04, 0x74, 0x47};  // 0xD33D2E cmp r14b,4 ; je 0xD33D7B
const Ctx kFixCode3527[] = {{0xD3394C, kVecZero3527},   {0xD33B3B, kVecStore3527},  {0xD33B50, kVecInit3527},
                            {0xD33B77, kVecCount3527},  {0xD33B90, kVecStride3527}, {0xD338F8, kPlayData3527},
                            {0xD33D7B, kCreateCall3527}, {0xD33E35, kVecFree3527},  {0xBA7D29, kCreateArg3527},
                            {0xBA7E75, kCreateWalk3527}, {0xBA7EC8, kCreateType3527}, {0xBA7F63, kCreateCopy3527}};
// Not in the list: 0xD33D2E (kRoutePoint3527) is guest_seq_route's own hook point. That module checks those bytes
// before it hooks them, and once it has hooked them they are its jump: checked here they failed every time the fix was
// wanted (live 2026-11-05, "the code at exe+0xD33D2E (6 bytes) is not this build's"), and this fix only ever runs
// inside that hook.
constexpr uint32_t kHandlerBegin3527 = 0xD33880, kHandlerEnd3527 = 0xD33F91, kCreateBegin3527 = 0xBA7D00,
                   kCreateEnd3527 = 0xBA888E;
constexpr uint8_t kP1Sig3527[] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x53, 0x56, 0x57,
                                  0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x88, 0xEF,
                                  0xFF, 0xFF, 0xB8, 0x78, 0x11, 0x00, 0x00, 0xE8, 0xC8, 0x70, 0x4E, 0x04};  // 0x6C02C0
constexpr uint8_t kP1Caller3527[] = {0x48, 0x8B, 0x0B, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x4C, 0x8B, 0xC6, 0xE8, 0x31, 0x72,
                                     0xB1, 0xFF};  // 0xBA907F mov rcx,[rbx] ; lea rdx,[rsp+0x58] ; mov r8,rsi ; call 0x6C02C0

// Build 3576 (static, 2026-11-06 evening; not yet run): the 2661 handler and 0xBA7D00 moved as whole functions by +0x420
// (.pdata [0xD33CA0,0xD343B1) and [0xBA8120,0xBA8CAE), the same sizes), every fix array there with the same bytes; P1 by
// +0x660 ([0x6C0920,0x6C10D0)), its signature and its caller's with new rel32s.
const Ctx kFixCode3576[] = {{0xD33D6C, kVecZero3527},   {0xD33F5B, kVecStore3527},  {0xD33F70, kVecInit3527},
                            {0xD33F97, kVecCount3527},  {0xD33FB0, kVecStride3527}, {0xD33D18, kPlayData3527},
                            {0xD3419B, kCreateCall3527}, {0xD34255, kVecFree3527},  {0xBA8149, kCreateArg3527},
                            {0xBA8295, kCreateWalk3527}, {0xBA82E8, kCreateType3527}, {0xBA8383, kCreateCopy3527}};
constexpr uint32_t kHandlerBegin3576 = 0xD33CA0, kHandlerEnd3576 = 0xD343B1, kCreateBegin3576 = 0xBA8120,
                   kCreateEnd3576 = 0xBA8CAE;
constexpr uint8_t kP1Sig3576[] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x53, 0x56, 0x57,
                                  0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x88, 0xEF,
                                  0xFF, 0xFF, 0xB8, 0x78, 0x11, 0x00, 0x00, 0xE8, 0x48, 0x7A, 0x4E, 0x04};  // 0x6C0920
constexpr uint8_t kP1Caller3576[] = {0x48, 0x8B, 0x0B, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x4C, 0x8B, 0xC6, 0xE8, 0x71, 0x74,
                                     0xB1, 0xFF};  // 0xBA949F

// Build 1.0.0.3663 (static, 2026-11-13; never run): the 2661 handler moved as a whole function by +0x38ED0 from 3527
// (.pdata [0xD6C750,0xD6CE61), 3527's size 0x711) and 0xBA7D00 by +0x37F90 ([0xBDFC90,0xBE081E), 3527's size 0xB8E): every
// fix array is 3527's at old + that shift with the same bytes (kCreateWalk / kCreateType / kVecInit are anchors of
// anchors_3663.json), but the handler's call to the create (the two functions no longer moved together: new rel32,
// target 0xBDFC90). P1 by +0x2C5E0 ([0x6EC8A0,0x6ED050), 3527's size 0x7B0; kP1Sig3527 / kP1Caller3527 are anchors): its
// signature with a new __chkstk rel32; its only caller 0xBE100F in 0xBE0F60 (3527's 0xBA8FD0) with a new rel32 to it. P1
// reads the stage as on 3527 (0x6EC987 / 0x6EC98E +0x130 / +0x128, stride 0x28 at 0x6EC9CA, node +0xAC at 0x6ECB63, key
// entry+8 at 0x6ECB72, info +0x50 at 0x6ECA05, the scene key comp+0x2E0 vs stage+0x30 at 0x6ECBB4). No branch lands in
// P1's patched bytes (rel8 sweep of the function, rel32 scan of both code sections).
constexpr uint8_t kCreateCall3663[] = {0x4C, 0x8D, 0x4D, 0x80, 0x4C, 0x8D, 0x45, 0x10, 0x48, 0x8D, 0x95, 0x00,
                                       0x01, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0xE8, 0x2E, 0x30, 0xE7, 0xFF};  // 0xD6CC4B
const Ctx kFixCode3663[] = {{0xD6C81C, kVecZero3527},   {0xD6CA0B, kVecStore3527},  {0xD6CA20, kVecInit3527},
                            {0xD6CA47, kVecCount3527},  {0xD6CA60, kVecStride3527}, {0xD6C7C8, kPlayData3527},
                            {0xD6CC4B, kCreateCall3663}, {0xD6CD05, kVecFree3527},  {0xBDFCB9, kCreateArg3527},
                            {0xBDFE05, kCreateWalk3527}, {0xBDFE58, kCreateType3527}, {0xBDFEF3, kCreateCopy3527}};
constexpr uint32_t kHandlerBegin3663 = 0xD6C750, kHandlerEnd3663 = 0xD6CE61, kCreateBegin3663 = 0xBDFC90,
                   kCreateEnd3663 = 0xBE081E;
constexpr uint8_t kP1Sig3663[] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x53, 0x56, 0x57,
                                  0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x88, 0xEF,
                                  0xFF, 0xFF, 0xB8, 0x78, 0x11, 0x00, 0x00, 0xE8, 0x08, 0x81, 0x53, 0x04};  // 0x6EC8A0
constexpr uint8_t kP1Caller3663[] = {0x48, 0x8B, 0x0B, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x4C, 0x8B, 0xC6, 0xE8, 0x81, 0xB8,
                                     0xB0, 0xFF};  // 0xBE100F
// The stage fields on 3663: 3527's but `started` (+0x2C4 there). The timeline id moved +0x2D0 -> +0x2E0 (0xBE0FFD; the
// stage constructor 0x90714C0 writes -1 there at 0x9071509), so the block from +0x2C4 on is taken as moved +0x10: +0x2D4
// [E: 0xBDA43E reads a byte there, only ever logged here]. +0x69 at 0xBDA399 (+0x68 next to it [E]); owner +0xA0 (the
// owner lookup 0x228876B, observer_scene_copy's bytes); binds / info / name as P1 and SetInteraction 0x25CFA60 read them.
constexpr gsf::StageOffsets kStage3663{0x68, 0x69, 0xA0, 0x128, 0x130, 0x2D4, 0x50, 0x1B8};

enum ProbeId : uint8_t { kP1, kP21, kP22, kP3, kP4, kProbes };
struct ProbeDef {
    ProbeId id;
    uint32_t rva;
    uint32_t patch;
    uint32_t fn_begin, fn_end;  // its RUNTIME_FUNCTION
    std::span<const uint8_t> sig;
    std::vector<Ctx> ctx;
    const char* what;
};

// ---------------------------------------------------------------- state

uintptr_t g_base = 0;
// The build and its stage fields: written by guest_seq_foreign_start before any hook or thread.
bool g_3527 = false;  // 3527's layout (3527, 3549, 3576, 3663: the same handler frames)
bool g_3576 = false;  // 3576's addresses
bool g_3663 = false;  // 3663's addresses (and kStage3663)
const gsf::StageOffsets* g_so = &gsf::kStage2976;
uintptr_t g_world_slot = off::kWorldSystemSlot;
std::atomic<bool> g_probe{false};
std::atomic<bool> g_present{false};  // S45 guest_seq_foreign_present(_probe): P1 for guest_seq_present's S-A / R-A
std::atomic<bool> g_settled{false};
std::atomic<uint8_t> g_mode{0};  // gsf::Mode
std::atomic<bool> g_layout_ok{false};
std::atomic<bool> g_on[kProbes] = {};
SafetyHookMid g_hooks[kProbes];
std::string g_route_mode;  // written before the install thread starts

std::atomic<uint64_t> g_verdict[static_cast<size_t>(gsf::Verdict::Count)] = {};
std::atomic<uint64_t> g_written{0}, g_write_fail{0};
std::atomic<uint64_t> g_hidden_seen{0}, g_status_read{0};  // H-3: copies with Status bit 0x200 at a judged 2661
std::atomic<uint64_t> g_p1[static_cast<size_t>(gsf::P1::Count)] = {};
std::atomic<uint64_t> g_p1_calls{0}, g_learnt{0}, g_learn_skipped{0};
// S44 live: a stage whose owner P1 sees at a NON-player node after its binding was already neutralized (type 0):
// that instance was touched before the exception was known; a WRN line '[foreign NOT player node]' names it.
std::atomic<uint64_t> g_p1_not_player_neutralized{0};
std::atomic<uint64_t> g_p2[2][static_cast<size_t>(gsf::P2::Count)] = {};
std::atomic<uint64_t> g_p2_foreign[2] = {};      // calls on a foreign scene (owner != this client's character)
std::atomic<uint64_t> g_p2_desc0_other[2] = {};  // H-2: of those, the ones whose desc+0 (0x205D7C0) is another player
std::atomic<uint64_t> g_p2_truncated{0};         // H-7: more than 16 target ids
std::atomic<uint64_t> g_p3[static_cast<size_t>(gsf::P3::Count)] = {};
std::atomic<uint64_t> g_p3_vf178_local{0};  // P3 actors whose vf178 replica says "local" (expected 0)
std::atomic<uint64_t> g_p4[static_cast<size_t>(gsf::P4::Count)] = {};
// H-1 b: (resource, node id) -> node type learnt by P1; sequencer -> resource of the judged 2661s.
gsf::NodeMap<1024> g_nodes;
gsf::SeqResRing<256> g_seqres;

enum Kind : uint16_t { kEFix, kEP1, kEP2, kEP3, kEP4, kKindCount };
p::EventRing<512> g_ring;
p::WindowLimiter g_lim[kKindCount] = {{64, 5'000'000}, {64, 5'000'000}, {48, 5'000'000}, {48, 5'000'000}, {48, 5'000'000}};
std::atomic<uint64_t> g_limited{0}, g_lost{0};
uint64_t g_lines = 0, g_capped = 0;  // tick thread only
constexpr uint64_t kMaxLines = 4000;

// ---------------------------------------------------------------- hot path (SEH reads, no CRT, no allocation)

template <class T>
bool rd(uintptr_t a, T& v) noexcept {
    if (a < 0x10000) return false;
    __try {
        v = *reinterpret_cast<const volatile T*>(a);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
template <class T>
T rdv(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return rd(a, v) ? v : fallback;
}
uintptr_t rdp(uintptr_t a) noexcept { return rdv<uintptr_t>(a); }
bool wr8(uintptr_t a, uint8_t v) noexcept {
    if (a < 0x10000) return false;
    __try {
        *reinterpret_cast<volatile uint8_t*>(a) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void emit(Kind k, p::Event& e) noexcept {
    e.kind = k;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    if (!g_lim[k].take(e.qpc_us)) {
        g_limited.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!g_ring.push(e)) g_lost.fetch_add(1, std::memory_order_relaxed);
}

// A stage's actor list (stage+0x120 / +0x128), read-only, bounded, without the game's [stage+0x20] lock (review H-11:
// SEH makes it safe against faults; a torn read only gives a wrong line / learns nothing new).
size_t read_stage_binds(uintptr_t stage, gsf::StageBind* out, size_t cap, bool& readable) noexcept {
    readable = false;
    const uintptr_t vec = rdp(stage + g_so->binds);
    uint32_t n = 0;
    if (!rd(stage + g_so->bind_count, n) || n > gsf::kMaxStageBinds || (n && !vec)) return 0;
    readable = true;
    size_t k = 0;
    for (uint32_t i = 0; i < n && k < cap; ++i) {
        const uintptr_t e = vec + static_cast<uintptr_t>(i) * gsf::kBindStride;
        const uintptr_t node = rdp(e + gsf::kBind_Node);
        gsf::StageBind b;
        b.key = rdv<uint32_t>(e + gsf::kBind_Key);
        b.link = rdv<uint8_t>(e + gsf::kBind_Type, 0xFF);
        b.node_type = node ? rdv<uint8_t>(node + gsf::kNode_Type, 0xFF) : 0xFF;
        b.node_id = node ? rdv<uint32_t>(node + gsf::kNode_Id) : 0;
        b.node_id2 = node ? rdv<uint32_t>(node + gsf::kNode_Id2) : 0;
        out[k++] = b;
    }
    return k;
}

// One bind in a u64: key | node type << 32 | link << 40 | owner << 48 | own << 49 (its node id goes apart, whole: H-8).
uint64_t pack_bind(const gsf::StageBind& b, uint32_t owner, uint32_t own) noexcept {
    return b.key | static_cast<uint64_t>(b.node_type) << 32 | static_cast<uint64_t>(b.link) << 40 |
           static_cast<uint64_t>(b.key && b.key == owner) << 48 | static_cast<uint64_t>(b.key && own && b.key == own) << 49;
}
void put_name(uintptr_t stage, p::Event& e) noexcept {
    const uintptr_t info = rdp(stage + g_so->info);
    const uintptr_t name = info ? rdp(info + g_so->name) : 0;
    for (int k = 0; k < 3 && name; ++k) e.v[9 + k] = rdv<uint64_t>(name + 8 * k);
}
// Up to 3 binds of a stage, the owner's first: e.v[4..6] packed, their whole node ids in e.v[7] (two) and e.v[8].
void put_binds(const gsf::StageBind* b, size_t n, uint32_t owner, uint32_t own, p::Event& e) noexcept {
    uint32_t ids[3] = {};
    size_t slot = 0;
    for (int pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i < n && slot < 3; ++i) {
            if ((b[i].key == owner) != (pass == 0)) continue;
            e.v[4 + slot] = pack_bind(b[i], owner, own);
            ids[slot] = b[i].node_id;
            ++slot;
        }
    }
    e.v[7] = ids[0] | static_cast<uint64_t>(ids[1]) << 32;
    e.v[8] = ids[2];
}

// P1: the entry of 0x602940 (RCX = the stage that starts). Feeds the learnt node map (whenever it is installed: with
// guest_seq_foreign_player != 0 or the probe) for the stages of a 2661 the fix judged (its non-player nodes are the
// fix's exceptions from then on), and logs the foreign ones.
void on_p1(safetyhook::Context& ctx) noexcept {
    g_p1_calls.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t stage = ctx.rcx;
    const uint64_t seq = rdv<uint64_t>(stage + gsf::kStage_Seq);
    const uint32_t resource = g_seqres.find(seq);
    // S45 S-A (read-only) and R-A (guest_seq_foreign_present): two atomic loads when both keys are 0.
    guest_seq_present_p1(stage, resource);
    const uint32_t owner = rdv<uint32_t>(stage + g_so->owner);
    const uint32_t own = guest_seq_route_own_key();
    gsf::StageBind b[gsf::kMaxStageBinds];
    bool readable = false;
    const size_t n = read_stage_binds(stage, b, gsf::kMaxStageBinds, readable);
    // H-1 b: every node of the stage, by its ids (the 2661's u32 node is matched against node+0x30 / +0x34 [E]).
    if (resource && readable) {
        for (size_t i = 0; i < n; ++i) {
            if (b[i].node_type >= gsf::kNodeMixed) continue;
            bool ok = g_nodes.note(resource, b[i].node_id, b[i].node_type);
            if (b[i].node_id2 && b[i].node_id2 != b[i].node_id) ok = g_nodes.note(resource, b[i].node_id2, b[i].node_type) && ok;
            (ok ? g_learnt : g_learn_skipped).fetch_add(1, std::memory_order_relaxed);
        }
    }
    const gsf::P1 c = gsf::classify_p1(owner, own, std::span<const gsf::StageBind>(b, n), readable);
    g_p1[static_cast<size_t>(c)].fetch_add(1, std::memory_order_relaxed);
    if (c == gsf::P1::OwnScene || c == gsf::P1::OwnUnknown) return;
    uint8_t owner_nt = 0xFF, owner_link = 0xFF;
    for (size_t i = 0; i < n; ++i) {
        if (b[i].key == owner) {
            owner_nt = b[i].node_type;
            owner_link = b[i].link;
            break;
        }
    }
    if (c == gsf::P1::OwnerOtherNode && owner_link == gsf::kLinkNone) {
        g_p1_not_player_neutralized.fetch_add(1, std::memory_order_relaxed);
    }
    p::Event e;
    e.v[0] = static_cast<uint64_t>(c) | static_cast<uint64_t>(rdv<uint8_t>(stage + g_so->b60)) << 8 |
             static_cast<uint64_t>(rdv<uint8_t>(stage + g_so->b61)) << 16 |
             static_cast<uint64_t>(rdv<uint32_t>(stage + g_so->bind_count) & 0xFFFF) << 24 |
             static_cast<uint64_t>(owner_nt) << 40 | static_cast<uint64_t>(owner_link) << 48;
    e.v[1] = seq;
    e.v[2] = owner | static_cast<uint64_t>(own) << 32;
    e.v[3] = resource | static_cast<uint64_t>(resource != 0) << 32;
    put_binds(b, n, owner, own, e);
    put_name(stage, e);
    emit(kEP1, e);
}

// P2: the entries of vf21 0x601470 / vf22 0x601C10 (RCX = the stage, R8 = the SequencerControl description).
void on_p2(safetyhook::Context& ctx, int which) noexcept {
    if (!g_probe.load(std::memory_order_relaxed)) return;
    const uintptr_t stage = ctx.rcx;
    const uint32_t owner = rdv<uint32_t>(stage + g_so->owner);
    const uint32_t own = guest_seq_route_own_key();
    const bool started = rdv<uint8_t>(stage + g_so->started) != 0;
    const uintptr_t data = rdp(ctx.r8 + gsf::kDesc_Data);
    const uintptr_t idp = data ? rdp(data + gsf::kData_Ids) : 0;
    const uint32_t nid_all = data && idp ? rdv<uint32_t>(data + gsf::kData_IdCount) : 0;
    const bool truncated = nid_all > gsf::kMaxIds;  // H-7: the first 16, marked
    const uint32_t nid = truncated ? gsf::kMaxIds : nid_all;
    if (truncated) g_p2_truncated.fetch_add(1, std::memory_order_relaxed);
    uint32_t ids[gsf::kMaxIds] = {};
    for (uint32_t i = 0; i < nid; ++i) ids[i] = rdv<uint32_t>(idp + 4ull * i);
    gsf::StageBind b[gsf::kMaxStageBinds];
    bool readable = false;
    const size_t n = read_stage_binds(stage, b, gsf::kMaxStageBinds, readable);
    const gsf::Resolved r =
        gsf::resolve(std::span<const uint32_t>(ids, nid), std::span<const gsf::StageBind>(b, n));
    const gsf::P2 c = gsf::classify_p2(started, r, own);
    g_p2[which][static_cast<size_t>(c)].fetch_add(1, std::memory_order_relaxed);
    // H-9: foreign only with this client's own key known. H-2: vf21 / vf22 also hand [stage+0x98] (0x205D7C0, the
    // owner, resolved by key) to .xtls as desc+0, whatever the bindings say.
    const bool foreign = own && owner && owner != own;
    const bool desc0_other = foreign && gsf::is_character(owner);
    if (foreign) g_p2_foreign[which].fetch_add(1, std::memory_order_relaxed);
    if (desc0_other) g_p2_desc0_other[which].fetch_add(1, std::memory_order_relaxed);
    if (!foreign && c != gsf::P2::OtherPlayer) return;
    p::Event e;
    e.v[0] = static_cast<uint64_t>(c) | static_cast<uint64_t>(which) << 8 |
             static_cast<uint64_t>(r.mission_node) << 16 | static_cast<uint64_t>(truncated) << 17 |
             static_cast<uint64_t>(desc0_other) << 18 | static_cast<uint64_t>(r.counted) << 24 |
             static_cast<uint64_t>(nid_all & 0xFF) << 32 | static_cast<uint64_t>(r.n) << 40;
    e.v[1] = rdv<uint64_t>(stage + gsf::kStage_Seq);
    e.v[2] = owner | static_cast<uint64_t>(own) << 32;
    for (uint8_t i = 0; i < r.n && i < 4; ++i) e.v[3 + i] = r.keys[i] | static_cast<uint64_t>(r.links[i]) << 32;
    e.v[7] = (nid > 0 ? ids[0] : 0) | static_cast<uint64_t>(nid > 1 ? ids[1] : 0) << 32;
    put_name(stage, e);
    emit(kEP2, e);
}
void on_p21(safetyhook::Context& ctx) noexcept { on_p2(ctx, 0); }
void on_p22(safetyhook::Context& ctx) noexcept { on_p2(ctx, 1); }

// P3: 0x6034FA in 0x6030D0, right before the alignment's vf1A0 ([rbx] = the actor, r15 = the stage).
void on_p3(safetyhook::Context& ctx) noexcept {
    if (!g_probe.load(std::memory_order_relaxed)) return;
    const uintptr_t actor = rdp(ctx.rbx);
    const uintptr_t stage = ctx.r15;
    const uint32_t key = actor ? rdv<uint32_t>(actor + kActor_Key) : 0;
    const uint32_t own = guest_seq_route_own_key();
    const gsf::P3 c = gsf::classify_p3(key, own);
    g_p3[static_cast<size_t>(c)].fetch_add(1, std::memory_order_relaxed);
    const uintptr_t world = rdp(g_base + g_world_slot);
    const uintptr_t mgr = world ? rdp(world + off::kWorldSystem_ActorManager) : 0;
    const uintptr_t local_user = mgr ? rdp(mgr + kMgr_LocalUser) : 0;
    const uintptr_t user = actor ? rdp(actor + kActor_User) : 0;
    const uint8_t b94 = actor ? rdv<uint8_t>(actor + kActor_Local) : 0;
    const bool local = local_user && user == local_user && b94;
    if (local) g_p3_vf178_local.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    e.v[0] = static_cast<uint64_t>(c) | static_cast<uint64_t>(local) << 8 | static_cast<uint64_t>(b94) << 16;
    e.v[1] = rdv<uint64_t>(stage + gsf::kStage_Seq);
    e.v[2] = rdv<uint32_t>(stage + g_so->owner) | static_cast<uint64_t>(own) << 32;
    e.v[3] = key;
    put_name(stage, e);
    emit(kEP3, e);
}

// P4: the entry of 0x5EB310 (RCX = the order's owner, its stage at [rcx+0x10]; R8 = the order, [r8] = the node).
// Counts (and logs, foreign ones) what the native check at 0x5EB41F would let through: a binding at type 0 of the
// scene owner would get a client actor built (review H-1). Read-only.
void on_p4(safetyhook::Context& ctx) noexcept {
    const uintptr_t stage = rdp(ctx.rcx + kOrder_Stage);
    const uintptr_t node = rdp(ctx.r8);
    const uint32_t id = node ? rdv<uint32_t>(node + gsf::kNode_Id) : 0;
    const uint32_t owner = stage ? rdv<uint32_t>(stage + g_so->owner) : 0;
    const uint32_t own = guest_seq_route_own_key();
    gsf::StageBind b[gsf::kMaxStageBinds];
    bool readable = false;
    const size_t n = stage ? read_stage_binds(stage, b, gsf::kMaxStageBinds, readable) : 0;
    const gsf::StageBind* hit = nullptr;
    for (size_t i = 0; i < n && id; ++i) {
        if (b[i].node_id == id) {  // 0x5EB3B1: [entry node]+0x30 == [order node]+0x30, the first one
            hit = &b[i];
            break;
        }
    }
    const bool foreign = own && owner && owner != own;
    const gsf::P4 c = gsf::classify_p4(foreign, hit != nullptr, hit ? hit->key : 0, hit ? hit->link : 0xFF, owner);
    g_p4[static_cast<size_t>(c)].fetch_add(1, std::memory_order_relaxed);
    if (c == gsf::P4::NotForeign) return;
    p::Event e;
    e.v[0] = static_cast<uint64_t>(c) | static_cast<uint64_t>(hit ? hit->link : 0xFF) << 8 |
             static_cast<uint64_t>(hit ? hit->node_type : 0xFF) << 16;
    e.v[1] = stage ? rdv<uint64_t>(stage + gsf::kStage_Seq) : 0;
    e.v[2] = owner | static_cast<uint64_t>(own) << 32;
    e.v[3] = (hit ? hit->key : 0) | static_cast<uint64_t>(id) << 32;
    if (stage) put_name(stage, e);
    emit(kEP4, e);
}

// ---------------------------------------------------------------- lines (diagnostics thread)

std::string name_of(const p::Event& e) {
    char name[32] = {};
    gsr::scene_name(e.v + 9, 3, name, sizeof name);
    return name;
}
std::string node_type_text(uint8_t t) {
    if (t == gsf::kNodeUnknown) return "?";
    if (t == gsf::kNodeMixed) return "MIXED";
    return t == gsf::kNodeCurrentControl ? "0 (CurrentControl)" : std::format("{}", t);
}
std::string bind_text(uint64_t v, uint32_t node_id) {
    if (!v) return {};
    const auto key = static_cast<uint32_t>(v);
    const auto nt = static_cast<uint8_t>(v >> 32), link = static_cast<uint8_t>(v >> 40);
    const bool owner = (v >> 48) & 1, own = (v >> 49) & 1;
    return std::format(" [node 0x{:08X} type {} key 0x{:08X} link {}{}]", node_id, node_type_text(nt), key, link,
                       owner ? " OWNER" : own ? " THIS CLIENT'S" : "");
}

// The tick's tallies, per resource (bounded): the fix's verdicts, and P1's owner node (review H-1 a).
struct ResSeen {
    uint64_t applied = 0, applied_unseen = 0, would = 0, not_player = 0, no_owner = 0, other = 0;
    uint64_t p1_active = 0, p1_other_node = 0, p1_neutral = 0, p1_pending = 0, p1_no_owner = 0;
    uint32_t owner_node_types = 0;  // bit t: the owner was seen at a node of type t (bit 31: unreadable / >= 31)
    uint32_t owner_node_id = 0;     // the last owner node id P1 saw
    uint64_t hidden = 0;            // H-3: judged 2661 with the copy's Status bit 0x200 set
};
std::map<uint32_t, ResSeen> g_res;  // tick thread only
constexpr size_t kMaxRes = 128;
uint64_t g_ticks = 0;
ResSeen* res_slot(uint32_t r) {
    if (!r) return nullptr;
    if (!g_res.count(r) && g_res.size() >= kMaxRes) return nullptr;
    return &g_res[r];
}

// A P1 event of a foreign stage whose owner sits at a non-player node with its binding already at 0 (neutralized).
bool p1_late_exception(const p::Event& e) {
    return static_cast<gsf::P1>(e.v[0] & 0xFF) == gsf::P1::OwnerOtherNode &&
           static_cast<uint8_t>(e.v[0] >> 48) == gsf::kLinkNone;
}

std::string line_of(const p::Event& e) {
    const std::string when = p8_when(e.qpc_us);
    const uint64_t* v = e.v;
    if (e.kind == kEFix) {
        const auto verdict = static_cast<gsf::Verdict>(v[0] & 0xFF);
        const uint32_t written = (v[0] >> 8) & 0xFF, planned = (v[0] >> 16) & 0xFF, owner_entries = (v[0] >> 24) & 0xFF,
                       owner_other = (v[0] >> 32) & 0xFF, others = (v[0] >> 40) & 0xFF, count = (v[0] >> 48) & 0xFFFF;
        std::string binds;
        for (size_t i = 4; i < 8; ++i) {
            if (!v[i]) continue;
            const size_t k = i - 4;
            const auto node = static_cast<uint32_t>(k < 2 ? v[8] >> (32 * k) : v[9] >> (32 * (k - 2)));
            const auto nt = static_cast<uint8_t>(v[11] >> (8 * k));
            binds += std::format(" [{} 0x{:08X} -> 0x{:08X} type {}{}, node type {}]", (v[i] >> 48) & 0xFF, node,
                                 static_cast<uint32_t>(v[i]), (v[i] >> 32) & 0xFF,
                                 ((v[i] >> 40) & 1)   ? " -> 0 NEUTRALIZED"
                                 : ((v[i] >> 41) & 1) ? " -> 0 (would)"
                                                      : "",
                                 node_type_text(nt));
        }
        const char* tag = verdict == gsf::Verdict::Applied       ? "foreign"
                          : verdict == gsf::Verdict::Would       ? "would foreign"
                          : verdict == gsf::Verdict::NoOwnerBind ? "no owner bind"
                                                                 : "not touched";
        const std::string status = (v[10] >> 32) & 1
                                       ? std::format("Status +0x390 0x{:08X} (bit 0x200 {})", static_cast<uint32_t>(v[10]),
                                                     (v[10] & kStatusHidden) ? "SET: hidden" : "clear")
                                       : std::string("Status +0x390 unreadable");
        return std::format("GuestSeqForeign [{}] {} T{} | 2661 sequencer 0x{:X} resource 0x{:08X} of owner 0x{:08X} (this "
                           "client 0x{:08X}, M's 0x{:08X}) | {} | copy's {} | {} binding(s): owner's type 4/5 {}, owner's "
                           "other {}, left alone {} | written {}/{}{}{}",
                           tag, when, e.tid, v[1], static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[2]),
                           static_cast<uint32_t>(v[2] >> 32), static_cast<uint32_t>(v[3] >> 32),
                           gsf::verdict_name(verdict), status, count, owner_entries, owner_other, others, written, planned,
                           binds.empty() ? "" : " | first binds (entry, node -> actor, type):", binds);
    }
    if (e.kind == kEP1) {
        const bool late = p1_late_exception(e);
        std::string binds;
        const uint32_t ids[3] = {static_cast<uint32_t>(v[7]), static_cast<uint32_t>(v[7] >> 32),
                                 static_cast<uint32_t>(v[8])};
        for (size_t i = 0; i < 3; ++i) binds += bind_text(v[4 + i], ids[i]);
        return std::format("GuestSeqForeign [{}] {} T{} | stage seq 0x{:X} '{}' resource {} owner 0x{:08X} "
                           "(this client 0x{:08X}) +0x60/+0x61 {}/{} | {} | {} actor(s):{}{}",
                           late ? "foreign NOT player node" : "P1 start 0x602940", when, e.tid, v[1], name_of(e),
                           (v[3] >> 32) ? std::format("0x{:08X}", static_cast<uint32_t>(v[3])) : std::string("unknown"),
                           static_cast<uint32_t>(v[2]), static_cast<uint32_t>(v[2] >> 32), (v[0] >> 8) & 0xFF,
                           (v[0] >> 16) & 0xFF, gsf::p1_name(static_cast<gsf::P1>(v[0] & 0xFF)), (v[0] >> 24) & 0xFFFF,
                           binds,
                           late ? " | this instance's owner binding WAS neutralized (type 0) before the exception was known; "
                                  "its (resource, node) is never touched again (watch this scene; P4 is the abort criterion)"
                                : "");
    }
    if (e.kind == kEP2) {
        std::string keys;
        for (size_t i = 3; i < 7; ++i) {
            if (v[i]) keys += std::format(" 0x{:08X}(link {})", static_cast<uint32_t>(v[i]), (v[i] >> 32) & 0xFF);
        }
        return std::format("GuestSeqForeign [P2 SequencerControl {} {}] {} T{} | stage seq 0x{:X} '{}' owner 0x{:08X} "
                           "(this client 0x{:08X}){} | target ids {}{} (first 0x{:08X} 0x{:08X}{}) | 0x205DC30 would "
                           "count {}, resolve {}:{} | {}",
                           ((v[0] >> 8) & 0xFF) ? "vf22" : "vf21", ((v[0] >> 8) & 0xFF) ? "0x601C10" : "0x601470", when,
                           e.tid, v[1], name_of(e), static_cast<uint32_t>(v[2]), static_cast<uint32_t>(v[2] >> 32),
                           ((v[0] >> 18) & 1) ? " | desc+0 (0x205D7C0, [stage+0x98]) = ANOTHER player's character" : "",
                           (v[0] >> 32) & 0xFF, ((v[0] >> 17) & 1) ? " (TRUNCATED to 16)" : "",
                           static_cast<uint32_t>(v[7]), static_cast<uint32_t>(v[7] >> 32),
                           ((v[0] >> 16) & 1) ? ", mission node 0x1FFFFFFF" : "", (v[0] >> 24) & 0xFF, (v[0] >> 40) & 0xFF,
                           keys.empty() ? " none" : keys, gsf::p2_name(static_cast<gsf::P2>(v[0] & 0xFF)));
    }
    if (e.kind == kEP4) {
        return std::format("GuestSeqForeign [P4 client actor order 0x5EB310] {} T{} | stage seq 0x{:X} '{}' owner 0x{:08X} "
                           "(this client 0x{:08X}) | node 0x{:08X}: key 0x{:08X} link {} node type {} | {}",
                           when, e.tid, v[1], name_of(e), static_cast<uint32_t>(v[2]), static_cast<uint32_t>(v[2] >> 32),
                           static_cast<uint32_t>(v[3] >> 32), static_cast<uint32_t>(v[3]), (v[0] >> 8) & 0xFF,
                           node_type_text(static_cast<uint8_t>(v[0] >> 16)), gsf::p4_name(static_cast<gsf::P4>(v[0] & 0xFF)));
    }
    return std::format("GuestSeqForeign [P3 align 0x6034FA] {} T{} | stage seq 0x{:X} '{}' owner 0x{:08X} (this client "
                       "0x{:08X}) | actor 0x{:08X}: {} | vf178 replica {} (+0x94 {})",
                       when, e.tid, v[1], name_of(e), static_cast<uint32_t>(v[2]), static_cast<uint32_t>(v[2] >> 32),
                       static_cast<uint32_t>(v[3]), gsf::p3_name(static_cast<gsf::P3>(v[0] & 0xFF)),
                       ((v[0] >> 8) & 1) ? "LOCAL (unexpected)" : "not local", (v[0] >> 16) & 0xFF);
}

void tally(const p::Event& e) {
    if (e.kind == kEFix) {
        ResSeen* s = res_slot(static_cast<uint32_t>(e.v[3]));
        if (!s) return;
        switch (static_cast<gsf::Verdict>(e.v[0] & 0xFF)) {
            case gsf::Verdict::Applied: {
                ++s->applied;
                bool unseen = false;
                for (size_t k = 0; k < 4; ++k) {
                    unseen |= ((e.v[4 + k] >> 40) & 1) && static_cast<uint8_t>(e.v[11] >> (8 * k)) == gsf::kNodeUnknown;
                }
                s->applied_unseen += unseen;
                break;
            }
            case gsf::Verdict::Would: ++s->would; break;
            case gsf::Verdict::NotPlayerNode: ++s->not_player; break;
            case gsf::Verdict::NoOwnerBind: ++s->no_owner; break;
            default: ++s->other; break;
        }
        if (((e.v[10] >> 32) & 1) && (e.v[10] & kStatusHidden)) ++s->hidden;
    } else if (e.kind == kEP1 && (e.v[3] >> 32)) {
        ResSeen* s = res_slot(static_cast<uint32_t>(e.v[3]));
        if (!s) return;
        const auto nt = static_cast<uint8_t>(e.v[0] >> 40);
        switch (static_cast<gsf::P1>(e.v[0] & 0xFF)) {
            case gsf::P1::OwnerActive: ++s->p1_active; break;
            case gsf::P1::OwnerOtherNode: ++s->p1_other_node; break;
            case gsf::P1::OwnerNeutral: ++s->p1_neutral; break;
            case gsf::P1::OwnerPending: ++s->p1_pending; break;
            case gsf::P1::NoOwner: ++s->p1_no_owner; break;
            default: break;
        }
        if (nt != 0xFF) s->owner_node_types |= nt < 31 ? 1u << nt : 1u << 31;
        if ((e.v[4] >> 48) & 1) s->owner_node_id = static_cast<uint32_t>(e.v[7]);
    }
}

std::string node_types_text(uint32_t mask) {
    if (!mask) return "-";
    std::string t;
    for (uint32_t b = 0; b < 32; ++b) {
        if (mask & (1u << b)) t += (t.empty() ? "" : "/") + (b == 31 ? std::string(">=31") : std::format("{}", b));
    }
    return t;
}

std::string summary() {
    std::string fix;
    for (size_t k = 0; k < static_cast<size_t>(gsf::Verdict::Count); ++k) {
        if (const uint64_t n = g_verdict[k].load()) {
            fix += std::format(" {} x{};", gsf::verdict_name(static_cast<gsf::Verdict>(k)), n);
        }
    }
    std::string res;
    size_t shown = 0;
    for (const auto& [r, s] : g_res) {
        if (shown++ >= 64) break;
        res += std::format(" 0x{:08X} [fix: applied {} (node not seen yet {}), would {}, not player node {}, no owner bind "
                           "{}, other {}, copy hidden {} | P1: owner node type {} (node 0x{:08X}), active {}, OTHER NODE {}, "
                           "neutral {}, pending {}, no owner {}];",
                           r, s.applied, s.applied_unseen, s.would, s.not_player, s.no_owner, s.other, s.hidden,
                           node_types_text(s.owner_node_types), s.owner_node_id, s.p1_active, s.p1_other_node,
                           s.p1_neutral, s.p1_pending, s.p1_no_owner);
    }
    std::string p1, p2, p3, p4;
    for (size_t k = 0; k < static_cast<size_t>(gsf::P1::Count); ++k) {
        if (const uint64_t n = g_p1[k].load()) p1 += std::format(" {} x{};", gsf::p1_name(static_cast<gsf::P1>(k)), n);
    }
    for (int w = 0; w < 2; ++w) {
        std::string s;
        for (size_t k = 0; k < static_cast<size_t>(gsf::P2::Count); ++k) {
            if (const uint64_t n = g_p2[w][k].load()) s += std::format(" {} x{};", gsf::p2_name(static_cast<gsf::P2>(k)), n);
        }
        p2 += std::format(" {} (on foreign scenes {}, desc+0 another player {}):{}", w ? "vf22" : "vf21",
                          g_p2_foreign[w].load(), g_p2_desc0_other[w].load(), s.empty() ? " none;" : s);
    }
    for (size_t k = 0; k < static_cast<size_t>(gsf::P3::Count); ++k) {
        if (const uint64_t n = g_p3[k].load()) p3 += std::format(" {} x{};", gsf::p3_name(static_cast<gsf::P3>(k)), n);
    }
    for (size_t k = 0; k < static_cast<size_t>(gsf::P4::Count); ++k) {
        if (const uint64_t n = g_p4[k].load()) p4 += std::format(" {} x{};", gsf::p4_name(static_cast<gsf::P4>(k)), n);
    }
    return std::format(
        "GuestSeqForeign summary | guest_seq_foreign_player={} (handler layout {}): {} | written {}, write failures {}, "
        "copy hidden (Status 0x200) {} of {} read | learnt node map (exceptions = non-player nodes): {} pairs, notes {}, "
        "skipped {}, full {} | NEUTRALIZED at a non-player node (late exception) {} | per resource:{} | P1 [{}] calls {}:{} | P4 0x5EB310 [{}]:{} | guest_seq_foreign_probe={}: P2 [{} / {}] truncated {}:{} "
        "| P3 [{}]:{} vf178-replica local {} | lines limited {}, ring lost {}, lines over budget {}",
        gsf::mode_name(static_cast<gsf::Mode>(g_mode.load())), g_layout_ok.load() ? "verified" : "NOT verified",
        fix.empty() ? " none" : fix, g_written.load(), g_write_fail.load(), g_hidden_seen.load(), g_status_read.load(),
        g_nodes.used(), g_learnt.load(), g_learn_skipped.load(), g_nodes.full(), g_p1_not_player_neutralized.load(),
        res.empty() ? " none" : res,
        g_on[kP1].load() ? "hooked" : "not hooked", g_p1_calls.load(), p1.empty() ? " none" : p1,
        g_on[kP4].load() ? "hooked" : "not hooked", p4.empty() ? " none" : p4, g_probe.load() ? 1 : 0,
        g_on[kP21].load() ? "hooked" : "not hooked", g_on[kP22].load() ? "hooked" : "not hooked", g_p2_truncated.load(), p2,
        g_on[kP3].load() ? "hooked" : "not hooked", p3.empty() ? " none" : p3, g_p3_vf178_local.load(), g_limited.load(),
        g_ring.dropped(), g_capped);
}

// ---------------------------------------------------------------- install

bool bytes_at(uint32_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

// The build (base, PE timestamp) and the .pdata entries, read once.
bool read_pdata(std::vector<RUNTIME_FUNCTION>& out, std::string& why) {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (g_base != off::kImageBase || !game::safe_read(g_base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 ||
        !game::safe_read(g_base + static_cast<uint32_t>(dos.e_lfanew), &nt, sizeof nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || !(game::legacy_layout() || g_3576 || g_3663)) {
        why = "not build 1.0.0.2976, 3527, 3549, 3576 nor 3663 (base / PE timestamp)";
        return false;
    }
    const auto pd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!pd.VirtualAddress || !pd.Size || pd.Size % sizeof(RUNTIME_FUNCTION) || pd.Size > 0x1000000) {
        why = ".pdata unreadable";
        return false;
    }
    out.resize(pd.Size / sizeof(RUNTIME_FUNCTION));
    if (!game::safe_read(g_base + pd.VirtualAddress, out.data(), pd.Size)) {
        why = ".pdata unreadable";
        return false;
    }
    return true;
}
bool has_function(const std::vector<RUNTIME_FUNCTION>& pdata, uint32_t begin, uint32_t end) {
    return std::any_of(pdata.begin(), pdata.end(),
                       [&](const RUNTIME_FUNCTION& r) { return r.BeginAddress == begin && r.EndAddress == end; });
}

bool install_fix(std::span<const gad::Section> secs, const std::vector<RUNTIME_FUNCTION>& pdata) {
    std::string why;
    if (g_3663   ? !has_function(pdata, kHandlerBegin3663, kHandlerEnd3663) || !has_function(pdata, kCreateBegin3663, kCreateEnd3663)
        : g_3576 ? !has_function(pdata, kHandlerBegin3576, kHandlerEnd3576) || !has_function(pdata, kCreateBegin3576, kCreateEnd3576)
        : g_3527 ? !has_function(pdata, kHandlerBegin3527, kHandlerEnd3527) || !has_function(pdata, kCreateBegin3527, kCreateEnd3527)
                 : !has_function(pdata, kHandlerBegin, kHandlerEnd) || !has_function(pdata, kCreateBegin, kCreateEnd)) {
        why = ".pdata of 0xC05BB0 / 0xA9CA40 not the expected";
    }
    for (const Ctx& c : g_3663   ? std::span<const Ctx>(kFixCode3663)
                        : g_3576 ? std::span<const Ctx>(kFixCode3576)
                        : g_3527 ? std::span<const Ctx>(kFixCode3527)
                                 : std::span<const Ctx>(kFixCode)) {
        if (!why.empty()) break;
        if (!gad::in_real_code(secs, c.rva, static_cast<uint32_t>(c.bytes.size())) || !bytes_at(c.rva, c.bytes)) {
            why = std::format("the code at exe+0x{:X} ({} bytes) is not this build's", c.rva, c.bytes.size());
        }
    }
    g_layout_ok.store(why.empty(), std::memory_order_release);
    const auto mode = static_cast<gsf::Mode>(g_mode.load());
    const gsr::Mode route = gsr::parse_mode(g_route_mode);
    if (!why.empty()) {
        log::warn("GuestSeqForeign: guest_seq_foreign_player={} NOT active: {}; nothing is read nor written (as with 0)",
                  gsf::mode_name(mode), why);
        return false;
    }
    log::info("GuestSeqForeign guest_seq_foreign_player={} (handler layout verified: 0xC05BB0's binding vector "
              "[rbp-0x80] / count [rbp-0x78] / 12-byte entries, 0xA9CA40's copy and type check) | in guest_seq_route's "
              "0xC0612A hook, for a 2661 routed to X (owner = another player's character): {} | guest_seq_route={}{}",
              gsf::mode_name(mode),
              mode == gsf::Mode::On
                  ? "the owner's binding of type 5/4 set to 0 from its first appearance, except at a (resource, node) P1 "
                    "has seen NOT to be the player node (never touched again); NPC / gimmick bindings untouched"
                  : "only '[would foreign]' lines and counts, nothing written",
              g_route_mode.empty() ? "0" : g_route_mode,
              route == gsr::Mode::On      ? ""
              : route == gsr::Mode::Probe ? " (probe: the scenes go to M, so only WOULD)"
                                          : " (off: the hook never runs, nothing judged)");
    return true;
}

// P1 and P4 go in whenever the fix is on (P1 feeds its learnt map, P4 watches its risk); P2 / P3 only with the probe.
// P1 also for S45's guest_seq_foreign_present_probe (present): its S-A rides P1.
void install_probes(std::span<const gad::Section> secs, const std::vector<RUNTIME_FUNCTION>& pdata, bool fix, bool probe,
                    bool present) {
    const ProbeDef defs3527[] = {
        {kP1, 0x6C02C0, 5, 0x6C02C0, 0x6C0A70, kP1Sig3527, {{0xBA907F, kP1Caller3527}},
         "P1 0x6C02C0 entry (scene start, build 3527)"},
    };
    const ProbeDef defs3576[] = {
        {kP1, 0x6C0920, 5, 0x6C0920, 0x6C10D0, kP1Sig3576, {{0xBA949F, kP1Caller3576}},
         "P1 0x6C0920 entry (scene start, build 3576)"},
    };
    const ProbeDef defs3663[] = {
        {kP1, 0x6EC8A0, 5, 0x6EC8A0, 0x6ED050, kP1Sig3663, {{0xBE100F, kP1Caller3663}},
         "P1 0x6EC8A0 entry (scene start, build 3663)"},
    };
    const ProbeDef defs2976[] = {
        {kP1, 0x602940, 5, 0x602940, 0x6030C8, kP1Sig, {}, "P1 0x602940 entry (scene start)"},
        {kP21, 0x601470, 5, 0x601470, 0x601C04, kP21Sig, {}, "P2 vf21 0x601470 entry (SequencerControl start)"},
        {kP22, 0x601C10, 5, 0x601C10, 0x6021E1, kP22Sig, {}, "P2 vf22 0x601C10 entry (SequencerControl end)"},
        {kP3, 0x6034FA, 7, 0x6030D0, 0x603646, kP3Sig,
         {{0x603120, kP3R15}, {0x603368, kP3Rbx}, {0x603538, kP3Next}, {0x603373, kP3Vf178}, {0x4FE260, kVf178}},
         "P3 0x6034FA in 0x6030D0 (before the alignment's vf1A0)"},
        {kP4, 0x5EB310, 5, 0x5EB310, 0x5EC372, kP4Sig,
         {{0x5EB38F, kP4Stage}, {0x5EB3AD, kP4Match}, {0x5EB41F, kP4Type}},
         "P4 0x5EB310 entry (client actor order, CreateClientActorDesc_Sequencer)"},
    };
    const safetyhook::MidHookFn fns[kProbes] = {on_p1, on_p21, on_p22, on_p3, on_p4};
    std::string on, refused;
    if (g_3527 && (probe || fix)) {
        refused += " P4 and, with guest_seq_foreign_probe, P2 / P3 (not ported to build 3527: read-only, no effect on the scenes);";
    }
    for (const ProbeDef& d : g_3663   ? std::span<const ProbeDef>(defs3663)
                             : g_3576 ? std::span<const ProbeDef>(defs3576)
                             : g_3527 ? std::span<const ProbeDef>(defs3527)
                                      : std::span<const ProbeDef>(defs2976)) {
        const bool wanted = probe || (fix && (d.id == kP1 || d.id == kP4)) || (present && d.id == kP1);
        if (!wanted) continue;
        std::string why;
        if (!has_function(pdata, d.fn_begin, d.fn_end)) {
            why = std::format(".pdata [0x{:X},0x{:X}) not found", d.fn_begin, d.fn_end);
        } else if (!gad::in_real_code(secs, d.rva, static_cast<uint32_t>(d.sig.size())) || !bytes_at(d.rva, d.sig)) {
            why = "its 40-byte signature is not this build's";
        }
        for (const Ctx& c : d.ctx) {
            if (!why.empty()) break;
            if (!bytes_at(c.rva, c.bytes)) why = std::format("the code it relies on at exe+0x{:X} is not this build's", c.rva);
        }
        if (why.empty() && !p8_install_mid(g_base, secs, d.rva, d.patch, d.sig, fns[d.id], g_hooks[d.id],
                                           "GuestSeqForeign", d.what)) {
            why = "p8_install_mid refused it (see the line above)";
        }
        g_on[d.id].store(why.empty(), std::memory_order_release);
        if (why.empty()) {
            on += std::format(" {};", d.what);
        } else {
            refused += std::format(" {} ({});", d.what, why);
            log::warn("GuestSeqForeign: probe {} NOT installed: {}", d.what, why);
        }
    }
    log::info("GuestSeqForeign probes (READ-ONLY; guest_seq_foreign_probe={}, P1/P4 also for guest_seq_foreign_player, P1 "
              "also for guest_seq_foreign_present_probe={}): hooked:{} | refused:{} | lines for the scenes whose owner is "
              "not this client's character; counts for all; summary every 60 s",
              probe ? 1 : 0, present ? 1 : 0, on.empty() ? " none" : on, refused.empty() ? " none" : refused);
    if (fix && !g_on[kP1].load()) {
        log::warn("GuestSeqForeign: P1 is not hooked, so no non-player node is ever learnt: guest_seq_foreign_player=1 "
                  "neutralizes the owner's binding at every node (no exceptions)");
    }
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other guest modules
        uintptr_t world = 0;
        if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
        Sleep(500);
    }
    std::vector<gad::Section> secs;
    std::vector<RUNTIME_FUNCTION> pdata;
    std::string why;
    if (!read_pdata(pdata, why) || !p8_exe_sections(g_base, secs)) {
        log::warn("GuestSeqForeign: {}; nothing installed (guest_seq_foreign_player acts as 0, no probe)",
                  why.empty() ? "the exe's sections are unreadable" : why);
        g_settled.store(true, std::memory_order_release);
        return 0;
    }
    const bool fix = g_mode.load() != 0 && install_fix(secs, pdata);
    if (fix || g_probe.load() || g_present.load()) install_probes(secs, pdata, fix, g_probe.load(), g_present.load());
    g_settled.store(true, std::memory_order_release);
    return 0;
}

}  // namespace

bool guest_seq_foreign_settled() noexcept { return g_settled.load(std::memory_order_acquire); }
bool guest_seq_foreign_p1_hooked() noexcept { return g_on[kP1].load(std::memory_order_acquire); }

void guest_seq_foreign_start(bool probe, const std::string& player, const std::string& route_mode, bool present) {
    g_3576 = game::current_build() == game::Build::v3576;
    g_3663 = game::current_build() == game::Build::v3663;
    g_3527 = game::current_build() == game::Build::v3527 || g_3576 || g_3663;
    if (g_3527) {
        g_so = g_3663 ? &kStage3663 : &gsf::kStage3527;
        if (const auto* profile = game::reader_profile()) g_world_slot = profile->world_system;
        if (g_3576) g_world_slot = 0x71C0100;  // core_globals_3576.json
        // Build 1.0.0.3663 (static, 2026-11-13; never run): WorldSystem, profile_s2.h's rva3663().
        if (g_3663) g_world_slot = 0x72451C0;
    }
    bool bad = false;
    const gsf::Mode m = gsf::parse_mode(player, &bad);
    if (bad) log::warn("GuestSeqForeign: guest_seq_foreign_player={} is not 0, probe or 1: 0", player);
    g_route_mode = route_mode;
    g_mode.store(static_cast<uint8_t>(m));
    g_probe.store(probe);
    g_present.store(present);
    if (m == gsf::Mode::Off && !probe && !present) {
        g_settled.store(true, std::memory_order_release);
        return;
    }
    static std::atomic<bool> started{false};
    if (started.exchange(true)) return;
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

void guest_seq_foreign_2661(safetyhook::Context& ctx, bool routed, bool would_route, uint32_t owner, uint32_t m_key,
                            uint64_t seq, uint32_t resource, uintptr_t actor) noexcept {
    const auto mode = static_cast<gsf::Mode>(g_mode.load(std::memory_order_relaxed));
    if (mode == gsf::Mode::Off) return;
    gsf::Facts f;
    f.mode = mode;
    f.layout_ok = g_layout_ok.load(std::memory_order_acquire);
    f.routed = routed;
    f.would_route = would_route;
    f.owner = owner;
    f.own_key = guest_seq_route_own_key();
    f.m_key = m_key;
    gsf::Entry ents[gsf::kMaxEntries];
    uint8_t nodes[gsf::kMaxEntries];
    size_t n = 0;
    if (f.layout_ok && (routed || would_route)) {
        g_seqres.note(seq, resource);  // P1 keys what it learns from this stage by its resource
        f.owner_pd = rdv<uint32_t>(ctx.rbp + (g_3527 ? 0x10 : 0));  // the play data's +0: 0xD33D7F lea r8,[rbp+0x10] on 3527
        f.vec = rdp(ctx.rbp + gsf::kVecPtrSlot);
        f.count = rdv<uint32_t>(ctx.rbp + gsf::kVecCountSlot);
        f.capacity = rdv<uint32_t>(ctx.rbp + gsf::kVecCapSlot);
        if (f.count <= gsf::kMaxEntries && (f.vec || !f.count)) {
            for (uint32_t i = 0; i < f.count; ++i) {
                const uintptr_t a = static_cast<uintptr_t>(f.vec) + static_cast<uintptr_t>(i) * gsf::kEntrySize;
                gsf::Entry& e = ents[n];
                if (!rd(a + gsf::kEntryNode, e.node) || !rd(a + gsf::kEntryActor, e.actor) ||
                    !rd(a + gsf::kEntryType, e.type)) {
                    f.read_ok = false;
                    break;
                }
                nodes[n] = g_nodes.find(resource, e.node);
                ++n;
            }
        }
    }
    const gsf::Plan pl = gsf::plan(f, std::span<const gsf::Entry>(ents, n), std::span<const uint8_t>(nodes, n));
    g_verdict[static_cast<size_t>(pl.verdict)].fetch_add(1, std::memory_order_relaxed);
    uint32_t written = 0;
    bool done[gsf::kMaxPlan] = {};
    for (uint8_t k = 0; k < pl.n; ++k) {
        if (!pl.writes(k)) continue;
        const uintptr_t a = static_cast<uintptr_t>(f.vec) + static_cast<uintptr_t>(pl.idx[k]) * gsf::kEntrySize +
                            gsf::kEntryType;
        // Re-checked right before the write (the same thread built it: no one else has it).
        if (rdv<uint8_t>(a, 0xFF) == pl.was[k] && wr8(a, gsf::kLinkNone) && rdv<uint8_t>(a, 0xFF) == gsf::kLinkNone) {
            done[k] = true;
            ++written;
            g_written.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_write_fail.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (pl.verdict == gsf::Verdict::NotX || pl.verdict == gsf::Verdict::Off) return;
    // H-3: the copy's Status flags ([[[actor]+0x68]+0x20]+0x390): bit 0x200 hides it, and with 0 no scene start clears it.
    const uintptr_t comps = actor ? rdp(actor + kActor_Comps) : 0;
    const uintptr_t status = comps ? rdp(comps + kComps_Status) : 0;
    uint32_t flags = 0;
    const bool status_ok = status && rd(status + kStatus_Flags, flags);
    if (status_ok) {
        g_status_read.fetch_add(1, std::memory_order_relaxed);
        if (flags & kStatusHidden) g_hidden_seen.fetch_add(1, std::memory_order_relaxed);
    }
    p::Event e;
    e.v[0] = static_cast<uint64_t>(pl.verdict) | static_cast<uint64_t>(written) << 8 |
             static_cast<uint64_t>(pl.write() ? __popcnt(pl.write_mask) : 0) << 16 |
             static_cast<uint64_t>(pl.owner_entries & 0xFF) << 24 | static_cast<uint64_t>(pl.owner_other & 0xFF) << 32 |
             static_cast<uint64_t>(pl.others & 0xFF) << 40 | static_cast<uint64_t>(f.count & 0xFFFF) << 48;
    e.v[1] = seq;
    e.v[2] = owner | static_cast<uint64_t>(f.own_key) << 32;
    e.v[3] = resource | static_cast<uint64_t>(m_key) << 32;
    e.v[10] = flags | static_cast<uint64_t>(status_ok) << 32;
    // Up to 4 bindings, the owner's first: actor | type << 32 | neutralized << 40 | would << 41 | entry << 48; their whole
    // node ids in v[8] / v[9] (two each, H-8) and their learnt node types in v[11] (a byte each).
    size_t slot = 0;
    auto put = [&](size_t i, bool candidate, bool wrote) {
        if (slot >= 4 || i >= n) return;
        e.v[4 + slot] = ents[i].actor | static_cast<uint64_t>(ents[i].type) << 32 | static_cast<uint64_t>(wrote) << 40 |
                        static_cast<uint64_t>(candidate && !wrote) << 41 | static_cast<uint64_t>(i & 0xFF) << 48;
        e.v[8 + slot / 2] |= static_cast<uint64_t>(ents[i].node) << (32 * (slot % 2));
        e.v[11] |= static_cast<uint64_t>(nodes[i]) << (8 * slot);
        ++slot;
    };
    for (uint8_t k = 0; k < pl.n; ++k) put(pl.idx[k], true, done[k]);
    for (size_t i = 0; i < n; ++i) {
        bool planned = false;
        for (uint8_t k = 0; k < pl.n; ++k) planned |= pl.idx[k] == i;
        if (!planned) put(i, false, false);
    }
    for (size_t s = slot; s < 4; ++s) e.v[11] |= static_cast<uint64_t>(0xFF) << (8 * s);
    emit(kEFix, e);
}

void guest_seq_foreign_tick() noexcept {
    if (!g_mode.load(std::memory_order_relaxed) && !g_probe.load(std::memory_order_relaxed) &&
        !g_present.load(std::memory_order_relaxed)) {
        return;
    }
    try {
        ++g_ticks;
        p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind >= kKindCount) continue;
            tally(e);
            if (e.kind == kEP1 && p1_late_exception(e)) {
                log::warn("{}", line_of(e));  // always, beyond the line budget
            } else if (g_lines < kMaxLines) {
                ++g_lines;
                log::info("{}", line_of(e));
            } else {
                ++g_capped;
            }
        }
        if (g_ticks % 12 == 0) log::info("{}", summary());
    } catch (...) {
    }
}

}  // namespace cdmp::session2
