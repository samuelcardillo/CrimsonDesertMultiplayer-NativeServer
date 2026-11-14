#include "mod/session2/guest_seq_play.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/config.h"
#include "mod/game/build_profile.h"
#include "mod/game/game_fault.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/freeze_watchdog.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_sched_bind.h"
#include "mod/session2/guest_seq_present.h"
#include "mod/session2/guest_seq_play_logic.h"
#include "mod/session2/guest_x_veto.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;
namespace off = game::build_2976;
using gsp::Skip;

// ---------------------------------------------------------------- the code (build 2976, all in .rsrc)
//
// Verified with capstone on the read-only PE (p8-impl-escenas-play.md §1):
//   0x8B6060 (unwind 0x8B6060-0x8B6906), its only caller 0xAD277F in 0xAD2380 (once per main loop turn,
//   xmm1 = [[r13+0x60]+0x64], the frame's dt):
//   0x8B6076 lea rbp,[rax-0x5f]                 the frame
//   0x8B608F vmovaps xmm6,xmm1                  dt; xmm6 is not written again before 0x8B6144 (callee-saved)
//   0x8B60AF mov rcx,[rdi+0x50] ; test ; je ; test byte [rcx+0x5e],0x10 ; je   (the local actor, logged in)
//   0x8B60C6 lea rdx,[rbp-0x49] ; call 0x17FA6C0  the FieldAttacher: [rbp-0x41] = Q (held until 0x8B618F)
//   0x8B6102 mov rcx,[rbp-0x41] ; mov rax,[rcx] ; call [rax+0x48]   vf48 (0x9A5BE0) -> M in RAX
//   0x8B613D mov r8,[rdi+0x80]
//   0x8B6144 movzx r8d,byte [r8+0x50]           THE POINT (5 bytes; one instruction, no branch into it)
//   0x8B6149 mov rdx,[rbp-0x41] ; mov rcx,rax ; call 0xA953C0     the native tick of M
//   0x8B63CE / 0x8B67E3 cmp byte [0x6CC0218],0 ; jne ; vmovaps xmm1,xmm6 ; mov rcx,rdi ; call 0x8B2660
//   (0x8B2660: actor50 && +0x5E & 0x10 && M && mode != 2 -> 0xAA3350(M) ; 0xAA3E70(M, xmm1))
constexpr uintptr_t kPoint = 0x8B6144;
constexpr uint32_t kPatch = 5;
constexpr uint8_t kPointBytes[] = {0x45, 0x0F, 0xB6, 0x40, 0x50, 0x48, 0x8B, 0x55,
                                   0xBF, 0x48, 0x8B, 0xC8, 0xE8, 0x6B, 0xF2, 0x1D};
constexpr uint8_t kFrameBytes[] = {0x48, 0x8D, 0x68, 0xA1};                                    // 0x8B6076
constexpr uint8_t kDtBytes[] = {0xC5, 0xF8, 0x28, 0xF1};                                       // 0x8B608F
constexpr uint8_t kActorBytes[] = {0x48, 0x8B, 0x4F, 0x50, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0xD8, 0x00, 0x00,
                                   0x00, 0xF6, 0x41, 0x5E, 0x10, 0x0F, 0x84, 0xCE, 0x00, 0x00, 0x00};  // 0x8B60AF
constexpr uint8_t kAttachBytes[] = {0x48, 0x8D, 0x55, 0xB7, 0xE8, 0xF1, 0x45, 0xF4, 0x00};       // 0x8B60C6
constexpr uint8_t kVf48Bytes[] = {0x48, 0x8B, 0x4D, 0xBF, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};   // 0x8B6102
constexpr uint8_t kModePtrBytes[] = {0x4C, 0x8B, 0x87, 0x80, 0x00, 0x00, 0x00};                // 0x8B613D
constexpr uint8_t kLiveGate1Bytes[] = {0x80, 0x3D, 0x43, 0x9E, 0x40, 0x06, 0x00, 0x75,
                                       0x11, 0xC5, 0xF8, 0x28, 0xCE, 0x48, 0x8B, 0xCF};  // 0x8B63CE
constexpr uint8_t kLiveGate2Bytes[] = {0x80, 0x3D, 0x2E, 0x9A, 0x40, 0x06, 0x00, 0x75,
                                       0x0C, 0xC5, 0xF8, 0x28, 0xCE, 0x48, 0x8B, 0xCF};  // 0x8B67E3
// The callees (their first 16 bytes): 0xA953C0(G, Q, u8 mode); 0xAA3E70(G, float dt in xmm1); 0x9A5B70 = the
// ClientField's vf40 (FindUser([field+0x180]) -> its character's missions, 0 when not found).
constexpr uintptr_t kTickRva = 0xA953C0;
constexpr uint8_t kTickBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C,
                                  0x24, 0x18, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56};
constexpr uintptr_t kLiveRva = 0xAA3E70;
constexpr uint8_t kLiveBytes[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48,
                                  0x89, 0x48, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54};
constexpr uintptr_t kOwnerRva = 0x9A5B70;
constexpr uint8_t kOwnerBytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B,
                                   0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54};

// Phase 2's skip hook inside 0xAA3E70 (p8-impl-escenas-play.md §13.3; the whole 0xAA4B27..0xAA4CB2 range read):
//   0xAA4400 je 0xAA4B27            the only branch to the point (empty live list); none into 0xAA4B28..0xAA4B31
//   0xAA4B27 lea rdx,[rbp+0x20] ; mov rcx,[rip+..] (= [0x6D691E0]) ; mov rcx,[rcx+0x30] ; call 0x8B4570
//            THE POINT (11 bytes: lea + the RIP-relative mov, relocated by safetyhook). [rbp+0x20] is first written
//            by 0x8B4570 here (the local player's handle) and released at 0xAA4CA4..0xAA4CAC;
//            0xAA4B60 takes [G+8]'s lock and releases it before 0xAA4C8B; then 0xA96070 / 0xA9A1F0 / 0xA9A410,
//            0xAA5040, 0xAA5400.
//   0xAA4CB2 lea rcx,[rsp+0x38] ; call 0x3D3000   destroys the live-list copy made at 0xAA43CB (before the point);
//            then [rbp-0x78] (the entry's FieldAttacher) is released with rcx/rax/rsi as vtables, rsi =
//            exe+0x5725E48 (set at 0xAA3EF3 / 0xAA4AE6 / 0xAA4B13 on every path to the point), and the epilogue.
// So for OUR call (thread_local, rcx = X kept in r13 since 0xAA3EA2) the hook resumes at 0xAA4CB2: nothing built
// between the point and 0xAA4CB2 is left unreleased, nothing released there was built (not 0xAA4CA4: it would
// release the handle 0x8B4570 never built), no lock is held at the point (the 0xAA43B5 guard is released at
// 0xAA43ED). rsp is the same at both addresses (every call in between is balanced).
constexpr uintptr_t kSkipPoint = 0xAA4B27, kSkipResume = 0xAA4CB2, kBaseVtable = 0x5725E48;
constexpr uint32_t kSkipPatch = 11;
constexpr uint8_t kSkipBytes[] = {0x48, 0x8D, 0x55, 0x20, 0x48, 0x8B, 0x0D, 0xAE, 0x46, 0x2C,
                                  0x06, 0x48, 0x8B, 0x49, 0x30, 0xE8, 0x35, 0xFA, 0xE0, 0xFF};  // 0xAA4B27..0xAA4B3A
constexpr uint8_t kSkipTailBytes[] = {0x48, 0x89, 0x75, 0x20, 0x48, 0x8D, 0x4D, 0x20, 0xE8, 0xCF, 0xFB, 0x98,
                                      0x00, 0x90, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0x44, 0xE3, 0x92, 0xFF};  // 0xAA4CA4
constexpr uint8_t kSkipCopyBytes[] = {0x49, 0x8D, 0x55, 0x28, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0x3B, 0xCB, 0x92, 0xFF};  // 0xAA43C7
constexpr uint8_t kSkipLoopBytes[] = {0x0F, 0x84, 0x21, 0x07, 0x00, 0x00};                   // 0xAA4400 je 0xAA4B27
constexpr uint8_t kSkipR13Bytes[] = {0x4C, 0x8B, 0xE9};                                       // 0xAA3EA2 mov r13,rcx
constexpr uint8_t kSkipRsi1Bytes[] = {0x48, 0x8D, 0x35, 0x4E, 0x1F, 0xC8, 0x04};            // 0xAA3EF3 lea rsi
constexpr uint8_t kSkipRsi2Bytes[] = {0x48, 0x8D, 0x35, 0x5B, 0x13, 0xC8, 0x04};            // 0xAA4AE6 lea rsi
constexpr uint8_t kSkipRsi3Bytes[] = {0x48, 0x8D, 0x35, 0x2E, 0x13, 0xC8, 0x04};            // 0xAA4B13 lea rsi
// The fields of G that drive 0xAA5040 / 0xAA5400 (the read-only gate).
constexpr uint32_t kMgr_2A4 = 0x2A4, kMgr_288 = 0x288, kMgr_2A8 = 0x2A8, kMgr_2D4 = 0x2D4, kMgr_2CC = 0x2CC;
constexpr uint32_t kMgr_2B0 = 0x2B0, kMgr_2B4 = 0x2B4;  // floats: 0xAA5081 vmovss/vcomiss, 0xAA50B1 vmovss

constexpr uintptr_t kVtStageManager = 0x55C9720;  // pa::ClientSequencerStageManager (RTTI)
constexpr uintptr_t kVtClientField = 0x55BCEA0;   // pa::ClientField (RTTI; +0x40 = 0x9A5B70, +0x48 = 0x9A5BE0)
constexpr uint32_t kField_Vf40 = 0x40;
constexpr uintptr_t kLiveGateByte = 0x6CC0218;    // 0x8B63CE / 0x8B67E3
constexpr uint32_t kFrame_Q = 0x41;               // [rbp-0x41]
constexpr uint32_t kModeByte = 0x50;              // [r8+0x50]
// Structure offsets (guest_seq_route.cpp; p8-s8-escenas.md §3).
constexpr uint32_t kActor_Key = 0x60, kActor_Comps = 0x68, kComps_Seq = 0xA8, kSeqComp_Mgr = 0x18;
constexpr uint32_t kMgr_Ctx = 0x08, kMgr_Live = 0x30, kMgr_Actor = 0x18, kMgr_Ready = 0x231, kMgr_Loading = 0x174;
constexpr uint32_t kMgr_N1B0 = 0x1B8, kMgr_N1C0 = 0x1C8, kMgr_N1D0 = 0x1D8;
// The client actor table (game/actor_lookup.cpp's replica, as guest_seq_route's G5): the liveness check of X's
// character before each call (review 1). Read-only SEH reads without the table's lock: a torn read can only
// make the check fail (a skipped frame), never pass for an actor that is not there with that key and X.
constexpr uint32_t kManager_Table = 0x08, kTable_BucketCount = 0x88, kTable_Buckets = 0x98, kTable_Nodes = 0xA0;
constexpr uint32_t kBucketStride = 0x100, kBucketMaxEntries = (0x100 - 8) / 8, kNode_Key = 0x04, kNode_Actor = 0x08;

// ---------------------------------------------------------------- the code (build 1.0.0.3527, .rsrc)
//
// Read with capstone on the installed PE, 2026-11-05. The frame function shrank: 0x99C2E0 (RUNTIME_FUNCTION
// 0x99C2E0-0x99C443), its only caller 0x9A009A in 0x9A0060, called from the main loop 0xBDF7B0 (0xBDFBB3):
//   0x99C2FB mov rax,[rcx+0x50] ; test ; je ; test byte [rax+0x5E],0x10 ; je   (the local actor, logged in)
//   0x99C312 mov rax,[rcx+0x70] ; mov rbx,[rax]   Q; 0x99C321 call 0x1617950 (held?) ; 0x99C33C mov [rsp+0x28],rbx
//   0x99C375 mov rcx,rbx ; call 0xAAA7A0          the ClientField's vf48 -> M in RAX (test rax,rax ; je)
//   0x99C382 mov r8,[rdi+0x80]
//   0x99C389 movzx r8d,byte [r8+0x58]             THE POINT (5 bytes, one instruction, no branch into it)
//   0x99C38E mov rdx,[rsp+0x28] ; mov rcx,rax ; call 0xBA0080   the native tick of M
// At the point: RAX = M, R8 = the mode object (mode = byte [R8+0x58]), Q = [rsp+0x28] (and rbx). xmm6 = the caller
// 0x9A0060's dt (0x99C2E0 never writes it). The live update (guest_seq_play_live) has its own 3527 / 3549 port below
// ("phase 2 on 3527 / 3549"): X's call rides on M's native one at 0xBB0450's entry.
// 0xBA0080(G, Q, u8 mode): mov rbx,rdx ; mov rdi,rcx ; cmp r8b,2 ; je ; call 0xBA21F0(G, Q) ; call 0xBA2A30(G, Q): the same
// signature; 0xBA21F0 is 2976's 0xA97300 (locks [G+8], 0xBA224A) and 0xBA2A30 only walks G's own list {+0x218, n +0x220}.
// 0xAAA730 = the ClientField's vf40 (vtable 0x594BA50: +0x40 0xAAA730, +0x48 0xAAA7A0): FindUser([field+0x180]) ->
// user+0xD0 -> [[a+0x68]+0x138]+0x18; P1 0x6C02C0 calls it at 0x6C0306 and reads through the result, so 0 would fault:
// gsp::plan's OwnerMissionsNull guard stays.
constexpr uintptr_t kPoint3527 = 0x99C389, kTickRva3527 = 0xBA0080, kOwnerRva3527 = 0xAAA730;
constexpr uint8_t kPointBytes3527[] = {0x45, 0x0F, 0xB6, 0x40, 0x58, 0x48, 0x8B, 0x54,
                                       0x24, 0x28, 0x48, 0x8B, 0xC8, 0xE8, 0xE5, 0x3C};
constexpr uint8_t kActorBytes3527[] = {0x48, 0x8B, 0x41, 0x50, 0x48, 0x85, 0xC0, 0x0F, 0x84,
                                       0x22, 0x01, 0x00, 0x00, 0xF6, 0x40, 0x5E, 0x10};  // 0x99C2FB
constexpr uint8_t kQSlotBytes3527[] = {0x48, 0x89, 0x5C, 0x24, 0x28};                     // 0x99C33C
constexpr uint8_t kVf48Bytes3527[] = {0x48, 0x8B, 0xCB, 0xE8, 0x23, 0xE4, 0x10, 0x00};    // 0x99C375
constexpr uint8_t kModePtrBytes3527[] = {0x4C, 0x8B, 0x87, 0x80, 0x00, 0x00, 0x00};       // 0x99C382
constexpr uint8_t kTickBytes3527[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C,
                                      0x24, 0x18, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56};
constexpr uint8_t kOwnerBytes3527[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x8B,
                                       0x81, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54};
constexpr uint32_t kFrame_Q3527 = 0x28;  // [rsp+0x28]
// The fields per build (3527: the comments above guest_seq_route.cpp's kMgrOff3527).
struct Off {
    uintptr_t vt_mgr, vt_field, owner_rva;
    uint32_t mode, ready, loading, n1b0, n1c0, n1d0;
};
constexpr Off kOff2976{kVtStageManager, kVtClientField, kOwnerRva, kModeByte, kMgr_Ready, kMgr_Loading, kMgr_N1B0, kMgr_N1C0, kMgr_N1D0};
constexpr Off kOff3527{0x59572E0, 0x594BA50, kOwnerRva3527, 0x58, 0x259, 0x1C0, 0x1D0, 0x1E0, 0x1F0};

// ---------------------------------------------------------------- phase 2 on 3527 / 3549 (capstone on 3549's PE, 2026-11-06)
//
// The native live call: 0x9A0060 (the frame, xmm1 = dt) 0x9A0085 vmovaps xmm6,xmm1 ; 0x9A009A call 0x99C2E0 (our
// point 0x99C389 is inside it: 0x99C2E0 never writes xmm6, so xmm6 there is still the frame's dt, as in 2976) ;
// ... 0x9A017C cmp byte [0x710F318],0 ; jne ; vmovaps xmm1,xmm6 ; mov rcx,rdi ; call 0x99C450 (= 2976's 0x8B2660:
// actor50 && +0x5E & 0x10 && M && mode != 2 -> 0xBAEB20(M) ; 0xBAF680(M) ; 0xBB0450(M, xmm1)).
// 0xBB0450(G, dt) is 2976's 0xAA3E70 (RUNTIME_FUNCTION 0xBB0450-0xBB130E; same prologue, sub rsp,0x570, rbp = rax-0x4A8):
//   0xBB0482 mov r13,rcx ; r13 is zeroed / written at 0xBB05CC / 0xBB0607 inside the pre-loop and reloaded from
//            [rbp+0x4B0] (the entry's rcx) at 0xBB090A / 0xBB0971 before every jump back to 0xBB0570, whose two exits
//            (0xBB0573 / 0xBB057F) lead to 0xBB097D; no write of r13 after that line in the function (to 0xBB1306 pop).
//   0xBB0999 call 0x3E4100 (the guard of [G+8]) ... released at 0xBB09D5 (vf20, dl=1), before the live loop.
//   0xBB09AF lea rdx,[r13+0x28] ; lea rcx,[rsp+0x38] ; call 0xBB1FE0   the live-list copy (destroyed at the resume).
//   0xBB09E8 je 0xBB112F   the only branch to the point (empty list); the loop 0xBB0A00..0xBB1129 falls into it.
//   0xBB112F lea rdx,[rbp+0x18] ; mov rcx,[rip+..] (= [0x71BDF40]) ; mov rcx,[rcx+0x30] ; call 0x99E3E0
//            THE POINT (11 bytes, as in 2976). [rbp+0x18..0x2F] is used nowhere before it (0xBB112F / 0xBB1144 /
//            0xBB114E / 0xBB12AC / 0xBB12B0 are its only uses). Between it and the resume: [G+8]'s lock 0xBB1168
//            (released by vf20 at 0xBB118A / 0xBB1239), 0xBA0F70 / 0xBA54D0 / 0xBA56F0 (= 2976's 0xA96070 /
//            0xA9A1F0 / 0xA9A410), then 0xBB1640 / 0xBB1A00 (= 0xAA5040 / 0xAA5400), the handle released at
//            0xBB12AC..0xBB12B4 (0xBB11F3 jmp 0xBB12B4 is a native path only).
//   0xBB12BA lea rcx,[rsp+0x38] ; call 0x4429B0   THE RESUME: destroys the copy, then [rbp-0x78] (the entry's
//            FieldAttacher) released with rsi = exe+0x5AC37B0 (lea rsi at 0xBB04D3 / 0xBB10EE / 0xBB111B and the
//            loop's other exits, all the same vtable), and the epilogue. rsp is the same at both addresses (no push,
//            pop or rsp write between 0xBB0474 and 0xBB12FF).
// The gate fields of G moved by +0x40 (0xBB1640: +0x2E8 / +0x2F0 / +0x2F4 / +0x2C8 / +0x2E4, 0xBB19A4 mov byte
// [rbx+0x2E4],0; 0xBB1A00: +0x30C / +0x314).
constexpr uintptr_t kLiveRva3527 = 0xBB0450, kSkipPoint3527 = 0xBB112F, kSkipResume3527 = 0xBB12BA;
constexpr uintptr_t kBaseVtable3527 = 0x5AC37B0, kLiveGateByte3527 = 0x710F318;
constexpr uint32_t kLiveEntryPatch3527 = 7;  // 0xBB0450 mov rax,rsp ; mov [rax+0x10],rbx (the function's entry)
constexpr uint8_t kSkipBytes3527[] = {0x48, 0x8D, 0x55, 0x18, 0x48, 0x8B, 0x0D, 0x06, 0xCE, 0x60,
                                      0x06, 0x48, 0x8B, 0x49, 0x30, 0xE8, 0x9D, 0xD2, 0xDE, 0xFF};  // 0xBB112F..0xBB1142
constexpr uint8_t kSkipTailBytes3527[] = {0x48, 0x89, 0x75, 0x18, 0x48, 0x8D, 0x4D, 0x18, 0xE8, 0x87, 0x6B, 0xA6,
                                          0x00, 0x90, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0xEC, 0x16, 0x89, 0xFF};  // 0xBB12AC
constexpr uint8_t kSkipCopyBytes3527[] = {0x49, 0x8D, 0x55, 0x28, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0x23, 0x16, 0x00, 0x00};  // 0xBB09AF
constexpr uint8_t kSkipLoopBytes3527[] = {0x0F, 0x84, 0x41, 0x07, 0x00, 0x00};                 // 0xBB09E8 je 0xBB112F
constexpr uint8_t kSkipR13Reload3527[] = {0x4C, 0x8B, 0xAD, 0xB0, 0x04, 0x00, 0x00};          // 0xBB090A / 0xBB0971
constexpr uint8_t kSkipRsi1Bytes3527[] = {0x48, 0x8D, 0x35, 0xD6, 0x32, 0xF1, 0x04};          // 0xBB04D3 lea rsi
constexpr uint8_t kSkipRsi2Bytes3527[] = {0x48, 0x8D, 0x35, 0xBB, 0x26, 0xF1, 0x04};          // 0xBB10EE lea rsi
constexpr uint8_t kSkipRsi3Bytes3527[] = {0x48, 0x8D, 0x35, 0x8E, 0x26, 0xF1, 0x04};          // 0xBB111B lea rsi
constexpr uint8_t kLiveCallBytes3527[] = {0x40, 0x38, 0x2D, 0x95, 0xF1, 0x76, 0x06, 0x75,
                                          0x0C, 0xC5, 0xF8, 0x28, 0xCE, 0x48, 0x8B, 0xCF};  // 0x9A017C (the gate byte)
constexpr uint8_t kDtBytes3527[] = {0xC5, 0xF8, 0x28, 0xF1, 0x48, 0x8B, 0x54, 0xC2,
                                    0x10, 0x0F, 0xB6, 0x5A, 0x09, 0xE8, 0x59, 0x09};  // 0x9A0085 vmovaps xmm6,xmm1 ...
constexpr uint8_t kDtCallBytes3527[] = {0x48, 0x8B, 0xCF, 0xE8, 0x41, 0xC2, 0xFF, 0xFF};  // 0x9A0097 call 0x99C2E0
// The gate fields per build: +0x2A4 / +0x288 / +0x2A8 / +0x2B0 / +0x2B4 / +0x2D4 / +0x2CC in 2976.
struct GateOff {
    uint32_t f2a4, f288, f2a8, f2b0, f2b4, f2d4, f2cc;
};
constexpr GateOff kGate2976{kMgr_2A4, kMgr_288, kMgr_2A8, kMgr_2B0, kMgr_2B4, kMgr_2D4, kMgr_2CC};
constexpr GateOff kGate3527{0x2E4, 0x2C8, 0x2E8, 0x2F0, 0x2F4, 0x314, 0x30C};
// Build 1.0.0.3663 (static, 2026-11-13; never run): all +8, read in the two helpers the live update calls after the resume
// point (0xBE922A / 0xBE9236): 0xBE95D0 reads [+0x2F0] (0xBE95F9), the floats +0x2F8 / +0x2FC, [+0x2D0] and clears the byte
// +0x2EC (0xBE9931, 3527's 0xBB19A4 on +0x2E4); 0xBE9990 the float +0x314 and the byte +0x31C.
constexpr GateOff kGate3663{0x2EC, 0x2D0, 0x2F0, 0x2F8, 0x2FC, 0x31C, 0x314};

// ---------------------------------------------------------------- build 1.0.0.3576 (static, 2026-11-06 evening; not yet run)
//
// tools/porting/port_module.py: every function moved whole, each array at old + its function's shift with the same bytes
// but for the relative fields below. The frame 0x99C5A0-0x99C703 (+0x2C0, the same size): the point 0x99C649, the tick
// 0xBA04A0 (+0x420, 3527's 16 bytes), vf48 0xAAABB0 and vf40 0xAAAB40 (the ClientField's vtable 0x594DB40 by RTTI, +0x48
// / +0x40; vf40 with 3527's bytes). The caller 0x9A0540 (+0x4E0): dt 0x9A0565, call 0x99C5A0 at 0x9A0577, the gate byte
// 0x7111428 (+0x2110) at 0x9A065C. The live update 0xBB0870-0xBB172E (+0x420, the same size): skip 0xBB154F (its global
// 0x71C0150 = 3527's + 0x2210), resume 0xBB16DA, lea rsi to 0x5AC58E0 at 0xBB08F3 / 0xBB150E / 0xBB153B. The two gate
// helpers it calls after the resume (0xBB1A60, 0xBB1E20) read the same fields (+0x2C8..+0x2F4, +0x30C / +0x314).
constexpr uintptr_t kPoint3576 = 0x99C649, kTickRva3576 = 0xBA04A0, kOwnerRva3576 = 0xAAAB40;
constexpr uint8_t kPointBytes3576[] = {0x45, 0x0F, 0xB6, 0x40, 0x58, 0x48, 0x8B, 0x54,
                                       0x24, 0x28, 0x48, 0x8B, 0xC8, 0xE8, 0x45, 0x3E};
constexpr uint8_t kVf48Bytes3576[] = {0x48, 0x8B, 0xCB, 0xE8, 0x73, 0xE5, 0x10, 0x00};  // 0x99C635
constexpr Off kOff3576{0x5959438, 0x594DB40, kOwnerRva3576, 0x58, 0x259, 0x1C0, 0x1D0, 0x1E0, 0x1F0};
constexpr uintptr_t kLiveRva3576 = 0xBB0870, kSkipPoint3576 = 0xBB154F, kSkipResume3576 = 0xBB16DA;
constexpr uintptr_t kBaseVtable3576 = 0x5AC58E0, kLiveGateByte3576 = 0x7111428;
constexpr uint8_t kSkipBytes3576[] = {0x48, 0x8D, 0x55, 0x18, 0x48, 0x8B, 0x0D, 0xF6, 0xEB, 0x60,
                                      0x06, 0x48, 0x8B, 0x49, 0x30, 0xE8, 0x4D, 0xD5, 0xDE, 0xFF};  // 0xBB154F
constexpr uint8_t kSkipTailBytes3576[] = {0x48, 0x89, 0x75, 0x18, 0x48, 0x8D, 0x4D, 0x18, 0xE8, 0x87, 0x6F, 0xA6,
                                          0x00, 0x90, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0x2C, 0x16, 0x89, 0xFF};  // 0xBB16CC
constexpr uint8_t kSkipRsi1Bytes3576[] = {0x48, 0x8D, 0x35, 0xE6, 0x4F, 0xF1, 0x04};  // 0xBB08F3
constexpr uint8_t kSkipRsi2Bytes3576[] = {0x48, 0x8D, 0x35, 0xCB, 0x43, 0xF1, 0x04};  // 0xBB150E
constexpr uint8_t kSkipRsi3Bytes3576[] = {0x48, 0x8D, 0x35, 0x9E, 0x43, 0xF1, 0x04};  // 0xBB153B
constexpr uint8_t kLiveCallBytes3576[] = {0x40, 0x38, 0x2D, 0xC5, 0x0D, 0x77, 0x06, 0x75,
                                          0x0C, 0xC5, 0xF8, 0x28, 0xCE, 0x48, 0x8B, 0xCF};  // 0x9A065C
constexpr uint8_t kDtCallBytes3576[] = {0x48, 0x8B, 0xCF, 0xE8, 0x21, 0xC0, 0xFF, 0xFF};  // 0x9A0577

// ---------------------------------------------------------------- build 1.0.0.3663 (static, 2026-11-13; never run)
//
// The frame 0x9CB630-0x9CB793 (+0x2F350 from 3527, the same size; kActorBytes3527 is an anchor of anchors_3663.json): the
// point 0x9CB6D9 (movzx r8d,byte [r8+0x58]; its 16 bytes end inside the tick's rel32), vf48 0xAE0710 called at 0x9CB6C8,
// the tick 0xBD8000 (3527's 16 bytes; it calls 0xBDA180 = 3527's 0xBA21F0 and 0xBDA9D0), the ClientField's vtable
// 0x59C97C0 (RTTI) +0x40 = 0xAE06A0 (3527's bytes) / +0x48 = 0xAE0710. The native caller 0x9CF7C0 (3527's 0x9A0060,
// changed by 6 bytes): 0x9CF7E5 vmovaps xmm6,xmm1 (dt) ... 0x9CF7FA call 0x9CB630; 0x9CF8D6 cmp byte [0x7195BE8],0 ;
// jne ; vmovaps xmm1,xmm6 ; mov rcx,rdi ; call 0x9CB7A0 (= 3527's 0x99C450: actor / vf48 / mode != 2 ->
// 0xBE6AB0 ; 0xBE7610 ; 0xBE83E0(M, xmm1)). The live update 0xBE83E0-0xBE929E (+0x37F90, 3527's size 0xEBE; kSkipTail /
// kSkipCopy are anchors): skip 0xBE90BF (its global 0x7245210, the call 0x9CDC90), resume 0xBE924A, lea rsi to
// 0x5B40000 at 0xBE8463 / 0xBE907E / 0xBE90AB, r13 written only at 0xBE8412 / 0xBE855C / 0xBE8597 / 0xBE889A /
// 0xBE8901 (3527's places), the only branch to the point 0xBE8978. The manager's fields moved +8 (see kOff3663 /
// kGate3663). No branch lands in the three patches (rel8 sweep, rel32 scan of both code sections).
constexpr uintptr_t kPoint3663 = 0x9CB6D9, kTickRva3663 = 0xBD8000, kOwnerRva3663 = 0xAE06A0;
constexpr uint8_t kPointBytes3663[] = {0x45, 0x0F, 0xB6, 0x40, 0x58, 0x48, 0x8B, 0x54,
                                       0x24, 0x28, 0x48, 0x8B, 0xC8, 0xE8, 0x15, 0xC9};
constexpr uint8_t kVf48Bytes3663[] = {0x48, 0x8B, 0xCB, 0xE8, 0x43, 0x50, 0x11, 0x00};  // 0x9CB6C5
// The manager's fields +8 (0xBDA180: the vector count +0x1C8, the lists {+0x1D0, n +0x1D8} / {+0x1E0, n +0x1E8} /
// {+0x1F0, n +0x1F8}, the ready byte +0x261; the mode byte [r8+0x58] at the point).
constexpr Off kOff3663{0x59D57E8, 0x59C97C0, kOwnerRva3663, 0x58, 0x261, 0x1C8, 0x1D8, 0x1E8, 0x1F8};
constexpr uintptr_t kLiveRva3663 = 0xBE83E0, kSkipPoint3663 = 0xBE90BF, kSkipResume3663 = 0xBE924A;
constexpr uintptr_t kBaseVtable3663 = 0x5B40000, kLiveGateByte3663 = 0x7195BE8;
constexpr uint8_t kSkipBytes3663[] = {0x48, 0x8D, 0x55, 0x18, 0x48, 0x8B, 0x0D, 0x46, 0xC1, 0x65,
                                      0x06, 0x48, 0x8B, 0x49, 0x30, 0xE8, 0xBD, 0x4B, 0xDE, 0xFF};  // 0xBE90BF
constexpr uint8_t kSkipTailBytes3663[] = {0x48, 0x89, 0x75, 0x18, 0x48, 0x8D, 0x4D, 0x18, 0xE8, 0x37, 0x01, 0xA7,
                                          0x00, 0x90, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0xBC, 0x83, 0x87, 0xFF};  // 0xBE923C
constexpr uint8_t kSkipCopyBytes3663[] = {0x49, 0x8D, 0x55, 0x28, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xE8, 0x83, 0xA7, 0x8E, 0xFF};  // 0xBE893F
constexpr uint8_t kSkipRsi1Bytes3663[] = {0x48, 0x8D, 0x35, 0x96, 0x7B, 0xF5, 0x04};  // 0xBE8463
constexpr uint8_t kSkipRsi2Bytes3663[] = {0x48, 0x8D, 0x35, 0x7B, 0x6F, 0xF5, 0x04};  // 0xBE907E
constexpr uint8_t kSkipRsi3Bytes3663[] = {0x48, 0x8D, 0x35, 0x4E, 0x6F, 0xF5, 0x04};  // 0xBE90AB
constexpr uint8_t kLiveCallBytes3663[] = {0x40, 0x38, 0x2D, 0x0B, 0x63, 0x7C, 0x06, 0x75,
                                          0x0C, 0xC5, 0xF8, 0x28, 0xCE, 0x48, 0x8B, 0xCF};  // 0x9CF8D6
constexpr uint8_t kDtBytes3663[] = {0xC5, 0xF8, 0x28, 0xF1, 0x48, 0x8B, 0x54, 0xC2,
                                    0x10, 0x0F, 0xB6, 0x5A, 0x09, 0xE8, 0xE9, 0x0A};  // 0x9CF7E5
constexpr uint8_t kDtCallBytes3663[] = {0x48, 0x8B, 0xCF, 0xE8, 0x31, 0xBE, 0xFF, 0xFF};  // 0x9CF7F7 call 0x9CB630

using TickFn = void(__fastcall*)(uintptr_t mgr, uintptr_t field, uint8_t mode);
using LiveFn = void(__fastcall*)(uintptr_t mgr, float dt);
using OwnerFn = uintptr_t(__fastcall*)(uintptr_t field);

constexpr size_t kSlots = 8;

uintptr_t g_base = 0;
// The build, its fields and its world slot: written by guest_seq_play_start before any hook or thread.
bool g_3527 = false;  // 3527's layout (3527, 3549, 3576, 3663: the same frames and entry hook)
bool g_3576 = false;  // 3576's addresses
bool g_3663 = false;  // 3663's addresses (and kOff3663 / kGate3663)
const Off* g_off = &kOff2976;
const GateOff* g_gate = &kGate2976;
uintptr_t g_live_gate_rva = kLiveGateByte, g_skip_resume = kSkipResume, g_base_vt_rva = kBaseVtable;
uintptr_t g_live_rva = kLiveRva;  // the live update's entry (its function) of this build
const char* g_live_name = "0xAA3E70";  // the live update of this build, for the lines
uintptr_t g_world_slot = off::kWorldSystemSlot;
std::atomic<bool> g_started{false}, g_code_ok{false}, g_disabled{false};
std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_live{false}, g_route_on{false};
SafetyHookMid g_hook;
TickFn g_tick = nullptr;
LiveFn g_live_fn = nullptr;
OwnerFn g_owner = nullptr;

gsp::XTable<kSlots> g_table;
gsp::WriteMark g_mark[kSlots];  // main thread only
std::atomic<uint64_t> g_written_x[kSlots] = {}, g_written_us[kSlots] = {}, g_written_n[kSlots] = {};
std::atomic<uint64_t> g_written_gen[kSlots] = {}, g_rearms{0};
std::atomic<uint32_t> g_main_tid{0};  // the play hook's thread (the routing hooks are expected on it)
std::atomic<uint64_t> g_note_foreign{0}, g_note_busy{0}, g_reentry{0};
thread_local bool t_in_frame = false;  // review 2: on_frame never runs inside itself
// Phase 2: the X our own 0xAA3E70 call is for (0 otherwise); the skip hook only acts when r13 is it.
thread_local uintptr_t t_live_x = 0;
SafetyHookMid g_skip_hook;
std::atomic<bool> g_skip_ok{false};
std::atomic<uint64_t> g_live_skipped{0}, g_live_not_skipped{0}, g_live_rsi_fixed{0}, g_live_gated{0},
    g_live_no_hook{0}, g_live_held_after_tick{0}, g_live_stuck{0}, g_live_bad_dt{0};
// Review of 0383f70, 3: a live call the skip hook did NOT cut (r13 != X) latches the live path off for the session.
std::atomic<bool> g_live_latched{false};
// 3527 / 3549: the native live update of M runs from a job when [0x710F318] != 0 (0xBE02F0; read live on 3549: it is 1),
// so X's call is made inside M's native call: the frame marks X due, the entry hook of 0xBB0450 calls it, on the main
// thread only.
SafetyHookMid g_live_entry_hook;
std::atomic<uintptr_t> g_due_x[kSlots] = {};
std::atomic<uint32_t> g_due_key[kSlots] = {};
std::atomic<uintptr_t> g_last_m{0};
std::atomic<uint32_t> g_entry_tid{0};
std::atomic<uint64_t> g_entry_calls{0}, g_entry_not_m{0}, g_entry_other_thread{0}, g_due_replaced{0}, g_due_dropped{0};
gsp::GateWatch g_gate_watch[kSlots];  // main thread: how long X's gate has been held (review 5)
constexpr uint64_t kGateStuckUs = 10'000'000;
std::atomic<uint64_t> g_first_x[kSlots] = {};  // the X of the slot's first tick (a new X: a new first)
std::atomic<uint8_t> g_last_skip[kSlots] = {};  // main thread: the last reason (a line on change)
std::atomic<int8_t> g_last_owner{-1};           // main thread: the last vf40 answer (a line when it turns null)
std::atomic<uint64_t> g_slot_ticks[kSlots] = {}, g_slot_lives[kSlots] = {}, g_slot_consumed[kSlots] = {},
                      g_slot_grew[kSlots] = {}, g_slot_would[kSlots] = {};
std::atomic<uint64_t> g_frames{0}, g_ticks{0}, g_lives{0}, g_writes{0}, g_would_ticks{0}, g_would_writes{0},
    g_would_lives{0}, g_owner_calls{0}, g_owner_null{0}, g_faults{0}, g_write_faults{0};
std::atomic<uint64_t> g_skips[static_cast<size_t>(Skip::Count)] = {};

enum Kind : uint16_t { kEWrite, kESkip, kEFirst, kEOwner, kEStuck, kELatch, kKindCount };
p::EventRing<256> g_ring;
p::WindowLimiter g_lim[kKindCount] = {{32, 5'000'000}, {32, 5'000'000}, {32, 5'000'000},
                                      {8, 5'000'000},  {16, 5'000'000}, {4, 5'000'000}};
std::atomic<uint64_t> g_limited{0}, g_lost{0}, g_lines{0};
constexpr uint64_t kMaxLines = 2000;

// ---------------------------------------------------------------- hot path (no CRT, no allocation)

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
uint32_t key_of(uintptr_t actor) noexcept { return actor ? rdv<uint32_t>(actor + kActor_Key) : 0; }
uintptr_t manager_of(uintptr_t actor) noexcept {
    const uintptr_t comps = actor ? rdp(actor + kActor_Comps) : 0;
    const uintptr_t seq = comps ? rdp(comps + kComps_Seq) : 0;
    return seq ? rdp(seq + kSeqComp_Mgr) : 0;
}
uintptr_t find_actor(uint32_t key) noexcept {
    const uintptr_t world = rdp(g_base + g_world_slot);
    const uintptr_t mgr = world ? rdp(world + off::kWorldSystem_ActorManager) : 0;
    const uintptr_t table = mgr ? rdp(mgr + kManager_Table) : 0;
    const uint32_t buckets = table ? rdv<uint32_t>(table + kTable_BucketCount) : 0;
    if (!buckets || buckets > (1u << 24)) return 0;
    const uintptr_t base = rdp(table + kTable_Buckets), nodes = rdp(table + kTable_Nodes);
    if (!base || !nodes) return 0;
    const uintptr_t bucket = base + static_cast<uintptr_t>(key % buckets) * kBucketStride;
    const uint32_t count = rdv<uint32_t>(bucket);
    for (uint32_t i = 0; i < count && i < kBucketMaxEntries; ++i) {
        if (rdv<uint32_t>(bucket + 8 + i * 8) != key) continue;
        const uint32_t idx = rdv<uint32_t>(bucket + 0xC + i * 8);
        const uintptr_t node = idx ? rdp(nodes + static_cast<uintptr_t>(idx) * 8) : 0;
        if (!node || rdv<uint32_t>(node + kNode_Key) != key) return 0;
        return rdp(node + kNode_Actor);
    }
    return 0;
}
// Review 1: X's character is still registered in the client actor table under `key`, is X's [X+0x18], and
// still owns X. Every frame, only for a slot that passed the cheaper checks (one bucket walk).
bool actor_live(uintptr_t x, uint32_t key) noexcept {
    const uintptr_t actor = find_actor(key);
    return actor && actor == rdp(x + kMgr_Actor) && key_of(actor) == key && manager_of(actor) == x;
}
uint32_t lists_of(uintptr_t x) noexcept {
    return rdv<uint32_t>(x + g_off->n1b0) + rdv<uint32_t>(x + g_off->n1c0) + rdv<uint32_t>(x + g_off->n1d0);
}

// Our own write (no lock: neither the native 0xB87A67 nor .xtls 0x9F8FD19 takes one for it).
bool write_byte(uintptr_t a, uint8_t v) noexcept {
    if (a < 0x10000) return false;
    __try {
        *reinterpret_cast<volatile uint8_t*>(a) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// P8 review I1: an exception inside the game's code we called is the game's (it may hold [X+8]'s lock or
// a half-done list): the module switches off, one line goes straight to the log, the exception is passed on.
// Review 5 [V, unwind info of the PE]: no frame of the chain catches it: 0x8B6060, 0xAD2380 (main loop),
// 0x617290 and 0xA953C0 / 0xA97300 / 0xAA3E70 have only UNW_FLAG_UHANDLER (0x4898DE8: unwind cleanups, never
// called in the search phase), WinApp::vf9 0x3F41240 has no handler; above it [E] the CRT's main and the
// unhandled-exception filter, which end the process. So nothing in that chain resumes the main loop with
// [X+8] still locked: the fault is a real crash where it happened. Were something above to resume, the module is
// already off (g_disabled) and never calls the game again; the lock would stay taken (cannot be released
// safely from here: the game's guard object lives in the faulting frame).
int call_fault(EXCEPTION_POINTERS* ep, const char* where) noexcept {
    t_live_x = 0;
    guest_x_context_clear();  // guest_x_veto's X context (set by the scopes below), before any unwind
    g_disabled.store(true);
    g_faults.fetch_add(1);
    return game::game_fault_continue(ep, "GuestSeqPlay", where);
}
bool guarded_tick_body(uintptr_t x, uintptr_t q, uint8_t mode) noexcept {
    __try {
        g_tick(x, q, mode);
        return true;
    } __except (call_fault(GetExceptionInformation(), "0xA953C0(X, Q, mode) ran for the host character's manager X")) {
        return false;  // never reached: the filter passes it on
    }
}
// guest_x_veto (p8-s9-cinematica.md §8): our calls for X run in an "X context" (RAII; the filter clears it too):
// a load request 0x778AB0 from inside them is X's, never this client's own.
bool guarded_tick(uintptr_t x, uintptr_t q, uint8_t mode) noexcept {
    const GuestXContextScope scope(x);
    return guarded_tick_body(x, q, mode);
}
bool guarded_live(uintptr_t x, float dt) noexcept {
    __try {
        g_live_fn(x, dt);
        return true;
    } __except (call_fault(GetExceptionInformation(), "the live update (0xAA3E70 / 0xBB0450)(X, dt) ran for the host character's manager X")) {
        return false;
    }
}
// Review (0383f70) 1: t_live_x is set for exactly our call (RAII; the SEH filter clears it too, before any
// unwind). The skip hook at 0xAA4B27 cuts the local player's part of this call only.
struct LiveScope {
    explicit LiveScope(uintptr_t x) noexcept { t_live_x = x; }
    ~LiveScope() { t_live_x = 0; }
    LiveScope(const LiveScope&) = delete;
    LiveScope& operator=(const LiveScope&) = delete;
};
bool call_live(uintptr_t x, float dt) noexcept {
    const LiveScope scope(x);
    const GuestXContextScope x_scope(x);
    return guarded_live(x, dt);
}

bool guarded_owner(uintptr_t q, uintptr_t& out) noexcept {
    __try {
        out = g_owner(q);
        return true;
    } __except (call_fault(GetExceptionInformation(), "the field's vf40 0x9A5B70 ran before a tick of X")) {
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

// The five fields of X behind 0xAA5040 / 0xAA5400 (an unreadable one is not idle).
void read_gate(gsp::Facts& f) noexcept {
    const GateOff& g = *g_gate;
    f.x_2a4 = rdv<uint8_t>(f.x + g.f2a4, 0xFF);
    f.x_288 = rdp(f.x + g.f288);
    f.x_2a8 = rdp(f.x + g.f2a8);
    f.x_2b0 = rdv<float>(f.x + g.f2b0, 1.0f);
    f.x_2b4 = rdv<float>(f.x + g.f2b4, 0.0f);
    f.x_2d4 = rdv<uint8_t>(f.x + g.f2d4, 0xFF);
    f.x_2cc = rdv<float>(f.x + g.f2cc, 1.0f);
}

// Review of 0383f70, 5: a gate held for kGateStuckUs gets one line per episode (and a count); never forced.
void watch_gate(size_t i, const gsp::Facts& f, bool held) noexcept {
    const auto bits = [](float v) { return static_cast<uint64_t>(std::bit_cast<uint32_t>(v)); };
    const uint64_t now = p8_now_us();
    if (!g_gate_watch[i].update(held, now, kGateStuckUs)) return;
    g_live_stuck.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    e.v[0] = i;
    e.v[1] = f.x;
    e.v[2] = f.key;
    e.v[3] = now - g_gate_watch[i].since_us;
    e.v[4] = f.x_2a4;
    e.v[5] = f.x_288;
    e.v[6] = f.x_2a8;
    e.v[7] = f.x_2d4;
    e.v[8] = bits(f.x_2cc);
    e.v[9] = bits(f.x_2b0) | bits(f.x_2b4) << 32;
    // M's own values, to compare (the same fields of this client's own manager).
    e.v[10] = f.m ? rdp(f.m + g_gate->f2a8) : 0;
    e.v[11] = f.m ? bits(rdv<float>(f.m + g_gate->f2b0, 0.0f)) | bits(rdv<float>(f.m + g_gate->f2b4, 0.0f)) << 32 : 0;
    emit(kEStuck, e);
}

void on_frame_body(safetyhook::Context& ctx) noexcept {
    const auto mode = static_cast<gsp::Mode>(g_mode.load(std::memory_order_relaxed));
    if (mode == gsp::Mode::Off) return;
    // guest_x_veto's own-manager check (review 4): this frame's M (vf48 of the field) and its live owner.
    if (ctx.rax) guest_x_note_m(ctx.rax, key_of(rdp(ctx.rax + kMgr_Actor)));
    g_last_m.store(ctx.rax, std::memory_order_relaxed);
    const uint64_t frame = g_frames.fetch_add(1, std::memory_order_relaxed) + 1;
    if (!g_table.used()) return;
    const bool probe = mode == gsp::Mode::Probe;

    gsp::Facts base;
    base.epoch = guest_connection_epoch();
    base.mode = mode;
    base.live = g_live.load(std::memory_order_relaxed);
    base.code_ok = !g_disabled.load(std::memory_order_relaxed);
    base.field_mode = rdv<uint8_t>(ctx.r8 + g_off->mode, gsp::kFieldModeNoTick);
    base.m = ctx.rax;
    base.m_ready = base.m ? rdv<uint8_t>(base.m + g_off->ready) : 0;
    base.m_ctx_vt = base.m ? rdp(rdp(base.m + kMgr_Ctx)) : 0;
    const uintptr_t q = g_3527 ? rdp(ctx.rsp + kFrame_Q3527) : rdp(ctx.rbp - kFrame_Q);
    base.q = q;
    const uintptr_t q_vt = q ? rdp(q) : 0;
    base.q_is_field = q_vt == g_base + g_off->vt_field && rdp(q_vt + kField_Vf40) == g_base + g_off->owner_rva;
    // 2976: the native live call needs the byte at 0 (0x8B63CE). 3527 / 3549: the byte only picks WHERE it runs (0: the
    // frame 0x9A017C; else the job 0xBE02F0), and X's call rides on M's (on_live_entry) wherever that is.
    base.live_gate = g_3527 || rdv<uint8_t>(g_base + g_live_gate_rva, 1) == 0;
    base.want_vt = g_base + g_off->vt_mgr;
    base.skip_hook_ok = g_skip_ok.load(std::memory_order_acquire) && !g_live_latched.load(std::memory_order_relaxed);
    const float dt = ctx.xmm6.f32[0];  // the frame's dt (2976 0x8B608F; 3527 / 3549 0x9A0085, see the top)
    // A dt that is not a frame's (NaN, negative, a hitch over half a second) gets no live call this frame.
    const bool dt_ok = dt > 0.0f && dt < 0.5f;
    int8_t owner = -1;  // vf40(Q): asked at most once per frame

    for (size_t i = 0; i < kSlots; ++i) {
        const auto view = g_table.get(i);
        if (!view.key) continue;
        gsp::Facts f = base;
        f.x = view.x;
        f.key = view.key;
        f.slot_field = view.field;
        f.slot_epoch = view.epoch;
        if (f.x) {
            f.x_vt = rdp(f.x);
            const uintptr_t actor = rdp(f.x + kMgr_Actor);
            f.x_key = key_of(actor);
            f.x_own = manager_of(actor);
            f.x_ctx = rdp(f.x + kMgr_Ctx);
            f.x_ctx_vt = f.x_ctx ? rdp(f.x_ctx) : 0;
            f.x_ready = rdv<uint8_t>(f.x + g_off->ready);
            f.x_loading = rdv<uint32_t>(f.x + g_off->loading);
            f.n1b0 = rdv<uint32_t>(f.x + g_off->n1b0);
            f.n1c0 = rdv<uint32_t>(f.x + g_off->n1c0);
            if (base.live) read_gate(f);  // phase 2's read-only gate
            // The table walk only when the cheaper identity checks hold (it is the most expensive read).
            if (f.x_vt == base.want_vt && f.x_key == f.key && f.x_own == f.x) f.actor_live = actor_live(f.x, f.key);
        }
        // probe never writes: its "would write" mark must not re-arm on X still reading 2.
        f.armed = g_mark[i].armed(f.x, view.gen, probe ? 0 : f.x_ready);
        f.owner_q = owner;
        gsp::Plan pl = gsp::plan(f);
        if (gsp::clears_slot(pl.skip)) g_table.clear(i, view.key);
        if (pl.needs_owner) {
            uintptr_t missions = 0;
            if (!guarded_owner(q, missions)) return;  // never reached: the filter passes it on
            g_owner_calls.fetch_add(1, std::memory_order_relaxed);
            owner = missions ? 1 : 0;
            if (!missions) g_owner_null.fetch_add(1, std::memory_order_relaxed);
            if (g_last_owner.exchange(owner, std::memory_order_relaxed) != owner && !missions) {  // a line per turn to null
                p::Event e;
                e.v[0] = 1;
                e.v[1] = frame;
                emit(kEOwner, e);
            }
            f.owner_q = owner;
            pl = gsp::plan(f);
        }
        const auto skip_now = static_cast<uint8_t>(pl.skip);
        if (g_last_skip[i].exchange(skip_now, std::memory_order_relaxed) != skip_now) {
            p::Event e;
            e.v[0] = i;
            e.v[1] = f.x;
            e.v[2] = f.key;
            e.v[3] = skip_now;
            e.v[4] = f.x_ready;
            e.v[5] = f.m_ready;
            e.v[6] = f.field_mode;
            e.v[7] = probe;
            emit(kESkip, e);
        }
        g_skips[skip_now].fetch_add(1, std::memory_order_relaxed);
        if (pl.skip != Skip::None || !pl.tick) continue;
        if (pl.live_held) (pl.live_no_hook ? g_live_no_hook : g_live_gated).fetch_add(1, std::memory_order_relaxed);
        if (pl.live_held && !pl.live_no_hook && !probe) watch_gate(i, f, true);

        if (g_first_x[i].exchange(f.x, std::memory_order_relaxed) != f.x) {
            p::Event e;
            e.v[0] = i;
            e.v[1] = f.x;
            e.v[2] = f.key;
            e.v[3] = pl.live;
            e.v[4] = f.x_ready;
            e.v[5] = probe;
            e.v[6] = f.n1b0 | static_cast<uint64_t>(f.n1c0) << 32;
            emit(kEFirst, e);
        }
        // The 3 (review 9; p8-xtls-lectura.md §1.1-§1.4, read in Ghidra): the native .xtls 0x9F8FCE0 only
        // writes +0x231 = 3 (0x9F8FD19, no lock) and plays at once the eligible entries of +0x1C0; with the 3
        // the tick below plays every ready entry of +0x1B0/+0x1C0 itself, one per call (0xA97503).
        // Order (review 12): X's tick runs right BEFORE M's native tick in the same frame. The hook cannot sit
        // after 0x8B6150: RAX (M) and R8 (mode) are gone there, and 0x8B6156 is RIP-relative. X and M share
        // nothing but Q (read only) and, maybe, the class of their lock object, each taken and released inside
        // its own call (never nested), so the order changes nothing for M.
        if (pl.write3) {
            const bool ok = probe || write_byte(f.x + g_off->ready, gsp::kStatePlay);
            if (ok) {
                if (g_mark[i].mark(f.x, view.gen)) g_rearms.fetch_add(1, std::memory_order_relaxed);
                g_written_x[i].store(f.x, std::memory_order_relaxed);
                g_written_gen[i].store(view.gen, std::memory_order_relaxed);
                g_written_us[i].store(p8_now_us(), std::memory_order_relaxed);
                g_written_n[i].fetch_add(1, std::memory_order_relaxed);
                (probe ? g_would_writes : g_writes).fetch_add(1, std::memory_order_relaxed);
                p::Event e;
                e.v[0] = i;
                e.v[1] = f.x;
                e.v[2] = f.key;
                e.v[3] = view.gen;
                e.v[4] = f.n1b0 | static_cast<uint64_t>(f.n1c0) << 16 | static_cast<uint64_t>(f.m_ready) << 32 |
                         static_cast<uint64_t>(probe) << 40;
                e.v[5] = frame;
                emit(kEWrite, e);
            } else {
                g_write_faults.fetch_add(1, std::memory_order_relaxed);
                continue;  // X not writable: gone
            }
        }
        if (probe) {
            g_would_ticks.fetch_add(1, std::memory_order_relaxed);
            g_slot_would[i].fetch_add(1, std::memory_order_relaxed);
            if (pl.live) g_would_lives.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const bool playing = f.x_ready == gsp::kStatePlay || pl.write3;
        const uint32_t before = lists_of(f.x);
        const uint32_t live_before = rdv<uint32_t>(f.x + kMgr_Live);
        if (!guarded_tick(f.x, q, f.field_mode)) return;  // never reached
        g_ticks.fetch_add(1, std::memory_order_relaxed);
        g_slot_ticks[i].fetch_add(1, std::memory_order_relaxed);
        if (pl.live) {
            // Review of 0383f70, 2: the tick may have changed X's fields: the gate again, right before the call.
            gsp::Facts now = f;
            read_gate(now);
            if (!gsp::live_fields_idle(now)) {
                g_live_held_after_tick.fetch_add(1, std::memory_order_relaxed);
                watch_gate(i, now, true);
            } else if (g_3527 && !g_live_latched.load(std::memory_order_relaxed)) {
                // 3527 / 3549: X's live update runs inside M's native one (on_live_entry), never from here.
                watch_gate(i, now, false);
                g_due_key[i].store(f.key, std::memory_order_relaxed);
                if (g_due_x[i].exchange(f.x, std::memory_order_release)) g_due_replaced.fetch_add(1, std::memory_order_relaxed);
            } else if (!dt_ok) {
                g_live_bad_dt.fetch_add(1, std::memory_order_relaxed);
            } else if (!g_live_latched.load(std::memory_order_relaxed)) {
                watch_gate(i, now, false);
                if (!call_live(f.x, dt)) return;  // never reached
                g_lives.fetch_add(1, std::memory_order_relaxed);
                g_slot_lives[i].fetch_add(1, std::memory_order_relaxed);
            }
        }
        if (playing) {
            g_slot_consumed[i].fetch_add(gsp::consumed(before, lists_of(f.x)), std::memory_order_relaxed);
            const uint32_t live_after = rdv<uint32_t>(f.x + kMgr_Live);
            if (live_after > live_before) g_slot_grew[i].fetch_add(live_after - live_before, std::memory_order_relaxed);
        }
    }
}

// Phase 2's skip hook at 0xAA4B27 (inside 0xAA3E70, also for M's native call every frame: then it does nothing).
// For our own call for X (t_live_x, and r13 = X: G since 0xAA4389): resume at 0xAA4CB2, over the local player's
// part (0x8B4570, 0xA96070, 0xA9A1F0, 0xA9A410) and 0xAA5040 / 0xAA5400. rsi must be exe+0x5725E48 there (the
// base vtable 0xAA4CD2 stores); it is on every path [V], and is set anyway (counted if it was not).
// 3527 / 3549: the entry of 0xBB0450 (also our own calls for X: then nothing). For M's native call, on the main thread,
// every X marked due by this frame gets its live update first, right before M's, with M's dt (xmm1), after the same
// identity and gate checks again (time has passed since the frame).
void drop_due() noexcept {
    for (auto& d : g_due_x) {
        if (d.exchange(0, std::memory_order_relaxed)) g_due_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}
void on_live_entry(safetyhook::Context& ctx) noexcept {
    if (t_live_x) return;  // our own call for X
    if (!g_code_ok.load(std::memory_order_acquire)) return;
    g_entry_calls.fetch_add(1, std::memory_order_relaxed);
    const uint32_t tid = GetCurrentThreadId();
    g_entry_tid.store(tid, std::memory_order_relaxed);
    if (g_disabled.load(std::memory_order_relaxed) || !g_skip_ok.load(std::memory_order_acquire) ||
        g_live_latched.load(std::memory_order_relaxed)) {
        drop_due();
        return;
    }
    if (ctx.rcx != g_last_m.load(std::memory_order_relaxed)) {
        g_entry_not_m.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // M's native live update runs as a job on whichever pool thread takes it (0xBE02F0; seen live on 3549: never the
    // frame's thread, a different one from call to call), so X's runs there too, right before M's: the same thread,
    // order and [G+8] locking as the game's own for M. Calls not on the frame's thread are counted (all of them, so
    // far). Open risk, for the experiment only: X freed by the frame's thread during the call (the identity checks
    // right before it narrow the window, they cannot close it).
    if (tid != g_main_tid.load(std::memory_order_relaxed)) g_entry_other_thread.fetch_add(1, std::memory_order_relaxed);
    const float dt = ctx.xmm1.f32[0];
    if (!(dt > 0.0f && dt < 0.5f)) {
        g_live_bad_dt.fetch_add(1, std::memory_order_relaxed);
        drop_due();
        return;
    }
    const uintptr_t want_vt = g_base + g_off->vt_mgr;
    for (size_t i = 0; i < kSlots; ++i) {
        const uintptr_t x = g_due_x[i].exchange(0, std::memory_order_acquire);
        if (!x) continue;
        const uint32_t key = g_due_key[i].load(std::memory_order_relaxed);
        const uintptr_t actor = rdp(x + kMgr_Actor);
        if (rdp(x) != want_vt || key_of(actor) != key || manager_of(actor) != x || !actor_live(x, key) ||
            rdv<uint8_t>(x + g_off->ready) != gsp::kStatePlay || !g_table.knows(x, key, guest_connection_epoch())) {
            g_due_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        gsp::Facts now;
        now.x = x;
        read_gate(now);
        if (!gsp::live_fields_idle(now)) {
            g_live_held_after_tick.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (!call_live(x, dt)) return;  // never reached
        g_lives.fetch_add(1, std::memory_order_relaxed);
        g_slot_lives[i].fetch_add(1, std::memory_order_relaxed);
    }
}

void on_skip(safetyhook::Context& ctx) noexcept {
    const uintptr_t x = t_live_x;
    if (!x) return;  // the game's own call (M)
    if (ctx.r13 != x) {
        // Not expected [V call graph]: 0xAA3E70's only caller is 0x8B26B7 in 0x8B2660, whose only callers are
        // 0x8B63DE / 0x8B67F3 in 0x8B6060 (no pointer to either): no 0xAA3E70 for another manager can run inside
        // ours. Should r13 still differ, fail closed: this call runs natively (it cannot be cut safely here),
        // and the live path is off for the session (review of 0383f70, 3).
        g_live_not_skipped.fetch_add(1, std::memory_order_relaxed);
        if (!g_live_latched.exchange(true, std::memory_order_relaxed)) {
            p::Event e;
            e.v[0] = x;
            e.v[1] = ctx.r13;
            emit(kELatch, e);
        }
        return;
    }
    const uintptr_t base_vt = g_base + g_base_vt_rva;
    if (ctx.rsi != base_vt) {
        g_live_rsi_fixed.fetch_add(1, std::memory_order_relaxed);
        ctx.rsi = base_vt;
    }
    ctx.rip = g_base + g_skip_resume;
    g_live_skipped.fetch_add(1, std::memory_order_relaxed);
}

// Review 2: the game calls 0x8B6060 once per main loop turn; nothing it calls reaches 0x8B6144 again, but
// if it ever did (a nested frame update inside a tick of X), the inner call does nothing.
void on_frame(safetyhook::Context& ctx) noexcept {
    if (!g_code_ok.load(std::memory_order_acquire)) return;
    if (t_in_frame) {
        g_reentry.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!g_main_tid.load(std::memory_order_relaxed)) g_main_tid.store(GetCurrentThreadId(), std::memory_order_relaxed);
    freeze_watchdog_frame();  // once per main loop turn: the freeze watchdog's frame source (two relaxed stores)
    t_in_frame = true;
    // guest_sched_bind's retry queue (session 12): the main thread, before the native tick; nothing when it is off
    // or the queue is empty (two relaxed loads). RAX = M (this client's own manager, from the field's vf48).
    guest_sched_bind_frame(ctx.rax);
    on_frame_body(ctx);
    // S45 S-D (guest_seq_present.h): read-only sample of the client's camera / input state after X's tick and before
    // M's native one; one atomic load when guest_seq_foreign_present_probe=0.
    guest_seq_present_frame(ctx.rax);
    t_in_frame = false;
}

// ---------------------------------------------------------------- lines (diagnostics thread)

std::string line_of(const p::Event& e) {
    const uint64_t* v = e.v;
    const std::string when = p8_when(e.qpc_us);
    switch (e.kind) {
        case kEWrite:
            return std::format("GuestSeqPlay [3] {} T{} | slot {} X 0x{:X} (character 0x{:08X}, routed 2322 #{}): {} "
                               "X+0x231 2 -> 3 (lists +0x1B0 {}, +0x1C0 {}; M+0x231 {}) at frame {} | the tick plays "
                               "what is preloaded from now on, at most one per call (0xA97503)",
                               when, e.tid, v[0], v[1], static_cast<uint32_t>(v[2]), v[3],
                               (v[4] >> 40) & 1 ? "WOULD WRITE (probe)" : "WROTE", v[4] & 0xFFFF, (v[4] >> 16) & 0xFFFF,
                               (v[4] >> 32) & 0xFF, v[5]);
        case kESkip:
            return std::format("GuestSeqPlay [state] {} T{} | slot {} X 0x{:X} (character 0x{:08X}): {}{} | X+0x231 {}, "
                               "M+0x231 {}, field mode {}",
                               when, e.tid, v[0], v[1], static_cast<uint32_t>(v[2]),
                               gsp::skip_name(static_cast<Skip>(v[3])),
                               v[3] == static_cast<uint64_t>(Skip::None) && v[7] ? " (probe: would tick)" : "", v[4],
                               v[5], v[6]);
        case kEFirst:
            return std::format("GuestSeqPlay [first tick] {} T{} | slot {} X 0x{:X} (character 0x{:08X}): {} 0xA953C0(X, "
                               "Q, mode){} | X+0x231 {}, +0x1B0 {}, +0x1C0 {}",
                               when, e.tid, v[0], v[1], static_cast<uint32_t>(v[2]), v[5] ? "WOULD call (probe)" : "calls",
                               v[3] ? " + 0xAA3E70(X, dt)" : "", v[4], static_cast<uint32_t>(v[6]), v[6] >> 32);
        case kEOwner:
            return std::format("GuestSeqPlay [vf40] {} T{} | the field's vf40 0x9A5B70 returned NULL at frame {}: no tick "
                               "of X this frame (0x602940 would fault at 0x602997 / 0x1AC2830)",
                               when, e.tid, v[1]);
        case kEStuck:
        {
            const auto fl = [](uint64_t w) { return std::bit_cast<float>(static_cast<uint32_t>(w)); };
            return std::format("GuestSeqPlay [live held] {} T{} | slot {} X 0x{:X} (character 0x{:08X}): its live update "
                               "has been held {:.1f} s: X+0x2A4 {}, +0x288 0x{:X}, +0x2A8 0x{:X} (+0x2B0 {}, +0x2B4 {}), "
                               "+0x2D4 {}, +0x2CC {} | M: +0x2A8 0x{:X} (+0x2B0 {}, +0x2B4 {}) | idle = +0x2A4/+0x288/"
                               "+0x2D4 0, +0x2CC <= 0 and (+0x2A8 0 or +0x2B0 < 0); only 0xAA5040 / 0xAA5400 (skipped "
                               "for X) or the manager's vf1 0xA94660 clear them: not forced, the hold goes on",
                               when, e.tid, v[0], v[1], static_cast<uint32_t>(v[2]),
                               static_cast<double>(v[3]) / 1e6, v[4], v[5], v[6], fl(v[9]), fl(v[9] >> 32), v[7],
                               fl(v[8]), v[10], fl(v[11]), fl(v[11] >> 32));
        }
        case kELatch:
            return std::format("GuestSeqPlay [live OFF] {} T{} | X 0x{:X}: the skip hook at 0xAA4B27 saw r13 0x{:X} in our "
                               "own 0xAA3E70(X) call, so it did NOT cut the local player's part: the live update of every "
                               "X is OFF for this session (fail closed; the tick and the 3 go on)",
                               when, e.tid, v[0], v[1]);
        default:
            return std::format("GuestSeqPlay: event {}?", e.kind);
    }
}

uint64_t g_tick_n = 0;  // diagnostics thread only

void summary() {
    std::string slots;
    const uint64_t now = p8_now_us();
    for (size_t i = 0; i < kSlots; ++i) {
        const auto v = g_table.get(i);
        if (!v.key) continue;
        const uint64_t wus = g_written_us[i].load();
        slots += std::format(" | slot {} character 0x{:08X} X 0x{:X} (field 0x{:X}, 2322 gen {}): ticks {}{}, live calls {}, 3 {} "
                             "{}, started ~{} (instances that left +0x1B0/+0x1C0/+0x1D0 in state 3), live list +0x28 "
                             "grew {}",
                             i, v.key, v.x, v.field, v.gen, g_slot_ticks[i].load(),
                             g_slot_would[i].load() ? std::format(" (probe would {})", g_slot_would[i].load()) : "",
                             g_slot_lives[i].load(),
                             g_written_n[i].load() ? (g_mode.load() == 1 ? "would be written" : "written") : "not written",
                             g_written_n[i].load()
                                 ? std::format("x{} (last {} = {:.1f} s ago, X 0x{:X}, 2322 #{})", g_written_n[i].load(),
                                               p8_when(wus), wus && now > wus ? static_cast<double>(now - wus) / 1e6 : 0.0,
                                               g_written_x[i].load(), g_written_gen[i].load())
                                 : std::string(),
                             g_slot_consumed[i].load(), g_slot_grew[i].load());
    }
    std::string skips;
    for (size_t k = 1; k < static_cast<size_t>(Skip::Count); ++k) {
        if (const uint64_t n = g_skips[k].load()) skips += std::format(" {} x{};", gsp::skip_name(static_cast<Skip>(k)), n);
    }
    if (g_live.load()) {
        log::info("GuestSeqPlay live (phase 2): skip hook {}{} | {}(X) calls {}: local-player part skipped {} (rsi "
                  "set {}), NOT skipped {} | held back: X's gate fields (2976 +0x2A4/+0x288/+0x2A8/+0x2D4/+0x2CC, 3527 "
                  "+0x40) not idle {} (and right after the tick {}), no skip hook or latched off {}, dt out of (0, 0.5) "
                  "{} | held > {} s (stuck, not forced) {} | 3527 entry hook: M's native calls {} (thread {}, not M {}, "
                  "not the frame's thread {}), X due replaced {} dropped {}",
                  g_skip_ok.load() ? "in" : "MISSING (no live call)",
                  g_live_latched.load() ? ", LATCHED OFF (a call was not cut: see the [live OFF] line)" : "",
                  g_live_name, g_lives.load(), g_live_skipped.load(), g_live_rsi_fixed.load(), g_live_not_skipped.load(),
                  g_live_gated.load(), g_live_held_after_tick.load(), g_live_no_hook.load(), g_live_bad_dt.load(),
                  kGateStuckUs / 1'000'000, g_live_stuck.load(), g_entry_calls.load(), g_entry_tid.load(),
                  g_entry_not_m.load(), g_entry_other_thread.load(), g_due_replaced.load(), g_due_dropped.load());
    }
    log::info("GuestSeqPlay summary (guest_seq_play={}, live={}): frames {} | ticks {} (would {}), live calls {} (would "
              "{}), 3 written {} (would {}, re-armed after a native 2 {}) | vf40 asked {}, null {} | skipped:{} | table {} "
              "of {} (full {}, cleared {}, writer busy {}, unstable reads {}), routing hooks on another thread {}, "
              "re-entries {}{}{} | faults {}{} | limited {} lost {}",
              g_mode.load() == 2 ? "1" : g_mode.load() == 1 ? "probe" : "0", g_live.load() ? 1 : 0, g_frames.load(),
              g_ticks.load(), g_would_ticks.load(), g_lives.load(), g_would_lives.load(), g_writes.load(),
              g_would_writes.load(), g_rearms.load(), g_owner_calls.load(), g_owner_null.load(),
              skips.empty() ? " none" : skips, g_table.used(), kSlots, g_table.full(), g_table.cleared(),
              g_note_busy.load(), g_table.unstable(), g_note_foreign.load(), g_reentry.load(),
              slots.empty() ? " | no X routed yet" : "", slots, g_faults.load(),
              g_disabled.load() ? " (SWITCHED OFF after a fault in the game's code)" : "", g_limited.load(), g_lost.load());
}

// ---------------------------------------------------------------- install

struct Ctx {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
};

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<gad::Section> secs;
    if (g_base != off::kImageBase || !game::safe_read(g_base, &dos, sizeof dos) ||
        !game::safe_read(g_base + dos.e_lfanew, &nt, sizeof nt) || !(game::legacy_layout() || g_3576 || g_3663) ||
        !p8_exe_sections(g_base, secs)) {
        log::error("GuestSeqPlay: unsupported game build or unreadable sections; nothing installed");
        return 0;
    }
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other guest modules
        uintptr_t world = 0;
        if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
        Sleep(500);
    }
    const Ctx ctx2976[] = {
        {0x8B6076, kFrameBytes},      {0x8B608F, kDtBytes},     {0x8B60AF, kActorBytes},
        {0x8B60C6, kAttachBytes},     {0x8B6102, kVf48Bytes},   {0x8B613D, kModePtrBytes},
        {0x8B63CE, kLiveGate1Bytes},  {0x8B67E3, kLiveGate2Bytes}, {kTickRva, kTickBytes},
        {kLiveRva, kLiveBytes},       {kOwnerRva, kOwnerBytes},
    };
    const Ctx ctx3527[] = {
        {0x99C2FB, kActorBytes3527},   {0x99C33C, kQSlotBytes3527}, {0x99C375, kVf48Bytes3527},
        {0x99C382, kModePtrBytes3527}, {kTickRva3527, kTickBytes3527}, {kOwnerRva3527, kOwnerBytes3527},
    };
    const Ctx ctx3576[] = {
        {0x99C5BB, kActorBytes3527},   {0x99C5FC, kQSlotBytes3527}, {0x99C635, kVf48Bytes3576},
        {0x99C642, kModePtrBytes3527}, {kTickRva3576, kTickBytes3527}, {kOwnerRva3576, kOwnerBytes3527},
    };
    const Ctx ctx3663[] = {
        {0x9CB64B, kActorBytes3527},   {0x9CB68C, kQSlotBytes3527}, {0x9CB6C5, kVf48Bytes3663},
        {0x9CB6D2, kModePtrBytes3527}, {kTickRva3663, kTickBytes3527}, {kOwnerRva3663, kOwnerBytes3527},
    };
    const std::span<const Ctx> ctx = g_3663   ? std::span<const Ctx>(ctx3663)
                                     : g_3576 ? std::span<const Ctx>(ctx3576)
                                     : g_3527 ? std::span<const Ctx>(ctx3527)
                                              : std::span<const Ctx>(ctx2976);
    for (const Ctx& c : ctx) {
        if (!gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
            !bytes_at(c.rva, c.bytes)) {
            log::error("GuestSeqPlay: the code at exe+0x{:X} ({} bytes) is not this build's .rsrc code; REFUSED, nothing "
                       "installed",
                       c.rva, c.bytes.size());
            return 0;
        }
    }
    g_tick = reinterpret_cast<TickFn>(
        g_base + (g_3663 ? kTickRva3663 : g_3576 ? kTickRva3576 : g_3527 ? kTickRva3527 : kTickRva));
    g_live_fn = reinterpret_cast<LiveFn>(g_base + g_live_rva);
    g_owner = reinterpret_cast<OwnerFn>(g_base + g_off->owner_rva);
    const bool hooked =
        g_3663   ? p8_install_mid(g_base, secs, kPoint3663, kPatch, kPointBytes3663, on_frame, g_hook, "GuestSeqPlay",
                                  "the frame's sequencer tick 0x9CB6D9 (build 3663)")
        : g_3576 ? p8_install_mid(g_base, secs, kPoint3576, kPatch, kPointBytes3576, on_frame, g_hook, "GuestSeqPlay",
                                  "the frame's sequencer tick 0x99C649 (build 3576)")
        : g_3527 ? p8_install_mid(g_base, secs, kPoint3527, kPatch, kPointBytes3527, on_frame, g_hook, "GuestSeqPlay",
                                  "the frame's sequencer tick 0x99C389 (build 3527)")
                 : p8_install_mid(g_base, secs, kPoint, kPatch, kPointBytes, on_frame, g_hook, "GuestSeqPlay",
                                  "the frame's sequencer tick 0x8B6144");
    if (!hooked) {
        return 0;  // the line above says why
    }
    // Phase 2: the skip hook first (0xAA3E70(X) is never called without it: gsp::plan).
    std::string skip_line = "not wanted (live=0)";
    if (g_live.load()) {
        const Ctx skip2976[] = {
            {0xAA4CA4, kSkipTailBytes},          {0xAA43C7, kSkipCopyBytes}, {0xAA4400, kSkipLoopBytes},
            {0xAA3EA2, kSkipR13Bytes},           {0xAA3EF3, kSkipRsi1Bytes}, {0xAA4AE6, kSkipRsi2Bytes},
            {0xAA4B13, kSkipRsi3Bytes},
        };
        // 3527 / 3549 (see the top): the live update's head, its native call (gate byte, dt), the point's surroundings.
        const Ctx skip3527[] = {
            {kLiveRva3527, kLiveBytes},          {0x9A0085, kDtBytes3527},       {0x9A0097, kDtCallBytes3527},
            {0x9A017C, kLiveCallBytes3527},      {0xBB12AC, kSkipTailBytes3527}, {0xBB09AF, kSkipCopyBytes3527},
            {0xBB09E8, kSkipLoopBytes3527},      {0xBB0482, kSkipR13Bytes},      {0xBB090A, kSkipR13Reload3527},
            {0xBB0971, kSkipR13Reload3527},      {0xBB04D3, kSkipRsi1Bytes3527}, {0xBB10EE, kSkipRsi2Bytes3527},
            {0xBB111B, kSkipRsi3Bytes3527},
        };
        const Ctx skip3576[] = {
            {kLiveRva3576, kLiveBytes},          {0x9A0565, kDtBytes3527},       {0x9A0577, kDtCallBytes3576},
            {0x9A065C, kLiveCallBytes3576},      {0xBB16CC, kSkipTailBytes3576}, {0xBB0DCF, kSkipCopyBytes3527},
            {0xBB0E08, kSkipLoopBytes3527},      {0xBB08A2, kSkipR13Bytes},      {0xBB0D2A, kSkipR13Reload3527},
            {0xBB0D91, kSkipR13Reload3527},      {0xBB08F3, kSkipRsi1Bytes3576}, {0xBB150E, kSkipRsi2Bytes3576},
            {0xBB153B, kSkipRsi3Bytes3576},
        };
        const Ctx skip3663[] = {
            {kLiveRva3663, kLiveBytes},          {0x9CF7E5, kDtBytes3663},       {0x9CF7F7, kDtCallBytes3663},
            {0x9CF8D6, kLiveCallBytes3663},      {0xBE923C, kSkipTailBytes3663}, {0xBE893F, kSkipCopyBytes3663},
            {0xBE8978, kSkipLoopBytes3527},      {0xBE8412, kSkipR13Bytes},      {0xBE889A, kSkipR13Reload3527},
            {0xBE8901, kSkipR13Reload3527},      {0xBE8463, kSkipRsi1Bytes3663}, {0xBE907E, kSkipRsi2Bytes3663},
            {0xBE90AB, kSkipRsi3Bytes3663},
        };
        const std::span<const Ctx> skip_ctx = g_3663   ? std::span<const Ctx>(skip3663)
                                              : g_3576 ? std::span<const Ctx>(skip3576)
                                              : g_3527 ? std::span<const Ctx>(skip3527)
                                                       : std::span<const Ctx>(skip2976);
        bool ok = true;
        for (const Ctx& c : skip_ctx) {
            if (!gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
                !bytes_at(c.rva, c.bytes)) {
                skip_line = std::format("REFUSED: the code at exe+0x{:X} is not this build's (live=0 in effect)", c.rva);
                ok = false;
                break;
            }
        }
        const uintptr_t point = g_3663 ? kSkipPoint3663 : g_3576 ? kSkipPoint3576 : g_3527 ? kSkipPoint3527 : kSkipPoint;
        const std::span<const uint8_t> point_bytes = g_3663   ? std::span<const uint8_t>(kSkipBytes3663)
                                                     : g_3576 ? std::span<const uint8_t>(kSkipBytes3576)
                                                     : g_3527 ? std::span<const uint8_t>(kSkipBytes3527)
                                                              : std::span<const uint8_t>(kSkipBytes);
        if (ok && p8_install_mid(g_base, secs, point, kSkipPatch, point_bytes, on_skip, g_skip_hook, "GuestSeqPlay",
                                 g_3663   ? "the live update's local-player skip 0xBE90BF (3663)"
                                 : g_3576 ? "the live update's local-player skip 0xBB154F (3576)"
                                 : g_3527 ? "the live update's local-player skip 0xBB112F (3527 / 3549)"
                                          : "the live update's local-player skip 0xAA4B27")) {
            if (g_3527 && !p8_install_mid(g_base, secs, g_live_rva, kLiveEntryPatch3527, kLiveBytes, on_live_entry,
                                          g_live_entry_hook, "GuestSeqPlay",
                                          g_3663   ? "the live update's entry 0xBE83E0 (3663)"
                                          : g_3576 ? "the live update's entry 0xBB0870 (3576)"
                                                   : "the live update's entry 0xBB0450 (3527 / 3549)")) {
                g_skip_hook = {};  // no entry hook: no live call at all
                skip_line = std::format("REFUSED: the entry hook of {} (see the line above)", g_live_name);
            } else {
            g_skip_ok.store(true, std::memory_order_release);
            skip_line = std::format("hooked 0x{:X} -> 0x{:X} for our calls only (rsi := exe+0x{:X}), live update {}, gate "
                                    "byte exe+0x{:X}",
                                    point, g_skip_resume, g_base_vt_rva, g_live_name, g_live_gate_rva);
            if (g_3527) {
                skip_line += std::format(" | entry hook {}: X's live update runs inside M's native one", g_live_name);
            }
            }
        } else if (ok) {
            skip_line = "REFUSED (see the line above)";
        }
    }
    g_code_ok.store(true, std::memory_order_release);
    const auto mode = static_cast<gsp::Mode>(g_mode.load());
    log::info("GuestSeqPlay {} (guest_seq_play, live={}): hooked exe+0x{:X} (2976: 0x8B6144; movzx r8d,byte [r8+mode]; main loop, once per "
              "frame, before the native 0xA953C0(M, Q, mode)) | per X routed by guest_seq_route (the host's character's "
              "ClientSequencerStageManager, vtable exe+0x{:X} checked, never M): 0xA953C0(X, Q, mode) when mode != 2, "
              "M+0x231 == 3, the field's vf40 != 0; X+0x231 = 3 once per routed 2322 (X at 2, +0x174 0, +0x1B0/+0x1C0 "
              "not empty){} | live skip hook: {} | guest_seq_route={}{}",
              gsp::mode_name(mode), g_live.load() ? 1 : 0,
              g_3663 ? kPoint3663 : g_3576 ? kPoint3576 : g_3527 ? kPoint3527 : kPoint, g_off->vt_mgr,
              g_live.load() ? "; 0xAA3E70(X, dt) when X is at 3, byte [0x6CC0218] == 0, the skip hook is in and X+0x2A4/"
                              "+0x288/+0x2A8/+0x2D4 are 0 and +0x2CC <= 0 (the local player's part and 0xAA5040/"
                              "0xAA5400 never run for X); the 2524 routed to X"
                            : "",
              skip_line,
              g_route_on.load() ? "1" : "NOT 1",
              g_route_on.load() ? "" : " (probe only: guest_seq_route is not 1, nothing is routed, no X will be known)");
    return 0;
}

}  // namespace

void guest_seq_play_start(const std::string& mode, bool live, const std::string& route_mode) {
    g_3576 = game::current_build() == game::Build::v3576;
    g_3663 = game::current_build() == game::Build::v3663;
    g_3527 = game::current_build() == game::Build::v3527 || g_3576 || g_3663;
    if (g_3663) {
        // Build 1.0.0.3663 (static, 2026-11-13; never run): see the 3663 block at the top.
        g_off = &kOff3663;
        g_world_slot = 0x72451C0;  // WorldSystem, profile_s2.h's rva3663()
        g_gate = &kGate3663;
        g_live_gate_rva = kLiveGateByte3663;
        g_skip_resume = kSkipResume3663;
        g_base_vt_rva = kBaseVtable3663;
        g_live_rva = kLiveRva3663;
        g_live_name = "0xBE83E0";
    } else if (g_3576) {
        g_off = &kOff3576;
        g_world_slot = 0x71C0100;  // core_globals_3576.json (no reader profile for 3576 yet)
        g_gate = &kGate3527;       // the same fields (see the 3576 block at the top)
        g_live_gate_rva = kLiveGateByte3576;
        g_skip_resume = kSkipResume3576;
        g_base_vt_rva = kBaseVtable3576;
        g_live_rva = kLiveRva3576;
        g_live_name = "0xBB0870";
    } else if (g_3527) {
        g_off = &kOff3527;
        if (const auto* profile = game::reader_profile()) g_world_slot = profile->world_system;
        // Phase 2 ported (2026-11-06, read on 3549; see the top): 0xBB0450, its skip hook 0xBB112F -> 0xBB12BA. The 2524
        // routing stays refused on this build (guest_seq_route.cpp).
        g_gate = &kGate3527;
        g_live_gate_rva = kLiveGateByte3527;
        g_skip_resume = kSkipResume3527;
        g_base_vt_rva = kBaseVtable3527;
        g_live_rva = kLiveRva3527;
        g_live_name = "0xBB0450";
    }
    bool bad = false;
    const gsp::Mode asked = gsp::parse_mode(mode, &bad);
    if (bad) log::warn("GuestSeqPlay: guest_seq_play={} is not 0, probe or 1: off", mode);
    const gsp::Mode route = gsp::parse_mode(route_mode);
    const gsp::Mode m = gsp::effective_mode(asked, route);
    if (m != asked) {
        log::error("GuestSeqPlay: guest_seq_play={} REFUSED (off): it needs guest_seq_route=1 (it is {}); only a ROUTED "
                   "packet makes X known, and only the routing creates the host's instances in X",
                   mode, route_mode.empty() ? "0" : route_mode);
    } else if (m == gsp::Mode::Probe && route != gsp::Mode::On) {
        log::warn("GuestSeqPlay: guest_seq_play=probe with guest_seq_route={}: nothing is routed, so no X will be known "
                  "(only frames are counted)",
                  route_mode);
    }
    g_mode.store(static_cast<uint8_t>(m));
    g_live.store(live && m != gsp::Mode::Off);
    g_route_on.store(route == gsp::Mode::On);
    if (m == gsp::Mode::Off) {
        if (live) log::warn("GuestSeqPlay: guest_seq_play_live=1 needs guest_seq_play=probe or 1: off");
        return;
    }
    if (g_started.exchange(true)) return;
    for (auto& s : g_last_skip) s.store(0xFF);  // the first state of each slot (also "ticked") gets its line
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

bool guest_seq_play_wanted() { return g_started.load(); }

uint32_t guest_seq_play_main_tid() noexcept { return g_main_tid.load(std::memory_order_relaxed); }

bool guest_seq_play_routes_2524() {
    return g_mode.load(std::memory_order_relaxed) == static_cast<uint8_t>(gsp::Mode::On) &&
           g_live.load(std::memory_order_relaxed) && g_skip_ok.load(std::memory_order_relaxed) &&
           !g_live_latched.load(std::memory_order_relaxed) && !g_disabled.load(std::memory_order_relaxed);
}

bool guest_seq_play_ticks() {
    return g_mode.load(std::memory_order_relaxed) == static_cast<uint8_t>(gsp::Mode::On) &&
           !g_disabled.load(std::memory_order_relaxed);
}

void guest_seq_play_note_x(uintptr_t x, uint32_t key, uintptr_t field, bool milestone) noexcept {
    if (g_mode.load(std::memory_order_relaxed) == 0) return;
    // Expected on the play hook's thread (both are run by 0xAD2380): counted if not (the table stays correct:
    // writers serialize on a try-lock).
    const uint32_t main = g_main_tid.load(std::memory_order_relaxed);
    if (main && main != GetCurrentThreadId()) g_note_foreign.fetch_add(1, std::memory_order_relaxed);
    if (g_table.note(x, key, field, guest_connection_epoch(), milestone) == gsp::XTable<kSlots>::Noted::Busy) {
        g_note_busy.fetch_add(1, std::memory_order_relaxed);
    }
}

bool guest_seq_play_knows_x(uintptr_t x, uint32_t key) noexcept {
    return g_mode.load(std::memory_order_relaxed) != 0 && g_table.knows(x, key, guest_connection_epoch());
}

void guest_seq_play_tick() noexcept {
    if (!g_started.load()) return;
    try {
        ++g_tick_n;
        p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind >= kKindCount) continue;
            if (e.kind == kELatch) {
                log::error("{}", line_of(e));  // always, outside the line budget
            } else if (g_lines.fetch_add(1) < kMaxLines) {
                log::info("{}", line_of(e));
            }
        }
        if (g_tick_n % 12 == 0) summary();
    } catch (...) {
    }
}

std::string guest_seq_play_describe() {
    if (!g_started.load()) return {};
    return std::format(" | seq play {}{} (ticks {}, 3 written {}{})",
                       g_mode.load() == 2 ? "on" : "probe", g_live.load() ? "+live" : "",
                       g_mode.load() == 2 ? g_ticks.load() : g_would_ticks.load(),
                       g_mode.load() == 2 ? g_writes.load() : g_would_writes.load(), g_disabled.load() ? ", OFF after a fault" : "");
}

}  // namespace cdmp::session2
