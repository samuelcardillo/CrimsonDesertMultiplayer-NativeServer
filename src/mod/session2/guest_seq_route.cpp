#include "mod/session2/guest_seq_route.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <format>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "mod/config.h"
#include "mod/game/build_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_sched_bind.h"
#include "mod/session2/guest_seq_foreign.h"
#include "mod/session2/guest_seq_foreign_logic.h"
#include "mod/session2/guest_seq_play.h"
#include "mod/session2/guest_stage_diag.h"
#include "mod/session2/guest_stage_diag_logic.h"
#include "mod/session2/guest_x_veto.h"
#include "mod/session2/observer_seq_copy_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;
namespace off = game::build_2976;
using gsr::Point;

// ---------------------------------------------------------------- the points (build 2976, .rsrc)
//
// The same bytes guest_stage_diag.cpp (2661/2981/2810) and p8_probes.cpp (2322) verify for these
// addresses (pendientes/observador/fase2-verificacion-enganches.txt; p8-impl-s1s2.md): whole
// instructions, no branch into them, no RIP-relative operand. Re-checked with capstone for this
// module (p8-impl-opcion-a.md §5.2): the registers and frame slots read here are not written between
// their definition and the point.

//   0xC0612A cmp bl,4 ; je 0xC06179 (RAX = the manager vf48 returned; RAX reaches 0xC06185 mov rcx,rax)
constexpr uintptr_t kP2661 = 0xC0612A;
constexpr uint8_t kP2661Bytes[] = {0x80, 0xFB, 0x04, 0x74, 0x4A, 0x48, 0x8D, 0x05,
                                   0x7A, 0x37, 0x9C, 0x04, 0x48, 0x89, 0x44, 0x24};
constexpr uint8_t kFrame2661Bytes[] = {0x48, 0x8D, 0xAC, 0x24, 0x60, 0xFF, 0xFF, 0xFF};  // 0xC05BC0
constexpr uint8_t kKind2661Bytes[] = {0x0F, 0xB6, 0x9D, 0xF0, 0x00, 0x00, 0x00};          // 0xC060C6
constexpr uint8_t kActor2661Bytes[] = {0x49, 0x89, 0x1C, 0x24};                            // 0xC060C2 mov [r12],rbx
constexpr uint8_t kVf48_2661Bytes[] = {0x48, 0x8B, 0x4D, 0xC0, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC06120
constexpr uint8_t kWrap2661Bytes[] = {0x4D, 0x8B, 0xE0};  // 0xC05BCF mov r12,r8 (the wrapper)
//   0xC07749 lea rcx,[rbp-0x80] ; mov [rsp+0x30],rcx (RAX = the manager; RAX reaches 0xC0776E mov rcx,rax)
constexpr uintptr_t kP2981 = 0xC07749;
constexpr uint8_t kP2981Bytes[] = {0x48, 0x8D, 0x4D, 0x80, 0x48, 0x89, 0x4C, 0x24,
                                   0x30, 0x48, 0x8D, 0x4D, 0xB0, 0x48, 0x89, 0x4C};
constexpr uint8_t kWrap2981Bytes[] = {0x4D, 0x8B, 0xF8};                                   // 0xC073BC mov r15,r8
constexpr uint8_t kActor2981Bytes[] = {0x49, 0x89, 0x3F};                                  // 0xC076E6 mov [r15],rdi
constexpr uint8_t kVf48_2981Bytes[] = {0x48, 0x8B, 0x4D, 0xC8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC0773F
//   0xC0659E movzx ecx,byte [rbp+0x70] ; mov [rsp+0x20],cl (RAX = the manager; RAX reaches 0xC065B2 mov rcx,rax)
constexpr uintptr_t kP2810 = 0xC0659E;
constexpr uint8_t kP2810Bytes[] = {0x0F, 0xB6, 0x4D, 0x70, 0x88, 0x4C, 0x24, 0x20,
                                   0x4C, 0x8D, 0x4D, 0xA0, 0x4C, 0x8B, 0x45, 0xA8};
constexpr uint8_t kVf48_2810Bytes[] = {0x48, 0x8B, 0x4D, 0xB8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC06594
constexpr uint8_t kFrame2810Bytes[] = {0x48, 0x8D, 0x6C, 0x24, 0xE0};                     // 0xC06340 lea rbp,[rsp-0x20]
// 0xC06505 mov r8d,[rbp+0x78] ; lea rdx,[rbp-0x10] ; mov rcx,rsi ; call 0x8A67E0 ; nop ;
//          cmp byte [rbp],0 ; je 0xC06545 ; mov rsi,[rbp-8]   (the actor found: [rbp-8], found: [rbp])
constexpr uint8_t kFind2810Bytes[] = {0x44, 0x8B, 0x45, 0x78, 0x48, 0x8D, 0x55, 0xF0, 0x48, 0x8B, 0xCE, 0xE8, 0xCB, 0x02,
                                      0xCA, 0xFF, 0x90, 0x80, 0x7D, 0x00, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0xF8};
constexpr uint8_t kSeq2810Bytes[] = {0x4C, 0x8B, 0x45, 0xA8};  // 0xC065AA mov r8,[rbp-0x58] (the sequencer's u64)
//   0xB87A67 mov byte [rax+0x231],2 (RAX = M from 0xB87A5D..0xB87A64; R14 = the raw packet from 0xB878B8;
//            the handler's own lookup 0xB879DD 0x8A67E0(rsi, &[rbp-0x18], key): found = byte [rbp-8], actor =
//            [rbp-0x10], neither written again before 0xB87A67)
constexpr uintptr_t kP2322 = 0xB87A67;
constexpr uint8_t kP2322Bytes[] = {0xC6, 0x80, 0x31, 0x02, 0x00, 0x00, 0x02,
                                   0x48, 0x8D, 0x05, 0xEB, 0xB3, 0xD8, 0x04};
constexpr uint8_t kVf48_2322Bytes[] = {0x48, 0x8B, 0x4D, 0xA8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xB87A5D
constexpr uint8_t kRaw2322Bytes[] = {0x49, 0x8B, 0xF8, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF1, 0x45, 0x33,
                                     0xED, 0x4D, 0x8B, 0x70, 0x18, 0x41, 0x0F, 0xB7, 0x4E, 0x03};  // 0xB878AC
// 0xB879D6 lea rdx,[rbp-0x18] ; mov rcx,rsi ; call 0x8A67E0 ; nop ; cmp byte [rbp-8],0 ; je ; mov rsi,[rbp-0x10]
constexpr uint8_t kFind2322Bytes[] = {0x48, 0x8D, 0x55, 0xE8, 0x48, 0x8B, 0xCE, 0xE8, 0xFE, 0xED, 0xD1, 0xFF,
                                      0x90, 0x80, 0x7D, 0xF8, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0xF0};
// guest_seq_play_live (p8-impl-escenas-play.md §3), the 2524 StageOnBranchEventAck handler 0xC07D00:
//   0xC07D25 mov r15,r8 ; mov rdi,rdx ; mov rbx,rcx ; xor edx,edx ; mov r14,[r8+0x18]   (R15 = the wrapper, not
//            written again before the point; [R15+0x18] = the raw packet: u32 actor @5, u64 sequencer @9)
//   0xC080D1 mov r8d,[rbp-0x60] ; lea rdx,[rbp+8] ; mov rcx,r12 ; call 0x8A67E0 ; nop ; cmp byte [rbp+0x18],0 ;
//            je ; mov rbx,[rbp+0x10]  ...  0xC0810E mov [r15],rbx   (the actor the handler resolved)
//   0xC0816E mov rcx,[rbp-0x48] ; mov rax,[rcx] ; call [rax+0x48]    (vf48 -> M in RAX)
//   0xC08178 lea rcx,[rbp-8] ; mov [rsp+0x28],rcx   THE POINT (9 bytes, two whole instructions, no branch into
//            0xC0817C, no RIP-relative operand)
//   0xC08188 ... 0xC08198 mov rcx,rax ; call 0xA9E480(M, field, seq, ...)   (RAX not written in between)
constexpr uintptr_t kP2524 = 0xC08178;
constexpr uint8_t kP2524Bytes[] = {0x48, 0x8D, 0x4D, 0xF8, 0x48, 0x89, 0x4C, 0x24,
                                   0x28, 0x0F, 0xB6, 0x8D, 0xA8, 0x10, 0x00, 0x00};
constexpr uint8_t kWrap2524Bytes[] = {0x4D, 0x8B, 0xF8, 0x48, 0x8B, 0xFA, 0x48, 0x8B,
                                      0xD9, 0x33, 0xD2, 0x4D, 0x8B, 0x70, 0x18};  // 0xC07D25
constexpr uint8_t kFind2524Bytes[] = {0x44, 0x8B, 0x45, 0xA0, 0x48, 0x8D, 0x55, 0x08, 0x49, 0x8B, 0xCC, 0xE8, 0xFF, 0xE6,
                                      0xC9, 0xFF, 0x90, 0x80, 0x7D, 0x18, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x5D, 0x10};  // 0xC080D1
constexpr uint8_t kActor2524Bytes[] = {0x49, 0x89, 0x1F};  // 0xC0810E mov [r15],rbx
constexpr uint8_t kVf48_2524Bytes[] = {0x48, 0x8B, 0x4D, 0xB8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC0816E
constexpr uint8_t kUse2524Bytes[] = {0x88, 0x4C, 0x24, 0x20, 0x44, 0x8B, 0x4D, 0xA4, 0x4C, 0x8B, 0x45, 0xA8,
                                     0x48, 0x8B, 0x55, 0xB8, 0x48, 0x8B, 0xC8, 0xE8, 0xE0, 0x62, 0xE9, 0xFF};  // 0xC08188

// guest_sched_route (p8-impl-horarios-x.md §2), the NPC schedule Acks; capstone over the whole RUNTIME_FUNCTION of each
// handler: the points are whole instructions, no direct branch (rel8 in the function, rel32 anywhere in .rsrc/.xtls)
// lands inside them, no RIP-relative operand, RAX (vf48's M) not written between the point and its use.
//   2335 0xC0AFC0: 0xC0AFE5 mov r15,r8 (the wrapper) ; 0xC0B242 mov rax,[rbp-0x58] ; mov [rbp-0x38],rax (u64 key @14)
//        0xC0B50A mov r8d,[rbp-0x60] (u32 actor @1) ; lea rdx,[rbp+0x58] ; mov rcx,r12 ; call 0x8A67E0 ; nop ;
//                 cmp byte [rbp+0x68],0 ; je ; mov rbx,[rbp+0x60]   (found: [rbp+0x68], actor: [rbp+0x60])
//        0xC0B55E movzx ebx,byte [rbp+0x10F0] (kind @0: BL) ; 0xC0B5B7 mov rcx,[rbp-0x28] ; mov rax,[rcx] ; call [rax+0x48]
//        0xC0B5C1 lea rcx,[rbp+8] ; mov [rsp+0x58],rcx   THE POINT (9 bytes)
//        0xC0B612 mov rdx,[rbp-0x28] ; mov rcx,rax ; call 0xA9FEE0(G, field, kind, ...)   resource @9 = [rbp-0x48]
constexpr uintptr_t kS2335 = 0xC0B5C1;
constexpr uint8_t kS2335Bytes[] = {0x48, 0x8D, 0x4D, 0x08, 0x48, 0x89, 0x4C, 0x24,
                                   0x58, 0x48, 0x8D, 0x4D, 0x18, 0x48, 0x89, 0x4C};
constexpr uint8_t kS2335Frame[] = {0x48, 0x8D, 0xAC, 0x24, 0x60, 0xEF, 0xFF, 0xFF};           // 0xC0AFD0 lea rbp,[rsp-0x10A0]
constexpr uint8_t kS2335Wrap[] = {0x4D, 0x8B, 0xF8};                                          // 0xC0AFE5
constexpr uint8_t kS2335Key[] = {0x48, 0x8B, 0x45, 0xA8, 0x48, 0x89, 0x45, 0xC8};               // 0xC0B242
constexpr uint8_t kS2335Find[] = {0x44, 0x8B, 0x45, 0xA0, 0x48, 0x8D, 0x55, 0x58, 0x49, 0x8B, 0xCC, 0xE8, 0xC6, 0xB2,
                                  0xC9, 0xFF, 0x90, 0x80, 0x7D, 0x68, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x5D, 0x60};  // 0xC0B50A
constexpr uint8_t kS2335Kind[] = {0x0F, 0xB6, 0x9D, 0xF0, 0x10, 0x00, 0x00};                    // 0xC0B55E
constexpr uint8_t kS2335Vf48[] = {0x48, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC0B5B7
constexpr uint8_t kS2335Use[] = {0x48, 0x8B, 0x55, 0xD8, 0x48, 0x8B, 0xC8, 0xE8, 0xC2, 0x48, 0xE9, 0xFF};  // 0xC0B612
//   2126 0xC0B840: 0xC0B98E mov rax,[rbp+0x78] ; mov [rbp+0x78],rax (u64 key @4)
//        0xC0B9B5 mov r8d,[rbp+0x70] (u32 actor @0) ; lea rdx,[rbp-0x18] ; mov rcx,rsi ; call 0x8A67E0 ; nop ;
//                 cmp byte [rbp-8],0 ; je ; mov rsi,[rbp-0x10]   (found: [rbp-8], actor: [rbp-0x10])
//        0xC0BA44 mov rcx,[rbp-0x58] ; mov rax,[rcx] ; call [rax+0x48]
//        0xC0BA4E lea rdx,[rbp+0x78] ; mov rcx,[rax+0x148]   THE POINT (11 bytes: the relocated second instruction
//                 reads RAX after the callback, so RAX := X also makes it X's container) ; 0xC0BA59 call 0x43C750
constexpr uintptr_t kS2126 = 0xC0BA4E;
constexpr uint8_t kS2126Bytes[] = {0x48, 0x8D, 0x55, 0x78, 0x48, 0x8B, 0x88, 0x48,
                                   0x01, 0x00, 0x00, 0xE8, 0xF2, 0x0C, 0x83, 0xFF};
constexpr uint8_t kS2126Frame[] = {0x48, 0x8D, 0x6C, 0x24, 0xE0};                             // 0xC0B850 lea rbp,[rsp-0x20]
constexpr uint8_t kS2126Key[] = {0x48, 0x8B, 0x45, 0x78, 0x48, 0x89, 0x45, 0x78};               // 0xC0B98E
constexpr uint8_t kS2126Find[] = {0x44, 0x8B, 0x45, 0x70, 0x48, 0x8D, 0x55, 0xE8, 0x48, 0x8B, 0xCE, 0xE8, 0x1B, 0xAE,
                                  0xC9, 0xFF, 0x90, 0x80, 0x7D, 0xF8, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0xF0};  // 0xC0B9B5
constexpr uint8_t kS2126Vf48[] = {0x48, 0x8B, 0x4D, 0xA8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC0BA44
//   2958 0xC0C3F0 / 2909 0xC0C920 (the same body; offsets +0x530):
//        0xC0C5BA / 0xC0CAEA mov rax,[rbp-0x60] ; mov [rbp-0x60],rax (u64 key @9; u32 resource @5 = [rbp-0x58])
//        0xC0C6B7 / 0xC0CBE7 mov r8d,[rbp+0x10A8] (u32 actor @1) ; lea rdx,[rbp+8] ; mov rcx,r12 ; call 0x8A67E0 ; nop ;
//                 cmp byte [rbp+0x18],0 ; je ; mov rdi,[rbp+0x10]   (found: [rbp+0x18], actor: [rbp+0x10])
//        0xC0C757 / 0xC0CC87 mov rcx,[rbp-0x48] ; mov rax,[rcx] ; call [rax+0x48]
//        0xC0C761 / 0xC0CC91 lea r9,[rbp-8] ; lea r8,[rbp-0x60]   THE POINT (8 bytes)
//        0xC0C769 / 0xC0CC99 lea rdx,[rbp-0x58] ; mov rcx,rax ; call 0xAA0F00 / 0xAA1850 (.xtls 0x9FA5090)
constexpr uintptr_t kS2958 = 0xC0C761, kS2909 = 0xC0CC91;
constexpr uint8_t kSChangeBytes[] = {0x4C, 0x8D, 0x4D, 0xF8, 0x4C, 0x8D, 0x45, 0xA0,
                                     0x48, 0x8D, 0x55, 0xA8, 0x48, 0x8B, 0xC8, 0xE8};
constexpr uint8_t kSChangeFrame[] = {0x48, 0x8D, 0xAC, 0x24, 0xB0, 0xEF, 0xFF, 0xFF};  // 0xC0C400 / 0xC0C930 lea rbp,[rsp-0x1050]
constexpr uint8_t kSChangeKey[] = {0x48, 0x8B, 0x45, 0xA0, 0x48, 0x89, 0x45, 0xA0};
constexpr uint8_t kS2958Find[] = {0x44, 0x8B, 0x85, 0xA8, 0x10, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x08, 0x49, 0x8B, 0xCC, 0xE8,
                                  0x16, 0xA1, 0xC9, 0xFF, 0x90, 0x80, 0x7D, 0x18, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x7D, 0x10};
constexpr uint8_t kS2909Find[] = {0x44, 0x8B, 0x85, 0xA8, 0x10, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x08, 0x49, 0x8B, 0xCC, 0xE8,
                                  0xE6, 0x9B, 0xC9, 0xFF, 0x90, 0x80, 0x7D, 0x18, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x7D, 0x10};
constexpr uint8_t kSChangeVf48[] = {0x48, 0x8B, 0x4D, 0xB8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};
constexpr uint8_t kS2958Use[] = {0x48, 0x8D, 0x55, 0xA8, 0x48, 0x8B, 0xC8, 0xE8, 0x8B, 0x47, 0xE9, 0xFF};  // 0xC0C769
constexpr uint8_t kS2909Use[] = {0x48, 0x8D, 0x55, 0xA8, 0x48, 0x8B, 0xC8, 0xE8, 0xAB, 0x4B, 0xE9, 0xFF};  // 0xC0CC99
// The schedule container and the stage (p8-impl-horarios-x.md §5; gsr::SchedCensus).
constexpr uint32_t kMgr_Sched = 0x148, kSched_Vec = 0x18, kSched_Count = 0x20;
constexpr uint32_t kStage_Mgr = 0x28, kStage_Key = 0x30, kStage_Active = 0x178, kStage_Nodes = 0x138,
                   kStage_NodeCount = 0x140, kNodeStride = 0x168, kNode_Npc = 0x28;
constexpr uint32_t kComp_Stage = 0x318, kComp_Wait = 0x3D9;

// The field each handler's vf48 ran on: the frame slot of its `mov rcx,[rbp-N] ; mov rax,[rcx] ; call [rax+0x48]`
// (kVf48_* above, verified at install): 2661 [rbp-0x40], 2981 [rbp-0x38], 2810 [rbp-0x48], 2322 [rbp-0x58],
// 2524 [rbp-0x48]; nothing writes it between that call and the point.
constexpr uint32_t kFieldSlot[gsr::kPoints] = {0x40, 0x38, 0x48, 0x58, 0x48};

constexpr uintptr_t kVtStageManager = 0x55C9720;  // pa::ClientSequencerStageManager (RTTI)
constexpr uintptr_t kVtSeqPlayComp = 0x55BEE78;   // pa::ClientSequencerPlayDataActorComponent (RTTI)

// Structure offsets (guest_stage_diag.cpp; p8-s1-escenas-npc.md §2.1).
constexpr uint32_t kActor_Key = 0x60, kActor_Comps = 0x68, kComps_Seq = 0xA8, kSeqComp_Mgr = 0x18, kComps_Play = 0xB0;
constexpr uint32_t kMgr_Actor = 0x18, kMgr_Ready = 0x231, kMgr_Count = 0x174, kMgr_Created = 0x17C;
constexpr uint32_t kMgr_List1B0 = 0x1B0, kMgr_List1C0 = 0x1C0;  // lists {ptr, u32 count @+8}
constexpr uint32_t kActor_State = 0x5E, kActor_C2 = 0xC2, kActor_CF = 0xCF;
constexpr uint32_t kActor_Info = 0x88;  // [[actor+0x88]+1] = the actor type (3 = NPC; guest_sched_bind.cpp)
constexpr uint32_t kComp_Owner = 0x2D8, kComp_Key = 0x2E0;
// guest_seq_play G5 (p8-xtls-lectura.md §2): the login flag comp+0x3D8, its link comp+0x320, the parent actor+0xAC.
constexpr uint32_t kComp_Flag = 0x3D8, kComp_Link = 0x320, kActor_Parent = 0xAC;
// X's lists {ptr, u32 n @+8}: +0x1D0 (count +0x1D8); the live scenes vector +0x28 (count +0x30, 0xAA43C7);
// 0xAA3E70's engage queue +0x190 (count +0x194, 0xAA3F3D).
constexpr uint32_t kMgr_N1D0 = 0x1D8, kMgr_NLive = 0x30, kMgr_NEngage = 0x194;
constexpr uint32_t kWrap_Raw = 0x18;
constexpr size_t kHeader = 5;
constexpr uint16_t kOpMainPlayerDataStartAck = 2756;

// The client actor table (game/actor_lookup.cpp's replica, with this file's SEH reads: the 2322 point
// only has the key).
constexpr uint32_t kManager_Table = 0x08, kTable_BucketCount = 0x88, kTable_Buckets = 0x98, kTable_Nodes = 0xA0;
constexpr uint32_t kBucketStride = 0x100, kBucketMaxEntries = (0x100 - 8) / 8, kNode_Key = 0x04, kNode_Actor = 0x08;

// ---------------------------------------------------------------- the points (build 1.0.0.3527, .rsrc)
//
// Read with capstone on the installed PE, 2026-11-05 (every RVA below is this build's). Only the four sequencer points:
// the 2524 and the schedule points (kS*, kP2524) stay refused on this build. No other module hooks them; a sweep of each
// RUNTIME_FUNCTION and a rel32 scan of the whole PE find no branch into the patched bytes. RAX = the manager vf48 returned
// at all four, as in 2976. What moved:
//   2661 0xD33880: 0xD338A4 mov r12,r8 (the wrapper) but 0xD33CD5 / 0xD33CDC overwrite r12 and r13 before the point; the
//        wrapper is still r8's home [rbp+0x100] (0xD33B70 reloads it from there; nothing else writes it on this path).
//        0xD33CC9 movzx r14d,byte [rbp+0x108] (the kind: R14B, not BL); 0xD33D24 vf48 on [rbp-0x28];
//        0xD33D2E cmp r14b,4 ; je 0xD33D7B   THE POINT (6 bytes, two whole instructions)
//        0xD33D7B lea r9,[rbp-0x80] ; lea r8,[rbp+0x10] ; lea rdx,[rbp+0x100] ; mov rcx,rax ; call 0xBA7D00
//   2981 0xD35330: r13 = the raw packet from 0xD3535D, never written again before the point; the wrapper is gone (r14 is
//        overwritten at 0xD357FE and its home [rbp+0xA0] is reused by the binding loop at 0xD35696), so the actor is the
//        handler's own lookup 0xD357B4: found = byte [rbp+0x30], actor = [rbp+0x28]; 0xD3584A vf48 on [rbp-0x10];
//        0xD35854 lea rcx,[rbp-0x80] ; mov [rsp+0x30],rcx   THE POINT (9 bytes) ... 0xD35879 mov rcx,rax ; call 0xBA9870
//   2810 0xD33FA0: every slot +0x10: key [rbp+0x88], found [rbp+0x10], actor [rbp+8], u64 [rbp-0x48], u32 [rbp-0x50];
//        0xD3421B vf48 on [rbp-0x38]; 0xD34225 movzx ecx,byte [rbp+0x80]   THE POINT (7 bytes) ... 0xD3423C mov rcx,rax
//   2322 0xC9C9B0: r14 = the raw packet from 0xC9C9D8, never written again; found [rbp+8], actor [rbp]; 0xC9CB91 vf48 on
//        [rbp-0x48]; 0xC9CB9B mov byte [rax+0x259],2   THE POINT (7 bytes); 0xC9CBA2 loads RAX anew
constexpr uintptr_t kP2661_3527 = 0xD33D2E, kP2981_3527 = 0xD35854, kP2810_3527 = 0xD34225, kP2322_3527 = 0xC9CB9B;
constexpr uint8_t kP2661B_3527[] = {0x41, 0x80, 0xFE, 0x04, 0x74, 0x47, 0x48, 0x8D, 0x05, 0xB5, 0x3F, 0xC2, 0x04, 0x48, 0x89, 0x44};
constexpr uint8_t kFrame2661_3527[] = {0x48, 0x8D, 0xAC, 0x24, 0x50, 0xFF, 0xFF, 0xFF};        // 0xD33895
constexpr uint8_t kKind2661_3527[] = {0x44, 0x0F, 0xB6, 0xB5, 0x08, 0x01, 0x00, 0x00};         // 0xD33CC9
constexpr uint8_t kActor2661_3527[] = {0x4D, 0x89, 0x34, 0x24};                                // 0xD33CC5 mov [r12],r14
constexpr uint8_t kVf48_2661_3527[] = {0x48, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xD33D24
constexpr uint8_t kHome2661_3527[] = {0x4C, 0x89, 0x44, 0x24, 0x18};                           // 0xD33885 mov [rsp+0x18],r8
constexpr uint8_t kWrap2661_3527[] = {0x4D, 0x8B, 0xE0};                                       // 0xD338A4 mov r12,r8
constexpr uint8_t kP2981B_3527[] = {0x48, 0x8D, 0x4D, 0x80, 0x48, 0x89, 0x4C, 0x24, 0x30, 0x48, 0x8D, 0x4D, 0xD0, 0x48, 0x89, 0x4C};
constexpr uint8_t kFrame2981_3527[] = {0x48, 0x8D, 0x6C, 0x24, 0xB0};                          // 0xD35345
constexpr uint8_t kRaw2981_3527[] = {0x4D, 0x8B, 0x68, 0x18};                                  // 0xD3535D
constexpr uint8_t kFind2981_3527[] = {0x44, 0x8B, 0x45, 0xC0, 0x48, 0x8D, 0x55, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0xEC, 0xA0,
                                      0xC5, 0xFF, 0x90, 0x80, 0x7D, 0x30, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x7D, 0x28};  // 0xD357B4
constexpr uint8_t kVf48_2981_3527[] = {0x48, 0x8B, 0x4D, 0xF0, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xD3584A
constexpr uint8_t kP2810B_3527[] = {0x0F, 0xB6, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x88, 0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x4D, 0xB0, 0x4C};
constexpr uint8_t kFrame2810_3527[] = {0x48, 0x8D, 0x6C, 0x24, 0xD0};                          // 0xD33FB0
constexpr uint8_t kFind2810_3527[] = {0x44, 0x8B, 0x85, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x00, 0x48, 0x8B, 0xCE, 0xE8,
                                      0x14, 0xB7, 0xC5, 0xFF, 0x90, 0x80, 0x7D, 0x10, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0x08};  // 0xD34189
constexpr uint8_t kVf48_2810_3527[] = {0x48, 0x8B, 0x4D, 0xC8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xD3421B
constexpr uint8_t kSeq2810_3527[] = {0x4C, 0x8D, 0x4D, 0xB0, 0x4C, 0x8B, 0x45, 0xB8};          // 0xD34230 lea r9 ; mov r8
constexpr uint8_t kP2322B_3527[] = {0xC6, 0x80, 0x59, 0x02, 0x00, 0x00, 0x02, 0x48, 0x8D, 0x05, 0x57, 0xB9, 0x02, 0x05};
constexpr uint8_t kFrame2322_3527[] = {0x48, 0x8D, 0x6C, 0x24, 0xD0};                          // 0xC9C9C0
constexpr uint8_t kRaw2322_3527[] = {0x49, 0x8B, 0xF8, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF1, 0x45, 0x33,
                                     0xFF, 0x4D, 0x8B, 0x70, 0x18, 0x41, 0x0F, 0xB7, 0x4E, 0x03};  // 0xC9C9CC
constexpr uint8_t kFind2322_3527[] = {0x48, 0x8D, 0x55, 0xF8, 0x48, 0x8B, 0xCE, 0xE8, 0x9A, 0x2D, 0xCF, 0xFF,
                                      0x90, 0x80, 0x7D, 0x08, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0x00};  // 0xC9CB0A
constexpr uint8_t kVf48_2322_3527[] = {0x48, 0x8B, 0x4D, 0xB8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};  // 0xC9CB91
constexpr uint32_t kFieldSlot3527[gsr::kPoints] = {0x28, 0x10, 0x38, 0x48, 0};
// pa::ClientSequencerStageManager and pa::ClientSequencerPlayDataActorComponent (rtti_3527.json).
constexpr uintptr_t kVtStageManager3527 = 0x59572E0, kVtSeqPlayComp3527 = 0x594D930;
// Build 3576 (static, 2026-11-06 evening; not yet run): the four handlers moved as whole functions by +0x420, every point
// and context array is at old + 0x420 with the same bytes but for the relative fields below (tools/porting/
// port_module.py); the frames and the manager's fields are 3527's (g_3527 stays the layout flag, g_3576 the addresses).
constexpr uintptr_t kP2661_3576 = 0xD3414E, kP2981_3576 = 0xD35C74, kP2810_3576 = 0xD34645, kP2322_3576 = 0xC9CFBB;
constexpr uintptr_t kVtStageManager3576 = 0x5959438, kVtSeqPlayComp3576 = 0x594FAF0;  // vtable_map_3549_3576.json
constexpr uint8_t kP2661B_3576[] = {0x41, 0x80, 0xFE, 0x04, 0x74, 0x47, 0x48, 0x8D, 0x05, 0x95, 0x59, 0xC2, 0x04, 0x48, 0x89, 0x44};
constexpr uint8_t kFind2981_3576[] = {0x44, 0x8B, 0x45, 0xC0, 0x48, 0x8D, 0x55, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0x3C, 0xA0,
                                      0xC5, 0xFF, 0x90, 0x80, 0x7D, 0x30, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x7D, 0x28};
constexpr uint8_t kFind2810_3576[] = {0x44, 0x8B, 0x85, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x00, 0x48, 0x8B, 0xCE, 0xE8,
                                      0x64, 0xB6, 0xC5, 0xFF, 0x90, 0x80, 0x7D, 0x10, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0x08};
constexpr uint8_t kFind2322_3576[] = {0x48, 0x8D, 0x55, 0xF8, 0x48, 0x8B, 0xCE, 0xE8, 0xEA, 0x2C, 0xCF, 0xFF,
                                      0x90, 0x80, 0x7D, 0x08, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0x00};
constexpr uint8_t kP2322B_3576[] = {0xC6, 0x80, 0x59, 0x02, 0x00, 0x00, 0x02, 0x48, 0x8D, 0x05, 0xA7, 0xD4, 0x02, 0x05};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the four handlers moved as whole functions with 3527's .pdata sizes.
// 2661 [0xD6C750,0xD6CE61), 2810 [0xD6CE70,0xD6D2B4) and 2981 [0xD6E200,0xD6E99A) by +0x38ED0 from 3527 (kP2661B_3527,
// kP2810B_3527, kP2981B_3527 and kFind2981_3527 are anchors of tools/porting/data/anchors_3663.json, each unique);
// 2322 [0xCD5450,0xCD57B5) by +0x38AA0 (its frame, raw-packet and vf48 arrays identical there; the find with the same
// lookup 0x9BE640 as the other three). Every context array is 3527's at old + that shift, identical but for the rel32s
// below. The 2322 point is NOT byte-identical: the manager's ready byte moved +0x259 -> +0x261 (`mov byte [rax+0x261],2`,
// the only such instruction in the code; 0xBDA308 / 0xBDA383 compare it with 2 / 3). The frames (every rbp slot read in
// guest_seq_route_hook and kFieldSlot3527) are 3527's: the arrays that define them are identical. No branch lands in
// any of the four patches (rel8 sweep of each function, rel32 scan of both code sections).
constexpr uintptr_t kP2661_3663 = 0xD6CBFE, kP2981_3663 = 0xD6E724, kP2810_3663 = 0xD6D0F5, kP2322_3663 = 0xCD563B;
// pa::ClientSequencerStageManager / pa::ClientSequencerPlayDataActorComponent (vtable_map_3576_3663.json, rtti_3663.json).
constexpr uintptr_t kVtStageManager3663 = 0x59D57E8, kVtSeqPlayComp3663 = 0x59CB770;
constexpr uint8_t kP2661B_3663[] = {0x41, 0x80, 0xFE, 0x04, 0x74, 0x47, 0x48, 0x8D, 0x05, 0x85, 0x85, 0xC6, 0x04, 0x48, 0x89, 0x44};
constexpr uint8_t kFind2981_3663[] = {0x44, 0x8B, 0x45, 0xC0, 0x48, 0x8D, 0x55, 0x20, 0x49, 0x8B, 0xCF, 0xE8, 0xAC, 0xFF,
                                      0xC4, 0xFF, 0x90, 0x80, 0x7D, 0x30, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x7D, 0x28};
constexpr uint8_t kFind2810_3663[] = {0x44, 0x8B, 0x85, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x00, 0x48, 0x8B, 0xCE, 0xE8,
                                      0xD4, 0x15, 0xC5, 0xFF, 0x90, 0x80, 0x7D, 0x10, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0x08};
constexpr uint8_t kFind2322_3663[] = {0x48, 0x8D, 0x55, 0xF8, 0x48, 0x8B, 0xCE, 0xE8, 0x8A, 0x90, 0xCE, 0xFF,
                                      0x90, 0x80, 0x7D, 0x08, 0x00, 0x74, 0x29, 0x48, 0x8B, 0x75, 0x00};
constexpr uint8_t kP2322B_3663[] = {0xC6, 0x80, 0x61, 0x02, 0x00, 0x00, 0x02, 0x48, 0x8D, 0x05, 0x1F, 0x05, 0x07, 0x05};

// The manager's fields this module reads, per build. 3527 [V capstone]: the marker +0x259 (0xBA2FEB, 0xC9CB9B); 0xBA21F0
// (2976's 0xA97300) returns at once while the vector {+0x1B8, u32 +0x1C0} (0xBA88D0: stages by id) holds anything, which is
// what 2976's +0x174 did (0xBA2256, and 0xBA2FF8 in the start check); its three lists are {+0x1C8, n +0x1D0}, {+0x1D8, n
// +0x1E0} (played one per call at 0xBA2776 in state 3) and {+0x1E8, n +0x1F0} (2976's +0x1B0 / +0x1C0 / +0x1D0: 0xBA22B8,
// 0xBA22F8, 0xBA2381). created and the engage queue are only logged and were not re-derived: 0 = not read.
struct MgrOff {
    uint32_t ready, count, created, list1b0, list1c0, n1d0, engage;
};
constexpr MgrOff kMgrOff2976{kMgr_Ready, kMgr_Count, kMgr_Created, kMgr_List1B0, kMgr_List1C0, kMgr_N1D0, kMgr_NEngage};
constexpr MgrOff kMgrOff3527{0x259, 0x1C0, 0, 0x1C8, 0x1D8, 0x1F0, 0};
// Build 1.0.0.3663 (static, 2026-11-13; never run): every one of these fields moved +8. 0xBDA180 (3527's 0xBA21F0, called by
// the tick 0xBD8000 = 3527's 0xBA0080) tests the vector count +0x1C8 (0xBDA1E6), empties the lists {+0x1D0, n +0x1D8} and
// {+0x1F0, n +0x1F8} (0xBDA248..0xBDA2B4), plays {+0x1E0, n +0x1E8} in state 3 (0xBDA705..0xBDA740) and compares the
// ready byte +0x261 with 2 / 3 (0xBDA308, 0xBDA383, 0xBDA705); the 2322 handler writes +0x261 (kP2322B_3663).
constexpr MgrOff kMgrOff3663{0x261, 0x1C8, 0, 0x1D0, 0x1E0, 0x1F8, 0};

enum class How : uint8_t { None, Own, StageDiag, P8Probe, NotWanted };
const char* how_name(How h) {
    switch (h) {
        case How::Own: return "own hook";
        case How::StageDiag: return "guest_stage_diag's hook";
        case How::P8Probe: return "P8Probe's hook";
        case How::NotWanted: return "not wanted: guest_seq_play_live=0";
        default: return "not hooked";
    }
}

uintptr_t g_base = 0;
// The build, its world slot and the 2661's prefix: written by guest_seq_route_start before any hook or thread.
bool g_3527 = false;  // 3527's layout (3527, 3549, 3576 and 3663: the same handler frames)
bool g_3576 = false;  // 3576's addresses
bool g_3663 = false;  // 3663's addresses (and its manager fields, kMgrOff3663)
uintptr_t g_world_slot = off::kWorldSystemSlot;
size_t g_prefix = osq::kPreparePrefix;
const MgrOff* g_mo = &kMgrOff2976;
uintptr_t vt_mgr() noexcept {
    return g_3663 ? kVtStageManager3663 : g_3576 ? kVtStageManager3576 : g_3527 ? kVtStageManager3527 : kVtStageManager;
}
std::atomic<bool> g_started{false};         // guest_seq_route is probe or 1
std::atomic<bool> g_thread_started{false};  // the install thread (guest_seq_route or guest_sched_route)
std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_point_on[gsr::kPoints] = {};
std::atomic<uint8_t> g_how[gsr::kPoints] = {};
SafetyHookMid g_hooks[gsr::kPoints];
std::atomic<uint32_t> g_own_key{0};
std::atomic<uint64_t> g_own_epoch{~0ull};  // the connection epoch g_own_key was learnt in
std::atomic<bool> g_want_2524{false};       // guest_seq_play (probe or 1) with guest_seq_play_live=1
std::atomic<uint64_t> g_refused[gsr::kPoints] = {};
// The 2322 write of a refused packet lands here (+0x231), never in a manager of the game.
alignas(64) uint8_t g_sink[0x400] = {};
std::atomic<uint64_t> g_verdicts[gsr::kPoints][static_cast<size_t>(gsr::Verdict::Count)] = {};
std::atomic<uint64_t> g_gate_drop[gsr::kPoints] = {}, g_gate_pass_foreign[gsr::kPoints] = {};
std::string g_watch_text;  // the ini's list (install thread / tick thread: written before the thread starts)
// Session 9 (p8-impl-escenas-play.md §15): guest_seq_route_deny, read-only after guest_seq_route_start; the
// resource of each 2661 that came (routing hooks only: the game's main thread).
gsr::DenyList<32> g_deny;
gsr::SeqResources<256> g_seq_res;
// Review 7: g_seq_res is plain memory for the routing hooks, which all run on the game's main thread (0xAD2380 ->
// 0xAD246A call 0x35D0C0 -> 0x35D2A0 -> the Troc handlers; session 9: 907/907 GuestStage hook lines on T15980 and
// "routing hooks on another thread 0" in every GuestSeqPlay summary). Enforced: the first hook's thread owns it; a
// hook on any other thread neither reads nor writes it (counted).
std::atomic<uint32_t> g_res_tid{0};
std::atomic<uint64_t> g_res_foreign{0};
bool res_thread_ok() noexcept {
    const uint32_t me = GetCurrentThreadId();
    uint32_t owner = g_res_tid.load(std::memory_order_relaxed);
    if (!owner && g_res_tid.compare_exchange_strong(owner, me, std::memory_order_relaxed)) return true;
    if (owner == me || g_res_tid.load(std::memory_order_relaxed) == me) return true;
    g_res_foreign.fetch_add(1, std::memory_order_relaxed);
    return false;
}
std::atomic<uint64_t> g_branch2{0};
// Session 10, review of b728ec7: the inner hook in 0xA9E480 (0xA9E55B) for the 2524s routed into X.
//   0xA9E48F mov [rsp+8],rcx ; 0xA9E494 push x7 ; lea rbp,[rsp-0x1820]   -> G = [rbp+0x1860] (rcx's home)
//   0xA9E4B4 mov r12d,r9d (the branch) ; mov rdi,rcx                       r12 not written before the point
//   0xA9E50C mov rcx,rdi ; call 0x1F6C190 (lookup, [G+8]'s lock taken at 0xA9E4FA)
//   0xA9E534 mov rbx,[r15] ; mov [rsp+0x58],rbx ; mov [r15],r13 ; mov rdi,rbx   (rdi = the instance or 0)
//   0xA9E55B mov r15d,0x1fd ; test rdi,rdi ; jne 0xA9E5BF   THE POINT (6 bytes, one instruction, no branch into
//            0xA9E55C..0xA9E565; rdi := 0 takes the native not-found path 0xA9E566: lock released, then
//            0xA9ECBC: the inline vector [rbp+0x870] (not grown yet) and the reference [rsp+0x58] released)
//   0xA9E62E mov r13,[rsi+0x58] ; ... mov rax,[r13+0x38] ; mov rdx,[rax+8] ; mov rax,[rdx+r12*8]  (what it guards)
constexpr uintptr_t kP2524Lookup = 0xA9E55B;
constexpr uint8_t kLookupBytes[] = {0x41, 0xBF, 0xFD, 0x01, 0x00, 0x00, 0x48, 0x85, 0xFF, 0x75, 0x59};
constexpr uint8_t kLookupHomeBytes[] = {0x48, 0x89, 0x4C, 0x24, 0x08};                         // 0xA9E48F
constexpr uint8_t kLookupFrameBytes[] = {0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41,
                                         0x57, 0x48, 0x8D, 0xAC, 0x24, 0xE0, 0xE7, 0xFF, 0xFF};  // 0xA9E494
constexpr uint8_t kLookupBranchBytes[] = {0x45, 0x8B, 0xE1, 0x48, 0x8B, 0xF9};                 // 0xA9E4B4
constexpr uint8_t kLookupCallBytes[] = {0x48, 0x8B, 0xCF, 0xE8, 0x7C, 0xDC, 0x4C, 0x01};        // 0xA9E50C
constexpr uint8_t kLookupInstBytes[] = {0x49, 0x8B, 0x1F, 0x48, 0x89, 0x5C, 0x24,
                                        0x58, 0x4D, 0x89, 0x2F, 0x48, 0x8B, 0xFB};               // 0xA9E534
constexpr uint8_t kLookupUseBytes[] = {0x4C, 0x8B, 0x6E, 0x58, 0x4C, 0x89, 0x6C, 0x24, 0x60, 0x49, 0x8B,
                                       0x45, 0x38, 0x48, 0x8B, 0x50, 0x08, 0x4A, 0x8B, 0x04, 0xE2};  // 0xA9E62E
constexpr uint8_t kLookupMissBytes[] = {0x48, 0x8B, 0x5C, 0x24, 0x40};                          // 0xA9E566
constexpr uint32_t kLookupHomeG = 0x1860;  // [rbp+0x1860] = G
SafetyHookMid g_lookup_hook;
std::atomic<bool> g_lookup_on{false};
thread_local uintptr_t t_2524_x = 0;  // set by the routing hook for the call it sends to X, cleared by the inner one
std::atomic<uint64_t> g_2524_scene[5] = {};  // per gsr::Ready2524 (Ok, NotPlaying, NoInstance, SceneNotLoaded, BadBranch)
std::atomic<uint64_t> g_2524_mismatch{0};
// Session 13 (p8-impl-secuenciador-bodyanim.md): guest_seq_route_2524 and its allow list (read-only after start), the
// classes of the 2524s judged (routing hooks), and for the WORLD ones the inner check's verdict on X's instance as a
// read-only peek (the probe: the call itself goes to M, so 0xA9E55B never sees X).
std::atomic<uint8_t> g_mode_2524{0};  // gsr::Mode2524
gsr::DenyList<32> g_allow_2524;
std::atomic<uint64_t> g_2524_class[static_cast<size_t>(gsr::World2524::Count)] = {};
std::atomic<uint64_t> g_2524_peek[5] = {};      // WORLD ones with X readable, per gsr::Ready2524
std::atomic<uint64_t> g_2524_peek_pre[5] = {};  // WORLD ones, gsr::pre_2524 (X / this client at 3, X not loading)
std::atomic<uint64_t> g_2524_name_via[3] = {};  // per gsr::NameVia, every 2524 classified
std::atomic<uint64_t> g_2524_world_route{0}, g_2524_world_would{0};

// guest_sched_route (p8-impl-horarios-x.md): its own mode, points, verdicts and ledger (the routing hooks only, under
// res_thread_ok: the game's main thread).
std::atomic<uint8_t> g_sched_mode{0};
std::atomic<bool> g_sched_on[gsr::kSchedPoints] = {};
SafetyHookMid g_sched_hooks[gsr::kSchedPoints];
std::atomic<uint64_t> g_sched_verdicts[gsr::kSchedPoints][static_cast<size_t>(gsr::Verdict::Count)] = {};
gsr::SchedLedger<512> g_sched_ledger;
std::atomic<uint32_t> g_sched_char{0};     // the last character a schedule packet was (or would be) routed for
std::atomic<uint64_t> g_sched_ledger_x{0}, g_sched_ledger_m{0}, g_sched_evicted{0};  // snapshots for the tick
std::atomic<uint64_t> g_sched_key_probe{0};  // follow-ups of an unknown key judged by X's container
// p8-impl-horarios-x.md §10: a refused 2335 gets RAX := this (0xA9FEE0 returns at once when [G+0x148] == 0, 0xA9FF0C).
alignas(64) uint8_t g_sched_sink[0x200] = {};
std::atomic<uint64_t> g_sched_refused{0};
// P8 re-entry (s25/reentrada.md §1.4): the ledger's scene keys -> managers belong to one remote conversation (an X of
// the previous one under the host character's reused key 0xA0100001 must never be a follow-up's target). The routing
// hooks' thread only (res_thread_ok), at its next schedule packet.
uint32_t g_sched_conv = 0;
void sched_conversation_check() noexcept {
    const uint32_t conv = guest_conversation_id();
    if (conv == g_sched_conv) return;
    g_sched_conv = conv;
    if (conv < 2) return;
    const size_t dropped = g_sched_ledger.clear();
    try {
        log::info("GuestSchedRoute: remote conversation {} (re-entry): the schedule ledger starts again ({} key(s) of the "
                  "previous conversation dropped); the X registry stays (it keeps the stage teardown guard for the old "
                  "X managers)",
                  conv, dropped);
    } catch (...) {
    }
}
// §11: the X managers stages were routed into (with their character), and the stage teardown guard.
// P8 re-entry: NOT cleared per conversation: a stage of an X of the previous conversation may still be torn down
// later, and x_gone() (the character's live X != this one) keeps recognizing it.
gsr::XRegistry<8> g_xreg;
SafetyHookMid g_teardown_hook;
std::atomic<bool> g_teardown_on{false};
std::atomic<uint64_t> g_teardown[static_cast<size_t>(gsr::Teardown::Count)] = {};
using FakeVf = void(__fastcall*)(void*, void*, uint8_t);
void __fastcall fake_vf(void*, void*, uint8_t) noexcept {}
FakeVf g_fake_vt[16] = {fake_vf, fake_vf, fake_vf, fake_vf, fake_vf, fake_vf, fake_vf, fake_vf,
                        fake_vf, fake_vf, fake_vf, fake_vf, fake_vf, fake_vf, fake_vf, fake_vf};
struct FakeManager {
    FakeVf* vt;
    uint8_t rest[0x200];
};
alignas(64) FakeManager g_fake_mgr = {g_fake_vt, {}};  // a do-nothing manager: only its vf12 (+0x60) is ever called

// Session 13: the G5 watch list published for the hooks of guest_bodyanim_diag (any thread): append-only, written by
// watch() (the start, then the diagnostics thread only), read lock-free.
constexpr size_t kMaxWatch = 64;
std::atomic<uint32_t> g_watch_pub[kMaxWatch] = {};
std::atomic<uint32_t> g_watch_pub_n{0};

enum Kind : uint16_t { kERoute, kEGate, kEBranch, kEScene, kESched, kETear, kKindCount };
p::EventRing<1024> g_ring;
p::WindowLimiter g_lim[kKindCount] = {{128, 5'000'000}, {64, 5'000'000}, {64, 5'000'000}, {64, 5'000'000},
                                      {128, 5'000'000}, {32, 5'000'000}};
std::atomic<uint64_t> g_limited{0}, g_lost{0}, g_lines{0};
constexpr uint64_t kMaxLines = 3000;

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
// guest_sched_route: the schedule container [G+0x148] = C, its stage vector {C+0x18, u32 C+0x20} (0xA9FEE0 pushes
// there, 0x43C930 walks it comparing stage+0x30). Bounded SEH reads, no lock: the routing hooks run on the thread
// that mutates it (the Ack handlers), the census on the diagnostics thread only counts.
uint32_t sched_count(uintptr_t g) noexcept {
    const uintptr_t c = g ? rdp(g + kMgr_Sched) : 0;
    return c ? rdv<uint32_t>(c + kSched_Count) : 0;
}
bool sched_has(uintptr_t g, uint64_t key) noexcept {
    const uintptr_t c = g ? rdp(g + kMgr_Sched) : 0;
    const uintptr_t vec = c ? rdp(c + kSched_Vec) : 0;
    const uint32_t n = c ? rdv<uint32_t>(c + kSched_Count) : 0;
    if (!vec || !key || n > gsr::kMaxCensusStages) return false;
    for (uint32_t i = 0; i < n; ++i) {
        const uintptr_t s = rdp(vec + static_cast<uintptr_t>(i) * 8);
        if (s && rdv<uint64_t>(s + kStage_Key) == key) return true;
    }
    return false;
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
// §11: the stage manager the character has now (0 if the character is not in this client's actor table).
uintptr_t live_x_of(uint32_t owner) noexcept {
    const uintptr_t a = owner ? find_actor(owner) : 0;
    return a && key_of(a) == owner ? manager_of(a) : 0;
}
bool x_gone(uintptr_t x) noexcept {
    const uint32_t owner = g_xreg.owner_of(x);
    return owner && live_x_of(owner) != x;
}

// Session 13 (guest_seq_route_2524): X's instance of `seq`, read-only, no lock (gsr::kMgr_MapNodes; the 2524 hook runs
// on the game's main thread, as the Ack handlers that change X's map). Only for the classification and the probe's
// peek: a torn read gives a wrong log / a "name unknown" (fail closed), never a routed 2524 by itself (the routed call
// is still checked by the game's own lookup under its lock, 0xA9E55B).
uintptr_t peek_instance(uintptr_t x, uint64_t seq) noexcept {
    if (!x || !seq) return 0;
    const uint32_t n = rdv<uint32_t>(x + gsr::kMgr_MapCount);
    const uintptr_t nodes = rdp(x + gsr::kMgr_MapNodes);
    if (!nodes || n > gsr::kMaxMapNodes) return 0;
    for (uint32_t i = 0; i < n; ++i) {
        const uintptr_t node = rdp(nodes + static_cast<uintptr_t>(i) * 8);
        if (!node || rdv<uint64_t>(node + gsr::kMapNode_Seq) != seq) continue;
        const uintptr_t inst = rdp(node + gsr::kMapNode_Inst);
        return inst && rdv<uint8_t>(inst + gsr::kInst_Dead, 1) == 0 ? inst : 0;
    }
    return 0;
}
// The scene's name (3 raw qwords) from the object among {inst, [inst+0x58]} whose +0x30 is the sequencer id.
gsr::NameVia read_scene_name(uintptr_t inst, uint64_t seq, uint64_t q[3]) noexcept {
    q[0] = q[1] = q[2] = 0;
    if (!inst || !seq) return gsr::NameVia::None;
    const uintptr_t cand[2] = {inst, rdp(inst + gsr::kInst_StageOff)};
    for (int c = 0; c < 2; ++c) {
        const uintptr_t o = cand[c];
        if (!o || rdv<uint64_t>(o + gsr::kStage_KeyOff) != seq) continue;
        const uintptr_t info = rdp(o + gsr::kStage_InfoOff);
        const uintptr_t name = info ? rdp(info + gsr::kInfo_NameOff) : 0;
        if (!name) continue;
        for (int k = 0; k < 3 && rd(name + 8 * k, q[k]); ++k) {
        }
        return c == 0 ? gsr::NameVia::Instance : gsr::NameVia::Stage58;
    }
    return gsr::NameVia::None;
}

// Session 10, review of b728ec7: the scene behind the instance 0xA9E480 found for a 2524 routed into X, read
// under [G+8]'s lock by the inner hook at 0xA9E55B (gsr::scene_2524). Instance +0x58 = its stage, stage +0x38 =
// the scene data, data +8 = the branch table {ptr, u32 count @+0x10, u32 capacity @+0x14} [E layout].
constexpr uint32_t kInst_Stage = 0x58, kStage_Data = 0x38, kData_Branches = 0x08, kData_Count = 0x10,
                   kData_Capacity = 0x14;

// X's state in one u64: +0x231 | loading tasks +0x174 << 8 | created +0x17C << 24 | list +0x1C0 n << 40 | list +0x1B0 n << 52.
uint64_t mgr_state(uintptr_t m) noexcept {
    if (!m) return ~0ull;
    const MgrOff& o = *g_mo;
    const uint64_t ready = rdv<uint8_t>(m + o.ready, 0xFF);
    const uint64_t count = rdv<uint32_t>(m + o.count) & 0xFFFF;
    const uint64_t created = o.created ? rdv<uint32_t>(m + o.created) & 0xFFFF : 0;
    const uint64_t l1c0 = rdv<uint32_t>(m + o.list1c0 + 8) & 0xFFF;
    const uint64_t l1b0 = rdv<uint32_t>(m + o.list1b0 + 8) & 0xFFF;
    return ready | count << 8 | created << 24 | l1c0 << 40 | l1b0 << 52;
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

// ---------------------------------------------------------------- lines (diagnostics thread)

std::string mgr_text(uint64_t s) {
    if (s == ~0ull) return "unreadable";
    return std::format("+0x231 {}, loading tasks +0x174 {}, created {}, preload list +0x1C0 {}, list +0x1B0 {}", s & 0xFF,
                       (s >> 8) & 0xFFFF, (s >> 24) & 0xFFFF, (s >> 40) & 0xFFF, (s >> 52) & 0xFFF);
}

std::map<uint32_t, gsr::NpcState> g_watch;   // tick thread only: watched actor -> last state
struct XSeen {
    gsr::XState s;
    uintptr_t x = 0;
    bool logged = false;
};
std::map<uint32_t, XSeen> g_x_state;         // tick thread only: routed character -> its X's last state
uint64_t g_ticks = 0;

void watch(uint32_t key) {
    if (key && (key >> 28) == 0xB && g_watch.size() < kMaxWatch && !g_watch.count(key)) {
        g_watch[key] = gsr::NpcState{};
        const uint32_t n = g_watch_pub_n.load(std::memory_order_relaxed);
        if (n < kMaxWatch) {
            g_watch_pub[n].store(key, std::memory_order_relaxed);
            g_watch_pub_n.store(n + 1, std::memory_order_release);
        }
    }
}

// Session 13: the 2524s judged under guest_seq_route_2524 (tick thread only), per sequencer, for the summary: the
// list of scenes to put on guest_seq_route_2524_allow.
struct Scene2524Seen {
    uint32_t resource = 0;
    uint8_t cls = 0;     // gsr::World2524 (the last)
    uint8_t verdict = 0; // gsr::Verdict (the last)
    std::string name;
    uint64_t n = 0;
};
std::map<uint64_t, Scene2524Seen> g_2524_seen;
constexpr size_t kMax2524Seen = 96;

std::string line_of(const p::Event& e) {
    const uint64_t* v = e.v;
    const std::string when = p8_when(e.qpc_us);
    if (e.kind == kEGate) {
        return std::format("GuestSeqRoute [gate] {} T{} | a {} naming character 0x{:08X} (this client's own 0x{:08X}; "
                           "0 = not known yet on this connection) NOT delivered: the routing of that opcode is not on "
                           "({}), or this client's own character is not known yet | it would land in this client's own "
                           "manager M",
                           when, e.tid, v[0], static_cast<uint32_t>(v[1]), static_cast<uint32_t>(v[2]),
                           how_name(static_cast<How>(v[3])));
    }
    if (e.kind == kEScene) {
        static constexpr const char* kWhy[] = {"OK: the game goes on", "?", "the game did not find it (its own path)",
                                               "scene data NOT LOADED -> taken the game's not-found path",
                                               "branch NOT USABLE -> taken the game's not-found path"};
        const auto r = static_cast<size_t>(v[0]);
        return std::format("GuestSeqRoute [2524 scene check 0xA9E55B] {} T{} | X 0x{:X}: instance 0x{:X}, stage +0x58 "
                           "0x{:X}, data +0x38 0x{:X}, branches +8 0x{:X} (count {}, capacity {}), branch {} -> entry "
                           "0x{:X} | {}",
                           when, e.tid, v[1], v[2], v[3], v[4], v[5], static_cast<uint32_t>(v[6]),
                           static_cast<uint32_t>(v[6] >> 32), v[7], v[8], r < 5 ? kWhy[r] : "?");
    }
    if (e.kind == kETear) {
        return std::format("GuestSchedRoute [stage teardown 0x43B0B6] {} T{} | stage 0x{:X} (scene 0x{:X}) of X 0x{:X} "
                           "(character 0x{:08X}, now its X is 0x{:X}) | X GONE: its vf12 call sent to the mod's "
                           "do-nothing manager (the stage outlived X through an NPC's comp+0x318)",
                           when, e.tid, v[1], v[4], v[2], static_cast<uint32_t>(v[3]), v[5]);
    }
    if (e.kind == kESched) {
        const auto sp = static_cast<gsr::SchedPoint>(v[0] & 0xFF);
        const auto verdict = static_cast<gsr::Verdict>((v[0] >> 8) & 0xFF);
        const auto where = static_cast<gsr::SchedWhere>((v[0] >> 16) & 0xFF);
        const std::string res = sp == gsr::SchedPoint::P2126
                                    ? std::string()
                                    : std::format(", resource 0x{:08X}", static_cast<uint32_t>(v[3]));
        const std::string kind = sp == gsr::SchedPoint::P2335 ? std::format(", kind {}", v[3] >> 32) : std::string();
        const std::string ledger =
            sp == gsr::SchedPoint::P2335
                ? std::format("ledger: noted in {}", gsr::sched_where_name(where))
                : std::format("ledger: its 2335 went to {}{}", gsr::sched_where_name(where),
                              v[7] ? std::format(" 0x{:X}", v[7]) : std::string());
        return std::format("GuestSchedRoute [{}] {} T{} | scene 0x{:X} of character 0x{:08X}{}{} | vf48 gave M 0x{:X} "
                           "(character 0x{:08X}, +0x148 {} stages) | its own manager X 0x{:X} (+0x148 {} stages) | {} | "
                           "{}",
                           gsr::sched_point_name(sp), p8_when(e.qpc_us), e.tid, v[2], static_cast<uint32_t>(v[1]), res,
                           kind, v[4], static_cast<uint32_t>(v[1] >> 32), static_cast<uint32_t>(v[6] >> 32), v[5],
                           static_cast<uint32_t>(v[6]), ledger,
                           std::string(gsr::verdict_name(verdict)) +
                               (gsr::sched_refused(verdict) && g_sched_mode.load() != 2 ? " (probe: not applied)" : ""));
    }
    const auto point = static_cast<Point>(v[0] & 0xFF);
    const auto verdict = static_cast<gsr::Verdict>((v[0] >> 8) & 0xFF);
    const auto actor_key = static_cast<uint32_t>(v[1]), m_key = static_cast<uint32_t>(v[1] >> 32);
    std::string binds;
    for (size_t i = 6; i < 10 && point == Point::P2661; ++i) {
        for (int h = 0; h < 2; ++h) {
            const auto k = static_cast<uint32_t>(h ? v[i] >> 32 : v[i]);
            if (k) binds += std::format(" 0x{:08X}", k);
        }
    }
    // Session 13: a 2524 judged under guest_seq_route_2524 (v[6] bit 63): its scene's class and the inner check's
    // verdict on X's instance (read-only peek, 0xFF = X not readable / not known).
    std::string world;
    if (point == Point::P2524 && (v[6] >> 63)) {
        static constexpr const char* kPeek[] = {"OK", "X / this client not playing (pre_2524)", "no instance in X",
                                                "scene NOT LOADED in X", "bad branch"};
        char name[32];
        gsr::scene_name(v + 7, 3, name, sizeof name);
        const auto cls = static_cast<gsr::World2524>(v[6] & 0xFF);
        const auto peek = static_cast<uint32_t>((v[6] >> 8) & 0xFF);
        world = std::format(" | scene class: {} | binds {} (NPC {}, in this client {}, type 3 {}) | name '{}' (via {}) | "
                            "inner check on X (read-only peek, as 0xA9E55B would judge it): {}",
                            gsr::world_2524_name(cls), (v[6] >> 48) & 0x7F, (v[6] >> 24) & 0xFF, (v[6] >> 32) & 0xFF,
                            (v[6] >> 40) & 0xFF, name,
                            gsr::name_via_name(static_cast<gsr::NameVia>((v[6] >> 16) & 0xFF)),
                            peek < 5 ? kPeek[peek] : "not read (X not known / not a stage manager)");
    }
    const uint16_t op = gsr::kPointOp[static_cast<size_t>(point)];
    const std::string res = v[11] >> 32 ? std::format(" | resource 0x{:08X}", static_cast<uint32_t>(v[11])) : "";
    if (e.kind == kEBranch) {
        return std::format("GuestSeqRoute [2981 state {} into X] {} T{} | sequencer 0x{:X} of character 0x{:08X}{} | "
                           "a branch of the host's scene now runs on THIS client in X (session 9: branch 2 of 0x213, "
                           "resource 0x8CD771B1, reloaded this client's field): if a field load or a camera/control "
                           "change follows, add this resource to guest_seq_route_deny",
                           v[3], when, e.tid, v[2], actor_key, res.empty() ? " | resource unknown (2661 not seen)" : res);
    }
    return std::format("GuestSeqRoute [{}] {} T{} | {} | packet actor 0x{:08X} | vf48 gave M 0x{:X} (character "
                       "0x{:08X}) | its own manager X 0x{:X}: {} | {}{}{}{}",
                       gsr::point_name(point), when, e.tid,
                       gsd::corr_token(op, actor_key, v[2], static_cast<uint32_t>(v[3])), actor_key, v[4], m_key, v[5],
                       mgr_text(v[10]),
                       std::string(gsr::verdict_name(verdict)) +
                           ((v[0] >> 16) & 1 ? (point == Point::P2661 ? " -> REFUSED: kind set to 0, nothing created in M"
                                                                      : " -> REFUSED: the +0x231 write went to the mod's sink")
                                              : ""),
                       binds.empty() ? std::string() : " | binds (watched for G5):" + binds, res, world);
}

std::string allow_text() {
    std::string t;
    for (size_t i = 0; i < g_allow_2524.n; ++i) t += std::format(" 0x{:08X}", g_allow_2524.res[i]);
    return t.empty() ? " none (every WORLD scene)" : t;
}

// What the 2524 point does (the install line).
std::string text_2524(gsr::Mode mode) {
    const auto m = static_cast<gsr::Mode2524>(g_mode_2524.load());
    if (m == gsr::Mode2524::Legacy) {
        if (!g_want_2524.load()) return "not routed (guest_seq_play_live=0, guest_seq_route_2524=0)";
        return mode == gsr::Mode::On ? "routed to an X guest_seq_play ticks, with guest_seq_play=1 and its live skip hook "
                                       "in (never gated: it arrives natively)"
                                     : "decided only (guest_seq_route=probe)";
    }
    const bool ticks = guest_seq_play_ticks();
    if (m == gsr::Mode2524::Probe || mode != gsr::Mode::On || !ticks) {
        return std::format("guest_seq_route_2524=PROBE: every 2524 classified (WORLD = binds a type-3 NPC present here, "
                           "name read, not cd_seq_funcnpc_*, not denied) and judged, the WORLD ones with a read-only "
                           "peek of the inner check 0xA9E55B on X; NOTHING routed{} | allow list:{}",
                           m != gsr::Mode2524::On  ? ""
                           : mode != gsr::Mode::On ? " (guest_seq_route is not 1)"
                                                   : " (guest_seq_play is not 1: nothing ticks X)",
                           allow_text());
    }
    return std::format("guest_seq_route_2524=1: ONLY the WORLD scenes' 2524 routed into X (and only an X guest_seq_play "
                       "ticks, X and this client at 3, the inner check 0xA9E55B under the game's lock), independent of "
                       "guest_seq_play_live | allow list:{}",
                       allow_text());
}

std::string deny_text() {
    std::string t;
    for (size_t i = 0; i < g_deny.n; ++i) t += std::format(" 0x{:08X}", g_deny.res[i]);
    return t.empty() ? " none" : t;
}

std::string npc_text(const gsr::NpcState& s) {
    if (!s.exists) return "NOT in this client";
    std::string parent;
    if (s.parent) {
        parent = s.parent_found ? std::format(", parent +0xAC 0x{:08X} (its +0x3D8 {})", s.parent, s.parent_flag)
                                : std::format(", parent +0xAC 0x{:08X} (not in this client)", s.parent);
    }
    // guest_sched_route: what vf13 bound (comp+0x318) and that stage's state.
    const std::string bound =
        !s.comp ? std::string()
        : s.stage ? std::format(", bound stage +0x318 0x{:X} (scene +0x30 0x{:X}, active +0x178 {}, manager +0x28 0x{:X}), "
                                "+0x3D9 {}",
                                s.stage, s.stage_key, s.stage_active, s.stage_mgr, s.flag_3d9)
                  : std::format(", NOT bound (+0x318 0), +0x3D9 {}", s.flag_3d9);
    return std::format("exists, +0x5E 0x{:02X}, +0xC2 {}, +0xCF {}{}{}{}", s.state, s.ready_c2, s.ready_cf,
                       s.comp ? std::format(", sequencer component: owner 0x{:08X}, scene +0x2E0 0x{:X}, +0x320 0x{:X}, "
                                            "+0x3D8 {} (1 = +0xCF waits for its scene to start)",
                                            s.owner, s.scene, s.link_320, s.flag_3d8)
                              : std::string(", no sequencer component"),
                       bound, parent);
}

uintptr_t play_comp(uintptr_t a) {
    const uintptr_t comps = a ? rdp(a + kActor_Comps) : 0;
    const uintptr_t comp = comps ? rdp(comps + kComps_Play) : 0;
    const uintptr_t vt = g_3663   ? kVtSeqPlayComp3663
                         : g_3576 ? kVtSeqPlayComp3576
                         : g_3527 ? kVtSeqPlayComp3527
                                  : kVtSeqPlayComp;
    return comp && rdp(comp) == g_base + vt ? comp : 0;
}

gsr::NpcState read_npc(uint32_t key) {
    gsr::NpcState s;
    const uintptr_t a = find_actor(key);
    if (!a || key_of(a) != key) return s;
    s.exists = true;
    s.state = rdv<uint8_t>(a + kActor_State);
    s.ready_c2 = rdv<uint8_t>(a + kActor_C2);
    s.ready_cf = rdv<uint8_t>(a + kActor_CF);
    if (const uintptr_t comp = play_comp(a)) {
        // G5 only (log lines). 3527: the scene key is still +0x2E0 (0x6C05D4 cmp [rdx+0x2E0],[stage+0x30]), the later flags
        // moved by +8 (vf13 0xAF2E62 writes +0x3E1, 2976's +0x3D9; +0x3D8 and +0x320 by the same shift [E]); the schedule
        // stage's are not re-derived, so comp+0x318 stays out there.
        const uint32_t cs = g_3527 ? 8 : 0;
        s.comp = true;
        s.owner = rdv<uint32_t>(comp + kComp_Owner);
        s.scene = rdv<uint64_t>(comp + kComp_Key);
        s.flag_3d8 = rdv<uint8_t>(comp + kComp_Flag + cs);
        s.link_320 = rdv<uint64_t>(comp + kComp_Link + cs);
        // vf13 0x9ED290: comp+0x318 = the stage found in [X+0x148] (0x9ED4C6..), +0x3D9 = 1 if its +0x178 was 0
        // (0x9ED55B / 0x9ED568).
        s.stage = g_3527 ? 0 : rdp(comp + kComp_Stage);
        s.flag_3d9 = rdv<uint8_t>(comp + kComp_Wait + cs);
        if (s.stage) {
            s.stage_active = rdv<uint8_t>(s.stage + kStage_Active);
            s.stage_key = rdv<uint64_t>(s.stage + kStage_Key);
            s.stage_mgr = rdp(s.stage + kStage_Mgr);
        }
    }
    s.parent = rdv<uint32_t>(a + kActor_Parent);
    if (s.parent) {
        const uintptr_t pa = find_actor(s.parent);
        if (pa && key_of(pa) == s.parent) {
            s.parent_found = true;
            if (const uintptr_t pc = play_comp(pa)) s.parent_flag = rdv<uint8_t>(pc + kComp_Flag);
        }
    }
    return s;
}

gsr::XState read_x(uintptr_t x) {
    gsr::XState s;
    if (!x || rdp(x) != g_base + vt_mgr()) return s;
    const MgrOff& o = *g_mo;
    s.readable = true;
    s.ready = rdv<uint8_t>(x + o.ready, 0xFF);
    s.loading = rdv<uint32_t>(x + o.count);
    s.created = o.created ? rdv<uint32_t>(x + o.created) : 0;
    s.n1b0 = rdv<uint32_t>(x + o.list1b0 + 8);
    s.n1c0 = rdv<uint32_t>(x + o.list1c0 + 8);
    s.n1d0 = rdv<uint32_t>(x + o.n1d0);
    s.live = rdv<uint32_t>(x + kMgr_NLive);
    s.engage = o.engage ? rdv<uint32_t>(x + o.engage) : 0;
    return s;
}

std::string x_text(const gsr::XState& s) {
    if (!s.readable) return "unreadable (no X, or not a ClientSequencerStageManager)";
    return std::format("+0x231 {}, loading +0x174 {}, created +0x17C {}, lists +0x1B0 {} / +0x1C0 {} / +0x1D0 {}, live "
                       "scenes +0x28 {}, engage queue +0x190 {}",
                       s.ready, s.loading, s.created, s.n1b0, s.n1c0, s.n1d0, s.live, s.engage);
}

void g5() {
    for (auto& [key, last] : g_watch) {
        const gsr::NpcState now = read_npc(key);
        if (now == last && g_ticks % 60 != 1) continue;
        const bool changed = !(now == last);
        last = now;
        if (g_lines.fetch_add(1) < kMaxLines) {
            log::info("GuestSeqRoute [G5 actor] 0x{:08X}: {}{}", key, npc_text(now), changed ? "" : " (unchanged)");
        }
    }
    // With guest_seq_play the X lines also repeat every 30 s unchanged (its effect is what they show).
    const uint64_t repeat = guest_seq_play_wanted() ? 6 : 60;
    for (auto& [key, last] : g_x_state) {
        const uintptr_t a = find_actor(key);
        const uintptr_t x = a ? manager_of(a) : 0;
        const gsr::XState s = read_x(x);
        const bool changed = !last.logged || !(s == last.s) || x != last.x;
        if (!changed && g_ticks % repeat != 1) continue;
        last.s = s;
        last.x = x;
        last.logged = true;
        if (g_lines.fetch_add(1) < kMaxLines) {
            log::info("GuestSeqRoute [G5 X] character 0x{:08X}: X 0x{:X} {}{}", key, x, x_text(s),
                      changed ? "" : " (unchanged)");
        }
    }
}

// Session 13: the guest_seq_route_2524 summary (every 60 s): classes, the WORLD ones' verdicts and peeks, and the
// scenes seen (sequencer, 2661 resource, name, class, last verdict, count).
std::string summary_2524() {
    std::string cls;
    for (size_t k = 0; k < static_cast<size_t>(gsr::World2524::Count); ++k) {
        if (const uint64_t n = g_2524_class[k].load()) {
            cls += std::format(" {} x{};", gsr::world_2524_name(static_cast<gsr::World2524>(k)), n);
        }
    }
    std::string scenes;
    size_t shown = 0;
    for (const auto& [seq, sc] : g_2524_seen) {
        if (shown++ >= 48) break;
        scenes += std::format(" 0x{:X} res 0x{:08X} '{}' {} [{}] x{};", seq, sc.resource, sc.name,
                              gsr::world_2524_name(static_cast<gsr::World2524>(sc.cls)),
                              gsr::verdict_name(static_cast<gsr::Verdict>(sc.verdict)), sc.n);
    }
    std::string world_res;  // ready to paste into guest_seq_route_2524_allow
    for (const auto& [seq, sc] : g_2524_seen) {
        if (sc.cls != static_cast<uint8_t>(gsr::World2524::World) || !sc.resource) continue;
        const std::string r = std::format("{:08X}", sc.resource);
        if (world_res.find(r) == std::string::npos) world_res += (world_res.empty() ? "" : ",") + r;
    }
    const auto m = static_cast<gsr::Mode2524>(g_mode_2524.load());
    return std::format(
        "GuestSeqRoute [2524 world summary] guest_seq_route_2524={} | classes:{} | WORLD: ROUTED {}, WOULD route {} | "
        "WORLD pre_2524 (X / this client at 3, X not loading): ok {}, not playing {} | WORLD inner check on X (read-only "
        "peek, what 0xA9E55B would say): ok {}, no instance {}, NOT LOADED {}, bad branch {} | the inner hook (routed "
        "calls, under the lock): ok {}, NOT LOADED {}, bad branch {} | name via inst {}, via [inst+0x58] {}, none {} | "
        "allow list:{} | WORLD resources seen (for guest_seq_route_2524_allow): {} | scenes ({}):{}",
        m == gsr::Mode2524::On ? "1" : m == gsr::Mode2524::Probe ? "probe" : "0", cls.empty() ? " none" : cls,
        g_2524_world_route.load(), g_2524_world_would.load(), g_2524_peek_pre[0].load(), g_2524_peek_pre[1].load(),
        g_2524_peek[0].load(), g_2524_peek[2].load(), g_2524_peek[3].load(), g_2524_peek[4].load(),
        g_2524_scene[0].load(), g_2524_scene[3].load(), g_2524_scene[4].load(),
        g_2524_name_via[static_cast<size_t>(gsr::NameVia::Instance)].load(),
        g_2524_name_via[static_cast<size_t>(gsr::NameVia::Stage58)].load(),
        g_2524_name_via[static_cast<size_t>(gsr::NameVia::None)].load(), allow_text(),
        world_res.empty() ? "none" : world_res, g_2524_seen.size(), scenes.empty() ? " none" : scenes);
}

// ---------------------------------------------------------------- guest_sched_route's census (diagnostics thread)

gsr::SchedCensus census(uintptr_t g, std::vector<uint32_t>* npcs) {
    gsr::SchedCensus c;
    if (!g || rdp(g) != g_base + vt_mgr()) return c;
    const uintptr_t cont = rdp(g + kMgr_Sched);
    const uintptr_t vec = cont ? rdp(cont + kSched_Vec) : 0;
    const uint32_t n = cont ? rdv<uint32_t>(cont + kSched_Count) : 0;
    if (!cont || (n && !vec) || n > gsr::kMaxCensusStages) return c;
    c.readable = true;
    for (uint32_t i = 0; i < n; ++i) {
        const uintptr_t s = rdp(vec + static_cast<uintptr_t>(i) * 8);
        if (!s) continue;
        const uintptr_t nodes = rdp(s + kStage_Nodes);
        uint32_t nn = rdv<uint32_t>(s + kStage_NodeCount), bound = 0;
        if (!nodes || nn > gsr::kMaxCensusNodes) nn = 0;
        for (uint32_t j = 0; j < nn; ++j) {
            const uint32_t k = rdv<uint32_t>(nodes + static_cast<uintptr_t>(j) * kNodeStride + kNode_Npc);
            if (!k) continue;
            ++bound;
            if (npcs && npcs->size() < 16) npcs->push_back(k);
        }
        gsr::census_add_stage(c, rdv<uint8_t>(s + kStage_Active) != 0, rdp(s + kStage_Mgr) == g, nn, bound);
    }
    return c;
}

std::string census_text(const gsr::SchedCensus& c) {
    if (!c.readable) return "unreadable";
    return std::format("{} stages ({} active +0x178, {} of another manager), {} nodes, {} bound to an NPC", c.stages,
                       c.active, c.other_mgr, c.nodes, c.bound);
}

struct SchedTally {
    gsr::SchedCensus x, m;
    uintptr_t xg = 0, mg = 0;
    uint32_t x_char = 0;
    uint32_t comps = 0, bound = 0, active = 0, waiting = 0, in_x = 0, in_m = 0;  // the watched NPCs
    uint32_t orphan = 0;  // §11: watched NPCs bound to a stage whose +0x28 is a routed X that is no longer live
    uint32_t dead_x = 0;  // §11: routed X managers whose character no longer has them
    bool operator==(const SchedTally&) const = default;
};
// §11: the routed character's X as the last census saw it (the tick thread only).
struct XSeenSched {
    uint32_t chr = 0;
    uintptr_t x = 0;
    uint32_t stages = 0, bound_nodes = 0;
};
XSeenSched g_sched_last_x;
SchedTally g_sched_tally;  // tick thread only
bool g_sched_tally_logged = false;
size_t g_sched_auto_watch = 0;
constexpr size_t kMaxSchedAutoWatch = 16;

void sched_census_tick() {
    SchedTally t;
    t.x_char = g_sched_char.load(std::memory_order_relaxed);
    const uintptr_t xa = t.x_char ? find_actor(t.x_char) : 0;
    t.xg = xa && key_of(xa) == t.x_char ? manager_of(xa) : 0;
    const uint32_t own = guest_seq_route_own_key();
    const uintptr_t ma = own ? find_actor(own) : 0;
    t.mg = ma && key_of(ma) == own ? manager_of(ma) : 0;
    std::vector<uint32_t> npcs;
    t.x = census(t.xg, g_sched_auto_watch < kMaxSchedAutoWatch ? &npcs : nullptr);
    t.m = census(t.mg, nullptr);
    for (uint32_t k : npcs) {  // a few NPCs bound in X: their comp+0x318 / +0x178 in the G5 lines
        if (g_sched_auto_watch >= kMaxSchedAutoWatch || g_watch.count(k)) continue;
        const size_t before = g_watch.size();
        watch(k);
        g_sched_auto_watch += g_watch.size() != before;
    }
    for (const auto& [key, s] : g_watch) {
        if (!s.comp) continue;
        ++t.comps;
        if (!s.stage) continue;
        ++t.bound;
        t.active += s.stage_active != 0;
        t.waiting += s.flag_3d9 != 0;
        t.in_x += t.xg && s.stage_mgr == t.xg;
        t.in_m += t.mg && s.stage_mgr == t.mg;
        t.orphan += x_gone(static_cast<uintptr_t>(s.stage_mgr));
    }
    for (size_t k = 0; k < 8; ++k) {
        const uintptr_t x = static_cast<uintptr_t>(g_xreg.x_at(k));
        if (x && live_x_of(g_xreg.owner_at(k)) != x) ++t.dead_x;
    }
    // §11: the host character left this client's actor table (or got another X) while its X held stages.
    const XSeenSched& last = g_sched_last_x;
    if (last.x && last.stages && last.chr == t.x_char && t.xg != last.x && g_lines.fetch_add(1) < kMaxLines) {
        log::warn("GuestSchedRoute [X gone] character 0x{:08X} {} while its X 0x{:X} held {} stage(s) ({} node(s) with "
                  "an NPC) | NPCs still holding such a stage (comp+0x318) keep it alive past X: their last release runs "
                  "0x43AE50 again, whose [stage+0x28]->vf12 the teardown guard (0x43B0B6, {}) sends to the mod's "
                  "do-nothing manager | watched NPCs bound to a gone X now: {}",
                  last.chr, xa ? std::format("got another X 0x{:X}", t.xg) : std::string("left this client's actor table"),
                  last.x, last.stages, last.bound_nodes, g_teardown_on.load() ? "in" : "NOT installed", t.orphan);
    }
    g_sched_last_x = XSeenSched{t.x_char, t.xg, t.x.stages, t.x.bound};
    const bool changed = !g_sched_tally_logged || !(t == g_sched_tally);
    g_sched_tally = t;
    if (!changed && g_ticks % 12 != 1) return;
    g_sched_tally_logged = true;
    if (g_lines.fetch_add(1) < kMaxLines) {
        log::info("GuestSchedRoute [census] X 0x{:X} (character 0x{:08X}): {} | M 0x{:X} (this client's 0x{:08X}): {} | "
                  "watched NPCs with a sequencer component {}: bound (comp+0x318) {}, its stage active {}, waiting "
                  "(+0x3D9) {}, stage in X {}, in M {}, stage of a GONE X {} | routed X managers gone {}{}",
                  t.xg, t.x_char, census_text(t.x), t.mg, own, census_text(t.m), t.comps, t.bound, t.active, t.waiting,
                  t.in_x, t.in_m, t.orphan, t.dead_x, changed ? "" : " (unchanged)");
    }
}

// ---------------------------------------------------------------- install

struct Ctx {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
};
struct PointDef {
    Point point;
    uintptr_t rva;
    uint32_t patch;
    std::span<const uint8_t> bytes;
    std::vector<Ctx> ctx;  // all the code its reads rely on (the owner's and this module's)
    safetyhook::MidHookFn fn;
};

// The inner 2524 hook (0xA9E55B, inside 0xA9E480, [G+8]'s lock held): only for the call the routing hook sent to X.
void on_2524_lookup(safetyhook::Context& ctx) noexcept {
    const uintptr_t x = t_2524_x;
    if (!x) return;  // the game's own 2524s (M)
    t_2524_x = 0;
    const uintptr_t g = rdp(ctx.rbp + kLookupHomeG);
    if (g != x) {
        g_2524_mismatch.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    gsr::Scene2524 s;
    s.inst = ctx.rdi;
    s.stage = s.inst ? rdp(s.inst + kInst_Stage) : 0;
    s.data = s.stage ? rdp(s.stage + kStage_Data) : 0;
    s.branches = s.data ? rdp(s.data + kData_Branches) : 0;
    s.count = s.data ? rdv<uint32_t>(s.data + kData_Count) : 0;
    s.capacity = s.data ? rdv<uint32_t>(s.data + kData_Capacity) : 0;
    s.branch = static_cast<uint32_t>(ctx.r12);
    s.entry = s.branches && s.branch < s.count && s.count <= gsr::kMaxBranchTable
                  ? rdp(s.branches + static_cast<uintptr_t>(s.branch) * 8)
                  : 0;
    const gsr::Ready2524 r = gsr::scene_2524(s);
    g_2524_scene[static_cast<size_t>(r)].fetch_add(1, std::memory_order_relaxed);
    if (r != gsr::Ready2524::Ok && r != gsr::Ready2524::NoInstance) ctx.rdi = 0;  // the game's not-found path
    if (r != gsr::Ready2524::Ok || g_2524_scene[0].load(std::memory_order_relaxed) <= 8) {
        p::Event e;
        e.v[0] = static_cast<uint64_t>(r);
        e.v[1] = x;
        e.v[2] = s.inst;
        e.v[3] = s.stage;
        e.v[4] = s.data;
        e.v[5] = s.branches;
        e.v[6] = s.count | static_cast<uint64_t>(s.capacity) << 32;
        e.v[7] = s.branch;
        e.v[8] = s.entry;
        emit(kEScene, e);
    }
}

// §11, the stage teardown guard: 0x43AE50 (a ClientNPCScheduleStage's teardown: the container's destructor 0x43C253,
// the delete 0x890EF99, the stage's own destructor 0x88D35B3 on its last release, 0x43B794, 0x43CAA5), any thread.
//   0x43B0A3 lea rdx,[rdi+0x58] ; mov r15d,-1 ; cmp [rdx],r15d ; je 0x43B0BF   (no wake spot: no call)
//   0x43B0B2 mov rcx,[rdi+0x28]                                                 (the stage's manager G)
//   0x43B0B6 mov rax,[rcx] ; mov r8b,6   THE POINT (6 bytes)   0x43B0BC call [rax+0x60]  (G->vf12(&stage+0x58, 6))
// rdi = the stage all along (0x43AE71 mov rdi,rcx; reloaded from its home at 0x43B08F). When G is an X the routing
// put stages into and its character no longer has it, RCX := the mod's do-nothing manager: no read of a freed X.
void on_stage_teardown(safetyhook::Context& ctx) noexcept {
    const uintptr_t x = ctx.rcx;
    const uint32_t owner = g_xreg.owner_of(x);
    if (!owner) {
        g_teardown[static_cast<size_t>(gsr::Teardown::NotOurs)].fetch_add(1, std::memory_order_relaxed);
        return;  // M's, a native one, or a manager the routing never used: untouched
    }
    const uintptr_t live = live_x_of(owner);
    const gsr::Teardown d = gsr::teardown_guard(x, rdp(ctx.rdi + kStage_Mgr), owner, live);
    g_teardown[static_cast<size_t>(d)].fetch_add(1, std::memory_order_relaxed);
    if (d != gsr::Teardown::Redirect) return;
    ctx.rcx = reinterpret_cast<uintptr_t>(&g_fake_mgr);
    p::Event e;
    e.v[1] = ctx.rdi;
    e.v[2] = x;
    e.v[3] = owner;
    e.v[4] = rdv<uint64_t>(ctx.rdi + kStage_Key);
    e.v[5] = live;
    emit(kETear, e);
}

void on_p2661(safetyhook::Context& ctx) noexcept { guest_seq_route_hook(Point::P2661, ctx); }
void on_p2981(safetyhook::Context& ctx) noexcept { guest_seq_route_hook(Point::P2981, ctx); }
void on_p2810(safetyhook::Context& ctx) noexcept { guest_seq_route_hook(Point::P2810, ctx); }
void on_p2322(safetyhook::Context& ctx) noexcept { guest_seq_route_hook(Point::P2322, ctx); }
void on_p2524(safetyhook::Context& ctx) noexcept { guest_seq_route_hook(Point::P2524, ctx); }
void on_s2335(safetyhook::Context& ctx) noexcept { guest_sched_route_hook(gsr::SchedPoint::P2335, ctx); }
void on_s2126(safetyhook::Context& ctx) noexcept { guest_sched_route_hook(gsr::SchedPoint::P2126, ctx); }
void on_s2958(safetyhook::Context& ctx) noexcept { guest_sched_route_hook(gsr::SchedPoint::P2958, ctx); }
void on_s2909(safetyhook::Context& ctx) noexcept { guest_sched_route_hook(gsr::SchedPoint::P2909, ctx); }

struct SchedDef {
    gsr::SchedPoint point;
    uintptr_t rva;
    uint32_t patch;
    std::span<const uint8_t> bytes;
    std::vector<Ctx> ctx;
    safetyhook::MidHookFn fn;
};
std::vector<SchedDef> sched_points() {
    return {
        {gsr::SchedPoint::P2335, kS2335, 9, kS2335Bytes,
         {{0xC0AFD0, kS2335Frame}, {0xC0AFE5, kS2335Wrap}, {0xC0B242, kS2335Key}, {0xC0B50A, kS2335Find},
          {0xC0B55E, kS2335Kind}, {0xC0B5B7, kS2335Vf48}, {0xC0B612, kS2335Use}},
         on_s2335},
        {gsr::SchedPoint::P2126, kS2126, 11, kS2126Bytes,
         {{0xC0B850, kS2126Frame}, {0xC0B98E, kS2126Key}, {0xC0B9B5, kS2126Find}, {0xC0BA44, kS2126Vf48}},
         on_s2126},
        {gsr::SchedPoint::P2958, kS2958, 8, kSChangeBytes,
         {{0xC0C400, kSChangeFrame}, {0xC0C5BA, kSChangeKey}, {0xC0C6B7, kS2958Find}, {0xC0C757, kSChangeVf48},
          {0xC0C769, kS2958Use}},
         on_s2958},
        {gsr::SchedPoint::P2909, kS2909, 8, kSChangeBytes,
         {{0xC0C930, kSChangeFrame}, {0xC0CAEA, kSChangeKey}, {0xC0CBE7, kS2909Find}, {0xC0CC87, kSChangeVf48},
          {0xC0CC99, kS2909Use}},
         on_s2909},
    };
}

std::vector<PointDef> points_3527() {
    return {
        {Point::P2661, kP2661_3527, 6, kP2661B_3527,
         {{0xD33895, kFrame2661_3527}, {0xD33CC9, kKind2661_3527}, {0xD33CC5, kActor2661_3527},
          {0xD33D24, kVf48_2661_3527}, {0xD33885, kHome2661_3527}, {0xD338A4, kWrap2661_3527}},
         on_p2661},
        {Point::P2981, kP2981_3527, 9, kP2981B_3527,
         {{0xD35345, kFrame2981_3527}, {0xD3535D, kRaw2981_3527}, {0xD357B4, kFind2981_3527}, {0xD3584A, kVf48_2981_3527}},
         on_p2981},
        {Point::P2810, kP2810_3527, 7, kP2810B_3527,
         {{0xD33FB0, kFrame2810_3527}, {0xD34189, kFind2810_3527}, {0xD3421B, kVf48_2810_3527}, {0xD34230, kSeq2810_3527}},
         on_p2810},
        {Point::P2322, kP2322_3527, 7, kP2322B_3527,
         {{0xC9C9C0, kFrame2322_3527}, {0xC9C9CC, kRaw2322_3527}, {0xC9CB0A, kFind2322_3527}, {0xC9CB91, kVf48_2322_3527}},
         on_p2322},
    };
}

std::vector<PointDef> points_3576() {
    constexpr uintptr_t d = 0x420;  // every context array of the four handlers (port_module.py)
    return {
        {Point::P2661, kP2661_3576, 6, kP2661B_3576,
         {{0xD33895 + d, kFrame2661_3527}, {0xD33CC9 + d, kKind2661_3527}, {0xD33CC5 + d, kActor2661_3527},
          {0xD33D24 + d, kVf48_2661_3527}, {0xD33885 + d, kHome2661_3527}, {0xD338A4 + d, kWrap2661_3527}},
         on_p2661},
        {Point::P2981, kP2981_3576, 9, kP2981B_3527,
         {{0xD35345 + d, kFrame2981_3527}, {0xD3535D + d, kRaw2981_3527}, {0xD357B4 + d, kFind2981_3576},
          {0xD3584A + d, kVf48_2981_3527}},
         on_p2981},
        {Point::P2810, kP2810_3576, 7, kP2810B_3527,
         {{0xD33FB0 + d, kFrame2810_3527}, {0xD34189 + d, kFind2810_3576}, {0xD3421B + d, kVf48_2810_3527},
          {0xD34230 + d, kSeq2810_3527}},
         on_p2810},
        {Point::P2322, kP2322_3576, 7, kP2322B_3576,
         {{0xC9C9C0 + d, kFrame2322_3527}, {0xC9C9CC + d, kRaw2322_3527}, {0xC9CB0A + d, kFind2322_3576},
          {0xC9CB91 + d, kVf48_2322_3527}},
         on_p2322},
    };
}

// Build 1.0.0.3663 (static): the same contexts as 3527 at old + each handler's shift (see kP2661_3663).
std::vector<PointDef> points_3663() {
    constexpr uintptr_t d = 0x38ED0;  // 2661, 2981, 2810
    constexpr uintptr_t e = 0x38AA0;  // 2322
    return {
        {Point::P2661, kP2661_3663, 6, kP2661B_3663,
         {{0xD33895 + d, kFrame2661_3527}, {0xD33CC9 + d, kKind2661_3527}, {0xD33CC5 + d, kActor2661_3527},
          {0xD33D24 + d, kVf48_2661_3527}, {0xD33885 + d, kHome2661_3527}, {0xD338A4 + d, kWrap2661_3527}},
         on_p2661},
        {Point::P2981, kP2981_3663, 9, kP2981B_3527,
         {{0xD35345 + d, kFrame2981_3527}, {0xD3535D + d, kRaw2981_3527}, {0xD357B4 + d, kFind2981_3663},
          {0xD3584A + d, kVf48_2981_3527}},
         on_p2981},
        {Point::P2810, kP2810_3663, 7, kP2810B_3527,
         {{0xD33FB0 + d, kFrame2810_3527}, {0xD34189 + d, kFind2810_3663}, {0xD3421B + d, kVf48_2810_3527},
          {0xD34230 + d, kSeq2810_3527}},
         on_p2810},
        {Point::P2322, kP2322_3663, 7, kP2322B_3663,
         {{0xC9C9C0 + e, kFrame2322_3527}, {0xC9C9CC + e, kRaw2322_3527}, {0xC9CB0A + e, kFind2322_3663},
          {0xC9CB91 + e, kVf48_2322_3527}},
         on_p2322},
    };
}

std::vector<PointDef> points() {
    if (g_3663) return points_3663();
    if (g_3576) return points_3576();
    if (g_3527) return points_3527();
    return {
        {Point::P2661, kP2661, 5, kP2661Bytes,
         {{0xC05BC0, kFrame2661Bytes}, {0xC060C6, kKind2661Bytes}, {0xC060C2, kActor2661Bytes},
          {0xC06120, kVf48_2661Bytes}, {0xC05BCF, kWrap2661Bytes}},
         on_p2661},
        {Point::P2981, kP2981, 9, kP2981Bytes,
         {{0xC073BC, kWrap2981Bytes}, {0xC076E6, kActor2981Bytes}, {0xC0773F, kVf48_2981Bytes}},
         on_p2981},
        {Point::P2810, kP2810, 8, kP2810Bytes,
         {{0xC06594, kVf48_2810Bytes}, {0xC06340, kFrame2810Bytes}, {0xC06505, kFind2810Bytes},
          {0xC065AA, kSeq2810Bytes}},
         on_p2810},
        {Point::P2322, kP2322, 7, kP2322Bytes,
         {{0xB87A5D, kVf48_2322Bytes}, {0xB878AC, kRaw2322Bytes}, {0xB879D6, kFind2322Bytes}},
         on_p2322},
        {Point::P2524, kP2524, 9, kP2524Bytes,
         {{0xC07D25, kWrap2524Bytes}, {0xC080D1, kFind2524Bytes}, {0xC0810E, kActor2524Bytes},
          {0xC0816E, kVf48_2524Bytes}, {0xC08188, kUse2524Bytes}},
         on_p2524},
    };
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

// What the point's owner module did there (it installs first: this thread waits for it).
How owner_of(Point p, const Config& lc) {
    if (p == Point::P2322) return lc.s2_load_diag ? How::P8Probe : How::None;
    if (p == Point::P2524) return How::None;  // no other module hooks 0xC08178
    return lc.s2_guest_stage_diag ? How::StageDiag : How::None;
}

void install_sched(std::span<const gad::Section> secs) {
    std::string on, refused;
    for (const SchedDef& d : sched_points()) {
        const size_t i = static_cast<size_t>(d.point);
        std::string why;
        for (const Ctx& c : d.ctx) {
            if (!gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
                !bytes_at(c.rva, c.bytes)) {
                why = std::format("the code it reads at exe+0x{:X} ({} bytes) is not build 2976's .rsrc code", c.rva,
                                  c.bytes.size());
                break;
            }
        }
        if (why.empty() && !p8_install_mid(g_base, secs, d.rva, d.patch, d.bytes, d.fn, g_sched_hooks[i],
                                           "GuestSchedRoute", gsr::sched_point_name(d.point))) {
            why = "p8_install_mid refused it (see the line above)";
        }
        g_sched_on[i].store(why.empty(), std::memory_order_release);
        if (why.empty()) {
            on += std::format(" {}", gsr::sched_point_name(d.point));
        } else {
            refused += std::format(" {} ({})", gsr::sched_point_name(d.point), why);
        }
    }
    const auto mode = static_cast<gsr::Mode>(g_sched_mode.load());
    log::info("GuestSchedRoute {} (guest_sched_route): points:{} | REFUSED:{} | a 2335/2126/2958/2909 naming another "
              "character (0xA...) than this client's field owner's goes to THAT character's ClientSequencerStageManager "
              "X (vtable exe+0x{:X}, X+0x148 present) instead of M, where the NPCs' vf13 0x9ED290 looks for it; a "
              "2126/2958/2909 goes where its 2335 went (ledger). Never gated, never refused; nothing written to comp+0x318 "
              "or stage+0x178",
              mode == gsr::Mode::On ? "ON" : "PROBE (decides, never writes RAX)", on.empty() ? " none" : on,
              refused.empty() ? " none" : refused, kVtStageManager);
    // §11: the stage teardown guard (only with guest_sched_route=1: in probe nothing goes into X).
    if (mode == gsr::Mode::On) {
        static constexpr uint8_t kTearBytes[] = {0x48, 0x8B, 0x01, 0x41, 0xB0, 0x06, 0xFF, 0x50,
                                                 0x60, 0x4C, 0x8D, 0xB7, 0x80, 0x01, 0x00, 0x00};  // 0x43B0B6
        static constexpr uint8_t kTearWake[] = {0x48, 0x8D, 0x57, 0x58, 0x41, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                0x44, 0x39, 0x3A, 0x74, 0x0D, 0x48, 0x8B, 0x4F, 0x28};  // 0x43B0A3
        static constexpr uint8_t kTearEntry[] = {0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x89, 0x4C, 0x24, 0x08};  // 0x43AE50
        static constexpr uint8_t kTearRdi[] = {0x48, 0x8B, 0xF9};                                  // 0x43AE71
        static constexpr uint8_t kTearReload[] = {0x48, 0x8B, 0xBD, 0xC0, 0x00, 0x00, 0x00};       // 0x43B08F
        const Ctx tear[] = {{0x43B0A3, kTearWake}, {0x43AE50, kTearEntry}, {0x43AE71, kTearRdi}, {0x43B08F, kTearReload}};
        bool ok = true;
        for (const Ctx& c : tear) {
            ok = ok && gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) &&
                 bytes_at(c.rva, c.bytes);
        }
        ok = ok && p8_install_mid(g_base, secs, 0x43B0B6, 6, kTearBytes, on_stage_teardown, g_teardown_hook,
                                  "GuestSchedRoute", "stage teardown guard in 0x43AE50 0x43B0B6");
        g_teardown_on.store(ok);
        log::info("GuestSchedRoute: stage teardown guard 0x43B0B6 {}: a stage's last release after its X (the host "
                  "character's manager) is gone no longer calls into the freed X (its vf12 goes to a do-nothing "
                  "manager of the mod); other managers untouched",
                  ok ? "in" : "NOT installed (code not build 2976's or refused)");
    }
    // guest_sched_bind (needs guest_sched_route=1 and the 2335 point: it arms the bind after 0xA9FEE0).
    guest_sched_bind_install(g_base, secs,
                             g_sched_on[static_cast<size_t>(gsr::SchedPoint::P2335)].load(std::memory_order_acquire));
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<gad::Section> secs;
    if (g_base != off::kImageBase || !game::safe_read(g_base, &dos, sizeof dos) ||
        !game::safe_read(g_base + dos.e_lfanew, &nt, sizeof nt) || !(game::legacy_layout() || g_3576 || g_3663) ||
        !p8_exe_sections(g_base, secs)) {
        log::error("GuestSeqRoute: unsupported game build or unreadable sections; nothing is routed (the gate drops "
                   "every copy)");
        return 0;
    }
    const Config& lc = loaded_config();
    const std::vector<PointDef> defs = points();
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other guest modules
        uintptr_t world = 0;
        if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
        Sleep(500);
    }
    // guest_sched_route first (its points are this module's own: nobody to wait for).
    if (g_sched_mode.load() != 0) install_sched(secs);
    const auto mode = static_cast<gsr::Mode>(g_mode.load());
    if (mode == gsr::Mode::Off) return 0;  // guest_sched_route alone: no sequencer point
    // The owners first: one address never gets two hooks (up to 5 minutes; they wait for the code too).
    bool diag_settled = !lc.s2_guest_stage_diag, p8_settled = !lc.s2_load_diag;
    for (int i = 0; i < 3000 && !(diag_settled && p8_settled); ++i) {
        diag_settled = diag_settled || guest_stage_diag_settled();
        p8_settled = p8_settled || p8_probes_settled();
        if (!(diag_settled && p8_settled)) Sleep(100);
    }
    std::string on, refused;
    for (const PointDef& d : defs) {
        const size_t i = static_cast<size_t>(d.point);
        const How owner = owner_of(d.point, lc);
        // guest_seq_play_live=0 and guest_seq_route_2524=0: nothing at 0xC08178 (session 13: _2524 installs it alone).
        if (d.point == Point::P2524 &&
            !gsr::want_point_2524(g_want_2524.load(), static_cast<gsr::Mode2524>(g_mode_2524.load()))) {
            g_how[i].store(static_cast<uint8_t>(How::NotWanted));
            g_point_on[i].store(false);
            continue;
        }
        std::string why;
        if (d.point == Point::P2524) {  // the inner check first: no 2524 into X without it
            const Ctx inner[] = {{kP2524Lookup, kLookupBytes},       {0xA9E48F, kLookupHomeBytes},
                                 {0xA9E494, kLookupFrameBytes},      {0xA9E4B4, kLookupBranchBytes},
                                 {0xA9E50C, kLookupCallBytes},       {0xA9E534, kLookupInstBytes},
                                 {0xA9E62E, kLookupUseBytes},        {0xA9E566, kLookupMissBytes}};
            for (const Ctx& c : inner) {
                if (!gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
                    !bytes_at(c.rva, c.bytes)) {
                    why = std::format("the inner check's code at exe+0x{:X} is not build 2976's", c.rva);
                    break;
                }
            }
            if (why.empty() && p8_install_mid(g_base, secs, kP2524Lookup, 6, kLookupBytes, on_2524_lookup,
                                              g_lookup_hook, "GuestSeqRoute", "2524 scene check in 0xA9E480 0xA9E55B")) {
                g_lookup_on.store(true);
            } else if (why.empty()) {
                why = "the inner check 0xA9E55B was refused (see the line above)";
            }
        }
        for (const Ctx& c : d.ctx) {
            if (!gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
                !bytes_at(c.rva, c.bytes)) {
                why = std::format("the code it reads at exe+0x{:X} ({} bytes) is not this build's .rsrc code", c.rva,
                                  c.bytes.size());
                break;
            }
        }
        How how = How::None;
        if (why.empty()) {
            const bool owner_settled = owner == How::P8Probe ? p8_settled : owner == How::StageDiag ? diag_settled : true;
            const bool owner_hooked = owner == How::P8Probe     ? p8_probes_point_hooked(d.rva)
                                      : owner == How::StageDiag ? guest_stage_diag_point_hooked(d.rva)
                                                                : false;
            if (owner_hooked) {
                how = owner;
            } else if (!owner_settled) {
                why = std::format("{} has not finished installing (no second hook at one address)", how_name(owner));
            } else if (p8_install_mid(g_base, secs, d.rva, d.patch, d.bytes, d.fn, g_hooks[i], "GuestSeqRoute",
                                      gsr::point_name(d.point))) {
                how = How::Own;
            } else {
                why = "p8_install_mid refused it (see the line above)";
            }
        }
        g_how[i].store(static_cast<uint8_t>(how));
        g_point_on[i].store(how != How::None);
        if (how != How::None) {
            on += std::format(" {} exe+0x{:X} ({})", gsr::point_name(d.point), d.rva, how_name(how));
        } else {
            refused += std::format(" {} ({})", gsr::point_name(d.point), why);
        }
    }
    log::info("GuestSeqRoute {} (guest_seq_route): points:{} | REFUSED:{} | a 2661/2981/2810/2322 naming another "
              "character (0xA...) than this client's field owner's goes to THAT character's ClientSequencerStageManager "
              "X (vtable exe+0x{:X} checked) instead of M; the delivery gate drops a 2661/2810/2322 naming another "
              "character while its point is not ON | 2524: {} | deny (guest_seq_route_deny: a 2661 with such a resource is "
              "created nowhere, its 2981/2524 stay in M):{} | G5 watch:{}",
              mode == gsr::Mode::On ? "ON" : mode == gsr::Mode::Probe ? "PROBE (decides, never writes RAX)" : "off",
              on.empty() ? " none" : on, refused.empty() ? " none" : refused, vt_mgr(),
              text_2524(mode),
              deny_text(), g_watch_text.empty() ? " (only the routed 2661s' actors)" : " " + g_watch_text);
    return 0;
}

}  // namespace

void guest_seq_route_start(const std::string& mode, const std::string& watch_list, bool want_2524,
                           const std::string& deny_list, const std::string& sched_mode, const std::string& bind_mode,
                           const std::string& route_2524, const std::string& allow_2524) {
    g_3576 = game::current_build() == game::Build::v3576;
    g_3663 = game::current_build() == game::Build::v3663;
    g_3527 = game::current_build() == game::Build::v3527 || g_3576 || g_3663;
    if (g_3527) {
        if (const auto* profile = game::reader_profile()) g_world_slot = profile->world_system;
        if (g_3576) g_world_slot = 0x71C0100;  // core_globals_3576.json (no reader profile for 3576 yet)
        // Build 1.0.0.3663 (static, 2026-11-13; never run): WorldSystem, profile_s2.h's rva3663() (two AOB patterns).
        if (g_3663) g_world_slot = 0x72451C0;
        // 3663: the 2661 handler parses its payload with 3527's code (every fix / context array identical): same prefix.
        g_prefix = osq::kPreparePrefix3527;
        g_mo = g_3663 ? &kMgrOff3663 : &kMgrOff3527;
    }
    bool bad_2524 = false;
    gsr::Mode2524 m2524 = gsr::parse_mode_2524(route_2524, &bad_2524);
    if (bad_2524) log::warn("GuestSeqRoute: guest_seq_route_2524={} is not 0, probe or 1: 0", route_2524);
    if (g_3527) {
        // Not ported to 1.0.0.3527: the 2524 (its point, its inner check 0xA9E55B: the crash of p8-impl-escenas-play.md
        // §16) and the schedule stages. Refused here, so nothing below ever reaches their 2976 addresses.
        if (m2524 != gsr::Mode2524::Legacy || want_2524) {
            log::warn("GuestSeqRoute: guest_seq_route_2524 / guest_seq_play_live are not ported to build 3527: the 2524 "
                      "stays native (M), REFUSED");
        }
        if (gsr::parse_mode(sched_mode) != gsr::Mode::Off) {
            log::warn("GuestSchedRoute: guest_sched_route / guest_sched_bind are not ported to build 3527: REFUSED, off");
        }
        m2524 = gsr::Mode2524::Legacy;
        want_2524 = false;
        g_how[static_cast<size_t>(Point::P2524)].store(static_cast<uint8_t>(How::NotWanted));
    }
    g_mode_2524.store(static_cast<uint8_t>(m2524));
    g_allow_2524 = gsr::DenyList<32>::parse(allow_2524);
    if (!g_allow_2524.bad.empty()) {
        log::warn("GuestSeqRoute: guest_seq_route_2524_allow: '{}' ignored (not hex, zero or over the list's 32)",
                  g_allow_2524.bad);
    }
    bool sched_bad = false;
    const gsr::Mode sm = g_3527 ? gsr::Mode::Off : gsr::parse_mode(sched_mode, &sched_bad);
    if (sched_bad) log::warn("GuestSchedRoute: guest_sched_route={} is not 0, probe or 1: off", sched_mode);
    g_sched_mode.store(static_cast<uint8_t>(sm));
    guest_sched_bind_configure(bind_mode, sm);  // off unless guest_sched_route=1
    g_deny = gsr::DenyList<32>::parse(deny_list);
    if (!g_deny.bad.empty()) log::warn("GuestSeqRoute: guest_seq_route_deny: '{}' ignored (not hex, zero or over the list's 32)", g_deny.bad);
    bool bad = false;
    const gsr::Mode m = gsr::parse_mode(mode, &bad);
    if (bad) log::warn("GuestSeqRoute: guest_seq_route={} is not 0, probe or 1: off", mode);
    g_mode.store(static_cast<uint8_t>(m));
    g_want_2524.store(want_2524);
    const osq::OnlyFilter w = osq::OnlyFilter::parse(watch_list);
    for (uint32_t k : w.keys) {
        watch(k);
        g_watch_text += std::format(" 0x{:08X}", k);
    }
    // guest_seq_route=0: the gate stays (guest_seq_route_gate): nothing routed, copies dropped. The install thread
    // also runs for guest_sched_route alone (then it installs only the schedule points).
    if (m != gsr::Mode::Off) g_started.store(true);
    if (m == gsr::Mode::Off && sm == gsr::Mode::Off) return;
    if (g_thread_started.exchange(true)) return;
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

bool guest_seq_route_wanted() { return g_started.load(); }

void guest_seq_route_hook(Point point, safetyhook::Context& ctx) noexcept {
    const size_t i = static_cast<size_t>(point);
    if (i >= gsr::kPoints || g_mode.load(std::memory_order_relaxed) == 0) return;
    guest_x_context_hook_entry();  // guest_x_veto (review 3): a new handler; no X context survives from before
    gsr::RouteFacts f;
    f.mode = static_cast<gsr::Mode>(g_mode.load(std::memory_order_relaxed));
    // The 2524: guest_seq_route_2524 = 0 keeps the old switch (into X only with guest_seq_play=1 and _live=1); probe
    // decides only; 1 routes the WORLD scenes (session 13, gsr::mode_2524).
    const auto m2524 = static_cast<gsr::Mode2524>(g_mode_2524.load(std::memory_order_relaxed));
    if (point == Point::P2524) {
        f.mode = gsr::mode_2524(f.mode, m2524,
                                m2524 == gsr::Mode2524::Legacy && f.mode == gsr::Mode::On && guest_seq_play_routes_2524(),
                                guest_seq_play_ticks());
    }
    f.point_on = g_point_on[i].load(std::memory_order_acquire);
    if (!f.point_on) return;  // not verified (yet): as without this module
    f.m = ctx.rax;
    f.want_vt = g_base + vt_mgr();
    uintptr_t raw = 0;
    uint64_t seq = 0;
    uint32_t value = 0;
    // The frame slots on 1.0.0.3527: the block of comments above kP2661_3527.
    const uintptr_t rbp = ctx.rbp;
    switch (point) {
        case Point::P2661:
            if (g_3527) {
                const uintptr_t wrap = rdp(rbp + 0x100);  // r8's home; r12 and r13 are gone here
                f.kind_ok = (ctx.r14 & 0xFF) == 4;
                f.actor = rdp(wrap);
                raw = rdp(wrap + kWrap_Raw);
                break;
            }
            f.kind_ok = (ctx.rbx & 0xFF) == 4;
            f.actor = rdp(ctx.r12);
            raw = rdp(ctx.r12 + kWrap_Raw);
            break;
        case Point::P2981:
            if (g_3527) {
                f.actor = rdv<uint8_t>(rbp + 0x30) ? rdp(rbp + 0x28) : 0;  // the handler's own lookup
                raw = ctx.r13;
                break;
            }
            f.actor = rdp(ctx.r15);
            raw = rdp(ctx.r15 + kWrap_Raw);
            break;
        case Point::P2810: {
            const uintptr_t d = g_3527 ? 0x10 : 0;  // every slot of this frame moved by +0x10
            f.actor = rdv<uint8_t>(rbp + d) ? rdp(rbp + d - 8) : 0;
            f.packet_key = rdv<uint32_t>(rbp + d + 0x78);
            seq = rdv<uint64_t>(rbp + d - 0x58);
            value = rdv<uint32_t>(rbp + d - 0x60);
            break;
        }
        case Point::P2322: {
            const uintptr_t d = g_3527 ? 0x10 : 0;
            raw = ctx.r14;
            f.packet_key = rdv<uint32_t>(raw + kHeader);
            f.actor = rdv<uint8_t>(rbp + d - 8) ? rdp(rbp + d - 0x10) : 0;  // the handler's own lookup
            break;
        }
        case Point::P2524:  // [R15] = the actor 0xC0810E stored (the one 0xC0811F gave 0x17FA6C0)
            f.actor = rdp(ctx.r15);
            raw = rdp(ctx.r15 + kWrap_Raw);
            if (raw) {  // u8 4 | u32 actor @1 | u64 sequencer @5, as the 2981 (session 9 fix: it read @0 / @4)
                f.packet_key = rdv<uint32_t>(raw + kHeader + gsr::kBranchActorAt);
                seq = rdv<uint64_t>(raw + kHeader + gsr::kBranchSeqAt);
            }
            break;
        default:
            return;
    }
    uint32_t resource = 0;
    bool resource_known = false;
    const bool res_ok = res_thread_ok();
    if (point == Point::P2661 && raw) {
        f.packet_key = rdv<uint32_t>(raw + kHeader + gsr::kPrepareActorAt);
        seq = rdv<uint64_t>(raw + kHeader + gsr::kPrepareSeqAt);
        if (rdv<uint16_t>(raw + 3) >= gsr::kPrepareMinPayload) {
            resource = rdv<uint32_t>(raw + kHeader + gsr::kPrepareResourceAt);
            resource_known = true;
            f.denied = g_deny.has(resource);  // read-only after guest_seq_route_start
        }
    } else if (point == Point::P2981 && raw) {
        f.packet_key = rdv<uint32_t>(raw + kHeader + gsr::kBranchActorAt);
        seq = rdv<uint64_t>(raw + kHeader + gsr::kBranchSeqAt);
        value = rdv<uint32_t>(raw + kHeader + gsr::kBranchStateAt);
    }
    const decltype(g_seq_res)::Entry* seq_entry = nullptr;
    if ((point == Point::P2981 || point == Point::P2524) && seq && res_ok) {  // judged by its 2661's resource
        if (const auto* r = g_seq_res.find(seq)) {
            resource = r->resource;
            resource_known = true;
            f.denied = r->denied;
            seq_entry = r;
        }
    }
    f.actor_key = key_of(f.actor);
    f.m_key = f.m ? key_of(rdp(f.m + kMgr_Actor)) : 0;
    guest_x_note_m(f.m, f.m_key);  // guest_x_veto's own-manager check (review 4): M as this handler's vf48 gave it
    f.x = manager_of(f.actor);
    f.x_vt = f.x ? rdp(f.x) : 0;
    f.x_key = f.x ? key_of(rdp(f.x + kMgr_Actor)) : 0;
    if (point == Point::P2524) {  // review 11: only into an X guest_seq_play ticks
        f.need_known = true;
        f.x_known = f.x && guest_seq_play_knows_x(f.x, f.actor_key);
        // Session 10: only while X and this client play (gsr::pre_2524); the scene itself is checked inside
        // 0xA9E480 under the game's lock (on_2524_lookup).
        if (f.x_known && f.x_vt == f.want_vt) {
            f.ready2524 = static_cast<uint8_t>(gsr::pre_2524(rdv<uint8_t>(f.x + g_mo->ready),
                                                             rdv<uint32_t>(f.x + g_mo->count),
                                                             f.m ? rdv<uint8_t>(f.m + g_mo->ready) : 0));
            value = raw ? rdv<uint32_t>(raw + kHeader + gsr::kBranchStateAt) : 0;
        }
    }
    // Session 13 (guest_seq_route_2524 = probe | 1): the scene's class (gsr::classify_2524) from its 2661's binds, the
    // bound NPCs' type in this client and the scene's name in X; for the WORLD ones the inner check's verdict on X's
    // instance, read-only (in probe the call goes to M: 0xA9E55B never sees X).
    uint64_t world_bits = 0;
    uint64_t name_q[3] = {};
    if (point == Point::P2524 && gsr::need_world_2524(m2524)) {
        f.need_world = true;
        gsr::Scene2524Facts sf;
        sf.known = seq_entry != nullptr;
        sf.denied = f.denied;
        sf.resource = resource;
        if (seq_entry) {
            sf.binds = seq_entry->nbinds;
            for (uint8_t b = 0; b < seq_entry->nbinds; ++b) {
                const uint32_t k = seq_entry->binds[b];
                if ((k >> 28) != 0xB) continue;
                ++sf.npcs;
                const uintptr_t a = find_actor(k);
                if (!a || key_of(a) != k) continue;
                ++sf.npcs_found;
                const uintptr_t info = rdp(a + kActor_Info);
                if (info && rdv<uint8_t>(info + 1) == gsr::kActorTypeNpc) ++sf.type3;
            }
        }
        const bool x_ok = f.x && f.x_vt == f.want_vt;
        const uintptr_t inst = x_ok ? peek_instance(f.x, seq) : 0;
        const gsr::NameVia via = read_scene_name(inst, seq, name_q);
        char name[32] = {};
        sf.name_ok = via != gsr::NameVia::None && gsr::scene_name(name_q, 3, name, sizeof name);
        size_t name_len = 0;
        while (name_len < sizeof name && name[name_len]) ++name_len;
        sf.function = sf.name_ok && gsr::is_function_scene(std::string_view(name, name_len));
        sf.allow_empty = g_allow_2524.n == 0;
        sf.allowed = resource_known && g_allow_2524.has(resource);
        const gsr::World2524 cls = gsr::classify_2524(sf);
        f.world_ok = cls == gsr::World2524::World;
        g_2524_class[static_cast<size_t>(cls)].fetch_add(1, std::memory_order_relaxed);
        g_2524_name_via[static_cast<size_t>(via)].fetch_add(1, std::memory_order_relaxed);
        uint64_t peek = 0xFF;
        if (x_ok && f.x_known) {
            gsr::Scene2524 s;
            s.inst = inst;
            s.stage = s.inst ? rdp(s.inst + kInst_Stage) : 0;
            s.data = s.stage ? rdp(s.stage + kStage_Data) : 0;
            s.branches = s.data ? rdp(s.data + kData_Branches) : 0;
            s.count = s.data ? rdv<uint32_t>(s.data + kData_Count) : 0;
            s.capacity = s.data ? rdv<uint32_t>(s.data + kData_Capacity) : 0;
            s.branch = value;
            s.entry = s.branches && s.branch < s.count && s.count <= gsr::kMaxBranchTable
                          ? rdp(s.branches + static_cast<uintptr_t>(s.branch) * 8)
                          : 0;
            const gsr::Ready2524 r = gsr::scene_2524(s);
            peek = static_cast<uint64_t>(r);
            if (f.world_ok) {
                g_2524_peek[static_cast<size_t>(r)].fetch_add(1, std::memory_order_relaxed);
                g_2524_peek_pre[f.ready2524 < 5 ? f.ready2524 : 4].fetch_add(1, std::memory_order_relaxed);
            }
        }
        world_bits = static_cast<uint64_t>(cls) | peek << 8 | static_cast<uint64_t>(via) << 16 |
                     static_cast<uint64_t>(sf.npcs) << 24 | static_cast<uint64_t>(sf.npcs_found) << 32 |
                     static_cast<uint64_t>(sf.type3) << 40 | static_cast<uint64_t>(sf.binds & 0x7F) << 48 | 1ull << 63;
    }
    const gsr::Verdict v = gsr::decide(f);
    if (point == Point::P2524 && f.need_world && f.world_ok) {
        if (v == gsr::Verdict::Route) g_2524_world_route.fetch_add(1, std::memory_order_relaxed);
        if (v == gsr::Verdict::WouldRoute) g_2524_world_would.fetch_add(1, std::memory_order_relaxed);
    }
    g_verdicts[i][static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    // S44 guest_seq_foreign_player (guest_seq_foreign.h): a 2661 going to X (or that would, in probe) has its owner's
    // binding judged in the handler's own vector ([rbp-0x80]); this same hook, no second one at 0xC0612A.
    if (point == Point::P2661 &&
        gsf::wants_2661(raw != 0, resource_known, v == gsr::Verdict::Route, v == gsr::Verdict::WouldRoute)) {
        guest_seq_foreign_2661(ctx, v == gsr::Verdict::Route, v == gsr::Verdict::WouldRoute,
                               rdv<uint32_t>(raw + kHeader + gsf::kOwnerAt), f.m_key, seq, resource,
                               static_cast<uintptr_t>(f.actor));
    }
    if (point == Point::P2661 && resource_known && res_ok && (v == gsr::Verdict::Route || v == gsr::Verdict::WouldRoute ||
                                                    v == gsr::Verdict::Denied)) {
        // Session 13: with the keys it binds (the 2524's classification, gsr::classify_2524).
        uint32_t bk[gsr::kSeqBinds] = {};
        size_t nb = 0;
        const uint16_t len = rdv<uint16_t>(raw + 3);
        const uint32_t n = len >= g_prefix ? (len - static_cast<uint32_t>(g_prefix)) / osq::kBindingWire : 0;
        for (uint32_t b = 0; b < n && nb < gsr::kSeqBinds; ++b) {
            bk[nb++] = rdv<uint32_t>(raw + kHeader + g_prefix + b * osq::kBindingWire + 4);
        }
        g_seq_res.note(seq, resource, v == gsr::Verdict::Denied, std::span<const uint32_t>(bk, nb));
    }
    // guest_seq_play's table of X (a 2322 re-arms its 2 -> 3 step). Only what is really ROUTED (review 3), and
    // not the 2524 (it never creates anything in X). With the field the handler's vf48 ran on (review 10): the
    // frame slot it loaded into RCX right before the call (bytes verified with each point's vf48 context).
    if (v == gsr::Verdict::Route && point != Point::P2524) {
        guest_seq_play_note_x(f.x, f.actor_key, rdp(ctx.rbp - (g_3527 ? kFieldSlot3527[i] : kFieldSlot[i])),
                              point == Point::P2322);
    }
    if (v == gsr::Verdict::NotCharacter || v == gsr::Verdict::OwnCharacter || v == gsr::Verdict::Off) return;
    p::Event e;
    e.v[0] = static_cast<uint64_t>(point) | static_cast<uint64_t>(v) << 8;
    e.v[1] = f.actor_key | static_cast<uint64_t>(f.m_key) << 32;
    e.v[2] = seq;
    e.v[4] = f.m;
    e.v[5] = f.x;
    e.v[10] = f.x && f.x_vt == f.want_vt ? mgr_state(f.x) : ~0ull;
    e.v[11] = resource_known ? (1ull << 32 | resource) : 0;
    if (point == Point::P2661 && raw) {
        const uint16_t len = rdv<uint16_t>(raw + 3);
        const uint32_t n = len >= g_prefix ? (len - static_cast<uint32_t>(g_prefix)) / osq::kBindingWire : 0;
        value = n;
        for (uint32_t b = 0; b < n && b < 8; ++b) {
            const uint64_t k = rdv<uint32_t>(raw + kHeader + g_prefix + b * osq::kBindingWire + 4);
            e.v[6 + b / 2] |= b % 2 ? k << 32 : k;
        }
    }
    if (point == Point::P2524 && world_bits) {  // session 13: the class, the peek and the name (line_of)
        e.v[6] = world_bits;
        e.v[7] = name_q[0];
        e.v[8] = name_q[1];
        e.v[9] = name_q[2];
    }
    e.v[3] = value;
    if (v == gsr::Verdict::Route) {
        ctx.rax = f.x;
        if (point == Point::P2524) t_2524_x = f.x;  // the inner hook checks this call's scene under the lock
        // guest_x_veto's V0 (p8-s9-cinematica.md §8): the call 0xA9E100(X) below runs in an "X context" until
        // 0xC07776 (its clear point); a no-op unless that point is hooked.
        if (point == Point::P2981) guest_x_context_routed_2981(f.x, ctx.rsp);
    } else if (gsr::refuse(point, f, v)) {
        // Another character's 2661/2322 that cannot go to its own manager never touches M (gsr::refuse):
        // the 2661 takes the handler's native kind != 4 path (an error line, nothing created); the 2322's
        // byte write lands in a sink of the mod (RAX is not read again: 0xB87A6E loads it anew).
        if (point == Point::P2661) (g_3527 ? ctx.r14 : ctx.rbx) = 0;  // the kind the handler compares with 4
        else ctx.rax = reinterpret_cast<uintptr_t>(g_sink);
        g_refused[i].fetch_add(1, std::memory_order_relaxed);
        e.v[0] |= 1ull << 16;
    }
    // Session 9: every 2981 of state >= 2 put into X gets its own line with its sequencer's resource (to extend
    // guest_seq_route_deny), beyond the route lines' rate limit.
    if (point == Point::P2981 && v == gsr::Verdict::Route && value >= 2) {
        g_branch2.fetch_add(1, std::memory_order_relaxed);
        emit(kEBranch, e);  // emit only sets e's kind / time / thread: the route line below reuses it
    }
    emit(kERoute, e);
}

void guest_sched_route_hook(gsr::SchedPoint point, safetyhook::Context& ctx) noexcept {
    const size_t i = static_cast<size_t>(point);
    if (i >= gsr::kSchedPoints || g_sched_mode.load(std::memory_order_relaxed) == 0) return;
    if (!g_sched_on[i].load(std::memory_order_acquire)) return;
    guest_x_context_hook_entry();  // guest_x_veto (review 3): a new handler; no X context survives from before
    gsr::RouteFacts f;
    f.mode = static_cast<gsr::Mode>(g_sched_mode.load(std::memory_order_relaxed));
    f.point_on = true;
    f.need_sched = true;
    f.m = ctx.rax;
    f.want_vt = g_base + vt_mgr();
    uint64_t key = 0;
    uint32_t resource = 0, kind = 0;
    // The actor the handler itself resolved (0x8A67E0 on the client actor manager, this call, this thread) and the
    // values it decoded, from its frame (sched_points' context bytes): none is written between there and the point.
    switch (point) {
        case gsr::SchedPoint::P2335:
            f.actor = rdv<uint8_t>(ctx.rbp + 0x68) ? rdp(ctx.rbp + 0x60) : 0;
            f.packet_key = rdv<uint32_t>(ctx.rbp - 0x60);
            key = rdv<uint64_t>(ctx.rbp - 0x38);
            resource = rdv<uint32_t>(ctx.rbp - 0x48);
            kind = static_cast<uint32_t>(ctx.rbx & 0xFF);
            break;
        case gsr::SchedPoint::P2126:
            f.actor = rdv<uint8_t>(ctx.rbp - 8) ? rdp(ctx.rbp - 0x10) : 0;
            f.packet_key = rdv<uint32_t>(ctx.rbp + 0x70);
            key = rdv<uint64_t>(ctx.rbp + 0x78);
            break;
        case gsr::SchedPoint::P2958:
        case gsr::SchedPoint::P2909:
            f.actor = rdv<uint8_t>(ctx.rbp + 0x18) ? rdp(ctx.rbp + 0x10) : 0;
            f.packet_key = rdv<uint32_t>(ctx.rbp + 0x10A8);
            key = rdv<uint64_t>(ctx.rbp - 0x60);
            resource = rdv<uint32_t>(ctx.rbp - 0x58);
            break;
        default:
            return;
    }
    f.actor_key = key_of(f.actor);
    f.m_key = f.m ? key_of(rdp(f.m + kMgr_Actor)) : 0;
    guest_x_note_m(f.m, f.m_key);
    f.x = manager_of(f.actor);
    f.x_vt = f.x ? rdp(f.x) : 0;
    f.x_key = f.x ? key_of(rdp(f.x + kMgr_Actor)) : 0;
    f.x_sched_ok = f.x && f.x_vt == f.want_vt && rdp(f.x + kMgr_Sched) != 0;
    gsr::Verdict v = gsr::decide(f);
    // The ledger (scene key -> manager): only on the thread that owns it (the game's main thread, res_thread_ok).
    const bool res_ok = res_thread_ok();
    if (res_ok) sched_conversation_check();
    gsr::SchedWhere where = gsr::SchedWhere::Unknown;
    uint64_t ledger_mgr = 0;
    decltype(g_sched_ledger)::Entry* entry = nullptr;
    const bool creates = point == gsr::SchedPoint::P2335 && gsr::sched_creates(kind);
    if (creates) {
        where = gsr::sched_created_where(v);
        // §10: observer_sched_copy's copy may precede the native 2335 of the same key; 0xA9FEE0 dedups by wake spot
        // only. A second create of a key X+0x148 holds is refused (its ledger entry stays X).
        const bool x_has = (v == gsr::Verdict::Route || v == gsr::Verdict::WouldRoute) && sched_has(f.x, key);
        v = gsr::sched_2335_create(v, x_has);
        if (res_ok) entry = g_sched_ledger.note(key, where == gsr::SchedWhere::X ? f.x : f.m, f.packet_key, where);
    } else if (point == gsr::SchedPoint::P2335) {
        // §10 (review finding 7): a 2335 that does not create is a follow-up of its key (0xA9FEE0 looks it up and calls
        // 0x43A890 on what it finds, null or not): where its 2335 went, never noted as a creation.
        if (res_ok) entry = g_sched_ledger.find_mut(key);
        if (entry) where = entry->where, ledger_mgr = entry->mgr;
        bool x_has = false;
        if (where == gsr::SchedWhere::Unknown && (v == gsr::Verdict::Route || v == gsr::Verdict::WouldRoute)) {
            x_has = sched_has(f.x, key);
            g_sched_key_probe.fetch_add(1, std::memory_order_relaxed);
        }
        v = gsr::sched_followup(v, where, entry && entry->mgr == f.x, x_has);
        const bool to_x = v == gsr::Verdict::Route || v == gsr::Verdict::WouldRoute;
        const bool judged = gsr::sched_judged(v);
        v = gsr::sched_2335_other(v, judged, judged && sched_has(to_x ? f.x : f.m, key));
    } else {
        if (res_ok) entry = g_sched_ledger.find_mut(key);
        if (entry) where = entry->where, ledger_mgr = entry->mgr;
        bool x_has = false;
        if (where == gsr::SchedWhere::Unknown && (v == gsr::Verdict::Route || v == gsr::Verdict::WouldRoute)) {
            x_has = sched_has(f.x, key);
            g_sched_key_probe.fetch_add(1, std::memory_order_relaxed);
        }
        v = gsr::sched_followup(v, where, entry && entry->mgr == f.x, x_has);
    }
    g_sched_verdicts[i][static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    // guest_sched_bind (p8-impl-horarios-enlace.md): every 2335 sets (routed) or clears the pending bind that the point
    // after 0xA9FEE0 (0xC0B626) of this same call consumes.
    if (point == gsr::SchedPoint::P2335) {
        guest_sched_bind_note(creates && v == gsr::Verdict::Route, ctx.rbp, key, f.x, f.actor_key, resource, f.m);
    }
    if (v == gsr::Verdict::Route) {
        ctx.rax = f.x;  // 0xA9FEE0 / 0x43C750 / 0xAA0F00 / 0xAA1850 now run on X
        if (creates) g_xreg.note(f.x, f.actor_key);  // §11: a stage of X now exists
    } else if (gsr::sched_refused(v) && f.mode == gsr::Mode::On) {
        ctx.rax = reinterpret_cast<uintptr_t>(g_sched_sink);  // 0xA9FEE0 returns at 0xA9FF14: nothing created / touched
        g_sched_refused.fetch_add(1, std::memory_order_relaxed);
    }
    if (v == gsr::Verdict::Route || v == gsr::Verdict::WouldRoute) {
        g_sched_char.store(f.actor_key, std::memory_order_relaxed);  // the census reads this character's X
    }
    const bool judged = v != gsr::Verdict::Off && v != gsr::Verdict::NotCharacter && v != gsr::Verdict::OwnCharacter;
    if (judged && (gsr::sched_refused(v) || gsr::sched_line_ok(entry))) {  // every refusal gets its line
        p::Event e;
        e.v[0] = static_cast<uint64_t>(point) | static_cast<uint64_t>(v) << 8 | static_cast<uint64_t>(where) << 16;
        e.v[1] = f.packet_key | static_cast<uint64_t>(f.m_key) << 32;
        e.v[2] = key;
        e.v[3] = resource | static_cast<uint64_t>(kind) << 32;
        e.v[4] = f.m;
        e.v[5] = f.x;
        e.v[6] = sched_count(f.x && f.x_vt == f.want_vt ? f.x : 0) | static_cast<uint64_t>(sched_count(f.m)) << 32;
        e.v[7] = ledger_mgr;
        emit(kESched, e);
    }
    if (res_ok) {
        if (point == gsr::SchedPoint::P2126) g_sched_ledger.erase(key);  // deleted where its 2335 went (or nowhere)
        g_sched_ledger_x.store(g_sched_ledger.live(gsr::SchedWhere::X), std::memory_order_relaxed);
        g_sched_ledger_m.store(g_sched_ledger.live(gsr::SchedWhere::M), std::memory_order_relaxed);
        g_sched_evicted.store(g_sched_ledger.evicted(), std::memory_order_relaxed);
    }
}

bool guest_seq_route_gate(std::span<const uint8_t> packet) noexcept {
    if (packet.size() < kHeader) return false;
    const uint16_t op = static_cast<uint16_t>(packet[0] | packet[1] << 8);
    const std::span<const uint8_t> payload = packet.subspan(kHeader);
    const uint64_t epoch = guest_connection_epoch();
    if (op == kOpMainPlayerDataStartAck) {
        if (payload.size() >= 4) {
            g_own_key.store(gsr::le32(payload.data()));
            g_own_epoch.store(epoch);
        }
        return false;
    }
    const auto point = gsr::point_of_op(op);
    // 2981s / 2524s of other characters arrive natively (near finder): never gated.
    if (!point || *point == Point::P2981 || *point == Point::P2524) return false;
    const size_t i = static_cast<size_t>(*point);
    const bool active = g_mode.load(std::memory_order_relaxed) == static_cast<uint8_t>(gsr::Mode::On) &&
                        g_point_on[i].load(std::memory_order_acquire);
    // The own character of THIS connection only (a reconnection logs in with another character).
    const uint32_t own = g_own_epoch.load(std::memory_order_relaxed) == epoch ? g_own_key.load(std::memory_order_relaxed) : 0;
    const gsr::Gate g = gsr::gate(op, payload, own, active);
    const auto named = gsr::named_actor(op, payload);
    if (g == gsr::Gate::Deliver) {
        if (named && (*named >> 28) == gsr::kCharClass && own && *named != own) {
            g_gate_pass_foreign[i].fetch_add(1, std::memory_order_relaxed);
        }
        return false;
    }
    g_gate_drop[i].fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    e.v[0] = op;
    e.v[1] = named.value_or(0);
    e.v[2] = own;
    e.v[3] = g_how[i].load();
    emit(kEGate, e);
    return true;
}

bool guest_seq_route_other_character(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    const auto a = gsr::named_actor(opcode, payload);
    const uint32_t own = g_own_epoch.load(std::memory_order_relaxed) == guest_connection_epoch()
                             ? g_own_key.load(std::memory_order_relaxed)
                             : 0;
    return a && (*a >> 28) == gsr::kCharClass && own && *a != own;
}

void guest_seq_route_tick() noexcept {
    try {
        ++g_ticks;
        p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind >= kKindCount) continue;
            if (e.kind == kERoute) {
                const auto actor_key = static_cast<uint32_t>(e.v[1]);
                const auto verdict = static_cast<gsr::Verdict>((e.v[0] >> 8) & 0xFF);
                if ((verdict == gsr::Verdict::Route || verdict == gsr::Verdict::WouldRoute) && actor_key &&
                    !g_x_state.count(actor_key) && g_x_state.size() < 8) {
                    g_x_state[actor_key] = XSeen{};
                }
                if (static_cast<Point>(e.v[0] & 0xFF) == Point::P2661) {
                    for (size_t i = 6; i < 10; ++i) {
                        watch(static_cast<uint32_t>(e.v[i]));
                        watch(static_cast<uint32_t>(e.v[i] >> 32));
                    }
                }
                // Session 13: the 2524s classified under guest_seq_route_2524, per sequencer (the summary's list).
                if (static_cast<Point>(e.v[0] & 0xFF) == Point::P2524 && (e.v[6] >> 63) &&
                    (g_2524_seen.count(e.v[2]) || g_2524_seen.size() < kMax2524Seen)) {
                    Scene2524Seen& sc = g_2524_seen[e.v[2]];
                    sc.resource = (e.v[11] >> 32) ? static_cast<uint32_t>(e.v[11]) : 0;
                    sc.cls = static_cast<uint8_t>(e.v[6] & 0xFF);
                    sc.verdict = static_cast<uint8_t>((e.v[0] >> 8) & 0xFF);
                    char name[32];
                    gsr::scene_name(e.v + 7, 3, name, sizeof name);
                    if (name[0]) sc.name = name;
                    ++sc.n;
                }
            }
            if (g_lines.fetch_add(1) < kMaxLines) log::info("{}", line_of(e));
        }
        if (g_base) g5();
        // guest_sched_route: the census of X+0x148 / M+0x148 and the watched NPCs' binding, then the summary.
        if (g_base && g_sched_mode.load()) sched_census_tick();
        if (g_sched_mode.load()) guest_sched_bind_tick();  // its lines and its 60 s summary
        if (g_ticks % 12 == 0 && g_sched_mode.load()) {
            std::string s;
            for (size_t i = 0; i < gsr::kSchedPoints; ++i) {
                std::string vs;
                for (size_t k = 0; k < static_cast<size_t>(gsr::Verdict::Count); ++k) {
                    if (const uint64_t n = g_sched_verdicts[i][k].load()) {
                        vs += std::format(" {} x{};", gsr::verdict_name(static_cast<gsr::Verdict>(k)), n);
                    }
                }
                s += std::format(" | {} [{}]:{}", gsr::sched_point_name(static_cast<gsr::SchedPoint>(i)),
                                 g_sched_on[i].load() ? "hooked" : "NOT hooked", vs.empty() ? " none;" : vs);
            }
            const SchedTally& t = g_sched_tally;
            log::info("GuestSchedRoute summary (mode {}){} | ledger: live keys in X {}, in M {}, evicted {}, unknown keys "
                      "judged by X's container {} | census: X 0x{:X} {} ; M 0x{:X} {} | watched NPCs: {} with a sequencer "
                      "component, {} bound (comp+0x318), {} active, {} waiting (+0x3D9), {} in X, {} in M, {} of a gone X | "
                      "refused 2335 {} | routed X gone {} | teardown guard ({}): ours live {}, X GONE redirected {}, "
                      "mismatch {} | hooks on another thread {}",
                      g_sched_mode.load() == 2 ? "1" : "probe", s, g_sched_ledger_x.load(), g_sched_ledger_m.load(),
                      g_sched_evicted.load(), g_sched_key_probe.load(), t.xg, census_text(t.x), t.mg, census_text(t.m),
                      t.comps, t.bound, t.active, t.waiting, t.in_x, t.in_m, t.orphan, g_sched_refused.load(), t.dead_x,
                      g_teardown_on.load() ? "in" : "off",
                      g_teardown[static_cast<size_t>(gsr::Teardown::Live)].load(),
                      g_teardown[static_cast<size_t>(gsr::Teardown::Redirect)].load(),
                      g_teardown[static_cast<size_t>(gsr::Teardown::Mismatch)].load(), g_res_foreign.load());
        }
        if (g_ticks % 12 == 0 && (g_started.load() || g_gate_drop[0].load() || g_gate_drop[2].load() ||
                                  g_gate_drop[3].load())) {
            std::string s;
            for (size_t i = 0; i < gsr::kPoints; ++i) {
                std::string vs;
                for (size_t k = 0; k < static_cast<size_t>(gsr::Verdict::Count); ++k) {
                    if (const uint64_t n = g_verdicts[i][k].load()) {
                        vs += std::format(" {} x{};", gsr::verdict_name(static_cast<gsr::Verdict>(k)), n);
                    }
                }
                s += std::format(" | {} [{}]:{} refused {}, gate dropped {}, foreign delivered {}",
                                 gsr::point_name(static_cast<Point>(i)), how_name(static_cast<How>(g_how[i].load())),
                                 vs.empty() ? " none;" : vs, g_refused[i].load(), g_gate_drop[i].load(),
                                 g_gate_pass_foreign[i].load());
            }
            log::info("GuestSeqRoute summary (mode {}): own character 0x{:08X}{} | 2981 of state >= 2 put into X {} | "
                      "2524 scene check (inner hook {}): ok {}, not found {}, NOT LOADED {}, bad branch {}, other G {} | "
                      "watched {} | resource table: hooks on another thread {} | limited {} lost {}",
                      g_mode.load() == 2 ? "1" : g_mode.load() == 1 ? "probe" : "0", g_own_key.load(), s,
                      g_branch2.load(), g_lookup_on.load() ? "in" : "not installed", g_2524_scene[0].load(),
                      g_2524_scene[2].load(), g_2524_scene[3].load(), g_2524_scene[4].load(), g_2524_mismatch.load(),
                      g_watch.size(), g_res_foreign.load(),
                      g_limited.load(), g_lost.load());
            if (g_mode_2524.load()) log::info("{}", summary_2524());
        }
    } catch (...) {
    }
}

size_t guest_seq_route_watch_count() noexcept { return g_watch_pub_n.load(std::memory_order_acquire); }

uint32_t guest_seq_route_watch_key(size_t i) noexcept {
    return i < guest_seq_route_watch_count() ? g_watch_pub[i].load(std::memory_order_relaxed) : 0;
}

int guest_seq_route_watch_index(uint32_t key) noexcept {
    if (!key) return -1;
    const size_t n = guest_seq_route_watch_count();
    for (size_t i = 0; i < n; ++i) {
        if (g_watch_pub[i].load(std::memory_order_relaxed) == key) return static_cast<int>(i);
    }
    return -1;
}

uintptr_t guest_seq_route_find_actor(uint32_t key) noexcept {
    if (!g_base || !key) return 0;
    const uintptr_t a = find_actor(key);
    return a && key_of(a) == key ? a : 0;
}

uint32_t guest_seq_route_own_key() noexcept {
    return g_own_epoch.load(std::memory_order_relaxed) == guest_connection_epoch() ? g_own_key.load(std::memory_order_relaxed)
                                                                                     : 0;
}

std::string guest_seq_route_describe() {
    const uint64_t dropped = g_gate_drop[0].load() + g_gate_drop[2].load() + g_gate_drop[3].load();
    std::string sched;
    if (g_sched_mode.load()) {
        uint64_t routed = 0;
        for (size_t i = 0; i < gsr::kSchedPoints; ++i) {
            routed += g_sched_verdicts[i][static_cast<size_t>(gsr::Verdict::Route)].load() +
                      g_sched_verdicts[i][static_cast<size_t>(gsr::Verdict::WouldRoute)].load();
        }
        sched = std::format(" | sched route {} (routed {})", g_sched_mode.load() == 2 ? "on" : "probe", routed) +
                guest_sched_bind_describe();
    }
    if (!g_started.load() && !dropped) return sched;
    uint64_t routed = 0;
    for (size_t i = 0; i < gsr::kPoints; ++i) routed += g_verdicts[i][static_cast<size_t>(gsr::Verdict::Route)].load();
    return std::format(" | seq route {} (routed {}, gate dropped {})",
                       g_mode.load() == 2 ? "on" : g_mode.load() == 1 ? "probe" : "off", routed, dropped) +
           sched;
}

}  // namespace cdmp::session2
