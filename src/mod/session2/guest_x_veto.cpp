#include "mod/session2/guest_x_veto.h"

#include <windows.h>

#include <intrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <safetyhook.hpp>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest.h"
#include "mod/session2/freeze_watchdog.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_seq_play.h"
#include "mod/session2/guest_seq_present.h"
#include "mod/session2/guest_seq_route.h"
#include "mod/session2/guest_x_interaction.h"
#include "mod/session2/guest_shop_branch.h"
#include "mod/session2/guest_shop_window.h"
#include "mod/session2/guest_x_veto_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;
namespace off = game::build_2976;
using gxv::Act;
using gxv::Mode;
using gxv::Verdict;

// ---------------------------------------------------------------- the code (build 2976, all in .rsrc)
//
// Read with Ghidra and capstone on the read-only PE (p8-s9-cinematica.md §7):
//   0x5F2A00  ClientSequencerStage_StageChartProcessor (vtable 0x558C080) +0x218 = StageChart_Function_Loading's
//             handler (RUNTIME_FUNCTION 0x5F2A00-0x5F35F8):
//   0x5F2A27  mov rsi,r8 ; mov r14,rcx ; xor edi,edi ; mov [rbp-0x50],edi ; mov rdx,r8 ; call 0x204F730 (the gate)
//   0x5F2A3A  test al,al ; je 0x5F35D7           V1 (8 bytes, two whole instructions; no branch into 0x5F2A3B..41
//                                                 from this function or by rel32 from anywhere in the PE)
//   0x5F35D7  lea r11,[rsp+0x3E0] ...             the epilogue (rax = the gate's 0)
//   R14 = the processor all along (callee-saved over the gate's call); [proc+8] = its stage manager G.
constexpr uintptr_t kV1 = 0x5F2A3A, kV1Ctx = 0x5F2A27, kV1Epilogue = 0x5F35D7;
constexpr uint32_t kV1Patch = 8;
constexpr uint8_t kV1Bytes[] = {0x84, 0xC0, 0x0F, 0x84, 0x95, 0x0B, 0x00, 0x00};
constexpr uint8_t kV1CtxBytes[] = {0x49, 0x8B, 0xF0, 0x4C, 0x8B, 0xF1, 0x33, 0xFF, 0x89, 0x7D,
                                   0xB0, 0x49, 0x8B, 0xD0, 0xE8, 0xF6, 0xCC, 0xA5, 0x01};
constexpr uint8_t kV1EpilogueBytes[] = {0x4C, 0x8D, 0x9C, 0x24, 0xE0, 0x03, 0x00, 0x00};
//   0x778AB0  P's "start a load" (the only `mov byte [P+0x15C], 1`, at 0x778B99): copies the request and sets the
//             state 1; returns void. V0: inline hook at its entry (mov [rsp+0x10],rbx: 5 bytes).
constexpr uintptr_t kV0 = 0x778AB0;
constexpr uint32_t kV0Patch = 5;
constexpr uint8_t kV0Bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C,
                                0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57};
//   0xC07771  call 0xA9E100 (the 2981's branch, routed to X at 0xC07749 by guest_seq_route)
//   0xC07776  nop ; lea rax,[rip+0x4D0B6E2]       the clear point (8 bytes; the lea is relocated by safetyhook; no
//                                                 branch into 0xC07777..0xC0777D)
constexpr uintptr_t kClear = 0xC07776, kClearCtx = 0xC07771;
constexpr uint32_t kClearPatch = 8;
constexpr uint8_t kClearBytes[] = {0x90, 0x48, 0x8D, 0x05, 0xE2, 0xB6, 0xD0, 0x04};
constexpr uint8_t kClearCtxBytes[] = {0xE8, 0x8A, 0x69, 0xE9, 0xFF};

// guest_x_ui_veto (p8-s10.md §4): one mid hook per handler (gxv::Fn), read with capstone on the read-only PE.
//   Where the processor is (G = [proc+8], facts_of): rcx for the processor's slots and for the dialogue functions that
//   tail-jump to their code with rcx = [[rdx]+0x58] (vf8 0x236A510, 0x2368F90 / 0x2368FA0); [[rdx]+0x58] for
//   BlockInteraction / SetInteraction (vf8 / vf9 0x235E1B0.. / 0x235E0F0..: rcx = the StageChart function, rdx = its
//   context, r8b = 1 / 0).
//   Thunks (E9 rel32 -> .xtls): the hook relocates the 5-byte jmp; the code behind it is not readable (probe only).
//   Vetoable (gxv::fn_info): the hook sits after the prologue. The veto is FORCED (a call for X never runs the
//   handler's effect): it replays the register writes of the native refused path from the hook to its way out
//   (replay_way_out) and sets rip to that way out. The path from the hook to the way out has no push / pop / rsp
//   change; its calls (UIControl's try-lock 0x206AE30, SetInteraction's lookup 0x2049B90 + warning + free) are
//   balanced and the way out reads none of what they write (p8-s10.md §4.6, with the disassembly).
//     TimelineEvent  0x204BB90: [func+0x30] == 0 and [[func+0x38]] null / empty -> 0x204C3C6
//     SetInteraction 0x2369360: the actor lookup 0x2049B90 fails -> (a warning) -> 0x23698C6 (reads r14 = 0)
//     InputBlock     0x5E4E60: [proc+0x260] == func[0x20] -> 0x5E4E9F (eax = func[0x21], already loaded)
//     UIControl      0x5E4EB0: the try-lock 0x206AE30 fails -> 0x5E4F95 -> 0x5E5023
//     UIShowMinimap  0x5ECD90: [[func+0x20]] null / empty -> 0x5ED652
//     UIStageGuide   0x5F3A90: word func[0x20] == 0xFFFF, and func[0x22] != 0 or func[0x24] == 0 -> 0x5F4031
//   At install: the entry .. hook bytes, the hook bytes, the way out's first bytes and an FNV-1a 64 of the whole
//   hook .. way-out-end span must be build 2976's, else that handler stays a probe.
//   No branch lands inside any patched span (linear sweep of the RUNTIME_FUNCTION, rel32 xrefs of the whole PE).
enum class ProcAt : uint8_t { Rcx, CtxRdx };
struct FnPoint {
    gxv::Fn fn;
    uintptr_t rva;  // the hook
    uint32_t patch;
    std::span<const uint8_t> bytes;  // >= patch, verified
    ProcAt proc;
    // Vetoable only: the function's entry .. the hook (the frame the way out restores), the way out, and the hash of
    // [hook, resume + resume_bytes.size()).
    uintptr_t entry = 0;
    std::span<const uint8_t> entry_bytes = {};
    uintptr_t resume = 0;
    std::span<const uint8_t> resume_bytes = {};
    uint32_t span_len = 0;
    uint64_t span_fnv = 0;
};
constexpr uintptr_t kUiControlRaxRva = 0x5725E48;  // 0x5E4F95 lea rax,[rip+0x5140EAC]: what UIControl's way out carries
// dialogue
constexpr uint8_t kQuestDlgBytes[] = {0xE9, 0x0B, 0x77, 0xFF, 0x0B};  // jmp .xtls 0xE045390
constexpr uint8_t kTimelineEntry[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x4C, 0x89, 0x40, 0x18, 0x48,
                                      0x89, 0x48, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                      0x41, 0x57, 0x48, 0x8D, 0xA8, 0x08, 0xFF, 0xFF, 0xFF, 0x48, 0x81, 0xEC,
                                      0xC0, 0x01, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0x70, 0xB8};
constexpr uint8_t kTimelineBytes[] = {0x49, 0x8B, 0xF0, 0x48, 0x8B, 0xDA, 0x4C, 0x8B, 0xE1};  // mov rsi,r8 ; mov rbx,rdx
constexpr uint8_t kTimelineOut[] = {0x48, 0x8B, 0x9C, 0x24, 0x08, 0x02, 0x00, 0x00};       // mov rbx,[rsp+0x208]
constexpr uint8_t kTimelineEndBytes[] = {0xE9, 0xAB, 0x9F, 0xFE, 0x0B};                     // jmp .xtls 0xE0363C0
constexpr uint8_t kBlockInterBytes[] = {0xE9, 0x6B, 0x73, 0xC7, 0x0C};                      // jmp .xtls 0xEFE0C60
constexpr uint8_t kSetInterEntry[] = {0x44, 0x88, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x48,
                                      0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41,
                                      0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0xF8, 0xF7,
                                      0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x08, 0x09, 0x00, 0x00};
constexpr uint8_t kSetInterBytes[] = {0x45, 0x0F, 0xB6, 0xE8, 0x48, 0x8B, 0xF2, 0x4C, 0x8B, 0xF1};  // movzx ; mov rsi,rdx
constexpr uint8_t kSetInterOut[] = {0x4C, 0x89, 0x74, 0x24, 0x78, 0x48, 0xC7, 0x45};  // mov [rsp+0x78],r14 ; mov [rbp-0x80],0
// interface
constexpr uint8_t kInputEntry[] = {0x48, 0x83, 0xEC, 0x28, 0x41, 0x0F, 0xB6, 0x40, 0x21, 0x45, 0x0F, 0xB6, 0x40, 0x20};
constexpr uint8_t kInputBytes[] = {0x44, 0x38, 0x81, 0x60, 0x02, 0x00, 0x00, 0x74, 0x28};  // cmp [rcx+0x260],r8b (7)
constexpr uint8_t kInputOut[] = {0x48, 0x83, 0xC4, 0x28, 0xC3};                             // add rsp,0x28 ; ret
constexpr uint8_t kUiControlEntry[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56,
                                       0x57, 0x41, 0x56, 0x48, 0x81, 0xEC, 0x90, 0x08, 0x00, 0x00};
constexpr uint8_t kUiControlBytes[] = {0x49, 0x8B, 0xE8, 0x48, 0x8B, 0xDA, 0x4C, 0x8B, 0xF1};  // mov rbp,r8 ; mov rbx,rdx
constexpr uint8_t kUiControlOut[] = {0x4C, 0x8D, 0x9C, 0x24, 0x90, 0x08, 0x00, 0x00};       // lea r11,[rsp+0x890]
constexpr uint8_t kPhaseTagBytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x49, 0x8B, 0x48, 0x20};  // push ; sub (6)
constexpr uint8_t kMinimapEntry[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x10, 0xED, 0xFF, 0xFF, 0xB8, 0xF0, 0x13, 0x00, 0x00, 0xE8, 0x09, 0x95, 0x2A,
    0x04, 0x48, 0x2B, 0xE0, 0xC5, 0xF8, 0x29, 0xB4, 0x24, 0xE0, 0x13, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0xBC, 0x24, 0xD0,
    0x13, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x84, 0x24, 0xC0, 0x13, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x8C, 0x24, 0xB0, 0x13,
    0x00, 0x00};
constexpr uint8_t kMinimapBytes[] = {0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xFA, 0x4C, 0x8B, 0xF1};  // mov r13,r8 ; mov rdi,rdx
constexpr uint8_t kMinimapOut[] = {0x4C, 0x8D, 0x9C, 0x24, 0xF0, 0x13, 0x00, 0x00};       // lea r11,[rsp+0x13F0]
constexpr uint8_t kFindPathBytes[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x55};    // mov rax,rsp ; mov [rax+0x10],rbx
constexpr uint8_t kStageIconBytes[] = {0xE9, 0xDB, 0x9E, 0x94, 0x08};                     // jmp .xtls 0x8F3C860
constexpr uint8_t kGuideEntry[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41,
                                   0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x40, 0xF8,
                                   0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC0, 0x08, 0x00, 0x00};
constexpr uint8_t kGuideBytes[] = {0x4D, 0x8B, 0xF0, 0x48, 0x8B, 0xD9, 0xB8, 0xFF, 0xFF, 0x00, 0x00};  // mov r14,r8 ; mov rbx,rcx
constexpr uint8_t kGuideOut[] = {0x48, 0x8B, 0x9C, 0x24, 0x00, 0x09, 0x00, 0x00};                    // mov rbx,[rsp+0x900]
constexpr uint8_t kBgGuideBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18};
constexpr uint8_t kHintBytes[] = {0xE9, 0xFB, 0x09, 0x95, 0x08};     // jmp .xtls 0x8F44B10
constexpr uint8_t kHintEndBytes[] = {0xE9, 0x3B, 0x5F, 0x95, 0x08};  // jmp .xtls 0x8F4A140
// camera / screen (entry points, whole first instructions; §7.3)
constexpr uint8_t kFadeBytes[] = {0xE9, 0xEB, 0x8D, 0x95, 0x08};  // jmp .xtls
constexpr uint8_t kLetterBytes[] = {0xC4, 0xC1, 0x7A, 0x10, 0x50, 0x20, 0xB2, 0x01, 0xE9, 0x53, 0x73, 0x00, 0x00};
constexpr uint8_t kSeqCamBytes[] = {0xE9, 0x6B, 0xA3, 0x93, 0x08};  // jmp .xtls
constexpr uint8_t kDeactCamBytes[] = {0x4C, 0x8D, 0x0D, 0x09, 0x77, 0x47, 0x06, 0x45, 0x33,
                                      0xC0, 0x33, 0xD2, 0xE9, 0x8F, 0xC3, 0xFF, 0xFF};  // lea r9,[rip..] (7)
constexpr uint8_t kDeactCamEndBytes[] = {0x4C, 0x8D, 0x0D, 0xE9, 0x76, 0x47, 0x06, 0x45, 0x33,
                                         0xC0, 0xB2, 0x01, 0xE9, 0x6F, 0xC3, 0xFF, 0xFF};  // lea r9,[rip..] (7)
constexpr uint8_t kDeactFadeBytes[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x41, 0x10};  // push;sub (6)
constexpr uint8_t kDeactFade2Bytes[] = {0xE9, 0x4B, 0x76, 0x93, 0x08};                          // jmp .xtls
constexpr uint8_t kPresetBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10};
constexpr uint8_t kPresetEndBytes[] = {0x41, 0x0F, 0xB6, 0x50, 0x20, 0x4D, 0x8B, 0x40, 0x28};  // movzx edx,[r8+0x20] (5)
constexpr uint8_t kLockOnBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x44, 0x24, 0x18};
constexpr uint8_t kLookAtBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57};
constexpr uint8_t kLookAtEndBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18};
constexpr uint8_t kPostBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18};

using gxv::Fn;
constexpr FnPoint kFnPoints[] = {
    {Fn::SetQuestDialogAICategory, 0x204DC80, 5, kQuestDlgBytes, ProcAt::Rcx},
    {Fn::TimelineEvent, 0x204BBBD, 6, kTimelineBytes, ProcAt::Rcx, 0x204BB90, kTimelineEntry, 0x204C3C6, kTimelineOut,
     0x811, 0x638B87276CA702B8},
    {Fn::TimelineEventEnd, 0x204C410, 5, kTimelineEndBytes, ProcAt::Rcx},
    {Fn::BlockInteraction, 0x23698F0, 5, kBlockInterBytes, ProcAt::CtxRdx},
    {Fn::SetInteraction, 0x236938A, 7, kSetInterBytes, ProcAt::CtxRdx, 0x2369360, kSetInterEntry, 0x23698C6,
     kSetInterOut, 0x544, 0x28F2F0C5A3377E42},
    {Fn::InputBlock, 0x5E4E6E, 7, kInputBytes, ProcAt::Rcx, 0x5E4E60, kInputEntry, 0x5E4E9F, kInputOut, 0x36,
     0x8A81F3F32F60C873},
    {Fn::UIControl, 0x5E4EC5, 6, kUiControlBytes, ProcAt::Rcx, 0x5E4EB0, kUiControlEntry, 0x5E5023, kUiControlOut,
     0x166, 0x6847B03A2FFB8D76},
    {Fn::ChangePhasePanelTag, 0x5E9750, 6, kPhaseTagBytes, ProcAt::Rcx},
    {Fn::UIShowMinimap, 0x5ECDDE, 6, kMinimapBytes, ProcAt::Rcx, 0x5ECD90, kMinimapEntry, 0x5ED652, kMinimapOut,
     0x87C, 0xA05FE59779F1CB90},
    {Fn::UIFindPath, 0x5ED9A0, 7, kFindPathBytes, ProcAt::Rcx},
    {Fn::UIStageIcon, 0x5F2980, 5, kStageIconBytes, ProcAt::Rcx},
    {Fn::UIStageGuide, 0x5F3AAF, 6, kGuideBytes, ProcAt::Rcx, 0x5F3A90, kGuideEntry, 0x5F4031, kGuideOut, 0x58A,
     0x96A60DEF4E99B045},
    {Fn::UIStageBackgroundGuide, 0x5F4050, 5, kBgGuideBytes, ProcAt::Rcx},
    {Fn::UIHint, 0x5F4110, 5, kHintBytes, ProcAt::Rcx},
    {Fn::UIHintEnd, 0x5F4200, 5, kHintEndBytes, ProcAt::Rcx},
    {Fn::DeactiveSequencerCamera, 0x5EE210, 7, kDeactCamBytes, ProcAt::Rcx},
    {Fn::DeactiveSequencerCameraEnd, 0x5EE230, 7, kDeactCamEndBytes, ProcAt::Rcx},
    {Fn::SequencerCamera, 0x5EE250, 5, kSeqCamBytes, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeIn, 0x5EE0C0, 6, kDeactFadeBytes, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeInEnd, 0x5EE160, 5, kDeactFade2Bytes, ProcAt::Rcx},
    {Fn::CameraPreset, 0x5EDD30, 5, kPresetBytes, ProcAt::Rcx},
    {Fn::CameraPresetEnd, 0x5EE1F0, 5, kPresetEndBytes, ProcAt::Rcx},
    {Fn::ForceLockOn, 0x5EAE90, 5, kLockOnBytes, ProcAt::Rcx},
    {Fn::LetterBox, 0x5F2970, 6, kLetterBytes, ProcAt::Rcx},
    {Fn::FadeInOut, 0x5F52E0, 5, kFadeBytes, ProcAt::Rcx},
    {Fn::LookAt, 0x5F3600, 5, kLookAtBytes, ProcAt::Rcx},
    {Fn::LookAtEnd, 0x5F3810, 5, kLookAtEndBytes, ProcAt::Rcx},
    {Fn::PostProcess, 0x5F4440, 5, kPostBytes, ProcAt::Rcx},
};
constexpr size_t kFns = gxv::kFns;
static_assert(std::size(kFnPoints) == kFns);
constexpr bool fn_points_in_order() {
    for (size_t i = 0; i < kFns; ++i) {
        if (static_cast<size_t>(kFnPoints[i].fn) != i) return false;
    }
    return true;
}
static_assert(fn_points_in_order(), "kFnPoints follows gxv::Fn (the hook callbacks index it)");

// ---------------------------------------------------------------- build 1.0.0.3527 (capstone, 2026-11-05)
//
// V1 cannot be byte-ported: the handler Loading 0x6AFE10 (RUNTIME_FUNCTION 0x6AFE10-0x6B0AF8, processor slot +0x220) has no
// gate call any more. It starts:
//   0x6AFE28 lea rbp,[rsp-0x320] ; sub rsp,0x420     the frame, complete
//   0x6AFE37 mov r15,r8 ; mov r13,rcx                V1 (6 bytes, two whole instructions; no branch into 0x6AFE38..3C): RCX =
//                                                    the processor, nothing has run yet
//   0x6AFE3D xor esi,esi ; ... call 0x99E350 ...     the handler's body
//   0x6B0AD7 lea r11,[rsp+0x420] ; mov rbx,[r11+0x30] ; mov rsi,[r11+0x38] ; mov rdi,[r11+0x40] ; mov rsp,r11 ; pops ; ret
// The epilogue reads only the frame (homes saved before the hook, the pushes): resuming there from 0x6AFE37 is the
// handler returning without having done anything; 8 native paths reach it the same way (0x6AFE6C je 0x6B0AD7 ...), the
// dispatch sites never read RAX (p8-s10.md §4.6 for the 2976 sites; Execute is void).
constexpr uintptr_t kV1Entry3527 = 0x6AFE10, kV1Point3527 = 0x6AFE37, kV1Out3527 = 0x6B0AD7;
constexpr uint32_t kV1Patch3527 = 6;
constexpr uint8_t kV1EntryBytes3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C,
                                         0x24, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D,
                                         0xAC, 0x24, 0xE0, 0xFC, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x20, 0x04, 0x00, 0x00};
constexpr uint8_t kV1Bytes3527[] = {0x4D, 0x8B, 0xF8, 0x4C, 0x8B, 0xE9, 0x33, 0xF6, 0x89, 0x75, 0xC8, 0x48, 0x8D, 0x55, 0x80, 0x48};
constexpr uint8_t kV1OutBytes3527[] = {0x4C, 0x8D, 0x9C, 0x24, 0x20, 0x04, 0x00, 0x00, 0x49, 0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73,
                                       0x38, 0x49, 0x8B, 0x7B, 0x40, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41,
                                       0x5C, 0x5D, 0xC3};
// The vetoable handlers: the same native paths as 2976, read whole (replay_way_out says what moved). Span = [hook, way out
// + its bytes), hashed as in p8-s10.md §4.6.
//   TimelineEvent 0x2205B10 (vf8 0x255CF50 -> rcx = [[rdx]+0x60]): 0x2205B4A cmp [r14],0 ; je 0x2205EC6 -> [[r8+0x38]] null -> 0x220635C
//   InputBlock    0x6A1000: 0x6A100E cmp [rcx+0x260],r8b ; je 0x6A103F (the same bytes as 2976's, other rel8)
//   UIControl     0x6A1050: 0x6A1080 call 0x2227820 (try-lock) ; [rsp+0x50] = 0 -> 0x6A113B -> 0x6A11C9
//   UIShowMinimap 0x6A9CB0: 0x6A9D07 [[r8+0x20]] null / empty -> 0x6AA74F; r13, rdi and RSI (not r14) take the arguments
//   UIStageGuide  0x6B0FA0: 0x6B0FCA word [r8+0x20] == 0xFFFF and [r8+0x22] != 0 or [r8+0x24] == 0 -> 0x6B1543; r15 and RDI
// None of those spans has a branch into its patched bytes (linear sweep of the RUNTIME_FUNCTION, rel32 scan of the PE).
// The other handlers (camera family, thunks to .text, SetInteraction, BlockInteraction) are not ported: no hook, native. R-A
// cuts them on foreign stages; without R-A they run natively on X (on 2976 they were probes that ran natively too).
constexpr uintptr_t kUiControlRaxRva3527 = 0x5AC37B0;  // 0x6A113B lea rax,[rip+0x542266E]
constexpr uint8_t kTimelineEntry3527[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x4C, 0x89, 0x40, 0x18, 0x48,
                                          0x89, 0x48, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                          0x41, 0x57, 0x48, 0x8D, 0xA8, 0xF8, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC,
                                          0xD0, 0x01, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0x70, 0xB8};
constexpr uint8_t kTimelineOut3527[] = {0x48, 0x8B, 0x9C, 0x24, 0x18, 0x02, 0x00, 0x00};  // mov rbx,[rsp+0x218]
constexpr uint8_t kInputEntry3527[] = {0x48, 0x83, 0xEC, 0x28, 0x41, 0x0F, 0xB6, 0x40, 0x21, 0x45, 0x0F, 0xB6, 0x40, 0x20};
constexpr uint8_t kInputBytes3527[] = {0x44, 0x38, 0x81, 0x60, 0x02, 0x00, 0x00, 0x74, 0x28};
constexpr uint8_t kInputOut3527[] = {0x48, 0x83, 0xC4, 0x28, 0xC3};
constexpr uint8_t kUiControlEntry3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56,
                                           0x57, 0x41, 0x56, 0x48, 0x81, 0xEC, 0x90, 0x08, 0x00, 0x00};
constexpr uint8_t kUiControlBytes3527[] = {0x49, 0x8B, 0xE8, 0x48, 0x8B, 0xDA, 0x4C, 0x8B, 0xF1};
constexpr uint8_t kUiControlOut3527[] = {0x4C, 0x8D, 0x9C, 0x24, 0x90, 0x08, 0x00, 0x00};
constexpr uint8_t kMinimapEntry3527[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0xEC, 0xFF, 0xFF, 0xB8, 0x80, 0x14, 0x00, 0x00, 0xE8, 0xD9, 0xD6, 0x4F,
    0x04, 0x48, 0x2B, 0xE0, 0xC5, 0xF8, 0x29, 0xB4, 0x24, 0x70, 0x14, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0xBC, 0x24, 0x60,
    0x14, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x84, 0x24, 0x50, 0x14, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x8C, 0x24, 0x40, 0x14,
    0x00, 0x00};
constexpr uint8_t kMinimapBytes3527[] = {0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1};
constexpr uint8_t kMinimapOut3527[] = {0x4C, 0x8D, 0x9C, 0x24, 0x80, 0x14, 0x00, 0x00};
constexpr uint8_t kGuideEntry3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41,
                                       0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x40, 0xF8,
                                       0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC0, 0x08, 0x00, 0x00};
constexpr uint8_t kGuideBytes3527[] = {0x4D, 0x8B, 0xF8, 0x48, 0x8B, 0xF9, 0xB8, 0xFF, 0xFF, 0x00, 0x00};
constexpr uint8_t kGuideOut3527[] = {0x48, 0x8B, 0x9C, 0x24, 0x00, 0x09, 0x00, 0x00};
// rva 0: not ported to this build (no hook; the install line lists it).
constexpr FnPoint kFnPoints3527[] = {
    {Fn::SetQuestDialogAICategory, 0, 0, {}, ProcAt::Rcx},
    {Fn::TimelineEvent, 0x2205B3D, 6, kTimelineBytes, ProcAt::Rcx, 0x2205B10, kTimelineEntry3527, 0x220635C, kTimelineOut3527,
     0x827, 0xD063F9066506293F},
    {Fn::TimelineEventEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::BlockInteraction, 0, 0, {}, ProcAt::CtxRdx},
    {Fn::SetInteraction, 0, 0, {}, ProcAt::CtxRdx},
    {Fn::InputBlock, 0x6A100E, 7, kInputBytes3527, ProcAt::Rcx, 0x6A1000, kInputEntry3527, 0x6A103F, kInputOut3527, 0x36,
     0xCC1E2F50EC42C62A},
    {Fn::UIControl, 0x6A1065, 6, kUiControlBytes3527, ProcAt::Rcx, 0x6A1050, kUiControlEntry3527, 0x6A11C9, kUiControlOut3527,
     0x16C, 0xE5701AEEBDF3C4E3},
    {Fn::ChangePhasePanelTag, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIShowMinimap, 0x6A9CFE, 6, kMinimapBytes3527, ProcAt::Rcx, 0x6A9CB0, kMinimapEntry3527, 0x6AA74F, kMinimapOut3527,
     0xA59, 0xA0BFB755540B5206},
    {Fn::UIFindPath, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIStageIcon, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIStageGuide, 0x6B0FBF, 6, kGuideBytes3527, ProcAt::Rcx, 0x6B0FA0, kGuideEntry3527, 0x6B1543, kGuideOut3527, 0x58C,
     0x4C4AB7A83A4AB270},
    {Fn::UIStageBackgroundGuide, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIHint, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIHintEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactiveSequencerCamera, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactiveSequencerCameraEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::SequencerCamera, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeIn, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeInEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::CameraPreset, 0, 0, {}, ProcAt::Rcx},
    {Fn::CameraPresetEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::ForceLockOn, 0, 0, {}, ProcAt::Rcx},
    {Fn::LetterBox, 0, 0, {}, ProcAt::Rcx},
    {Fn::FadeInOut, 0, 0, {}, ProcAt::Rcx},
    {Fn::LookAt, 0, 0, {}, ProcAt::Rcx},
    {Fn::LookAtEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::PostProcess, 0, 0, {}, ProcAt::Rcx},
};
static_assert(std::size(kFnPoints3527) == kFns);
constexpr bool fn_points_3527_in_order() {
    for (size_t i = 0; i < kFns; ++i) {
        if (static_cast<size_t>(kFnPoints3527[i].fn) != i) return false;
    }
    return true;
}
static_assert(fn_points_3527_in_order(), "kFnPoints3527 follows gxv::Fn (the hook callbacks index it)");
constexpr uintptr_t kVtStageManager3527 = 0x59572E0;  // pa::ClientSequencerStageManager (rtti_3527.json)

// Build 3576 (static, 2026-11-06 evening; not yet run). Every handler moved as a whole function (+0x660; TimelineEvent
// +0xC40): the entry, hook and way-out bytes are 3527's (the minimap's entry but its __chkstk rel32), the spans have the
// same lengths, and their hashes differ only by the rel32 / RIP displacements inside them (InputBlock's 0x36 bytes read:
// its one call 0xBA4110 is the only difference). V1 moved by +0x660 with the same bytes. UIControl's way out loads
// 0x5AC58E0 (0x6A179B lea rax,[rip+0x542413E]).
constexpr uintptr_t kV1Entry3576 = 0x6B0470, kV1Point3576 = 0x6B0497, kV1Out3576 = 0x6B1137;
constexpr uintptr_t kUiControlRaxRva3576 = 0x5AC58E0;
constexpr uintptr_t kVtStageManager3576 = 0x5959438;  // vtable_map_3549_3576.json
constexpr uint8_t kMinimapEntry3576[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0xEC, 0xFF, 0xFF, 0xB8, 0x80, 0x14, 0x00, 0x00, 0xE8, 0x59, 0xE0, 0x4F,
    0x04, 0x48, 0x2B, 0xE0, 0xC5, 0xF8, 0x29, 0xB4, 0x24, 0x70, 0x14, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0xBC, 0x24, 0x60,
    0x14, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x84, 0x24, 0x50, 0x14, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x8C, 0x24, 0x40, 0x14,
    0x00, 0x00};
constexpr FnPoint kFnPoints3576[] = {
    {Fn::SetQuestDialogAICategory, 0, 0, {}, ProcAt::Rcx},
    {Fn::TimelineEvent, 0x220677D, 6, kTimelineBytes, ProcAt::Rcx, 0x2206750, kTimelineEntry3527, 0x2206F9C, kTimelineOut3527,
     0x827, 0x63E24A8F015A0750},
    {Fn::TimelineEventEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::BlockInteraction, 0, 0, {}, ProcAt::CtxRdx},
    {Fn::SetInteraction, 0, 0, {}, ProcAt::CtxRdx},
    {Fn::InputBlock, 0x6A166E, 7, kInputBytes3527, ProcAt::Rcx, 0x6A1660, kInputEntry3527, 0x6A169F, kInputOut3527, 0x36,
     0x51B91D24719C88E8},
    {Fn::UIControl, 0x6A16C5, 6, kUiControlBytes3527, ProcAt::Rcx, 0x6A16B0, kUiControlEntry3527, 0x6A1829, kUiControlOut3527,
     0x16C, 0x564A282DC7CBF3C4},
    {Fn::ChangePhasePanelTag, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIShowMinimap, 0x6AA35E, 6, kMinimapBytes3527, ProcAt::Rcx, 0x6AA310, kMinimapEntry3576, 0x6AADAF, kMinimapOut3527,
     0xA59, 0x11216A53D80FA7A8},
    {Fn::UIFindPath, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIStageIcon, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIStageGuide, 0x6B161F, 6, kGuideBytes3527, ProcAt::Rcx, 0x6B1600, kGuideEntry3527, 0x6B1BA3, kGuideOut3527, 0x58C,
     0x7AE9E078B55C2E68},
    {Fn::UIStageBackgroundGuide, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIHint, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIHintEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactiveSequencerCamera, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactiveSequencerCameraEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::SequencerCamera, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeIn, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeInEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::CameraPreset, 0, 0, {}, ProcAt::Rcx},
    {Fn::CameraPresetEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::ForceLockOn, 0, 0, {}, ProcAt::Rcx},
    {Fn::LetterBox, 0, 0, {}, ProcAt::Rcx},
    {Fn::FadeInOut, 0, 0, {}, ProcAt::Rcx},
    {Fn::LookAt, 0, 0, {}, ProcAt::Rcx},
    {Fn::LookAtEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::PostProcess, 0, 0, {}, ProcAt::Rcx},
};
static_assert(std::size(kFnPoints3576) == kFns);

// Build 1.0.0.3663 (static, 2026-11-13; never run). The handlers are the client processor vtable's (0x5997A38 by RTTI)
// slots +0x158 / +0x160 / +0x170 / +0x220 / +0x240, TimelineEvent the jmp of StageChart_Function_TimelineEvent's vf8
// 0x25CF5C0 (vtable 0x5DC1108). No branch lands in any patch (rel8 sweep of each function, rel32 scan of both code
// sections). The span hashes below are the 3663 bytes'.
//   V1 Loading 0x6DC360 (.pdata to 0x6DD04D, 5 bytes longer than 3527's): kV1EntryBytes3527 / kV1Bytes3527 /
//     kV1OutBytes3527 identical at +0x0 / +0x27 / +0xCCC (3527: +0xCC7; the entry and the epilogue are anchors of
//     anchors_3663.json); the 8 jumps to the epilogue are still there (0x6DC3BC ... 0x6DCFB9).
//   TimelineEvent 0x22758F0 (.pdata to 0x227617C): entry, hook (+0x2D) and way out (+0x84C) with 3527's bytes, span 0x827;
//     the path read: 0x227592A cmp [r14],0 ; je 0x2275CA6 -> [[r8+0x38]] null / empty -> 0x227613C (3527's replay).
//   InputBlock 0x6CD560: 3527's bytes, span 0x36; with its one rel32 put back to 3576's target 0xBA4110 the span hashes
//     exactly kFnPoints3576's 0x51B91D24719C88E8 (the rest of the span is 3576's byte for byte).
//   UIControl 0x6CD5B0: 3527's bytes, span 0x16C; the refused path 0x6CD5E0 (try-lock 0x2297780) -> 0x6CD69B lea rax,
//     [rip+0x547295E] (= exe+0x5B40000) -> 0x6CD729.
//   UIShowMinimap 0x6D61A0 (.pdata to 0x6D6C55): RECOMPILED with a smaller frame (rbp = rsp-0x1330, 0x1430 allocated):
//     the hook bytes (mov r13,r8 ; mov rdi,rdx ; mov rsi,rcx) are 3527's, the entry and the way out are new; the refused
//     path 0x6D6201 / 0x6D620B je 0x6D6C22 = the epilogue (lea r11,[rsp+0x1430]), span 0xA3C.
//   UIStageGuide 0x6DD4F0 (.pdata to 0x6DDABE): entry with 3527's bytes, but the hook is 2976's register choice again
//     (mov r14,r8 ; mov rbx,rcx ; mov eax,0xFFFF = kGuideBytes) and the way out moved to +0x5B3 (0x6DDAA3, 3527's bytes);
//     the same three tests jump there (0x6DD526 / 0x6DD531); span 0x59C. replay_way_out takes 2976's registers here.
constexpr uintptr_t kV1Entry3663 = 0x6DC360, kV1Point3663 = 0x6DC387, kV1Out3663 = 0x6DD02C;
constexpr uintptr_t kUiControlRaxRva3663 = 0x5B40000;  // 0x6CD69B lea rax,[rip+0x547295E]
constexpr uintptr_t kVtStageManager3663 = 0x59D57E8;   // pa::ClientSequencerStageManager (vtable_map_3576_3663.json)
constexpr uint8_t kMinimapEntry3663[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0xD0, 0xEC, 0xFF, 0xFF, 0xB8, 0x30, 0x14, 0x00, 0x00, 0xE8, 0x09, 0xE8, 0x54,
    0x04, 0x48, 0x2B, 0xE0, 0xC5, 0xF8, 0x29, 0xB4, 0x24, 0x20, 0x14, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0xBC, 0x24, 0x10,
    0x14, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x84, 0x24, 0x00, 0x14, 0x00, 0x00, 0xC5, 0x78, 0x29, 0x8C, 0x24, 0xF0, 0x13,
    0x00, 0x00};
constexpr uint8_t kMinimapOut3663[] = {0x4C, 0x8D, 0x9C, 0x24, 0x30, 0x14, 0x00, 0x00};  // lea r11,[rsp+0x1430]
constexpr FnPoint kFnPoints3663[] = {
    {Fn::SetQuestDialogAICategory, 0, 0, {}, ProcAt::Rcx},
    {Fn::TimelineEvent, 0x227591D, 6, kTimelineBytes, ProcAt::Rcx, 0x22758F0, kTimelineEntry3527, 0x227613C, kTimelineOut3527,
     0x827, 0x1A6A2803039C0874},
    {Fn::TimelineEventEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::BlockInteraction, 0, 0, {}, ProcAt::CtxRdx},
    {Fn::SetInteraction, 0, 0, {}, ProcAt::CtxRdx},
    {Fn::InputBlock, 0x6CD56E, 7, kInputBytes3527, ProcAt::Rcx, 0x6CD560, kInputEntry3527, 0x6CD59F, kInputOut3527, 0x36,
     0x2386ED143A237F54},
    {Fn::UIControl, 0x6CD5C5, 6, kUiControlBytes3527, ProcAt::Rcx, 0x6CD5B0, kUiControlEntry3527, 0x6CD729, kUiControlOut3527,
     0x16C, 0xB6422D722C907FFE},
    {Fn::ChangePhasePanelTag, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIShowMinimap, 0x6D61EE, 6, kMinimapBytes3527, ProcAt::Rcx, 0x6D61A0, kMinimapEntry3663, 0x6D6C22, kMinimapOut3663,
     0xA3C, 0xFB93C0A7B7BEAE3B},
    {Fn::UIFindPath, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIStageIcon, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIStageGuide, 0x6DD50F, 6, kGuideBytes, ProcAt::Rcx, 0x6DD4F0, kGuideEntry3527, 0x6DDAA3, kGuideOut3527, 0x59C,
     0x2932D3CD3C14D0D7},
    {Fn::UIStageBackgroundGuide, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIHint, 0, 0, {}, ProcAt::Rcx},
    {Fn::UIHintEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactiveSequencerCamera, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactiveSequencerCameraEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::SequencerCamera, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeIn, 0, 0, {}, ProcAt::Rcx},
    {Fn::DeactivateSequencerCameraFadeInEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::CameraPreset, 0, 0, {}, ProcAt::Rcx},
    {Fn::CameraPresetEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::ForceLockOn, 0, 0, {}, ProcAt::Rcx},
    {Fn::LetterBox, 0, 0, {}, ProcAt::Rcx},
    {Fn::FadeInOut, 0, 0, {}, ProcAt::Rcx},
    {Fn::LookAt, 0, 0, {}, ProcAt::Rcx},
    {Fn::LookAtEnd, 0, 0, {}, ProcAt::Rcx},
    {Fn::PostProcess, 0, 0, {}, ProcAt::Rcx},
};
static_assert(std::size(kFnPoints3663) == kFns);
constexpr bool fn_points_3663_in_order() {
    for (size_t i = 0; i < kFns; ++i) {
        if (static_cast<size_t>(kFnPoints3663[i].fn) != i) return false;
    }
    return true;
}
static_assert(fn_points_3663_in_order(), "kFnPoints3663 follows gxv::Fn (the hook callbacks index it)");

constexpr uintptr_t kVtStageManager = 0x55C9720;  // pa::ClientSequencerStageManager (RTTI)
constexpr uint32_t kProc_Mgr = 0x08, kProc_Stage = 0x10, kStage_Key = 0x30;
constexpr uint32_t kMgr_Actor = 0x18, kActor_Key = 0x60;
// The stage's data and name ([[[proc+0x10]+0x48]+0x1B8], as SetInteraction 0x2369410 reads it) and, for the two
// interaction functions, the processor from their context rdx ([[rdx]+0x58], as every vf8 wrapper reads it).
constexpr uint32_t kStage_Data = 0x48, kData_Name = 0x1B8, kCtx_Stage = 0x00, kStage_Proc = 0x58;
constexpr uint32_t kReq_Type = 0x18, kReq_Sub = 0x19;  // 0x778AB0's request: type -> P+0x1DD, +0x19 -> P+0x1DE

uintptr_t g_base = 0;
// The build and what depends on it: written by guest_x_veto_start before any hook or thread.
bool g_3527 = false;  // 3527's layout (3527, 3549, 3576, 3663)
bool g_3576 = false;  // 3576's addresses
bool g_3663 = false;  // 3663's addresses
const FnPoint* g_points = kFnPoints;
uintptr_t g_vt_mgr = kVtStageManager;
uintptr_t g_world_slot = off::kWorldSystemSlot;
uint32_t g_stage_data = kStage_Data, g_stage_proc = kStage_Proc;  // 3527: +0x50, +0x60
std::atomic<bool> g_started{false};
// The keys: g_cam = guest_x_camera_veto as asked (Off when not installed), g_camera_asked the raw value for the log.
std::atomic<uint8_t> g_stage{0}, g_cam{0}, g_camera_asked{0}, g_ui{0};
std::atomic<bool> g_v1_on{false}, g_v0_on{false}, g_clear_on{false};
SafetyHookMid g_v1_hook, g_clear_hook;
SafetyHookInline g_v0_hook;
uint16_t g_v0_mark = 0;  // freeze_watchdog's id for V0 (set before the hook is enabled)
SafetyHookMid g_fn_hooks[kFns];
std::atomic<bool> g_fn_on[kFns] = {};
std::atomic<uint8_t> g_fn_mode[kFns] = {};  // gxv::fn_mode, downgraded to probe if its way out did not verify
std::atomic<gxv::FnSet> g_allow{0};         // guest_x_ui_veto_allow (gxv::parse_allow): these run natively for X

thread_local gxv::ContextSlot t_ctx;

// The current M (review 4): the last vf48 result of this client's field seen on the main thread (guest_seq_play's
// frame hook, guest_seq_route's handlers) with its live owner; trusted for kMFreshUs and this connection only.
std::atomic<uint64_t> g_m{0}, g_m_us{0}, g_m_epoch{~0ull};
std::atomic<uint32_t> g_m_key{0};
constexpr uint64_t kMFreshUs = 2'000'000;

std::atomic<uint64_t> g_v1_calls{0}, g_v1_vetoed{0}, g_v1_would{0}, g_v1_own_m{0};
std::atomic<uint64_t> g_v1_verdicts[static_cast<size_t>(Verdict::Count)] = {};
std::atomic<uint64_t> g_v0_calls{0}, g_v0_in_ctx{0}, g_v0_would{0}, g_v0_stale{0};
std::atomic<uint64_t> g_ctx_2981{0}, g_ctx_cleared{0}, g_ctx_kept{0}, g_ctx_entry_clear{0};
// Per handler: calls, run with G = X (another character's manager), with G = the own M, vetoed, would veto, allowed
// (guest_x_ui_veto_allow: ran natively for X), and for the two with a direction (gxv::fn_dir) X's calls on / off.
std::atomic<uint64_t> g_fn_calls[kFns] = {}, g_fn_x[kFns] = {}, g_fn_m[kFns] = {}, g_fn_vetoed[kFns] = {},
                      g_fn_would[kFns] = {}, g_fn_allowed[kFns] = {}, g_fn_x_on[kFns] = {}, g_fn_x_off[kFns] = {};

enum Kind : uint16_t { kEV1, kEV0, kEFn, kKindCount };
p::EventRing<256> g_ring;
p::WindowLimiter g_lim[kKindCount] = {{16, 5'000'000}, {16, 5'000'000}, {32, 5'000'000}};
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

// Whose stage manager runs this processor's function (gxv::judge).
gxv::Facts facts_of(uintptr_t proc) noexcept {
    gxv::Facts f;
    f.remote = guest_remote_live();
    if (!f.remote) return f;
    f.g = rdp(proc + kProc_Mgr);
    f.want_vt = g_base + g_vt_mgr;
    if (!f.g) return f;
    f.g_vt = rdp(f.g);
    if (f.g_vt != f.want_vt) return f;
    const uintptr_t actor = rdp(f.g + kMgr_Actor);
    f.g_key = actor ? rdv<uint32_t>(actor + kActor_Key) : 0;
    f.own_key = guest_seq_route_own_key();
    const uint64_t now = p8_now_us(), m_us = g_m_us.load(std::memory_order_relaxed);
    if (g_m_epoch.load(std::memory_order_relaxed) == guest_connection_epoch() && now >= m_us && now - m_us <= kMFreshUs) {
        f.m = g_m.load(std::memory_order_relaxed);
        f.m_key = g_m_key.load(std::memory_order_relaxed);
    }
    f.in_table = f.g_key && guest_seq_play_knows_x(f.g, f.g_key);
    return f;
}

void fill(p::Event& e, uintptr_t proc, const gxv::Facts& f, Verdict v, Act a) noexcept {
    e.v[0] = static_cast<uint64_t>(v) | static_cast<uint64_t>(a) << 8;
    e.v[1] = proc;
    e.v[2] = f.g;
    e.v[3] = f.g_key | static_cast<uint64_t>(f.own_key) << 32;
    e.v[4] = static_cast<uint64_t>(f.in_table ? 1 : 0) | static_cast<uint64_t>(f.m_key) << 32;
    e.v[8] = f.m;
    const uintptr_t stage = rdp(proc + kProc_Stage);
    e.v[5] = stage;
    e.v[6] = stage ? rdv<uint64_t>(stage + kStage_Key) : 0;
}

// V1: 0x5F2A3A, right after Loading's gate. RAX := 0 takes the native gate-refused path (the gate itself returns a
// bool in AL: 0x204F7D7 xor al,al / 0x204F7F5 mov al,1; RAX = 0 is one of the values the native path can carry).
void on_v1(safetyhook::Context& ctx) noexcept {
    if (!g_v1_on.load(std::memory_order_acquire)) return;
    if ((ctx.rax & 0xFF) == 0) return;  // the gate already refused: nothing would happen
    g_v1_calls.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t proc = ctx.r14;
    const gxv::Facts f = facts_of(proc);
    const Verdict v = gxv::judge(f);
    g_v1_verdicts[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    const Act a = gxv::act(static_cast<Mode>(g_stage.load(std::memory_order_relaxed)), v);
    if (v == Verdict::OwnManager) g_v1_own_m.fetch_add(1, std::memory_order_relaxed);
    if (a == Act::None) return;
    if (a == Act::Veto) {
        ctx.rax = 0;  // je 0x5F35D7: the epilogue, the handler returns 0
        g_v1_vetoed.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_v1_would.fetch_add(1, std::memory_order_relaxed);
    }
    p::Event e;
    fill(e, proc, f, v, a);
    emit(kEV1, e);
}

// V1 on 1.0.0.3527: 0x6AFE37, the handler's first instructions after its prologue (see kV1Point3527). There is no gate to
// follow: a veto resumes at the epilogue 0x6B0AD7 and the handler returns having done nothing.
void on_v1_3527(safetyhook::Context& ctx) noexcept {
    if (!g_v1_on.load(std::memory_order_acquire)) return;
    g_v1_calls.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t proc = ctx.rcx;
    const gxv::Facts f = facts_of(proc);
    const Verdict v = gxv::judge(f);
    g_v1_verdicts[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    const Act a = gxv::act(static_cast<Mode>(g_stage.load(std::memory_order_relaxed)), v);
    if (v == Verdict::OwnManager) g_v1_own_m.fetch_add(1, std::memory_order_relaxed);
    if (a == Act::None) return;
    if (a == Act::Veto) {
        ctx.rip = g_base + (g_3663 ? kV1Out3663 : g_3576 ? kV1Out3576 : kV1Out3527);
        g_v1_vetoed.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_v1_would.fetch_add(1, std::memory_order_relaxed);
    }
    p::Event e;
    fill(e, proc, f, v, a);
    emit(kEV1, e);
}

// V0: 0x778AB0(P, req). Never skips (review 2, gxv::v0_effective): neither P (one global object) nor the request
// names the stage that asked; a call from inside an X context is counted and logged. V1 is the veto.
void __fastcall v0_detour(uintptr_t pobj, uintptr_t req) noexcept {
    const FreezeMark mark(g_v0_mark);  // freeze_watchdog: this thread is in V0 (0 = off: nothing)
    g_v0_calls.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t here = reinterpret_cast<uintptr_t>(_AddressOfReturnAddress());
    const uint64_t x = t_ctx.get().x;
    bool was_stale = false;
    const bool in = t_ctx.check(here, p8_now_us(), &was_stale);
    if (was_stale) g_v0_stale.fetch_add(1, std::memory_order_relaxed);
    if (in && guest_remote_live()) {
        g_v0_in_ctx.fetch_add(1, std::memory_order_relaxed);
        if (gxv::act(gxv::v0_effective(static_cast<Mode>(g_stage.load(std::memory_order_relaxed))), Verdict::Veto) !=
            Act::None) {
            g_v0_would.fetch_add(1, std::memory_order_relaxed);
            p::Event e;
            e.v[0] = static_cast<uint64_t>(Act::Would);
            e.v[1] = x;
            e.v[2] = pobj;
            e.v[3] = rdv<uint8_t>(req + kReq_Type) | static_cast<uint64_t>(rdv<uint8_t>(req + kReq_Sub)) << 8;
            e.v[4] = reinterpret_cast<uintptr_t>(_ReturnAddress()) - g_base;
            emit(kEV0, e);
        }
    }
    g_v0_hook.unsafe_call<void>(pobj, req);
}

// 0xC07776: the routed 2981's call 0xA9E100 returned. Clears a context set at this frame or deeper (rsp >= its sp;
// the routed 2981's own is set at the same rsp at 0xC07749); a context of a frame above (a scope) is kept.
void on_clear(safetyhook::Context& ctx) noexcept {
    if (t_ctx.get().x == 0) return;
    if (t_ctx.clear_at(ctx.rsp)) {
        g_ctx_cleared.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_ctx_kept.fetch_add(1, std::memory_order_relaxed);
    }
}

// The register writes of each vetoable handler's native refused path, from the hook to its way out (p8-s10.md §4.6),
// so the way out runs with the registers it would have natively. Callee-saved ones are popped by the epilogue anyway;
// volatile ones set by the path's own calls are left (the dispatch sites never read rax, §4.6). Writes the path makes
// to the frame's locals / home slots are not replayed: the way out and the epilogue read none of them.
void replay_way_out(gxv::Fn fn, safetyhook::Context& ctx) noexcept {
    using gxv::Fn;
    switch (fn) {
        case Fn::TimelineEvent:  // 0x204BBBD mov rsi,r8 ; mov rbx,rdx ; mov r12,rcx ; lea r14,[r8+0x30] ; ...
            ctx.rsi = ctx.r8;    // 0x204BF3E lea rax,[r8+0x38] ; ... ; mov rax,[rax] ; mov rcx,[rax]
            ctx.rbx = ctx.rdx;
            ctx.r12 = ctx.rcx;
            ctx.r14 = ctx.r8 + 0x30;
            ctx.rax = rdv<uint64_t>(ctx.r8 + 0x38);
            ctx.rcx = rdv<uint64_t>(ctx.rax);
            break;
        case Fn::SetInteraction:  // 0x236938A movzx r13d,r8b ; mov rsi,rdx ; mov r14,rcx ; xor eax,eax ; mov r15d,eax ;
            ctx.r13 = ctx.r8 & 0xFF;  // lea rbx,[rcx+0x20] ; call 0x2049B90 (al = 0) ; mov r12d,[rbp-0x80] (0) ;
            ctx.rbx = ctx.rcx + 0x20;  // mov rdi,[rsp+0x78] (0) ; 0x23693D3 xor r14d,r14d ; ... ; 0x23694C0 mov esi,0x1FD
            ctx.r15 = 0;
            ctx.r12 = 0;
            ctx.rdi = 0;
            ctx.r14 = 0;  // read by the way out: 0x23698C6 mov [rsp+0x78],r14
            ctx.rsi = 0x1FD;
            ctx.rax = 0;  // the lookup's refused al (the warning / free calls after it leave theirs)
            break;
        case Fn::InputBlock:  // 0x5E4E6E cmp ; je 0x5E4E9F: eax = func[0x21] since 0x5E4E64, nothing else written
            break;
        case Fn::UIControl:  // 0x5E4EC5 mov rbp,r8 ; mov rbx,rdx ; mov r14,rcx ; xor edi,edi ; ... call 0x206AE30 (fails)
            ctx.rbp = ctx.r8;  // 0x5E4F95 lea rax,[rip+0x5140EAC]
            ctx.rbx = ctx.rdx;  // 3527: the same, 0x6A1065; the try-lock is 0x2227820, the lea 0x6A113B
            ctx.r14 = ctx.rcx;
            ctx.rdi = 0;
            ctx.rax = g_base + (g_3663   ? kUiControlRaxRva3663
                                : g_3576 ? kUiControlRaxRva3576
                                : g_3527 ? kUiControlRaxRva3527
                                         : kUiControlRaxRva);
            break;
        case Fn::UIShowMinimap:  // 0x5ECDDE mov r13,r8 ; mov rdi,rdx ; mov r14,rcx ; mov rax,[r8+0x20] ; mov r9,[rax]
            ctx.r13 = ctx.r8;  // 3527: 0x6A9CFE mov r13,r8 ; mov rdi,rdx ; mov rsi,rcx ; the same two reads
            ctx.rdi = ctx.rdx;
            (g_3527 ? ctx.rsi : ctx.r14) = ctx.rcx;
            ctx.rax = rdv<uint64_t>(ctx.r8 + 0x20);
            ctx.r9 = rdv<uint64_t>(ctx.rax);
            break;
        case Fn::UIStageGuide:  // 0x5F3AAF mov r14,r8 ; mov rbx,rcx ; mov eax,0xFFFF ; cmp ... ; jcc 0x5F4031
            // 3663: 0x6DD50F mov r14,r8 ; mov rbx,rcx (2976's registers again) ; jcc 0x6DDAA3
            if (g_3527 && !g_3663) {  // 0x6B0FBF mov r15,r8 ; mov rdi,rcx ; mov eax,0xFFFF ; cmp ... ; jcc 0x6B1543
                ctx.r15 = ctx.r8;
                ctx.rdi = ctx.rcx;
            } else {
                ctx.r14 = ctx.r8;
                ctx.rbx = ctx.rcx;
            }
            ctx.rax = 0xFFFF;
            break;
        default:
            break;
    }
}

// guest_x_ui_veto: one callback per handler (gxv::Fn). Counts every call by whose manager runs it; with '1' and a
// vetoable handler whose way out verified, a call for X is forced to that native way out (replay_way_out, rip). A
// handler of guest_x_ui_veto_allow is never touched (both directions run natively) and its X calls are logged ALLOWED.
template <size_t I>
void on_fn(safetyhook::Context& ctx) noexcept {
    if (!g_fn_on[I].load(std::memory_order_acquire)) return;
    const FnPoint& pt = g_points[I];
    g_fn_calls[I].fetch_add(1, std::memory_order_relaxed);
    const uintptr_t proc = pt.proc == ProcAt::Rcx ? ctx.rcx : rdp(rdp(ctx.rdx + kCtx_Stage) + g_stage_proc);
    const gxv::Facts f = facts_of(proc);
    const Verdict v = gxv::judge(f);
    const gxv::Dir dir = gxv::fn_dir(pt.fn, ctx.r8);
    switch (gxv::who(v)) {
        case gxv::Who::X:
            g_fn_x[I].fetch_add(1, std::memory_order_relaxed);
            guest_x_interaction_note_x(f.g, f.g_key);  // C1 (guest_x_interaction.h): a known X (no-op when off)
            guest_seq_present_x_fn(I, proc);  // S45 S-A2 (read-only; one atomic load when off: it reads proc+0x10 itself)
            if (dir == gxv::Dir::On) g_fn_x_on[I].fetch_add(1, std::memory_order_relaxed);
            if (dir == gxv::Dir::Off) g_fn_x_off[I].fetch_add(1, std::memory_order_relaxed);
            break;
        case gxv::Who::M:
            g_fn_m[I].fetch_add(1, std::memory_order_relaxed);
            if (pt.fn == Fn::InputBlock) guest_shop_window_on_scene();  // its own shop scene's UI phase
            break;
        case gxv::Who::Other: break;
    }
    // guest_shop_branch: while this client has a shop of the host's world open locally, the host scenes' UI handlers
    // run (the shop's menu and window are UIControl events of that scene).
    const bool allowed = gxv::fn_in(g_allow.load(std::memory_order_relaxed), pt.fn) ||
                         (gxv::who(v) == gxv::Who::X && guest_shop_open_now());
    const Act a = gxv::fn_act(static_cast<Mode>(g_fn_mode[I].load(std::memory_order_relaxed)), allowed, v);
    if (a == Act::None) return;
    Act done = Act::Would;
    if (a == Act::Allow) {
        done = Act::Allow;  // the handler runs natively: nothing written to ctx
        g_fn_allowed[I].fetch_add(1, std::memory_order_relaxed);
    } else if (a == Act::Veto && pt.resume != 0) {
        replay_way_out(pt.fn, ctx);
        ctx.rip = g_base + pt.resume;  // forced to the native way out (same frame); the hooked instructions never run
        done = Act::Veto;
        g_fn_vetoed[I].fetch_add(1, std::memory_order_relaxed);
    } else {
        g_fn_would[I].fetch_add(1, std::memory_order_relaxed);
    }
    p::Event e;
    fill(e, proc, f, v, done);
    e.v[0] |= static_cast<uint64_t>(dir) << 16;
    e.v[7] = I;
    // The stage's name, [[[proc+0x10]+0x48]+0x1B8] (a char*), up to 24 bytes.
    const uintptr_t data = rdp(rdp(proc + kProc_Stage) + g_stage_data);
    const uintptr_t name = data ? rdp(data + kData_Name) : 0;
    for (size_t k = 0; name && k < 3 && rd(name + 8 * k, e.v[9 + k]); ++k) {
    }
    emit(kEFn, e);
}
template <size_t... I>
constexpr std::array<safetyhook::MidHookFn, sizeof...(I)> fn_fns(std::index_sequence<I...>) {
    return {&on_fn<I>...};
}
constexpr auto kFnFns = fn_fns(std::make_index_sequence<kFns>{});

// ---------------------------------------------------------------- lines (diagnostics thread)

std::string line_of(const p::Event& e) {
    const uint64_t* v = e.v;
    const std::string when = p8_when(e.qpc_us);
    const auto verdict = static_cast<Verdict>(v[0] & 0xFF);
    const auto a = static_cast<Act>((v[0] >> 8) & 0xFF);
    switch (e.kind) {
        case kEV1:
            return std::format("GuestXVeto [Loading] {} T{} | {} the stage chart function Loading (0x5F2A00) of manager "
                               "0x{:X} (character 0x{:08X}; own 0x{:08X}; current M 0x{:X} of 0x{:08X}; in the XTable "
                               "{}): {} | processor 0x{:X}, stage 0x{:X} (key 0x{:X}) | {}",
                               when, e.tid, a == Act::Veto ? "VETOED" : "WOULD VETO (probe)", v[2],
                               static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[3] >> 32), v[8],
                               static_cast<uint32_t>(v[4] >> 32), v[4] & 1 ? "yes" : "no",
                               gxv::verdict_name(verdict), v[1], v[5], v[6],
                               a == Act::Veto ? "AL=0: the handler takes its gate-refused path; no reload, no "
                                                "GameLoadingStartReq of this client"
                                              : "this client will start its own field reload now (session 9)");
        case kEV0:
            return std::format("GuestXVeto [0x778AB0] {} T{} | {} a load request inside the X context (X 0x{:X}): P 0x{:X}, "
                               "request type {} / {}, called from exe+0x{:X} (V0 counts only; V1 is the veto)",
                               when, e.tid, "WOULD SKIP", v[1],
                               v[2], v[3] & 0xFF, (v[3] >> 8) & 0xFF, v[4]);
        case kEFn: {
            const auto fn = static_cast<gxv::Fn>(v[7] < gxv::kFns ? v[7] : 0);
            const gxv::FnInfo info = gxv::fn_info(fn);
            char name[32];
            gxv::stage_name(v + 9, 3, name, sizeof name);
            const auto dir = static_cast<gxv::Dir>((v[0] >> 16) & 0xFF);
            const char* what = a == Act::Veto    ? "VETOED (forced to the native way out)"
                               : a == Act::Allow ? "ALLOWED (guest_x_ui_veto_allow: runs natively)"
                                                 : "WOULD VETO (probe)";
            return std::format("GuestXVeto [{}] {} T{} | {} {}{}{} of manager 0x{:X} (character 0x{:08X}; own 0x{:08X}; "
                               "current M 0x{:X} of 0x{:08X}; in the XTable {}): {} | stage '{}' 0x{:X} (key 0x{:X}), "
                               "processor 0x{:X}{}",
                               gxv::family_name(info.family), when, e.tid, what, info.name,
                               dir == gxv::Dir::None ? "" : " ", gxv::dir_name(fn, dir), v[2],
                               static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[3] >> 32), v[8],
                               static_cast<uint32_t>(v[4] >> 32), v[4] & 1 ? "yes" : "no", gxv::verdict_name(verdict),
                               name, v[5], v[6], v[1],
                               a != Act::Would || info.vetoable ? "" : " | not vetoable: stays a probe even with 1");
        }
        default:
            return std::format("GuestXVeto: event {}?", e.kind);
    }
}

uint64_t g_tick_n = 0;  // diagnostics thread only

void summary() {
    std::string verdicts;
    for (size_t k = 0; k < static_cast<size_t>(Verdict::Count); ++k) {
        if (const uint64_t n = g_v1_verdicts[k].load()) {
            verdicts += std::format(" {} x{};", gxv::verdict_name(static_cast<Verdict>(k)), n);
        }
    }
    // Per handler that ran: G = X (with SetInteraction's / BlockInteraction's on / off) / own M / calls, then what was
    // done (VETOED, ALLOWED) or would have been (probe).
    std::string fns;
    size_t fns_on = 0, fns_veto = 0, fns_allowed = 0;
    for (size_t i = 0; i < kFns; ++i) {
        if (!g_fn_on[i].load()) continue;
        ++fns_on;
        if (g_fn_mode[i].load() == static_cast<uint8_t>(Mode::On)) ++fns_veto;
        if (gxv::fn_in(g_allow.load(), static_cast<gxv::Fn>(i))) ++fns_allowed;
        const uint64_t n = g_fn_calls[i].load();
        if (!n) continue;
        const auto fn = static_cast<gxv::Fn>(i);
        fns += std::format(" {} X {}", gxv::fn_info(fn).name, g_fn_x[i].load());
        if (gxv::fn_has_dir(fn)) {
            fns += std::format(" ({} {} / {} {})", gxv::dir_name(fn, gxv::Dir::On), g_fn_x_on[i].load(),
                               gxv::dir_name(fn, gxv::Dir::Off), g_fn_x_off[i].load());
        }
        fns += std::format(" / M {} / {}", g_fn_m[i].load(), n);
        if (const uint64_t vt = g_fn_vetoed[i].load()) fns += std::format(" VETOED {}", vt);
        if (const uint64_t w = g_fn_would[i].load()) fns += std::format(" would {}", w);
        if (const uint64_t al = g_fn_allowed[i].load()) fns += std::format(" ALLOWED {}", al);
        fns += ";";
    }
    log::info("GuestXVeto summary (guest_x_stage_veto={}, guest_x_camera_veto={}{}, guest_x_ui_veto={}): V1 Loading {} | "
              "calls past its gate {}, VETOED {}, would {}, own M {} | verdicts:{} | V0 0x778AB0 {} (count only): calls "
              "{}, inside an X context {}, would skip {}, stale contexts dropped {} | X context: routed 2981 {} (clear "
              "point {}), cleared {}, kept (a frame above) {}, cleared at a routing hook's entry {} | handlers {}/{} "
              "hooked ({} vetoing, {} allowed), G = X / own M / calls:{} | limited {} lost {}",
              gxv::mode_name(static_cast<Mode>(g_stage.load())), gxv::mode_name(static_cast<Mode>(g_camera_asked.load())),
              g_camera_asked.load() == static_cast<uint8_t>(Mode::On) ? " (acts as probe)" : "",
              gxv::mode_name(static_cast<Mode>(g_ui.load())),
              g_v1_on.load() ? "in" : "NOT in", g_v1_calls.load(), g_v1_vetoed.load(), g_v1_would.load(),
              g_v1_own_m.load(), verdicts.empty() ? " none" : verdicts, g_v0_on.load() ? "in" : "NOT in",
              g_v0_calls.load(), g_v0_in_ctx.load(), g_v0_would.load(), g_v0_stale.load(), g_ctx_2981.load(),
              g_clear_on.load() ? "in" : "NOT in (never set)", g_ctx_cleared.load(), g_ctx_kept.load(),
              g_ctx_entry_clear.load(), fns_on, kFns, fns_veto, fns_allowed, fns.empty() ? " none" : fns,
              g_limited.load(), g_lost.load());
}

// ---------------------------------------------------------------- install

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

bool context_ok(std::span<const gad::Section> secs, uintptr_t rva, std::span<const uint8_t> bytes, const char* what) {
    if (gad::in_real_code(secs, static_cast<uint32_t>(rva), static_cast<uint32_t>(bytes.size())) && bytes_at(rva, bytes)) {
        return true;
    }
    log::error("GuestXVeto: {} (exe+0x{:X}, {} bytes) is not this build's .rsrc code; REFUSED", what, rva, bytes.size());
    return false;
}

// The whole hook .. way-out-end span of a vetoable handler (FNV-1a 64 over the read-only PE's bytes, p8-s10.md §4.6):
// the native path the veto replays is exactly build 2976's.
bool span_ok(std::span<const gad::Section> secs, uintptr_t rva, uint32_t len, uint64_t want, const char* what) {
    std::vector<uint8_t> b(len);
    if (len && gad::in_real_code(secs, static_cast<uint32_t>(rva), len) &&
        game::safe_read(g_base + rva, b.data(), b.size())) {
        uint64_t h = 0xCBF29CE484222325ull;
        for (const uint8_t x : b) h = (h ^ x) * 0x100000001B3ull;
        if (h == want) return true;
        log::error("GuestXVeto: {}: the span exe+0x{:X}..0x{:X} hashes 0x{:016X}, not 0x{:016X}; stays a probe", what, rva,
                   rva + len, h, want);
        return false;
    }
    log::error("GuestXVeto: {}: the span exe+0x{:X} ({} bytes) is not readable .rsrc code; stays a probe", what, rva, len);
    return false;
}

bool install_v0(std::span<const gad::Section> secs) {
    if (!context_ok(secs, kV0, kV0Bytes, "0x778AB0's entry")) return false;
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(
        g_base + kV0, reinterpret_cast<void*>(&v0_detour),
        [](const std::vector<uint8_t>& o) {
            return o.size() == kV0Patch && std::memcmp(o.data(), kV0Bytes, kV0Patch) == 0;
        },
        "GuestXVeto", "V0 0x778AB0");
    if (!h) {
        log::error("GuestXVeto: 0x778AB0: the inline hook could not be prepared ({}); REFUSED",
                   game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (orig.size() != kV0Patch || std::memcmp(orig.data(), kV0Bytes, kV0Patch) != 0) {
        log::error("GuestXVeto: 0x778AB0: the hook would patch {} bytes, {} were verified; REFUSED, nothing written",
                   orig.size(), kV0Patch);
        return false;
    }
    g_v0_mark = freeze_watchdog_register("GuestXVeto", "V0 0x778AB0 (detour + the game's original)");
    g_v0_hook = std::move(*h);  // the detour calls through it: in place before enabling
    if (!g_v0_hook.enable()) {
        log::error("GuestXVeto: 0x778AB0: the hook could not be enabled; REFUSED");
        return false;
    }
    return true;
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<gad::Section> secs;
    if (g_base != off::kImageBase || !game::safe_read(g_base, &dos, sizeof dos) ||
        !game::safe_read(g_base + dos.e_lfanew, &nt, sizeof nt) || !(game::legacy_layout() || g_3576 || g_3663) ||
        !p8_exe_sections(g_base, secs)) {
        log::error("GuestXVeto: unsupported game build or unreadable sections; nothing installed");
        return 0;
    }
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other guest modules
        uintptr_t world = 0;
        if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
        Sleep(500);
    }
    std::string stage_line = "off", fn_line = "off";
    if (g_stage.load() != 0 && g_3527) {
        // V1 with the frame it relies on and the whole epilogue it resumes at. V0 and the X context's clear point only
        // counted a load request inside an X context: not ported (V1 is the veto).
        const uintptr_t v1_entry = g_3663 ? kV1Entry3663 : g_3576 ? kV1Entry3576 : kV1Entry3527;
        const uintptr_t v1_point = g_3663 ? kV1Point3663 : g_3576 ? kV1Point3576 : kV1Point3527;
        const uintptr_t v1_out = g_3663 ? kV1Out3663 : g_3576 ? kV1Out3576 : kV1Out3527;
        if (context_ok(secs, v1_entry, kV1EntryBytes3527, "Loading's prologue") &&
            context_ok(secs, v1_out, kV1OutBytes3527, "Loading's epilogue") &&
            p8_install_mid(g_base, secs, v1_point, kV1Patch3527, kV1Bytes3527, on_v1_3527, g_v1_hook, "GuestXVeto",
                           "V1, Loading's first instructions (0x6AFE37 on build 3527)")) {
            g_v1_on.store(true, std::memory_order_release);
        }
        stage_line = std::format("V1 exe+0x{:X} -> exe+0x{:X} {}, V0 and the X context's clear point not ported to build "
                                 "3527 (they only counted)",
                                 v1_point, v1_out, g_v1_on.load() ? "hooked" : "REFUSED");
    } else if (g_stage.load() != 0) {
        // V1 with its context and the epilogue its je reaches.
        if (context_ok(secs, kV1Ctx, kV1CtxBytes, "Loading's gate call") &&
            context_ok(secs, kV1Epilogue, kV1EpilogueBytes, "Loading's epilogue") &&
            p8_install_mid(g_base, secs, kV1, kV1Patch, kV1Bytes, on_v1, g_v1_hook, "GuestXVeto",
                           "V1, Loading's gate test 0x5F2A3A")) {
            g_v1_on.store(true, std::memory_order_release);
        }
        if (install_v0(secs)) g_v0_on.store(true, std::memory_order_release);
        // The clear point first, then the routed 2981 may set the context (guest_x_context_routed_2981).
        if (g_v0_on.load() && context_ok(secs, kClearCtx, kClearCtxBytes, "the 2981's call 0xA9E100") &&
            p8_install_mid(g_base, secs, kClear, kClearPatch, kClearBytes, on_clear, g_clear_hook, "GuestXVeto",
                           "the X context's clear point 0xC07776")) {
            g_clear_on.store(true, std::memory_order_release);
        }
        stage_line = std::format("V1 0x5F2A3A {}, V0 0x778AB0 {}, X context clear point 0xC07776 {}",
                                 g_v1_on.load() ? "hooked" : "REFUSED", g_v0_on.load() ? "hooked" : "REFUSED",
                                 g_clear_on.load() ? "hooked" : "REFUSED (no 2981 context; tick context only)");
    }
    // guest_x_ui_veto (every family) / guest_x_camera_veto (the camera family): one hook per handler.
    const auto ui = static_cast<Mode>(g_ui.load()), cam = static_cast<Mode>(g_cam.load());
    const gxv::FnSet allow = g_allow.load();
    if (ui != Mode::Off || cam != Mode::Off) {
        size_t n = 0, wanted = 0;
        std::string veto, probe, held, refused, allowed, not_ported;
        for (size_t i = 0; i < kFns; ++i) {
            const FnPoint& pt = g_points[i];
            const gxv::FnInfo info = gxv::fn_info(pt.fn);
            const bool is_allowed = gxv::fn_in(allow, pt.fn);
            Mode m = gxv::fn_mode(pt.fn, ui, cam, is_allowed);
            if (m == Mode::Off) continue;
            if (!pt.rva) {  // build 3527: runs natively (R-A cuts it on foreign stages), no hook, no count
                not_ported += std::format(" {}", info.name);
                continue;
            }
            ++wanted;
            // A veto resumes at the native way out: the frame it restores (entry .. hook) and the way out itself must
            // be build 2976's; otherwise this handler is only counted.
            if (m == Mode::On && !(pt.resume && context_ok(secs, pt.entry, pt.entry_bytes, info.name) &&
                                   context_ok(secs, pt.resume, pt.resume_bytes, info.name) &&
                                   span_ok(secs, pt.rva, pt.span_len, pt.span_fnv, info.name))) {
                m = Mode::Probe;
                held += std::format(" {} (way out not verified)", info.name);
            }
            g_fn_mode[i].store(static_cast<uint8_t>(m), std::memory_order_relaxed);
            if (!p8_install_mid(g_base, secs, pt.rva, pt.patch, pt.bytes, kFnFns[i], g_fn_hooks[i], "GuestXVeto",
                                info.name)) {
                refused += std::format(" {}", info.name);
                continue;
            }
            g_fn_on[i].store(true, std::memory_order_release);
            ++n;
            if (m == Mode::On) {
                veto += std::format(" {} (exe+0x{:X} -> 0x{:X})", info.name, pt.rva, pt.resume);
            } else if (is_allowed) {
                allowed += std::format(" {}", info.name);
            } else if (gxv::fn_held_as_probe(pt.fn, ui, is_allowed)) {
                held += std::format(" {}", info.name);
            } else {
                probe += std::format(" {}", info.name);
            }
        }
        fn_line = std::format("{} of {} handlers hooked | veto:{} | allowed (guest_x_ui_veto_allow, both directions run "
                              "natively for X, counted):{} | probe:{} | held as probe although 1 (no native way out "
                              "read whole: .xtls thunk, none, or not verified):{}{}",
                              n, wanted, veto.empty() ? " none" : veto, allowed.empty() ? " none" : allowed,
                              probe.empty() ? " none" : probe, held.empty() ? " none" : held,
                              refused.empty() ? "" : " | REFUSED:" + refused) +
                  (not_ported.empty() ? std::string() : " | not ported to this build, native:" + not_ported);
    }
    log::info("GuestXVeto (guest_x_stage_veto={}, guest_x_camera_veto={}{}, guest_x_ui_veto={}): {} | handlers: {} | "
              "acts only while this connection plays on the host, on a ClientSequencerStageManager (vtable exe+0x{:X}) "
              "that is not this connection's own character's: in guest_seq_play's XTable, or owned by another character",
              gxv::mode_name(static_cast<Mode>(g_stage.load())), gxv::mode_name(static_cast<Mode>(g_camera_asked.load())),
              g_camera_asked.load() == static_cast<uint8_t>(Mode::On) ? " (acts as probe)" : "",
              gxv::mode_name(static_cast<Mode>(g_ui.load())), stage_line, fn_line, g_vt_mgr);
    return 0;
}

}  // namespace

void guest_x_veto_start(const std::string& stage_mode, const std::string& camera_mode, const std::string& ui_mode,
                        const std::string& ui_allow, const std::string& route_mode) {
    g_3576 = game::current_build() == game::Build::v3576;
    g_3663 = game::current_build() == game::Build::v3663;
    g_3527 = game::current_build() == game::Build::v3527 || g_3576 || g_3663;
    if (g_3527) {
        g_points = g_3663 ? kFnPoints3663 : g_3576 ? kFnPoints3576 : kFnPoints3527;
        g_vt_mgr = g_3663 ? kVtStageManager3663 : g_3576 ? kVtStageManager3576 : kVtStageManager3527;
        // [[stage+0x50]+0x1B8]: SetInteraction 0x255D3F0 (3663: 0x25CFA60 / 0x25CFA69, and [stage+0x60] at 0x25CFA87)
        g_stage_data = 0x50;
        g_stage_proc = 0x60;
        if (const auto* profile = game::reader_profile()) g_world_slot = profile->world_system;
        if (g_3576) g_world_slot = 0x71C0100;  // core_globals_3576.json (no reader profile for 3576 yet)
        // Build 1.0.0.3663 (static, 2026-11-13; never run): WorldSystem, profile_s2.h's rva3663().
        if (g_3663) g_world_slot = 0x72451C0;
    }
    bool bad_s = false, bad_c = false, bad_u = false;
    Mode stage = gxv::parse_mode(stage_mode, &bad_s);
    const Mode cam_asked = gxv::parse_mode(camera_mode, &bad_c);
    Mode ui = gxv::parse_mode(ui_mode, &bad_u);
    if (bad_s) log::warn("GuestXVeto: guest_x_stage_veto={} is not 0, probe or 1: off", stage_mode);
    if (bad_c) log::warn("GuestXVeto: guest_x_camera_veto={} is not 0, probe or 1: off", camera_mode);
    if (bad_u) log::warn("GuestXVeto: guest_x_ui_veto={} is not 0, probe or 1: off", ui_mode);
    // guest_x_ui_veto_allow: an unknown name is ignored (the rest still apply) and said once.
    const gxv::AllowList allow = gxv::parse_allow(ui_allow);
    if (allow.bad) {
        log::warn("GuestXVeto: guest_x_ui_veto_allow='{}': {} name(s) of no handler (first '{}'), ignored", ui_allow,
                  allow.bad, allow.first_bad);
    }
    g_allow.store(allow.set);
    Mode cam = cam_asked;  // gxv::fn_mode applies camera_effective
    if ((stage != Mode::Off || cam != Mode::Off || ui != Mode::Off) && gxv::parse_mode(route_mode) != Mode::On) {
        log::info("GuestXVeto: guest_x_stage_veto={} / guest_x_camera_veto={} / guest_x_ui_veto={} not installed: "
                  "guest_seq_route is not 1, so no other character's manager ever gets a stage on this client",
                  stage_mode, camera_mode, ui_mode);
        stage = cam = ui = Mode::Off;
    }
    g_stage.store(static_cast<uint8_t>(stage));
    g_cam.store(static_cast<uint8_t>(cam));
    g_camera_asked.store(static_cast<uint8_t>(cam_asked));
    g_ui.store(static_cast<uint8_t>(ui));
    if (ui != Mode::Off || cam != Mode::Off) {
        std::string allow_names;
        for (size_t i = 0; i < kFns; ++i) {
            if (gxv::fn_in(allow.set, static_cast<gxv::Fn>(i))) {
                allow_names += std::format(" {}", gxv::fn_info(static_cast<gxv::Fn>(i)).name);
            }
        }
        log::info("GuestXVeto: guest_x_ui_veto_allow='{}': run natively for X (never vetoed, both directions):{}",
                  ui_allow, allow_names.empty() ? " none" : allow_names);
    }
    if (stage == Mode::Off && cam == Mode::Off && ui == Mode::Off) return;
    if (g_started.exchange(true)) return;
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

void guest_x_veto_tick() noexcept {
    if (!g_started.load()) return;
    try {
        ++g_tick_n;
        p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind >= kKindCount) continue;
            const bool fn_vetoed =
                e.kind == kEFn && static_cast<Act>((e.v[0] >> 8) & 0xFF) == Act::Veto;  // a handler of X skipped
            if (e.kind == kEV1 || e.kind == kEV0 || fn_vetoed) {
                log::warn("{}", line_of(e));  // always, outside the line budget (rate-limited at the source)
            } else if (g_lines.fetch_add(1) < kMaxLines) {
                log::info("{}", line_of(e));
            }
        }
        if (g_tick_n % 12 == 0) summary();
    } catch (...) {
    }
}

void guest_x_context_routed_2981(uintptr_t x, uintptr_t sp) noexcept {
    // C1 (guest_x_interaction.h): every X a 2981 is routed into is a known X, whatever this module's keys (a no-op
    // when guest_x_interaction_stage=0). Its character: [[X+0x18]+0x60] (SEH reads).
    if (x) {
        const uintptr_t actor = rdp(x + kMgr_Actor);
        guest_x_interaction_note_x(x, actor ? rdv<uint32_t>(actor + kActor_Key) : 0);
    }
    if (!x || !g_clear_on.load(std::memory_order_acquire)) return;
    t_ctx.set(x, sp, p8_now_us());
    g_ctx_2981.fetch_add(1, std::memory_order_relaxed);
}

void guest_x_context_clear() noexcept { t_ctx.clear(); }

void guest_x_context_hook_entry() noexcept {
    if (t_ctx.get().x == 0) return;
    t_ctx.clear();
    g_ctx_entry_clear.fetch_add(1, std::memory_order_relaxed);
}

void guest_x_note_m(uintptr_t m, uint32_t m_key) noexcept {
    if (!m) return;
    g_m.store(m, std::memory_order_relaxed);
    g_m_key.store(m_key, std::memory_order_relaxed);
    g_m_epoch.store(guest_connection_epoch(), std::memory_order_relaxed);
    g_m_us.store(p8_now_us(), std::memory_order_relaxed);
}

uintptr_t guest_x_current_m() noexcept {
    const uint64_t now = p8_now_us(), m_us = g_m_us.load(std::memory_order_relaxed);
    if (g_m_epoch.load(std::memory_order_relaxed) != guest_connection_epoch() || now < m_us || now - m_us > kMFreshUs) {
        return 0;
    }
    return g_m.load(std::memory_order_relaxed);
}

GuestXContextScope::GuestXContextScope(uintptr_t x) noexcept {
    // This object lives in the caller's frame: the callees are deeper.
    const gxv::Context prev = t_ctx.exchange({x, reinterpret_cast<uintptr_t>(this), p8_now_us()});
    prev_x_ = prev.x;
    prev_sp_ = prev.sp;
    prev_us_ = prev.us;
}

GuestXContextScope::~GuestXContextScope() { t_ctx.exchange({prev_x_, prev_sp_, prev_us_}); }

}  // namespace cdmp::session2
