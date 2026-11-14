#include "mod/session2/observer_scene_copy.h"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <format>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/game_fault.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_stage_diag_logic.h"
#include "mod/session2/observer_scene_copy_logic.h"
#include "mod/session2/owner_fanout.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

// ---------------------------------------------------------------- the code it relies on (build 2976, .rsrc)
//
// Read from the authorised read-only PE (D:\RE\CrimsonDesert_2976\bin\CrimsonDesert.exe) with capstone
// (pendientes/p8-escenas-y-acks.md §2.3). Nothing here is patched: the bytes are compared before the
// copy may run, and the functions are called exactly as 0x2879440 calls them.

// DeleteSequencer 0x2879440 (rcx = r12 = the manager; rsi = the server sequencer, removed from the
// manager's map at 0x28794EC), its native 2810:
//   0x28797AD mov rdi,rax ; mov rcx,[rsi+0x30] ; mov [rbp+0x320],rcx      (the u64 id, -> r8)
//   0x28797BB mov rcx,[r12+0x18] ; ToTarget base/derived vtables, +8 = 0, +0x10 = rcx->vfE8()
//   0x28797F9 lea rax,[rbp+0x338] ; mov [rsp+0x20],rax ; mov r9,rdi ; lea r8,[rbp+0x320] ;
//             lea rdx,[rsp+0x60] ; mov rcx,[r12+0x18] ; call 0x2A4E4C0   (returns to 0x287981E)
constexpr uintptr_t kSiteRva = 0x28797AD;
constexpr uint8_t kSiteBytes[] = {
    0x48, 0x8B, 0xF8, 0x48, 0x8B, 0x4E, 0x30, 0x48, 0x89, 0x8D, 0x20, 0x03, 0x00, 0x00, 0x49, 0x8B, 0x4C, 0x24, 0x18,
    0x48, 0x8D, 0x05, 0x31, 0xBC, 0x2A, 0x03, 0x48, 0x89, 0x44, 0x24, 0x60, 0xC6, 0x44, 0x24, 0x68, 0x00, 0x48, 0x8D,
    0x05, 0x60, 0xBC, 0x2A, 0x03, 0x48, 0x89, 0x44, 0x24, 0x60, 0x48, 0xC7, 0x44, 0x24, 0x70, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xC9, 0x74, 0x0E, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x70,
    0x48, 0x8D, 0x85, 0x38, 0x03, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8B, 0xCF, 0x4C, 0x8D, 0x85, 0x20,
    0x03, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x60, 0x49, 0x8B, 0x4C, 0x24, 0x18, 0xE8, 0xA2, 0x4C, 0x1D, 0x00};
constexpr uintptr_t kReturnRva = 0x287981E;
// The sequencer's owner: 0x287974C movzx edx,byte [rbp+0x320] ; mov rcx,rsi ; call 0x20532B0, which
// (0x20532D5 mov rdi,rcx ... 0x20532E6 call 0x205D7C0) asks 0x205D7C0(sequencer, &out); there
// 0x205D7DC mov rsi,rcx ... 0x205D83B mov r8d,[rsi+0x98] ; mov rdx,rbp ; mov rcx,rdi ; call rbx: the
// actor manager's find-by-key (vf+0x28) with the key at +0x98 (rsi is not written between 0x2879753
// and 0x2879819).
constexpr uintptr_t kOwnerCallRva = 0x287974C;
constexpr uint8_t kOwnerCallBytes[] = {0x0F, 0xB6, 0x95, 0x20, 0x03, 0x00, 0x00, 0x48, 0x8B, 0xCE, 0xE8, 0x55, 0x9B, 0x7D, 0xFF};
constexpr uintptr_t kOwnerMethodRva = 0x20532D5;
constexpr uint8_t kOwnerMethodBytes[] = {0x48, 0x8B, 0xF9, 0x33, 0xDB, 0x44, 0x8B, 0xF3, 0x89, 0x5C, 0x24,
                                         0x20, 0x48, 0x8D, 0x54, 0x24, 0x70, 0xE8, 0xD5, 0xA4, 0x00, 0x00};
constexpr uintptr_t kOwnerFindRva = 0x205D7DC;
constexpr uint8_t kOwnerFindBytes[] = {
    0x48, 0x8B, 0xF1, 0x45, 0x33, 0xC9, 0x44, 0x89, 0x4C, 0x24, 0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00,
    0x00, 0x4C, 0x8B, 0x00, 0xB9, 0xEC, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x19, 0xBD, 0xD0, 0x04, 0x46, 0x38, 0x0C,
    0x01, 0x48, 0x0F, 0x45, 0x05, 0x15, 0xBD, 0xD0, 0x04, 0x48, 0x8B, 0x38, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0x58, 0x28,
    0x48, 0x8D, 0x56, 0x20, 0x48, 0x85, 0xF6, 0x49, 0x0F, 0x44, 0xD1, 0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4C, 0x24, 0x28,
    0xE8, 0xC3, 0x65, 0x33, 0xFE, 0x90, 0x48, 0x89, 0x74, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00,
    0x44, 0x8B, 0x86, 0x98, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD5, 0x48, 0x8B, 0xCF, 0xFF, 0xD3};
constexpr uint32_t kSeq_Id = 0x30, kSeq_OwnerKey = 0x98, kManager_Actor = 0x18;

// DeleteSequencerAck 2810's serializer 0x2A4E4C0(actor, finder, &u64 seq, &u32, &u8): its first 5
// bytes are observer_stage's mid hook (the original prologue, or its jmp); from +5: the frame, TLS
// block 0 +0x250 = the send context, +0x2B8 = 0, finder->vf1(ctx+0x2B0), count 0 -> return, then the
// scope sender lookup 0x2961CA0. It only READS [r8], [r9] and [5th] (0x2A4E5C2, 0x2A4E5DD, 0x2A4E602).
constexpr uintptr_t kEmitRva = 0x2A4E4C0;
constexpr uint8_t kEmitHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08};
constexpr uint8_t kEmitBody[] = {
    0x4C, 0x89, 0x4C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C,
    0x24, 0xE1, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE0, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF1, 0x65,
    0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x45, 0x0F, 0xB9, 0x50, 0x02, 0x00,
    0x00, 0x48, 0x8B, 0x04, 0x01, 0x33, 0xFF, 0x89, 0xB8, 0xB8, 0x02, 0x00, 0x00, 0x4C, 0x8D, 0xB8, 0xB0, 0x02, 0x00,
    0x00, 0x48, 0x8B, 0x02, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xFF, 0x50, 0x08, 0x45, 0x8B, 0x6F, 0x08, 0x45, 0x85,
    0xED, 0x0F, 0x84, 0x4A, 0x04, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8, 0x6D, 0x37, 0xF1, 0xFF};
constexpr uintptr_t kEmitOpRva = 0x2A4E60C;  // mov word [r14],0xAFA
constexpr uint8_t kEmitOpBytes[] = {0x66, 0x41, 0xC7, 0x06, 0xFA, 0x0A};

// pa::ToTargetSendTargetFinder (the same bytes observer_milestone.cpp verifies; p8-2322-observador.md
// §2.1): its constructor 0x2A757A0(this, actor), vtable exe+0x5B25438 (slots 0-2) and its base's
// exe+0x5B253F8 (slot 0).
constexpr uintptr_t kCtorRva = 0x2A757A0;
constexpr uint8_t kCtorBytes[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05, 0x44, 0xFC, 0x0A,
    0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0x76, 0xFC, 0x0A, 0x03, 0x48, 0x89, 0x01, 0x48,
    0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xD2, 0x74, 0x10, 0x48, 0x8B, 0x02, 0x48, 0x8B, 0xCA, 0xFF,
    0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x43, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3};
constexpr uintptr_t kVtToTarget = 0x5B25438, kVtFinderBase = 0x5B253F8;
constexpr uintptr_t kVf0Rva = 0x2A75740, kVf1Rva = 0x2A757F0, kVf2Rva = 0x2A75850, kBaseVf0Rva = 0x2A756B0;
constexpr uint8_t kVf1Bytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48, 0x8B, 0xDA, 0x48,
    0x8B, 0xF9, 0x74, 0x3D, 0x8B, 0x4A, 0x08, 0x8B, 0x42, 0x0C, 0x3B, 0xC1, 0x77, 0x22, 0x8D, 0x14, 0x45, 0x01, 0x00,
    0x00, 0x00, 0x03, 0xD0, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xD1, 0xEA, 0x3B, 0xD0, 0x0F, 0x42, 0xD0, 0x3B, 0xCA, 0x0F,
    0x47, 0xD1, 0x48, 0x8B, 0xCB, 0xE8, 0xBD, 0x8B, 0x8E, 0xFD, 0x8B, 0x53, 0x08, 0x48, 0x8B, 0x47, 0x10, 0x48, 0x8B,
    0x0B, 0x48, 0x89, 0x04, 0xD1, 0xFF, 0x43, 0x08, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3};
constexpr uint8_t kVf2Bytes[] = {0x48, 0x8B, 0x42, 0x10, 0x48, 0x39, 0x41, 0x10, 0x0F, 0x94, 0xC0, 0xC3};
// The scope sender lookup 0x2961CA0 (TLS block 0 +0x250 -> +0x2AC mode, +0x2A0 count) and
// ServerRunThread's realm mark (TLS +0x1EC = 1): the fields the decision reads.
constexpr uint8_t kScopeFindBytes[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF1, 0xBD, 0x50,
                                       0x02, 0x00, 0x00, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0x2C, 0x2A, 0x80, 0xBD, 0xAC, 0x02,
                                       0x00, 0x00, 0x00, 0x74, 0x44, 0x44, 0x8B, 0xB5, 0xA0, 0x02, 0x00, 0x00};
constexpr uint8_t kRealmBytes[] = {0xB8, 0xEC, 0x01, 0x00, 0x00, 0xC6, 0x04, 0x18, 0x01};

struct Region {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* what;
};
const Region kRegions[] = {
    {kSiteRva, kSiteBytes, "the native 2810 call in 0x2879440 (0x28797AD..0x287981E)"},
    {kOwnerCallRva, kOwnerCallBytes, "0x2879440's call of the sequencer's owner method"},
    {kOwnerMethodRva, kOwnerMethodBytes, "0x20532B0 -> 0x205D7C0"},
    {kOwnerFindRva, kOwnerFindBytes, "0x205D7C0's owner lookup by [sequencer+0x98]"},
    {kEmitRva + sizeof kEmitHead, kEmitBody, "the 2810 serializer's body"},
    {kEmitOpRva, kEmitOpBytes, "the 2810 serializer's opcode write"},
    {kCtorRva, kCtorBytes, "ToTarget constructor"},
    {kVf1Rva, kVf1Bytes, "ToTarget vf1 (recipients)"},
    {kVf2Rva, kVf2Bytes, "ToTarget vf2 (equality)"},
    {0x2961CBA, kScopeFindBytes, "the scope sender lookup (TLS +0x250 +0x2AC/+0x2A0)"},
    {0x27733A6, kRealmBytes, "ServerRunThread's realm mark (TLS +0x1EC)"},
};

// Build 1.0.0.3527 [V capstone, 2026-11-05]. DeleteSequencer 0x2AD4280: the sequencer is in rdi and the manager in r13
// (both still there at the serializer's entry), and r9 points at [rsi+8] of the object from 0x4DDF30.
constexpr uint8_t kSite3527[] = {
    0x48, 0x8B, 0xF0, 0x48, 0x8B, 0x47, 0x30, 0x48, 0x89, 0x85, 0x50, 0x03, 0x00, 0x00, 0x49, 0x8B, 0x4D, 0x18, 0x4C,
    0x8D, 0x3D, 0x70, 0x82, 0x41, 0x03, 0x4C, 0x89, 0x7C, 0x24, 0x70, 0xC6, 0x44, 0x24, 0x78, 0x00, 0x48, 0x8D, 0x05,
    0x3F, 0x82, 0x41, 0x03, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0xC7, 0x45, 0x80, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85,
    0xC9, 0x74, 0x0D, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x80, 0x48, 0x8D, 0x85,
    0x68, 0x03, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D, 0x4E, 0x08, 0x4C, 0x8D, 0x85, 0x50, 0x03, 0x00,
    0x00, 0x48, 0x8D, 0x54, 0x24, 0x70, 0x49, 0x8B, 0x4D, 0x18, 0xE8, 0x1B, 0x65, 0x20, 0x00};
// The owner lookup 0x2218700: the key is at +0xA0.
constexpr uint8_t kOwnerFind3527[] = {0x44, 0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD5, 0x48, 0x8B, 0xCF, 0xFF, 0xD3};
constexpr uint8_t kEmitBody3527[] = {
    0x4C, 0x89, 0x4C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C,
    0x24, 0xE1, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE0, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF1, 0x65,
    0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x45, 0x0F, 0xB9, 0x50, 0x02, 0x00,
    0x00, 0x48, 0x8B, 0x04, 0x01, 0x33, 0xFF, 0x89, 0xB8, 0xB8, 0x02, 0x00, 0x00, 0x4C, 0x8D, 0xB8, 0xB0, 0x02, 0x00,
    0x00, 0x48, 0x8B, 0x02, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xFF, 0x50, 0x08, 0x45, 0x8B, 0x6F, 0x08, 0x45, 0x85,
    0xED, 0x0F, 0x84, 0x4F, 0x04, 0x00, 0x00, 0x48, 0x8B, 0xCB};
constexpr uint8_t kEmitOp3527[] = {0x66, 0x41, 0xC7, 0x06, 0xF4, 0x08};
constexpr uint8_t kCtor3527[] = {0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
                                 0xBC, 0x82, 0x1E, 0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0x8E, 0x82};
constexpr uint8_t kVf1_3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48,
                                 0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x74, 0x3D, 0x8B, 0x4A, 0x08, 0x8B, 0x42, 0x0C, 0x3B, 0xC1, 0x77};
constexpr uint8_t kVf2_3527[] = {0x48, 0x8B, 0x42, 0x10, 0x48, 0x39, 0x41, 0x10, 0x0F, 0x94, 0xC0, 0xC3};
constexpr uint8_t kScope3527[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF1, 0xBD, 0x50,
                                  0x02, 0x00, 0x00, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0x2C, 0x2A, 0x80, 0xBD, 0xAC, 0x02,
                                  0x00, 0x00, 0x00, 0x74, 0x44, 0x44, 0x8B, 0xB5, 0xA0, 0x02, 0x00, 0x00};
constexpr uint8_t kRealm3527[] = {0xB8, 0xEB, 0x01, 0x00, 0x00, 0xC6, 0x04, 0x18, 0x01};
const Region kRegions3527[] = {
    {0x2AD45D7, kSite3527, "the native 2810 call in DeleteSequencer 0x2AD4280"},
    {0x221877B, kOwnerFind3527, "the owner lookup by [sequencer+0xA0]"},
    {0x2CDAB65, kEmitBody3527, "the 2810 serializer's body"},
    {0x2CDACAC, kEmitOp3527, "the 2810 serializer's opcode write"},
    {0x2D04590, kCtor3527, "ToTarget constructor"},
    {0x2D045E0, kVf1_3527, "ToTarget vf1 (recipients)"},
    {0x2D04640, kVf2_3527, "ToTarget vf2 (equality)"},
    {0x2BD571A, kScope3527, "the scope sender lookup"},
    {0x29AAF36, kRealm3527, "ServerRunThread's realm mark (TLS +0x1EB)"},
};
// Build 1.0.0.3576 (static, 2026-11-06 evening; not yet run): every region moved with its function (DeleteSequencer
// 0x2AD4ED0 +0xC50, the owner lookup +0xC40, the serializer 0x2CDB7D0 / ToTarget / scope +0xC70, the realm +0xC50), the
// same bytes but for the site's two lea (to the finder vtables 0x5EEEA80 / 0x5EEEA60, mapped by RTTI) and its call
// (0x2CDB7D0), and the constructor's two lea (the same vtables).
constexpr uint8_t kSite3576[] = {
    0x48, 0x8B, 0xF0, 0x48, 0x8B, 0x47, 0x30, 0x48, 0x89, 0x85, 0x50, 0x03, 0x00, 0x00, 0x49, 0x8B, 0x4D, 0x18, 0x4C,
    0x8D, 0x3D, 0x40, 0x98, 0x41, 0x03, 0x4C, 0x89, 0x7C, 0x24, 0x70, 0xC6, 0x44, 0x24, 0x78, 0x00, 0x48, 0x8D, 0x05,
    0x0F, 0x98, 0x41, 0x03, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0xC7, 0x45, 0x80, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85,
    0xC9, 0x74, 0x0D, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x80, 0x48, 0x8D, 0x85,
    0x68, 0x03, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D, 0x4E, 0x08, 0x4C, 0x8D, 0x85, 0x50, 0x03, 0x00,
    0x00, 0x48, 0x8D, 0x54, 0x24, 0x70, 0x49, 0x8B, 0x4D, 0x18, 0xE8, 0x3B, 0x65, 0x20, 0x00};
constexpr uint8_t kCtor3576[] = {0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
                                 0x6C, 0x98, 0x1E, 0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0x3E, 0x98};
const Region kRegions3576[] = {
    {0x2AD5227, kSite3576, "the native 2810 call in DeleteSequencer 0x2AD4ED0"},
    {0x22193BB, kOwnerFind3527, "the owner lookup by [sequencer+0xA0]"},
    {0x2CDB7D5, kEmitBody3527, "the 2810 serializer's body"},
    {0x2CDB91C, kEmitOp3527, "the 2810 serializer's opcode write"},
    {0x2D05200, kCtor3576, "ToTarget constructor"},
    {0x2D05250, kVf1_3527, "ToTarget vf1 (recipients)"},
    {0x2D052B0, kVf2_3527, "ToTarget vf2 (equality)"},
    {0x2BD638A, kScope3527, "the scope sender lookup"},
    {0x29ABB86, kRealm3527, "ServerRunThread's realm mark (TLS +0x1EB)"},
};
// Build 1.0.0.3663 (static, 2026-11-13; never run): each region searched over the whole code section by its 3527/3576
// bytes (relative fields masked), one hit each. The site 0x2B3971A in DeleteSequencer 0x2B393C0 (+0x35A; 3576 +0x357):
// the same bytes but for its two lea (base 0x5F68740 / ToTarget 0x5F68760 by RTTI, vtable_map_3576_3663.json) and its
// call of the serializer 0x2D42250 (its only caller; it returns to 0x2B39788); the sequencer still in rdi ([rdi+0x30],
// the id) and the manager in r13 ([r13+0x18]), r9 = [rsi+8]. The owner lookup 0x228876B (in 0x22886F0, key +0xA0), the
// serializer's body (from 0x2D42255, identical to 3527's, rel32 included) and its opcode write 0x2D4239C (+0x14C as
// before) `mov word [r14],0xA63` = DeleteSequencerAck 2659 on 3663; it allocates 0x16 bytes (5 + 17: u32 actor | u64
// [r8] | u32 [r9] | u8 [5th], 0x2D42467..0x2D4251F). ToTarget 0x5F68760: vf0 0x2D6C0F0, vf1 0x2D6C1A0, vf2 0x2D6C200
// (vf1 / vf2 identical); the constructor 0x2D6C150 (between them, as in 3576) differs only in its two lea (the same
// vtables). The scope lookup 0x2C3BDFA (in 0x2C3BDE0) and the realm mark 0x2A0E1B6 (in 0x2A0E1A0) identical. The vf 0xE8
// getters: ChildOnlyInGame 0xC1D4E0 mov rax,[rcx+0xD0], NormalInGame 0x3AD510 xor eax,eax, ServerUserActor 0x2D740C0
// mov rax,[rcx+0x1F8]. The 2661 it books: its serializer 0x2D41C70 writes u8 4 | u32 actor | 87 bytes of play data
// (0x26B31E0: owner u32 first, then the u64 id) | 11 bytes per binding: 3527's prefix 92. MoveFieldAck (0x2C7A2B0):
// u8 | u32 | u32 | u32 | u32 + 0x30 per entry (0x26AB510), as 3527's.
constexpr uint8_t kSite3663[] = {
    0x48, 0x8B, 0xF0, 0x48, 0x8B, 0x47, 0x30, 0x48, 0x89, 0x85, 0x50, 0x03, 0x00, 0x00, 0x49, 0x8B, 0x4D, 0x18, 0x4C,
    0x8D, 0x3D, 0x0D, 0xF0, 0x42, 0x03, 0x4C, 0x89, 0x7C, 0x24, 0x70, 0xC6, 0x44, 0x24, 0x78, 0x00, 0x48, 0x8D, 0x05,
    0x1C, 0xF0, 0x42, 0x03, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0xC7, 0x45, 0x80, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85,
    0xC9, 0x74, 0x0D, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x80, 0x48, 0x8D, 0x85,
    0x68, 0x03, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D, 0x4E, 0x08, 0x4C, 0x8D, 0x85, 0x50, 0x03, 0x00,
    0x00, 0x48, 0x8D, 0x54, 0x24, 0x70, 0x49, 0x8B, 0x4D, 0x18, 0xE8, 0xC8, 0x8A, 0x20, 0x00};
constexpr uint8_t kCtor3663[] = {0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
                                 0xDC, 0xC5, 0x1F, 0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0xEE, 0xC5};
constexpr uint8_t kEmitOp3663[] = {0x66, 0x41, 0xC7, 0x06, 0x63, 0x0A};
const Region kRegions3663[] = {
    {0x2B3971A, kSite3663, "the native 2810 call in DeleteSequencer 0x2B393C0"},
    {0x228876B, kOwnerFind3527, "the owner lookup by [sequencer+0xA0]"},
    {0x2D42255, kEmitBody3527, "the 2810 serializer's body"},
    {0x2D4239C, kEmitOp3663, "the 2810 serializer's opcode write"},
    {0x2D6C150, kCtor3663, "ToTarget constructor"},
    {0x2D6C1A0, kVf1_3527, "ToTarget vf1 (recipients)"},
    {0x2D6C200, kVf2_3527, "ToTarget vf2 (equality)"},
    {0x2C3BDFA, kScope3527, "the scope sender lookup"},
    {0x2A0E1B6, kRealm3527, "ServerRunThread's realm mark (TLS +0x1EB)"},
};

struct Layout {
    uintptr_t ret, emit, ctor, vt_target, vt_base, vf0, vf1, vf2;
    uint32_t seq_owner_key, tls_realm;
};
constexpr Layout kLayout2976{kReturnRva, kEmitRva, kCtorRva, kVtToTarget, kVtFinderBase, kVf0Rva, kVf1Rva, kVf2Rva, kSeq_OwnerKey, 0x1EC};
constexpr Layout kLayout3527{0x2AD4645, 0x2CDAB60, 0x2D04590, 0x5EEC840, 0x5EEC860, 0x2D04530, 0x2D045E0, 0x2D04640, 0xA0, 0x1EB};
constexpr Layout kLayout3576{0x2AD5295, 0x2CDB7D0, 0x2D05200, 0x5EEEA60, 0x5EEEA80, 0x2D051A0, 0x2D05250, 0x2D052B0, 0xA0, 0x1EB};
// Build 1.0.0.3663 (static, 2026-11-13; never run): see kRegions3663.
constexpr Layout kLayout3663{0x2B39788, 0x2D42250, 0x2D6C150, 0x5F68760, 0x5F68740, 0x2D6C0F0, 0x2D6C1A0, 0x2D6C200, 0xA0, 0x1EB};
const Layout* g_layout = &kLayout2976;  // published before g_verified

constexpr uint32_t kActor_Key = 0x60, kActor_User = 0xA0, kUser_Main = 0xD0;
constexpr uint32_t kTls_SendCtx = 0x250;
constexpr uint32_t kCtx_ScopeCount = 0x2A0, kCtx_ScopeMode = 0x2AC;
constexpr uint32_t kStack_Fifth = 0x28;  // at the callee's entry: [rsp] return, +8..+0x20 home, +0x28 the 5th

using CtorFn = void*(__fastcall*)(void* finder, uintptr_t actor);
using EmitFn = void(__fastcall*)(uintptr_t actor, void* finder, const uint64_t* seq, const uint32_t* extra,
                                 const uint8_t* flag);

uintptr_t g_base = 0;
std::atomic<bool> g_wanted{false}, g_verified{false}, g_disabled{false};
CtorFn g_ctor = nullptr;
EmitFn g_emit = nullptr;

std::mutex g_mu;
osc::SceneBook g_book;  // under g_mu

// Our own call, on this thread (its hook sees it; take_frame confirms its 2810).
thread_local bool t_in_copy = false;
thread_local uint64_t t_copy_seq = 0;
thread_local uint32_t t_copy_seen = 0, t_copy_pushed = 0;

std::atomic<uint64_t> g_why[static_cast<size_t>(osc::Why::Count)]{};
std::atomic<uint64_t> g_copies{0}, g_copies_queued{0}, g_copies_lost{0}, g_copies_unseen{0}, g_faults{0},
    g_own_seen{0}, g_book_prepared{0}, g_book_closed{0};

enum Note : uint16_t { kNDecision, kNCopied, kNBook, kNoteCount };
p8p::EventRing<512> g_ring;
std::atomic<uint64_t> g_ring_lost{0}, g_decision_lines{0}, g_book_lines{0};
constexpr uint64_t kMaxOtherDecisionLines = 16, kMaxBookLines = 64, kMaxLines = 2000;
uint64_t g_lines = 0;  // drain thread only

void push(p8p::Event& e) {
    if (!e.qpc_us) e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    if (!g_ring.push(e)) g_ring_lost.fetch_add(1, std::memory_order_relaxed);
}

// ---------------------------------------------------------------- reads (SEH only, the server's thread)

template <class T>
T fr(uintptr_t a, bool& ok) noexcept {
    const auto v = a >= 0x10000 ? game::fast<T>(a) : std::nullopt;
    if (!v) ok = false;
    return v.value_or(T{});
}

uintptr_t fp(uintptr_t a, bool& ok) noexcept {
    const auto v = a >= 0x10000 ? game::fast_ptr(a) : std::nullopt;
    if (!v) ok = false;
    return v.value_or(0);
}

// This thread's own stack, above its current rsp (committed: no guard page is touched).
template <class T>
bool stack_read(uintptr_t a, T& out) noexcept {
    __try {
        out = *reinterpret_cast<const volatile T*>(a);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void read_tls(osc::CopyFacts& f) noexcept {
    const uintptr_t array = static_cast<uintptr_t>(__readgsqword(0x58));
    bool ok = true;
    const uintptr_t block = fp(array, ok);
    if (!ok || !block) return;
    bool r = true;
    f.realm = fr<uint8_t>(block + g_layout->tls_realm, r) != 0 && r;
    bool c = true;
    const uintptr_t ctx = fp(block + kTls_SendCtx, c);
    f.send_ctx = c && ctx;
    if (f.send_ctx) {
        bool s = true;
        const uint8_t mode = fr<uint8_t>(ctx + kCtx_ScopeMode, s);
        const uint32_t count = fr<uint32_t>(ctx + kCtx_ScopeCount, s);
        f.scope_open = !s || (mode && count);  // unreadable: treated as open (refused)
    }
}

// The ToTarget constructor 0x2A757A0 writes only our stack finder and calls the
// actor's vf 0xE8, a lock-free getter in every server actor class [V]
// (ServerActor/NormalInGame 0x3600B0 xor eax,eax; ChildOnlyInGame 0xAD83F0
// mov rax,[rcx+0xD0]; ServerUserActor 0x2A7D9E0 mov rax,[rcx+0x1F8]): a fault
// there is a bad actor pointer, ours to handle (the copy is then switched off,
// counted and logged by the 'copied' line).
int guarded_ctor(void* finder, uintptr_t actor) noexcept {
    __try {
        g_ctor(finder, actor);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
}

// The emitter 0x2A4E4C0 writes the thread's send context (TLS+0x250: +0x2B8,
// +0x2B0), looks for a bundle scope and builds and queues the packet: an
// exception inside it may leave that state half done or a lock taken. P8 review
// I1: the copy is switched off here, one line goes straight to the log and the
// exception is passed on (a real crash where it happened, never swallowed).
int emit_fault(EXCEPTION_POINTERS* ep) noexcept {
    g_disabled.store(true);
    g_faults.fetch_add(1);
    t_in_copy = false;
    return game::game_fault_continue(ep, "ObserverSceneCopy", "the 2810 emitter 0x2A4E4C0 ran for user 2's copy");
}

int guarded_emit(uintptr_t actor, void* finder, const uint64_t* seq, const uint32_t* extra,
                 const uint8_t* flag) noexcept {
    __try {
        g_emit(actor, finder, seq, extra, flag);
        return 0;
    } __except (emit_fault(GetExceptionInformation())) {
        return 1;  // never reached: the filter passes it on
    }
}

enum class CallResult : uint8_t { Returned, FaultCtor, BadFinder, WrongRecipient, FaultEmit };
const char* call_name(CallResult r) {
    switch (r) {
        case CallResult::Returned: return "returned";
        case CallResult::FaultCtor: return "FAULT in the ToTarget constructor";
        case CallResult::BadFinder: return "NOT CALLED: the finder is not a ToTarget with tag 0";
        case CallResult::WrongRecipient: return "NOT CALLED: the finder's session is not the live session 2";
        case CallResult::FaultEmit: return "FAULT in 0x2A4E4C0";
        default: return "?";
    }
}

// ---------------------------------------------------------------- the lines (observer_stage's thread)

std::string head(const char* what, const p8p::Event& e) {
    return std::format("ObserverSceneCopy [{}] {}{} |", what, p8_when(e.qpc_us),
                       e.tid ? std::format(" T{}", e.tid) : std::string());
}

std::string line_of(const p8p::Event& e) {
    const uint64_t* v = e.v;
    switch (e.kind) {
        case kNDecision: {
            const uint64_t seq = v[0];
            const auto owner = static_cast<uint32_t>(v[1]), recipient = static_cast<uint32_t>(v[1] >> 32);
            const auto user2 = static_cast<uint32_t>(v[2]);
            const auto why = static_cast<osc::Why>(v[2] >> 32);
            const auto extra = static_cast<uint32_t>(v[6]);
            std::string delivered = "its 2661 did NOT reach user 2's queue";
            if (v[5] & 1) {
                delivered = std::format("its 2661 reached user 2 (actor 0x{:08X}, owner 0x{:08X}; epoch {} trip {}, now "
                                        "epoch {} trip {}; {:.3f} s ago)",
                                        static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[3] >> 32),
                                        static_cast<uint32_t>(v[4]), static_cast<uint32_t>(v[4] >> 32),
                                        static_cast<uint32_t>(v[7]), static_cast<uint32_t>(v[7] >> 32),
                                        e.qpc_us >= v[8] ? static_cast<double>(e.qpc_us - v[8]) / 1e6 : 0.0);
            }
            const bool copy = why == osc::Why::Copy;
            return std::format("{} DeleteSequencerAck 2810 of sequencer 0x{:X} (owner [seq+0x98] 0x{:08X}) natively to "
                               "0x{:08X} ([manager+0x18]) | {} | user 2's character 0x{:08X} | {} | thread: realm {}, "
                               "send context {}, scope {} | {}{}",
                               head("decision", e), seq, owner, recipient,
                               gsd::corr_token(osc::kOpDelete, recipient, seq, extra), user2, delivered,
                               (v[5] >> 1) & 1 ? "yes" : "NO", (v[5] >> 2) & 1 ? "yes" : "NO",
                               (v[5] >> 3) & 1 ? "OPEN" : "closed",
                               copy ? "COPY to user 2: 0x2A757A0 + 0x2A4E4C0 on this thread, "
                                    : std::format("NOT COPIED: {}", osc::why_name(why)),
                               copy ? gsd::corr_token(osc::kOpDelete, user2, seq, extra) : std::string());
        }
        case kNCopied: {
            const auto r = static_cast<CallResult>(v[2]);
            const auto actor = static_cast<uint32_t>(v[1]);
            std::string what;
            if (r != CallResult::Returned) {
                what = std::format("{} (finder session 0x{:X}, live session 2 0x{:X})", call_name(r), v[8], v[9]);
            } else if (!v[3]) {
                what = "0x2A4E4C0 returned but NO 2810 reached take_frame on this thread (no recipient, or a scope "
                       "bundle): not retried";
            } else {
                what = std::format("0x2A4E4C0 returned; its 2810 {} in user 2's queue (x{})",
                                   v[4] ? "IS" : "is NOT (LOST)", v[3]);
            }
            return std::format("{} sequencer 0x{:X}: {} | {} | call {:.3f} ms | next on the guest: GuestStage [2810 in "
                               "0xC06330] with the same corr=, then its scene ends (control back)",
                               head("copied", e), v[0], what,
                               gsd::corr_token(osc::kOpDelete, actor, v[0], static_cast<uint32_t>(v[6])),
                               static_cast<double>(v[5]) / 1e3);
        }
        case kNBook: {
            const auto seen = static_cast<osc::SceneBook::Seen>(v[0]);
            const auto actor = static_cast<uint32_t>(v[2]), owner = static_cast<uint32_t>(v[2] >> 32);
            if (seen == osc::SceneBook::Seen::Prepared || seen == osc::SceneBook::Seen::Replaced) {
                return std::format("{} 2661 of sequencer 0x{:X} reached user 2's queue (actor 0x{:08X}, owner 0x{:08X}; "
                                   "epoch {} trip {}){} | {}{}",
                                   head("2661", e), v[1], actor, owner, static_cast<uint32_t>(v[3]),
                                   static_cast<uint32_t>(v[3] >> 32), seen == osc::SceneBook::Seen::Replaced ? " again" : "",
                                   gsd::corr_token(osc::kOpPrepare, actor, v[1], static_cast<uint32_t>(v[4])),
                                   owner == static_cast<uint32_t>(v[5]) ? " | user 2's own scene: its 2810 is watched"
                                                                        : "");
            }
            return std::format("{} a 2810 of sequencer 0x{:X} reached user 2's queue{} (actor 0x{:08X}): {}", head("2810", e),
                               v[1], v[6] ? " (OUR COPY)" : " (native)", static_cast<uint32_t>(v[5] >> 32),
                               seen == osc::SceneBook::Seen::Closed ? "closed in the book"
                                                                    : "no 2661 of it in the book");
        }
        default:
            return std::format("ObserverSceneCopy: note {}?", e.kind);
    }
}

bool code_at(uintptr_t rva, std::span<const uint8_t> b) {
    std::vector<uint8_t> actual(b.size());
    // P8 B step 2: owner_fanout's hook on ToTarget::vf1 is not a change of the game's code (its original bytes).
    return owner_fanout_read_unpatched(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), b.begin());
}

}  // namespace

bool observer_scene_copy_configure(bool on) {
    g_wanted.store(on);
    return on;
}

bool observer_scene_copy_wanted() { return g_wanted.load(); }

bool observer_scene_copy_in_copy() noexcept { return t_in_copy; }

bool observer_scene_copy_active() { return g_wanted.load() && g_verified.load() && !g_disabled.load(); }

bool observer_scene_copy_verify(uintptr_t base, std::span<const gad::Section> secs) {
    if (!g_wanted.load()) return false;
    g_base = base;
    std::string bad;
    for (const Region& r : kRegions) {
        if (!gad::in_real_code(secs, static_cast<uint32_t>(r.rva), static_cast<uint32_t>(r.bytes.size())) ||
            !code_at(r.rva, r.bytes)) {
            bad += std::format(" {} (exe+0x{:X}, {} bytes)", r.what, r.rva, r.bytes.size());
        }
    }
    // The serializer's first bytes: the original prologue, or observer_stage's jmp already there.
    uint8_t head5[5] = {};
    if (!game::safe_read(base + kEmitRva, head5, sizeof head5) ||
        (!std::equal(std::begin(head5), std::end(head5), std::begin(kEmitHead)) && head5[0] != 0xE9)) {
        bad += " 2810 serializer entry (exe+0x2A4E4C0)";
    }
    const auto s0 = game::read<uintptr_t>(base + kVtToTarget), s1 = game::read<uintptr_t>(base + kVtToTarget + 8),
               s2 = game::read<uintptr_t>(base + kVtToTarget + 16), b0 = game::read<uintptr_t>(base + kVtFinderBase);
    if (!s0 || *s0 != base + kVf0Rva || !s1 || *s1 != base + kVf1Rva || !s2 || *s2 != base + kVf2Rva || !b0 ||
        *b0 != base + kBaseVf0Rva) {
        bad += " ToTarget/ISendTargetFinder vtables (exe+0x5B25438 / exe+0x5B253F8)";
    }
    if (!bad.empty()) {
        g_wanted.store(false);
        log::error("ObserverSceneCopy: REFUSED, not build 2976's code at:{}; observer_scene_copy stays OFF (nothing "
                   "copied)",
                   bad);
        return false;
    }
    g_ctor = reinterpret_cast<CtorFn>(base + kCtorRva);
    g_emit = reinterpret_cast<EmitFn>(base + kEmitRva);
    g_verified.store(true);
    log::info("ObserverSceneCopy ON (observer_scene_copy=1): at the entry of the 2810 serializer 0x2A4E4C0 (called only "
              "from 0x2879819, DeleteSequencer 0x2879440, on the server's logic thread), a sequencer whose owner "
              "[seq+0x98] is user 2's character, whose 2661 reached user 2's queue in this trip and whose native 2810 "
              "goes to another character ([manager+0x18]: the host's when the host owns the field) gets the native "
              "emitter once more for user 2: ToTarget 0x2A757A0(finder, user 2's character) (session must be the "
              "live session 2) + 0x2A4E4C0(user 2's character, finder, the same id/u32/u8) | the host's own scenes "
              "and the host's 2810 are untouched | {} code regions + serializer entry + vtables checked against "
              "build 2976",
              std::size(kRegions));
    return true;
}

bool observer_scene_copy_verify_current(uintptr_t base) {
    if (!g_wanted.load()) return false;
    g_base = base;
    const bool b3576 = game::current_build() == game::Build::v3576;
    const bool b3663 = game::current_build() == game::Build::v3663;
    const char* build_name = b3663 ? "3663" : b3576 ? "3576" : "3527";
    g_layout = b3663 ? &kLayout3663 : b3576 ? &kLayout3576 : &kLayout3527;
    std::string bad;
    for (const Region& r : b3663   ? std::span<const Region>(kRegions3663)
                           : b3576 ? std::span<const Region>(kRegions3576)
                                   : std::span<const Region>(kRegions3527)) {
        std::vector<uint8_t> actual(r.bytes.size());
        if (!game::safe_read(base + r.rva, actual.data(), actual.size()) ||
            !std::equal(actual.begin(), actual.end(), r.bytes.begin())) {
            bad += std::format(" {} (exe+0x{:X}, {} bytes)", r.what, r.rva, r.bytes.size());
        }
    }
    const auto s0 = game::read<uintptr_t>(base + g_layout->vt_target), s1 = game::read<uintptr_t>(base + g_layout->vt_target + 8),
               s2 = game::read<uintptr_t>(base + g_layout->vt_target + 16);
    if (!s0 || *s0 != base + g_layout->vf0 || !s1 || *s1 != base + g_layout->vf1 || !s2 || *s2 != base + g_layout->vf2) {
        bad += " the ToTarget vtable";
    }
    if (!bad.empty()) {
        g_wanted.store(false);
        log::error("ObserverSceneCopy: REFUSED, not build {}'s code at:{}; observer_scene_copy stays OFF", build_name,
                   bad);
        return false;
    }
    g_ctor = reinterpret_cast<CtorFn>(base + g_layout->ctor);
    g_emit = reinterpret_cast<EmitFn>(base + g_layout->emit);
    {
        std::lock_guard lock(g_mu);
        g_book.set_prepare_prefix(92);
    }
    g_verified.store(true);
    log::info("ObserverSceneCopy ON (build {}): a scene user 2 starts in the host's field lives in the host's manager, "
              "so its closing 2810 goes to the host; user 2 gets the native 2810 too, or its client stays without control",
              build_name);
    return true;
}

void observer_scene_copy_disable(const char* why) {
    if (!g_wanted.load() || g_disabled.exchange(true)) return;
    log::error("ObserverSceneCopy: OFF: {}", why);
}

void observer_scene_copy_on_delete(uintptr_t rcx, uintptr_t r8, uintptr_t r9, uintptr_t rsi, uintptr_t r12,
                                   uintptr_t rsp) noexcept {
    if (!g_wanted.load(std::memory_order_relaxed)) return;
    if (t_in_copy) {  // our own call of the emitter, seen by its hook
        g_own_seen.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    osc::CopyFacts f;
    f.on = observer_scene_copy_active();
    uintptr_t ret = 0;
    f.from_delete = stack_read(rsp, ret) && ret == g_base + g_layout->ret;
    // r8, r9 and the 5th argument point into 0x2879440's frame ([rbp+0x320], rdi, [rbp+0x338]): SEH reads.
    bool ok = stack_read(r8, f.seq);
    bool heap = true;
    const uint64_t seq_obj = fr<uint64_t>(rsi + kSeq_Id, heap);
    const uintptr_t mgr_actor = fp(r12 + kManager_Actor, heap);
    f.owner_key = fr<uint32_t>(rsi + g_layout->seq_owner_key, heap);
    f.recipient_key = fr<uint32_t>(rcx + kActor_Key, heap);
    uint32_t extra = 0;
    uintptr_t fifth = 0;
    uint8_t flag = 0;
    ok = ok && heap && stack_read(r9, extra) && stack_read(rsp + kStack_Fifth, fifth) && fifth && stack_read(fifth, flag);
    f.consistent = ok && f.seq == seq_obj && mgr_actor == rcx;
    uintptr_t live = 0;
    try {
        live = server_live_session2();
        f.live_session = live != 0;
        f.user2_key = server_user2_player_key();
        f.logout = server_logout_requested();
        f.epoch = server_epoch();
    } catch (...) {
        f.live_session = false;
    }
    uint64_t now_epoch_trip = 0;
    {
        std::lock_guard lock(g_mu);
        f.delivered = g_book.find(f.seq);
        f.book_epoch = g_book.epoch();
        f.book_trip = g_book.trip();
        now_epoch_trip = f.book_epoch | static_cast<uint64_t>(f.book_trip) << 32;
    }
    read_tls(f);
    uintptr_t actor = 0;
    uintptr_t user2 = 0;
    if (server_user2(user2) && user2) {
        bool a = true;
        actor = fp(user2 + kUser_Main, a);
        const uint32_t key = a ? fr<uint32_t>(actor + kActor_Key, a) : 0;
        const uintptr_t back = a ? fp(actor + kActor_User, a) : 0;
        f.actor_ok = a && actor && key && key == f.user2_key && back == user2;
    }
    const osc::Why why = osc::decide(f);
    g_why[static_cast<size_t>(why)].fetch_add(1, std::memory_order_relaxed);
    // A line for every 2810 of a sequencer whose owner is user 2 (or that reached it), a few for the others.
    const bool user2_related = (f.user2_key && f.owner_key == f.user2_key) || f.delivered.has_value();
    if (why != osc::Why::Off &&
        (user2_related || g_decision_lines.fetch_add(1, std::memory_order_relaxed) < kMaxOtherDecisionLines)) {
        p8p::Event e;
        e.kind = kNDecision;
        e.v[0] = f.seq;
        e.v[1] = f.owner_key | static_cast<uint64_t>(f.recipient_key) << 32;
        e.v[2] = f.user2_key | static_cast<uint64_t>(why) << 32;
        if (f.delivered) {
            e.v[3] = f.delivered->actor | static_cast<uint64_t>(f.delivered->owner) << 32;
            e.v[4] = f.delivered->epoch | static_cast<uint64_t>(f.delivered->trip) << 32;
            e.v[8] = f.delivered->t_us;
        }
        e.v[5] = (f.delivered ? 1u : 0u) | (f.realm ? 2u : 0u) | (f.send_ctx ? 4u : 0u) | (f.scope_open ? 8u : 0u);
        e.v[6] = extra;
        e.v[7] = now_epoch_trip;
        push(e);
    }
    if (why != osc::Why::Copy) return;
    // The copy: this thread, this frame, no lock of ours held; the same recipe as 0x28797BB..0x2879819
    // with user 2's character in place of [manager+0x18].
    alignas(16) uintptr_t finder[4] = {0, 0, 0, 0};  // 0x18 used: vt, u8 tag (+8), session (+0x10)
    const uint64_t seq = f.seq;
    const uint32_t extra_copy = extra;
    const uint8_t flag_copy = flag;
    CallResult r = CallResult::Returned;
    const uint64_t t0 = p8_now_us();
    t_copy_seq = seq;
    t_copy_seen = 0;
    t_copy_pushed = 0;
    if (guarded_ctor(finder, actor)) {
        r = CallResult::FaultCtor;
    } else if (finder[0] != g_base + g_layout->vt_target || (finder[1] & 0xFF) != 0) {
        r = CallResult::BadFinder;
    } else if (!live || finder[2] != live) {
        r = CallResult::WrongRecipient;
    } else {
        t_in_copy = true;
        if (guarded_emit(actor, finder, &seq, &extra_copy, &flag_copy)) r = CallResult::FaultEmit;
        t_in_copy = false;
    }
    finder[0] = g_base + g_layout->vt_base;  // as 0x287981F: the base vtable back (nothing to free)
    const uint64_t dur = p8_now_us() - t0;
    g_copies.fetch_add(1);
    if (r == CallResult::FaultCtor || r == CallResult::FaultEmit) {
        g_faults.fetch_add(1);
        observer_scene_copy_disable("an exception inside the game's code during the copy (see the 'copied' line)");
    } else if (r == CallResult::Returned) {
        if (!t_copy_seen) g_copies_unseen.fetch_add(1);
        else if (t_copy_pushed) g_copies_queued.fetch_add(1);
        else g_copies_lost.fetch_add(1);
    }
    p8p::Event e;
    e.kind = kNCopied;
    e.v[0] = seq;
    e.v[1] = f.user2_key;
    e.v[2] = static_cast<uint64_t>(r);
    e.v[3] = t_copy_seen;
    e.v[4] = t_copy_pushed;
    e.v[5] = dur;
    e.v[6] = extra_copy;
    e.v[7] = flag_copy;
    e.v[8] = finder[2];
    e.v[9] = live;
    push(e);
    t_copy_seq = 0;
}

void observer_scene_copy_on_out(uint16_t opcode, std::span<const uint8_t> payload, bool pushed) noexcept {
    if (!g_wanted.load(std::memory_order_relaxed)) return;
    if (opcode != osc::kOpPrepare && opcode != osc::kOpDelete && opcode != osc::kOpMoveField) return;
    try {
        bool ours = false;
        if (opcode == osc::kOpDelete && t_in_copy && payload.size() == osc::kDeletePayload &&
            osc::le64(&payload[4]) == t_copy_seq) {
            ++t_copy_seen;
            if (pushed) ++t_copy_pushed;
            ours = true;
        }
        if (!pushed) return;
        osc::Delivered d;
        osc::SceneBook::Seen seen;
        uint32_t epoch = 0, trip = 0;
        {
            std::lock_guard lock(g_mu);
            seen = g_book.on_out(opcode, payload, p8_now_us(), server_epoch(), &d);
            epoch = g_book.epoch();
            trip = g_book.trip();
        }
        if (seen == osc::SceneBook::Seen::Prepared || seen == osc::SceneBook::Seen::Replaced) {
            g_book_prepared.fetch_add(1, std::memory_order_relaxed);
        } else if (seen == osc::SceneBook::Seen::Closed) {
            g_book_closed.fetch_add(1, std::memory_order_relaxed);
        }
        if (seen == osc::SceneBook::Seen::Other || seen == osc::SceneBook::Seen::Trip) return;
        if (g_book_lines.fetch_add(1, std::memory_order_relaxed) >= kMaxBookLines && !ours) return;
        p8p::Event e;
        e.kind = kNBook;
        e.v[0] = static_cast<uint64_t>(seen);
        if (seen == osc::SceneBook::Seen::Prepared || seen == osc::SceneBook::Seen::Replaced) {
            e.v[1] = d.seq;
            e.v[2] = d.actor | static_cast<uint64_t>(d.owner) << 32;
            e.v[3] = epoch | static_cast<uint64_t>(trip) << 32;
            e.v[4] = static_cast<uint32_t>((payload.size() - osc::kPreparePrefix) / osc::kBindingWire);
            e.v[5] = server_user2_player_key();
        } else {
            e.v[1] = osc::le64(&payload[4]);
            e.v[5] = static_cast<uint64_t>(osc::le32(&payload[0])) << 32;
            e.v[6] = ours ? 1 : 0;
        }
        push(e);
    } catch (...) {
    }
}

void observer_scene_copy_on_epoch(uint32_t epoch) noexcept {
    if (!g_wanted.load()) return;
    try {
        std::lock_guard lock(g_mu);
        g_book.on_epoch(epoch);
    } catch (...) {
    }
}

void observer_scene_copy_drain() {
    if (!g_wanted.load()) return;
    p8p::Event e;
    while (g_ring.pop(e)) {
        if (e.kind >= kNoteCount) continue;
        std::string s = line_of(e);
        if (g_lines++ < kMaxLines) log::info("{}", s);
    }
    static uint64_t lost_logged = 0;
    if (const uint64_t lost = g_ring_lost.load(); lost != lost_logged) {
        log::warn("ObserverSceneCopy: {} line(s) lost (ring full)", lost - lost_logged);
        lost_logged = lost;
    }
}

std::string observer_scene_copy_counters() {
    if (!g_wanted.load() && !g_verified.load()) return {};
    std::string why;
    for (size_t i = 0; i < static_cast<size_t>(osc::Why::Count); ++i) {
        if (const uint64_t n = g_why[i].load()) why += std::format(" {} x{};", osc::why_name(static_cast<osc::Why>(i)), n);
    }
    size_t live = 0;
    uint64_t prepared = 0, closed = 0, unknown = 0, evicted = 0;
    uint32_t epoch = 0, trip = 0;
    {
        std::lock_guard lock(g_mu);
        live = g_book.live();
        prepared = g_book.prepared();
        closed = g_book.closed();
        unknown = g_book.closed_unknown();
        evicted = g_book.evicted();
        epoch = g_book.epoch();
        trip = g_book.trip();
    }
    return std::format("ObserverSceneCopy ({}) | 2810 decisions:{} | copies {} (in user 2's queue {}, LOST {}, not seen "
                       "{}, faults {}) | own calls seen by the hook {} | book (epoch {} trip {}): 2661 to user 2 {}, "
                       "closed by a 2810 to user 2 {}, 2810 without its 2661 {}, live {}, evicted {}",
                       observer_scene_copy_active() ? "on" : (g_disabled.load() ? "OFF after a fault" : "not verified"),
                       why.empty() ? std::string(" none") : why, g_copies.load(), g_copies_queued.load(),
                       g_copies_lost.load(), g_copies_unseen.load(), g_faults.load(), g_own_seen.load(), epoch, trip,
                       prepared, closed, unknown, live, evicted);
}

std::string observer_scene_copy_describe() {
    if (!g_wanted.load() && !g_verified.load()) return {};
    return std::format("ObserverSceneCopy {} copies {} queued {} user 2's 2661 {}",
                       observer_scene_copy_active() ? "on" : "inactive", g_copies.load(), g_copies_queued.load(),
                       g_book_prepared.load());
}

}  // namespace cdmp::session2
