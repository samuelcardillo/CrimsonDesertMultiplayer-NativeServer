#include "mod/session2/observer_milestone.h"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <format>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "mod/game/game_fault.h"
#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/fast_travel.h"
#include "mod/session2/guest_stage_diag_logic.h"
#include "mod/session2/owner_fanout.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/server.h"
#include "mod/session2/travel_probe_logic.h"

namespace cdmp::session2 {
namespace {

// ---------------------------------------------------------------- the code it relies on (build 2976, .rsrc)
//
// Read from the authorised read-only PE (D:\RE\CrimsonDesert_2976\bin\CrimsonDesert.exe,
// SHA-256 57DA440D...E1E7) with capstone (pendientes/p8-2322-observador.md §2). Nothing
// here is patched: these bytes are compared before the emission may run, and the
// functions are called exactly as the native code calls them.

// pa::ToTargetSendTargetFinder::ToTargetSendTargetFinder(this, actor) -> this (46 rel32 callers):
// [this] = ISendTargetFinder vt; byte [this+8] = 0; [this] = ToTarget vt; [this+0x10] = 0;
// if (actor) [this+0x10] = actor->vfE8() (the actor's session). Same recipe as 0x287F194-0x287F1C7.
constexpr uintptr_t kCtorRva = 0x2A757A0;
constexpr uint8_t kCtorBytes[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05, 0x44, 0xFC, 0x0A,
    0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0x76, 0xFC, 0x0A, 0x03, 0x48, 0x89, 0x01, 0x48,
    0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xD2, 0x74, 0x10, 0x48, 0x8B, 0x02, 0x48, 0x8B, 0xCA, 0xFF,
    0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x43, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3};
// Its vtable (slots 0-2) and the base's: vf0 the scalar deleting destructor (resets the vtable
// to the base; frees only with flag & 1: never for a stack object), vf1 the recipient list
// (appends [this+0x10] when non-null), vf2 the scope sender's equality (+0x10).
constexpr uintptr_t kVtToTarget = 0x5B25438, kVtFinderBase = 0x5B253F8;
constexpr uintptr_t kVf0Rva = 0x2A75740, kVf1Rva = 0x2A757F0, kVf2Rva = 0x2A75850, kBaseVf0Rva = 0x2A756B0;
constexpr uint8_t kVf0Bytes[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05, 0xA4,
    0xFC, 0x0A, 0x03, 0x48, 0x89, 0x01, 0xF6, 0xC2, 0x01, 0x74, 0x2D, 0xB9, 0xFD, 0x01, 0x00, 0x00, 0x65,
    0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x10, 0x80, 0x3C, 0x11, 0x00, 0x48, 0x8B,
    0xCB, 0x74, 0x0E, 0xE8, 0x41, 0xAC, 0xD7, 0x01, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3,
    0xE8, 0x33, 0xAB, 0xD7, 0x01, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3};
constexpr uint8_t kVf1Bytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48, 0x8B, 0xDA, 0x48,
    0x8B, 0xF9, 0x74, 0x3D, 0x8B, 0x4A, 0x08, 0x8B, 0x42, 0x0C, 0x3B, 0xC1, 0x77, 0x22, 0x8D, 0x14, 0x45, 0x01, 0x00,
    0x00, 0x00, 0x03, 0xD0, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xD1, 0xEA, 0x3B, 0xD0, 0x0F, 0x42, 0xD0, 0x3B, 0xCA, 0x0F,
    0x47, 0xD1, 0x48, 0x8B, 0xCB, 0xE8, 0xBD, 0x8B, 0x8E, 0xFD, 0x8B, 0x53, 0x08, 0x48, 0x8B, 0x47, 0x10, 0x48, 0x8B,
    0x0B, 0x48, 0x89, 0x04, 0xD1, 0xFF, 0x43, 0x08, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3};
constexpr uint8_t kVf2Bytes[] = {0x48, 0x8B, 0x42, 0x10, 0x48, 0x39, 0x41, 0x10, 0x0F, 0x94, 0xC0, 0xC3};

// PlayAllPreLoadSequencerAck 2322's emitter 0x2999D80(actor, finder): only direct caller
// 0x287F1D4. Its first 5 bytes are observer_stage's mid hook (checked there, or a jmp once
// hooked); from +5: the frame, TLS block 0 (gs:[0x58] -> [0]) +0x250 = the send context,
// +0x2B8 = 0, finder->vf1(&ctx+0x2B0), count == 0 -> return, then 0x2961CA0 (the scope
// sender lookup). 0x2999E77 writes the opcode 0x912.
constexpr uintptr_t kEmitRva = 0x2999D80;
constexpr uint8_t kEmitHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08};
constexpr uint8_t kEmitBody[] = {
    0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xD9, 0x48, 0x81,
    0xEC, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00,
    0x00, 0x00, 0x4C, 0x8B, 0x20, 0x4C, 0x89, 0x65, 0xD7, 0xB8, 0x50, 0x02, 0x00, 0x00, 0x4A, 0x8B, 0x04, 0x20,
    0x33, 0xDB, 0x89, 0x98, 0xB8, 0x02, 0x00, 0x00, 0x4C, 0x8D, 0xB8, 0xB0, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x02,
    0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCF, 0xFF, 0x50, 0x08, 0x45, 0x8B, 0x6F, 0x08, 0x45, 0x85, 0xED, 0x0F, 0x84,
    0x77, 0x03, 0x00, 0x00, 0x48, 0x8B, 0xCF, 0xE8, 0xB5, 0x7E, 0xFC, 0xFF};
constexpr uintptr_t kEmitOpRva = 0x2999E77;
constexpr uint8_t kEmitOpBytes[] = {0x66, 0x41, 0xC7, 0x06, 0x12, 0x09};

struct Region {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* what;
};

// The native recipe at 0x287F194 (up to 0x287F1CC: from there the P8 probe may patch).
constexpr uint8_t kRecipeBytes[] = {0x48, 0x8D, 0x3D, 0x5D, 0x62, 0x2A, 0x03, 0x48, 0x89, 0x7C, 0x24, 0x50, 0xC6, 0x44,
                                    0x24, 0x58, 0x00, 0x48, 0x8D, 0x05, 0x8C, 0x62, 0x2A, 0x03, 0x48, 0x89, 0x44, 0x24,
                                    0x50, 0x4C, 0x89, 0x7C, 0x24, 0x60, 0x4D, 0x85, 0xF6, 0x74, 0x11, 0x49, 0x8B, 0x06,
                                    0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x60};
// The 2144: 0x2BC6BB0 builds ToTarget(rsi->vfE8()) and calls 0x299A180 (its serializer,
// mov word [r14],0x860 at 0x299A2B3) at 0x2BC7433; then 0x2BC7475 calls MoveFieldCompleteCore.
constexpr uint8_t kSite2144Bytes[] = {
    0x48, 0x8D, 0x3D, 0x14, 0xE0, 0xF5, 0x02, 0x48, 0x89, 0x7C, 0x24, 0x30, 0xC6, 0x44, 0x24, 0x38, 0x00, 0x48, 0x8D,
    0x05, 0x43, 0xE0, 0xF5, 0x02, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x89, 0x5C, 0x24, 0x40, 0x48, 0x8B, 0x06, 0x48,
    0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x8B, 0x5D, 0x70, 0x4C, 0x8D,
    0x8B, 0x50, 0x04, 0x00, 0x00, 0x48, 0x8D, 0x85, 0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D,
    0x45, 0xE0, 0x48, 0x8D, 0x54, 0x24, 0x30, 0x48, 0x8B, 0xCE, 0xE8, 0x48, 0x2D, 0xDD, 0xFF};
constexpr uint8_t kCallCoreBytes[] = {0x48, 0x8B, 0xCB, 0xE8, 0xF6, 0x01, 0x00, 0x00};
// The 3066: inside MoveFieldCompleteCore, ToTarget(r14->vfE8()) and 0x299A610 (mov word
// [r14],0xBFA at 0x299A737) at 0x2BC80F0, before 0x2BC84E2 on every path that reaches it.
constexpr uint8_t kSite3066Bytes[] = {
    0x48, 0x8D, 0x1D, 0x44, 0xD3, 0xF5, 0x02, 0x48, 0x89, 0x5D, 0x80, 0xC6, 0x45, 0x88, 0x00, 0x48, 0x8D, 0x05,
    0x75, 0xD3, 0xF5, 0x02, 0x48, 0x89, 0x45, 0x80, 0x33, 0xC9, 0x48, 0x89, 0x4D, 0x90, 0x49, 0x8B, 0x06, 0x49,
    0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x90, 0x4C, 0x8D, 0x8D, 0xC8, 0x00, 0x00,
    0x00, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x48, 0x8D, 0x55, 0x80, 0x49, 0x8B, 0xCE, 0xE8, 0x1B, 0x25, 0xDD, 0xFF};
// The scope sender lookup 0x2961CA0 (TLS block 0 +0x250 -> +0x2AC mode, +0x2A0 count) and the
// flush of the current one 0x2962220 (+0x2A8 index, +0x298 array): the fields the hook reads.
constexpr uint8_t kScopeFindBytes[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF1, 0xBD, 0x50,
                                       0x02, 0x00, 0x00, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0x2C, 0x2A, 0x80, 0xBD, 0xAC, 0x02,
                                       0x00, 0x00, 0x00, 0x74, 0x44, 0x44, 0x8B, 0xB5, 0xA0, 0x02, 0x00, 0x00};
constexpr uint8_t kScopeCurBytes[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0xBF, 0x50, 0x02,
                                      0x00, 0x00, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x3C, 0x0F, 0x8B, 0x87, 0xA8,
                                      0x02, 0x00, 0x00, 0x83, 0xF8, 0xFF, 0x74, 0x5C, 0x8B, 0xC8, 0x48, 0x89,
                                      0x5C, 0x24, 0x30, 0x48, 0x8B, 0x87, 0x98, 0x02, 0x00, 0x00};
// ServerRunThread 0x2773390 marks its thread as the server's realm: TLS block 0 +0x1EC = 1.
constexpr uint8_t kRealmBytes[] = {0xB8, 0xEC, 0x01, 0x00, 0x00, 0xC6, 0x04, 0x18, 0x01};

const Region kRegions[] = {
    {kCtorRva, kCtorBytes, "ToTarget constructor"},
    {kVf0Rva, kVf0Bytes, "ToTarget vf0 (destructor)"},
    {kVf1Rva, kVf1Bytes, "ToTarget vf1 (recipients)"},
    {kVf2Rva, kVf2Bytes, "ToTarget vf2 (equality)"},
    {kEmitRva + sizeof kEmitHead, kEmitBody, "2322 emitter body"},
    {kEmitOpRva, kEmitOpBytes, "2322 emitter opcode write"},
    {0x287F194, kRecipeBytes, "the native ToTarget recipe before 0x287F1D4"},
    {0x2BC73DD, kSite2144Bytes, "the 2144 send in 0x2BC6BB0"},
    {0x2BC7472, kCallCoreBytes, "the call of MoveFieldCompleteCore after it"},
    {0x2BC80AD, kSite3066Bytes, "the 3066 send inside MoveFieldCompleteCore"},
    {0x2961CBA, kScopeFindBytes, "the scope sender lookup (TLS +0x250 +0x2AC/+0x2A0)"},
    {0x2962226, kScopeCurBytes, "the current scope flush (+0x2A8/+0x298)"},
    {0x27733A6, kRealmBytes, "ServerRunThread's realm mark (TLS +0x1EC)"},
};

// Build 3527 evidence: tools/porting/data/observer_milestone_3527.json and
// field_mover_layout_3527.json. Executable SHA-256:
// dc4237f21d6ce1e49f8e5d6fa89bf803fbbe6549123078efdc393265c7bf6841.
// Keep original bytes, including call displacements and layout operands.
constexpr uint8_t kCurrentCode0[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05, 
    0xBC, 0x82, 0x1E, 0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0x8E, 0x82, 
    0x1E, 0x03, 0x48, 0x89, 0x01, 0x48, 0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xD2, 
    0x74, 0x10, 0x48, 0x8B, 0x02, 0x48, 0x8B, 0xCA, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 
    0x43, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 
};
constexpr uint8_t kCurrentCode1[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05, 
    0x1C, 0x83, 0x1E, 0x03, 0x48, 0x89, 0x01, 0xF6, 0xC2, 0x01, 0x74, 0x32, 0xE8, 0xBF, 0x15, 0x85, 
    0xFE, 0xBA, 0xFE, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 
    0x8B, 0x08, 0x80, 0x3C, 0x0A, 0x00, 0x48, 0x8B, 0xCB, 0x74, 0x0E, 0xE8, 0x3C, 0xCF, 0xDF, 0x01, 
    0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xE8, 0x2E, 0xCE, 0xDF, 0x01, 0x48, 0x8B, 
    0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 
};
constexpr uint8_t kCurrentCode2[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48, 
    0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x74, 0x3D, 0x8B, 0x4A, 0x08, 0x8B, 0x42, 0x0C, 0x3B, 0xC1, 0x77, 
    0x22, 0x8D, 0x14, 0x45, 0x01, 0x00, 0x00, 0x00, 0x03, 0xD0, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xD1, 
    0xEA, 0x3B, 0xD0, 0x0F, 0x42, 0xD0, 0x3B, 0xCA, 0x0F, 0x47, 0xD1, 0x48, 0x8B, 0xCB, 0xE8, 0xDD, 
    0x38, 0x6A, 0xFD, 0x8B, 0x53, 0x08, 0x48, 0x8B, 0x47, 0x10, 0x48, 0x8B, 0x0B, 0x48, 0x89, 0x04, 
    0xD1, 0xFF, 0x43, 0x08, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3 
};
constexpr uint8_t kCurrentCode3[] = {
    0x48, 0x8B, 0x42, 0x10, 0x48, 0x39, 0x41, 0x10, 0x0F, 0x94, 0xC0, 0xC3 
};
constexpr uint8_t kCurrentCode4[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08 
};
constexpr uint8_t kCurrentCode5[] = {
    0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xD9, 
    0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x65, 0x48, 0x8B, 
    0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x20, 0x4C, 0x89, 0x65, 0xD7, 0xB8, 0x50, 0x02, 
    0x00, 0x00, 0x4A, 0x8B, 0x04, 0x20, 0x33, 0xDB, 0x89, 0x98, 0xB8, 0x02, 0x00, 0x00, 0x4C, 0x8D, 
    0xB8, 0xB0, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x02, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCF, 0xFF, 0x50, 
    0x08, 0x45, 0x8B, 0x6F, 0x08, 0x45, 0x85, 0xED, 0x0F, 0x84, 0x7C, 0x03, 0x00, 0x00, 0x48, 0x8B, 
    0xCF, 0xE8, 0xF5, 0x13, 0xFC, 0xFF 
};
constexpr uint8_t kCurrentCode6[] = {
    0x48, 0x85, 0xF6, 0x74, 0x03, 0x8B, 0x5E, 0x60, 0x89, 0x5D, 0x6F, 0x48, 0x8B, 0x00, 0x41, 0xB8, 
    0x04, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x6F, 0xFF, 0x50, 0x08 
};
constexpr uint8_t kCurrentCode7[] = {
    0x66, 0x41, 0xC7, 0x06, 0x50, 0x09 
};
constexpr uint8_t kCurrentCode8[] = {
    0x48, 0x8D, 0x3D, 0x95, 0x15, 0x41, 0x03, 0x48, 0x89, 0x7C, 0x24, 0x50, 0xC6, 0x44, 0x24, 0x58, 
    0x00, 0x48, 0x8D, 0x05, 0x64, 0x15, 0x41, 0x03, 0x48, 0x89, 0x44, 0x24, 0x50, 0x4C, 0x89, 0x7C, 
    0x24, 0x60, 0x4D, 0x85, 0xF6, 0x74, 0x11, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 
    0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x60 
};
constexpr uint8_t kCurrentCode9[] = {
    0x48, 0x8D, 0x54, 0x24, 0x50, 0x49, 0x8B, 0xCE, 0xE8, 0x97, 0x8F, 0x13, 0x00, 0x90, 0x48, 0x89, 
    0x7C, 0x24, 0x50 
};
constexpr uint8_t kCurrentCode10[] = {
    0x48, 0x8D, 0x3D, 0x35, 0x25, 0x08, 0x03, 0x48, 0x89, 0x7D, 0x90, 0xC6, 0x45, 0x98, 0x00, 0x48, 
    0x8D, 0x05, 0x06, 0x25, 0x08, 0x03, 0x48, 0x89, 0x45, 0x90, 0x4C, 0x89, 0x65, 0xA0, 0x48, 0x8B, 
    0x06, 0x48, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xA0, 0x4D, 0x8D, 
    0x8D, 0x50, 0x04, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x70, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D, 
    0x45, 0xE0, 0x48, 0x8D, 0x55, 0x90, 0x48, 0x8B, 0xCE, 0xE8, 0x2E, 0xA3, 0xDA, 0xFF 
};
constexpr uint8_t kCurrentCode11[] = {
    0x66, 0x41, 0xC7, 0x06, 0x24, 0x09 
};
constexpr uint8_t kCurrentCode12[] = {
    0x4C, 0x8B, 0x4C, 0x24, 0x70, 0x4C, 0x8B, 0xC3, 0x48, 0x8D, 0x55, 0x60, 0x49, 0x8B, 0xCD, 0xE8, 
    0x4D, 0x03, 0x00, 0x00 
};
constexpr uint8_t kCurrentCode13[] = {
    0x4D, 0x8B, 0xE9, 0x4D, 0x8B, 0xF8, 0x48, 0x8B, 0xF1, 0x33, 0xC0, 0x89, 0x44, 0x24, 0x68, 0x4C, 
    0x8B, 0x71, 0x08 
};
constexpr uint8_t kCurrentCode14[] = {
    0x48, 0x8D, 0x1D, 0x7B, 0x16, 0x08, 0x03, 0x48, 0x89, 0x5C, 0x24, 0x70, 0xC6, 0x44, 0x24, 0x78, 
    0x00, 0x48, 0x8D, 0x05, 0x4A, 0x16, 0x08, 0x03, 0x48, 0x89, 0x44, 0x24, 0x70, 0x33, 0xC9, 0x48, 
    0x89, 0x4D, 0x80, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 
    0x89, 0x45, 0x80, 0x4C, 0x8D, 0x8D, 0x18, 0x01, 0x00, 0x00, 0x4C, 0x8D, 0x44, 0x24, 0x40, 0x48, 
    0x8D, 0x54, 0x24, 0x70, 0x49, 0x8B, 0xCE, 0xE8, 0x16, 0x99, 0xDA, 0xFF 
};
constexpr uint8_t kCurrentCode15[] = {
    0x66, 0x41, 0xC7, 0x06, 0xD5, 0x0B 
};
constexpr uint8_t kCurrentCode16[] = {
    0x49, 0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x45, 0x33, 0xED, 0x48, 0x85, 0xC0, 0x74, 0x05, 0x8B, 
    0x40, 0x60, 0xEB, 0x03, 0x41, 0x8B, 0xC5, 0x45, 0x8B, 0x87, 0x80, 0x01, 0x00, 0x00, 0x41, 0x3B, 
    0xC0, 0x75, 0x69 
};
constexpr uint8_t kCurrentCode17[] = {
    0x48, 0x8B, 0x44, 0x24, 0x78, 0x48, 0x8B, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x68, 
    0x48, 0x8B, 0x88, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x59, 0x18 
};
constexpr uint8_t kCurrentCode18[] = {
    0x4C, 0x8B, 0x4C, 0x24, 0x50, 0x4D, 0x8B, 0xC6, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xE8, 0x24, 
    0xFA, 0xC6, 0xFF, 0x48, 0x8B, 0x4F, 0x18, 0xE8, 0x9B, 0xED, 0xC1, 0xFF 
};
constexpr uint8_t kCurrentCode19[] = {
    0x49, 0x8B, 0x87, 0xD8, 0x02, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x75, 0x07, 0xB8, 0xFF, 0xFF, 0x00 
};
constexpr uint8_t kCurrentCode20[] = {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF1, 0xBD, 0x50, 0x02, 0x00, 
    0x00, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0x2C, 0x2A, 0x80, 0xBD, 0xAC, 0x02, 0x00, 0x00, 0x00, 0x74, 
    0x44, 0x44, 0x8B, 0xB5, 0xA0, 0x02, 0x00, 0x00 
};
constexpr uint8_t kCurrentCode21[] = {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0xBF, 0x50, 0x02, 0x00, 0x00, 0x48, 0x8B, 
    0x08, 0x48, 0x8B, 0x3C, 0x0F, 0x8B, 0x87, 0xA8, 0x02, 0x00, 0x00, 0x83, 0xF8, 0xFF, 0x74, 0x5C, 
    0x8B, 0xC8, 0x48, 0x89, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0x87, 0x98, 0x02, 0x00, 0x00 
};
constexpr uint8_t kCurrentCode22[] = {
    0xB8, 0xEB, 0x01, 0x00, 0x00, 0xC6, 0x04, 0x18, 0x01 
};
constexpr uint8_t kCurrentCode23[] = {
    0x48, 0x8B, 0x81, 0xD0, 0x00, 0x00, 0x00, 0xC3 
};
constexpr uint8_t kCurrentCode24[] = {
    0x48, 0x8B, 0x81, 0xF8, 0x01, 0x00, 0x00, 0xC3 
};
constexpr uint8_t kCurrentCode25[] = {
    0x48, 0x8B, 0x4D, 0xB8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0xC6, 0x80, 0x59, 0x02, 0x00, 0x00, 
    0x02 
};
constexpr uint8_t kCurrentCode26[] = {
    0x49, 0x8B, 0x8D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x09, 0xE8, 0x01, 0x47, 0x25, 0x00, 0x80, 
    0xB8, 0x59, 0x02, 0x00, 0x00, 0x02, 0x0F, 0x82, 0x62, 0x03, 0x00, 0x00, 0xC4, 0xC1, 0x7B, 0x10, 
    0x85, 0x50, 0x01, 0x00, 0x00, 0xC5, 0xFB, 0x11, 0x45, 0x10, 0x41, 0x8B, 0x8D, 0x58, 0x01, 0x00, 
    0x00, 0x89, 0x4D, 0x18, 0x48, 0x8D, 0x55, 0x10, 0x48, 0x8B, 0xC8, 0xE8, 0xA0, 0xCE, 0x34, 0x00, 
    0x84, 0xC0, 0x0F, 0x84, 0x36, 0x03, 0x00, 0x00, 0x41, 0xC6, 0x85, 0x5C, 0x01, 0x00, 0x00 
};
constexpr uint8_t kCurrentCode27[] = {
    0x48, 0x8B, 0x6E, 0x10 
};
constexpr uint8_t kCurrentCode28[] = {
    0x48, 0x8B, 0x46, 0x68 
};
constexpr uint8_t kCurrentCode29[] = {
    0x48, 0x8B, 0x88, 0xA0, 0x01, 0x00, 0x00 
};
constexpr uint8_t kCurrentTsFieldChain[] = {
    0x48, 0x8B, 0x48, 0x68, 0x48, 0x8B, 0x99, 0xA0, 0x01, 0x00, 0x00,
    0x48, 0x8D, 0x8B, 0x08, 0x05, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24,
    0x20, 0xE8, 0xDA, 0xCA, 0x15, 0x00};
constexpr uint8_t kCurrentFieldThis[] = {0x48, 0x8B, 0xF9};
constexpr uint8_t kCurrentFieldKey[] = {0xC7, 0x87, 0xD0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00};
const Region kRegions3527[] = {
    {0x2d04590, kCurrentCode0, "ToTarget constructor: RCX=finder, RDX=actor; vfE8 returns session"},
    {0x2d04530, kCurrentCode1, "ToTarget scalar deleting destructor; flag0 only resets base vtable"},
    {0x2d045e0, kCurrentCode2, "ToTarget recipient append from finder+10"},
    {0x2d04640, kCurrentCode3, "ToTarget session equality"},
    {0x2c142a0, kCurrentCode4, "2322/native2384 emitter original head"},
    {0x2c142a5, kCurrentCode5, "Emitter frame, actor/finder ABI, TLS250, recipients2B0/count2B8, ScopeFind"},
    {0x2c1437c, kCurrentCode6, "Emitter serializes actor key+60 as exactly four bytes"},
    {0x2c14397, kCurrentCode7, "Emitter native2384 opcode0x950"},
    {0x2adb2c4, kCurrentCode8, "Native stack ToTarget recipe before emitter call"},
    {0x2adb2fc, kCurrentCode9, "Native actor/finder argument setup, emitter call, stack destructor reset"},
    {0x2e6a324, kCurrentCode10, "2144/native2340 finder recipe and emitter call"},
    {0x2c147d3, kCurrentCode11, "2144 writer native2340 opcode0x924"},
    {0x2e6a39f, kCurrentCode12, "2144 wrapper sets R8 field, RCX component and calls MoveFieldCompleteCore"},
    {0x2e6a72a, kCurrentCode13, "Core register provenance: R15=R8 field; R14=[RCX+8] actor"},
    {0x2e6b1de, kCurrentCode14, "3066/native3029 finder recipe and emitter call before milestone"},
    {0x2c14c67, kCurrentCode15, "3066 writer native3029 opcode0xBD5"},
    {0x2e6b5e0, kCurrentCode16, "Actor+A0 user, user+60 identity compared with fieldR15+180; nonowner skips native2322"},
    {0x2e6b628, kCurrentCode17, "Owner user+D0 main, main+68 components, components+A8 sequencer, component+18 manager"},
    {0x2e6b659, kCurrentCode18, "Owner-only native2322 call then owner/nonowner converge before hook"},
    {0x2e6b675, kCurrentCode19, "Milestone hook: original seven-byte instruction reads fieldR15+2D8"},
    {0x2bd571a, kCurrentCode20, "Scope lookup TLS250, mode2AC and count2A0"},
    {0x2bd5c86, kCurrentCode21, "Current scope flush TLS250, current2A8 and array298"},
    {0x29aaf36, kCurrentCode22, "ServerRunThread realm TLS1EB=1"},
    {0xbe5a10, kCurrentCode23, "ServerChildOnlyInGameActor vfE8 returns actor+D0 session"},
    {0x2d0c4f0, kCurrentCode24, "ServerUserActor vfE8 returns user+1F8 session"},
    {0xc9cb91, kCurrentCode25, "2322 client handler obtains field sequencer and writes readiness+259=2"},
    {0x856090, kCurrentCode26, "Loading state11 waits for owner sequencer+259>=2 then BA2F70 predicate before state12"},
    {0x2e61263, kCurrentCode27, "The same object supplies its ServerField"},
    {0x2e61a23, kCurrentCode28, "MoveField obtains the actor component table"},
    {0x2e61a27, kCurrentCode29, "MoveField obtains TransformSync"},
    {0x2D0467A, kCurrentTsFieldChain, "actor+68 -> components+1A0 -> TS+508 GetField; its field at +10 gives TS+518"},
    {0x2D8CA6F, kCurrentFieldThis, "ServerField constructor preserves this in RDI"},
    {0x2D8CDDF, kCurrentFieldKey, "ServerField constructor initializes its key at +2D0"},
};

// The objects the decision reads (the same offsets as the rest of option D):
constexpr uint32_t kActor_Key = 0x60, kActor_User = 0xA0, kActor_Comp = 0x68, kComp_TS = 0x1A0;
constexpr uint32_t kUser_Key = 0x60, kUser_Main = 0xD0, kUser_Session = 0x1F8;
constexpr uint32_t kField_Owner = 0x180;
constexpr uint32_t kCtx_ScopeCount = 0x2A0, kCtx_ScopeCurrent = 0x2A8, kCtx_ScopeMode = 0x2AC;

struct NativeLayout {
    uintptr_t ctor, emit, target_vtable, base_vtable;
    uint32_t ts_field, field_key, tls_realm, tls_send_ctx;
};
constexpr NativeLayout kLayout2976{kCtorRva, kEmitRva, kVtToTarget, kVtFinderBase,
                                    0x500, 0x2C8, 0x1EC, 0x250};
// The current finder and emitter retain their ABI. Field/TS tails and the
// server realm byte moved; the send-context scope fields above did not.
constexpr NativeLayout kLayout3527{0x2D04590, 0x2C142A0, 0x5EEC840, 0x5EEC860,
                                    0x518, 0x2D0, 0x1EB, 0x250};
constexpr uintptr_t kEntry3527 = 0x2E6B675;
constexpr uint8_t kEntryBytes3527[] = {0x49, 0x8B, 0x87, 0xD8, 0x02, 0x00, 0x00,
                                      0x48, 0x85, 0xC0, 0x75, 0x07, 0xB8, 0xFF, 0xFF, 0x00};

// Build 1.0.0.3576 (static, 2026-11-06; not yet run). Every 3527 region was found again with relative operands masked,
// each at one place: +0xC70 for the finder, the emitter, MoveField/MoveFieldCompleteCore, the scope lookup, the user
// session and the ServerField constructor; +0xC50 for 0x2ADB2C4/0x2ADB2FC (native recipe) and 0x29AAF36 (realm);
// +0x420 for 0xBE5A10 (actor session) and 0xC9CB91 (client 2322 handler); +0x250 for 0x856090 (loading state 11).
// The nine `_3576` arrays differ from 3527 only in rel32/RIP fields, and each new target is the mapped one: the
// ToTarget/ISendTargetFinder vtables 0x5EEC840/0x5EEC860 -> 0x5EEEA60/0x5EEEA80 (RTTI map), the emitter 0x2C142A0 ->
// 0x2C14F10, its writers 0x2C146A0/0x2C14B40 -> 0x2C15310/0x2C157B0, 0x2ADB090 -> 0x2ADBCE0, 0x2A8A410 -> 0x2A8B060,
// 0xAAA7A0 -> 0xAAABB0, 0xBA2F70 -> 0xBA3390 (all function starts in .pdata). Layout operands (TS+0x508/+0x518, field
// +0x2D0/+0x2D8/+0x180, TLS +0x1EB/+0x250, scope +0x2A0/+0x2A8/+0x2AC, opcodes 0x950/0x924/0xBD5) are unchanged.
constexpr uint8_t kCurrentCode0_3576[] = {  // 0x2D05200
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
    0x6C, 0x98, 0x1E, 0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0x3E, 0x98,
    0x1E, 0x03, 0x48, 0x89, 0x01, 0x48, 0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xD2,
    0x74, 0x10, 0x48, 0x8B, 0x02, 0x48, 0x8B, 0xCA, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89,
    0x43, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};
constexpr uint8_t kCurrentCode1_3576[] = {  // 0x2D051A0
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
    0xCC, 0x98, 0x1E, 0x03, 0x48, 0x89, 0x01, 0xF6, 0xC2, 0x01, 0x74, 0x32, 0xE8, 0x6F, 0x11, 0x85,
    0xFE, 0xBA, 0xFE, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48,
    0x8B, 0x08, 0x80, 0x3C, 0x0A, 0x00, 0x48, 0x8B, 0xCB, 0x74, 0x0E, 0xE8, 0xAC, 0xD2, 0xDF, 0x01,
    0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xE8, 0x9E, 0xD1, 0xDF, 0x01, 0x48, 0x8B,
    0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};
constexpr uint8_t kCurrentCode2_3576[] = {  // 0x2D05250
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48,
    0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x74, 0x3D, 0x8B, 0x4A, 0x08, 0x8B, 0x42, 0x0C, 0x3B, 0xC1, 0x77,
    0x22, 0x8D, 0x14, 0x45, 0x01, 0x00, 0x00, 0x00, 0x03, 0xD0, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xD1,
    0xEA, 0x3B, 0xD0, 0x0F, 0x42, 0xD0, 0x3B, 0xCA, 0x0F, 0x47, 0xD1, 0x48, 0x8B, 0xCB, 0xE8, 0x4D,
    0x2F, 0x6A, 0xFD, 0x8B, 0x53, 0x08, 0x48, 0x8B, 0x47, 0x10, 0x48, 0x8B, 0x0B, 0x48, 0x89, 0x04,
    0xD1, 0xFF, 0x43, 0x08, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3
};
constexpr uint8_t kCurrentCode8_3576[] = {  // 0x2ADBF14
    0x48, 0x8D, 0x3D, 0x65, 0x2B, 0x41, 0x03, 0x48, 0x89, 0x7C, 0x24, 0x50, 0xC6, 0x44, 0x24, 0x58,
    0x00, 0x48, 0x8D, 0x05, 0x34, 0x2B, 0x41, 0x03, 0x48, 0x89, 0x44, 0x24, 0x50, 0x4C, 0x89, 0x7C,
    0x24, 0x60, 0x4D, 0x85, 0xF6, 0x74, 0x11, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8,
    0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x60
};
constexpr uint8_t kCurrentCode9_3576[] = {  // 0x2ADBF4C
    0x48, 0x8D, 0x54, 0x24, 0x50, 0x49, 0x8B, 0xCE, 0xE8, 0xB7, 0x8F, 0x13, 0x00, 0x90, 0x48, 0x89,
    0x7C, 0x24, 0x50
};
constexpr uint8_t kCurrentCode10_3576[] = {  // 0x2E6AF94
    0x48, 0x8D, 0x3D, 0xE5, 0x3A, 0x08, 0x03, 0x48, 0x89, 0x7D, 0x90, 0xC6, 0x45, 0x98, 0x00, 0x48,
    0x8D, 0x05, 0xB6, 0x3A, 0x08, 0x03, 0x48, 0x89, 0x45, 0x90, 0x4C, 0x89, 0x65, 0xA0, 0x48, 0x8B,
    0x06, 0x48, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xA0, 0x4D, 0x8D,
    0x8D, 0x50, 0x04, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x70, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D,
    0x45, 0xE0, 0x48, 0x8D, 0x55, 0x90, 0x48, 0x8B, 0xCE, 0xE8, 0x2E, 0xA3, 0xDA, 0xFF
};
constexpr uint8_t kCurrentCode14_3576[] = {  // 0x2E6BE4E
    0x48, 0x8D, 0x1D, 0x2B, 0x2C, 0x08, 0x03, 0x48, 0x89, 0x5C, 0x24, 0x70, 0xC6, 0x44, 0x24, 0x78,
    0x00, 0x48, 0x8D, 0x05, 0xFA, 0x2B, 0x08, 0x03, 0x48, 0x89, 0x44, 0x24, 0x70, 0x33, 0xC9, 0x48,
    0x89, 0x4D, 0x80, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48,
    0x89, 0x45, 0x80, 0x4C, 0x8D, 0x8D, 0x18, 0x01, 0x00, 0x00, 0x4C, 0x8D, 0x44, 0x24, 0x40, 0x48,
    0x8D, 0x54, 0x24, 0x70, 0x49, 0x8B, 0xCE, 0xE8, 0x16, 0x99, 0xDA, 0xFF
};
constexpr uint8_t kCurrentCode18_3576[] = {  // 0x2E6C2C9
    0x4C, 0x8B, 0x4C, 0x24, 0x50, 0x4D, 0x8B, 0xC6, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xE8, 0x04,
    0xFA, 0xC6, 0xFF, 0x48, 0x8B, 0x4F, 0x18, 0xE8, 0x7B, 0xED, 0xC1, 0xFF
};
constexpr uint8_t kCurrentCode26_3576[] = {  // 0x8562E0
    0x49, 0x8B, 0x8D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x09, 0xE8, 0xC1, 0x48, 0x25, 0x00, 0x80,
    0xB8, 0x59, 0x02, 0x00, 0x00, 0x02, 0x0F, 0x82, 0x62, 0x03, 0x00, 0x00, 0xC4, 0xC1, 0x7B, 0x10,
    0x85, 0x50, 0x01, 0x00, 0x00, 0xC5, 0xFB, 0x11, 0x45, 0x10, 0x41, 0x8B, 0x8D, 0x58, 0x01, 0x00,
    0x00, 0x89, 0x4D, 0x18, 0x48, 0x8D, 0x55, 0x10, 0x48, 0x8B, 0xC8, 0xE8, 0x70, 0xD0, 0x34, 0x00,
    0x84, 0xC0, 0x0F, 0x84, 0x36, 0x03, 0x00, 0x00, 0x41, 0xC6, 0x85, 0x5C, 0x01, 0x00, 0x00
};
const Region kRegions3576[] = {
    {0x2D05200, kCurrentCode0_3576, "ToTarget constructor: RCX=finder, RDX=actor; vfE8 returns session"},
    {0x2D051A0, kCurrentCode1_3576, "ToTarget scalar deleting destructor; flag0 only resets base vtable"},
    {0x2D05250, kCurrentCode2_3576, "ToTarget recipient append from finder+10"},
    {0x2D052B0, kCurrentCode3, "ToTarget session equality"},
    {0x2C14F10, kCurrentCode4, "2322/native2384 emitter original head"},
    {0x2C14F15, kCurrentCode5, "Emitter frame, actor/finder ABI, TLS250, recipients2B0/count2B8, ScopeFind"},
    {0x2C14FEC, kCurrentCode6, "Emitter serializes actor key+60 as exactly four bytes"},
    {0x2C15007, kCurrentCode7, "Emitter native2384 opcode0x950"},
    {0x2ADBF14, kCurrentCode8_3576, "Native stack ToTarget recipe before emitter call"},
    {0x2ADBF4C, kCurrentCode9_3576, "Native actor/finder argument setup, emitter call, stack destructor reset"},
    {0x2E6AF94, kCurrentCode10_3576, "2144/native2340 finder recipe and emitter call"},
    {0x2C15443, kCurrentCode11, "2144 writer native2340 opcode0x924"},
    {0x2E6B00F, kCurrentCode12, "2144 wrapper sets R8 field, RCX component and calls MoveFieldCompleteCore"},
    {0x2E6B39A, kCurrentCode13, "Core register provenance: R15=R8 field; R14=[RCX+8] actor"},
    {0x2E6BE4E, kCurrentCode14_3576, "3066/native3029 finder recipe and emitter call before milestone"},
    {0x2C158D7, kCurrentCode15, "3066 writer native3029 opcode0xBD5"},
    {0x2E6C250, kCurrentCode16, "Actor+A0 user, user+60 identity compared with fieldR15+180; nonowner skips native2322"},
    {0x2E6C298, kCurrentCode17, "Owner user+D0 main, main+68 components, components+A8 sequencer, component+18 manager"},
    {0x2E6C2C9, kCurrentCode18_3576, "Owner-only native2322 call then owner/nonowner converge before hook"},
    {0x2E6C2E5, kCurrentCode19, "Milestone hook: original seven-byte instruction reads fieldR15+2D8"},
    {0x2BD638A, kCurrentCode20, "Scope lookup TLS250, mode2AC and count2A0"},
    {0x2BD68F6, kCurrentCode21, "Current scope flush TLS250, current2A8 and array298"},
    {0x29ABB86, kCurrentCode22, "ServerRunThread realm TLS1EB=1"},
    {0xBE5E30, kCurrentCode23, "ServerChildOnlyInGameActor vfE8 returns actor+D0 session"},
    {0x2D0D160, kCurrentCode24, "ServerUserActor vfE8 returns user+1F8 session"},
    {0xC9CFB1, kCurrentCode25, "2322 client handler obtains field sequencer and writes readiness+259=2"},
    {0x8562E0, kCurrentCode26_3576, "Loading state11 waits for owner sequencer+259>=2 then BA2F70 predicate before state12"},
    {0x2E61ED3, kCurrentCode27, "The same object supplies its ServerField"},
    {0x2E62693, kCurrentCode28, "MoveField obtains the actor component table"},
    {0x2E62697, kCurrentCode29, "MoveField obtains TransformSync"},
    {0x2D052EA, kCurrentTsFieldChain, "actor+68 -> components+1A0 -> TS+508 GetField; its field at +10 gives TS+518"},
    {0x2D8D6DF, kCurrentFieldThis, "ServerField constructor preserves this in RDI"},
    {0x2D8DA4F, kCurrentFieldKey, "ServerField constructor initializes its key at +2D0"},
};
constexpr NativeLayout kLayout3576{0x2D05200, 0x2C14F10, 0x5EEEA60, 0x5EEEA80,
                                    0x518, 0x2D0, 0x1EB, 0x250};
constexpr uintptr_t kEntry3576 = 0x2E6C2E5;  // 0x2E6B675 + 0xC70, kEntryBytes3527 unchanged

// Build 1.0.0.3663 (static, 2026-11-13; never run). Every 3527 region was found again (relative operands masked) inside
// the same function, located by .pdata and by calls to functions already mapped: ToTarget's ctor/vf0/vf1/vf2 at 3527 +
// 0x67BC0 (= slots 0..2 of .?AVToTarget's vtable 0x5F68760 and slot 0 of the finder base 0x5F68740, RTTI map of 3576's
// 0x5EEEA60/0x5EEEA80), the three writers at 3527 + 0x66700 (2322 emitter 0x2C7A9A0, 2144 writer 0x2C7ADA0, 3066 writer
// 0x2C7B240: the only functions that write the 3663 natives of logical 2322/2144/3066, 2941/2268/2792 =
// 0xB7D/0x8DC/0xAE8, opcode_mapping_3576_3663.json PlayAllPreLoadSequencerAck/MoveFieldCompleteAck/
// MoveFieldCompletePostAck), the native recipe 0x2B3F9B0 (+0x64920; Code18 calls it), the 2144 wrapper and
// MoveFieldCompleteCore 0x2ED29D0/0x2ED3360 (Code12's call +0x34D unchanged), the scope lookup/flush 0x2C3BDE0/0x2C3C360
// (the emitter's call target), the realm mark 0x2A0E1A0, GetField 0x2EC9C70 (the chain's call), MoveField 0x2ECA480 and
// the ServerField ctor 0x2DF4470 (+0x67A10). The vfE8 session getters are slot 0x1D of ServerChildOnlyInGameActor
// 0x5F610C8 (0xC1D4E0) and ServerUserActor 0x5F68B10 (0x2D740C0), same bytes. The `_3663` arrays: 0/1/2/5/8/9/10/18 and
// the TS chain differ only in rel32/RIP fields (each new target named above); 7/11/15 carry the new native opcodes; four
// regions changed shape:
//   13: MoveFieldCompleteCore no longer copies r9 to r13 (r9 goes to its home slot); still r15 = r8 (field) and r14 =
//       [rcx+8] (actor), and r14 is reloaded from [rbp+0x108] only on the result-store exits (0x2ED37B6, 0x2ED39AC,
//       0x2ED3B47, 0x2ED4055, 0x2ED40EF, and 0x2ED4338 after the entry), never on the path through 0x2ED426D..0x2ED4302;
//   14: the 3066 writer's last two arguments are now &[rsp+0x41]/&[rsp+0x40] (same ToTarget recipe, same writer);
//   25/26: the client sequencer's readiness byte moved +0x259 -> +0x261 (written 0/1/2 at 0x883807/0x883E61/0xCD563B,
//       compared with 2 at 0x882D87/0xBDA308/0xBDAF8B; nothing in the code section writes or compares +0x259 any more),
//       and the client load machine's fields moved +0xF0 (+0xC0 -> +0x1B0, +0x150/+0x158 -> +0x240/+0x248, state
//       +0x15C -> +0x24C); the wait-for-readiness state is now 0x12 (0x13 after it), with the same check and predicate
//       0xBDAF10 (3527's 0xBA2F70);
//   28: MoveField now keeps the actor in r12: `mov rax,[r12+0x68]`, then Code29 (+0x1A0) unchanged.
// Layout operands used by the hook (TS+0x508/+0x518 via GetField, field +0x2D0/+0x2D8/+0x180, TLS +0x1EB/+0x250, scope
// +0x2A0/+0x2A8/+0x2AC, actor +0x60/+0xA0/+0x68, user +0xD0/+0x1F8, main +0x68/+0xA8/+0x18) keep 3527's bytes.
constexpr uint8_t kCurrentCode0_3663[] = {  // 0x2D6C150
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
    0xDC, 0xC5, 0x1F, 0x03, 0x48, 0x89, 0x01, 0xC6, 0x41, 0x08, 0x00, 0x48, 0x8D, 0x05, 0xEE, 0xC5,
    0x1F, 0x03, 0x48, 0x89, 0x01, 0x48, 0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xD2,
    0x74, 0x10, 0x48, 0x8B, 0x02, 0x48, 0x8B, 0xCA, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89,
    0x43, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};
constexpr uint8_t kCurrentCode1_3663[] = {  // 0x2D6C0F0
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x05,
    0x3C, 0xC6, 0x1F, 0x03, 0x48, 0x89, 0x01, 0xF6, 0xC2, 0x01, 0x74, 0x32, 0xE8, 0x2F, 0x96, 0x82,
    0xFE, 0xBA, 0xFE, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x48,
    0x8B, 0x08, 0x80, 0x3C, 0x0A, 0x00, 0x48, 0x8B, 0xCB, 0x74, 0x0E, 0xE8, 0x9C, 0x29, 0xE1, 0x01,
    0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xE8, 0x8E, 0x28, 0xE1, 0x01, 0x48, 0x8B,
    0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};
constexpr uint8_t kCurrentCode2_3663[] = {  // 0x2D6C1A0
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48,
    0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x74, 0x3D, 0x8B, 0x4A, 0x08, 0x8B, 0x42, 0x0C, 0x3B, 0xC1, 0x77,
    0x22, 0x8D, 0x14, 0x45, 0x01, 0x00, 0x00, 0x00, 0x03, 0xD0, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xD1,
    0xEA, 0x3B, 0xD0, 0x0F, 0x42, 0xD0, 0x3B, 0xCA, 0x0F, 0x47, 0xD1, 0x48, 0x8B, 0xCB, 0xE8, 0xDD,
    0xF1, 0x63, 0xFD, 0x8B, 0x53, 0x08, 0x48, 0x8B, 0x47, 0x10, 0x48, 0x8B, 0x0B, 0x48, 0x89, 0x04,
    0xD1, 0xFF, 0x43, 0x08, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3
};
constexpr uint8_t kCurrentCode5_3663[] = {  // 0x2C7A9A5
    0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xD9,
    0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x65, 0x48, 0x8B,
    0x04, 0x25, 0x58, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x20, 0x4C, 0x89, 0x65, 0xD7, 0xB8, 0x50, 0x02,
    0x00, 0x00, 0x4A, 0x8B, 0x04, 0x20, 0x33, 0xDB, 0x89, 0x98, 0xB8, 0x02, 0x00, 0x00, 0x4C, 0x8D,
    0xB8, 0xB0, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x02, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCF, 0xFF, 0x50,
    0x08, 0x45, 0x8B, 0x6F, 0x08, 0x45, 0x85, 0xED, 0x0F, 0x84, 0x7C, 0x03, 0x00, 0x00, 0x48, 0x8B,
    0xCF, 0xE8, 0xD5, 0x13, 0xFC, 0xFF
};
constexpr uint8_t kCurrentCode7_3663[] = {  // 0x2C7AA97
    0x66, 0x41, 0xC7, 0x06, 0x7D, 0x0B
};
constexpr uint8_t kCurrentCode8_3663[] = {  // 0x2B3FBE4
    0x48, 0x8D, 0x3D, 0x55, 0x8B, 0x42, 0x03, 0x48, 0x89, 0x7C, 0x24, 0x50, 0xC6, 0x44, 0x24, 0x58,
    0x00, 0x48, 0x8D, 0x05, 0x64, 0x8B, 0x42, 0x03, 0x48, 0x89, 0x44, 0x24, 0x50, 0x4C, 0x89, 0x7C,
    0x24, 0x60, 0x4D, 0x85, 0xF6, 0x74, 0x11, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8,
    0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x60
};
constexpr uint8_t kCurrentCode9_3663[] = {  // 0x2B3FC1C
    0x48, 0x8D, 0x54, 0x24, 0x50, 0x49, 0x8B, 0xCE, 0xE8, 0x77, 0xAD, 0x13, 0x00, 0x90, 0x48, 0x89,
    0x7C, 0x24, 0x50
};
constexpr uint8_t kCurrentCode10_3663[] = {  // 0x2ED2F84
    0x48, 0x8D, 0x3D, 0xB5, 0x57, 0x09, 0x03, 0x48, 0x89, 0x7D, 0x90, 0xC6, 0x45, 0x98, 0x00, 0x48,
    0x8D, 0x05, 0xC6, 0x57, 0x09, 0x03, 0x48, 0x89, 0x45, 0x90, 0x4C, 0x89, 0x65, 0xA0, 0x48, 0x8B,
    0x06, 0x48, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xA0, 0x4D, 0x8D,
    0x8D, 0x50, 0x04, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x70, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D,
    0x45, 0xE0, 0x48, 0x8D, 0x55, 0x90, 0x48, 0x8B, 0xCE, 0xE8, 0xCE, 0x7D, 0xDA, 0xFF
};
constexpr uint8_t kCurrentCode11_3663[] = {  // 0x2C7AED3
    0x66, 0x41, 0xC7, 0x06, 0xDC, 0x08
};
constexpr uint8_t kCurrentCode13_3663[] = {  // 0x2ED338E
    0x4D, 0x8B, 0xF8, 0x48, 0x8B, 0xF1, 0x33, 0xC0, 0x89, 0x44, 0x24, 0x68, 0x4C, 0x8B, 0x71, 0x08
};
constexpr uint8_t kCurrentCode14_3663[] = {  // 0x2ED3E3B
    0x48, 0x8D, 0x1D, 0xFE, 0x48, 0x09, 0x03, 0x48, 0x89, 0x5C, 0x24, 0x70, 0xC6, 0x44, 0x24, 0x78,
    0x00, 0x48, 0x8D, 0x05, 0x0D, 0x49, 0x09, 0x03, 0x48, 0x89, 0x44, 0x24, 0x70, 0x33, 0xC0, 0x48,
    0x89, 0x45, 0x80, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x48,
    0x89, 0x45, 0x80, 0x4C, 0x8D, 0x4C, 0x24, 0x40, 0x4C, 0x8D, 0x44, 0x24, 0x41, 0x48, 0x8D, 0x54,
    0x24, 0x70, 0x49, 0x8B, 0xCE, 0xE8, 0xBB, 0x73, 0xDA, 0xFF
};
constexpr uint8_t kCurrentCode15_3663[] = {  // 0x2C7B367
    0x66, 0x41, 0xC7, 0x06, 0xE8, 0x0A
};
constexpr uint8_t kCurrentCode18_3663[] = {  // 0x2ED42E6
    0x4C, 0x8B, 0x4C, 0x24, 0x50, 0x4D, 0x8B, 0xC6, 0x49, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xE8, 0xB7,
    0xB6, 0xC6, 0xFF, 0x48, 0x8B, 0x4F, 0x18, 0xE8, 0xCE, 0xAE, 0xC1, 0xFF
};
constexpr uint8_t kCurrentCode25_3663[] = {  // 0xCD5631
    0x48, 0x8B, 0x4D, 0xB8, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0xC6, 0x80, 0x61, 0x02, 0x00, 0x00,
    0x02
};
constexpr uint8_t kCurrentCode26_3663[] = {  // 0x882D78
    0x49, 0x8B, 0x8D, 0xB0, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x09, 0xE8, 0x89, 0xD9, 0x25, 0x00, 0x80,
    0xB8, 0x61, 0x02, 0x00, 0x00, 0x02, 0x0F, 0x82, 0x56, 0x03, 0x00, 0x00, 0xC4, 0xC1, 0x7B, 0x10,
    0x85, 0x40, 0x02, 0x00, 0x00, 0xC5, 0xFB, 0x11, 0x44, 0x24, 0x70, 0x41, 0x8B, 0x8D, 0x48, 0x02,
    0x00, 0x00, 0x89, 0x4C, 0x24, 0x78, 0x48, 0x8D, 0x54, 0x24, 0x70, 0x48, 0x8B, 0xC8, 0xE8, 0x55,
    0x81, 0x35, 0x00, 0x84, 0xC0, 0x0F, 0x84, 0x27, 0x03, 0x00, 0x00, 0x41, 0xC6, 0x85, 0x4C, 0x02,
    0x00, 0x00
};
constexpr uint8_t kCurrentCode28_3663[] = {  // 0x2ECA514
    0x49, 0x8B, 0x44, 0x24, 0x68
};
constexpr uint8_t kCurrentTsFieldChain_3663[] = {  // 0x2D6C23A
    0x48, 0x8B, 0x48, 0x68, 0x48, 0x8B, 0x99, 0xA0, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8B, 0x08, 0x05,
    0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0xE8, 0x1A, 0xDA, 0x15, 0x00
};
const Region kRegions3663[] = {
    {0x2D6C150, kCurrentCode0_3663, "ToTarget constructor: RCX=finder, RDX=actor; vfE8 returns session"},
    {0x2D6C0F0, kCurrentCode1_3663, "ToTarget scalar deleting destructor; flag0 only resets base vtable"},
    {0x2D6C1A0, kCurrentCode2_3663, "ToTarget recipient append from finder+10"},
    {0x2D6C200, kCurrentCode3, "ToTarget session equality"},
    {0x2C7A9A0, kCurrentCode4, "2322/native2941 emitter original head"},
    {0x2C7A9A5, kCurrentCode5_3663, "Emitter frame, actor/finder ABI, TLS250, recipients2B0/count2B8, ScopeFind"},
    {0x2C7AA7C, kCurrentCode6, "Emitter serializes actor key+60 as exactly four bytes"},
    {0x2C7AA97, kCurrentCode7_3663, "Emitter native2941 opcode0xB7D"},
    {0x2B3FBE4, kCurrentCode8_3663, "Native stack ToTarget recipe before emitter call"},
    {0x2B3FC1C, kCurrentCode9_3663, "Native actor/finder argument setup, emitter call, stack destructor reset"},
    {0x2ED2F84, kCurrentCode10_3663, "2144/native2268 finder recipe and emitter call"},
    {0x2C7AED3, kCurrentCode11_3663, "2144 writer native2268 opcode0x8DC"},
    {0x2ED2FFF, kCurrentCode12, "2144 wrapper sets R8 field, RCX component and calls MoveFieldCompleteCore"},
    {0x2ED338E, kCurrentCode13_3663, "Core register provenance: R15=R8 field; R14=[RCX+8] actor"},
    {0x2ED3E3B, kCurrentCode14_3663, "3066/native2792 finder recipe and emitter call before milestone"},
    {0x2C7B367, kCurrentCode15_3663, "3066 writer native2792 opcode0xAE8"},
    {0x2ED426D, kCurrentCode16, "Actor+A0 user, user+60 identity compared with fieldR15+180; nonowner skips native2322"},
    {0x2ED42B5, kCurrentCode17, "Owner user+D0 main, main+68 components, components+A8 sequencer, component+18 manager"},
    {0x2ED42E6, kCurrentCode18_3663, "Owner-only native2322 call then owner/nonowner converge before hook"},
    {0x2ED4302, kCurrentCode19, "Milestone hook: original seven-byte instruction reads fieldR15+2D8"},
    {0x2C3BDFA, kCurrentCode20, "Scope lookup TLS250, mode2AC and count2A0"},
    {0x2C3C366, kCurrentCode21, "Current scope flush TLS250, current2A8 and array298"},
    {0x2A0E1B6, kCurrentCode22, "ServerRunThread realm TLS1EB=1"},
    {0xC1D4E0, kCurrentCode23, "ServerChildOnlyInGameActor vfE8 returns actor+D0 session"},
    {0x2D740C0, kCurrentCode24, "ServerUserActor vfE8 returns user+1F8 session"},
    {0xCD5631, kCurrentCode25_3663, "2322 client handler obtains field sequencer and writes readiness+261=2"},
    {0x882D78, kCurrentCode26_3663, "Loading state12 waits for owner sequencer+261>=2 then BDAF10 predicate before state13"},
    {0x2EC9D63, kCurrentCode27, "The same object supplies its ServerField"},
    {0x2ECA514, kCurrentCode28_3663, "MoveField obtains the actor component table"},
    {0x2ECA519, kCurrentCode29, "MoveField obtains TransformSync"},
    {0x2D6C23A, kCurrentTsFieldChain_3663, "actor+68 -> components+1A0 -> TS+508 GetField; its field at +10 gives TS+518"},
    {0x2DF447F, kCurrentFieldThis, "ServerField constructor preserves this in RDI"},
    {0x2DF47EF, kCurrentFieldKey, "ServerField constructor initializes its key at +2D0"},
};
constexpr NativeLayout kLayout3663{0x2D6C150, 0x2C7A9A0, 0x5F68760, 0x5F68740,
                                    0x518, 0x2D0, 0x1EB, 0x250};
constexpr uintptr_t kEntry3663 = 0x2ED4302;  // 0x2E6B675 + 0x68C8D, kEntryBytes3527 unchanged

// The synchronous installer's per-build profile (3527/3549 and 3576 share the logic and the layout).
struct CurrentPort {
    const char* build;
    std::span<const Region> regions;
    const NativeLayout* layout;
    uintptr_t entry;
    uintptr_t target_vf0, target_vf1, target_vf2, base_vf0;  // the finder vtables' slots
    uintptr_t actor_session_slot, actor_session_fn;          // ServerChildOnlyInGameActor vtable + 0xE8
    uintptr_t user_session_slot, user_session_fn;            // ServerUserActor vtable + 0xE8
};
const CurrentPort kPort3527{"3527", kRegions3527, &kLayout3527, kEntry3527,
                            0x2D04530, 0x2D045E0, 0x2D04640, 0x2D04490,
                            0x5EE4E90, 0xBE5A10, 0x5EECD90, 0x2D0C4F0};
// 3576 slots by RTTI: ServerChildOnlyInGameActor 0x5EE4DA8 -> 0x5EE74D0 (+0xE8 = 0xBE5E30), ServerUserActor 0x5EECCA8
// -> 0x5EEEEA8 (+0xE8 = 0x2D0D160); finder slots 0x2D051A0/0x2D05250/0x2D052B0, base slot 0 = 0x2D05100 (+0xC70).
const CurrentPort kPort3576{"3576", kRegions3576, &kLayout3576, kEntry3576,
                            0x2D051A0, 0x2D05250, 0x2D052B0, 0x2D05100,
                            0x5EE75B8, 0xBE5E30, 0x5EEEF90, 0x2D0D160};
// Build 1.0.0.3663 (static, 2026-11-13; never run), slots by RTTI: ToTarget 0x5F68760 (0x2D6C0F0/0x2D6C1A0/0x2D6C200),
// finder base 0x5F68740 (slot 0 = 0x2D6C050), ServerChildOnlyInGameActor 0x5F610C8 (+0xE8 = 0xC1D4E0), ServerUserActor
// 0x5F68B10 (+0xE8 = 0x2D740C0).
const CurrentPort kPort3663{"3663", kRegions3663, &kLayout3663, kEntry3663,
                            0x2D6C0F0, 0x2D6C1A0, 0x2D6C200, 0x2D6C050,
                            0x5F611B0, 0xC1D4E0, 0x5F68BF8, 0x2D740C0};

// The build that uses the synchronous installer, or null (2976 uses observer_stage's verifier).
const CurrentPort* current_port() noexcept {
    switch (game::current_build()) {
        case game::Build::v3527: return &kPort3527;
        case game::Build::v3576: return &kPort3576;
        case game::Build::v3663: return &kPort3663;
        default: return nullptr;
    }
}

const NativeLayout* g_layout = &kLayout2976;  // published before g_verified

using CtorFn = void*(__fastcall*)(void* finder, uintptr_t actor);
using EmitFn = void(__fastcall*)(uintptr_t actor, void* finder);

uintptr_t g_base = 0;
std::atomic<oms::Mode> g_mode{oms::Mode::Off};
std::atomic<bool> g_verified{false}, g_disabled{false};
std::atomic<bool> g_current_entry_ready{false};
std::mutex g_install_mu;
bool g_current_attempted = false;  // under g_install_mu; refusal cannot turn into Off-success
SafetyHookMid g_current_entry;
CtorFn g_ctor = nullptr;
EmitFn g_emit = nullptr;

std::mutex g_mu;
oms::Ledger g_ledger;  // under g_mu

p8p::EventRing<1024> g_ring;
std::atomic<uint64_t> g_ring_lost{0};
std::atomic<uint64_t> g_a_entries{0}, g_a_emits{0}, g_a_enqueued{0}, g_a_refused{0}, g_a_trips{0};

struct RingSink final : oms::NoteSink {
    void note(const p8p::Event& e) override {
        if (!g_ring.push(e)) g_ring_lost.fetch_add(1, std::memory_order_relaxed);
    }
};
RingSink g_sink;

// P8 S16 (observer_milestone_reload_logic.h): user 2's reload trips. Own lock (never held while the game runs, never
// taken under g_mu); g_r_waiting mirrors "armed, undecided" for the cheap test on every Req of user 2.
std::atomic<omr::Mode> g_r_mode{omr::Mode::Off};
std::atomic<omr::Mode> g_r_any{omr::Mode::Off};  // P8 S27: observer_milestone_reload_any
// P8 S27: the last Req of user 2 that started a load (2283 / 2362) and when (server thread; for the trip's line).
std::atomic<uint16_t> g_load_op{0};
std::atomic<uint64_t> g_load_op_us{0};
std::mutex g_rmu;
omr::Ledger g_rledger;  // under g_rmu
std::atomic<bool> g_r_waiting{false};
std::atomic<uint64_t> g_r_emits{0}, g_r_enqueued{0};
// This thread is inside the reload emission (take_frame's 2322 belongs to the reload ledger, not to the trips').
thread_local bool t_r_emitting = false;

// ---------------------------------------------------------------- reads (SEH only: game threads)

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

// The selected build's TS->field; 0 if unreadable.
uintptr_t field_of_actor(uintptr_t actor) noexcept {
    bool ok = true;
    const uintptr_t c = fp(actor + kActor_Comp, ok);
    const uintptr_t ts = ok ? fp(c + kComp_TS, ok) : 0;
    const uintptr_t f = ok ? fp(ts + g_layout->ts_field, ok) : 0;
    return ok ? f : 0;
}

void read_tls(oms::EntryFacts& f) noexcept {
    const uintptr_t array = static_cast<uintptr_t>(__readgsqword(0x58));
    bool ok = true;
    const uintptr_t block = fp(array, ok);
    if (!ok || !block) return;
    bool r = true;
    f.realm = fr<uint8_t>(block + g_layout->tls_realm, r) != 0 && r;
    bool c = true;
    f.send_ctx = fp(block + g_layout->tls_send_ctx, c);
    if (!c) f.send_ctx = 0;
    if (f.send_ctx) {
        bool s = true;
        f.scope_flag = fr<uint8_t>(f.send_ctx + kCtx_ScopeMode, s);
        f.scope_count = fr<uint32_t>(f.send_ctx + kCtx_ScopeCount, s);
        f.scope_current = fr<int32_t>(f.send_ctx + kCtx_ScopeCurrent, s);
        if (!s) {  // unreadable: treat as open (refused), never as closed
            f.scope_flag = 1;
            f.scope_count = 1;
        }
    }
}

oms::EntryFacts read_facts(uintptr_t field, uintptr_t actor) noexcept {
    oms::EntryFacts f;
    f.tid = GetCurrentThreadId();
    f.t_us = p8_now_us();
    f.field = field;
    f.actor = actor;
    bool ok = field && actor;
    f.actor_key = fr<uint32_t>(actor + kActor_Key, ok);
    f.user = fp(actor + kActor_User, ok);
    f.user_key = ok ? fr<uint32_t>(f.user + kUser_Key, ok) : 0;
    f.field_owner = fr<uint32_t>(field + kField_Owner, ok);
    f.field_key = fr<uint32_t>(field + g_layout->field_key, ok);
    f.reads_ok = ok;
    if (ok) {
        bool o = true;
        f.user_session = fp(f.user + kUser_Session, o);
        f.main_character = fp(f.user + kUser_Main, o);
        f.fm_field = field_of_actor(actor);
    }
    try {
        f.epoch = server_epoch();
        f.logout_asked = server_logout_requested();
        f.in_take_frame = server_in_take_frame();
        f.live_session = server_live_session2();
        f.user2_user_key = server_user2_user_key();
        f.user2_actor_key = server_user2_player_key();
        uintptr_t host = 0;
        if (server_host_user(host) && host) {
            bool h = true;
            f.host_user_key = fr<uint32_t>(host + kUser_Key, h);
            const uintptr_t pj = h ? fp(host + kUser_Main, h) : 0;
            f.host_field = h && pj ? field_of_actor(pj) : 0;
        }
    } catch (...) {
        f.reads_ok = false;
    }
    read_tls(f);
    return f;
}

// ---------------------------------------------------------------- the call (Send only)

// The selected ToTarget constructor: only our stack finder and the actor's
// lock-free vf 0xE8 getter [V] (observer_scene_copy.cpp): a fault there is a bad
// actor pointer, ours to handle (FaultCtor: emission off, logged).
int guarded_ctor(void* finder, uintptr_t actor) noexcept {
    __try {
        g_ctor(finder, actor);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
}

// The selected native milestone emitter queues the packet through the thread's
// send context: an exception inside it is the game's (P8 review I1). Emission
// off here, one line straight to the log, the exception passed on.
int emit_fault(EXCEPTION_POINTERS* ep) noexcept {
    g_disabled.store(true);
    return game::game_fault_continue(ep, "ObserverMilestone", "the verified native preload milestone emitter ran for user 2");
}

int guarded_emit(uintptr_t actor, void* finder) noexcept {
    __try {
        g_emit(actor, finder);
        return 0;
    } __except (emit_fault(GetExceptionInformation())) {
        return 1;  // never reached: the filter passes it on
    }
}

struct CallOutcome {
    oms::CallResult result = oms::CallResult::Returned;
    uintptr_t finder_session = 0;
    uint64_t dur_us = 0;
};

// As 0x287F194-0x287F1DA: a ToTarget on the stack built by the game's own constructor for
// the traveller, the emitter with (traveller, &finder), then the vtable back to the base
// (the object is trivially destroyed: nothing to free). Called once, no lock held.
CallOutcome call_native(uintptr_t actor, uintptr_t expected_session) noexcept {
    CallOutcome o;
    alignas(16) uintptr_t finder[4] = {0, 0, 0, 0};  // 0x18 used: vt, u8 tag (+8), session (+0x10)
    const uint64_t t0 = p8_now_us();
    if (guarded_ctor(finder, actor)) {
        o.result = oms::CallResult::FaultCtor;
        return o;
    }
    o.finder_session = finder[2];
    if (finder[0] != g_base + g_layout->target_vtable || (finder[1] & 0xFF) != 0) {
        o.result = oms::CallResult::BadFinder;
    } else if (!expected_session || finder[2] != expected_session) {
        o.result = oms::CallResult::WrongRecipient;
    } else if (guarded_emit(actor, finder)) {
        o.result = oms::CallResult::FaultEmit;
    }
    finder[0] = g_base + g_layout->base_vtable;  // native stack-finder cleanup: no allocation to free
    o.dur_us = p8_now_us() - t0;
    return o;
}

// ---------------------------------------------------------------- the lines (report thread)

std::map<uint32_t, uint32_t> g_gen_epoch;  // drain thread only
uint64_t g_lines = 0;                      // drain thread only
constexpr uint64_t kMaxLines = 4000;

std::string txn(uint32_t gen) {
    const auto it = g_gen_epoch.find(gen);
    return it == g_gen_epoch.end() ? std::format("T{}", gen) : std::format("E{}.T{}", it->second, gen);
}

std::string ms_since(uint64_t a, uint64_t b) {
    return a && b && b >= a ? std::format("{:.3f} ms", static_cast<double>(b - a) / 1000.0) : std::string("-");
}

std::string head(const char* what, const p8p::Event& e) {
    return std::format("ObserverMilestone [{}] {}{} |", what, p8_when(e.qpc_us),
                       e.tid ? std::format(" T{}", e.tid) : std::string());
}

std::string line_of(const p8p::Event& e) {
    const uint64_t* v = e.v;
    const auto gen = static_cast<uint32_t>(v[0]);
    switch (e.kind) {
        case oms::kNTripStart:
            g_gen_epoch[gen] = static_cast<uint32_t>(v[1]);
            if (g_gen_epoch.size() > 256) g_gen_epoch.erase(g_gen_epoch.begin());
            return std::format("{} trip {} begins: MoveFieldAck 2174 to session 2 {} | field owner written by the "
                               "server 0x{:08X} (user 2's copy is rewritten) | previous trip {}{}",
                               head("2174", e), txn(gen), v[3] ? "queued" : "LOST IN THE QUEUE (trip poisoned)",
                               static_cast<uint32_t>(v[2]), v[4] ? txn(static_cast<uint32_t>(v[4])) : std::string("-"),
                               v[2] ? "" : " | owner unknown (2174 layout)");
        case oms::kNTripEnd: {
            const auto out = static_cast<oms::Outcome>(v[2]);
            return std::format("{} trip {} ends: {}{} | 2174 -> 2144 {} | 2144 -> our 2322 {} | our 2322 -> 2445 {} | "
                               "2445 -> 2762 {} | native 2322 x{} | ours x{} | observer entries {}",
                               head("trip end", e), txn(gen), oms::outcome_name(out),
                               out == oms::Outcome::Refused || out == oms::Outcome::Cancelled
                                   ? std::format(" ({})", oms::why_name(static_cast<oms::Why>(v[3])))
                                   : std::string(),
                               ms_since(v[4], v[5]), ms_since(v[5], v[6]), ms_since(v[6], v[7]), ms_since(v[7], v[8]),
                               v[9], v[10], v[11]);
        }
        case oms::kN2144:
            return std::format("{} trip {}: MoveFieldCompleteAck 2144 #{} to session 2 {} (seq {})", head("2144", e),
                               txn(gen), v[3], v[1] ? "queued" : "LOST IN THE QUEUE (trip poisoned)", v[2]);
        case oms::kN3066:
            return std::format("{} trip {}: MoveFieldCompletePostAck 3066 to session 2 {} | {}", head("3066", e),
                               txn(gen), v[1] ? "queued" : "LOST IN THE QUEUE",
                               v[2] ? std::format("after the trip's 2144 (seq {}) on the same thread: this "
                                                  "MoveFieldCompleteCore's direct sends reach take_frame",
                                                  v[2])
                                    : std::string("NOT after a 2144 of this trip on this thread"));
        case oms::kNNative2322:
            return std::format("{} trip {}: a NATIVE 2322 to session 2 (actor 0x{:08X}) {}{}", head("native 2322", e),
                               txn(gen), static_cast<uint32_t>(v[2]), v[1] ? "queued" : "LOST IN THE QUEUE",
                               v[4] ? " | AFTER OURS: DUPLICATE MILESTONE" : " | ours will not be sent in this trip");
        case oms::kNOurs2322:
            return std::format("{} trip {}: OUR 2322 reached take_frame on this thread (actor 0x{:08X}, {}) -> {} | "
                               "{}",
                               head("our 2322", e), txn(gen), static_cast<uint32_t>(v[2]),
                               v[3] ? "the live session 2" : "NOT THE LIVE SESSION 2", v[1] ? "queued" : "LOST IN THE QUEUE",
                               gsd::corr_token(oms::kOpMilestone, static_cast<uint32_t>(v[2]), 0, 0));
        case oms::kNBundle:
            return std::format("{} trip {}: a ScopeSenderAck 2042 bundle went to session 2 ({}; #{}): a 2144/3066/2322 "
                               "inside it is not seen by this ledger",
                               head("2042", e), txn(gen), v[1] ? "queued" : "LOST", v[2]);
        case oms::kNIn:
            return std::format("{} trip {}: user 2's {} #{} handed to the server{}", head("in", e), txn(gen),
                               v[1] == oms::kOpLoadingCompleteReq ? "LoadingCompleteReq 2445" : "MoveFieldCompleteReq 2549",
                               v[2], v[3] ? std::format(" ({:.3f} s after our 2322)", static_cast<double>(v[3]) / 1e6) : "");
        case oms::kNOut2762:
            return std::format("{} trip {}: LoadingCompleteAck 2762 to session 2 {}{}{} | the load's normal exit seen "
                               "from the host",
                               head("2762", e), txn(gen), v[1] ? "queued" : "LOST IN THE QUEUE",
                               v[2] ? std::format(" | {:.3f} s after our 2322", static_cast<double>(v[2]) / 1e6) : "",
                               v[3] ? std::format(" | {:.3f} ms after its 2445", static_cast<double>(v[3]) / 1e3) : "");
        case oms::kNDecision: {
            const auto why = static_cast<oms::Why>(v[1]);
            const bool emit = v[2] != 0, dry = (v[11] >> 2) & 1;
            const auto actor = static_cast<uint32_t>(v[5]), user = static_cast<uint32_t>(v[5] >> 32);
            const auto owner = static_cast<uint32_t>(v[7]), fkey = static_cast<uint32_t>(v[7] >> 32);
            const auto scope_flag = static_cast<uint32_t>(v[10] & 0xFF);
            const auto scope_count = static_cast<uint32_t>((v[10] >> 8) & 0xFFFFFFFF);
            const auto scope_cur = static_cast<int32_t>(static_cast<uint32_t>(v[10] >> 40));
            std::string verdict = emit ? (dry ? "WOULD EMIT (dry run: observer_milestone_send=0, nothing called)"
                                              : "EMIT NOW: verified native ToTarget + milestone writer on this thread")
                                       : std::format("NO 2322 FROM US: {}", oms::why_name(why));
            return std::format(
                "{} trip {} | observer entry of user 0x{:08X} actor 0x{:08X} into field 0x{:X} (key 0x{:08X}) owned by "
                "0x{:08X} | {} | epoch {} | session: live 0x{:X}, the traveller's 0x{:X} | thread: server realm {}, "
                "send context {}, scope mode {} open {} current {} | mode {}",
                head("decision", e), gen ? txn(gen) : std::string("-"), user, actor, v[6], fkey, owner, verdict, v[4],
                v[8], v[9], (v[11] & 1) ? "yes" : "NO", (v[11] & 2) ? "yes" : "NO", scope_flag, scope_count, scope_cur,
                oms::mode_name(static_cast<oms::Mode>(v[3])));
        }
        case oms::kNCalled: {
            const auto r = static_cast<oms::CallResult>(v[1]);
            std::string what;
            if (r != oms::CallResult::Returned) {
                what = std::format("{} (ToTarget session 0x{:X})", oms::call_name(r), v[5]);
            } else if (!v[2]) {
                what = std::format("native milestone writer returned but NO 2322 reached take_frame on this thread (no recipient, "
                                   "or a scope bundle): not retried (ToTarget session 0x{:X})",
                                   v[5]);
            } else {
                what = std::format("native milestone writer returned; its 2322 {} in user 2's queue (x{}){} (ToTarget session 0x{:X})",
                                   v[3] ? "IS" : "is NOT (LOST)", v[4], v[7] ? " | ALSO SEEN FOR ANOTHER SESSION" : "",
                                   v[5]);
            }
            return std::format("{} trip {}: {} | call {:.3f} ms | next on the guest: P8Probe [2322 entry 0xB87890], "
                               "[2322 write 0xB87A67], GuestLoad [in 2322]",
                               head("called", e), txn(gen), what, static_cast<double>(v[6]) / 1e3);
        }
        case oms::kNEpoch:
            return std::format("{} guest epoch {} begins (or the server instance was replaced): trip {} {}; nothing "
                               "carries over",
                               head("epoch", e), v[0], v[1] ? txn(static_cast<uint32_t>(v[1])) : std::string("-"),
                               v[1] ? (v[2] ? "was already decided" : "CANCELLED before its entry") : "none");
        case oms::kNLogout:
            return std::format("{} user 2's logout asked: trip {} {}", head("logout", e), txn(gen),
                               v[1] ? "was already decided" : "CANCELLED (no 2322 will be sent for it)");
        case oms::kNFollowUp:
            return std::format("{} trip {}: +{} s after our 2322: 2445 {} | 2762 {} (report only: nothing is sent "
                               "again)",
                               head("follow-up", e), txn(gen), v[1], v[2] ? "handed" : "NOT YET",
                               v[3] ? "out" : "NOT YET");
        case oms::kNSkip: {
            const auto why = static_cast<oms::Why>(v[0]);
            if (why == oms::Why::Owner) {
                return std::format("{} user 0x{:08X} actor 0x{:08X} owns the field (0x{:08X}): the native "
                                   "0x287EF60 path sends its 2322 (watched as 'native 2322')",
                                   head("owner entry", e), static_cast<uint32_t>(v[1]), static_cast<uint32_t>(v[2]),
                                   static_cast<uint32_t>(v[3]));
            }
            return std::format("{} {}", head("skip", e), oms::why_name(why));
        }
        default:
            return std::format("ObserverMilestone: note {}?", e.kind);
    }
}

// P8 S16: the reload ledger's lines (observer_milestone_reload_logic.h).
std::string rkey(uint64_t k) { return k ? std::format("0x{:08X}", static_cast<uint32_t>(k)) : std::string("none"); }
std::string rms(uint64_t us) { return us ? std::format("{:.3f} s", static_cast<double>(us) / 1e6) : std::string("-"); }
const char* where_text(uint64_t w) {
    switch (static_cast<ftl::Where>(w)) {
        case ftl::Where::HostField: return "the host's field (shared)";
        case ftl::Where::OwnField: return "a field of its own";
        case ftl::Where::OtherField: return "another user's field";
        default: return "unknown";
    }
}

// P8 S27: observer_milestone_reload_any's mode, as the lines say it.
const char* any_name(uint64_t m) {
    switch (static_cast<omr::Mode>(m)) {
        case omr::Mode::On: return "1 (a trip at user 2's 2437 too)";
        case omr::Mode::Probe: return "probe (trips at its 2437 only say WOULD)";
        default: return "0 (trips only from an F3 2283)";
    }
}

std::string ts_text(uint64_t packed) {
    const tpl::TsSnap t = tpl::unpack(packed);
    if (!t.ok) return "not read";
    return std::format("+0x550 0x{:X} +0x568 {} +0x569 {} +0x591 {}", t.pending, t.f568, t.f569, t.armed);
}

std::string r_line_of(const p8p::Event& e) {
    const uint64_t* v = e.v;
    const std::string h = std::format("ObserverMilestone [reload] {}{} |", p8_when(e.qpc_us),
                                      e.tid ? std::format(" T{}", e.tid) : std::string());
    switch (e.kind) {
        case omr::kNTrip:
            return std::format("{} trip R{} begins: user 2's ReloadStageStartReq 2283 was accepted by F3 (its own "
                               "manager / the block at 0x2A5F7FC) | epoch {} | previous trip {}",
                               h, v[0], v[1], v[2] ? std::format("R{}", v[2]) : std::string("-"));
        case omr::kNTrip2437:
            return std::format("{} trip R{} begins at user 2's GameLoadingStartReq 2437 with no trip open (no F3 2283): "
                               "the load began with {}{} | TS_user2 before the 2437 [{}] | epoch {} | previous trip {} | "
                               "observer_milestone_reload={} observer_milestone_reload_any={}{}",
                               h, v[0], omr::load_req_name(static_cast<uint16_t>(v[3])),
                               v[4] ? std::format(" ({} before)", rms(v[4])) : std::string(), ts_text(v[5]), v[1],
                               v[2] ? std::format("R{}", v[2]) : std::string("-"),
                               omr::mode_name(static_cast<omr::Mode>(v[7])), any_name(v[8]),
                               v[6] ? " | probe trip: its 2873 goes to the server, only WOULD DROP / WOULD EMIT" : "");
        case omr::kNNested:
            return std::format("{} trip R{}: user 2's 2437 entered again while the trip is live ({}); the trip is kept "
                               "(the load began with {})",
                               h, v[0], omr::phase_name(static_cast<omr::Phase>(v[1])),
                               omr::load_req_name(static_cast<uint16_t>(v[2])));
        case omr::kNNativeInReload:
            return std::format("{} trip {}: user 2's PreLoadSequencerReq 2873 (#{} of the run) WENT TO THE SERVER during "
                               "a reload in {} ({} after its 2437: 2643/3066, no 2174, no 2762 yet) with no 2322 of ours "
                               "({}): the server's 2322 goes to the field owner's character and the guest's load will "
                               "wait in state 0x11 (docs/research/s25/reaparicion.md) | observer_milestone_reload={} "
                               "observer_milestone_reload_any={}",
                               h, v[0] ? std::format("R{}", v[0]) : std::string("-"), v[2], where_text(v[4]), rms(v[3]),
                               omr::gate_name(static_cast<omr::Gate>(v[1])),
                               omr::mode_name(static_cast<omr::Mode>(v[5])), any_name(v[6]));
        case omr::kNPhase:
            return std::format("{} trip R{}: {} after {} {}{}", h, v[0], omr::phase_name(static_cast<omr::Phase>(v[1])),
                               v[2], v[2] == omr::kOpGameLoadingStartReq ? "entered the server" : "to user 2",
                               v[3] ? std::format(" (+{} after its 2437)", rms(v[3])) : std::string());
        case omr::kNOffer:
            return std::format("{} trip {}: user 2's PreLoadSequencerReq 2873 #{} ({}; user 2 in {}) -> {} | {} | "
                               "observer_milestone_reload={}",
                               h, v[0] ? std::format("R{}", v[0]) : std::string("-"), v[3],
                               omr::phase_name(static_cast<omr::Phase>(v[5])), where_text(v[4]),
                               omr::gate_name(static_cast<omr::Gate>(v[1])),
                               v[2] ? "handed to the server" : "NOT handed to the server",
                               omr::mode_name(static_cast<omr::Mode>(v[6])));
        case omr::kNDecision: {
            const auto why = static_cast<omr::Why>(v[1]);
            const bool emit = v[2] != 0, dry = v[3] != 0;
            std::string verdict = emit ? (dry ? std::string("WOULD EMIT the 2322 for user 2's character (probe: nothing "
                                                            "called; its 2873 went to the server)")
                                              : std::string("EMIT NOW: 0x2A757A0 + 0x2999D80 for user 2's character on "
                                                            "this thread"))
                                       : std::format("NO 2322 FROM US: {}", omr::why_name(why));
            return std::format("{} trip R{}: {} | +{} after the 2873, attempt {} | actor {} user {} | field owner {} "
                               "(host {}) | session: live 0x{:X}, its user's 0x{:X} | thread: server realm {}, send "
                               "context {}",
                               h, v[0], verdict, rms(v[5]), v[4] + 1, rkey(v[6]), rkey(v[6] >> 32), rkey(v[7]),
                               rkey(v[7] >> 32), v[8], v[9], (v[11] & 1) ? "yes" : "NO", (v[11] & 2) ? "yes" : "NO");
        }
        case omr::kNTransient:
            return std::format("{} trip R{}: not now ({}), attempt {}: retried at user 2's next Req", h, v[0],
                               omr::why_name(static_cast<omr::Why>(v[1])), v[2]);
        case omr::kNCalled: {
            const auto r = static_cast<oms::CallResult>(v[1]);
            std::string what;
            if (r != oms::CallResult::Returned) {
                what = std::format("{} (ToTarget session 0x{:X})", oms::call_name(r), v[5]);
            } else if (!v[2]) {
                what = std::format("0x2999D80 returned but NO 2322 reached take_frame on this thread: not retried "
                                   "(ToTarget session 0x{:X})",
                                   v[5]);
            } else {
                what = std::format("2322 EMITTED to user 2 after its PreLoadSequencerReq 2873: {} in user 2's queue "
                                   "(x{}){} (ToTarget session 0x{:X})",
                                   v[3] ? "IS" : "is NOT (LOST)", v[4], v[7] ? " | ALSO SEEN FOR ANOTHER SESSION" : "",
                                   v[5]);
            }
            return std::format("{} trip R{}: {} | call {:.3f} ms | next on the guest: GuestStage M+0x231 1 -> 2, "
                               "state 0x11 -> 0x12",
                               h, v[0], what, static_cast<double>(v[6]) / 1e3);
        }
        case omr::kNNative:
            return std::format("{} trip R{}: a NATIVE 2322 for user 2's character {} reached its queue ({}) | ours "
                               "will not be sent in this trip",
                               h, v[0], rkey(v[1]), v[2] ? "queued" : "LOST IN THE QUEUE");
        case omr::kNOurs:
            return std::format("{} trip R{}: OUR 2322 reached take_frame on this thread (actor {}, {}) -> {}", h, v[0],
                               rkey(v[2]), v[3] ? "the live session 2" : "NOT THE LIVE SESSION 2",
                               v[1] ? "queued" : "LOST IN THE QUEUE");
        case omr::kNLoaded:
            return std::format("{} trip R{}: LoadingCompleteAck 2762 to user 2 ({}){} | the reload's normal exit", h,
                               v[0], v[2] ? "queued" : "LOST",
                               v[1] ? std::format(", {} after our 2322", rms(v[1])) : std::string());
        case omr::kNTripEnd:
            return std::format("{} trip R{} ends: {}{} | 2873 seen {} dropped {} | 2437 -> 2873 {} | 2873 -> our 2322 {} "
                               "| our 2322 -> 2762 {} | native 2322 for user 2 x{} | last phase: {} | origin {}{}{}",
                               h, v[0], omr::outcome_name(static_cast<omr::Outcome>(v[1])),
                               static_cast<omr::Outcome>(v[1]) == omr::Outcome::Refused
                                   ? std::format(" ({})", omr::why_name(static_cast<omr::Why>(v[2])))
                                   : std::string(),
                               v[3], v[4], rms(v[5]), rms(v[6]), rms(v[7]), v[8],
                               omr::phase_name(static_cast<omr::Phase>(v[9])),
                               omr::origin_name(static_cast<omr::Origin>(v[10] & 0xFF)), (v[10] >> 8) & 1 ? " (probe)" : "",
                               static_cast<omr::Origin>(v[10] & 0xFF) == omr::Origin::At2437
                                   ? std::format(", the load began with {}",
                                                 omr::load_req_name(static_cast<uint16_t>(v[10] >> 16)))
                                   : std::string());
        case omr::kNCancel:
            return std::format("{} trip R{}: {} ({})", h, v[0],
                               v[1] ? std::format("guest epoch {} begins", v[1]) : std::string("user 2's logout asked"),
                               v[2] ? "it was already decided" : "nothing is sent for it");
        default:
            return std::format("ObserverMilestone [reload]: note {}?", e.kind);
    }
}

bool code_at(uintptr_t rva, std::span<const uint8_t> b) {
    std::vector<uint8_t> actual(b.size());
    // P8 B step 2: owner_fanout's hook on ToTarget::vf1 is not a change of the game's code (its original bytes).
    return owner_fanout_read_unpatched(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), b.begin());
}

// The current port owns only the entry hook. It accepts no third-party jump
// at the native emitter or finder: every checked region must be original.
bool current_code_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

void current_on_entry(SafetyHookContext& ctx) {
    // 3527's prologue sets R15=field and R14=[FieldMover+0]+8 traveller.
    // R13 no longer holds the field. This common continuation follows the
    // owner/nonowner branch and the traveller's native 2144/3066 sends.
    observer_milestone_on_entry(ctx.r15, ctx.r14);
}

DWORD WINAPI current_report_thread(LPVOID) {
    for (uint64_t tick = 1;; ++tick) {
        Sleep(1000);
        try {
            observer_milestone_drain();
            if (tick % 60 == 0) log::info("{}", observer_milestone_counters());
        } catch (...) {
            log::error("ObserverMilestone: report drain failed; emission is never retried by this thread");
        }
    }
}

}  // namespace

oms::Mode observer_milestone_configure(bool diag, bool send) {
    const oms::Mode m = oms::choose_mode(diag, send);
    g_mode.store(m);
    {
        std::lock_guard lock(g_mu);
        g_ledger.set_mode(m);
    }
    return m;
}

oms::Mode observer_milestone_mode() { return g_mode.load(); }

bool observer_milestone_active() {
    return g_mode.load() != oms::Mode::Off && g_verified.load() && !g_disabled.load() &&
           (!current_port() || g_current_entry_ready.load());
}

bool observer_milestone_install_current() {
    std::lock_guard lock(g_install_mu);
    // Preserve a refusal even if a later caller changes the configured mode.
    if (g_current_attempted) return g_current_entry_ready.load() && !g_disabled.load();
    if (g_mode.load() == oms::Mode::Off) return true;
    g_current_attempted = true;
    const auto refuse = [](const char* why) {
        g_disabled.store(true);
        g_verified.store(false);
        log::error("ObserverMilestone: build {} install REFUSED: {}; guest admission must stay closed",
                   current_port() ? current_port()->build : "?", why);
        return false;
    };
    const CurrentPort* port = current_port();
    if (!port || !game::validate_native_catalog()) {
        return refuse("unsupported executable or native message catalog");
    }
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    std::vector<gad::Section> sections;
    if (!p8_exe_sections(g_base, sections)) return refuse("unreadable executable sections");
    for (const Region& r : port->regions) {
        if (!gad::in_real_code(sections, static_cast<uint32_t>(r.rva), static_cast<uint32_t>(r.bytes.size())) ||
            !current_code_at(r.rva, r.bytes)) {
            log::error("ObserverMilestone: current {} differs at exe+0x{:X} ({} bytes)", r.what, r.rva, r.bytes.size());
            return refuse("native code or layout witness differs");
        }
    }
    const auto target0 = game::read<uintptr_t>(g_base + port->layout->target_vtable);
    const auto target1 = game::read<uintptr_t>(g_base + port->layout->target_vtable + 8);
    const auto target2 = game::read<uintptr_t>(g_base + port->layout->target_vtable + 16);
    const auto base0 = game::read<uintptr_t>(g_base + port->layout->base_vtable);
    const auto actor_session = game::read<uintptr_t>(g_base + port->actor_session_slot);
    const auto user_session = game::read<uintptr_t>(g_base + port->user_session_slot);
    if (!target0 || *target0 != g_base + port->target_vf0 || !target1 || *target1 != g_base + port->target_vf1 ||
        !target2 || *target2 != g_base + port->target_vf2 || !base0 || *base0 != g_base + port->base_vf0 ||
        !actor_session || *actor_session != g_base + port->actor_session_fn ||
        !user_session || *user_session != g_base + port->user_session_fn) {
        return refuse("native finder or actor/user session vtable differs");
    }
    g_layout = port->layout;
    g_ctor = reinterpret_cast<CtorFn>(g_base + g_layout->ctor);
    g_emit = reinterpret_cast<EmitFn>(g_base + g_layout->emit);
    g_verified.store(true);
    // The callback remains disarmed until all installation work has succeeded.
    if (!p8_install_mid(g_base, sections, port->entry, 7, kEntryBytes3527, current_on_entry,
                        g_current_entry, "ObserverMilestone", "the current field-entry completion")) {
        return refuse("field-entry hook could not be installed");
    }
    const HANDLE report = CreateThread(nullptr, 0, current_report_thread, nullptr, 0, nullptr);
    if (!report) {
        // Keep the trampoline alive if a game thread is already inside it.
        (void)g_current_entry.disable();
        return refuse("report thread could not be started");
    }
    CloseHandle(report);
    g_current_entry_ready.store(true, std::memory_order_release);
    log::info("ObserverMilestone ON (build {}, {}): {} exact code regions and finder vtables verified; entry "
              "exe+0x{:X} field=R15 actor=R14; native 2384 (logical 2322) writer exe+0x{:X}, "
              "ToTarget exe+0x{:X}; once per observer trip after same-thread queued 2144/3066; "
              "no worker emission or reload path",
              port->build, oms::mode_name(g_mode.load()), port->regions.size(), port->entry, port->layout->emit,
              port->layout->ctor);
    return true;
}

bool observer_milestone_verify(uintptr_t base, std::span<const gad::Section> secs) {
    if (g_mode.load() == oms::Mode::Off) return false;
    if (game::current_build() != game::Build::v2976) {
        log::error("ObserverMilestone: legacy verifier refused on this build; build 3527 requires its synchronous installer");
        return false;
    }
    g_base = base;
    g_layout = &kLayout2976;
    std::string bad;
    for (const Region& r : kRegions) {
        if (!gad::in_real_code(secs, static_cast<uint32_t>(r.rva), static_cast<uint32_t>(r.bytes.size())) ||
            !code_at(r.rva, r.bytes)) {
            bad += std::format(" {} (exe+0x{:X}, {} bytes)", r.what, r.rva, r.bytes.size());
        }
    }
    // The emitter's first bytes: the original prologue, or observer_stage's jmp already there.
    uint8_t head5[5] = {};
    if (!game::safe_read(base + kEmitRva, head5, sizeof head5) ||
        (!std::equal(std::begin(head5), std::end(head5), std::begin(kEmitHead)) && head5[0] != 0xE9)) {
        bad += " 2322 emitter entry (exe+0x2999D80)";
    }
    // The vtables (data): ToTarget slots 0-2 and the base's slot 0.
    const auto s0 = game::read<uintptr_t>(base + kVtToTarget), s1 = game::read<uintptr_t>(base + kVtToTarget + 8),
               s2 = game::read<uintptr_t>(base + kVtToTarget + 16), b0 = game::read<uintptr_t>(base + kVtFinderBase);
    if (!s0 || *s0 != base + kVf0Rva || !s1 || *s1 != base + kVf1Rva || !s2 || *s2 != base + kVf2Rva || !b0 ||
        *b0 != base + kBaseVf0Rva) {
        bad += " ToTarget/ISendTargetFinder vtables (exe+0x5B25438 / exe+0x5B253F8)";
    }
    if (!bad.empty()) {
        g_mode.store(oms::Mode::Off);
        log::error("ObserverMilestone: REFUSED, not build 2976's code at:{}; observer_milestone stays OFF (nothing "
                   "decided, nothing sent)",
                   bad);
        return false;
    }
    g_ctor = reinterpret_cast<CtorFn>(base + kCtorRva);
    g_emit = reinterpret_cast<EmitFn>(base + kEmitRva);
    g_verified.store(true);
    log::info("ObserverMilestone ON ({}): user 2's trips (2174 -> 2144 -> 3066 -> entry 0x2BC84E2) followed in "
              "take_frame/inject; at its first OBSERVER entry of a trip the 2322 is {} | binds the decision to the "
              "real g_outgoing.push of this trip's 2144 and of the 3066 that followed it on the same thread | once per "
              "trip, no retry, no timer | {} code regions + emitter entry + vtables checked against build 2976 | "
              "observer_stage_sync never sends (=2 is refused)",
              oms::mode_name(g_mode.load()),
              g_mode.load() == oms::Mode::Send
                  ? "EMITTED there: ToTarget 0x2A757A0(finder, traveller) (session = traveller->vfE8(), must be the "
                    "live session 2) + 0x2999D80(traveller, finder)"
                  : "only DECIDED and logged ('WOULD EMIT'); observer_milestone_send=1 emits",
              std::size(kRegions));
    return true;
}

void observer_milestone_disable(const char* why) {
    if (g_mode.load() == oms::Mode::Off || g_disabled.exchange(true)) return;
    log::error("ObserverMilestone: OFF: {}", why);
}

void observer_milestone_on_entry(uintptr_t field, uintptr_t actor) noexcept {
    if (!observer_milestone_active()) return;
    g_a_entries.fetch_add(1, std::memory_order_relaxed);
    const oms::EntryFacts f = read_facts(field, actor);
    oms::Decision d;
    {
        std::lock_guard lock(g_mu);
        d = g_ledger.decide(f, g_sink);
    }
    if (d.tracked && !d.emit) g_a_refused.fetch_add(1, std::memory_order_relaxed);
    if (!d.emit || g_mode.load() != oms::Mode::Send) return;
    // The emission: this thread, this MoveFieldCompleteCore, no lock of ours held.
    const CallOutcome o = call_native(actor, f.live_session);
    g_a_emits.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lock(g_mu);
    g_ledger.on_called(d.gen, o.result, o.finder_session, p8_now_us(), o.dur_us, f.tid, g_sink);
    if (g_ledger.trip().gen == d.gen && g_ledger.trip().ours_pushed) g_a_enqueued.fetch_add(1);
}

void observer_milestone_on_out(uint16_t opcode, uintptr_t self, bool pushed, uint32_t value) noexcept {
    if (g_mode.load(std::memory_order_relaxed) == oms::Mode::Off || !oms::followed_out(opcode)) return;
    if (t_r_emitting) return;  // P8 S16: the reload's own 2322 (observer_milestone_reload_on_out accounts for it)
    try {
        const bool live = self && self == server_live_session2();
        const uint32_t tid = GetCurrentThreadId();
        std::lock_guard lock(g_mu);
        g_ledger.on_out(opcode, live, pushed, tid, p8_now_us(), value, g_sink);
        g_a_trips.store(g_ledger.counters().trips, std::memory_order_relaxed);
    } catch (...) {
    }
}

void observer_milestone_on_in(uint16_t opcode) noexcept {
    if (g_mode.load(std::memory_order_relaxed) == oms::Mode::Off || !oms::followed_in(opcode)) return;
    try {
        std::lock_guard lock(g_mu);
        g_ledger.on_in(opcode, p8_now_us(), g_sink);
    } catch (...) {
    }
}

void observer_milestone_on_epoch(uint32_t epoch, const char* why) noexcept {
    if (g_mode.load() == oms::Mode::Off) return;
    try {
        std::lock_guard lock(g_mu);
        g_ledger.on_epoch(epoch, p8_now_us(), g_sink);
    } catch (...) {
    }
    if (g_r_mode.load() != omr::Mode::Off) {
        try {
            std::lock_guard lock(g_rmu);
            g_rledger.on_epoch(epoch, p8_now_us(), g_sink);
            g_r_waiting.store(g_rledger.waiting());
        } catch (...) {
        }
    }
    g_load_op.store(0);
    g_load_op_us.store(0);
    (void)why;
}

void observer_milestone_on_logout() noexcept {
    if (g_mode.load() == oms::Mode::Off) return;
    try {
        std::lock_guard lock(g_mu);
        g_ledger.on_logout(p8_now_us(), g_sink);
    } catch (...) {
    }
    if (g_r_mode.load() != omr::Mode::Off) {
        try {
            std::lock_guard lock(g_rmu);
            g_rledger.on_logout(p8_now_us(), g_sink);
            g_r_waiting.store(g_rledger.waiting());
        } catch (...) {
        }
    }
    g_load_op.store(0);
    g_load_op_us.store(0);
}

void observer_milestone_drain() {
    if (g_mode.load() == oms::Mode::Off) return;
    {
        std::lock_guard lock(g_mu);
        g_ledger.follow_ups(p8_now_us(), g_sink);
    }
    p8p::Event e;
    while (g_ring.pop(e)) {
        std::string s;
        if (e.kind >= omr::kNoteBase && e.kind < omr::kNoteEnd) {
            s = r_line_of(e);
        } else if (e.kind < oms::kNoteCount) {
            s = line_of(e);
        } else {
            continue;
        }
        // P8 S27: a 2873 handed to the server during an unfinished reload is a warning (bounded by the ledger).
        if (e.kind == omr::kNNativeInReload) {
            log::warn("{}", s);
            continue;
        }
        if (g_lines++ < kMaxLines) log::info("{}", s);
    }
    static uint64_t lost_logged = 0;
    if (const uint64_t lost = g_ring_lost.load(); lost != lost_logged) {
        log::warn("ObserverMilestone: {} line(s) lost (ring full)", lost - lost_logged);
        lost_logged = lost;
    }
}

// P8 S16: the reload ledger's part of the 60 s line ("" when off).
static std::string reload_counters() {
    if (g_r_mode.load() == omr::Mode::Off) return {};
    omr::Counters c;
    {
        std::lock_guard lock(g_rmu);
        c = g_rledger.counters();
    }
    std::string refused;
    for (size_t i = 1; i < c.refused.size(); ++i) {
        if (c.refused[i]) refused += std::format(" {} x{};", omr::why_name(static_cast<omr::Why>(i)), c.refused[i]);
    }
    return std::format(" || reload ({}; any {}): trips {} (reload {}, field change {}, 2679 {}; at the 2437 {}: reload {}, "
                       "2437 inside a live trip {}, stale live trips closed {}) | 2873 of user 2 {}: DROPPED {}, would "
                       "drop {}, to the server {} (no "
                       "trip {}, not a reload {}, over {}, own field {}, not shared {}, emitter off {}; DURING AN UNFINISHED "
                       "RELOAD {}) | decisions {}: emit {} / would emit {} | calls {}: enqueued {}, LOST {}, not seen {}, "
                       "failed {} | native 2322 for user 2 {} | retried {} | cancelled {} | refusals:{}",
                       omr::mode_name(g_r_mode.load()), any_name(static_cast<uint64_t>(g_r_any.load())), c.trips,
                       c.reloads, c.field_changes, c.refused_2679, c.trips_at_2437, c.reloads_at_2437, c.nested_2437,
                       c.stale_closed,
                       c.seen_2873, c.dropped, c.would_drop, c.passed,
                       c.gates[static_cast<size_t>(omr::Gate::NoTrip)], c.gates[static_cast<size_t>(omr::Gate::NotReload)],
                       c.gates[static_cast<size_t>(omr::Gate::Over)], c.gates[static_cast<size_t>(omr::Gate::OwnField)],
                       c.gates[static_cast<size_t>(omr::Gate::NotShared)],
                       c.gates[static_cast<size_t>(omr::Gate::EmitterOff)], c.native_in_reload, c.decisions, c.emits,
                       c.dry_emits, c.calls, c.enqueued, c.lost, c.not_seen, c.failed, c.native, c.transient,
                       c.cancelled, refused.empty() ? std::string(" none") : refused);
}

std::string observer_milestone_counters() {
    if (g_mode.load() == oms::Mode::Off) return {};
    oms::Counters c;
    bool faulted = false;
    {
        std::lock_guard lock(g_mu);
        c = g_ledger.counters();
        faulted = g_ledger.faulted();
    }
    std::string refused;
    for (size_t i = 1; i < c.refused.size(); ++i) {
        if (c.refused[i]) refused += std::format(" {} x{};", oms::why_name(static_cast<oms::Why>(i)), c.refused[i]);
    }
    return std::format("ObserverMilestone ({}{}{}) | entries {} (observer {}, owner {}, host {}, unreadable {}) | trips "
                       "{} | decisions {}: emit {} / would emit {} | calls {}: enqueued {}, LOST {}, not seen {}, failed "
                       "{} | native 2322 {} (after ours {}) | duplicates avoided {} | cancelled {} | 2042 bundles {} | "
                       "refusals:{}",
                       oms::mode_name(g_mode.load()), g_verified.load() ? "" : ", NOT VERIFIED",
                       faulted ? ", FAULTED: off" : "", c.entries, c.observer_entries, c.owner_entries,
                       c.host_entries, c.unreadable, c.trips, c.decisions, c.emits, c.dry_emits, c.calls, c.enqueued,
                       c.queue_lost, c.not_seen, c.call_failed, c.native_2322, c.native_after_ours,
                       c.duplicates_avoided, c.cancelled, c.bundles, refused.empty() ? std::string(" none") : refused) +
           reload_counters();
}

// ---------------------------------------------------------------- P8 S16: observer_milestone_reload

omr::Mode observer_milestone_reload_configure(const std::string& value) {
    const omr::ParsedMode m = omr::parse_mode(value);
    if (!m.known) {
        log::warn("ObserverMilestone reload: observer_milestone_reload='{}' is not 0, probe or 1; it stays 0", value);
    }
    omr::Mode mode = m.mode;
    if (mode != omr::Mode::Off && current_port()) {
        log::warn("ObserverMilestone reload: builds 3527/3576/3663 support field-entry milestones only; reload={} is refused",
                  value);
        mode = omr::Mode::Off;
    }
    if (mode != omr::Mode::Off && g_mode.load() == oms::Mode::Off) {
        log::warn("ObserverMilestone reload: observer_milestone_reload={} needs observer_milestone=1 (its verified "
                  "emitter and its thread; _send=1 for mode 1): OFF",
                  value);
        mode = omr::Mode::Off;
    }
    g_r_mode.store(mode);
    {
        std::lock_guard lock(g_rmu);
        g_rledger.set_mode(mode);
    }
    if (mode == omr::Mode::Off) return mode;
    log::info("ObserverMilestone reload: observer_milestone_reload={}: user 2's reload trips (its 2283 accepted by F3 "
              "-> 2437 -> 2643/3066, no 2174) in the host's field: {} | needs user2_fast_travel=1 (F3 and ExecuteTroc's "
              "subject){}",
              omr::mode_name(mode),
              mode == omr::Mode::On
                  ? "its PreLoadSequencerReq 2873 is DROPPED (the host's sequencers are not re-prepared) and ONE "
                    "PlayAllPreLoadSequencerAck 2322 for its character is emitted at the exit of its next ExecuteTroc "
                    "(>= 300 ms later) with 0x2A757A0 + 0x2999D80"
                  : "its 2873 goes to the server as before; what mode 1 would do is decided and logged ('WOULD')",
              mode == omr::Mode::On && g_mode.load() != oms::Mode::Send
                  ? " | WARNING: observer_milestone_send=0: nothing is dropped or emitted (gate 'emitter off')"
                  : "");
    return mode;
}

omr::Mode observer_milestone_reload_mode() { return g_r_mode.load(); }

omr::Mode observer_milestone_reload_any_configure(const std::string& value) {
    const omr::ParsedMode m = omr::parse_mode(value);
    if (!m.known) {
        log::warn("ObserverMilestone reload: observer_milestone_reload_any='{}' is not 0, probe or 1; it stays 0", value);
    }
    omr::Mode mode = m.mode;
    if (mode != omr::Mode::Off && current_port()) {
        log::warn("ObserverMilestone reload: builds 3527/3576/3663 support field-entry milestones only; reload_any={} is "
                  "refused",
                  value);
        mode = omr::Mode::Off;
    }
    if (mode != omr::Mode::Off && g_r_mode.load() == omr::Mode::Off) {
        log::warn("ObserverMilestone reload: observer_milestone_reload_any={} needs observer_milestone_reload=probe or 1 "
                  "(its ledger, its 2873 gate and its emission): OFF",
                  value);
        mode = omr::Mode::Off;
    } else if (mode != omr::Mode::Off && g_mode.load() != oms::Mode::Send) {
        log::warn("ObserverMilestone reload: observer_milestone_reload_any={} needs observer_milestone_send=1 "
                  "(observer_milestone's verified emitter): OFF",
                  value);
        mode = omr::Mode::Off;
    }
    g_r_any.store(mode);
    {
        std::lock_guard lock(g_rmu);
        g_rledger.set_any(mode);
    }
    if (mode == omr::Mode::Off) return mode;
    const bool acts = mode == omr::Mode::On && g_r_mode.load() == omr::Mode::On;
    log::info("ObserverMilestone reload: observer_milestone_reload_any={}: user 2's GameLoadingStartReq 2437 with no "
              "reload trip open OPENS one (origin 'at its 2437': a revive ReviveLoadingReq 2362, or any other path "
              "without an F3 2283); classified as an F3 trip (2643/3066 with no 2174 = reload, 2174 = field change and "
              "never ours, 2762 = over) | {} | needs ExecuteTroc's subject (user2_funnels) | a 2873 handed to the "
              "server during an unfinished reload is a WRN whatever this key says",
              any_name(static_cast<uint64_t>(mode)),
              acts ? "its 2873 is DROPPED and ONE 2322 for user 2's character is emitted at its next Req (>= 300 ms), "
                     "as in an F3 trip"
                   : "these trips only say WOULD DROP / WOULD EMIT: their 2873 still goes to the server (the guest "
                     "stays in load state 0x11 as before)");
    return mode;
}

omr::Mode observer_milestone_reload_any_mode() { return g_r_any.load(); }

ReloadVerdict observer_milestone_reload_judge(uint16_t opcode) noexcept {
    ReloadVerdict v;
    if (opcode != omr::kOpPreLoadSequencerReq) return v;
    const omr::Mode mode = g_r_mode.load(std::memory_order_relaxed);
    if (mode == omr::Mode::Off) return v;
    try {
        omr::OfferFacts f;
        f.mode = mode;
        f.emitter_ready = observer_milestone_active() && g_mode.load() == oms::Mode::Send && g_ctor && g_emit;
        f.where = fast_travel_user2_where();
        f.t_us = p8_now_us();
        std::lock_guard lock(g_rmu);
        v.gate = g_rledger.judge(f);
        v.relevant = v.gate != omr::Gate::NotRelevant;
        v.drop = omr::drops(v.gate);
        v.where = f.where;
    } catch (...) {
        v = ReloadVerdict{};  // nothing known: the 2873 goes on, as natively
    }
    return v;
}

void observer_milestone_reload_record(const ReloadVerdict& v, bool handed) noexcept {
    if (!v.relevant) return;
    try {
        std::lock_guard lock(g_rmu);
        g_rledger.record_offer(v.gate, handed, v.where, p8_now_us(), g_sink);
        g_r_waiting.store(g_rledger.waiting());
    } catch (...) {
    }
}

void observer_milestone_reload_on_f3() noexcept {
    if (g_r_mode.load(std::memory_order_relaxed) == omr::Mode::Off) return;
    try {
        std::lock_guard lock(g_rmu);
        g_rledger.on_f3_accepted(p8_now_us(), g_sink);
        g_r_waiting.store(g_rledger.waiting());
    } catch (...) {
    }
}

void observer_milestone_reload_note_load_req(uint16_t opcode) noexcept {
    if (opcode != omr::kOpReloadStageStartReq && opcode != omr::kOpReviveLoadingReq) return;
    g_load_op_us.store(p8_now_us(), std::memory_order_relaxed);
    g_load_op.store(opcode, std::memory_order_relaxed);
}

void observer_milestone_reload_before(uint16_t opcode, uint64_t ts_packed) noexcept {
    if (opcode != omr::kOpGameLoadingStartReq || g_r_mode.load(std::memory_order_relaxed) == omr::Mode::Off) return;
    // The Req that started this load, taken by this 2437 (for the line only).
    const uint16_t load_op = g_load_op.exchange(0, std::memory_order_relaxed);
    const uint64_t at = g_load_op_us.exchange(0, std::memory_order_relaxed);
    const uint64_t now = p8_now_us();
    const uint64_t load_age_us = load_op && at && now >= at ? now - at : 0;
    try {
        std::lock_guard lock(g_rmu);
        // P8 S27: the F3 trip's 2437 as before; with observer_milestone_reload_any a trip opens here when none is.
        g_rledger.on_2437_any(now, load_op, load_age_us, ts_packed, g_sink);
        g_r_waiting.store(g_rledger.waiting());
    } catch (...) {
    }
}

void observer_milestone_reload_at_exit(uintptr_t actor) noexcept {
    if (!g_r_waiting.load(std::memory_order_relaxed) || !actor) return;
    if (g_r_mode.load(std::memory_order_relaxed) == omr::Mode::Off) return;
    // The same reads as an observer entry, with the field = the actor's field-mover field (SEH reads only).
    const oms::EntryFacts f = read_facts(field_of_actor(actor), actor);
    omr::ExitDecision d;
    try {
        std::lock_guard lock(g_rmu);
        d = g_rledger.at_exit(f, g_disabled.load(), g_sink);
        g_r_waiting.store(g_rledger.waiting());
    } catch (...) {
        return;
    }
    if (!d.act || !d.emit || d.dry || !g_ctor || !g_emit) return;
    // The emission: this thread, at the exit of user 2's Req, no lock of ours held (take_frame takes them).
    t_r_emitting = true;
    const CallOutcome o = call_native(actor, f.live_session);
    t_r_emitting = false;
    g_r_emits.fetch_add(1, std::memory_order_relaxed);
    try {
        std::lock_guard lock(g_rmu);
        g_rledger.on_called(d.gen, o.result, o.finder_session, p8_now_us(), o.dur_us, f.tid, g_sink);
        if (g_rledger.trip().gen == d.gen && g_rledger.trip().ours_pushed) g_r_enqueued.fetch_add(1);
    } catch (...) {
    }
}

void observer_milestone_reload_on_out(uint16_t opcode, uintptr_t self, bool pushed, uint32_t value) noexcept {
    if (g_r_mode.load(std::memory_order_relaxed) == omr::Mode::Off || !omr::followed_out(opcode)) return;
    try {
        const bool live = self && self == server_live_session2();
        const uint32_t ch = opcode == omr::kOpMilestone ? server_user2_player_key() : 0;
        const bool user2_char = ch && value == ch;
        std::lock_guard lock(g_rmu);
        g_rledger.on_out(opcode, live, pushed, GetCurrentThreadId(), p8_now_us(), value, user2_char, g_sink);
        g_r_waiting.store(g_rledger.waiting());
    } catch (...) {
    }
}

std::string observer_milestone_describe() {
    if (g_mode.load() == oms::Mode::Off) return {};
    return std::format("ObserverMilestone {}{} entries {} trips {} emitted {} enqueued {} refused {}{}",
                       g_mode.load() == oms::Mode::Send ? "SEND" : "dry run",
                       observer_milestone_active() ? "" : " (inactive)", g_a_entries.load(), g_a_trips.load(),
                       g_a_emits.load(), g_a_enqueued.load(), g_a_refused.load(),
                       g_r_mode.load() == omr::Mode::Off
                           ? std::string()
                           : std::format(" | reload {} (any {}): emitted {} enqueued {}",
                                         g_r_mode.load() == omr::Mode::On ? "1" : "probe",
                                         g_r_any.load() == omr::Mode::On      ? "1"
                                         : g_r_any.load() == omr::Mode::Probe ? "probe"
                                                                              : "0",
                                         g_r_emits.load(), g_r_enqueued.load()));
}

}  // namespace cdmp::session2
