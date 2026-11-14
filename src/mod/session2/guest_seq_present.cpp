#include "mod/session2/guest_seq_present.h"

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

#include "mod/game/build_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_seq_foreign.h"
#include "mod/session2/guest_seq_play.h"
#include "mod/session2/guest_seq_present_logic.h"
#include "mod/session2/guest_seq_route.h"
#include "mod/session2/guest_seq_route_logic.h"
#include "mod/session2/guest_x_veto_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;
namespace off = game::build_2976;
using gpr::Ev;
using gpr::Tl;
using gpr::Whose;

// The build, its fields and its world slot: written by guest_seq_present_start before any hook or thread.
bool g_3527 = false;  // 3527's layout (3527, 3549, 3576, 3663: the same processor slots)
bool g_3576 = false;  // 3576's addresses
bool g_3663 = false;  // 3663's addresses (and its stage layout, kStageLayout3663)
const gpr::StageLayout* g_sl = &gpr::kStageLayout2976;
const gpr::RaLayout* g_rl = &gpr::kRaLayout2976;
uintptr_t g_world_slot = off::kWorldSystemSlot;
gpr::EvInfo ev_of(Ev e) {
    return g_3663 ? gpr::ev_info_3663(e) : g_3576 ? gpr::ev_info_3576(e) : g_3527 ? gpr::ev_info_3527(e) : gpr::ev_info(e);
}

// ---------------------------------------------------------------- verified code (build 2976, capstone; s45-datos)
//
// S-B / S-C points. Every signature is unique in .rsrc of the 2976 exe; a raw scan of the whole exe found no rel8 /
// rel32 branch and no absolute pointer into any patched byte but its first one (scratchpad sondas\inbr.py).
struct Bytes {
    uint32_t rva;
    std::span<const uint8_t> bytes;
};
// CameraSelectorEventData slot 99: a 5-byte thunk jmp .xtls 0x12DBBCA0 (no .pdata: a leaf jump).
constexpr uint8_t kCamSelSig[] = {0xE9, 0x7B, 0xC0, 0x8E, 0x0F, 0x4E, 0xE9, 0x0C,
                                  0x15, 0x9F, 0x02, 0xCC, 0x3E, 0x47, 0xDC, 0x10};
// SequencerPlayerCameraPreset slot 99 0xB27880 (.pdata 0xB27880-0xB27DDE): mov [rsp+0x10],rbx (5).
constexpr uint8_t kPresetSig[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                  0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xD9, 0x48, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00,
                                  0x48, 0x8B, 0xFA, 0x4C, 0x8B, 0xF9, 0x48, 0x8B, 0x41, 0x38, 0x83, 0x78};
// The letter box's slot 99 0xC38F30: movzx edx,byte [rcx+0x3C] (4) ; jmp 0xC39050 (5) (no .pdata: a leaf stub).
constexpr uint8_t kLetterSig[] = {0x0F, 0xB6, 0x51, 0x3C, 0xE9, 0x17, 0x01, 0x00,
                                  0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
// The post process's slot 99 0xC3A440 (.pdata 0xC3A440-0xC3A510): push rbx (2) ; sub rsp,0x20 (4).
constexpr uint8_t kPostSig[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0xE8, 0x52, 0x9A, 0xB5, 0x02,
                                0x48, 0x8B, 0x90, 0x30, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0x42, 0x28, 0x4D, 0x85, 0xC0,
                                0x0F, 0x84, 0xA8, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x43, 0x39, 0x45, 0x33};
// SequencerAIDialog slot 99 0xC4D6B0 (.pdata 0xC4D6B0-0xC4E14D): mov rax,rsp (3) ; mov [rax+0x10],rbx (4).
constexpr uint8_t kDialogSig[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x48, 0x08, 0x55, 0x56, 0x57,
                                  0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0xD8, 0xF8, 0xFF,
                                  0xFF, 0x48, 0x81, 0xEC, 0xF0, 0x07, 0x00, 0x00, 0xC5, 0xF8, 0x29, 0x70};
// StartLoadingSequencer 0xC45740 (0x16 bytes, no .pdata: a leaf): 0xC45740 mov rax,[rip+0x6123A99] (= [0x6D691E0],
// RIP-relative: not patched) ; THE POINT 0xC45747 mov rdx,[rax+0x10] (4) ; movzx eax,byte [rcx+0x38] (4) ; mov
// [rdx+0x1E0],al ; ret. At the point RAX = the client world, RCX = the event, RDX = the context (still the argument).
constexpr uint8_t kLoadSig[] = {0x48, 0x8B, 0x50, 0x10, 0x0F, 0xB6, 0x41, 0x38, 0x88, 0x82, 0xE0, 0x01,
                                0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
constexpr uint8_t kLoadHead[] = {0x48, 0x8B, 0x05, 0x99, 0x3A, 0x12, 0x06};

struct EvPoint {
    Ev ev;
    uint32_t hook;      // where the mid hook goes
    uint32_t patch;     // its bytes (whole instructions)
    uint32_t fn_begin;  // the exact RUNTIME_FUNCTION of the entry; 0: a leaf stub (no entry may cover it)
    uint32_t fn_end;
    std::span<const uint8_t> sig;  // at `hook`
    std::span<const uint8_t> head; // at the entry, when the hook is not the entry
};
constexpr EvPoint kEvPoints[] = {
    {Ev::CameraSelector, 0x34CFC20, 5, 0, 0, kCamSelSig, {}},
    {Ev::PlayerCameraPreset, 0xB27880, 5, 0xB27880, 0xB27DDE, kPresetSig, {}},
    {Ev::LetterBox, 0xC38F30, 9, 0, 0, kLetterSig, {}},
    {Ev::PostProcess, 0xC3A440, 6, 0xC3A440, 0xC3A510, kPostSig, {}},
    {Ev::AIDialog, 0xC4D6B0, 7, 0xC4D6B0, 0xC4E14D, kDialogSig, {}},
    {Ev::StartLoading, 0xC45747, 8, 0, 0, kLoadSig, kLoadHead},
};
static_assert(std::size(kEvPoints) == gpr::kEvs);
constexpr bool ev_points_in_order() {
    for (size_t i = 0; i < gpr::kEvs; ++i) {
        if (static_cast<size_t>(kEvPoints[i].ev) != i) return false;
    }
    return true;
}
static_assert(ev_points_in_order(), "kEvPoints follows gpr::Ev (the hook callbacks index it)");

// Build 1.0.0.3527 (capstone 2026-11-05), R-B's two points only; S-A, S-B, S-C and S-D are not ported (the probe key is
// refused there). CameraSelectorEventData slot 99 0x37A0620: a 5-byte thunk jmp .text 0x1068DEB0, no .pdata.
// SequencerPlayerCameraPreset slot 99 0xC345C0 (.pdata 0xC345C0-0xC34AA0): mov [rsp+0x10],rbx (5). RTTI: their vtables
// 0x59185A0 / 0x5987070, slots 97 / 98 = `ret 0` 0x3A3450, 100 / 101 native. No branch lands in the patched bytes.
constexpr uint8_t kCamSelSig3527[] = {0xE9, 0x8B, 0xD8, 0xEE, 0x0C, 0x85, 0x19, 0xA3,
                                      0xE9, 0x48, 0x61, 0xCD, 0x01, 0xD5, 0x22, 0xA9};
constexpr uint8_t kPresetSig3527[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D,
                                      0x6C, 0x24, 0xC9, 0x48, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xFA, 0x4C,
                                      0x8B, 0xF1, 0x48, 0x8B, 0x41, 0x38, 0x83, 0x78, 0x40, 0x00, 0x75, 0x0C};
constexpr EvPoint kEvPoints3527[] = {
    {Ev::CameraSelector, 0x37A0620, 5, 0, 0, kCamSelSig3527, {}},
    {Ev::PlayerCameraPreset, 0xC345C0, 5, 0xC345C0, 0xC34AA0, kPresetSig3527, {}},
};
// 1.0.0.3549: the same points; the thunk's rel32 moved (jmp 0x104B17F0), the next 11 bytes did not.
constexpr uint8_t kCamSelSig3549[] = {0xE9, 0xCB, 0x11, 0xD1, 0x0C, 0x85, 0x19, 0xA3,
                                      0xE9, 0x48, 0x61, 0xCD, 0x01, 0xD5, 0x22, 0xA9};
constexpr EvPoint kEvPoints3549[] = {
    {Ev::CameraSelector, 0x37A0620, 5, 0, 0, kCamSelSig3549, {}},
    {Ev::PlayerCameraPreset, 0xC345C0, 5, 0xC345C0, 0xC34AA0, kPresetSig3527, {}},
};
// 1.0.0.3576 (static): slot 99 of each vtable (RTTI). The thunk moved +0xD00 (jmp 0x1035B910; the 11 bytes after it are
// other thunks, read as they are); the preset +0x420 with 3527's 40 bytes and .pdata 0xC349E0-0xC34EC0 (the same size).
constexpr uint8_t kCamSelSig3576[] = {0xE9, 0xEB, 0xA5, 0xBB, 0x0C, 0xE9, 0xF5, 0xE6,
                                      0xCE, 0xFF, 0xC5, 0x5F, 0x0D, 0xE9, 0x63, 0xEC};
constexpr EvPoint kEvPoints3576[] = {
    {Ev::CameraSelector, 0x37A1320, 5, 0, 0, kCamSelSig3576, {}},
    {Ev::PlayerCameraPreset, 0xC349E0, 5, 0xC349E0, 0xC34EC0, kPresetSig3527, {}},
};
// Build 1.0.0.3663 (static, 2026-11-13; never run): slot 99 of each vtable (RTTI). The thunk 0x3818600 is a 5-byte jmp to
// 0x10B8A670 in the protected section, no .pdata covers it (the 11 bytes after it read as they are); the preset
// 0xC6CC40 (+0x38680 from 3527) with 3527's 40 bytes and .pdata [0xC6CC40,0xC6D120) (3527's size 0x4E0). No branch lands
// in either patch (rel32 scan of both code sections).
constexpr uint8_t kCamSelSig3663[] = {0xE9, 0x6B, 0x20, 0x37, 0x0D, 0x0F, 0x8E, 0x05,
                                      0xE4, 0x3A, 0x01, 0xBB, 0x92, 0xB5, 0x0C, 0xCC};
constexpr EvPoint kEvPoints3663[] = {
    {Ev::CameraSelector, 0x3818600, 5, 0, 0, kCamSelSig3663, {}},
    {Ev::PlayerCameraPreset, 0xC6CC40, 5, 0xC6CC40, 0xC6D120, kPresetSig3527, {}},
};
// 0xBA9066 mov rcx,[0x71BDF40] ; mov edx,[rdx+0x2D0] ; mov rcx,[rcx+0x120] ; call 0x37ACC60 (right before P1's call)
constexpr uint8_t kStartLookup3527[] = {0x48, 0x8B, 0x0D, 0xD3, 0x4E, 0x61, 0x06, 0x8B, 0x92, 0xD0, 0x02, 0x00, 0x00,
                                        0x48, 0x8B, 0x89, 0x20, 0x01, 0x00, 0x00, 0xE8, 0xE1, 0x3B, 0xC0, 0x02};
constexpr uint8_t kTlIdCmp3527[] = {0x39, 0xA8, 0xF8, 0x01, 0x00, 0x00};  // 0x37ACCA5 cmp [rax+0x1F8],ebp
constexpr uint8_t kTlIdSet3527[] = {0x89, 0x9F, 0xF8, 0x01, 0x00, 0x00};  // 0x37AC63D mov [rdi+0x1F8],ebx
// 3576: 0xBA9486 mov rcx,[0x71C0150] ; ... ; call 0x37AD960 (+0x420; the global +0x2210, the callee +0xD00).
constexpr uint8_t kStartLookup3576[] = {0x48, 0x8B, 0x0D, 0xC3, 0x6C, 0x61, 0x06, 0x8B, 0x92, 0xD0, 0x02, 0x00, 0x00,
                                        0x48, 0x8B, 0x89, 0x20, 0x01, 0x00, 0x00, 0xE8, 0xC1, 0x44, 0xC0, 0x02};
// S-A / S-D context (no hook there; checked so the offsets read are this build's).
constexpr uint8_t kStartLookup[] = {0x48, 0x8B, 0x0D, 0xE3, 0xB8, 0x2C, 0x06, 0x8B, 0x92, 0x98, 0x02, 0x00, 0x00,
                                    0x48, 0x8B, 0x89, 0x20, 0x01, 0x00, 0x00, 0xE8, 0x21, 0xE8, 0xA3, 0x02};
// 0xA9D8F6 mov rcx,[0x6D691E0] ; mov edx,[rdx+0x298] ; mov rcx,[rcx+0x120] ; call 0x34DC130 (right before P1)
constexpr uint8_t kTlIdCmp[] = {0x39, 0xA8, 0xD8, 0x01, 0x00, 0x00};  // 0x34DC175 cmp [rax+0x1D8],ebp
constexpr uint8_t kTlIdSet[] = {0x89, 0x9F, 0xD8, 0x01, 0x00, 0x00};  // 0x34DBB03 mov [rdi+0x1D8],ebx
constexpr uint8_t kCamRead[] = {0x48, 0x8B, 0x05, 0xEB, 0x13, 0x24, 0x06, 0x33, 0xD2, 0x48, 0x8B, 0x88, 0x18, 0x01,
                                0x00, 0x00, 0x48, 0x8B, 0x41, 0x40, 0x48, 0x85, 0xC0, 0x48, 0x8D, 0x48, 0xD8};
// 0xB27DEE mov rax,[0x6D691E0] ; xor edx,edx ; mov rcx,[rax+0x118] ; mov rax,[rcx+0x40] ; test ; lea rcx,[rax-0x28]
constexpr uint8_t kBlockSet[] = {0x41, 0x88, 0xBD, 0x30, 0x02, 0x00, 0x00};  // 0xA98D3E mov [r13+0x230],dil
const Bytes kSaCode[] = {{0xA9D8F6, kStartLookup}, {0x34DC175, kTlIdCmp}, {0x34DBB03, kTlIdSet}};
// S-D: G+0x230 is verified by its writer 0xA98D3E. (Step 1 live: 0x5E4E6E, InputBlock's call into 0xA98AD0, is where
// guest_x_ui_veto puts its own 7-byte hook, so comparing its original bytes refused S-D; it only documented the path.)
const Bytes kSdCode[] = {{0xB27DEE, kCamRead}, {0xA98D3E, kBlockSet}, {0xA9D8F6, kStartLookup}};
// R-B: the dispatcher's two slot-99 calls (call [rax+0x318]) and what follows them (vivo1.md §2.3, s45-datos/ra/):
// 0x36574C7 call ; 0x36574CD jmp 0x36575EC (the epilogue) | 0x36575D0 call ; 0x36575D6 mov rcx,[rsi+0xA8] (then slot
// 101) | 0x3657600 mov al,1 (the dispatcher's own return: the event's RAX is never used).
constexpr uint8_t kRbCall1[] = {0x48, 0x8B, 0x01, 0xFF, 0x90, 0x18, 0x03, 0x00, 0x00, 0xE9, 0x1A, 0x01, 0x00, 0x00};
constexpr uint8_t kRbCall2[] = {0x48, 0x8B, 0x01, 0xFF, 0x90, 0x18, 0x03, 0x00, 0x00, 0x48, 0x8B, 0x8E, 0xA8, 0x00, 0x00,
                                0x00};
constexpr uint8_t kRbRet[] = {0xB0, 0x01, 0x48, 0x83, 0xC4, 0x38, 0x5E, 0x5D, 0xC3};
const Bytes kRbCode[] = {{0x36574C4, kRbCall1}, {0x36575CD, kRbCall2}, {0x3657600, kRbRet}};
// 3527: the same bytes at 0x392F584, 0x392F68D and 0x392F6C0 (their rel32 and the slot offsets did not change).
const Bytes kRbCode3527[] = {{0x392F584, kRbCall1}, {0x392F68D, kRbCall2}, {0x392F6C0, kRbRet}};
const Bytes kSaCode3527[] = {{0xBA9066, kStartLookup3527}, {0x37ACCA5, kTlIdCmp3527}, {0x37AC63D, kTlIdSet3527}};
// 3576: the dispatcher +0xDB0 with the same bytes; the id's compare and store +0xD00 with the same bytes.
const Bytes kRbCode3576[] = {{0x3930334, kRbCall1}, {0x393043D, kRbCall2}, {0x3930470, kRbRet}};
const Bytes kSaCode3576[] = {{0xBA9486, kStartLookup3576}, {0x37AD9A5, kTlIdCmp3527}, {0x37AD33D, kTlIdSet3527}};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the dispatcher's three pieces with 2976's bytes (each unique in the
// PE). 0xBE0FF6 (in P1's caller 0xBE0F60) mov rcx,[0x7245210] ; mov edx,[rdx+0x2E0] (THE STAGE'S TIMELINE ID MOVED: +0x2D0
// before) ; mov rcx,[rcx+0x120] ; call 0x3824BA0; the id's compare 0x3824BE5 (callee + 0x45, as on 3576) and its store
// 0x382457D (after a lock xadd of the counter) with 3527's bytes.
constexpr uint8_t kStartLookup3663[] = {0x48, 0x8B, 0x0D, 0x13, 0x42, 0x66, 0x06, 0x8B, 0x92, 0xE0, 0x02, 0x00, 0x00,
                                        0x48, 0x8B, 0x89, 0x20, 0x01, 0x00, 0x00, 0xE8, 0x91, 0x3B, 0xC4, 0x02};
const Bytes kRbCode3663[] = {{0x39A98B4, kRbCall1}, {0x39A99BD, kRbCall2}, {0x39A99F0, kRbRet}};
const Bytes kSaCode3663[] = {{0xBE0FF6, kStartLookup3663}, {0x3824BE5, kTlIdCmp3527}, {0x382457D, kTlIdSet3527}};

// ---------------------------------------------------------------- state

// R-A's lifetime evidence (s45-escenas-ajenas.md §3.1; the .xtls bodies are read statically, these .rsrc thunks are
// checked at install so the addresses are this build's): the processor's constructor 0x8F08E30 (writes 0x558C080) is
// reached only through 0x5D94F0, called only by ClientSequencerStage's constructor 0x8F5EBD0, which allocates 0x2F8
// bytes, constructs the processor with the stage and stores it in [stage+0x58]; the deleting destructor (slot 0,
// 0x5D9750 -> 0x8F094A0 -> 0x5D97B0 -> 0x8F0E3D0, which first writes 0x558C080 back) is called through [vptr] by the
// stage's base destructor (0x20516B0 -> 0xE0617E0: call [[stage+0x58]] with 1, then [stage+0x58] = 0).
struct Jmp {
    uint32_t at, to;
};
constexpr Jmp kRaLifetime[] = {{0x5D94F0, 0x8F08E30}, {0x5D9750, 0x8F094A0}, {0x5D97B0, 0x8F0E3D0}, {0x20516B0, 0xE0617E0}};
constexpr uint32_t kRaDeletingDtor = 0x5D9750;  // the client vtable's slot 0
// 1.0.0.3527 [V capstone]: only the constructor 0x8DF2F60 and the destructor 0x8DF44E0 load the vtable 0x5919128 (lea
// refs of the whole PE); the first is reached by the thunk 0x695740 and by 0x8E26FAB, inside ClientSequencerStage's
// constructor 0x8E26D40, which allocates, constructs with r8 = the stage and stores it in [stage+0x60] (0x8E26FCB); the
// deleting destructor (slot 0, 0x6959B0 -> 0x8DF4480 -> 0x8DF44E0, which writes 0x5919128 back at 0x8DF44F4) is called through
// [vptr] by the stage's base destructor at 0x220BCE5: mov rcx,[rdi+0x60] ; ... ; mov edx,1 ; call [rax] ; mov [rdi+0x60],rsi.
constexpr Jmp kRaLifetime3527[] = {{0x695740, 0x8DF2F60}, {0x6959B0, 0x8DF4480}, {0x695A10, 0x8DF44E0}};
constexpr Jmp kRaLifetime3549[] = {{0x695740, 0x8DBACE0}, {0x6959B0, 0x8DBC940}, {0x695A10, 0x8DBDAA0}};  // the same thunks, relocated targets
constexpr uint32_t kRaDeletingDtor3527 = 0x6959B0;
// 3576 (static): the thunks +0x660; the constructor 0x8E885D0 and the destructor 0x8E8AF20 are the two that load the
// client vtable 0x591B1B8 (0x8E885EA, 0x8E8AF34); the deleting destructor 0x8E89070 calls 0x8E8AF20 first. The stage's
// base destructor: 3527's 23 bytes at 0x220C925 (+0xC40), the only hit in the PE.
constexpr Jmp kRaLifetime3576[] = {{0x695DA0, 0x8E885D0}, {0x696010, 0x8E89070}, {0x696070, 0x8E8AF20}};
constexpr uint32_t kRaDeletingDtor3576 = 0x696010;
// Build 1.0.0.3663 (static, 2026-11-13; never run): the client vtable 0x5997A38's slot 0 is the thunk 0x6C1EE0 -> 0x9037B20
// (the deleting destructor, which calls 0x90402D0 first); the thunks 0x6C1C70 -> 0x9036A70 (the constructor) and
// 0x6C1F40 -> 0x90402D0 (the destructor) sit -0x270 / +0x60 from it as on 3576; 0x9036A70 and 0x90402D0 are the only two
// functions that load the client vtable (lea at 0x9036A8A / 0x90402E4, both code sections scanned). The stage's base
// destructor: 3527's 23 bytes at 0x227BB86, the only hit in the PE (an anchor of anchors_3663.json).
constexpr Jmp kRaLifetime3663[] = {{0x6C1C70, 0x9036A70}, {0x6C1EE0, 0x9037B20}, {0x6C1F40, 0x90402D0}};
constexpr uint32_t kRaDeletingDtor3663 = 0x6C1EE0;
constexpr uint8_t kRaBaseDtor3527[] = {0x48, 0x8B, 0x4F, 0x60, 0x48, 0x85, 0xC9, 0x74, 0x0E, 0x48, 0x8B, 0x01,
                                       0xBA, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x10, 0x48, 0x89, 0x77, 0x60};  // 0x220BCE5

uintptr_t g_base = 0;
std::atomic<bool> g_wanted{false};
std::atomic<bool> g_probe_wanted{false};
std::atomic<uint8_t> g_rb_wanted{0};  // R-B: gpr::RaMode asked for (guest_seq_foreign_timeline)
std::atomic<uint8_t> g_rb_mode{0};    // R-B armed (both camera starts hooked, the dispatcher and timeline verified)
std::string g_route_mode;  // written before the install thread starts
std::atomic<bool> g_on{false};     // S-A / S-A2 (the table): the install verified S-A's context
std::atomic<bool> g_sa_vt{false};  // the three processor vtables' COLs verified (S-A's classification)
std::atomic<bool> g_sd_on{false};
std::atomic<bool> g_settled{false};
std::atomic<bool> g_ev_on[gpr::kEvs] = {};
SafetyHookMid g_ev_hooks[gpr::kEvs];
uint64_t g_qpf = 0;  // QPC frequency (set before any hook is enabled)

std::atomic<uint64_t> g_m{0};
std::atomic<uint32_t> g_m_key{0};

gpr::StageTable<1024> g_stages;
gpr::StageTable<16> g_foreign;  // the foreign starts only (S-D's "latest live foreign stage")

// S-A
std::atomic<uint64_t> g_sa[static_cast<size_t>(Whose::Count)][static_cast<size_t>(gpr::ProcVt::Count)] = {};
std::atomic<uint64_t> g_sa_calls{0}, g_sa_mgr_diff{0}, g_sa_stage_diff{0}, g_sa_g_is_m{0}, g_sa_no_tl{0};
// S-A2 (per gxv::Fn): calls of X's handlers [before / after P1][foreign owner or not]
std::atomic<uint64_t> g_a2[gxv::kFns][2][2] = {};
std::atomic<uint64_t> g_a2_calls{0}, g_a2_no_stage{0};
// S-B / S-C
std::atomic<uint64_t> g_ev[gpr::kEvs][static_cast<size_t>(Tl::Count)] = {};
std::atomic<uint64_t> g_ev_vt_bad[gpr::kEvs] = {}, g_ev_cut[gpr::kEvs] = {};
gpr::Cost g_ev_cost[gpr::kEvs];
gpr::CallerCounts<4> g_ev_callers[gpr::kEvs];  // B1: who called each start (the letter box's slot 67 vs 99)
// S-D
std::atomic<uint64_t> g_sd_frames{0}, g_sd_changes[10] = {}, g_sd_x_not_mgr{0}, g_sd_tl_capped{0}, g_sd_tl_scans{0};
gpr::Cost g_sd_cost;
gpr::Present g_sd_prev;  // the main thread only (guest_seq_play's frame hook, which never re-enters)
bool g_sd_first = true;
uint64_t g_sd_tl_seq = 0;      // B3 (main thread only): the stage the last timeline scan was for
uint32_t g_sd_tl_frames = 0;   // frames since that scan

// R-A
std::atomic<uint8_t> g_ra_wanted{0};  // gpr::RaMode asked for (the key)
std::atomic<uint8_t> g_ra_mode{0};    // gpr::RaMode armed: set by the install once the table is verified and built
uint64_t g_ra_client_vt = 0;          // exe+0x558C080 } written before g_ra_mode (release), read after it (acquire)
uint64_t g_ra_mod_vt = 0;             // &table[1]     }
uint64_t* g_ra_page = nullptr;        // the table's page: [0] the COL, [1..105] the slots; read-only, never freed
std::string g_ra_cut_text;            // the decided slots, for the lines (written before g_ra_mode)
std::atomic<uint64_t> g_ra_verdicts[static_cast<size_t>(gpr::RaVerdict::Count)] = {};
std::atomic<uint64_t> g_ra_p1{0}, g_ra_written{0}, g_ra_write_failed{0}, g_ra_restored{0}, g_ra_restore_failed{0};
std::atomic<uint32_t> g_image_size{0};  // the exe's SizeOfImage (review P3-1: rva_of's bound), set before any hook
std::atomic<uint32_t> g_rb_bad_tl_vt{0};  // R-B: the last vptr of a [ctx+8] that was not the timeline's (RVA, for the summary)

// The processor slot of each of guest_x_veto's interface / camera handlers (guest_x_veto_logic.h's gxv::Fn); 0 for
// the dialogue ones (not processor slots).
uint16_t gxv_slot_2976(size_t fn) {
    switch (static_cast<gxv::Fn>(fn)) {
        case gxv::Fn::InputBlock: return 0x150;
        case gxv::Fn::UIControl: return 0x158;
        case gxv::Fn::ChangePhasePanelTag: return 0x160;
        case gxv::Fn::UIShowMinimap: return 0x168;
        case gxv::Fn::UIFindPath: return 0x170;
        case gxv::Fn::UIStageIcon: return 0x1F8;
        case gxv::Fn::UIStageGuide: return 0x238;
        case gxv::Fn::UIStageBackgroundGuide: return 0x240;
        case gxv::Fn::UIHint: return 0x248;
        case gxv::Fn::UIHintEnd: return 0x250;
        case gxv::Fn::DeactiveSequencerCamera: return 0x1B8;
        case gxv::Fn::DeactiveSequencerCameraEnd: return 0x1C0;
        case gxv::Fn::SequencerCamera: return 0x1C8;
        case gxv::Fn::DeactivateSequencerCameraFadeIn: return 0x1D0;
        case gxv::Fn::DeactivateSequencerCameraFadeInEnd: return 0x1D8;
        case gxv::Fn::CameraPreset: return 0x1E0;
        case gxv::Fn::CameraPresetEnd: return 0x1E8;
        case gxv::Fn::ForceLockOn: return 0x1F0;
        case gxv::Fn::LetterBox: return 0x208;
        case gxv::Fn::FadeInOut: return 0x210;
        case gxv::Fn::LookAt: return 0x220;
        case gxv::Fn::LookAtEnd: return 0x228;
        case gxv::Fn::PostProcess: return 0x260;
        default: return 0;
    }
}
// 3527: every slot above moved by +8 (kRaExpect3527).
uint16_t gxv_slot(size_t fn) {
    const uint16_t s = gxv_slot_2976(fn);
    return s && g_3527 ? static_cast<uint16_t>(s + 8) : s;
}

// R-B counters, per hooked class (0 CameraSelector, 1 PlayerCameraPreset) and verdict.
std::atomic<uint64_t> g_rb[2][static_cast<size_t>(gpr::RbVerdict::Count)] = {};

enum Kind : uint16_t { kESA, kESA2, kESB, kESBo, kESC, kESD, kERA, kERB, kKindCount };
p::EventRing<512> g_ring;
p::WindowLimiter g_lim[kKindCount] = {{48, 5'000'000}, {32, 5'000'000}, {64, 5'000'000}, {8, 5'000'000},
                                      {32, 5'000'000}, {24, 5'000'000}, {48, 5'000'000}, {48, 5'000'000}};
std::atomic<uint64_t> g_limited{0};
uint64_t g_lines = 0, g_capped = 0, g_ticks = 0;  // tick thread only
constexpr uint64_t kMaxLines = 3000;

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
uint32_t rva_of(uint64_t va) noexcept {
    const uint64_t size = g_image_size.load(std::memory_order_relaxed);  // review P3-1: the whole image (.xtls too)
    return va >= g_base && va - g_base < size ? static_cast<uint32_t>(va - g_base) : 0;
}
uint64_t qpc() noexcept {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return static_cast<uint64_t>(t.QuadPart);
}

void emit(Kind k, p::Event& e) noexcept {
    e.kind = k;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    if (!g_lim[k].take(e.qpc_us)) {
        g_limited.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_ring.push(e);  // a full ring counts its own drops
}

void put_name(uintptr_t stage, uint64_t seq, p::Event& e) noexcept {
    if (!stage || rdv<uint64_t>(stage + gpr::kStage_Seq) != seq) return;  // gone (or reused): no name
    const uintptr_t info = rdp(stage + g_sl->info);
    const uintptr_t name = info ? rdp(info + g_sl->name) : 0;
    for (int k = 0; k < 3 && name; ++k) e.v[9 + k] = rdv<uint64_t>(name + 8 * k);
}

Whose whose_now(uint32_t owner) noexcept {
    return gpr::whose(owner, guest_seq_route_own_key(), g_m_key.load(std::memory_order_relaxed));
}

// R-A's only write: [proc] from the client vtable to the mod's table, as one locked compare-exchange (the read and
// the comparison are the write's own: if anything else changed the vptr in between, nothing is written).
bool cas_vptr(uintptr_t proc, uint64_t expected, uint64_t desired) noexcept {
    if (proc < 0x10000 || (proc & 7)) return false;
    __try {
        return static_cast<uint64_t>(_InterlockedCompareExchange64(reinterpret_cast<volatile long long*>(proc),
                                                                   static_cast<long long>(desired),
                                                                   static_cast<long long>(expected))) == expected;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// R-A in P1 (any thread; in practice the main thread, which is checked): judge, write (1) or restore (review P2-2),
// one line per foreign stage and per restore.
void ra_p1(uintptr_t stage, uint32_t resource, gpr::RaMode mode) noexcept {
    g_ra_p1.fetch_add(1, std::memory_order_relaxed);
    gpr::RaFacts f;
    f.mode = mode;
    f.stage = stage;
    const uint32_t owner = rdv<uint32_t>(stage + g_sl->owner);
    f.whose = whose_now(owner);
    f.stage_mgr = rdp(stage + gpr::kStage_Mgr);
    f.m = g_m.load(std::memory_order_relaxed);
    f.proc = rdp(stage + g_sl->proc);
    f.vt_read = f.proc && rd(f.proc, f.vt);
    f.client_vt = g_ra_client_vt;
    f.mod_vt = g_ra_mod_vt;
    gpr::RaVerdict v = gpr::ra_judge(f);  // NotForeign / NoProcessor / Unreadable / MUnknown / InM need nothing more
    if (v != gpr::RaVerdict::NotForeign && v != gpr::RaVerdict::NoProcessor && v != gpr::RaVerdict::Unreadable &&
        v != gpr::RaVerdict::MUnknown && v != gpr::RaVerdict::InM) {
        f.proc_stage = rdp(f.proc + gpr::kProc_Stage);
        f.proc_mgr = rdp(f.proc + gpr::kProc_Mgr);
        f.x_known = f.stage_mgr && guest_seq_play_knows_x(f.stage_mgr, owner);  // P1-1: G is a known X of the owner
        f.tid = GetCurrentThreadId();
        f.main_tid = guest_seq_play_main_tid();
        v = gpr::ra_judge(f);
    }
    bool wrote = false, failed = false, restored = false;
    if (gpr::ra_restore_due(f, v)) {
        // P2-2: a stage that must never carry the mod's table does: put the client vtable back.
        restored = cas_vptr(f.proc, f.mod_vt, f.client_vt) && rdv<uint64_t>(f.proc) == f.client_vt;
        failed = !restored;
        (restored ? g_ra_restored : g_ra_restore_failed).fetch_add(1, std::memory_order_relaxed);
    } else if (v == gpr::RaVerdict::Write) {
        wrote = cas_vptr(f.proc, f.client_vt, f.mod_vt) && rdv<uint64_t>(f.proc) == f.mod_vt;
        failed = !wrote;
        (wrote ? g_ra_written : g_ra_write_failed).fetch_add(1, std::memory_order_relaxed);
    }
    g_ra_verdicts[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    if (v == gpr::RaVerdict::NotForeign && !restored && !failed) return;  // own / world stages: counted, no line
    p::Event e;
    const uint64_t seq = rdv<uint64_t>(stage + gpr::kStage_Seq);
    e.v[0] = static_cast<uint64_t>(v) | static_cast<uint64_t>(wrote) << 8 | static_cast<uint64_t>(failed) << 9 |
             static_cast<uint64_t>(restored) << 10 | static_cast<uint64_t>(mode) << 16;
    e.v[1] = seq;
    e.v[2] = owner | static_cast<uint64_t>(guest_seq_route_own_key()) << 32;
    e.v[3] = resource | static_cast<uint64_t>(rdv<uint8_t>(stage + g_sl->started, 0xFF)) << 32;
    e.v[4] = f.vt_read ? rva_of(f.vt) : 0;
    e.v[5] = f.proc;
    e.v[6] = (f.vt_read && f.vt == f.mod_vt ? 1 : 0) | (f.stage_mgr == f.m && f.m ? 2 : 0) |
             (static_cast<uint64_t>(f.x_known) << 2);
    e.v[7] = f.tid | static_cast<uint64_t>(f.main_tid) << 32;
    e.v[8] = f.proc_stage == stage || !f.proc_stage ? 0 : f.proc_stage;
    put_name(stage, seq, e);
    emit(kERA, e);
}

// Every stage start into the table (S-A's, S-B's and R-B's link timeline id -> stage).
gpr::StageRec note_stage(uintptr_t stage) noexcept {
    gpr::StageRec r;
    r.seq = rdv<uint64_t>(stage + gpr::kStage_Seq);
    r.mgr = rdp(stage + gpr::kStage_Mgr);
    r.stage = stage;
    r.us = p8_now_us();
    r.tl = rdv<uint32_t>(stage + g_sl->timeline, 0xFFFFFFFFu);
    r.owner = rdv<uint32_t>(stage + g_sl->owner);
    r.whose = whose_now(r.owner);
    g_stages.note(r);
    if (r.whose == Whose::Foreign) g_foreign.note(r);
    return r;
}

// S-A: P1 (the entry of 0x602940; RCX = the stage that starts).
void sa_p1(uintptr_t stage) noexcept {
    g_sa_calls.fetch_add(1, std::memory_order_relaxed);
    const gpr::StageRec r = note_stage(stage);
    if (r.tl == 0 || r.tl == 0xFFFFFFFFu) g_sa_no_tl.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t proc = rdp(stage + g_sl->proc);
    uintptr_t vt = 0;
    const bool vt_ok = proc && rd(proc, vt);
    const uint32_t vt_rva = vt_ok ? rva_of(vt) : 0;
    const gpr::ProcVt pv = gpr::classify_proc(proc, vt_ok, vt_rva);
    g_sa[static_cast<size_t>(r.whose)][static_cast<size_t>(pv)].fetch_add(1, std::memory_order_relaxed);
    const uintptr_t p_mgr = proc ? rdp(proc + gpr::kProc_Mgr) : 0;
    const uintptr_t p_stage = proc ? rdp(proc + gpr::kProc_Stage) : 0;
    const uint64_t m = g_m.load(std::memory_order_relaxed);
    if (r.whose != Whose::Foreign) return;
    if (proc && p_mgr != r.mgr) g_sa_mgr_diff.fetch_add(1, std::memory_order_relaxed);
    if (proc && p_stage != stage) g_sa_stage_diff.fetch_add(1, std::memory_order_relaxed);
    if (m && r.mgr == m) g_sa_g_is_m.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    e.v[0] = static_cast<uint64_t>(pv) | static_cast<uint64_t>(proc && p_mgr == r.mgr) << 8 |
             static_cast<uint64_t>(proc && p_stage == stage) << 9 | static_cast<uint64_t>(m != 0) << 10 |
             static_cast<uint64_t>(m && r.mgr == m) << 11 |
             static_cast<uint64_t>(rdv<uint8_t>(stage + g_sl->started, 0xFF)) << 16 |
             static_cast<uint64_t>(g_sa_vt.load(std::memory_order_relaxed)) << 24;
    e.v[1] = r.seq;
    e.v[2] = r.owner | static_cast<uint64_t>(guest_seq_route_own_key()) << 32;
    e.v[3] = r.tl | static_cast<uint64_t>(g_m_key.load(std::memory_order_relaxed)) << 32;
    e.v[4] = vt_rva;
    e.v[5] = p_mgr;
    e.v[6] = r.mgr;
    e.v[7] = proc;
    e.v[8] = p_stage == stage ? 0 : p_stage;
    put_name(stage, r.seq, e);
    emit(kESA, e);
}

}  // namespace

// P1 (the entry of 0x602940; RCX = the stage that starts): S-A (probe), R-B's table and R-A.
void guest_seq_present_p1(uintptr_t stage, uint32_t resource) noexcept {
    const bool sa = g_on.load(std::memory_order_acquire);
    const auto ra = static_cast<gpr::RaMode>(g_ra_mode.load(std::memory_order_acquire));
    const bool rb = g_rb_mode.load(std::memory_order_acquire) != 0;
    if (!stage || (!sa && !rb && ra == gpr::RaMode::Off)) return;
    if (sa) {
        sa_p1(stage);
    } else if (rb) {
        note_stage(stage);
    }
    if (ra != gpr::RaMode::Off) ra_p1(stage, resource, ra);
}

// S-A2: one of guest_x_veto's handlers ran for a stage of X (proc = its processor; the stage is read here, after the
// key's check, so nothing is read with the probe off: revision.md B2).
void guest_seq_present_x_fn(size_t fn, uintptr_t proc) noexcept {
    if (!g_on.load(std::memory_order_acquire) || fn >= gxv::kFns) return;
    g_a2_calls.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t stage = proc ? rdp(proc + gpr::kProc_Stage) : 0;
    if (!stage) {
        g_a2_no_stage.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const uint64_t seq = rdv<uint64_t>(stage + gpr::kStage_Seq);
    const uint32_t owner = rdv<uint32_t>(stage + g_sl->owner);
    const bool foreign = whose_now(owner) == Whose::Foreign;
    gpr::StageRec r;
    const bool seen = g_stages.find_seq(seq, r);
    g_a2[fn][seen ? 1 : 0][foreign ? 1 : 0].fetch_add(1, std::memory_order_relaxed);
    if (seen) return;
    p::Event e;
    e.v[0] = fn | static_cast<uint64_t>(foreign) << 8 |
             static_cast<uint64_t>(rdv<uint8_t>(stage + g_sl->started, 0xFF)) << 16;
    e.v[1] = seq;
    e.v[2] = owner | static_cast<uint64_t>(guest_seq_route_own_key()) << 32;
    e.v[3] = rdv<uint32_t>(stage + g_sl->timeline, 0xFFFFFFFFu);
    put_name(stage, seq, e);
    emit(kESA2, e);
}

namespace {

// S-B / S-C: a timeline event's start (RCX = the event, RDX = the context).
void on_event(Ev ev, safetyhook::Context& ctx) noexcept {
    const size_t i = static_cast<size_t>(ev);
    const gpr::EvInfo info = gpr::ev_info(ev);
    const uintptr_t event = ctx.rcx, cx = ctx.rdx;
    // B1: [rsp] is the return address at every point (the entries, and 0xC45747 after a load that leaves rsp alone).
    const uint32_t caller = rva_of(rdv<uint64_t>(ctx.rsp));
    g_ev_callers[i].add(caller);
    const bool vt_ok = rdp(event) == g_base + info.vt;
    if (!vt_ok) g_ev_vt_bad[i].fetch_add(1, std::memory_order_relaxed);
    const uintptr_t node = rdp(cx + gpr::kCtx_Node);
    uint32_t depth = 0;
    bool cut = false;
    const uintptr_t root = gpr::root_of(node, [](uint64_t a, uint64_t& out) { return rd<uint64_t>(a, out); }, depth, cut);
    if (cut) g_ev_cut[i].fetch_add(1, std::memory_order_relaxed);
    uint32_t id = 0;
    const bool id_ok = root && !cut && rd(root + g_sl->tl_id, id);
    gpr::StageRec r;
    const bool found = id_ok && g_stages.find_tl(id, r);
    const Whose w = found ? whose_now(r.owner) : Whose::OwnUnknown;
    const Tl t = gpr::classify_tl(id_ok, found, w);
    g_ev[i][static_cast<size_t>(t)].fetch_add(1, std::memory_order_relaxed);
    // A line for every foreign one and every StartLoadingSequencer (budgeted); the rest only sampled (8 per 5 s).
    const bool loading = ev == Ev::StartLoading;
    p::Event e;
    e.v[0] = static_cast<uint64_t>(ev) | static_cast<uint64_t>(t) << 8 | static_cast<uint64_t>(vt_ok) << 16 |
             static_cast<uint64_t>(depth & 0xFF) << 24 | static_cast<uint64_t>(cut) << 32 |
             static_cast<uint64_t>(root ? rdv<uint8_t>(root + g_sl->tl_listed, 0xFF) : 0xFF) << 40 |
             static_cast<uint64_t>(root ? rdv<uint8_t>(root + gpr::kTl_Playing, 0xFF) : 0xFF) << 48;
    e.v[1] = found ? r.seq : 0;
    e.v[2] = id | static_cast<uint64_t>(found ? r.owner : 0) << 32;
    e.v[3] = rdv<uint8_t>(cx + gpr::kCtx_Flags, 0xFF) | static_cast<uint64_t>(id_ok) << 8;
    e.v[4] = rdv<uint64_t>(event + gpr::kEv_Data);
    e.v[5] = root ? rva_of(rdp(root)) : 0;
    e.v[6] = node ? rva_of(rdp(node)) : 0;
    e.v[7] = guest_seq_route_own_key() | static_cast<uint64_t>(g_m_key.load(std::memory_order_relaxed)) << 32;
    if (loading) {
        // RAX = the client world at 0xC45747 (0xC45740's load); P = [rax+0x10]; the byte written and the one there.
        const uintptr_t pobj = rdp(ctx.rax + gpr::kCw_Loading);
        uint8_t before = 0;
        const bool p_ok = pobj && rd(pobj + gpr::kP_StartLoading, before);
        e.v[8] = rdv<uint8_t>(event + gpr::kEv_Data, 0xFF) | static_cast<uint64_t>(before) << 8 |
                 static_cast<uint64_t>(p_ok) << 16 |
                 static_cast<uint64_t>(ctx.rax == rdp(g_base + gpr::kWorldSlot)) << 17;
    }
    e.v[8] |= static_cast<uint64_t>(caller) << 32;
    if (found) put_name(r.stage, r.seq, e);
    emit(loading ? kESC : t == Tl::Foreign ? kESB : kESBo, e);
}

// R-B at a camera event's start (the entry: [rsp] = the return address). Skip = return to the caller as the
// class's empty slot would: safetyhook's mid-hook exit does `pop rsp ; ret` from trampoline_rsp, so pointing it at the
// entry's own rsp (ctx.rsp, the return address on top) leaves with rsp + 8 and rip = the return address, every other
// register (RAX included) as it came in, and none of the entry's instructions run.
void rb_event(Ev ev, safetyhook::Context& ctx, gpr::RaMode mode) noexcept {
    const size_t k = ev == Ev::CameraSelector ? 0 : 1;
    gpr::RbFacts f;
    f.mode = mode;
    f.caller = rva_of(rdv<uint64_t>(ctx.rsp));
    if (g_3663) {
        f.callers = gpr::kRbCallers3663;
    } else if (g_3576) {
        f.callers = gpr::kRbCallers3576;
    } else if (g_3527) {
        f.callers = gpr::kRbCallers3527;
    }
    f.event_class = rdp(ctx.rcx) == g_base + ev_of(ev).vt;  // review P3-2
    const uintptr_t tl = rdp(ctx.rdx + gpr::kCtx_Node);
    f.timeline = tl && rdp(tl) == g_base + g_sl->vt_timeline;
    if (tl && !f.timeline) g_rb_bad_tl_vt.store(rva_of(rdp(tl)), std::memory_order_relaxed);
    uint32_t id = 0;
    gpr::StageRec r;
    f.found = f.timeline && rd(tl + g_sl->tl_id, id) && g_stages.find_tl(id, r);
    if (f.found) {
        // Review P3-1: still the same stage, with the same timeline id.
        f.alive = rdv<uint64_t>(r.stage + gpr::kStage_Seq) == r.seq && rdv<uint32_t>(r.stage + g_sl->owner) == r.owner &&
                  rdv<uint32_t>(r.stage + g_sl->timeline) == id;
        f.whose = whose_now(r.owner);
        f.stage_mgr = r.mgr;
        f.x_known = r.mgr && guest_seq_play_knows_x(r.mgr, r.owner);
    }
    f.m = g_m.load(std::memory_order_relaxed);
    f.tid = GetCurrentThreadId();
    f.main_tid = guest_seq_play_main_tid();
    const gpr::RbVerdict v = gpr::rb_judge(f);
    g_rb[k][static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
    if (v == gpr::RbVerdict::Skip) ctx.trampoline_rsp = ctx.rsp;  // return at the entry
    if (!gpr::rb_makes_line(f, v)) return;
    p::Event e;
    e.v[0] = static_cast<uint64_t>(v) | static_cast<uint64_t>(ev) << 8 | static_cast<uint64_t>(mode) << 16 |
             static_cast<uint64_t>(f.alive) << 24 | static_cast<uint64_t>(f.x_known) << 25 |
             static_cast<uint64_t>(f.m && f.stage_mgr == f.m) << 26;
    e.v[1] = f.found ? r.seq : 0;
    e.v[2] = id | static_cast<uint64_t>(f.found ? r.owner : 0) << 32;
    e.v[3] = f.caller | static_cast<uint64_t>(guest_seq_route_own_key()) << 32;
    e.v[4] = rdv<uint64_t>(ctx.rcx + gpr::kEv_Data);
    e.v[5] = tl && !g_3527 ? rdv<uint8_t>(tl + gpr::kTl_Playing, 0xFF) : 0xFF;  // not re-derived on 3527 (log only)
    e.v[7] = f.tid | static_cast<uint64_t>(f.main_tid) << 32;
    if (f.found) put_name(r.stage, r.seq, e);
    emit(kERB, e);
}

template <size_t I>
void on_ev(safetyhook::Context& ctx) noexcept {
    if (!g_ev_on[I].load(std::memory_order_acquire)) return;
    const uint64_t t0 = qpc();
    if (g_probe_wanted.load(std::memory_order_relaxed)) on_event(static_cast<Ev>(I), ctx);
    if constexpr (static_cast<Ev>(I) == Ev::CameraSelector || static_cast<Ev>(I) == Ev::PlayerCameraPreset) {
        const auto rb = static_cast<gpr::RaMode>(g_rb_mode.load(std::memory_order_acquire));
        if (rb != gpr::RaMode::Off) rb_event(static_cast<Ev>(I), ctx, rb);  // slot 99 only: checked by the caller
    }
    g_ev_cost[I].add(qpc() - t0);
}
template <size_t... I>
constexpr std::array<safetyhook::MidHookFn, sizeof...(I)> ev_fns(std::index_sequence<I...>) {
    return {&on_ev<I>...};
}
constexpr auto kEvFns = ev_fns(std::make_index_sequence<gpr::kEvs>{});

// S-D's replica of 0x34DC130 on the three unlocked lists (the main thread, which owns them natively): the list (1..3)
// and +0xDC of the timeline with this id; 0 = not found, 0xFF = unreadable.
uint8_t find_timeline(uintptr_t player, uint32_t id, uint8_t& playing) noexcept {
    playing = 0xFF;
    if (!player) return 0xFF;
    if (!id || id == 0xFFFFFFFFu) return 0;
    for (uint8_t l = 0; l < 3; ++l) {
        const gpr::TlList& L = gpr::kTlLists[l];
        const uintptr_t arr = rdp(player + L.ptr);
        uint32_t n = 0;
        if (!rd(player + L.count, n)) return 0xFF;
        if (n > gpr::kTlMaxPerList) {
            g_sd_tl_capped.fetch_add(1, std::memory_order_relaxed);
            n = gpr::kTlMaxPerList;
        }
        for (uint32_t k = 0; k < n && arr; ++k) {
            const uintptr_t t = rdp(arr + 8ull * k);
            if (!t) continue;
            if (L.needs_listed && !rdv<uint8_t>(t + g_sl->tl_listed)) continue;
            if (rdv<uint32_t>(t + g_sl->tl_id) != id) continue;
            playing = rdv<uint8_t>(t + gpr::kTl_Playing, 0xFF);
            return static_cast<uint8_t>(l + 1);
        }
    }
    return 0;
}

}  // namespace

// S-D: once per frame, the main thread (guest_seq_play's hook at 0x8B6144; RAX = M).
void guest_seq_present_frame(uintptr_t m) noexcept {
    const bool sd = g_sd_on.load(std::memory_order_acquire);
    // Review of R-B P2-1: R-A and R-B both need M and its owner's key, with or without S-D.
    if (!sd && !g_ra_mode.load(std::memory_order_relaxed) && !g_rb_mode.load(std::memory_order_relaxed)) return;
    // M and its owner's key: S-A's and R-A's "own" is this client's character OR M's live owner (S44's judgement).
    uint32_t m_key = 0;
    if (m) {
        const uintptr_t actor = rdp(m + gpr::kMgr_Actor);
        m_key = actor ? rdv<uint32_t>(actor + gpr::kActor_Key) : 0;
        g_m.store(m, std::memory_order_relaxed);
        g_m_key.store(m_key, std::memory_order_relaxed);
    }
    if (!sd) return;
    const uint64_t t0 = qpc();
    g_sd_frames.fetch_add(1, std::memory_order_relaxed);
    gpr::Present s;
    const uintptr_t cw = rdp(g_base + gpr::kWorldSlot);
    s.world = cw != 0;
    uintptr_t player = 0;
    if (cw) {
        const uintptr_t cam = rdp(cw + gpr::kCw_Camera);
        s.cam = cam ? rdp(cam + gpr::kCam_Current) : 0;
        s.cam_vt = s.cam ? rva_of(rdp(rdp(s.cam - gpr::kCamEntryAdjust))) : 0;
        player = rdp(cw + gpr::kCw_Player);
        for (size_t l = 0; l < 3 && player; ++l) s.tl_n[l] = rdv<uint32_t>(player + gpr::kTlLists[l].count);
        const uintptr_t w0 = rdp(cw);
        s.de8_ok = w0 && rd(w0 + gpr::kW0_De8, s.de8);
    }
    s.m_block = m ? rdv<uint8_t>(m + gpr::kMgr_InputBlock, 0xFF) : 0xFF;
    // The latest foreign start still alive (its stage reads back its sequencer and owner).
    gpr::StageRec f, best;
    bool have = false;
    const uint64_t now = p8_now_us();
    if (g_foreign.latest_foreign(f)) {  // the 16 most recent foreign starts
        const uint64_t seq = rdv<uint64_t>(f.stage + gpr::kStage_Seq);
        const uint32_t owner = rdv<uint32_t>(f.stage + g_sl->owner);
        if (gpr::foreign_live(f, now, seq, owner)) {
            best = f;
            have = true;
        }
    }
    if (have) {
        s.fseq = best.seq;
        if (rdp(best.mgr) == g_base + gpr::kVtStageManager) {
            s.x_block = rdv<uint8_t>(best.mgr + gpr::kMgr_InputBlock, 0xFF);
        } else {
            g_sd_x_not_mgr.fetch_add(1, std::memory_order_relaxed);
        }
        if (gpr::sd_scan_due(best.seq, g_sd_tl_seq, g_sd_tl_frames)) {  // B3: not every frame
            s.ftl = find_timeline(player, best.tl, s.fplay);
            g_sd_tl_seq = best.seq;
            g_sd_tl_frames = 0;
            g_sd_tl_scans.fetch_add(1, std::memory_order_relaxed);
        } else {
            s.ftl = g_sd_prev.ftl;
            s.fplay = g_sd_prev.fplay;
            ++g_sd_tl_frames;
        }
    } else {
        g_sd_tl_seq = 0;  // the next live foreign stage is scanned at once
    }
    const uint32_t d = g_sd_first ? ~0u : gpr::diff(g_sd_prev, s);
    if (d) {
        for (uint32_t b = 0; b < 10; ++b) {
            if (d & (1u << b)) g_sd_changes[b].fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (g_sd_first || gpr::makes_line(d)) {
        p::Event e;
        e.v[0] = (g_sd_first ? 0xFFFFu : d) | static_cast<uint64_t>(s.world) << 16 |
                 static_cast<uint64_t>(s.de8_ok) << 17 | static_cast<uint64_t>(s.m_block) << 24 |
                 static_cast<uint64_t>(s.x_block) << 32 | static_cast<uint64_t>(s.ftl) << 40 |
                 static_cast<uint64_t>(s.fplay) << 48;
        e.v[1] = s.cam;
        e.v[2] = s.cam_vt | static_cast<uint64_t>(s.de8) << 32;
        e.v[3] = s.tl_n[0] | static_cast<uint64_t>(s.tl_n[1]) << 32;
        e.v[4] = s.tl_n[2] | static_cast<uint64_t>(m_key) << 32;
        e.v[5] = s.fseq;
        e.v[6] = have ? best.tl | static_cast<uint64_t>(best.owner) << 32 : 0;
        e.v[7] = have ? best.mgr : 0;
        e.v[8] = have && now >= best.us ? (now - best.us) / 1000 : 0;  // ms since its P1
        if (have) put_name(best.stage, best.seq, e);
        emit(kESD, e);
    }
    g_sd_prev = s;
    g_sd_first = false;
    g_sd_cost.add(qpc() - t0);
}

namespace {

// ---------------------------------------------------------------- lines (diagnostics thread)

std::string name_of(const p::Event& e) {
    char name[32] = {};
    gsr::scene_name(e.v + 9, 3, name, sizeof name);
    return name;
}
std::string hex_or_none(uint64_t v) { return v ? std::format("0x{:X}", v) : std::string("none"); }
std::string tl_text(uint32_t tl) { return tl == 0xFFFFFFFFu ? std::string("none (-1)") : std::format("{}", tl); }

std::string line_of(const p::Event& e) {
    const std::string when = p8_when(e.qpc_us);
    const uint64_t* v = e.v;
    switch (e.kind) {
        case kESA: {
            const auto pv = static_cast<gpr::ProcVt>(v[0] & 0xFF);
            const bool has_proc = v[7] != 0;
            return std::format(
                "GuestSeqPresent [S-A P1 FOREIGN stage] {} T{} | stage seq 0x{:X} '{}' owner 0x{:08X} (this client "
                "0x{:08X}, M's 0x{:08X}) | timeline id stage+0x298 {} | processor [stage+0x58] {}: vtable exe+0x{:X} = "
                "{}{} | [proc+8] {} [stage+0x28] (G 0x{:X}{}) | [proc+0x10] {} | started +0x28B {}",
                when, e.tid, v[1], name_of(e), static_cast<uint32_t>(v[2]), static_cast<uint32_t>(v[2] >> 32),
                static_cast<uint32_t>(v[3] >> 32), tl_text(static_cast<uint32_t>(v[3])), hex_or_none(v[7]), v[4],
                gpr::proc_vt_name(pv), ((v[0] >> 24) & 1) ? "" : " (vtables NOT verified)",
                !has_proc ? "-" : ((v[0] >> 8) & 1) ? "==" : "!=", v[6],
                !((v[0] >> 10) & 1) ? ", M unknown" : ((v[0] >> 11) & 1) ? ", = M: NOT X" : ", != M",
                !has_proc ? "-" : ((v[0] >> 9) & 1) ? "== the stage" : std::format("!= the stage (0x{:X})", v[8]),
                (v[0] >> 16) & 0xFF);
        }
        case kESA2: {
            const auto fn = static_cast<gxv::Fn>(v[0] & 0xFF);
            return std::format("GuestSeqPresent [S-A2 BEFORE P1] {} T{} | {} ran for stage seq 0x{:X} '{}' of X before "
                               "P1 noted it (not among the table's last {} starts) | owner 0x{:08X} ({}; this client "
                               "0x{:08X}) timeline {} started +0x28B {}",
                               when, e.tid, gxv::fn_info(fn).name, v[1], name_of(e), g_stages.capacity(),
                               static_cast<uint32_t>(v[2]),
                               ((v[0] >> 8) & 1) ? "FOREIGN" : "not foreign", static_cast<uint32_t>(v[2] >> 32),
                               tl_text(static_cast<uint32_t>(v[3])), (v[0] >> 16) & 0xFF);
        }
        case kESB:
        case kESBo:
        case kESC: {
            const auto ev = static_cast<Ev>(v[0] & 0xFF);
            const auto t = static_cast<Tl>((v[0] >> 8) & 0xFF);
            std::string extra;
            if (e.kind == kESC) {
                extra = std::format(" | writes P+0x1E0 = {} (was {}{}){}", v[8] & 0xFF, (v[8] >> 8) & 0xFF,
                                    ((v[8] >> 16) & 1) ? "" : ", P unreadable",
                                    ((v[8] >> 17) & 1) ? "" : " | RAX is NOT [0x6D691E0] (unexpected)");
            }
            return std::format(
                "GuestSeqPresent [{} {}] {} T{} | {}{} | timeline: root of [ctx+8] at depth {}{} (vtable exe+0x{:X}, node "
                "vtable exe+0x{:X}) id +0x1D8 {} listed +0x1D1 {} playing +0xDC {} | stage seq {} '{}' owner 0x{:08X} "
                "(this client 0x{:08X}, M's 0x{:08X}) | ctx+0x5C 0x{:02X} | ev+0x38 0x{:X} | caller exe+0x{:X}{}",
                e.kind == kESC ? "S-C" : "S-B", gpr::ev_info(ev).name, when, e.tid, gpr::tl_name(t),
                ((v[0] >> 16) & 1) ? "" : " (event vtable NOT the class's)", (v[0] >> 24) & 0xFF,
                ((v[0] >> 32) & 1) ? " (CUT)" : "", v[5], v[6],
                ((v[3] >> 8) & 1) ? std::format("{}", static_cast<uint32_t>(v[2])) : std::string("unreadable"),
                (v[0] >> 40) & 0xFF, (v[0] >> 48) & 0xFF, hex_or_none(v[1]), name_of(e),
                static_cast<uint32_t>(v[2] >> 32), static_cast<uint32_t>(v[7]), static_cast<uint32_t>(v[7] >> 32),
                v[3] & 0xFF, v[4], static_cast<uint32_t>(v[8] >> 32), extra);
        }
        case kESD: {
            const uint32_t d = static_cast<uint32_t>(v[0] & 0xFFFF);
            std::string what;
            const char* names[10] = {"world", "camera entry", "camera vtable", "timeline counts", "+0xDE8",
                                     "M input block", "X input block", "foreign stage", "its timeline", "its +0xDC"};
            if (d == 0xFFFF) {
                what = " first sample";
            } else {
                for (uint32_t b = 0; b < 10; ++b) {
                    if (d & (1u << b)) what += std::format(" {};", names[b]);
                }
            }
            const auto blk = [](uint64_t b) { return b == 0xFF ? std::string("?") : std::format("{}", b); };
            const uint8_t ftl = static_cast<uint8_t>(v[0] >> 40), fplay = static_cast<uint8_t>(v[0] >> 48);
            return std::format(
                "GuestSeqPresent [S-D change] {} T{} |{} | camera [[cw+0x118]+0x40] {} (object vtable exe+0x{:X}) | "
                "[[cw]]+0xDE8 {} | player lists {}/{}/{} | input block M+0x230 {} (M's 0x{:08X}), X+0x230 {} | latest "
                "live foreign stage {} '{}' owner 0x{:08X} timeline {} ({} ms after P1): {}",
                when, e.tid, what, hex_or_none(v[1]), static_cast<uint32_t>(v[2]),
                ((v[0] >> 17) & 1) ? std::format("{}", static_cast<uint32_t>(v[2] >> 32)) : std::string("unreadable"),
                static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[3] >> 32), static_cast<uint32_t>(v[4]),
                blk((v[0] >> 24) & 0xFF), static_cast<uint32_t>(v[4] >> 32), blk((v[0] >> 32) & 0xFF),
                hex_or_none(v[5]), name_of(e), static_cast<uint32_t>(v[6] >> 32), tl_text(static_cast<uint32_t>(v[6])),
                v[8],
                !v[5]          ? std::string("-")
                : ftl == 0     ? std::string("NOT in the player's lists")
                : ftl == 0xFF  ? std::string("player unreadable")
                               : std::format("in the player (list {}), +0xDC {}", ftl, blk(fplay)));
        }
        case kERA: {
            const auto verdict = static_cast<gpr::RaVerdict>(v[0] & 0xFF);
            const bool wrote = (v[0] >> 8) & 1, failed = (v[0] >> 9) & 1, restored = (v[0] >> 10) & 1;
            const bool restore = gpr::RaVerdict::NotForeign == verdict || gpr::RaVerdict::InM == verdict ||
                                 gpr::RaVerdict::MUnknown == verdict;
            const auto mode = static_cast<gpr::RaMode>((v[0] >> 16) & 0xFF);
            const char* head = restored                                 ? "R-A RESTORED (the client vtable put back)"
                               : failed && restore                      ? "R-A RESTORE FAILED"
                               : failed                                 ? "R-A WRITE FAILED (nothing changed)"
                               : wrote                                  ? "R-A CUT presentation"
                               : verdict == gpr::RaVerdict::Would       ? "R-A WOULD CUT presentation"
                                                                        : "R-A NOT cut";
            const bool acts = wrote || verdict == gpr::RaVerdict::Would;
            return std::format(
                "GuestSeqPresent [{}] {} T{} | stage seq 0x{:X} '{}' resource 0x{:08X} owner 0x{:08X} (this client "
                "0x{:08X}) started +0x28B {} | processor [stage+0x58] {} vtable exe+0x{:X}{}{} | G {}, known X of the "
                "owner: {} | P1 thread {} (frame thread {}) | guest_seq_foreign_present={}: {}{}",
                head, when, e.tid, v[1], name_of(e), static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[2]),
                static_cast<uint32_t>(v[2] >> 32), (v[3] >> 32) & 0xFF, hex_or_none(v[5]), v[4],
                (v[6] & 1) ? " (the mod's table)" : v[4] == g_rl->vt_client ? " (client)" : "",
                v[8] ? std::format(" | [proc+0x10] 0x{:X} is NOT the stage", v[8]) : std::string(),
                (v[6] & 2) ? "= M" : "!= M", (v[6] & 4) ? "yes" : "no", static_cast<uint32_t>(v[7]), static_cast<uint32_t>(v[7] >> 32), gpr::ra_mode_name(mode),
                gpr::ra_verdict_name(verdict),
                acts ? std::format(" | {} -> {}", wrote ? "vptr now the mod's table" : "would point the vptr at the "
                                                                                      "mod's table",
                                   g_ra_cut_text)
                     : std::string());
        }
        case kERB: {
            const auto verdict = static_cast<gpr::RbVerdict>(v[0] & 0xFF);
            const auto ev = static_cast<Ev>((v[0] >> 8) & 0xFF);
            const auto mode = static_cast<gpr::RaMode>((v[0] >> 16) & 0xFF);
            const char* head = verdict == gpr::RbVerdict::Skip    ? "R-B SKIPPED"
                               : verdict == gpr::RbVerdict::Would ? "R-B WOULD SKIP"
                                                                  : "R-B NOT skipped";
            return std::format(
                "GuestSeqPresent [{}] {} T{} | {} start (slot 99), caller exe+0x{:X} | timeline id +0x1D8 {} playing "
                "+0xDC {} | stage seq {} '{}' owner 0x{:08X} (this client 0x{:08X}){}{}, known X of the owner: {} | "
                "ev+0x38 0x{:X} | thread {} (frame thread {}) | guest_seq_foreign_timeline={}: {}",
                head, when, e.tid, gpr::ev_info(ev).name, static_cast<uint32_t>(v[3]), static_cast<uint32_t>(v[2]),
                v[5] & 0xFF, hex_or_none(v[1]), name_of(e), static_cast<uint32_t>(v[2] >> 32),
                static_cast<uint32_t>(v[3] >> 32), ((v[0] >> 24) & 1) ? "" : " (GONE)",
                ((v[0] >> 26) & 1) ? ", G = M" : "", ((v[0] >> 25) & 1) ? "yes" : "no", v[4],
                static_cast<uint32_t>(v[7]), static_cast<uint32_t>(v[7] >> 32), gpr::ra_mode_name(mode),
                gpr::rb_verdict_name(verdict));
        }
        default: return "GuestSeqPresent [?]";
    }
}

std::string cost_text(const gpr::Cost& c) {
    const uint64_t n = c.n();
    if (!n) return "0 calls";
    return std::format("{} calls, avg {} ns, max {} ns, total {:.2f} ms", n, gpr::ticks_ns(c.total() / n, g_qpf),
                       gpr::ticks_ns(c.max(), g_qpf), static_cast<double>(gpr::ticks_ns(c.total(), g_qpf)) / 1e6);
}

std::string summary() {
    std::string sa;
    for (size_t w = 0; w < static_cast<size_t>(Whose::Count); ++w) {
        std::string row;
        for (size_t k = 0; k < static_cast<size_t>(gpr::ProcVt::Count); ++k) {
            if (const uint64_t n = g_sa[w][k].load()) {
                row += std::format(" {} x{};", gpr::proc_vt_name(static_cast<gpr::ProcVt>(k)), n);
            }
        }
        if (!row.empty()) sa += std::format(" [{}:{}]", gpr::whose_name(static_cast<Whose>(w)), row);
    }
    std::string a2;
    for (size_t f = 0; f < gxv::kFns; ++f) {
        const uint64_t bf = g_a2[f][0][1].load(), bo = g_a2[f][0][0].load(), af = g_a2[f][1][1].load(),
                       ao = g_a2[f][1][0].load();
        if (bf + bo + af + ao) {
            a2 += std::format(" {} before P1 {} (foreign {}) / after {} (foreign {});",
                              gxv::fn_info(static_cast<gxv::Fn>(f)).name, bf + bo, bf, af + ao, af);
        }
    }
    std::string ev;
    for (size_t i = 0; i < gpr::kEvs; ++i) {
        std::string row;
        for (size_t t = 0; t < static_cast<size_t>(Tl::Count); ++t) {
            if (const uint64_t n = g_ev[i][t].load()) row += std::format(" {} {};", gpr::tl_name(static_cast<Tl>(t)), n);
        }
        std::string callers;
        const auto& cc = g_ev_callers[i];
        for (size_t k = 0; k < cc.capacity(); ++k) {
            if (cc.rva(k)) callers += std::format(" exe+0x{:X} x{};", cc.rva(k), cc.n(k));
        }
        if (cc.other()) callers += std::format(" other x{};", cc.other());
        ev += std::format(" [{} {}: {}{}{} | callers{} | cost {}]", gpr::ev_info(static_cast<Ev>(i)).name,
                          g_ev_on[i].load() ? "hooked" : "NOT hooked", row.empty() ? " none" : row,
                          g_ev_vt_bad[i].load() ? std::format(" event vtable not the class's {};", g_ev_vt_bad[i].load())
                                                : std::string(),
                          g_ev_cut[i].load() ? std::format(" chain cut {};", g_ev_cut[i].load()) : std::string(),
                          callers.empty() ? " none" : callers, cost_text(g_ev_cost[i]));
    }
    std::string sd;
    const char* names[10] = {"world", "camera entry", "camera vtable", "timeline counts", "+0xDE8",
                             "M input block", "X input block", "foreign stage", "its timeline", "its +0xDC"};
    for (uint32_t b = 0; b < 10; ++b) {
        if (const uint64_t n = g_sd_changes[b].load()) sd += std::format(" {} {};", names[b], n);
    }
    return std::format(
        "GuestSeqPresent summary (guest_seq_foreign_present_probe=1, READ-ONLY) | S-A (P1 {}) calls {}, table noted {} "
        "(overwritten {}), no timeline id {}:{} | foreign: [proc+8] != G {}, [proc+0x10] != stage {}, G = M {} | S-A2 "
        "(guest_x_veto handler calls with G = X: {}, no stage {}):{} | S-B/S-C:{} | S-D {}: frames {}, changes:{} X not a "
        "stage manager {}, player list capped {}, timeline scans {} (on a new foreign stage or every {} frames) | cost {} "
        "| lines limited {}, ring lost {}, over budget {}",
        guest_seq_foreign_p1_hooked() ? "hooked" : "NOT hooked", g_sa_calls.load(), g_stages.noted(),
        g_stages.overwritten(), g_sa_no_tl.load(), sa.empty() ? " none" : sa, g_sa_mgr_diff.load(),
        g_sa_stage_diff.load(), g_sa_g_is_m.load(), g_a2_calls.load(), g_a2_no_stage.load(),
        a2.empty() ? " none (0 = its handlers are not hooked or no stage of X ran one)" : a2, ev,
        g_sd_on.load() ? "on" : "OFF", g_sd_frames.load(), sd.empty() ? " none;" : sd, g_sd_x_not_mgr.load(),
        g_sd_tl_capped.load(), g_sd_tl_scans.load(), gpr::kSdTlEvery,
        g_sd_frames.load() ? cost_text(g_sd_cost) : std::string("0 frames (guest_seq_play's 0x8B6144 hook not active)"),
        g_limited.load(), g_ring.dropped(), g_capped);
}

std::string ra_summary() {
    std::string vs;
    for (size_t k = 0; k < static_cast<size_t>(gpr::RaVerdict::Count); ++k) {
        if (const uint64_t n = g_ra_verdicts[k].load()) {
            vs += std::format(" {} x{};", gpr::ra_verdict_name(static_cast<gpr::RaVerdict>(k)), n);
        }
    }
    // S-A2 over guest_x_veto's interface / camera handlers, split by what R-A does with the handler's slot:
    // - CUT slots ('Ret'): calls for a FOREIGN stage before its P1 (R-A's gap) and after it (0 with 1: redundant vetoes);
    // - every one of those handlers' calls from X's NOT foreign stages (world stages: R-A never cuts them) and the
    //   kept-native ('Off') ones: review P2-1 wants to see which activations reach this client from where R-A does not
    //   cut, so an on / off pair is never split (the offs stay native by design).
    uint64_t before = 0, after = 0;
    std::string not_foreign, kept;
    for (size_t fn = 0; fn < gxv::kFns; ++fn) {
        const uint16_t off = gxv_slot(fn);
        if (!off) continue;
        const gpr::RaExpect* x = gpr::ra_expect(*g_rl, off);
        const gpr::RaUse use = x ? x->use : gpr::RaUse::Native;
        const uint64_t bf = g_a2[fn][0][1].load(), af = g_a2[fn][1][1].load();
        const uint64_t nf = g_a2[fn][0][0].load() + g_a2[fn][1][0].load();
        const char* name = gxv::fn_info(static_cast<gxv::Fn>(fn)).name;
        if (use == gpr::RaUse::Ret) {
            before += bf;
            after += af;
            if (nf) not_foreign += std::format(" {} x{};", name, nf);
        } else if (bf + af + nf) {
            kept += std::format(" {} (+0x{:X}) foreign before P1 {} / after {}, not foreign {};", name, off, bf, af, nf);
        }
    }
    const auto armed = static_cast<gpr::RaMode>(g_ra_mode.load());
    return std::format(
        "GuestSeqPresent R-A summary (guest_seq_foreign_present={}{}) | P1 {} calls {}:{} | vptr written {}, write "
        "failed {}, RESTORED {}, restore failed {} | guest_x_veto's handlers of CUT slots run for FOREIGN stages (S-A2{}): "
        "before their P1 {} (R-A's gap), after it {} | the same handlers from X's NOT foreign stages:{} | handlers of "
        "slots kept native (off / direction in data):{}",
        gpr::ra_mode_name(static_cast<gpr::RaMode>(g_ra_wanted.load())),
        armed == gpr::RaMode::Off ? ", NOT armed: see the install line" : "",
        guest_seq_foreign_p1_hooked() ? "hooked" : "NOT hooked", g_ra_p1.load(), vs.empty() ? " none" : vs,
        g_ra_written.load(), g_ra_write_failed.load(), g_ra_restored.load(), g_ra_restore_failed.load(),
        g_on.load() ? "" : "; needs guest_seq_foreign_present_probe=1: NOT measured", before, after,
        not_foreign.empty() ? " none" : not_foreign, kept.empty() ? " none" : kept);
}

std::string rb_summary() {
    std::string rows;
    const char* names[2] = {"CameraSelectorEventData", "SequencerPlayerCameraPreset"};
    for (size_t k = 0; k < 2; ++k) {
        std::string row;
        for (size_t x = 0; x < static_cast<size_t>(gpr::RbVerdict::Count); ++x) {
            if (const uint64_t n = g_rb[k][x].load()) {
                row += std::format(" {} x{};", gpr::rb_verdict_name(static_cast<gpr::RbVerdict>(x)), n);
            }
        }
        rows += std::format(" [{}:{}]", names[k], row.empty() ? " none" : row);
    }
    const uint64_t skipped = g_rb[0][static_cast<size_t>(gpr::RbVerdict::Skip)].load() +
                             g_rb[1][static_cast<size_t>(gpr::RbVerdict::Skip)].load();
    const uint64_t would = g_rb[0][static_cast<size_t>(gpr::RbVerdict::Would)].load() +
                           g_rb[1][static_cast<size_t>(gpr::RbVerdict::Would)].load();
    return std::format("GuestSeqPresent R-B summary (guest_seq_foreign_timeline={}{}) | SKIPPED {}, WOULD SKIP {} |{}{}",
                       gpr::ra_mode_name(static_cast<gpr::RaMode>(g_rb_wanted.load())),
                       g_rb_mode.load() ? "" : ", NOT armed: see the install line", skipped, would, rows,
                       g_rb_bad_tl_vt.load() ? std::format(" | last [ctx+8] whose vtable is not the timeline's: exe+0x{:X}",
                                                           g_rb_bad_tl_vt.load())
                                             : std::string());
}

// ---------------------------------------------------------------- install

bool bytes_at(uint32_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}
bool code_ok(std::span<const gad::Section> secs, std::span<const Bytes> code, std::string& why) {
    for (const Bytes& c : code) {
        if (!gad::in_real_code(secs, c.rva, static_cast<uint32_t>(c.bytes.size())) || !bytes_at(c.rva, c.bytes)) {
            why = std::format("the code at exe+0x{:X} ({} bytes) is not this build's", c.rva, c.bytes.size());
            return false;
        }
    }
    return true;
}
uint64_t q64(uint32_t rva) {
    uint64_t v = 0;
    return game::safe_read(g_base + rva, &v, sizeof v) ? v : 0;
}
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
    g_image_size.store(nt.OptionalHeader.SizeOfImage, std::memory_order_relaxed);  // before any hook (rva_of)
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
bool covered(const std::vector<RUNTIME_FUNCTION>& pdata, uint32_t begin, uint32_t end) {
    return std::any_of(pdata.begin(), pdata.end(),
                       [&](const RUNTIME_FUNCTION& r) { return r.BeginAddress < end && begin < r.EndAddress; });
}
// An event class: its vtable's COL and its slot 99 = the entry.
bool class_ok(Ev ev, std::string& why) {
    const gpr::EvInfo i = ev_of(ev);
    if (q64(i.vt - 8) != g_base + i.col) {
        why = std::format("the vtable exe+0x{:X}'s COL is not {}'s", i.vt, i.name);
        return false;
    }
    if (q64(i.vt + 8 * gpr::kStartSlot) != g_base + i.entry) {
        why = std::format("slot 99 of exe+0x{:X} is not exe+0x{:X}", i.vt, i.entry);
        return false;
    }
    return true;
}

// S-A: the three processor vtables (COL), and R-A's table computed from them (logged once, never applied).
void verify_sa(std::span<const gad::Section> secs) {
    std::string why;
    const bool cols = q64(gpr::kVtProcClient - 8) == g_base + gpr::kColProcClient &&
                      q64(gpr::kVtProcCommon - 8) == g_base + gpr::kColProcCommon &&
                      q64(gpr::kVtProcServer - 8) == g_base + gpr::kColProcServer;
    g_sa_vt.store(cols, std::memory_order_release);
    if (!code_ok(secs, kSaCode, why)) {
        log::warn("GuestSeqPresent: S-A / S-A2 / S-B's stage match NOT active: {} (stage+0x298 / T+0x1D8)", why);
        return;
    }
    g_on.store(true, std::memory_order_release);
    if (!cols) {
        log::warn("GuestSeqPresent: S-A: the processor vtables' COLs are not build 2976's: the processor is logged raw, "
                  "not classified; R-A's table not computed");
        return;
    }
    std::vector<uint32_t> c(gpr::kProcSlots), m(gpr::kProcSlots), s(gpr::kProcSlots);
    for (size_t k = 0; k < gpr::kProcSlots; ++k) {
        c[k] = rva_of(q64(gpr::kVtProcClient + static_cast<uint32_t>(8 * k)));
        m[k] = rva_of(q64(gpr::kVtProcCommon + static_cast<uint32_t>(8 * k)));
        s[k] = rva_of(q64(gpr::kVtProcServer + static_cast<uint32_t>(8 * k)));
    }
    const gpr::RaTable t = gpr::ra_table(c, m, s);
    auto list = [](const uint16_t* a, size_t n) {
        std::string r;
        for (size_t i = 0; i < n; ++i) r += std::format(" +0x{:X}", a[i]);
        return r.empty() ? std::string(" none") : r;
    };
    log::info("GuestSeqPresent R-A table (the raw classification COMPUTED from the three native vtables, for S-A; what "
              "guest_seq_foreign_present applies is its own 'R-A ... ARMED' line; slots "
              "+0x{:X}..+0x{:X}): client only (common and server = ret 0x359B50) {}:{} | client and server {}:{} | common "
              "differs {}:{} | client-only slots outside that range (the processor's own, NOT presentation): {}",
              gpr::kFnSlotLo, gpr::kFnSlotHi, t.n_client_only, list(t.client_only, t.n_client_only), t.n_client_server,
              list(t.client_server, t.n_client_server), t.n_common_differs,
              list(t.common_differs, t.n_common_differs), t.outside_client_only);
}

// R-A: verify everything its decisions rest on, build the table once (a page of its own, read-only once filled,
// never freed) and arm P1. Any failure: nothing armed (the key acts as 0) and a WRN says why.
void verify_ra(std::span<const gad::Section> secs, gpr::RaMode mode) {
    auto refuse = [&](const std::string& why) {
        log::warn("GuestSeqPresent: R-A (guest_seq_foreign_present={}) NOT armed, nothing will be written: {}",
                  gpr::ra_mode_name(mode), why);
    };
    const gpr::RaLayout& layout = *g_rl;
    if (q64(layout.vt_client - 8) != g_base + layout.col_client ||
        q64(layout.vt_common - 8) != g_base + layout.col_common ||
        q64(layout.vt_server - 8) != g_base + layout.col_server) {
        refuse("the three processor vtables' COLs are not this build's");
        return;
    }
    std::vector<uint32_t> c(layout.slots), m(layout.slots), s(layout.slots);
    std::vector<uint64_t> c_abs(layout.slots), m_abs(layout.slots);
    for (size_t k = 0; k < layout.slots; ++k) {
        c_abs[k] = q64(layout.vt_client + static_cast<uint32_t>(8 * k));
        m_abs[k] = q64(layout.vt_common + static_cast<uint32_t>(8 * k));
        c[k] = rva_of(c_abs[k]);
        m[k] = rva_of(m_abs[k]);
        s[k] = rva_of(q64(layout.vt_server + static_cast<uint32_t>(8 * k)));
        if (!c[k] || !m[k] || !s[k]) {
            refuse(std::format("slot +0x{:X} of a processor vtable is not a pointer into the exe", 8 * k));
            return;
        }
    }
    const gpr::RaPlan plan = gpr::ra_plan_for(layout, c, m, s);
    if (!plan.ok) {
        refuse(std::format("{} (slot +0x{:X})", plan.why, plan.bad_off));
        return;
    }
    // Each decided slot is reached by its StageChart_Function_* Execute through [[stage]+0x58]'s vptr at that offset.
    for (const gpr::RaExpect& x : layout.expect) {
        uint8_t tb[gpr::kTrampBytes];
        gpr::tramp_bytes(x.off, tb, layout.stage_proc);
        if (!gad::in_real_code(secs, x.tramp, gpr::kTrampBytes) || !bytes_at(x.tramp, tb)) {
            refuse(std::format("the trampoline exe+0x{:X} to slot +0x{:X} is not this build's", x.tramp, x.off));
            return;
        }
    }
    // The lifetime evidence (per stage, deleted through slot 0): the .rsrc thunks it goes through.
    const uint32_t deleting_dtor = g_3663   ? kRaDeletingDtor3663
                                   : g_3576 ? kRaDeletingDtor3576
                                   : g_3527 ? kRaDeletingDtor3527
                                            : kRaDeletingDtor;
    if (c[0] != deleting_dtor || plan.use[0] != gpr::RaUse::Native) {
        refuse("slot 0 (the deleting destructor) is not the expected one or not kept native");
        return;
    }
    const uint32_t base_dtor = g_3663 ? 0x227BB86u : g_3576 ? 0x220C925u : 0x220BCE5u;
    if (g_3527 &&
        !(gad::in_real_code(secs, base_dtor, sizeof kRaBaseDtor3527) && bytes_at(base_dtor, kRaBaseDtor3527))) {
        refuse(std::format("the stage's base destructor exe+0x{:X} is not this build's", base_dtor));
        return;
    }
    const std::span<const Jmp> lifetime = !g_3527            ? std::span<const Jmp>(kRaLifetime)
                                          : g_3663          ? std::span<const Jmp>(kRaLifetime3663)
                                          : g_3576          ? std::span<const Jmp>(kRaLifetime3576)
                                          : game::is_3549() ? std::span<const Jmp>(kRaLifetime3549)
                                                            : std::span<const Jmp>(kRaLifetime3527);
    for (const Jmp& j : lifetime) {
        const int64_t rel = static_cast<int64_t>(j.to) - static_cast<int64_t>(j.at) - 5;
        const uint8_t jb[5] = {0xE9, static_cast<uint8_t>(rel), static_cast<uint8_t>(rel >> 8),
                               static_cast<uint8_t>(rel >> 16), static_cast<uint8_t>(rel >> 24)};
        if (!gad::in_real_code(secs, j.at, 5) || !bytes_at(j.at, jb)) {
            refuse(std::format("the lifetime thunk exe+0x{:X} -> exe+0x{:X} is not this build's", j.at, j.to));
            return;
        }
    }
    // The table: its own page, filled, then read-only. Never freed once armed (it must outlive every processor pointed
    // at it); released on a refusal below (review P3-4), when nothing can point at it yet.
    const size_t bytes = (1 + layout.slots) * sizeof(uint64_t);
    auto* page = static_cast<uint64_t*>(VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!page) {
        refuse("VirtualAlloc failed");
        return;
    }
    const uint64_t col = q64(layout.vt_client - 8);
    if (!gpr::ra_build(plan, c_abs, m_abs, col, std::span<uint64_t>(page, 1 + layout.slots), layout.slots)) {
        refuse("the table could not be built");
        VirtualFree(page, 0, MEM_RELEASE);
        return;
    }
    DWORD old = 0;
    if (!VirtualProtect(page, bytes, PAGE_READONLY, &old)) {
        refuse("VirtualProtect (read-only) failed");
        VirtualFree(page, 0, MEM_RELEASE);
        return;
    }
    for (size_t k = 0; k < layout.slots; ++k) {
        const uint64_t want = gpr::ra_keeps_native(plan.use[k]) ? c_abs[k] : m_abs[k];
        if (page[1 + k] != want || page[0] != col) {
            refuse("the table reads back wrong");
            VirtualFree(page, 0, MEM_RELEASE);
            return;
        }
    }
    std::string ret, common, world, offs;
    for (size_t k = 0; k < layout.slots; ++k) {
        if (plan.use[k] == gpr::RaUse::Ret) ret += std::format(" +0x{:X}", 8 * k);
        if (plan.use[k] == gpr::RaUse::Common) common += std::format(" +0x{:X} (0x{:X})", 8 * k, m[k]);
        if (plan.use[k] == gpr::RaUse::World) world += std::format(" +0x{:X}", 8 * k);
        if (plan.use[k] == gpr::RaUse::Off) offs += std::format(" +0x{:X}", 8 * k);
    }
    g_ra_cut_text = std::format("{} slots that turn presentation ON to the common's ret 0x{:X}:{}; {} to the common's "
                                "own:{}; kept native as world effects:{}; kept native as they turn it OFF or carry the "
                                "direction in their data:{}",
                                plan.n_ret, layout.ret, ret, plan.n_common, common, world, offs);
    g_ra_page = page;
    g_ra_client_vt = g_base + layout.vt_client;
    g_ra_mod_vt = reinterpret_cast<uint64_t>(page + 1);
    g_ra_mode.store(static_cast<uint8_t>(mode), std::memory_order_release);
    log::info("GuestSeqPresent R-A guest_seq_foreign_present={} ARMED{} | the mod's table at 0x{:X} (its [-1] = the "
              "client's COL exe+0x{:X}; {} slots, read-only page, never freed): {}; the other {} copied from 0x{:X} "
              "| verified: base / PE timestamp, three COLs, the {} decisions, their {} trampolines, slot 0 and the {} "
              "lifetime thunks | per foreign stage, in P1: vptr == exe+0x{:X}, [proc+0x10] == the stage, [proc+8] == "
              "[stage+0x28], P1 on guest_seq_play's frame thread; {}",
              gpr::ra_mode_name(mode), mode == gpr::RaMode::Probe ? " (probe: nothing is ever written)" : "",
              g_ra_mod_vt, layout.col_client, layout.slots, g_ra_cut_text,
              layout.slots - plan.n_ret - plan.n_common, layout.vt_client, layout.expect.size(), layout.expect.size(),
              lifetime.size(), layout.vt_client,
              mode == gpr::RaMode::On ? "then ONE locked compare-exchange of that processor's vptr"
                                      : "then a '[R-A WOULD CUT presentation]' line");
}

// R-B: arm only when both camera starts are hooked and what the skip rests on is this build's: the dispatcher's two
// slot-99 call sites and its `mov al,1` return, the timeline's id field (+0x1D8: S-A's 0x34DC175 / 0x34DBB03), the
// timeline object's vtable (its first two slots), and both classes' slots 97 / 98 = the void `ret 0` 0x359B50.
void verify_rb(std::span<const gad::Section> secs, gpr::RaMode mode) {
    std::string why;
    auto refuse = [&](const std::string& w) {
        log::warn("GuestSeqPresent: R-B (guest_seq_foreign_timeline={}) NOT armed, nothing will be skipped: {}",
                  gpr::ra_mode_name(mode), w);
    };
    if (!g_ev_on[static_cast<size_t>(Ev::CameraSelector)].load() ||
        !g_ev_on[static_cast<size_t>(Ev::PlayerCameraPreset)].load()) {
        refuse("a camera start hook (0x34CFC20 / 0xB27880) is not installed (see its line)");
        return;
    }
    const std::span<const Bytes> rb_code = g_3663   ? std::span<const Bytes>(kRbCode3663)
                                           : g_3576 ? std::span<const Bytes>(kRbCode3576)
                                           : g_3527 ? std::span<const Bytes>(kRbCode3527)
                                                    : std::span<const Bytes>(kRbCode);
    const std::span<const Bytes> sa_code = g_3663   ? std::span<const Bytes>(kSaCode3663)
                                           : g_3576 ? std::span<const Bytes>(kSaCode3576)
                                           : g_3527 ? std::span<const Bytes>(kSaCode3527)
                                                    : std::span<const Bytes>(kSaCode);
    if (!code_ok(secs, rb_code, why) || !code_ok(secs, sa_code, why)) {
        refuse(why);
        return;
    }
    // The timeline object's vtable has no RTTI: its first two slots (3527: the constructor 0x1062DB50 writes it; 3663:
    // 0x10B1E270, gpr::kVtTimeline3663).
    const uint64_t tl_slot0 = g_3663 ? 0x3808590 : g_3576 ? 0x37912A0 : g_3527 ? 0x37905A0 : 0x34C0B60;
    const uint64_t tl_slot1 = g_3663 ? 0x3805130 : g_3576 ? 0x378DE40 : g_3527 ? 0x378D140 : 0x34BD680;
    if (q64(g_sl->vt_timeline) != g_base + tl_slot0 || q64(g_sl->vt_timeline + 8) != g_base + tl_slot1) {
        refuse(std::format("the timeline object's vtable exe+0x{:X} is not this build's", g_sl->vt_timeline));
        return;
    }
    for (const Ev ev : {Ev::CameraSelector, Ev::PlayerCameraPreset}) {
        const uint32_t vt = ev_of(ev).vt;
        if (q64(vt + 8 * 97) != g_base + g_rl->ret || q64(vt + 8 * 98) != g_base + g_rl->ret) {
            refuse(std::format("slots 97 / 98 of exe+0x{:X} are not the void ret 0x{:X}", vt, g_rl->ret));
            return;
        }
    }
    g_rb_mode.store(static_cast<uint8_t>(mode), std::memory_order_release);
    log::info("GuestSeqPresent R-B guest_seq_foreign_timeline={} ARMED{} | CameraSelectorEventData 0x34CFC20 and "
              "SequencerPlayerCameraPreset 0xB27880, slot 99 (the START) only, called back from 0x36574CD / 0x36575D6; "
              "the timeline [ctx+8] (vptr exe+0x5C75F30) -> id +0x1D8 -> the stage P1 noted: foreign, M known, G != M, "
              "G = guest_seq_play's X of the owner, frame thread | {} | slots 100, 101 (end) and 103 native; the "
              "other event classes untouched",
              gpr::ra_mode_name(mode), mode == gpr::RaMode::Probe ? " (probe: nothing is ever skipped)" : "",
              mode == gpr::RaMode::On ? "then the start returns at its entry ('[R-B SKIPPED]')"
                                      : "then a '[R-B WOULD SKIP]' line");
}

DWORD WINAPI install_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    for (int i = 0; i < 1200; ++i) {  // WorldSystem (up to 10 minutes), as the other guest modules
        uintptr_t world = 0;
        if (game::safe_read(g_base + g_world_slot, &world, sizeof world) && world) break;
        Sleep(500);
    }
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_qpf = static_cast<uint64_t>(f.QuadPart);
    std::vector<gad::Section> secs;
    std::vector<RUNTIME_FUNCTION> pdata;
    std::string why;
    const bool probe = g_probe_wanted.load();
    const auto ra = static_cast<gpr::RaMode>(g_ra_wanted.load());
    const auto rb = static_cast<gpr::RaMode>(g_rb_wanted.load());
    if (!read_pdata(pdata, why) || !p8_exe_sections(g_base, secs)) {
        log::warn("GuestSeqPresent: {}; nothing installed (guest_seq_foreign_present_probe, guest_seq_foreign_present "
                  "and guest_seq_foreign_timeline act as 0)",
                  why.empty() ? "the exe's sections are unreadable" : why);
        g_settled.store(true);
        return 0;
    }
    if (ra != gpr::RaMode::Off) verify_ra(secs, ra);
    if (probe) verify_sa(secs);
    // P1 is guest_seq_foreign's (its install thread, started first, waits for WorldSystem as this one did and then
    // verifies and installs). B4: wait until it SETTLED (bounded: 11 min, more than its own WorldSystem wait), so the
    // WRN below is only written when P1 really ended up not installed.
    int waited = 0;
    for (; waited < 1320 && !guest_seq_foreign_settled(); ++waited) Sleep(500);
    if (!guest_seq_foreign_settled()) {
        log::warn("GuestSeqPresent: guest_seq_foreign has not settled after {} s: P1 (0x602940) may still be installed "
                  "later (S-A / R-A start with it; the summary says 'P1 hooked' once it is)",
                  waited / 2);
    } else if (!guest_seq_foreign_p1_hooked()) {
        log::warn("GuestSeqPresent: guest_seq_foreign settled WITHOUT P1 (0x602940) (see its 'NOT installed' line): no "
                  "stage is noted, so R-A never acts, S-A has no line and S-A2 / S-B / S-C / S-D cannot tell whose "
                  "stage anything belongs to (all 'no stage')");
    }
    if (!probe && rb == gpr::RaMode::Off) {
        g_settled.store(true);
        return 0;
    }
    std::string on, refused;
    const std::span<const EvPoint> ev_points = !g_3527            ? std::span<const EvPoint>(kEvPoints)
                                               : g_3663          ? std::span<const EvPoint>(kEvPoints3663)
                                               : g_3576          ? std::span<const EvPoint>(kEvPoints3576)
                                               : game::is_3549() ? std::span<const EvPoint>(kEvPoints3549)
                                                                 : std::span<const EvPoint>(kEvPoints3527);
    for (const EvPoint& pt : ev_points) {
        const size_t i = static_cast<size_t>(pt.ev);
        const gpr::EvInfo info = ev_of(pt.ev);
        // Without the probe only R-B's two camera starts are hooked.
        if (!probe && pt.ev != Ev::CameraSelector && pt.ev != Ev::PlayerCameraPreset) continue;
        std::string w;
        if (!class_ok(pt.ev, w)) {
        } else if (pt.fn_begin && !has_function(pdata, pt.fn_begin, pt.fn_end)) {
            w = std::format(".pdata [0x{:X},0x{:X}) not found", pt.fn_begin, pt.fn_end);
        } else if (!pt.fn_begin && covered(pdata, info.entry, pt.hook + pt.patch)) {
            w = "a RUNTIME_FUNCTION covers what should be a leaf stub";
        } else if (!pt.head.empty() && !bytes_at(info.entry, pt.head)) {
            w = std::format("the entry exe+0x{:X} is not this build's", info.entry);
        } else if (!gad::in_real_code(secs, pt.hook, static_cast<uint32_t>(pt.sig.size())) || !bytes_at(pt.hook, pt.sig)) {
            w = std::format("its {}-byte signature is not this build's", pt.sig.size());
        } else if (!p8_install_mid(g_base, secs, pt.hook, pt.patch, pt.sig, kEvFns[i], g_ev_hooks[i], "GuestSeqPresent",
                                   info.name)) {
            w = "p8_install_mid refused it (see the line above)";
        }
        g_ev_on[i].store(w.empty(), std::memory_order_release);
        const std::string what = std::format("{} exe+0x{:X} ({} B{})", info.name, pt.hook, pt.patch,
                                             pt.fn_begin ? ", entry with .pdata" : pt.head.empty() ? ", leaf stub entry" :
                                                                                   ", inside a leaf, after its RIP load");
        if (w.empty()) {
            on += " " + what + ";";
        } else {
            refused += std::format(" {} ({});", what, w);
            log::warn("GuestSeqPresent: {} {} NOT installed: {}", pt.ev == Ev::StartLoading ? "S-C" : "S-B", what, w);
        }
    }
    if (rb != gpr::RaMode::Off) verify_rb(secs, rb);
    if (!probe) {
        g_settled.store(true);
        return 0;
    }
    if (code_ok(secs, kSdCode, why)) {
        g_sd_on.store(true, std::memory_order_release);
    } else {
        log::warn("GuestSeqPresent: S-D NOT active: {}", why);
    }
    log::info("GuestSeqPresent guest_seq_foreign_present_probe=1 (READ-ONLY, nothing written) | S-A in P1: {} (processor "
              "vtables {}) | S-A2 in guest_x_veto's handlers (G = X): {} | S-B/S-C hooked:{} | refused:{} | S-D in "
              "guest_seq_play's frame hook 0x8B6144: {} | guest_seq_route={}{} | lines for FOREIGN stages / their events "
              "(others sampled), summary every 60 s",
              g_on.load() ? "on" : "OFF", g_sa_vt.load() ? "verified" : "NOT verified", g_on.load() ? "on" : "OFF",
              on.empty() ? " none" : on, refused.empty() ? " none" : refused,
              g_sd_on.load() ? "on (only while guest_seq_play runs)" : "OFF", g_route_mode.empty() ? "0" : g_route_mode,
              g_route_mode == "1" ? "" : " (not 1: no scene of another player reaches X; every probe will be quiet)");
    g_settled.store(true);
    return 0;
}

}  // namespace

bool guest_seq_present_needs_p1(bool probe, const std::string& ra, const std::string& rb) {
    return probe || gpr::parse_ra_mode(ra) != gpr::RaMode::Off || gpr::parse_ra_mode(rb) != gpr::RaMode::Off;
}

void guest_seq_present_start(bool probe, const std::string& ra, const std::string& rb, const std::string& route_mode) {
    g_3576 = game::current_build() == game::Build::v3576;
    g_3663 = game::current_build() == game::Build::v3663;
    g_3527 = game::current_build() == game::Build::v3527 || g_3576 || g_3663;
    if (g_3527) {
        g_sl = g_3663 ? &gpr::kStageLayout3663 : g_3576 ? &gpr::kStageLayout3576 : &gpr::kStageLayout3527;
        g_rl = g_3663 ? &gpr::kRaLayout3663 : g_3576 ? &gpr::kRaLayout3576 : &gpr::kRaLayout3527;
        if (const auto* profile = game::reader_profile()) g_world_slot = profile->world_system;
        if (g_3576) g_world_slot = 0x71C0100;  // core_globals_3576.json (no reader profile for 3576 yet)
        // Build 1.0.0.3663 (static, 2026-11-13; never run): WorldSystem, profile_s2.h's rva3663().
        if (g_3663) g_world_slot = 0x72451C0;
        if (probe) {
            log::warn("GuestSeqPresent: guest_seq_foreign_present_probe (S-A, S-B, S-C, S-D) is not ported to build 3527: "
                      "REFUSED; R-A and R-B do not need it, and their own 'probe' value still works");
            probe = false;
        }
    }
    bool bad = false;
    const gpr::RaMode mode = gpr::parse_ra_mode(ra, &bad);
    if (bad) log::warn("GuestSeqPresent: guest_seq_foreign_present={} is not 0, probe or 1: 0", ra);
    const gpr::RaMode rb_mode = gpr::parse_ra_mode(rb, &bad);
    if (bad) log::warn("GuestSeqPresent: guest_seq_foreign_timeline={} is not 0, probe or 1: 0", rb);
    if (!probe && mode == gpr::RaMode::Off && rb_mode == gpr::RaMode::Off) return;
    static std::atomic<bool> started{false};
    if (started.exchange(true)) return;
    g_route_mode = route_mode;
    g_probe_wanted.store(probe);
    g_ra_wanted.store(static_cast<uint8_t>(mode));
    g_rb_wanted.store(static_cast<uint8_t>(rb_mode));
    g_wanted.store(true);
    CloseHandle(CreateThread(nullptr, 0, install_thread, nullptr, 0, nullptr));
}

bool guest_seq_present_wanted() { return g_wanted.load(); }

bool guest_seq_present_set_muted(uint64_t seq, bool muted) noexcept {
    if (!g_ra_client_vt || !g_ra_mod_vt || !g_sl || !seq) return false;
    gpr::StageRec r;
    if (!g_stages.find_seq(seq, r) || !r.stage || rdv<uint64_t>(r.stage + gpr::kStage_Seq) != seq) return false;
    const uintptr_t proc = rdp(r.stage + g_sl->proc);
    if (!proc) return false;
    const uint64_t want = muted ? g_ra_mod_vt : g_ra_client_vt, from = muted ? g_ra_client_vt : g_ra_mod_vt;
    if (rdv<uint64_t>(proc) == want) return true;
    return cas_vptr(proc, from, want) && rdv<uint64_t>(proc) == want;
}

bool guest_seq_present_stage_ready(uint64_t seq) noexcept {
    if (!g_sl || !seq) return false;
    gpr::StageRec r;
    if (!g_stages.find_seq(seq, r) || !r.stage || rdv<uint64_t>(r.stage + gpr::kStage_Seq) != seq) return false;
    const uintptr_t proc = rdp(r.stage + g_sl->proc);
    const uintptr_t charts = proc ? rdp(proc + 0x38) : 0;
    return charts && rdp(charts + 8);
}

uint32_t guest_seq_present_stage_nodes_at(uintptr_t stage) noexcept {
    if (!g_sl || stage < 0x10000) return 0;
    const uintptr_t proc = rdp(stage + g_sl->proc);
    const uintptr_t charts = proc ? rdp(proc + 0x38) : 0;
    if (!charts || !rdp(charts + 8)) return 0;
    const uint32_t n = rdv<uint32_t>(charts + 0x10);
    return n <= 4096 ? n : 0;
}

bool guest_seq_present_funcnpc_nodes(uint64_t seq, uint32_t* nodes) noexcept {
    if (nodes) *nodes = 0;
    if (!g_sl || !seq) return false;
    gpr::StageRec r;
    if (!g_stages.find_seq(seq, r) || !r.stage || rdv<uint64_t>(r.stage + gpr::kStage_Seq) != seq) return false;
    const uintptr_t info = rdp(r.stage + g_sl->info);
    const uintptr_t name = info ? rdp(info + g_sl->name) : 0;
    static constexpr char kPrefix[] = "cd_seq_funcnpc_";  // 15 characters
    uint64_t head[2] = {};
    if (!name || !rd(name, head[0]) || !rd(name + 8, head[1]) || std::memcmp(head, kPrefix, sizeof kPrefix - 1) != 0) {
        return false;
    }
    if (nodes) *nodes = guest_seq_present_stage_nodes_at(r.stage);
    return true;
}

uint32_t guest_seq_present_stage_nodes(uint64_t seq) noexcept {
    if (!g_sl || !seq) return 0;
    gpr::StageRec r;
    if (!g_stages.find_seq(seq, r) || !r.stage || rdv<uint64_t>(r.stage + gpr::kStage_Seq) != seq) return 0;
    return guest_seq_present_stage_nodes_at(r.stage);
}

bool guest_seq_present_stage_node_ready(uint64_t seq, uint32_t node) noexcept {
    if (!guest_seq_present_stage_ready(seq) || node > 64) return false;
    gpr::StageRec r;
    if (!g_stages.find_seq(seq, r) || !r.stage) return false;
    const uintptr_t proc = rdp(r.stage + g_sl->proc);
    const uintptr_t charts = proc ? rdp(proc + 0x38) : 0;
    const uintptr_t table = charts ? rdp(charts + 8) : 0;
    // The table is a vector: +0x10 its count, +0x14 its capacity (7 / 7 for the shops, 3 / 3 for Vellua's Farm Owner
    // selling from his table, 2026-11-12). Past the count is another object's memory: the 7-nov crash read it.
    if (!table || node >= rdv<uint32_t>(charts + 0x10)) return false;
    const uintptr_t entry = rdp(table + 8ull * node);
    uint64_t head[2] = {};
    return entry && rd(entry, head[0]) && rd(entry + 8, head[1]);
}

void guest_seq_present_tick() noexcept {
    if (!g_wanted.load(std::memory_order_relaxed)) return;
    try {
        ++g_ticks;
        p::Event e;
        while (g_ring.pop(e)) {
            if (e.kind >= kKindCount) continue;
            if (e.kind == kERA && ((e.v[0] >> 9) & 3)) {
                log::warn("{}", line_of(e));  // a failed write / restore or a RESTORED stage: always, beyond the budget
            } else if (g_lines < kMaxLines) {
                ++g_lines;
                log::info("{}", line_of(e));
            } else {
                ++g_capped;
            }
        }
        if (g_ticks % 12 == 0 && g_settled.load()) {
            if (g_probe_wanted.load(std::memory_order_relaxed)) log::info("{}", summary());
            if (g_ra_wanted.load(std::memory_order_relaxed)) log::info("{}", ra_summary());
            if (g_rb_wanted.load(std::memory_order_relaxed)) log::info("{}", rb_summary());
        }
    } catch (...) {
    }
}

}  // namespace cdmp::session2
