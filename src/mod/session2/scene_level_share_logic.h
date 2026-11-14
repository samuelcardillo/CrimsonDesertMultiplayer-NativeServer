#pragma once
// S43 (docs/research/s25/s43-puertas-y-r42.md): [session2] scene_level_share = 0 | probe | 1, HOST only. The pure
// logic of scene_level_share.cpp, with no game access, so the tests can run it.
//
// The server's SceneLevel registry is per field ([ServerField+0x80]) and keyed by the level's NAME:
//   A  only 0x2830400 marks an entry ready (+0x40), and only when the loader is the field's owner (the owner gate
//      0x283044D `cmp [r8+0x180],eax`). It runs right after the FIRST registration (2598 / Resync 2104). When the
//      guest registers a level first, the entry stays not ready and the host's later 2598 is dropped ("already
//      registered"): every door (2928 -> 0x282DC80) of that level answers 0x6CF701C for both players.
//   B  the delete 0x2829E60(mgr, &name, &type, ...) has no reference count and no user: the 2834 of either client,
//      0x2836110 (the owner's own load with DL != 0) and the field loader remove a level the other player still uses.
// A: inside 0x2830400 at the owner gate, user 2's own 2598 / 2104 (its Troc, its main character, the host's field)
//    gets eax := [field+0x180] (mode 1; probe only says it would). B: the entry of 0x2829E60; per user (host, user 2)
//    the type-0 SceneLevel hashes its client has loaded, from the C->S traffic the server already sees; a 2834 delete
//    of a level ANOTHER user still has loaded is skipped (mode 1), only when the name's hash is proven equal to the
//    packet's in this process.
//
// Builds 1.0.0.2976 (PE 0x6AB28F00), 1.0.0.3527 (PE 0x6AEA07A6), 1.0.0.3576 (PE 0x6AED2E85) and 1.0.0.3663 (PE
// 0x6AF5D198), base 0x140000000. The addresses named in the comments are 2976's unless they say otherwise; 3527's,
// 3576's and 3663's tables are in their sections.

#include "mod/session2/guest_sched_load_logic.h"  // gsl::hashlittle, kNameHashInit, base_without_ext

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace cdmp::session2::sls {

// ---------------------------------------------------------------- the key

enum class Mode : uint8_t { Off, Probe, On };
struct ParsedMode {
    Mode mode = Mode::Off;
    bool known = true;  // false: not 0 / probe / 1 (it stays off, with a warning)
};
inline ParsedMode parse_mode(std::string_view v) {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r')) v.remove_suffix(1);
    if (v.empty() || v == "0") return {Mode::Off, true};
    if (v == "probe") return {Mode::Probe, true};
    if (v == "1") return {Mode::On, true};
    return {Mode::Off, false};
}
inline const char* mode_name(Mode m) {
    switch (m) {
        case Mode::Off: return "0";
        case Mode::Probe: return "probe";
        case Mode::On: return "1";
    }
    return "?";
}

// ---------------------------------------------------------------- build 2976

inline constexpr uint32_t kPeTimestamp = 0x6AB28F00;
inline constexpr uintptr_t kImageBase = 0x140000000;
inline constexpr uint32_t kVtServerField = 0x5B29A60;  // pa::ServerField (as user2_stages_logic.h)
inline constexpr uintptr_t kMgrField = 0x210;          // registry -> its ServerField
inline constexpr uintptr_t kFieldOwner = 0x180;        // ServerField -> the owner's user key
inline constexpr uintptr_t kActorKey = 0x60;           // actor -> its key
// The resource of the S42 door (door_trace_logic.h): its packets get a line each (the others are counted).
inline constexpr uint32_t kWatchedHash = 0xDE7B52AA;

// A: the owner gate inside 0x2830400 (.pdata [0x2830400, 0x28308D7)). 0x2830432..0x283045A (40 bytes, once in the
// exe): mov rax,[rdx+0xA0] ; test ; jz ; mov eax,[rax+0x60] ; test ; jz ; cmp [r8+0x180],eax ; jnz. The mid hook
// takes the 7-byte cmp (no RIP-relative operand; no branch of the function lands inside it). Context there:
// r13 = rcx = the registry (mgr), rdx = the actor, r8 = [mgr+0x210] = the field, eax = [[actor+0xA0]+0x60] (its user
// key), rdi = r9 = &name (the string object's holder).
inline constexpr uint32_t kGateFnBegin = 0x2830400, kGateFnEnd = 0x28308D7;
inline constexpr uint32_t kGateRva = 0x283044D, kGatePatch = 7;
inline constexpr uint32_t kGateSigRva = 0x2830432;
inline constexpr std::array<uint8_t, 40> kGateSig{
    0x48, 0x8B, 0x82, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x7A, 0x04, 0x00, 0x00, 0x8B, 0x40, 0x60, 0x85,
    0xC0, 0x0F, 0x84, 0x6F, 0x04, 0x00, 0x00, 0x41, 0x39, 0x80, 0x80, 0x01, 0x00, 0x00, 0x0F, 0x85, 0x62, 0x04, 0x00, 0x00};
inline constexpr size_t kGateSigPatchAt = kGateRva - kGateSigRva;  // 27: the cmp inside the signature

// B: the delete 0x2829E60(mgr, &name, &type, char, u8, u8, u8) -> void (.pdata [0x2829E60, 0x282A9CA)). Its first
// instruction `mov [rsp+0x20],r9b` is exactly 5 bytes (the inline hook's jump).
inline constexpr uint32_t kDeleteRva = 0x2829E60, kDeleteEnd = 0x282A9CA, kDeletePatch = 5;
inline constexpr std::array<uint8_t, 16> kDeleteHead{0x44, 0x88, 0x4C, 0x24, 0x20, 0x4C, 0x89, 0x44,
                                                     0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55};
inline bool delete_patch_ok(std::span<const uint8_t> relocated) {
    return relocated.size() == kDeletePatch && std::memcmp(relocated.data(), kDeleteHead.data(), kDeletePatch) == 0;
}

// The direct callers of 0x2829E60 (E8 rel32 in .rsrc; the returns are what the hook sees).
inline constexpr uint32_t kRet2834 = 0x29C3049;       // 0x29C3044: SceneLevelUnloadReq 2834's handler 0x29C2D50
inline constexpr uint32_t kRetOwnerLoad = 0x28363D4;  // 0x28363CF: 0x2836110 (every ready entry; owner load, DL != 0)
inline constexpr uint32_t kRetLoader = 0x2876460;     // 0x287645B: 0x2876420, the field loader's unload event
// 0x2877145 (type 1), 0x281CADC (type 3), 0x2A9E728 (type 2): never changed.

// The 2834 handler's frame at its call (0x29C2D50: 7 pushes, lea rbp,[rsp-0x60], sub rsp,0x170, so rbp = C + 0x110
// with C the rsp at the call = the hook's address of the return address + 8). Its arguments and the packet's hash:
//   0x29C2FF7 mov r8d,[rbp-0x38]   the packet's u32 hash (C + 0xD8), kept in the frame (only read up to the call)
//   0x29C3036 mov r9b,1 ; lea r8,[rbp-0x78] (C + 0x98 = &type) ; lea rdx,[rbp+0x30] (C + 0x140 = &name) ; call
inline constexpr uint32_t kFrameSiteRva = 0x29C2D60;
inline constexpr std::array<uint8_t, 12> kFrameSite{0x48, 0x8D, 0x6C, 0x24, 0xA0, 0x48, 0x81, 0xEC, 0x70, 0x01, 0x00, 0x00};
inline constexpr uint32_t kCallSiteRva = 0x29C2FF7;
inline constexpr std::array<uint8_t, 82> kCallSite{
    0x44, 0x8B, 0x45, 0xC8, 0x48, 0x8D, 0x55, 0x28, 0x48, 0x8B, 0x8B, 0x10, 0x02, 0x00, 0x00, 0xE8, 0xA5, 0x2E, 0x72, 0xFF,
    0x90, 0x83, 0x7D, 0x28, 0x00, 0x74, 0x3A, 0x48, 0x8B, 0x45, 0x30, 0x48, 0x8B, 0x10, 0x48, 0x85, 0xD2, 0x74, 0x2E, 0x80,
    0x3A, 0x00, 0x74, 0x29, 0x44, 0x88, 0x75, 0x88, 0x40, 0x88, 0x74, 0x24, 0x30, 0xC6, 0x44, 0x24, 0x28, 0x00, 0xC6, 0x44,
    0x24, 0x20, 0x00, 0x41, 0xB1, 0x01, 0x4C, 0x8D, 0x45, 0x88, 0x48, 0x8D, 0x55, 0x30, 0x48, 0x8B, 0xCB, 0xE8, 0x17, 0x6E,
    0xE6, 0xFF};
inline constexpr uintptr_t kFrameName = 0x140, kFrameType = 0x98, kFrameHash = 0xD8;
// The frame is the 2834 handler's exactly when the call's own arguments sit where its code puts them.
inline bool frame_matches(uintptr_t frame, uintptr_t name_arg, uintptr_t type_arg) {
    return frame && name_arg == frame + kFrameName && type_arg == frame + kFrameType;
}

// The registry's type-0 map ([V] 0x2836110's walk, 0x2836186..0x283631F): mgr+0x80 the map; +0x84 its count; +0x8C its
// stamp (0x2829E60 bumps it before an erase; the walk stops when it changes); +0x98 the array of node pointers. A node:
// +0x10 its key (the name's string object), +0x18 / +0x20 its UUIDs, +0x40 the ready byte.
inline constexpr uintptr_t kMapCount = 0x84, kMapStamp = 0x8C, kMapNodes = 0x98;
inline constexpr uintptr_t kNodeKey = 0x10, kNodeReady = 0x40;
inline constexpr uint32_t kMapMaxWalk = 4096;

// The string object behind &name (both functions): [holder] = S; [S] = char*; [S+8] u32 length (-1: not counted
// yet); [S+0xC] u32 cdmp_HashLittle of the name (-1: not computed yet).
inline constexpr uintptr_t kStrLen = 8, kStrHash = 0xC;
inline constexpr size_t kNameMax = 255;

// ---------------------------------------------------------------- build 1.0.0.3527 [V capstone on the installed PE]

// PE 0x6AEA07A6. pa::ServerField's vtable from RTTI (rtti_3527.json). Every offset in the sections above is the same:
// the gate reads [rcx+0x210], [rdx+0xA0], [rax+0x60], [r8+0x180]; the 3527 walk is below.
inline constexpr uint32_t kPeTimestamp3527 = 0x6AEA07A6;
inline constexpr uint32_t kVtServerField3527 = 0x5EF0908;
// A: 0x2A77180 (.pdata [0x2A77180, 0x2A7765D)), same registers (0x2A771A5 mov rdi,r9; 0x2A771A8 mov r13,rcx; 0x2A771AB
// mov r8,[rcx+0x210]). Its ready write: 0x2A77301 mov byte [rax+0x30],1 with rax = node+0x10. Callers: 0x2A7D2C9 (Resync,
// handler 0x2C413C0 -> 0x2A7D0E0) and 0xE31EFEA (2598, handler 0x2C41B10 -> 0x2A74890 jmp 0xE31EE80, only after the name
// is not yet registered). The signature is once in the exe; no branch of the function lands in 0x2A771CE..0x2A771D3.
inline constexpr uint32_t kGateFnBegin3527 = 0x2A77180, kGateFnEnd3527 = 0x2A7765D;
inline constexpr uint32_t kGateRva3527 = 0x2A771CD;
inline constexpr uint32_t kGateSigRva3527 = 0x2A771B2;
inline constexpr std::array<uint8_t, 40> kGateSig3527{
    0x48, 0x8B, 0x82, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x80, 0x04, 0x00, 0x00, 0x8B, 0x40, 0x60, 0x85,
    0xC0, 0x0F, 0x84, 0x75, 0x04, 0x00, 0x00, 0x41, 0x39, 0x80, 0x80, 0x01, 0x00, 0x00, 0x0F, 0x85, 0x68, 0x04, 0x00, 0x00};
static_assert(kGateRva3527 - kGateSigRva3527 == kGateSigPatchAt);
// B: 0x2A70A10 (.pdata [0x2A70A10, 0x2A715C2)), the same 16-byte head (kDeleteHead). Direct callers that matter:
//   0x2C4355A in the 2834 handler 0x2C43250 (vtable 0x5EEBAD8 slot 2); after it `nop ; jmp` and it frees the name itself;
//   0x2A7D06F in 0x2A7CE10 (2976's 0x2836110: walks +0x84 / +0x98, stamp +0x8C, node +0x40 / +0x10, then clears +0x238 and
//   +0x258, the owner's load, DL != 0); 0x2AD113B in 0x2AD1100 (2976's 0x2876420, the field loader's unload event).
// The rest (0x2A61224, 0x2AD1E84, 0x2D2F893, 0xE301157) are other callers: never changed.
inline constexpr uint32_t kDeleteRva3527 = 0x2A70A10, kDeleteEnd3527 = 0x2A715C2;
inline constexpr uint32_t kRet28343527 = 0x2C4355F, kRetOwnerLoad3527 = 0x2A7D074, kRetLoader3527 = 0x2AD1140;
// The 2834 handler's frame at its call (0x2C43250: 7 pushes, lea rbp,[rsp-0x70], sub rsp,0x180, again rbp = C + 0x110):
//   0x2C4350D mov r8d,[rbp-0x28]   the packet's u32 hash (C + 0xE8), parsed at 0x2C4337C, only read up to the call
//   0x2C4354C mov r9b,1 ; lea r8,[rbp-0x78] (C + 0x98 = &type) ; lea rdx,[rbp+0x40] (C + 0x150 = &name) ; call
inline constexpr uint32_t kFrameSiteRva3527 = 0x2C43260;
inline constexpr std::array<uint8_t, 12> kFrameSite3527{0x48, 0x8D, 0x6C, 0x24, 0x90, 0x48, 0x81, 0xEC, 0x80, 0x01, 0x00, 0x00};
inline constexpr uint32_t kCallSiteRva3527 = 0x2C4350D;
inline constexpr std::array<uint8_t, 82> kCallSite3527{
    0x44, 0x8B, 0x45, 0xD8, 0x48, 0x8D, 0x55, 0x38, 0x48, 0x8B, 0x8B, 0x10, 0x02, 0x00, 0x00, 0xE8, 0x4F, 0x63, 0x66, 0xFF,
    0x90, 0x83, 0x7D, 0x38, 0x00, 0x74, 0x3A, 0x48, 0x8B, 0x45, 0x40, 0x48, 0x8B, 0x10, 0x48, 0x85, 0xD2, 0x74, 0x2E, 0x80,
    0x3A, 0x00, 0x74, 0x29, 0x44, 0x88, 0x75, 0x88, 0x40, 0x88, 0x74, 0x24, 0x30, 0xC6, 0x44, 0x24, 0x28, 0x00, 0xC6, 0x44,
    0x24, 0x20, 0x00, 0x41, 0xB1, 0x01, 0x4C, 0x8D, 0x45, 0x88, 0x48, 0x8D, 0x55, 0x40, 0x48, 0x8B, 0xCB, 0xE8, 0xB1, 0xD4,
    0xE2, 0xFF};
inline constexpr uintptr_t kFrameName3527 = 0x150, kFrameType3527 = 0x98, kFrameHash3527 = 0xE8;

// ---------------------------------------------------------------- build 1.0.0.3576 (static, 2026-11-06; not yet run)

// PE 0x6AED2E85. pa::ServerField 0x5EF0908 -> 0x5EF2B10 (vtable_map_3549_3576.json). The functions moved whole:
// A's 0x2A77180 -> 0x2A77DD0 (+0xC50, .pdata size 0x4DD; the 40-byte signature is at 0x2A77E02, once in the exe, the 3527
// bytes); B's 0x2A70A10 -> 0x2A71660 (+0xC50, size 0xBB2, the same head). Its callers' return addresses: the 2834 handler
// 0x2C43250 -> 0x2C43EC0 (+0xC70) returns at 0x2C441CF; 0x2A7CE10 -> 0x2A7DA60 (+0xC50, still walks +0x84 / +0x98 /
// +0x8C and clears +0x238 / +0x258) at 0x2A7DCC4; 0x2AD1100 -> 0x2AD1D50 (+0xC50) at 0x2AD1D90. Each is the return of a
// call to 0x2A71660. The 2834 frame site has the 3527 bytes at 0x2C43ED0; its call site 0x2C4417D differs only in two
// rel32s (0x22A9870 -> 0x22AA4B0, +0xC40; the delete 0x2A70A10 -> 0x2A71660). Frame offsets unchanged.
inline constexpr uint32_t kPeTimestamp3576 = 0x6AED2E85;
inline constexpr uint32_t kVtServerField3576 = 0x5EF2B10;
inline constexpr uint32_t kGateFnBegin3576 = 0x2A77DD0, kGateFnEnd3576 = 0x2A782AD;
inline constexpr uint32_t kGateRva3576 = 0x2A77E1D;
inline constexpr uint32_t kGateSigRva3576 = 0x2A77E02;
static_assert(kGateRva3576 - kGateSigRva3576 == kGateSigPatchAt);
inline constexpr uint32_t kDeleteRva3576 = 0x2A71660, kDeleteEnd3576 = 0x2A72212;
inline constexpr uint32_t kRet28343576 = 0x2C441CF, kRetOwnerLoad3576 = 0x2A7DCC4, kRetLoader3576 = 0x2AD1D90;
inline constexpr uint32_t kFrameSiteRva3576 = 0x2C43ED0;
inline constexpr uint32_t kCallSiteRva3576 = 0x2C4417D;
inline constexpr std::array<uint8_t, 82> kCallSite3576{
    0x44, 0x8B, 0x45, 0xD8, 0x48, 0x8D, 0x55, 0x38, 0x48, 0x8B, 0x8B, 0x10, 0x02, 0x00, 0x00, 0xE8, 0x1F, 0x63, 0x66, 0xFF,
    0x90, 0x83, 0x7D, 0x38, 0x00, 0x74, 0x3A, 0x48, 0x8B, 0x45, 0x40, 0x48, 0x8B, 0x10, 0x48, 0x85, 0xD2, 0x74, 0x2E, 0x80,
    0x3A, 0x00, 0x74, 0x29, 0x44, 0x88, 0x75, 0x88, 0x40, 0x88, 0x74, 0x24, 0x30, 0xC6, 0x44, 0x24, 0x28, 0x00, 0xC6, 0x44,
    0x24, 0x20, 0x00, 0x41, 0xB1, 0x01, 0x4C, 0x8D, 0x45, 0x88, 0x48, 0x8D, 0x55, 0x40, 0x48, 0x8B, 0xCB, 0xE8, 0x91, 0xD4,
    0xE2, 0xFF};

// ---------------------------------------------------------------- build 1.0.0.3663 (static, 2026-11-13; never run)

// PE 0x6AF5D198. pa::ServerField 0x5EF2B10 -> 0x5F6C7E8 (vtable_map_3576_3663.json). A: 0x2A77180 -> 0x2ADBE00
// (+0x64C80, .pdata size 0x4DD as on 3576); the 40-byte signature is at 0x2ADBE32, once in the code section, with the
// 3527 bytes; the same registers (0x2ADBE25 mov rdi,r9; 0x2ADBE28 mov r13,rcx; 0x2ADBE2B mov r8,[rcx+0x210]), its ready
// write at 0x2ADBF81, and no rel32 or in-function branch lands in 0x2ADBE4E..0x2ADBE53. B: 0x2A70A10 -> 0x2AD51C0
// (+0x647B0, the same 16-byte head; .pdata size 0xB73, 0x3F less than on 3576); it has the same seven rel32 callers as on
// 3527, at the same offsets in their functions: the 2834 handler 0x2CA9D40 (+0x30A) returns at 0x2CAA04F, 0x2AE1AB0
// (+0x25F; it still walks +0x84 / +0x98 / +0x8C, node +0x40 / +0x10, and clears +0x238 / +0x258) at 0x2AE1D14,
// 0x2B36200 (+0x3B) at 0x2B36240; the others (0x2AC5934, 0x2B36F84, 0x2D96F13, 0xE8535F7) are never changed.
// The 2834 handler's frame changed: `lea rbp,[rsp-0x60] ; sub rsp,0x170` (7 pushes: still rbp = C + 0x110; 2976's
// kFrameSite bytes) and the lookup's result moved: &name = [rbp+0x28] = C + 0x138 (3527 C + 0x150), its status at
// [rbp+0x48]; &type = [rbp-0x78] = C + 0x98 and the hash [rbp-0x28] = C + 0xE8 unchanged. The call site (82 bytes from
// 0x2CA9FFD) has the 3527 instructions with those displacements and two new rel32 (0x231AA90; the delete 0x2AD51C0).
// The string object's +8 length is the shared string's (interaction_condition.cpp); its +0xC hash is 3527's, not
// re-derived.
inline constexpr uint32_t kPeTimestamp3663 = 0x6AF5D198;
inline constexpr uint32_t kVtServerField3663 = 0x5F6C7E8;
inline constexpr uint32_t kGateFnBegin3663 = 0x2ADBE00, kGateFnEnd3663 = 0x2ADC2DD;
inline constexpr uint32_t kGateRva3663 = 0x2ADBE4D;
inline constexpr uint32_t kGateSigRva3663 = 0x2ADBE32;
static_assert(kGateRva3663 - kGateSigRva3663 == kGateSigPatchAt);
inline constexpr uint32_t kDeleteRva3663 = 0x2AD51C0, kDeleteEnd3663 = 0x2AD5D33;
inline constexpr uint32_t kRet28343663 = 0x2CAA04F, kRetOwnerLoad3663 = 0x2AE1D14, kRetLoader3663 = 0x2B36240;
inline constexpr uint32_t kFrameSiteRva3663 = 0x2CA9D50;
inline constexpr std::array<uint8_t, 12> kFrameSite3663{0x48, 0x8D, 0x6C, 0x24, 0xA0, 0x48, 0x81, 0xEC, 0x70, 0x01, 0x00, 0x00};
inline constexpr uint32_t kCallSiteRva3663 = 0x2CA9FFD;
inline constexpr std::array<uint8_t, 82> kCallSite3663{
    0x44, 0x8B, 0x45, 0xD8, 0x48, 0x8D, 0x55, 0x28, 0x48, 0x8B, 0x8B, 0x10, 0x02, 0x00, 0x00, 0xE8, 0x7F, 0x0A, 0x67, 0xFF,
    0x90, 0x83, 0x7D, 0x48, 0x00, 0x74, 0x3A, 0x48, 0x8B, 0x45, 0x28, 0x48, 0x8B, 0x10, 0x48, 0x85, 0xD2, 0x74, 0x2E, 0x80,
    0x3A, 0x00, 0x74, 0x29, 0x44, 0x88, 0x75, 0x88, 0x40, 0x88, 0x74, 0x24, 0x30, 0xC6, 0x44, 0x24, 0x28, 0x00, 0xC6, 0x44,
    0x24, 0x20, 0x00, 0x41, 0xB1, 0x01, 0x4C, 0x8D, 0x45, 0x88, 0x48, 0x8D, 0x55, 0x28, 0x48, 0x8B, 0xCB, 0xE8, 0x71, 0xB1,
    0xE2, 0xFF};
inline constexpr uintptr_t kFrameName3663 = 0x138, kFrameType3663 = 0x98, kFrameHash3663 = 0xE8;

inline bool frame_matches(uintptr_t frame, uintptr_t name_arg, uintptr_t type_arg, uintptr_t name_off, uintptr_t type_off) {
    return frame && name_arg == frame + name_off && type_arg == frame + type_off;
}

// ---------------------------------------------------------------- packets (C->S, payload after the 5-byte header)

inline constexpr uint16_t kOpLoad = 2598;     // SceneLevelLoadCompleteSyncSceneObjectListReq: u32 != 0, u32 hash != 0
inline constexpr uint16_t kOpUnload = 2834;   // SceneLevelUnloadReq: u32 != 0, u8 type 0..3, u32 hash != 0, u8 flag
inline constexpr uint16_t kOpResync = 2104;   // ResyncSyncSceneObjectDataForReloadReq: u8, then u32 hashes
inline constexpr uint16_t kOpReloadStage = 2283, kOpRevive = 2362, kOpGameLoading = 2437, kOpLogout = 2001;
inline constexpr size_t kHeader = 5;  // u16 opcode, u8, u16 payload size

enum class Kind : uint8_t { None, Bad, Load, Unload, Resync, Flush };
struct Packet {
    Kind kind = Kind::None;
    uint8_t type = 0;
    uint32_t hash = 0;
    std::span<const uint8_t> list;  // Resync: the hashes, 4 bytes each
    uint32_t count = 0;
};
inline uint32_t le32(const uint8_t* p) {
    uint32_t x;
    std::memcpy(&x, p, 4);
    return x;
}
// The payload rules are the handlers' (0x29C1900, 0x29C2D50, 0x29C12C0): exact sizes, the same zero checks.
inline Packet parse_payload(uint16_t op, std::span<const uint8_t> p) {
    Packet r;
    switch (op) {
        case kOpLoad:
            r.kind = Kind::Bad;
            if (p.size() != 8 || !le32(p.data()) || !le32(p.data() + 4)) return r;
            r.kind = Kind::Load;
            r.hash = le32(p.data() + 4);
            return r;
        case kOpUnload:
            r.kind = Kind::Bad;
            if (p.size() != 10 || !le32(p.data()) || p[4] > 3 || !le32(p.data() + 5)) return r;
            r.kind = Kind::Unload;
            r.type = p[4];
            r.hash = le32(p.data() + 5);
            return r;
        case kOpResync:
            r.kind = Kind::Bad;
            if (p.empty() || (p.size() - 1) % 4) return r;
            r.kind = Kind::Resync;
            r.list = p.subspan(1);
            r.count = static_cast<uint32_t>(r.list.size() / 4);
            return r;
        case kOpReloadStage:
        case kOpRevive:
        case kOpGameLoading:
        case kOpLogout:
            r.kind = Kind::Flush;
            return r;
        default:
            return r;
    }
}
inline bool relevant(uint16_t op) {
    return op == kOpLoad || op == kOpUnload || op == kOpResync || op == kOpReloadStage || op == kOpRevive ||
           op == kOpGameLoading || op == kOpLogout;
}
inline Packet parse_frame(std::span<const uint8_t> f) {
    if (f.size() < kHeader) return {};
    const uint16_t op = static_cast<uint16_t>(f[0] | (f[1] << 8));
    const size_t n = static_cast<size_t>(f[3] | (f[4] << 8));
    if (n != f.size() - kHeader) return relevant(op) ? Packet{Kind::Bad} : Packet{};
    return parse_payload(op, f.subspan(kHeader));
}

// ---------------------------------------------------------------- the name's hash

// cdmp_HashLittle 0x1364780 = lookup3 hashlittle, initval 0xC5EDE (guest_sched_load_logic.h). raw: over the name as
// 0x2829E60 caches it at [S+0xC]; base: over its base name without extension (0x1422F90's rule, gsl::base_without_ext),
// measured too. Plain loops only (no STL algorithm, no CRT call): it runs inside a mid hook.
struct NameHashes {
    uint32_t raw = 0, base = 0;
};
inline NameHashes name_hashes(const uint8_t* s, size_t n) {
    NameHashes h;
    h.raw = gsl::hashlittle(s, n, gsl::kNameHashInit);
    size_t start = 0;
    for (size_t i = 0; i < n; ++i) {
        if (s[i] == '\\' || s[i] == '/') start = i + 1;
    }
    size_t len = n - start;
    if (len > gsl::kBaseNameMax) len = gsl::kBaseNameMax;
    for (size_t i = len; i-- > 0;) {
        if (s[start + i] == '.') {
            len = i;
            break;
        }
    }
    h.base = gsl::hashlittle(s + start, len, gsl::kNameHashInit);
    return h;
}

enum class Variant : uint8_t { None, Raw, Base };
inline const char* variant_name(Variant v) {
    return v == Variant::Raw ? "nombre" : v == Variant::Base ? "nombre-base" : "ninguna";
}
// Which name -> hash rule is proven in this process: at least one 2834 where it gave the packet's hash, and never
// one where it did not. Any thread (relaxed atomics).
class HashCheck {
public:
    void record(const NameHashes& n, uint32_t packet_hash) noexcept {
        (n.raw == packet_hash ? match_[0] : miss_[0]).fetch_add(1, std::memory_order_relaxed);
        (n.base == packet_hash ? match_[1] : miss_[1]).fetch_add(1, std::memory_order_relaxed);
    }
    Variant usable() const noexcept {
        if (match_[0].load(std::memory_order_relaxed) && !miss_[0].load(std::memory_order_relaxed)) return Variant::Raw;
        if (match_[1].load(std::memory_order_relaxed) && !miss_[1].load(std::memory_order_relaxed)) return Variant::Base;
        return Variant::None;
    }
    static uint32_t pick(Variant v, const NameHashes& n) { return v == Variant::Raw ? n.raw : v == Variant::Base ? n.base : 0; }
    uint64_t matches(size_t i) const { return match_[i].load(std::memory_order_relaxed); }
    uint64_t misses(size_t i) const { return miss_[i].load(std::memory_order_relaxed); }

private:
    std::atomic<uint64_t> match_[2]{}, miss_[2]{};
};

// ---------------------------------------------------------------- per-user loaded sets

enum class User : uint8_t { Host, User2, Count };
inline constexpr size_t kUsers = static_cast<size_t>(User::Count);
inline const char* user_name(User u) { return u == User::Host ? "anfitrion" : "usuario2"; }

enum class Has : uint8_t { No, Yes, Unknown };
inline const char* has_name(Has h) { return h == Has::Yes ? "si" : h == Has::No ? "no" : "?"; }

// Open addressing with linear probes and backward-shift deletion (no tombstones). ONE writer at a time (the caller
// guarantees it); readers on any thread through a sequence lock: a lookup that overlaps a write answers Busy (never a
// stale Yes). 0 and 1 are never keys (the 2598 handler rejects hash 0; 1 is not tracked). At most 3/4 full: past that
// the set says overflow() and the tracker stops trusting it until its next flush.
template <size_t N>
class HashSet {
    static_assert(N >= 8 && (N & (N - 1)) == 0, "N must be a power of two");

public:
    static constexpr uint32_t kMax = static_cast<uint32_t>(N / 4 * 3);
    enum class Look : uint8_t { No, Yes, Busy };

    bool add(uint32_t h) noexcept {
        if (h < 2) return false;
        if (find(h) != kNone) return true;
        if (count_.load(std::memory_order_relaxed) >= kMax) {
            overflow_.store(true, std::memory_order_relaxed);
            return false;
        }
        begin();
        size_t i = home(h);
        while (slots_[i].load(std::memory_order_relaxed)) i = (i + 1) & (N - 1);
        slots_[i].store(h, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
        end();
        return true;
    }
    bool remove(uint32_t h) noexcept {
        size_t i = h < 2 ? kNone : find(h);
        if (i == kNone) return false;
        begin();
        slots_[i].store(0, std::memory_order_relaxed);
        for (size_t j = (i + 1) & (N - 1);; j = (j + 1) & (N - 1)) {
            const uint32_t v = slots_[j].load(std::memory_order_relaxed);
            if (!v) break;
            const size_t k = home(v);
            // v stays when its home lies cyclically in (i, j]; otherwise it moves into the hole.
            const bool stays = i <= j ? (k > i && k <= j) : (k > i || k <= j);
            if (stays) continue;
            slots_[i].store(v, std::memory_order_relaxed);
            slots_[j].store(0, std::memory_order_relaxed);
            i = j;
        }
        count_.fetch_sub(1, std::memory_order_relaxed);
        end();
        return true;
    }
    void clear() noexcept {
        begin();
        for (auto& s : slots_) s.store(0, std::memory_order_relaxed);
        count_.store(0, std::memory_order_relaxed);
        overflow_.store(false, std::memory_order_relaxed);
        end();
    }
    Look contains(uint32_t h) const noexcept {
        if (h < 2) return Look::No;
        const uint32_t s1 = seq_.load(std::memory_order_acquire);
        if (s1 & 1) return Look::Busy;
        bool found = false;
        size_t i = home(h);
        for (size_t n = 0; n < N; ++n, i = (i + 1) & (N - 1)) {
            const uint32_t v = slots_[i].load(std::memory_order_relaxed);
            if (!v) break;
            if (v == h) {
                found = true;
                break;
            }
        }
        std::atomic_thread_fence(std::memory_order_acquire);
        if (seq_.load(std::memory_order_relaxed) != s1) return Look::Busy;
        return found ? Look::Yes : Look::No;
    }
    uint32_t size() const noexcept { return count_.load(std::memory_order_relaxed); }
    bool overflow() const noexcept { return overflow_.load(std::memory_order_relaxed); }

private:
    static constexpr size_t kNone = ~size_t{0};
    static size_t home(uint32_t h) {
        uint32_t x = h;
        x ^= x >> 16;
        x *= 0x45D9F3Bu;
        x ^= x >> 16;
        return x & (N - 1);
    }
    size_t find(uint32_t h) const {
        size_t i = home(h);
        for (size_t n = 0; n < N; ++n, i = (i + 1) & (N - 1)) {
            const uint32_t v = slots_[i].load(std::memory_order_relaxed);
            if (!v) return kNone;
            if (v == h) return i;
        }
        return kNone;
    }
    void begin() noexcept {
        seq_.store(seq_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
    }
    void end() noexcept { seq_.store(seq_.load(std::memory_order_relaxed) + 1, std::memory_order_release); }

    std::atomic<uint32_t> slots_[N]{};
    std::atomic<uint32_t> seq_{0};
    std::atomic<uint32_t> count_{0};
    std::atomic<bool> overflow_{false};
};

// What one packet did to a user's set (counters and the lines).
enum class Applied : uint8_t { Ignored, Added, AlreadyIn, Removed, NotIn, OtherType, Replaced, Flushed, Overflow, Bad };

// The two users' sets. apply(): one writer at a time (server.cpp's OnRecvPacket hook, ServerRunThread). flush():
// any thread (a request the next apply() of that user honours; meanwhile has() answers No). invalidate(): any thread
// (an update was lost: has() answers Unknown until the user's next flush / Resync).
template <size_t N>
class Tracker {
public:
    Applied apply(User u, const Packet& p) noexcept {
        const size_t i = static_cast<size_t>(u);
        if (i >= kUsers) return Applied::Ignored;
        // Review of a4c2661 (P2-2): the request is cleared only AFTER the set is empty, so a reader never sees the
        // request gone with the old set still there. One writer: a request made during reset() is absorbed by it.
        if (flush_req_[i].load(std::memory_order_acquire)) {
            reset(i);
            flush_req_[i].store(false, std::memory_order_release);
        }
        switch (p.kind) {
            case Kind::Load:
                if (sets_[i].contains(p.hash) == HashSet<N>::Look::Yes) return Applied::AlreadyIn;
                if (sets_[i].add(p.hash)) return Applied::Added;
                if (sets_[i].overflow()) invalid_[i].store(true, std::memory_order_release);
                return Applied::Overflow;
            case Kind::Unload:
                if (p.type != 0) return Applied::OtherType;
                return sets_[i].remove(p.hash) ? Applied::Removed : Applied::NotIn;
            case Kind::Resync: {
                // The client's whole list after a reload (measured: every 2598 since its load is in it): the set is it.
                reset(i);
                bool full = false;
                for (uint32_t k = 0; k < p.count; ++k) {
                    if (!sets_[i].add(le32(p.list.data() + size_t(k) * 4)) && sets_[i].overflow()) full = true;
                }
                if (full) invalid_[i].store(true, std::memory_order_release);
                return full ? Applied::Overflow : Applied::Replaced;
            }
            case Kind::Flush:
                reset(i);
                return Applied::Flushed;
            case Kind::Bad:
                return Applied::Bad;
            default:
                return Applied::Ignored;
        }
    }
    void flush(User u) noexcept {
        const size_t i = static_cast<size_t>(u);
        if (i < kUsers) flush_req_[i].store(true, std::memory_order_release);
    }
    void invalidate(User u) noexcept {
        const size_t i = static_cast<size_t>(u);
        if (i < kUsers) invalid_[i].store(true, std::memory_order_release);
    }
    Has has(User u, uint32_t h) const noexcept {
        const size_t i = static_cast<size_t>(u);
        if (i >= kUsers) return Has::Unknown;
        if (flush_req_[i].load(std::memory_order_acquire)) return Has::No;
        if (invalid_[i].load(std::memory_order_acquire)) return Has::Unknown;
        switch (sets_[i].contains(h)) {
            case HashSet<N>::Look::Yes: return Has::Yes;
            case HashSet<N>::Look::No: return Has::No;
            default: return Has::Unknown;
        }
    }
    uint32_t size(User u) const noexcept {
        const size_t i = static_cast<size_t>(u);
        if (i >= kUsers || flush_req_[i].load(std::memory_order_acquire)) return 0;
        return sets_[i].size();
    }
    bool valid(User u) const noexcept {
        const size_t i = static_cast<size_t>(u);
        return i < kUsers && !invalid_[i].load(std::memory_order_acquire);
    }

private:
    void reset(size_t i) noexcept {
        sets_[i].clear();
        invalid_[i].store(false, std::memory_order_release);
    }
    HashSet<N> sets_[kUsers];
    std::atomic<bool> flush_req_[kUsers]{};
    std::atomic<bool> invalid_[kUsers]{};
};

// ---------------------------------------------------------------- A: the owner gate

enum class GateWhy : uint8_t {
    Owner,         // eax == [field+0x180]: the native pass (the field owner's own load)
    NoKeys,        // the host's or user 2's user key is not known yet, or user 2 is not logged in
    NotHostField,  // the field is not a ServerField the host owns
    NotUser2,      // eax is not user 2's user key
    NoSubjectHook, // user2_funnels' ExecuteTroc subject is not hooked (no Troc can be told)
    NoTroc,        // not inside a Troc of user 2
    OtherSubject,  // the Troc's subject is not this actor
    WrongOpcode,   // a Troc of user 2 other than 2598 / 2104
    WouldReady,    // probe: all of the above hold
    Ready,         // mode 1: eax := [field+0x180]
    Count
};
inline const char* gate_why_name(GateWhy w) {
    constexpr const char* n[] = {"dueno-nativo", "sin-claves", "campo-no-anfitrion", "no-usuario2", "sin-gancho-sujeto",
                                 "sin-troc",     "otro-sujeto", "otro-opcode",        "would ready", "ready for user 2"};
    const auto i = static_cast<size_t>(w);
    return i < std::size(n) ? n[i] : "?";
}
struct GateIn {
    Mode mode = Mode::Off;
    bool keys_live = false;  // user 2 logged in
    uint32_t eax = 0, owner = 0, host_user = 0, user2_user = 0;
    bool field_ok = false;  // r8 is a ServerField (vtable)
    bool hooked = false;    // the subject hook is in
    uintptr_t subject = 0;  // user 2's main character while its Troc runs (0 otherwise)
    uintptr_t actor = 0;    // rdx
    uint16_t opcode = 0;
};
inline GateWhy decide_gate(const GateIn& in) {
    if (in.eax == in.owner) return GateWhy::Owner;
    if (!in.keys_live || !in.host_user || !in.user2_user || in.host_user == in.user2_user) return GateWhy::NoKeys;
    if (!in.field_ok || in.owner != in.host_user) return GateWhy::NotHostField;
    if (in.eax != in.user2_user) return GateWhy::NotUser2;
    if (!in.hooked) return GateWhy::NoSubjectHook;
    if (!in.subject) return GateWhy::NoTroc;
    if (in.subject != in.actor) return GateWhy::OtherSubject;
    if (in.opcode != kOpLoad && in.opcode != kOpResync) return GateWhy::WrongOpcode;
    return in.mode == Mode::On ? GateWhy::Ready : GateWhy::WouldReady;
}

// ---------------------------------------------------------------- B: the delete

enum class Caller : uint8_t { Unload2834, OwnerLoad, Loader, Other, Count };
inline Caller caller_of(uint32_t ret_rva) {
    return ret_rva == kRet2834 ? Caller::Unload2834
           : ret_rva == kRetOwnerLoad ? Caller::OwnerLoad
           : ret_rva == kRetLoader ? Caller::Loader
                                   : Caller::Other;
}
// The same, with the build's return addresses.
inline Caller caller_of(uint32_t ret_rva, uint32_t ret_2834, uint32_t ret_owner_load, uint32_t ret_loader) {
    return ret_rva == ret_2834 ? Caller::Unload2834
           : ret_rva == ret_owner_load ? Caller::OwnerLoad
           : ret_rva == ret_loader ? Caller::Loader
                                   : Caller::Other;
}
inline const char* caller_name(Caller c) {
    constexpr const char* n[] = {"2834", "carga-dueno-0x2836110", "cargador-0x2876420", "otro"};
    const auto i = static_cast<size_t>(c);
    return i < std::size(n) ? n[i] : "?";
}
// Mode 1 skips the delete only for the caller statically shown safe: the 2834 handler (the void result is ignored,
// the caller releases the name itself; skipping is exactly "this 2834 never came"). 0x2836110 clears +0x238 / +0x258
// and its caller 0x287BCE0 then calls 0x141EF8FE0 on the whole field: a kept entry would be left half torn down. The
// loader's event 0x2876420 is the loader's own unload. Both stay observed only ([would keep]).
inline bool skip_allowed(Caller c) { return c == Caller::Unload2834; }

enum class Who : uint8_t { Host, User2, Nobody, Unknown };
inline const char* who_name(Who w) {
    constexpr const char* n[] = {"anfitrion", "usuario2", "nadie", "?"};
    const auto i = static_cast<size_t>(w);
    return i < std::size(n) ? n[i] : "?";
}
// Who makes this delete happen: the 2834's sender (user 2 when its Troc 2834 runs; with the subject hook in, any other
// 2834 is the host's - the session has two users); 0x2836110 runs in the owner's load (user 2 only inside its Troc);
// the loader is nobody's. Without the subject hook: unknown.
inline Who provoker_of(Caller c, bool hooked, bool user2_troc, uint16_t opcode) {
    switch (c) {
        case Caller::Unload2834:
            if (!hooked) return Who::Unknown;
            if (user2_troc) return opcode == kOpUnload ? Who::User2 : Who::Unknown;
            return Who::Host;
        case Caller::OwnerLoad:
            if (!hooked) return Who::Unknown;
            return user2_troc ? Who::User2 : Who::Host;
        case Caller::Loader: return Who::Nobody;
        default: return Who::Unknown;
    }
}

enum class Verdict : uint8_t { Delete, WouldKeep, Keep };
enum class Why : uint8_t {
    Off,
    OtherCaller,
    NotType0,
    NotHostField,
    ProvokerUnknown,
    NameUnreadable,
    NoPacketHash,    // 2834: the handler's frame or its hash could not be read
    HashUnverified,  // no name -> hash rule proven in this process yet
    HashMismatch,    // 2834: this name's hash is not the packet's
    NoHolder,        // nobody else has it loaded (also: the last user's own 2834)
    HolderUnknown,   // the other user's set cannot be trusted now
    NotReady,        // 2834: the entry is registered but not ready (+0x40 == 0): keeping it would keep a broken door
    ReadyUnknown,    // 2834: the entry's ready byte could not be read safely
    Probe,           // would keep (probe)
    ObserveOnly,     // would keep, but this caller is never skipped
    Kept,            // mode 1: skipped
    Count
};
inline const char* why_name(Why w) {
    constexpr const char* n[] = {"apagado",         "otro-llamador",   "tipo-no-0",       "campo-no-anfitrion",
                                 "quien-desconocido", "nombre-ilegible", "sin-hash-paquete", "hash-no-verificado",
                                 "hash-distinto",   "nadie-mas-lo-tiene", "conjunto-dudoso", "entrada-no-lista",
                                 "listo-ilegible",  "would keep",
                                 "would keep (solo observa este llamador)", "kept"};
    const auto i = static_cast<size_t>(w);
    return i < std::size(n) ? n[i] : "?";
}
struct DeleteIn {
    Mode mode = Mode::Off;
    Caller caller = Caller::Other;
    bool type_ok = false;
    uint8_t type = 0;
    bool field_host = false;  // [mgr+0x210] is a ServerField whose owner is the host's user key
    Who provoker = Who::Unknown;
    bool name_ok = false;
    bool packet_hash_ok = false;  // 2834 only: the frame matched and its hash was read
    bool hash_matches = false;    // 2834 only: the proven rule gives the packet's hash for this name
    Variant variant = Variant::None;
    Has host = Has::Unknown, user2 = Has::Unknown;  // who has this hash loaded now
    // 2834 only (review of a4c2661, P2-4): the registry entry's ready byte (+0x40) now: Yes = ready, No = not ready or
    // not registered, Unknown = not read (yet) or not readable. Only a ready entry is kept.
    Has ready = Has::Unknown;
};
struct DeleteOut {
    Verdict verdict = Verdict::Delete;
    Why why = Why::Off;
    uint8_t holders = 0;  // bit 0 host, bit 1 user 2 (users other than the provoker that have it)
};
inline DeleteOut decide_delete(const DeleteIn& in) {
    DeleteOut o;
    auto del = [&](Why w) {
        o.verdict = Verdict::Delete;
        o.why = w;
        return o;
    };
    if (in.mode == Mode::Off) return del(Why::Off);
    if (in.caller == Caller::Other) return del(Why::OtherCaller);
    if (!in.type_ok || in.type != 0) return del(Why::NotType0);
    if (!in.field_host) return del(Why::NotHostField);
    if (in.provoker == Who::Unknown) return del(Why::ProvokerUnknown);
    if (!in.name_ok) return del(Why::NameUnreadable);
    if (in.caller == Caller::Unload2834 && !in.packet_hash_ok) return del(Why::NoPacketHash);
    if (in.variant == Variant::None) return del(Why::HashUnverified);
    if (in.caller == Caller::Unload2834 && !in.hash_matches) return del(Why::HashMismatch);
    bool unknown = false;
    if (in.provoker != Who::Host) {
        if (in.host == Has::Yes) o.holders |= 1;
        if (in.host == Has::Unknown) unknown = true;
    }
    if (in.provoker != Who::User2) {
        if (in.user2 == Has::Yes) o.holders |= 2;
        if (in.user2 == Has::Unknown) unknown = true;
    }
    if (!o.holders) return del(unknown ? Why::HolderUnknown : Why::NoHolder);
    // (the holders stay in the result: the line says who still had it)
    if (in.caller == Caller::Unload2834 && in.ready != Has::Yes) {
        return del(in.ready == Has::No ? Why::NotReady : Why::ReadyUnknown);
    }
    if (in.mode == Mode::Probe) {
        o.verdict = Verdict::WouldKeep;
        o.why = Why::Probe;
        return o;
    }
    if (!skip_allowed(in.caller)) {
        o.verdict = Verdict::WouldKeep;
        o.why = Why::ObserveOnly;
        return o;
    }
    o.verdict = Verdict::Keep;
    o.why = Why::Kept;
    return o;
}

// ---------------------------------------------------------------- the kept entries (the module thread)

// Entries B skipped and no delete has passed for since: the possible orphans. When the last user that had one loaded
// sends its 2834, that delete reaches the original (nobody else has it) and the entry leaves the book. An entry still
// here while nobody has it loaded is reported (orphan): the native cleanups (the owner's DL != 0 load, the loader)
// still remove it. Bounded: past kKeptMax the oldest is forgotten (counted).
inline constexpr size_t kKeptMax = 64;
struct KeptEntry {
    uint32_t hash = 0;
    uint64_t first_us = 0, last_us = 0;
    uint32_t times = 0;
};
class KeptBook {
public:
    void kept(uint32_t hash, uint64_t now_us) {
        for (size_t i = 0; i < n_; ++i) {
            if (e_[i].hash == hash) {
                e_[i].last_us = now_us;
                ++e_[i].times;
                return;
            }
        }
        if (n_ == kKeptMax) {
            for (size_t i = 1; i < n_; ++i) e_[i - 1] = e_[i];
            --n_;
            ++forgotten_;
        }
        e_[n_++] = {hash, now_us, now_us, 1};
    }
    // A delete reached the original for this hash: it is no longer kept.
    bool deleted(uint32_t hash) {
        for (size_t i = 0; i < n_; ++i) {
            if (e_[i].hash != hash) continue;
            for (size_t j = i + 1; j < n_; ++j) e_[j - 1] = e_[j];
            --n_;
            return true;
        }
        return false;
    }
    std::span<const KeptEntry> entries() const { return {e_.data(), n_}; }
    uint64_t forgotten() const { return forgotten_; }

private:
    std::array<KeptEntry, kKeptMax> e_{};
    size_t n_ = 0;
    uint64_t forgotten_ = 0;
};

}  // namespace cdmp::session2::sls
