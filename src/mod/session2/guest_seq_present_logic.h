#pragma once
// S45 (docs/research/s25/s45-escenas-ajenas.md), GUEST: the scenes of ANOTHER player on this client's own camera,
// input and interface. guest_seq_foreign_present_probe = 0 | 1, READ-ONLY probes (nothing is written in the game).
// The pure logic (no game access; tests: tests/optd_seq_present_tests.cpp).
//
// A stage is FOREIGN as in S44 (guest_seq_foreign_logic.h): its owner [stage+0x98] is a character key (0xA...) that is
// neither this client's own (its 2756) nor M's live owner; nothing is foreign while this client's own key is unknown.
//
// The probes (nativo.md §4; every RVA is build 1.0.0.2976's):
//   S-A   in P1 (0x602940's entry, guest_seq_foreign): the stage's processor [stage+0x58], its vtable compared with the
//         three native StageChartProcessor vtables, [proc+8] / [proc+0x10] against the stage's manager / the stage, and
//         the stage's timeline id stage+0x298; every stage started is noted in a table (sequencer, timeline id, whose).
//   S-A2  guest_x_veto's handlers, G = X: a stage function of a stage that has not passed P1 yet.
//   S-B   the slot-99 (start) entry of five timeline event classes (the camera selector, the player camera preset, the
//         letter box, the post process, the AI dialogue): which timeline the event belongs to (the root of [ctx+8]'s
//         parent chain +0x98, its id +0x1D8) and, through the table, to which stage, foreign or not; count and cost.
//   S-C   StartLoadingSequencer's slot 99 (0xC45740, the write P+0x1E0 = ev+0x38): the same, plus the values.
//   S-D   once per frame (guest_seq_play's 0x8B6144 hook): the client's camera manager's current entry, the timeline
//         player's lists, [[cw]+0xDE8], M's / X's input-block level (+0x230) and the latest live foreign stage's
//         timeline in the player; only the CHANGES are logged.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>
#include <string_view>

namespace cdmp::session2::gpr {

// ---------------------------------------------------------------- build 2976 layout [V capstone / Ghidra]

// The three StageChartProcessor vtables (RTTI: ClientSequencerStage_ / CommonSequencerStage_ /
// ServerSequencerStage_StageChartProcessor), their complete object locators ([vt-8]) and the common `ret` 0x359B50.
inline constexpr uint32_t kVtProcClient = 0x558C080, kVtProcCommon = 0x590DF78, kVtProcServer = 0x5B1FE10;
inline constexpr uint32_t kColProcClient = 0x5DB7A20, kColProcCommon = 0x5EE6C48, kColProcServer = 0x5F83DF8;
inline constexpr uint32_t kRetRva = 0x359B50;
inline constexpr size_t kProcSlots = 105;  // slot 105 of each is data (its COL area)
// The StageChart_Function_* trampolines reach the slots +0x108 .. +0x2A0 (scf.txt); the rest are the processor's own
// (tick, conditions, binding) and are NOT a presentation classification (they differ between client and common too).
inline constexpr uint32_t kFnSlotLo = 0x100, kFnSlotHi = 0x2A8;
// The largest slot count of any build (RaPlan's array; a build's own count is RaLayout::slots).
inline constexpr size_t kProcSlotsMax = 107;

// The stage (S44, nativo.md §2.1): [stage+0x28] its manager G, +0x30 its sequencer id, +0x58 its processor, +0x98 its
// owner key, +0x28B started, +0x298 its timeline's id in the client's player (0xA9D8FD mov edx,[rdx+0x298] ->
// 0x34DC130([[0x6D691E0]+0x120], id)). The processor: +8 G, +0x10 the stage (the Execute trampolines, nativo.md §2.1).
inline constexpr uint32_t kStage_Mgr = 0x28, kStage_Seq = 0x30, kStage_Proc = 0x58, kStage_Owner = 0x98,
                          kStage_Started = 0x28B, kStage_Timeline = 0x298;
inline constexpr uint32_t kProc_Mgr = 0x08, kProc_Stage = 0x10;
// The timeline player [[0x6D691E0]+0x120] (0x34DC130): three lists {ptr, u32 n} at +0x58/+0x60, +0x48/+0x50 (both
// also need T+0x1D1) and +0x38/+0x40; a fourth one, +0xB8/+0xC0 (stride 0x18), is read by the game under the
// player's lock and is left out of the replica. T+0x1D8 = the id (0x34DBB03, a counter), T+0xDC "playing" [E: the
// manager's tick 0xAA3E70 asks it].
inline constexpr uint32_t kTl_Id = 0x1D8, kTl_Listed = 0x1D1, kTl_Playing = 0xDC;
struct TlList {
    uint32_t ptr, count;
    bool needs_listed;
};
inline constexpr TlList kTlLists[3] = {{0x58, 0x60, true}, {0x48, 0x50, true}, {0x38, 0x40, false}};
inline constexpr uint32_t kTlMaxPerList = 512;
// A timeline event's slot 99 (start): rcx = the event, rdx = the context; [ctx+8] a timeline node whose parent chain
// (+0x98) ends at the timeline (0xB27880 / 0xC35790 walk it; their root has the timeline's +0x1F8). Its +0x1D8 is
// compared with stage+0x298: that the root IS the player's timeline object is what S-B measures [H].
inline constexpr uint32_t kCtx_Node = 0x08, kNode_Parent = 0x98, kCtx_Flags = 0x5C, kEv_Data = 0x38;
inline constexpr uint32_t kMaxDepth = 32;
// The client world [0x6D691E0]: +0x10 the loading state P (P+0x1E0 = StartLoadingSequencer's byte), +0x118 the camera
// manager (its +0x40 the current entry, the object at entry - 0x28: 0xB27DFE / 0xB27E05), +0x120 the timeline player.
// [[cw]]+0xDE8: what SequencerCamera's .xtls code writes 0 (p8-s9-cinematica.md §7.3 [V est]).
inline constexpr uint32_t kWorldSlot = 0x6D691E0, kCw_Loading = 0x10, kCw_Camera = 0x118, kCw_Player = 0x120,
                          kCam_Current = 0x40, kCamEntryAdjust = 0x28, kP_StartLoading = 0x1E0, kW0_De8 = 0xDE8;
// A manager's input-block level: 0xA98AD0 (InputBlock 0x5E4E60 -> G) keeps the max level of its stages' blocks at
// G+0x230 (0xA98D3E mov [r13+0x230],dil) and hands it to .xtls. The stage manager's vtable 0x55C9720.
inline constexpr uint32_t kMgr_InputBlock = 0x230, kMgr_Actor = 0x18, kActor_Key = 0x60, kVtStageManager = 0x55C9720;

// ---------------------------------------------------------------- whose stage

inline constexpr uint32_t kCharClass = 0xA;
inline bool is_character(uint32_t key) { return key && (key >> 28) == kCharClass; }

enum class Whose : uint8_t {
    OwnUnknown,    // this client's own character is not known yet: nothing is foreign (S44 H-9)
    Own,           // the owner is this client's character or M's
    NotCharacter,  // no owner / an NPC key (a world stage)
    Foreign,       // another player's character
    Count
};
inline Whose whose(uint32_t owner, uint32_t own_key, uint32_t m_key) {
    if (!own_key) return Whose::OwnUnknown;
    if (owner && (owner == own_key || (m_key && owner == m_key))) return Whose::Own;
    if (!is_character(owner)) return Whose::NotCharacter;
    return Whose::Foreign;
}
inline const char* whose_name(Whose w) {
    switch (w) {
        case Whose::OwnUnknown: return "own key unknown";
        case Whose::Own: return "own";
        case Whose::NotCharacter: return "world (owner not a character)";
        case Whose::Foreign: return "FOREIGN";
        default: return "?";
    }
}

// ---------------------------------------------------------------- S-A: the stage's processor

enum class ProcVt : uint8_t { NoProc, Unreadable, Client, Common, Server, Other, Count };
inline ProcVt classify_proc(uint64_t proc, bool vt_read, uint64_t vt_rva) {
    if (!proc) return ProcVt::NoProc;
    if (!vt_read) return ProcVt::Unreadable;
    if (vt_rva == kVtProcClient) return ProcVt::Client;
    if (vt_rva == kVtProcCommon) return ProcVt::Common;
    if (vt_rva == kVtProcServer) return ProcVt::Server;
    return ProcVt::Other;
}
inline const char* proc_vt_name(ProcVt v) {
    switch (v) {
        case ProcVt::NoProc: return "no processor yet ([stage+0x58] = 0)";
        case ProcVt::Unreadable: return "processor unreadable";
        case ProcVt::Client: return "ClientSequencerStage_StageChartProcessor 0x558C080";
        case ProcVt::Common: return "CommonSequencerStage_StageChartProcessor 0x590DF78";
        case ProcVt::Server: return "ServerSequencerStage_StageChartProcessor 0x5B1FE10";
        case ProcVt::Other: return "ANOTHER vtable (none of the three)";
        default: return "?";
    }
}

// R-A's table, computed (never applied): per processor slot in the function range, its kind by the three natives.
enum class SlotKind : uint8_t { Same, ClientOnly, ClientServer, CommonDiffers };
inline SlotKind slot_kind(uint32_t client, uint32_t common, uint32_t server, uint32_t ret = kRetRva) {
    if (common != ret) return client == common ? SlotKind::Same : SlotKind::CommonDiffers;
    if (client == ret) return SlotKind::Same;
    return server == ret ? SlotKind::ClientOnly : SlotKind::ClientServer;
}
struct RaTable {
    static constexpr size_t kMax = 64;
    uint16_t client_only[kMax] = {};    // slot offsets (bytes), presentation for this client only
    uint16_t client_server[kMax] = {};  // implemented by the client and the server (Loading, Reward, ...)
    uint16_t common_differs[kMax] = {};
    size_t n_client_only = 0, n_client_server = 0, n_common_differs = 0;
    size_t outside_client_only = 0;     // client-only slots OUTSIDE the function range (internal: not presentation)
};
inline RaTable ra_table(std::span<const uint32_t> c, std::span<const uint32_t> m, std::span<const uint32_t> s,
                        uint32_t ret = kRetRva) {
    RaTable t;
    const size_t n = c.size() < m.size() ? (c.size() < s.size() ? c.size() : s.size()) : (m.size() < s.size() ? m.size() : s.size());
    for (size_t k = 0; k < n; ++k) {
        const auto off = static_cast<uint16_t>(8 * k);
        const SlotKind sk = slot_kind(c[k], m[k], s[k], ret);
        const bool in_fn = off >= kFnSlotLo && off < kFnSlotHi;
        if (sk == SlotKind::ClientOnly && !in_fn) {
            ++t.outside_client_only;
            continue;
        }
        if (!in_fn) continue;
        if (sk == SlotKind::ClientOnly && t.n_client_only < RaTable::kMax) t.client_only[t.n_client_only++] = off;
        if (sk == SlotKind::ClientServer && t.n_client_server < RaTable::kMax) t.client_server[t.n_client_server++] = off;
        if (sk == SlotKind::CommonDiffers && t.n_common_differs < RaTable::kMax) t.common_differs[t.n_common_differs++] = off;
    }
    return t;
}

// ---------------------------------------------------------------- R-A: the "world only" processor table
//
// guest_seq_foreign_present = 0 | probe | 1 (s45-escenas-ajenas.md §3.1). In P1, a FOREIGN stage whose processor
// [stage+0x58] has the client vtable 0x558C080 gets (1) or would get (probe) its vptr pointed at the mod's table: a copy
// of 0x558C080 whose presentation slots hold what the COMMON processor 0x590DF78 holds there. Every in-range slot
// whose three natives differ has an evidence-based decision for build 2976 (capstone on the exe, s45-datos/ra/):
//   Ret     what TURNS ON presentation for this client: client-only slots (common = server = ret 0x359B50) and the
//           three client+server ones (+0x200 HireMercenary, +0x218 Loading, +0x258 Reward): the common's `ret 0`;
//   Common  +0x288 VarySharpness: the common's own 0x204DDD0 (the owner-online check the client's handler calls first,
//           0x5F4EF0), without the client's work after it (UI service [cw]+0x28);
//   World   +0x1A0 / +0x1A8 DisableCharacterCollision: its only effect is a collision flag of the actors the function
//           binds (0x2049B90 -> 0x5037B0, comps+0x40 -> +0xE0 -> +0x4C), no client service: a WORLD effect, kept;
//   Off     review P2-1: what TURNS presentation OFF, or whose direction is in its data, is kept native, so an end /
//           off never stays cut while its on came from somewhere R-A does not cut (a world stage of X, before P1, a
//           refused stage): DeactivateMiniGame +0x130, DeactiveSequencerCamera +0x1B8 (0x5EA5B0 with dl = 0),
//           SequencerCamera +0x1C8 (dl = data+0x28: on or off), DeactivateSequencerCameraFadeIn +0x1D0 (sets
//           [[cw]]+0xDE8 = 1, the player camera) and its end +0x1D8 (opaque .xtls), CameraPreset's end +0x1E8
//           (0x5EB200, also the processor's own +0x310), FadeInOut +0x210 (from / to alpha in data+0x20 / +0x24),
//           LookAt's end +0x228, UIHint's end +0x250. Cut on-sides of those pairs: DeactiveSequencerCamera's end
//           +0x1C0 (0x5EA5B0 with dl = 1: back ON), CameraPreset +0x1E0, LookAt +0x220, UIHint +0x248, and LetterBox
//           +0x208 (0x5F9CD0 with dl = 1, always on; its off comes from the processor's own +0x80, 0x5EE93B dl = 0, or
//           the timeline event, both native).
// Any other difference (a slot that is not in this list, a handler at another RVA, another kind) means the exe is not
// the one the decisions were made for: R-A refuses as a whole.
enum class RaMode : uint8_t { Off, Probe, On };
inline RaMode parse_ra_mode(std::string_view v, bool* bad = nullptr) {
    if (bad) *bad = false;
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    if (v.empty() || v == "0") return RaMode::Off;
    if (v == "1") return RaMode::On;
    if (v.size() == 5 && (v[0] | 0x20) == 'p' && (v[1] | 0x20) == 'r' && (v[2] | 0x20) == 'o' && (v[3] | 0x20) == 'b' &&
        (v[4] | 0x20) == 'e') {
        return RaMode::Probe;
    }
    if (bad) *bad = true;
    return RaMode::Off;
}
inline const char* ra_mode_name(RaMode m) {
    switch (m) {
        case RaMode::Off: return "0";
        case RaMode::Probe: return "probe";
        case RaMode::On: return "1";
        default: return "?";
    }
}

enum class RaUse : uint8_t { Native, Ret, Common, World, Off };
inline bool ra_keeps_native(RaUse u) { return u == RaUse::Native || u == RaUse::World || u == RaUse::Off; }
struct RaExpect {
    uint16_t off;     // the processor slot (bytes)
    uint32_t client;  // 0x558C080's handler there (RVA)
    uint32_t tramp;   // the StageChart_Function_* Execute (vf8/vf9) that jumps to it (the only one, tramp.py)
    SlotKind kind;    // what slot_kind() gives with the three natives
    RaUse use;
};
inline constexpr RaExpect kRaExpect[] = {
    {0x128, 0x5E36A0, 0x2368030, SlotKind::ClientOnly, RaUse::Ret},    // ActivateMiniGame
    {0x130, 0x5E4400, 0x2368050, SlotKind::ClientOnly, RaUse::Off},    // DeactivateMiniGame: off
    {0x138, 0x5E4B00, 0x2368070, SlotKind::ClientOnly, RaUse::Ret},    // ExecuteMiniGameEvent
    {0x140, 0x5E4B60, 0x2368150, SlotKind::ClientOnly, RaUse::Ret},    // Craft (GetLocalPlayer)
    {0x150, 0x5E4E60, 0x2368240, SlotKind::ClientOnly, RaUse::Ret},    // InputBlock
    {0x158, 0x5E4EB0, 0x2368880, SlotKind::ClientOnly, RaUse::Ret},    // UIControl (the shop)
    {0x160, 0x5E9750, 0x23688A0, SlotKind::ClientOnly, RaUse::Ret},    // ChangePhasePanelTag ([cw]+0x20)
    {0x168, 0x5ECD90, 0x2369A80, SlotKind::ClientOnly, RaUse::Ret},    // UIShowMinimap
    {0x170, 0x5ED9A0, 0x2369AA0, SlotKind::ClientOnly, RaUse::Ret},    // UIFindPath
    {0x198, 0x5E9790, 0x2369C30, SlotKind::ClientOnly, RaUse::Ret},    // SetCustomMesh ([cw]+0x120, +0x90)
    {0x1A0, 0x5E99C0, 0x2369C50, SlotKind::ClientOnly, RaUse::World},  // DisableCharacterCollision: world
    {0x1A8, 0x5E9B00, 0x2369C70, SlotKind::ClientOnly, RaUse::World},  // its end: world
    {0x1B0, 0x5E9C40, 0x2369C90, SlotKind::ClientOnly, RaUse::Ret},    // SetPreviewTarget
    {0x1B8, 0x5EE210, 0x2369CB0, SlotKind::ClientOnly, RaUse::Off},    // DeactiveSequencerCamera (dl 0): off
    {0x1C0, 0x5EE230, 0x2369CD0, SlotKind::ClientOnly, RaUse::Ret},    // its end (dl 1): back on
    {0x1C8, 0x5EE250, 0x2369CF0, SlotKind::ClientOnly, RaUse::Off},    // SequencerCamera: on/off in data
    {0x1D0, 0x5EE0C0, 0x2369D10, SlotKind::ClientOnly, RaUse::Off},    // DeactivateSequencerCameraFadeIn: off
    {0x1D8, 0x5EE160, 0x2369D30, SlotKind::ClientOnly, RaUse::Off},    // its end (opaque): kept
    {0x1E0, 0x5EDD30, 0x2369D50, SlotKind::ClientOnly, RaUse::Ret},    // CameraPreset: on
    {0x1E8, 0x5EE1F0, 0x2369D70, SlotKind::ClientOnly, RaUse::Off},    // its end (0x5EB200): off
    {0x1F0, 0x5EAE90, 0x2369D90, SlotKind::ClientOnly, RaUse::Ret},    // ForceLockOn
    {0x1F8, 0x5F2980, 0x2369F00, SlotKind::ClientOnly, RaUse::Ret},    // UIStageIcon
    {0x200, 0x5F4BC0, 0x2369FF0, SlotKind::ClientServer, RaUse::Ret},  // HireMercenary (client: [cw]+0x30)
    {0x208, 0x5F2970, 0x236A010, SlotKind::ClientOnly, RaUse::Ret},    // LetterBox (dl 1): on
    {0x210, 0x5F52E0, 0x236A030, SlotKind::ClientOnly, RaUse::Off},    // FadeInOut: direction in data
    {0x218, 0x5F2A00, 0x236A120, SlotKind::ClientServer, RaUse::Ret},  // Loading (what V1 forces since S9)
    {0x220, 0x5F3600, 0x236A140, SlotKind::ClientOnly, RaUse::Ret},    // LookAt: on
    {0x228, 0x5F3810, 0x236A160, SlotKind::ClientOnly, RaUse::Off},    // its end: off
    {0x238, 0x5F3A90, 0x236A1A0, SlotKind::ClientOnly, RaUse::Ret},    // UIStageGuide
    {0x240, 0x5F4050, 0x236A1C0, SlotKind::ClientOnly, RaUse::Ret},    // UIStageBackgroundGuide
    {0x248, 0x5F4110, 0x236A1E0, SlotKind::ClientOnly, RaUse::Ret},    // UIHint: on
    {0x250, 0x5F4200, 0x236A200, SlotKind::ClientOnly, RaUse::Off},    // its end: off
    {0x258, 0x5F4280, 0x236A2C0, SlotKind::ClientServer, RaUse::Ret},  // Reward (client: a thunk to .xtls)
    {0x260, 0x5F4440, 0x236A360, SlotKind::ClientOnly, RaUse::Ret},    // PostProcess
    {0x268, 0x5F4590, 0x236A400, SlotKind::ClientOnly, RaUse::Ret},    // MaterialParameter ([cw]+0x120)
    {0x288, 0x5F4EC0, 0x236A520, SlotKind::CommonDiffers, RaUse::Common},  // VarySharpness -> the common's 0x204DDD0
};
inline constexpr size_t kRaExpected = std::size(kRaExpect);
inline const RaExpect* ra_expect(uint32_t off) {
    for (const RaExpect& e : kRaExpect) {
        if (e.off == off) return &e;
    }
    return nullptr;
}

// Build 1.0.0.3527 [V capstone + RTTI: each slot's name is the StageChart_Function_* class whose vf8 / vf9 is that
// trampoline; tools: rtti_3527.json]. Slots from +0x138 on moved by +8: the new StageChart_Function_ReserveMiniGame
// (vtable 0x5D434D0) took +0x138. Its handler 0x6A0C30 appends func[0x20] to a vector of the client service
// [[0x71BDF40]+0x18]+0x78: client state only, the server and the common have ret: Ret, as ActivateMiniGame.
// Pairs re-read: +0x1C0 / +0x1C8 lea r9 ; dl = 0 / 1 -> 0x6A6F90 (0x6AB320, 0x6AB340); +0x1F0 -> 0x6A7BC0 = the
// processor's own +0x320 (0x6AB300); +0x210 dl = 1 -> 0x6B7690 (0x6AFD90); +0x290 calls the common's 0x2208110 first
// (0x6B2420). The processor's lifetime: kRaLifetime3527 in guest_seq_present.cpp.
inline constexpr RaExpect kRaExpect3527[] = {
    {0x128, 0x69F990, 0x255BEE0, SlotKind::ClientOnly, RaUse::Ret},    // ActivateMiniGame
    {0x130, 0x6A0700, 0x255BF00, SlotKind::ClientOnly, RaUse::Off},    // DeactivateMiniGame: off
    {0x138, 0x6A0C30, 0x255BF20, SlotKind::ClientOnly, RaUse::Ret},    // ReserveMiniGame (new in this build)
    {0x140, 0x6A0CA0, 0x255BF40, SlotKind::ClientOnly, RaUse::Ret},    // ExecuteMiniGameEvent
    {0x148, 0x6A0D00, 0x255C020, SlotKind::ClientOnly, RaUse::Ret},    // Craft
    {0x158, 0x6A1000, 0x255C110, SlotKind::ClientOnly, RaUse::Ret},    // InputBlock
    {0x160, 0x6A1050, 0x255C800, SlotKind::ClientOnly, RaUse::Ret},    // UIControl (the shop)
    {0x168, 0x6A60F0, 0x255C820, SlotKind::ClientOnly, RaUse::Ret},    // ChangePhasePanelTag
    {0x170, 0x6A9CB0, 0x255DA80, SlotKind::ClientOnly, RaUse::Ret},    // UIShowMinimap
    {0x178, 0x6AAAA0, 0x255DAA0, SlotKind::ClientOnly, RaUse::Ret},    // UIFindPath
    {0x1A0, 0x6A6150, 0x255DC30, SlotKind::ClientOnly, RaUse::Ret},    // SetCustomMesh
    {0x1A8, 0x6A63B0, 0x255DC50, SlotKind::ClientOnly, RaUse::World},  // DisableCharacterCollision: world
    {0x1B0, 0x6A64F0, 0x255DC70, SlotKind::ClientOnly, RaUse::World},  // its end: world
    {0x1B8, 0x6A6630, 0x255DC90, SlotKind::ClientOnly, RaUse::Ret},    // SetPreviewTarget
    {0x1C0, 0x6AB320, 0x255DCB0, SlotKind::ClientOnly, RaUse::Off},    // DeactiveSequencerCamera (dl 0): off
    {0x1C8, 0x6AB340, 0x255DCD0, SlotKind::ClientOnly, RaUse::Ret},    // its end (dl 1): back on
    {0x1D0, 0x6AB360, 0x255DCF0, SlotKind::ClientOnly, RaUse::Off},    // SequencerCamera: on/off in data
    {0x1D8, 0x6AB1D0, 0x255DD10, SlotKind::ClientOnly, RaUse::Off},    // DeactivateSequencerCameraFadeIn: off
    {0x1E0, 0x6AB270, 0x255DD30, SlotKind::ClientOnly, RaUse::Off},    // its end (opaque): kept
    {0x1E8, 0x6AAE30, 0x255DD50, SlotKind::ClientOnly, RaUse::Ret},    // CameraPreset: on
    {0x1F0, 0x6AB300, 0x255DD70, SlotKind::ClientOnly, RaUse::Off},    // its end: off
    {0x1F8, 0x6A7800, 0x255DD90, SlotKind::ClientOnly, RaUse::Ret},    // ForceLockOn
    {0x200, 0x6AFDA0, 0x255DF00, SlotKind::ClientOnly, RaUse::Ret},    // UIStageIcon
    {0x208, 0x6B20F0, 0x255DFF0, SlotKind::ClientServer, RaUse::Ret},  // HireMercenary
    {0x210, 0x6AFD90, 0x255E010, SlotKind::ClientOnly, RaUse::Ret},    // LetterBox (dl 1): on
    {0x218, 0x6B2830, 0x255E030, SlotKind::ClientOnly, RaUse::Off},    // FadeInOut: direction in data
    {0x220, 0x6AFE10, 0x255E120, SlotKind::ClientServer, RaUse::Ret},  // Loading
    {0x228, 0x6B0B00, 0x255E140, SlotKind::ClientOnly, RaUse::Ret},    // LookAt: on
    {0x230, 0x6B0D20, 0x255E160, SlotKind::ClientOnly, RaUse::Off},    // its end: off
    {0x240, 0x6B0FA0, 0x255E1A0, SlotKind::ClientOnly, RaUse::Ret},    // UIStageGuide
    {0x248, 0x6B1560, 0x255E1C0, SlotKind::ClientOnly, RaUse::Ret},    // UIStageBackgroundGuide
    {0x250, 0x6B1610, 0x255E1E0, SlotKind::ClientOnly, RaUse::Ret},    // UIHint: on
    {0x258, 0x6B1700, 0x255E200, SlotKind::ClientOnly, RaUse::Off},    // its end: off
    {0x260, 0x6B1780, 0x255E2D0, SlotKind::ClientServer, RaUse::Ret},  // Reward
    {0x268, 0x6B1930, 0x255E370, SlotKind::ClientOnly, RaUse::Ret},    // PostProcess
    {0x270, 0x6B1A80, 0x255E420, SlotKind::ClientOnly, RaUse::Ret},    // MaterialParameter
    {0x290, 0x6B23F0, 0x255E540, SlotKind::CommonDiffers, RaUse::Common},  // VarySharpness -> the common's 0x2208110
};
// What R-A needs from a build: its three vtables, its `ret`, how many slots, the function range and the decisions.
struct RaLayout {
    uint32_t vt_client, vt_common, vt_server, col_client, col_common, col_server, ret;
    size_t slots;
    uint32_t fn_lo, fn_hi;
    std::span<const RaExpect> expect;
    uint8_t stage_proc;  // the trampolines' `mov rcx,[rax+stage_proc]`
};
inline constexpr RaLayout kRaLayout2976{kVtProcClient, kVtProcCommon, kVtProcServer, kColProcClient, kColProcCommon,
                                        kColProcServer, kRetRva, kProcSlots, kFnSlotLo, kFnSlotHi, kRaExpect, 0x58};
inline constexpr RaLayout kRaLayout3527{0x5919128, 0x5CC2E68, 0x5EE7020, 0x6187890, 0x62C0200, 0x63656E8, 0x3A3450, 107,
                                        0x100, 0x2B0, kRaExpect3527, 0x60};
// Build 1.0.0.3576 (static, 2026-11-06 evening; not yet run): the same 107 slots and the same 37 decisions with the same
// kinds (slot_kind of the three vtables matched by RTTI name, vtable_map_3549_3576.json); every handler moved by +0x660
// and every trampoline by +0xDD0, each trampoline unique in the PE (stage_proc 0x60); ret 0x3A3730 (CameraSelector's
// slots 97 / 98); COLs read at [vt-8].
inline constexpr RaExpect kRaExpect3576[] = {
    {0x128, 0x69FFF0, 0x255CCB0, SlotKind::ClientOnly, RaUse::Ret},  // ActivateMiniGame
    {0x130, 0x6A0D60, 0x255CCD0, SlotKind::ClientOnly, RaUse::Off},  // DeactivateMiniGame: off
    {0x138, 0x6A1290, 0x255CCF0, SlotKind::ClientOnly, RaUse::Ret},  // ReserveMiniGame (new in this build)
    {0x140, 0x6A1300, 0x255CD10, SlotKind::ClientOnly, RaUse::Ret},  // ExecuteMiniGameEvent
    {0x148, 0x6A1360, 0x255CDF0, SlotKind::ClientOnly, RaUse::Ret},  // Craft
    {0x158, 0x6A1660, 0x255CEE0, SlotKind::ClientOnly, RaUse::Ret},  // InputBlock
    {0x160, 0x6A16B0, 0x255D5D0, SlotKind::ClientOnly, RaUse::Ret},  // UIControl (the shop)
    {0x168, 0x6A6750, 0x255D5F0, SlotKind::ClientOnly, RaUse::Ret},  // ChangePhasePanelTag
    {0x170, 0x6AA310, 0x255E850, SlotKind::ClientOnly, RaUse::Ret},  // UIShowMinimap
    {0x178, 0x6AB100, 0x255E870, SlotKind::ClientOnly, RaUse::Ret},  // UIFindPath
    {0x1A0, 0x6A67B0, 0x255EA00, SlotKind::ClientOnly, RaUse::Ret},  // SetCustomMesh
    {0x1A8, 0x6A6A10, 0x255EA20, SlotKind::ClientOnly, RaUse::World},  // DisableCharacterCollision: world
    {0x1B0, 0x6A6B50, 0x255EA40, SlotKind::ClientOnly, RaUse::World},  // its end: world
    {0x1B8, 0x6A6C90, 0x255EA60, SlotKind::ClientOnly, RaUse::Ret},  // SetPreviewTarget
    {0x1C0, 0x6AB980, 0x255EA80, SlotKind::ClientOnly, RaUse::Off},  // DeactiveSequencerCamera (dl 0): off
    {0x1C8, 0x6AB9A0, 0x255EAA0, SlotKind::ClientOnly, RaUse::Ret},  // its end (dl 1): back on
    {0x1D0, 0x6AB9C0, 0x255EAC0, SlotKind::ClientOnly, RaUse::Off},  // SequencerCamera: on/off in data
    {0x1D8, 0x6AB830, 0x255EAE0, SlotKind::ClientOnly, RaUse::Off},  // DeactivateSequencerCameraFadeIn: off
    {0x1E0, 0x6AB8D0, 0x255EB00, SlotKind::ClientOnly, RaUse::Off},  // its end (opaque): kept
    {0x1E8, 0x6AB490, 0x255EB20, SlotKind::ClientOnly, RaUse::Ret},  // CameraPreset: on
    {0x1F0, 0x6AB960, 0x255EB40, SlotKind::ClientOnly, RaUse::Off},  // its end: off
    {0x1F8, 0x6A7E60, 0x255EB60, SlotKind::ClientOnly, RaUse::Ret},  // ForceLockOn
    {0x200, 0x6B0400, 0x255ECD0, SlotKind::ClientOnly, RaUse::Ret},  // UIStageIcon
    {0x208, 0x6B2750, 0x255EDC0, SlotKind::ClientServer, RaUse::Ret},  // HireMercenary
    {0x210, 0x6B03F0, 0x255EDE0, SlotKind::ClientOnly, RaUse::Ret},  // LetterBox (dl 1): on
    {0x218, 0x6B2E90, 0x255EE00, SlotKind::ClientOnly, RaUse::Off},  // FadeInOut: direction in data
    {0x220, 0x6B0470, 0x255EEF0, SlotKind::ClientServer, RaUse::Ret},  // Loading
    {0x228, 0x6B1160, 0x255EF10, SlotKind::ClientOnly, RaUse::Ret},  // LookAt: on
    {0x230, 0x6B1380, 0x255EF30, SlotKind::ClientOnly, RaUse::Off},  // its end: off
    {0x240, 0x6B1600, 0x255EF70, SlotKind::ClientOnly, RaUse::Ret},  // UIStageGuide
    {0x248, 0x6B1BC0, 0x255EF90, SlotKind::ClientOnly, RaUse::Ret},  // UIStageBackgroundGuide
    {0x250, 0x6B1C70, 0x255EFB0, SlotKind::ClientOnly, RaUse::Ret},  // UIHint: on
    {0x258, 0x6B1D60, 0x255EFD0, SlotKind::ClientOnly, RaUse::Off},  // its end: off
    {0x260, 0x6B1DE0, 0x255F0A0, SlotKind::ClientServer, RaUse::Ret},  // Reward
    {0x268, 0x6B1F90, 0x255F140, SlotKind::ClientOnly, RaUse::Ret},  // PostProcess
    {0x270, 0x6B20E0, 0x255F1F0, SlotKind::ClientOnly, RaUse::Ret},  // MaterialParameter
    {0x290, 0x6B2A50, 0x255F310, SlotKind::CommonDiffers, RaUse::Common},  // VarySharpness -> the common's 0x2208110
};
inline constexpr RaLayout kRaLayout3576{0x591B1B8, 0x5CC4F30, 0x5EE8FE0, 0x6189988, 0x62C2308, 0x6367800, 0x3A3730, 107,
                                        0x100, 0x2B0, kRaExpect3576, 0x60};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the three vtables by RTTI name (pa::Client / Common /
// ServerSequencerStage_StageChartProcessor 0x5997A38 / 0x5D40A38 / 0x5F62E40, COLs at [vt-8] = rtti_3663.json's), 107
// slots each, all pointers into the exe. slot_kind over [0x100,0x2B0) with ret 0x3A6D80 (CameraSelectorEventData's
// slots 97 / 98, `ret 0`) gives exactly these 37 differing slots with 3576's kinds and uses (the common's slot is the ret
// for every Ret, not for VarySharpness). Each handler is the client vtable's slot (moved +0x2BE60..+0x2BF20); each
// trampoline (stage_proc 0x60) is unique in the PE and is the vf8 / vf9 of its own StageChart_Function_* class.
inline constexpr RaExpect kRaExpect3663[] = {
    {0x128, 0x6CBED0, 0x25CE530, SlotKind::ClientOnly, RaUse::Ret},  // ActivateMiniGame
    {0x130, 0x6CCC40, 0x25CE550, SlotKind::ClientOnly, RaUse::Off},  // DeactivateMiniGame: off
    {0x138, 0x6CD190, 0x25CE570, SlotKind::ClientOnly, RaUse::Ret},  // ReserveMiniGame
    {0x140, 0x6CD200, 0x25CE590, SlotKind::ClientOnly, RaUse::Ret},  // ExecuteMiniGameEvent
    {0x148, 0x6CD260, 0x25CE670, SlotKind::ClientOnly, RaUse::Ret},  // Craft
    {0x158, 0x6CD560, 0x25CE760, SlotKind::ClientOnly, RaUse::Ret},  // InputBlock
    {0x160, 0x6CD5B0, 0x25CEE70, SlotKind::ClientOnly, RaUse::Ret},  // UIControl (the shop)
    {0x168, 0x6D25B0, 0x25CEE90, SlotKind::ClientOnly, RaUse::Ret},  // ChangePhasePanelTag
    {0x170, 0x6D61A0, 0x25D00F0, SlotKind::ClientOnly, RaUse::Ret},  // UIShowMinimap
    {0x178, 0x6D6F70, 0x25D0110, SlotKind::ClientOnly, RaUse::Ret},  // UIFindPath
    {0x1A0, 0x6D2610, 0x25D02A0, SlotKind::ClientOnly, RaUse::Ret},  // SetCustomMesh
    {0x1A8, 0x6D2870, 0x25D02C0, SlotKind::ClientOnly, RaUse::World},  // DisableCharacterCollision: world
    {0x1B0, 0x6D29B0, 0x25D02E0, SlotKind::ClientOnly, RaUse::World},  // its end: world
    {0x1B8, 0x6D2AF0, 0x25D0300, SlotKind::ClientOnly, RaUse::Ret},  // SetPreviewTarget
    {0x1C0, 0x6D77F0, 0x25D0320, SlotKind::ClientOnly, RaUse::Off},  // DeactiveSequencerCamera (dl 0): off
    {0x1C8, 0x6D7810, 0x25D0340, SlotKind::ClientOnly, RaUse::Ret},  // its end (dl 1): back on
    {0x1D0, 0x6D7830, 0x25D0360, SlotKind::ClientOnly, RaUse::Off},  // SequencerCamera: on/off in data
    {0x1D8, 0x6D76A0, 0x25D0380, SlotKind::ClientOnly, RaUse::Off},  // DeactivateSequencerCameraFadeIn: off
    {0x1E0, 0x6D7740, 0x25D03A0, SlotKind::ClientOnly, RaUse::Off},  // its end (opaque): kept
    {0x1E8, 0x6D7300, 0x25D03C0, SlotKind::ClientOnly, RaUse::Ret},  // CameraPreset: on
    {0x1F0, 0x6D77D0, 0x25D03E0, SlotKind::ClientOnly, RaUse::Off},  // its end: off
    {0x1F8, 0x6D3CD0, 0x25D0400, SlotKind::ClientOnly, RaUse::Ret},  // ForceLockOn
    {0x200, 0x6DC2E0, 0x25D0570, SlotKind::ClientOnly, RaUse::Ret},  // UIStageIcon
    {0x208, 0x6DE660, 0x25D0660, SlotKind::ClientServer, RaUse::Ret},  // HireMercenary
    {0x210, 0x6DC2D0, 0x25D0680, SlotKind::ClientOnly, RaUse::Ret},  // LetterBox (dl 1): on
    {0x218, 0x6DEDA0, 0x25D06A0, SlotKind::ClientOnly, RaUse::Off},  // FadeInOut: direction in data
    {0x220, 0x6DC360, 0x25D0790, SlotKind::ClientServer, RaUse::Ret},  // Loading
    {0x228, 0x6DD050, 0x25D07B0, SlotKind::ClientOnly, RaUse::Ret},  // LookAt: on
    {0x230, 0x6DD270, 0x25D07D0, SlotKind::ClientOnly, RaUse::Off},  // its end: off
    {0x240, 0x6DD4F0, 0x25D0810, SlotKind::ClientOnly, RaUse::Ret},  // UIStageGuide
    {0x248, 0x6DDAC0, 0x25D0830, SlotKind::ClientOnly, RaUse::Ret},  // UIStageBackgroundGuide
    {0x250, 0x6DDB80, 0x25D0850, SlotKind::ClientOnly, RaUse::Ret},  // UIHint: on
    {0x258, 0x6DDC70, 0x25D0870, SlotKind::ClientOnly, RaUse::Off},  // its end: off
    {0x260, 0x6DDCF0, 0x25D0940, SlotKind::ClientServer, RaUse::Ret},  // Reward
    {0x268, 0x6DDEB0, 0x25D09E0, SlotKind::ClientOnly, RaUse::Ret},  // PostProcess
    {0x270, 0x6DE000, 0x25D0A90, SlotKind::ClientOnly, RaUse::Ret},  // MaterialParameter
    {0x290, 0x6DE960, 0x25D0BB0, SlotKind::CommonDiffers, RaUse::Common},  // VarySharpness -> the common's own
};
inline constexpr RaLayout kRaLayout3663{0x5997A38, 0x5D40A38, 0x5F62E40, 0x6206240, 0x633EC68, 0x63E3910, 0x3A6D80, 107,
                                        0x100, 0x2B0, kRaExpect3663, 0x60};
inline const RaExpect* ra_expect(const RaLayout& l, uint32_t off) {
    for (const RaExpect& e : l.expect) {
        if (e.off == off) return &e;
    }
    return nullptr;
}
// The trampoline every StageChart_Function_* Execute uses (52 of them, tramp.py): mov rax,[rdx] (the stage) ; mov
// r8,rcx ; mov rcx,[rax+0x58] (its processor) ; mov rax,[rcx] (the vptr) ; jmp [rax+off]. A tail jump: what the slot
// returns is what Execute returns, and Execute is void (the base StageChart_Function's vf8 / vf9 are the folded void
// `ret 0` 0x359B50, while the folded bool `xor al,al ; ret` is 0x359BA0).
inline constexpr size_t kTrampBytes = 20;
inline void tramp_bytes(uint32_t off, uint8_t out[kTrampBytes], uint8_t stage_proc = 0x58) {
    constexpr uint8_t head[16] = {0x48, 0x8B, 0x02, 0x4C, 0x8B, 0xC1, 0x48, 0x8B,
                                  0x48, 0x58, 0x48, 0x8B, 0x01, 0x48, 0xFF, 0xA0};
    for (size_t i = 0; i < 16; ++i) out[i] = head[i];
    out[9] = stage_proc;
    for (size_t i = 0; i < 4; ++i) out[16 + i] = static_cast<uint8_t>(off >> (8 * i));
}

struct RaPlan {
    bool ok = false;
    const char* why = "";
    uint16_t bad_off = 0;      // the slot that failed, when !ok
    RaUse use[kProcSlotsMax] = {};  // Native everywhere but the decided slots
    size_t n_ret = 0, n_common = 0, n_world = 0, n_off = 0, n_client_server = 0;
};
// c / m / s: the build's slots (RVAs) of the client, common and server vtables.
inline RaPlan ra_plan_for(const RaLayout& l, std::span<const uint32_t> c, std::span<const uint32_t> m,
                          std::span<const uint32_t> s) {
    const uint32_t ret = l.ret;
    RaPlan p;
    if (c.size() < l.slots || m.size() < l.slots || s.size() < l.slots || l.slots > kProcSlotsMax) {
        p.why = "fewer than 105 slots read";
        return p;
    }
    size_t seen = 0;
    for (size_t k = 0; k < l.slots; ++k) {
        const auto off = static_cast<uint16_t>(8 * k);
        const RaExpect* e = ra_expect(l, off);
        if (off < l.fn_lo || off >= l.fn_hi) {
            if (e) {
                p.why = "a decided slot is outside the StageChart function range";
                p.bad_off = off;
                return p;
            }
            continue;
        }
        const SlotKind kind = slot_kind(c[k], m[k], s[k], ret);
        if (kind == SlotKind::Same) {
            if (e) {
                p.why = "a decided slot is the same in the three vtables";
                p.bad_off = off;
                return p;
            }
            continue;
        }
        if (!e) {
            p.why = "a slot differs between the vtables and has no decision (not this build's table)";
            p.bad_off = off;
            return p;
        }
        if (e->client != c[k] || e->kind != kind) {
            p.why = "a decided slot has another handler or another kind (not this build's table)";
            p.bad_off = off;
            return p;
        }
        if (e->use == RaUse::Native || (e->use == RaUse::Ret && m[k] != ret) ||
            (e->use == RaUse::Common && m[k] == ret)) {
            p.why = "the common's slot is not what the decision takes";
            p.bad_off = off;
            return p;
        }
        p.use[k] = e->use;
        ++seen;
        if (e->use == RaUse::Ret) ++p.n_ret;
        if (e->use == RaUse::Common) ++p.n_common;
        if (e->use == RaUse::World) ++p.n_world;
        if (e->use == RaUse::Off) ++p.n_off;
        if (e->kind == SlotKind::ClientServer) ++p.n_client_server;
    }
    if (seen != l.expect.size()) {
        p.why = "not every decided slot was found";
        return p;
    }
    p.ok = true;
    return p;
}
// Build 2976's plan. ret: the tests' own value (the build's kRetRva otherwise).
inline RaPlan ra_plan(std::span<const uint32_t> c, std::span<const uint32_t> m, std::span<const uint32_t> s,
                      uint32_t ret = kRetRva) {
    RaLayout l = kRaLayout2976;
    l.ret = ret;
    return ra_plan_for(l, c, m, s);
}
// The mod's table: out[0] = the client vtable's [-1] (its COL: typeid / dynamic_cast keep working), out[1 + k] = the
// slot: the client's (Native / World / Off) or the common's (Ret / Common). c_abs / m_abs: the slots as absolute addresses.
inline bool ra_build(const RaPlan& p, std::span<const uint64_t> c_abs, std::span<const uint64_t> m_abs, uint64_t col_abs,
                     std::span<uint64_t> out, size_t slots = kProcSlots) {
    if (!p.ok || slots > kProcSlotsMax || c_abs.size() < slots || m_abs.size() < slots || out.size() < 1 + slots ||
        !col_abs) {
        return false;
    }
    out[0] = col_abs;
    for (size_t k = 0; k < slots; ++k) out[1 + k] = ra_keeps_native(p.use[k]) ? c_abs[k] : m_abs[k];
    return true;
}

// One P1 of a stage, judged (any thread; the write itself is the caller's: a compare-exchange of [proc]).
enum class RaVerdict : uint8_t {
    NotForeign,        // not another player's stage: never cut (restored if it has the mod's table: review P2-2)
    NoProcessor,       // [stage+0x58] = 0 at P1
    Unreadable,        // the processor or its vptr unreadable
    MUnknown,          // review P1-1: M (this client's own manager) not seen yet: nothing written
    InM,               // review P1-1: the stage is M's (G = M): never cut (restored if it has the mod's table)
    AlreadyMod,        // its vptr is already the mod's table (a second P1 of the same stage)
    OtherVtable,       // not 0x558C080 (common / server / another class): never touched
    NotThisStage,      // [proc+0x10] is not the stage (the per-stage processor not proven for it)
    OtherManager,      // [proc+8] is not [stage+0x28]
    NotKnownX,         // review P1-1: G is not guest_seq_play's current X of the stage's owner
    NotMainThread,     // P1 is not on the thread that ticks X (guest_seq_play's 0x8B6144), or that one is unknown
    Would,             // probe: all checks passed, 1 would write
    Write,             // 1: all checks passed: write
    Count
};
struct RaFacts {
    RaMode mode = RaMode::Off;
    Whose whose = Whose::OwnUnknown;
    uint64_t stage = 0, stage_mgr = 0;  // the stage and its [stage+0x28]
    uint64_t m = 0;                     // this client's M (0: not seen yet)
    bool x_known = false;               // guest_seq_play_knows_x(stage_mgr, owner): G is a known X of that owner
    uint64_t proc = 0;
    bool vt_read = false;
    uint64_t vt = 0;                    // [proc]
    uint64_t proc_stage = 0, proc_mgr = 0;
    uint64_t client_vt = 0, mod_vt = 0;  // absolute: exe+0x558C080 and &table[1]
    uint32_t tid = 0, main_tid = 0;
};
inline RaVerdict ra_judge(const RaFacts& f) {
    if (f.whose != Whose::Foreign) return RaVerdict::NotForeign;
    if (!f.proc) return RaVerdict::NoProcessor;
    if (!f.vt_read) return RaVerdict::Unreadable;
    if (!f.m) return RaVerdict::MUnknown;
    if (f.stage_mgr == f.m) return RaVerdict::InM;
    if (f.mod_vt && f.vt == f.mod_vt) return RaVerdict::AlreadyMod;
    if (!f.client_vt || f.vt != f.client_vt) return RaVerdict::OtherVtable;
    if (f.proc_stage != f.stage) return RaVerdict::NotThisStage;
    if (f.proc_mgr != f.stage_mgr) return RaVerdict::OtherManager;
    if (!f.x_known) return RaVerdict::NotKnownX;
    if (!f.main_tid || f.tid != f.main_tid) return RaVerdict::NotMainThread;
    return f.mode == RaMode::On ? RaVerdict::Write : RaVerdict::Would;
}
// Review P2-2: a stage that must never carry the mod's table (not foreign, or M's) but does (a recycled stage, or an
// earlier wrong judgement): the caller puts the client vtable back (one compare-exchange) and says so.
inline bool ra_restore_due(const RaFacts& f, RaVerdict v) {
    if (!f.proc || !f.vt_read || !f.mod_vt || !f.client_vt || f.vt != f.mod_vt) return false;
    return v == RaVerdict::NotForeign || v == RaVerdict::MUnknown || v == RaVerdict::InM;
}
inline const char* ra_verdict_name(RaVerdict v) {
    switch (v) {
        case RaVerdict::NotForeign: return "not foreign";
        case RaVerdict::NoProcessor: return "no processor ([stage+0x58] = 0)";
        case RaVerdict::Unreadable: return "processor unreadable";
        case RaVerdict::MUnknown: return "M not seen yet";
        case RaVerdict::InM: return "the stage is M's (G = M)";
        case RaVerdict::AlreadyMod: return "already the mod's table";
        case RaVerdict::OtherVtable: return "not the client processor vtable 0x558C080";
        case RaVerdict::NotThisStage: return "[proc+0x10] is not the stage";
        case RaVerdict::OtherManager: return "[proc+8] is not [stage+0x28]";
        case RaVerdict::NotKnownX: return "G is not guest_seq_play's X of the owner";
        case RaVerdict::NotMainThread: return "P1 not on guest_seq_play's frame thread";
        case RaVerdict::Would: return "WOULD CUT (probe)";
        case RaVerdict::Write: return "CUT";
        default: return "?";
    }
}

// ---------------------------------------------------------------- R-B: the foreign timeline's camera starts
//
// guest_seq_foreign_timeline = 0 | probe | 1 (s45-escenas-ajenas.md §3.2; measured in the step-1 live run, vivo1.md).
// In the S-B hooks of CameraSelectorEventData (0x34CFC20, a 5-byte leaf thunk) and SequencerPlayerCameraPreset
// (0xB27880, an entry with .pdata), slot 99 (the event's START) only: when the event's timeline belongs to a stage R-A
// would cut, probe logs '[R-B WOULD SKIP]' and 1 returns at the entry without running it ('[R-B SKIPPED]').
// - The event -> stage link [V live]: [ctx+8] IS the timeline object (vptr exe+0x5C75F30, depth 0), its +0x1D8 is the
//   stage's +0x298 that P1 noted.
// - Slot 99 only [V]: each entry is that class's slot 99 and no other slot of its vtable; no direct call reaches it;
//   and the call must come back to one of the two verified slot-99 call sites of the event dispatcher (0x36574C7 ->
//   0x36574CD, which jumps to the epilogue; 0x36575D0 -> 0x36575D6, which goes on to slot 101). Both ignore RAX: the
//   dispatcher ends with `mov al,1 ; ret` (0x3657600).
// - Slots 97 / 98 of both classes are 0x359B50 (`ret 0`): returning at the entry with RAX untouched is what the base
//   class's empty void body does. Slots 100, 101 (the end) and 103 stay native.
inline constexpr uint32_t kVtTimeline = 0x5C75F30;  // the timeline object's vptr ([ctx+8]); no RTTI ([-1] is code)
inline constexpr uint32_t kRbCallers[] = {0x36574CD, 0x36575D6};
inline bool rb_caller_ok(uint32_t caller_rva, std::span<const uint32_t> callers = kRbCallers) {
    for (uint32_t c : callers) {
        if (c == caller_rva) return true;
    }
    return false;
}
// Build 1.0.0.3527 [V capstone]: the dispatcher's two slot-99 sites return to 0x392F58D (then its jmp to the epilogue) and
// 0x392F696 (then slot 101); its own return `mov al,1` 0x392F6C0: the same bytes as 2976's. The timeline object: its
// constructor 0x1062DB50 (thunk 0x3790270) writes vptr 0x6042EF0 at [T] and 0x6043310 at [T+0x28], [-1] is code (no RTTI),
// and 0x37AC63D writes its id at +0x1F8 (a counter, lock xadd), compared by 0x37ACCA5 [E strong: what the dispatcher
// passes at [ctx+8] is only provable live; a mismatch reads 'NoTimeline' and nothing is skipped].
inline constexpr uint32_t kVtTimeline3527 = 0x6042EF0;
inline constexpr uint32_t kRbCallers3527[] = {0x392F58D, 0x392F696};
// 1.0.0.3576 (static): the dispatcher moved by +0xDB0 with the same bytes (0x3930334 / 0x393043D, ret 0x3930470); the
// timeline vtable (no RTTI) is the only one whose slots 0 / 1 are 3527's + 0xD00 (0x37912A0 / 0x378DE40).
inline constexpr uint32_t kVtTimeline3576 = 0x6043A90;
inline constexpr uint32_t kRbCallers3576[] = {0x393033D, 0x3930446};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the dispatcher's two slot-99 sites 0x39A98B4 / 0x39A99BD and its
// `mov al,1 ; ...ret` 0x39A99F0 with 2976's bytes (each the only one in the PE; +0x109 / +0x13C apart as on 3576), so the
// return addresses are 0x39A98BD / 0x39A99C6. The timeline vtable (no RTTI, [-1] is code): 0x60C1868, the only table
// whose slots 0 / 1 (0x3808590 / 0x3805130) are 3576's + 0x772F0 and 0x3460 apart; its constructor 0x10B1E270 (thunk
// 0x3808260) writes it at [T] (0x10B1E28A) and a second vptr at [T+0x28], as 3527's 0x1062DB50.
inline constexpr uint32_t kVtTimeline3663 = 0x60C1868;
inline constexpr uint32_t kRbCallers3663[] = {0x39A98BD, 0x39A99C6};

enum class RbVerdict : uint8_t {
    NotSlot99,      // the return address is not one of the dispatcher's two slot-99 call sites
    NotClass,       // the event's vptr is not the hooked class's (review of R-B P3-2)
    NoTimeline,     // [ctx+8] unreadable or not the timeline object (vptr != exe+0x5C75F30)
    NoStage,        // its id (+0x1D8) is no stage P1 noted
    Gone,           // that stage no longer reads back its sequencer / owner (destroyed or reused)
    NotForeign,     // the stage is not another player's: runs natively
    MUnknown,       // M not seen yet
    InM,            // the stage is M's
    NotKnownX,      // its G is not guest_seq_play's X of its owner
    NotMainThread,  // not on guest_seq_play's frame thread
    Would,          // probe: 1 would skip
    Skip,           // 1: return at the entry
    Count
};
struct RbFacts {
    RaMode mode = RaMode::Off;
    uint32_t caller = 0;     // RVA of [rsp] at the entry
    bool event_class = false;  // [rcx] is the hooked class's vtable
    bool timeline = false;   // [ctx+8] read and its vptr is exe+0x5C75F30
    bool found = false;      // its id is a stage P1 noted
    bool alive = false;      // that stage still reads back its sequencer, owner and timeline id (+0x298)
    Whose whose = Whose::OwnUnknown;
    uint64_t stage_mgr = 0, m = 0;
    bool x_known = false;
    uint32_t tid = 0, main_tid = 0;
    std::span<const uint32_t> callers = kRbCallers;  // the build's two slot-99 return addresses
};
inline RbVerdict rb_judge(const RbFacts& f) {
    if (!rb_caller_ok(f.caller, f.callers)) return RbVerdict::NotSlot99;
    if (!f.event_class) return RbVerdict::NotClass;
    if (!f.timeline) return RbVerdict::NoTimeline;
    if (!f.found) return RbVerdict::NoStage;
    if (!f.alive) return RbVerdict::Gone;
    if (f.whose != Whose::Foreign) return RbVerdict::NotForeign;
    if (!f.m) return RbVerdict::MUnknown;
    if (f.stage_mgr == f.m) return RbVerdict::InM;
    if (!f.x_known) return RbVerdict::NotKnownX;
    if (!f.main_tid || f.tid != f.main_tid) return RbVerdict::NotMainThread;
    return f.mode == RaMode::On ? RbVerdict::Skip : RbVerdict::Would;
}
inline const char* rb_verdict_name(RbVerdict v) {
    switch (v) {
        case RbVerdict::NotSlot99: return "not from the dispatcher's slot-99 call";
        case RbVerdict::NotClass: return "the event is not of the hooked class";
        case RbVerdict::NoTimeline: return "[ctx+8] is not the timeline object";
        case RbVerdict::NoStage: return "timeline of no stage P1 noted";
        case RbVerdict::Gone: return "its stage is gone";
        case RbVerdict::NotForeign: return "not foreign";
        case RbVerdict::MUnknown: return "M not seen yet";
        case RbVerdict::InM: return "the stage is M's";
        case RbVerdict::NotKnownX: return "G is not guest_seq_play's X of the owner";
        case RbVerdict::NotMainThread: return "not on guest_seq_play's frame thread";
        case RbVerdict::Would: return "WOULD SKIP (probe)";
        case RbVerdict::Skip: return "SKIPPED";
        default: return "?";
    }
}
// A line is worth writing when the event belongs to a foreign stage (whatever the verdict) or R-B acts.
inline bool rb_makes_line(const RbFacts& f, RbVerdict v) {
    return v == RbVerdict::Would || v == RbVerdict::Skip || (f.found && f.alive && f.whose == Whose::Foreign);
}

// ---------------------------------------------------------------- the stages P1 saw

struct StageRec {
    uint64_t seq = 0;    // stage+0x30
    uint64_t mgr = 0;    // stage+0x28 (G; this process only, never sent anywhere)
    uint64_t stage = 0;  // the stage (this process only: S-D's liveness check re-reads seq / owner there)
    uint64_t us = 0;     // when P1 saw it
    uint32_t tl = 0;     // stage+0x298
    uint32_t owner = 0;  // stage+0x98
    Whose whose = Whose::OwnUnknown;
};
// Written by P1 (any thread), read by S-A2 / S-B / S-C / S-D (any thread): lock-free, per-slot sequence check (a torn
// read only gives a wrong diagnostic line). The most recent N starts; an older one is overwritten (counted).
template <size_t N>
class StageTable {
public:
    void note(const StageRec& r) {
        if (!r.seq) return;
        size_t i = N;
        for (size_t k = 0; k < N; ++k) {
            if (seq_[k].load(std::memory_order_acquire) == r.seq) {
                i = k;
                break;
            }
        }
        if (i == N) {
            i = next_.fetch_add(1, std::memory_order_relaxed) % N;
            if (seq_[i].load(std::memory_order_relaxed)) overwritten_.fetch_add(1, std::memory_order_relaxed);
        }
        seq_[i].store(0, std::memory_order_release);
        mgr_[i].store(r.mgr, std::memory_order_relaxed);
        stage_[i].store(r.stage, std::memory_order_relaxed);
        us_[i].store(r.us, std::memory_order_relaxed);
        tl_[i].store(r.tl, std::memory_order_relaxed);
        owner_[i].store(r.owner, std::memory_order_relaxed);
        whose_[i].store(static_cast<uint8_t>(r.whose), std::memory_order_relaxed);
        seq_[i].store(r.seq, std::memory_order_release);
        noted_.fetch_add(1, std::memory_order_relaxed);
    }
    // A timeline id: 0 and 0xFFFFFFFF (no timeline) never match. Several slots with the id: the most recent start
    // (review of R-B P3-1).
    bool find_tl(uint32_t tl, StageRec& out) const {
        if (!tl || tl == 0xFFFFFFFFu) return false;
        bool any = false;
        for (size_t k = 0; k < N; ++k) {
            const uint64_t s = seq_[k].load(std::memory_order_acquire);
            if (!s || tl_[k].load(std::memory_order_relaxed) != tl) continue;
            StageRec r;
            if (!read(k, s, r)) continue;
            if (!any || r.us > out.us) {
                out = r;
                any = true;
            }
        }
        return any;
    }
    bool find_seq(uint64_t seq, StageRec& out) const {
        if (!seq) return false;
        for (size_t k = 0; k < N; ++k) {
            if (seq_[k].load(std::memory_order_acquire) != seq) continue;
            if (read(k, seq, out)) return true;
        }
        return false;
    }
    // The most recent foreign start (by P1's time).
    bool latest_foreign(StageRec& out) const {
        bool any = false;
        for (size_t k = 0; k < N; ++k) {
            const uint64_t s = seq_[k].load(std::memory_order_acquire);
            if (!s || whose_[k].load(std::memory_order_relaxed) != static_cast<uint8_t>(Whose::Foreign)) continue;
            StageRec r;
            if (!read(k, s, r)) continue;
            if (!any || r.us > out.us) {
                out = r;
                any = true;
            }
        }
        return any;
    }
    uint64_t noted() const { return noted_.load(std::memory_order_relaxed); }
    uint64_t overwritten() const { return overwritten_.load(std::memory_order_relaxed); }
    static constexpr size_t capacity() { return N; }

private:
    bool read(size_t k, uint64_t s, StageRec& out) const {
        StageRec r;
        r.seq = s;
        r.mgr = mgr_[k].load(std::memory_order_relaxed);
        r.stage = stage_[k].load(std::memory_order_relaxed);
        r.us = us_[k].load(std::memory_order_relaxed);
        r.tl = tl_[k].load(std::memory_order_relaxed);
        r.owner = owner_[k].load(std::memory_order_relaxed);
        r.whose = static_cast<Whose>(whose_[k].load(std::memory_order_relaxed));
        std::atomic_thread_fence(std::memory_order_acquire);
        if (seq_[k].load(std::memory_order_relaxed) != s) return false;
        out = r;
        return true;
    }
    std::atomic<uint64_t> seq_[N] = {}, mgr_[N] = {}, stage_[N] = {}, us_[N] = {};
    std::atomic<uint32_t> tl_[N] = {}, owner_[N] = {};
    std::atomic<uint8_t> whose_[N] = {};
    std::atomic<size_t> next_{0};
    std::atomic<uint64_t> noted_{0}, overwritten_{0};
};

// The root of a timeline node's parent chain (+0x98), bounded. rd(addr, out) is the caller's guarded 8-byte read.
// Returns 0 when the node is 0 or a read fails; depth = the links followed; *cut = the chain was longer than max.
template <class Rd>
uint64_t root_of(uint64_t node, Rd&& rd, uint32_t& depth, bool& cut, uint32_t max_depth = kMaxDepth) {
    depth = 0;
    cut = false;
    if (!node) return 0;
    uint64_t cur = node;
    for (;;) {
        uint64_t parent = 0;
        if (!rd(cur + kNode_Parent, parent)) return 0;
        if (!parent) return cur;
        if (depth >= max_depth) {
            cut = true;
            return cur;
        }
        cur = parent;
        ++depth;
    }
}

// ---------------------------------------------------------------- S-B / S-C: the timeline events

enum class Ev : uint8_t { CameraSelector, PlayerCameraPreset, LetterBox, PostProcess, AIDialog, StartLoading, Count };
inline constexpr size_t kEvs = static_cast<size_t>(Ev::Count);
struct EvInfo {
    const char* name;
    uint32_t vt;     // the event class's vtable (RTTI)
    uint32_t col;    // its complete object locator [vt-8]
    uint32_t entry;  // its slot 99 (start), [vt + 99*8]
};
inline constexpr uint32_t kStartSlot = 99;
inline EvInfo ev_info(Ev e) {
    switch (e) {
        case Ev::CameraSelector: return {"CameraSelectorEventData", 0x558B4A8, 0x5DB7610, 0x34CFC20};
        case Ev::PlayerCameraPreset: return {"SequencerPlayerCameraPreset", 0x55F71B8, 0x5DE2538, 0xB27880};
        case Ev::LetterBox: return {"SequencerCustomEventLetterBoxControl", 0x562E0B0, 0x5E08690, 0xC38F30};
        case Ev::PostProcess: return {"SequencerCustomEventPostProcess", 0x562E420, 0x5E085F0, 0xC3A440};
        case Ev::AIDialog: return {"SequencerAIDialog", 0x5629BF0, 0x5E08488, 0xC4D6B0};
        case Ev::StartLoading: return {"SequencerGamePlayEventStartLoadingSequencer", 0x5630920, 0x5E07EE8, 0xC45740};
        default: return {"?", 0, 0, 0};
    }
}

// R-B's two classes on build 1.0.0.3527 [V RTTI + capstone]; the other four are not ported (S-B / S-C refuse there).
inline EvInfo ev_info_3527(Ev e) {
    switch (e) {
        case Ev::CameraSelector: return {"CameraSelectorEventData", 0x59185A0, 0x6187570, 0x37A0620};
        case Ev::PlayerCameraPreset: return {"SequencerPlayerCameraPreset", 0x5987070, 0x61B94F8, 0xC345C0};
        default: return {"?", 0, 0, 0};
    }
}
// 1.0.0.3576 (static): vtables by RTTI name, COLs at [vt-8], slot 99 read from them.
inline EvInfo ev_info_3576(Ev e) {
    switch (e) {
        case Ev::CameraSelector: return {"CameraSelectorEventData", 0x591A668, 0x6189668, 0x37A1320};
        case Ev::PlayerCameraPreset: return {"SequencerPlayerCameraPreset", 0x5988D88, 0x61BBB80, 0xC349E0};
        default: return {"?", 0, 0, 0};
    }
}
// Build 1.0.0.3663 (static, 2026-11-13; never run): vtables by RTTI name (vtable_map_3576_3663.json), COLs at [vt-8]
// (= rtti_3663.json's), slot 99 read from them; slots 97 / 98 of both are the `ret 0` 0x3A6D80.
inline EvInfo ev_info_3663(Ev e) {
    switch (e) {
        case Ev::CameraSelector: return {"CameraSelectorEventData", 0x5996EB0, 0x6205F20, 0x3818600};
        case Ev::PlayerCameraPreset: return {"SequencerPlayerCameraPreset", 0x5A04B08, 0x6238338, 0xC6CC40};
        default: return {"?", 0, 0, 0};
    }
}

// The stage's, timeline's and context's fields R-A and R-B read, per build. 3527 [V capstone]: the processor at +0x60
// (the trampolines; the stage constructor 0x8E26FB3..0x8E26FCB), the owner at +0xA0 (0x221877B), the timeline id at
// +0x2D0 (0xBA9008 / 0xBA906D) and the name at [[stage+0x50]+0x1B8]; the timeline's id +0x1F8 and its listed flag +0x1F1
// (0x37ACC9C, 0x37ACCA5). started +0x2C4 [E, only ever logged].
struct StageLayout {
    uint32_t proc, owner, started, timeline, info, name;
    uint32_t tl_id, tl_listed, vt_timeline;
};
inline constexpr StageLayout kStageLayout2976{kStage_Proc, kStage_Owner, kStage_Started, kStage_Timeline, 0x48, 0x1B8,
                                              kTl_Id, kTl_Listed, kVtTimeline};
inline constexpr StageLayout kStageLayout3527{0x60, 0xA0, 0x2C4, 0x2D0, 0x50, 0x1B8, 0x1F8, 0x1F1, kVtTimeline3527};
// 3576: the same fields (the trampolines' +0x60, the base destructor's bytes, 0xBA9486's +0x2D0 / +0x120, the id's
// +0x1F8 at 0x37AD9A5 / 0x37AD33D: all with 3527's bytes); only the timeline vtable moved.
inline constexpr StageLayout kStageLayout3576{0x60, 0xA0, 0x2C4, 0x2D0, 0x50, 0x1B8, 0x1F8, 0x1F1, kVtTimeline3576};
// Build 1.0.0.3663 (static, 2026-11-13; never run): the stage's timeline id moved +0x2D0 -> +0x2E0 (0xBE0FFD mov edx,
// [rdx+0x2E0] right before P1's call, as 3527's 0xBA906D; the stage constructor 0x90714C0 writes -1 there at 0x9071509).
// started taken as +0x2D4 (the same +0x10) [E: only ever logged]. The rest re-read: the processor +0x60 (the base
// destructor 0x227BB86 with 3527's 23 bytes, the only hit; the constructor 0x907172A; the trampolines), the owner +0xA0
// (0x228876B), the name [[stage+0x50]+0x1B8] (SetInteraction 0x25CFA60 / 0x25CFA69, P1 0x6ECA05), the timeline's id
// +0x1F8 (0x3824BE5 cmp, 0x382457D mov after a lock xadd) and its listed byte +0x1F1 (0x3824BDC).
inline constexpr StageLayout kStageLayout3663{0x60, 0xA0, 0x2D4, 0x2E0, 0x50, 0x1B8, 0x1F8, 0x1F1, kVtTimeline3663};

// Whose timeline an event belongs to.
enum class Tl : uint8_t {
    Foreign,     // the root's id is the timeline of a FOREIGN stage P1 saw
    Own,         // ... of this client's own stage
    World,       // ... of a stage without a character owner
    OwnUnknown,  // ... of a stage P1 saw before this client's own key was known
    NotAStage,   // the root's id is no stage's P1 saw (another kind of timeline, or a stage older than the table)
    Unreadable,  // no node, a read failed, or the chain was cut
    Count
};
inline Tl classify_tl(bool root_ok, bool found, Whose w) {
    if (!root_ok) return Tl::Unreadable;
    if (!found) return Tl::NotAStage;
    switch (w) {
        case Whose::Foreign: return Tl::Foreign;
        case Whose::Own: return Tl::Own;
        case Whose::NotCharacter: return Tl::World;
        default: return Tl::OwnUnknown;
    }
}
inline const char* tl_name(Tl t) {
    switch (t) {
        case Tl::Foreign: return "timeline of a FOREIGN stage";
        case Tl::Own: return "timeline of an own stage";
        case Tl::World: return "timeline of a world stage";
        case Tl::OwnUnknown: return "timeline of a stage judged before the own key was known";
        case Tl::NotAStage: return "timeline of no stage P1 saw";
        case Tl::Unreadable: return "context unreadable";
        default: return "?";
    }
}

// ---------------------------------------------------------------- S-A2: stage functions before P1

enum class When : uint8_t { BeforeP1, AfterP1, Count };

// ---------------------------------------------------------------- S-D: the client's presentation state

struct Present {
    bool world = false;     // [0x6D691E0] read
    uint64_t cam = 0;       // [[cw+0x118]+0x40]
    uint32_t cam_vt = 0;    // RVA of the vtable of the object at cam - 0x28 (0: none / unreadable)
    uint32_t tl_n[3] = {};  // the player's three lists' counts (kTlLists order)
    bool de8_ok = false;
    uint32_t de8 = 0;       // [[cw]+0xDE8]
    uint8_t m_block = 0xFF; // M+0x230 (0xFF: unknown)
    uint8_t x_block = 0xFF; // the latest live foreign stage's G+0x230 (0xFF: none / not a stage manager)
    uint64_t fseq = 0;      // that stage's sequencer (0: no live foreign stage)
    uint8_t ftl = 0;        // its timeline in the player: 0 not found, 1..3 the list, 0xFF unreadable
    uint8_t fplay = 0xFF;   // that timeline's +0xDC (0xFF: not found)
};
enum PresentField : uint32_t {
    kFWorld = 1u << 0,
    kFCam = 1u << 1,
    kFCamVt = 1u << 2,
    kFTlCounts = 1u << 3,  // counted, but alone never makes a line (it moves with every timeline of the game)
    kFDe8 = 1u << 4,
    kFMBlock = 1u << 5,
    kFXBlock = 1u << 6,
    kFForeign = 1u << 7,
    kFForeignTl = 1u << 8,
    kFForeignPlay = 1u << 9,
};
inline uint32_t diff(const Present& a, const Present& b) {
    uint32_t d = 0;
    if (a.world != b.world) d |= kFWorld;
    if (a.cam != b.cam) d |= kFCam;
    if (a.cam_vt != b.cam_vt) d |= kFCamVt;
    if (a.tl_n[0] != b.tl_n[0] || a.tl_n[1] != b.tl_n[1] || a.tl_n[2] != b.tl_n[2]) d |= kFTlCounts;
    if (a.de8_ok != b.de8_ok || a.de8 != b.de8) d |= kFDe8;
    if (a.m_block != b.m_block) d |= kFMBlock;
    if (a.x_block != b.x_block) d |= kFXBlock;
    if (a.fseq != b.fseq) d |= kFForeign;
    if (a.ftl != b.ftl) d |= kFForeignTl;
    if (a.fplay != b.fplay) d |= kFForeignPlay;
    return d;
}
// The changes that make a line (every one is counted).
inline constexpr uint32_t kLineFields = ~static_cast<uint32_t>(kFTlCounts);
inline bool makes_line(uint32_t d) { return (d & kLineFields) != 0; }

// S-D's replica of 0x34DC130 (up to 3 x 512 entries, 2-3 guarded reads each) runs only when the latest live foreign
// stage changed or every kSdTlEvery frames; in between the last result is kept (revision.md B3: the cost per frame).
inline constexpr uint32_t kSdTlEvery = 16;
inline bool sd_scan_due(uint64_t fseq, uint64_t last_fseq, uint32_t frames_since_scan) {
    return fseq != last_fseq || frames_since_scan >= kSdTlEvery;
}

// A foreign stage counts as live for S-D while its stage still reads back its sequencer and owner, for at most this
// long after its start (a stage older than that is not "the latest" any more).
inline constexpr uint64_t kForeignLiveUs = 600'000'000;  // 10 min
inline bool foreign_live(const StageRec& r, uint64_t now_us, uint64_t seq_read, uint32_t owner_read) {
    return r.seq && seq_read == r.seq && owner_read == r.owner && now_us >= r.us && now_us - r.us <= kForeignLiveUs;
}

// S-B's callers (revision.md B1): the RVA of each event start's return address ([rsp] at the entry), per class, in a
// few lock-free slots; the letter box's 0xC38F30 is also its vtable's slot 67 (a property change, not a start), and its
// callers tell the two apart. Any thread; a full table counts the rest as "other".
template <size_t N>
class CallerCounts {
public:
    void add(uint32_t rva) {
        for (size_t k = 0; k < N && rva; ++k) {  // 0 (a caller outside the exe / unreadable): "other"
            uint32_t cur = rva_[k].load(std::memory_order_acquire);
            if (cur == 0 && rva_[k].compare_exchange_strong(cur, rva, std::memory_order_acq_rel)) cur = rva;
            if (cur == rva) {
                n_[k].fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        other_.fetch_add(1, std::memory_order_relaxed);
    }
    uint32_t rva(size_t k) const { return k < N ? rva_[k].load(std::memory_order_acquire) : 0; }
    uint64_t n(size_t k) const { return k < N ? n_[k].load(std::memory_order_relaxed) : 0; }
    uint64_t other() const { return other_.load(std::memory_order_relaxed); }
    static constexpr size_t capacity() { return N; }

private:
    std::atomic<uint32_t> rva_[N] = {};
    std::atomic<uint64_t> n_[N] = {};
    std::atomic<uint64_t> other_{0};
};

// ---------------------------------------------------------------- cost of a probe callback (QPC ticks)

class Cost {
public:
    void add(uint64_t ticks) {
        n_.fetch_add(1, std::memory_order_relaxed);
        total_.fetch_add(ticks, std::memory_order_relaxed);
        uint64_t m = max_.load(std::memory_order_relaxed);
        while (ticks > m && !max_.compare_exchange_weak(m, ticks, std::memory_order_relaxed)) {
        }
    }
    uint64_t n() const { return n_.load(std::memory_order_relaxed); }
    uint64_t total() const { return total_.load(std::memory_order_relaxed); }
    uint64_t max() const { return max_.load(std::memory_order_relaxed); }

private:
    std::atomic<uint64_t> n_{0}, total_{0}, max_{0};
};
// ticks -> nanoseconds with the QPC frequency (0 frequency: 0).
inline uint64_t ticks_ns(uint64_t ticks, uint64_t freq) {
    if (!freq) return 0;
    return static_cast<uint64_t>(static_cast<long double>(ticks) * 1e9L / static_cast<long double>(freq));
}

}  // namespace cdmp::session2::gpr
