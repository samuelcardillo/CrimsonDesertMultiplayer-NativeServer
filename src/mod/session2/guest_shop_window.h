#pragma once
// [session2] guest_shop_window = 0 (default) | 1, GUEST, builds 3549, 3576 and 3663 (static). The shopkeeper's buy window on the guest.
//
// On the host a shopkeeper's window comes from its scene: "Buy" in the menu sends the StageChartUIControl events
// (live, 2026-11-06, shop_ui_trace) to window 'NpcStoreBuyView' / control 'selector-stagechart-self': type 9 (the
// shopkeeper's actor key as text) -> the window UIGamePlayControlRootNpcBuyStore2 (vtable 0x59ECA30) takes the NPC in
// vf+0x498 = 0xE8BD20(window, {handle*, 1}, cmd) (store and stock follow from the NPC: +0x2F0 its key, +0x2F4 its
// CharacterKey), then type 14 -> vf+0x490 = 0xE8C020(window, 0, 0, cmd 0xE) shows it. The guest never gets those events
// (the scene is the host's; docs/ESTADO-3527.md). With 1, the guest's own press on a shopkeeper (interact_gate's press
// hook, the game's frame thread, right after the native handler) does the same two calls on its own client:
//   - the window is found once, 90 s after the world is up, by a scan of the private RW memory for its vtable; of the
//     instances, the one whose body ([[w+8]+0x100]) is "NpcStoreBuyBody" (the others: trade store, stables);
//   - handle: 0x71C0E0(0, &h, npc key) (0x20 bytes; released with its vf0(h, 0), as the subscriber 0xFFAB10 does);
//   - shown only if the window then names that NPC (+0x2F0) and was not shown already (+0x130).
// Every call is SEH-guarded. Buying from it needs store_gate=1 on both PCs.

#include <cstdint>
#include <string>

namespace cdmp::session2 {

void guest_shop_window_start(const std::string& mode, bool guest);
// interact_gate's press hook, after the native press handler returned (frame thread): the guest pressed an NPC.
void guest_shop_window_on_press(uintptr_t npc_actor, uint32_t npc_key) noexcept;
// guest_x_veto's InputBlock hook for a scene of this client's own manager (frame thread): the shop scene's UI phase
// has begun (guest_shop_branch's copy in branch 6); a window opened by the press within 8 s is hidden and shown again
// there (live 11:22: shown at the press, before the phase, its element was flagged visible but nothing was drawn).
void guest_shop_window_on_scene() noexcept;
// The press's scene ([entry+0x20]) for the dispatched events' SequencerStageId (mode 2).
void guest_shop_window_note_stage(uint64_t stage) noexcept;

}  // namespace cdmp::session2
