#pragma once
// [session2] interact_gate = 0 (default) | probe | 1, BOTH roles (bypass on the guest only), builds 3549, 3576 and 3663 (static).
// interact_gate_errors = hex error values (the runtime values of eErrNo* globals) the guest lets pass with 1.
// interact_gate_pass = the result code written then (default 3).
//
// The client's "may I start this interaction" evaluation, called when an interaction key is pressed (and by a pre-check):
// 0x22E62A0 (a 5-byte jmp thunk into the protected section, 0xCAF4350 on 3549), called from 0xBCCD50 at 0xBCCE64 and
// from 0xBCD5E0 at 0xBCD656 with rcx = an interaction component, rdx = the target actor, r8 = the interaction entry
// ([r8+0x10] u16 its index), r9 = the result: u8 code at +0, u32 error at +4. The caller 0xBCCD50 (capstone 2026-11-06):
// code < 2 -> fails with the error (nothing is sent), == 2 -> another branch, > 2 -> goes on to the 2671 sender 0xABAE00.
// The prompt (FindManualInteractionTargetProcessor) runs the same checks in mode 0 and shows; the press runs them in mode
// 3, where conditions of categories 2 / 3 are evaluated too. Live on 3549: the guest gets the prompts of the host's
// world objects ("Chair E Carry", "Empty Bottle E Buy") and, with guest_x_interaction_stage=1, of the shopkeepers
// ("R Shop"), but the press sends nothing; with the object's controller (+0x90) set to the guest's user it works.
//
// 1 (guest) also hooks the press handler 0xBCCD50: during one press on an actor of a listed type that another user
// controls, its controller (+0x90) is this client's, put back right after. Live 2026-11-06: a "Buy" at a Hernand
// stall (hold E) then sends 2671 -> success, 2720 -> success, CatchActionResultAck; the item is acquired and the
// guest's money goes down by its price (Rosemary, 8 copper).
// probe: every call that does not pass (code <= 2) is logged once per (target, entry index, code, error, caller), with
// counts; the passes are counted (a few logged) so the host shows what success looks like. 1 (guest): as probe, and a
// result with code < pass whose error is listed becomes {pass, 0}. The server still validates the 2671 / 2720.

#include <string>

namespace cdmp::session2 {

// mod.cpp's worker, both roles. Nothing for 0.
// interact_gate_types = actor types the guest's press swap applies to (comma list, default "7": world objects).
void interact_gate_start(const std::string& mode, const std::string& errors, const std::string& pass,
                         const std::string& types, bool guest);

}  // namespace cdmp::session2
