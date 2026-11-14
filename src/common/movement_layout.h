#pragma once
// Wire payload layouts, not the game's in-memory structs. 3527 evidence:
// tools/porting/data/payload_abi_3527.json (sequential native stream readers).
// Native payloads remain intact; readers/writers select offsets explicitly.
#include "common/native_opcode.h"
#include <cstddef>
#include <cstdint>

namespace cdmp::movement {
using Build = native_opcode::Build;
struct Layout {
    size_t move_req, move_ack, action;
    size_t pos, quat, aux, local_pos, local_quat, local_scale;
    size_t parent, world_pos, world_quat, world_end, timestamp, request_history;
    size_t action_target; // relative to StartAction block B
    size_t move_field_record;
};
inline constexpr Layout k2976{514, 235, 725, 4, 16, 32, 76, 88, 104,
                              140, 148, 160, 212, 213, 234, 222, 48};
inline constexpr Layout k3527{518, 239, 729, 196, 180, 208, 4, 16, 32,
                              68, 76, 88, 140, 212, 238, 226, 56};
inline constexpr const Layout* layout(Build build) noexcept {
    // 3576: the Troc catalogue did not change (troc_mapping_3549_3576.json: 0 size changes), so 3527's payloads.
    // Build 1.0.0.3663 (static, 2026-11-13; never run): opcodes renumbered, payload readers unchanged: the MoveActorReq /
    // MoveActorAck / StartActionReq / StartActionAck / MoveFieldAck / LoadingFieldDataAck handlers and their MoveData,
    // StartAction A/B, Path, Transform and MoveField entry readers are 3527's instruction for instruction with relative
    // operands masked (game::wire_build() in build_profile.h lists the addresses). So 3527's payloads.
    return build == Build::v2976 ? &k2976
           : build == Build::v3527 || build == Build::v3576 || build == Build::v3663 ? &k3527
                                                                                  : nullptr;
}
inline constexpr size_t action_shift(bool ack) noexcept { return ack ? 139 : 138; }
// The logical opcode selects a message; the build selects its native payload.
inline constexpr size_t payload_size(Build build, uint16_t opcode) noexcept {
    const auto* l = layout(build);
    if (!l) return 0;
    return opcode == 2556 ? l->move_req : opcode == 2697 ? l->move_ack :
           (opcode == 2223 || opcode == 2991) ? l->action : 0;
}
inline constexpr size_t position_offset(Build build, uint16_t opcode) noexcept {
    const auto* l = layout(build);
    if (!l || !payload_size(build, opcode)) return 0;
    return l->pos + (opcode == 2223 ? action_shift(false) : opcode == 2991 ? action_shift(true) : 0);
}
} // namespace cdmp::movement
