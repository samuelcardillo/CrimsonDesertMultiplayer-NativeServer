#pragma once

#include "common/native_opcode_mapping_id.h"
#include "common/troc_frame.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace cdmp::native_opcode {

// v3576 (1.0.0.3576, 2026-11-06): the Troc catalogue is 3527's, message for message (all 1175 RTTI-named singletons
// resolved, 0 opcode and 0 size changes: tools/porting/data/troc_mapping_3549_3576.json), so it shares kEntries3527.
// v3663 (1.0.0.3663, 2026-11-13): the same 1175 messages renumbered (1066 of them; kinds and sizes unchanged) plus 4 new
// ones (tools/porting/data/opcode_mapping_3576_3663.json): its own table, kEntries3663; logical IDs unchanged.
enum class Build : uint32_t { unsupported = 0, v2976 = 2976, v3527 = 3527, v3576 = 3576, v3663 = 3663 };

// Logical IDs preserve the 2976 catalog. Verified additions in 3527 use
// 0x8000 | native ID; that namespace is unavailable to unknown messages.
struct Entry {
    uint16_t logical;
    uint16_t native;
    uint32_t kind;
    std::string_view name;
};

// Sorted by native ID. Unsupported builds return an empty catalog.
std::span<const Entry> entries(Build build) noexcept;
std::optional<uint16_t> decode(Build build, uint16_t native) noexcept;
std::optional<uint16_t> encode(Build build, uint16_t logical) noexcept;

// Native boundary only: controls 1/2, unknown IDs, invalid directions, and
// malformed packets fail closed. Failure leaves the complete buffer intact.
// Only the first two bytes are changed. Scope payloads remain opaque native
// bytes, so peers still need the SAME native build and mapping identity.
// Direction validates the special short 2001/2002/2003 forms; ordinary
// message admission/channel policy belongs to the caller.
bool decode_packet(Build build, std::span<uint8_t> packet, troc::Dir dir) noexcept;
bool encode_packet(Build build, std::span<uint8_t> packet, troc::Dir dir) noexcept;
std::optional<std::vector<uint8_t>> decode_copy(Build build, std::span<const uint8_t> packet, troc::Dir dir);
std::optional<std::vector<uint8_t>> encode_copy(Build build, std::span<const uint8_t> packet, troc::Dir dir);

} // namespace cdmp::native_opcode
