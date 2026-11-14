#include "common/native_opcode.h"

#include <algorithm>
#include <array>

namespace cdmp::native_opcode {
namespace {
#include "common/native_opcode_table.inc"

uint16_t read16(std::span<const uint8_t> packet, size_t offset = 0) noexcept {
    return static_cast<uint16_t>(packet[offset] | (packet[offset + 1] << 8));
}

bool valid_shape(std::span<const uint8_t> packet, uint16_t logical, troc::Dir dir) noexcept {
    if (dir != troc::Dir::ToHostServer && dir != troc::Dir::ToGuestClient) return false;
    if (packet.size() < troc::kInternalHeaderSize || packet.size() > troc::kMaxPacketSize) return false;
    if (logical == troc::kOpLogoutSessionReq) {
        return dir == troc::Dir::ToHostServer && packet[2] == 0xFF && packet.size() == troc::kInternalHeaderSize;
    }
    if (logical == troc::kOpLogoutSessionAck || logical == troc::kOpLogoutUserAck) {
        return dir == troc::Dir::ToGuestClient && packet[2] == 0xFF && packet.size() == troc::kLogoutAckSize;
    }
    return packet.size() >= troc::kHeaderSize && read16(packet, 3) == packet.size() - troc::kHeaderSize;
}

std::optional<uint16_t> translated(Build build, std::span<const uint8_t> packet, troc::Dir dir, bool to_native) noexcept {
    if (packet.size() < 2) return std::nullopt;
    const uint16_t original = read16(packet);
    const auto replacement = to_native ? encode(build, original) : decode(build, original);
    if (!replacement || !valid_shape(packet, to_native ? original : *replacement, dir)) return std::nullopt;
    return replacement;
}

bool mutate(Build build, std::span<uint8_t> packet, troc::Dir dir, bool to_native) noexcept {
    const auto replacement = translated(build, packet, dir, to_native);
    if (!replacement) return false;
    packet[0] = static_cast<uint8_t>(*replacement);
    packet[1] = static_cast<uint8_t>(*replacement >> 8);
    return true;
}

std::optional<std::vector<uint8_t>> copy(Build build, std::span<const uint8_t> packet, troc::Dir dir, bool to_native) {
    const auto replacement = translated(build, packet, dir, to_native);
    if (!replacement) return std::nullopt;
    std::vector<uint8_t> result(packet.begin(), packet.end());
    result[0] = static_cast<uint8_t>(*replacement);
    result[1] = static_cast<uint8_t>(*replacement >> 8);
    return result;
}
} // namespace

std::span<const Entry> entries(Build build) noexcept {
    switch (build) {
    case Build::v2976: return kEntries2976;
    case Build::v3527:
    case Build::v3576: return kEntries3527;  // the same catalogue (native_opcode.h)
    case Build::v3663: return kEntries3663;
    default: return {};
    }
}

std::optional<uint16_t> decode(Build build, uint16_t native) noexcept {
    const auto catalog = entries(build);
    const auto it = std::lower_bound(catalog.begin(), catalog.end(), native,
        [](const Entry& entry, uint16_t id) { return entry.native < id; });
    if (it == catalog.end() || it->native != native) return std::nullopt;
    return it->logical;
}

std::optional<uint16_t> encode(Build build, uint16_t logical) noexcept {
    if (build == Build::v2976) return decode(build, logical); // Identity catalog, including removed messages.
    if (build == Build::v3663) {
        const auto it = std::lower_bound(kLogicalOrder3663.begin(), kLogicalOrder3663.end(), logical,
            [](uint16_t index, uint16_t id) { return kEntries3663[index].logical < id; });
        if (it == kLogicalOrder3663.end() || kEntries3663[*it].logical != logical) return std::nullopt;
        return kEntries3663[*it].native;
    }
    if (build != Build::v3527 && build != Build::v3576) return std::nullopt;
    const auto it = std::lower_bound(kLogicalOrder3527.begin(), kLogicalOrder3527.end(), logical,
        [](uint16_t index, uint16_t id) { return kEntries3527[index].logical < id; });
    if (it == kLogicalOrder3527.end() || kEntries3527[*it].logical != logical) return std::nullopt;
    return kEntries3527[*it].native;
}

bool decode_packet(Build build, std::span<uint8_t> packet, troc::Dir dir) noexcept { return mutate(build, packet, dir, false); }
bool encode_packet(Build build, std::span<uint8_t> packet, troc::Dir dir) noexcept { return mutate(build, packet, dir, true); }
std::optional<std::vector<uint8_t>> decode_copy(Build build, std::span<const uint8_t> packet, troc::Dir dir) { return copy(build, packet, dir, false); }
std::optional<std::vector<uint8_t>> encode_copy(Build build, std::span<const uint8_t> packet, troc::Dir dir) { return copy(build, packet, dir, true); }

} // namespace cdmp::native_opcode
