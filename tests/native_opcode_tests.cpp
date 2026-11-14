#include "common/native_opcode.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <vector>

namespace {
int failures = 0;
#define CHECK(condition) do { if (!(condition)) { std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); ++failures; } } while (0)
namespace codec = cdmp::native_opcode;
namespace troc = cdmp::troc;
using codec::Build;
using Bytes = std::vector<uint8_t>;
constexpr auto host = troc::Dir::ToHostServer;
constexpr auto guest = troc::Dir::ToGuestClient;

uint16_t opcode(const Bytes& packet) { return static_cast<uint16_t>(packet[0] | (packet[1] << 8)); }
Bytes packet_for(uint16_t op) {
    if (op == 2001) return {0xD1, 0x07, 0xFF};
    if (op == 2002 || op == 2003) return {static_cast<uint8_t>(op), 0x07, 0xFF, 0xAB, 0xCD, 0xEF, 0x12};
    const std::array<uint8_t, 8> payload{0, 1, 2, 0xFF, 0xD1, 0x07, 0xE4, 0x09};
    return troc::make(op, -1, payload);
}

void catalogs_roundtrip() {
    CHECK(codec::entries(Build::v2976).size() == 1115);
    CHECK(codec::entries(Build::v3527).size() == 1175);
    CHECK(codec::entries(Build::v3663).size() == 1179);
    size_t additions = 0, additions3663 = 0;
    for (const Build build : {Build::v2976, Build::v3527, Build::v3663}) {
        std::array<bool, 65536> logical_seen{}, native_seen{};
        uint16_t last = 0;
        for (const auto& entry : codec::entries(build)) {
            CHECK(entry.native > last);
            last = entry.native;
            CHECK(!logical_seen[entry.logical]);
            CHECK(!native_seen[entry.native]);
            logical_seen[entry.logical] = native_seen[entry.native] = true;
            CHECK(codec::decode(build, entry.native) == entry.logical);
            CHECK(codec::encode(build, entry.logical) == entry.native);
            CHECK(!entry.name.empty());
            if (entry.logical >= 0xC000) {
                ++additions3663;
                CHECK(build == Build::v3663);
                CHECK(entry.logical == (0xC000 | entry.native));
                CHECK(!codec::encode(Build::v3527, entry.logical));
            } else if (entry.logical >= 0x8000) {
                if (build == Build::v3527) ++additions;
                CHECK(build == Build::v3527 || build == Build::v3663);
                CHECK(!codec::encode(Build::v2976, entry.logical));
                // 3527's additions keep their logical ID in 3663 (0x8000 | the 3527 native ID).
                if (build == Build::v3527) {
                    CHECK(entry.logical == (0x8000 | entry.native));
                    CHECK(codec::encode(Build::v3663, entry.logical).has_value());
                }
            }
            const auto dir = entry.logical == 2001 ? host : guest;
            const auto logical = packet_for(entry.logical);
            auto native = codec::encode_copy(build, logical, dir);
            CHECK(native.has_value());
            if (!native) continue;
            CHECK(opcode(*native) == entry.native);
            CHECK(std::equal(native->begin() + 2, native->end(), logical.begin() + 2));
            const auto decoded = codec::decode_copy(build, *native, dir);
            CHECK(decoded && *decoded == logical);
            CHECK(codec::decode_packet(build, *native, dir));
            CHECK(*native == logical);
            CHECK(codec::encode_packet(build, *native, dir));
            CHECK(opcode(*native) == entry.native);
        }
        // Exhaust the entire ID space: unknown IDs cannot acquire identity mappings.
        for (uint32_t id = 0; id <= 0xFFFF; ++id) {
            CHECK(codec::decode(build, static_cast<uint16_t>(id)).has_value() == native_seen[id]);
            CHECK(codec::encode(build, static_cast<uint16_t>(id)).has_value() == logical_seen[id]);
        }
    }
    CHECK(additions == 67);
    CHECK(additions3663 == 4);
    // Every 3527 message has a 3663 native ID and the same name and kind.
    for (const auto& entry : codec::entries(Build::v3527)) {
        const auto native = codec::encode(Build::v3663, entry.logical);
        CHECK(native.has_value());
        if (!native) continue;
        const auto& all = codec::entries(Build::v3663);
        const auto it = std::lower_bound(all.begin(), all.end(), *native,
            [](const codec::Entry& e, uint16_t id) { return e.native < id; });
        CHECK(it != all.end() && it->name == entry.name && it->kind == entry.kind);
    }
}

void semantic_collisions() {
    CHECK(codec::encode(Build::v3527, 2556) == 2833); // MoveActorReq.
    // 3576 shares 3527's catalogue (troc_mapping_3549_3576.json: 0 opcode and size changes).
    CHECK(codec::entries(Build::v3576).size() == codec::entries(Build::v3527).size());
    CHECK(codec::encode(Build::v3576, 2556) == 2833);
    CHECK(codec::decode(Build::v3576, 2833) == 2556);
    CHECK(codec::encode(Build::v3576, 2991) == 2552);
    CHECK(codec::decode(Build::v3527, 2833) == 2556);
    CHECK(codec::decode(Build::v2976, 2556) == 2556);
    CHECK(codec::decode(Build::v3527, 2556).has_value());
    CHECK(codec::decode(Build::v3527, 2556) != 2556); // Same number means a different message.
    CHECK(codec::encode(Build::v3527, 2697) == 3094); // MoveActorAck.
    CHECK(codec::encode(Build::v3527, 2223) == 2202); // StartActionReq.
    CHECK(codec::encode(Build::v3527, 2991) == 2552); // StartActionAck.
    // 3663 (opcode_mapping_3576_3663.json): the same messages under new numbers.
    CHECK(codec::encode(Build::v3663, 2556) == 2790); // MoveActorReq.
    CHECK(codec::encode(Build::v3663, 2697) == 3008); // MoveActorAck.
    CHECK(codec::encode(Build::v3663, 2223) == 2431); // StartActionReq.
    CHECK(codec::encode(Build::v3663, 2991) == 2800); // StartActionAck.
    CHECK(codec::decode(Build::v3663, 2833) != 2556); // 3576's MoveActorReq number is another message in 3663.
    CHECK(codec::decode(Build::v3663, 2005) == codec::decode(Build::v3527, 2005)); // ActorLoadDataAck kept 2005.
    CHECK(codec::decode(Build::v3663, 2601) == (0xC000 | 2601)); // GameEventGiveUpStageAck, new in 3663.
    for (const uint16_t removed : std::array<uint16_t, 7>{3045, 2584, 2296, 2141, 2686, 2198, 2097}) {
        CHECK(codec::encode(Build::v2976, removed) == removed);
        CHECK(!codec::encode(Build::v3527, removed));
        auto packet = packet_for(removed);
        const auto before = packet;
        CHECK(!codec::encode_packet(Build::v3527, packet, guest));
        CHECK(packet == before);
    }
}

void reject(Bytes packet, troc::Dir dir = guest, Build build = Build::v3527) {
    const auto before = packet;
    CHECK(!codec::decode_packet(build, packet, dir));
    CHECK(packet == before);
    CHECK(!codec::encode_packet(build, packet, dir));
    CHECK(packet == before);
    CHECK(!codec::decode_copy(build, packet, dir));
    CHECK(!codec::encode_copy(build, packet, dir));
}

void malformed_and_internal() {
    reject({}); reject({0}); reject({0xD5, 0x07}); reject({0xD5, 0x07, 0xFF});
    reject({0xD5, 0x07, 0xFF, 0}); // Truncated length.
    reject({0xD5, 0x07, 0xFF, 1, 0}); // Truncated payload.
    reject({0xD5, 0x07, 0xFF, 0, 0, 1}); // Trailing byte.
    reject(troc::make(1, -1, {})); reject(troc::make(2, -1, {}));
    reject(troc::make(0, -1, {})); reject(troc::make(0xFFFF, -1, {}));
    reject(troc::make(2005, -1, {}), static_cast<troc::Dir>(0));
    reject(troc::make(2005, -1, {}), static_cast<troc::Dir>(3));
    reject(troc::make(2005, -1, {}), guest, Build::unsupported);
    reject(troc::make(2005, -1, {}), guest, static_cast<Build>(1));
    CHECK(codec::entries(Build::unsupported).empty());
    CHECK(!codec::decode(Build::unsupported, 2005));
    CHECK(!codec::encode(Build::unsupported, 2005));
    for (const uint16_t op : std::array<uint16_t, 3>{2001, 2002, 2003}) {
        const auto dir = op == 2001 ? host : guest;
        const auto good = packet_for(op);
        CHECK(codec::decode_copy(Build::v3527, good, dir) == good);
        CHECK(codec::encode_copy(Build::v3527, good, dir) == good);
        reject(good, dir == host ? guest : host);
        auto bad = good; bad[2] = 0; reject(bad, dir);
        bad = good; bad.pop_back(); reject(bad, dir);
        bad = good; bad.push_back(0); reject(bad, dir);
        reject(troc::make(op, -1, {}), dir);
    }
    const Bytes max_payload(troc::kMaxPacketSize - troc::kHeaderSize, 0xAA);
    const auto maximum = troc::make(2005, -1, max_payload);
    CHECK(codec::decode_copy(Build::v3527, maximum, guest) == maximum);
    CHECK(codec::encode_copy(Build::v3527, maximum, guest) == maximum);
    reject(troc::make(2005, -1, Bytes(max_payload.size() + 1, 0xAA)));
}

void scope_payload_is_opaque() {
    // Deliberately include native opcode bytes and an incomplete nested packet.
    // They could straddle fragments; the codec must never recurse into them.
    const Bytes scope_payload{1, 0x44, 0x33, 0x22, 0x11, 0xE4, 0x09, 0xFF, 5, 0, 0x07, 0x08, 3};
    const auto native = troc::make(2046, 2, scope_payload);
    const auto logical = codec::decode_copy(Build::v3527, native, guest);
    CHECK(logical.has_value());
    if (!logical) return;
    CHECK(opcode(*logical) == 2042);
    CHECK(std::equal(logical->begin() + 2, logical->end(), native.begin() + 2));
    CHECK(codec::encode_copy(Build::v3527, *logical, guest) == native);
    CHECK(opcode(native) == 2046); // Copy API never mutates input.
}
} // namespace

int main() {
    catalogs_roundtrip();
    semantic_collisions();
    malformed_and_internal();
    scope_payload_is_opaque();
    std::printf("Native opcode tests: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
