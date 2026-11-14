#pragma once
// Wire protocol shared by the mod (cdmp.asi) and the tools (peer simulator).
//
// Every datagram is: [16-byte header][body]. All integers and floats are
// little-endian. Fields are written one by one (no struct memcpy) so the
// layout never depends on compiler packing.
//
// Header: magic u32 | version u16 | type u8 | reserved u8 | seq u32 | send_ms u32

#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

static_assert(std::endian::native == std::endian::little,
              "Protocol encoding assumes a little-endian host");

namespace cdmp::proto {

inline constexpr uint32_t kMagic = 0x504D4443;  // bytes "CDMP"
// 5: session nonce in Hello/Welcome. 6: RelData stream id (ordered delivery),
// mod build in Welcome, GuestHit arrows keyed by their ProjectileInfo, enemy
// messages name the receiver itself with kSelfMarker. 7: the gear in
// SpawnInfo keeps a removal for each slot the sender's template had filled
// (equip_state.h); a v6 peer would lose them. 8: RelKind::TrocFrame (option D,
// common/troc_frame.h). 9: logical Troc IDs with a native-build/map handshake;
// v8 game traffic contains native IDs and must never be interpreted as logical.
// 10: PlayerState ends with the character's key and what it stands on (anchor: an actor key and the character's pose
// local to it), for ship passengers (session2/vehicle_follow.h).
inline constexpr uint16_t kVersion = 10;
// Hello and Welcome start the same in every version from 5 (name, then the
// rest), so a peer with another version is recognised and reported instead
// of being ignored in silence.
inline constexpr size_t kHeaderSize = 16;
inline constexpr size_t kMaxPacketSize = 1200;  // stays under typical MTU
inline constexpr size_t kMaxNameLen = 32;

enum class Type : uint8_t {
    Hello = 1,    // client -> peer, repeated until Welcome arrives
    Welcome = 2,  // peer -> client
    Bye = 3,      // either side, best effort
    Ping = 4,
    Pong = 5,
    PlayerState = 16,
    GameEvent = 17,  // one of the player's internal game messages (unreliable)
    RelData = 18,    // fragment of a reliable message
    RelAck = 19,     // acknowledges one RelData fragment
};

// Payload of a GameEvent: the sender's own client->server game message
// (MoveActorReq...) exactly as the game produced it, with the sender's own
// actor key. The receiver turns it into the matching Ack for its copy of the
// sender. Formats: docs/research/mirror-ack-formats.md.
enum class EventKind : uint8_t {
    Move = 1,         // MoveActorReq, 514 bytes
    StartAction = 2,  // StartActionReq, 725 bytes
    Rotate = 3,       // RotateActorReq, 176 bytes
    WallUp = 4,       // UpdateWallUpData, 132 bytes (built from memory)
    Equip = 5,        // OtherEquipItemAck payload (9 + 6n bytes); sent reliably
    Docking = 6,      // ChangeDockingSocketByFrameEventAck payload (16 bytes): weapon hand/back
    Relay = 7,        // u16 opcode + a server->client message about the sender (HP, buffs...)
    Damage = 8,       // the sender hurt an enemy in its world (DamageEvent, 25 bytes)
    EnemyAct = 9,     // u16 Req opcode + StartActionReq/RotateActorReq of one of the sender's
                      // enemies the receiver has a copy of (keys already translated)
    EnemyPos = 10,    // EnemyPosEvent: where such an enemy is (read from memory, 15 Hz)
    PlayerHit = 11,   // one of the sender's enemies hit the receiver's copy (player_hits.h):
                      // u32 attacker copy | u32 action hash | i64 damage x1000 (0 = unknown)
    GuestHit = 12,    // the sender hit the receiver's enemy through its copy (guest_hits.h):
                      // u32 copy key | u32 action hash | u32 frame | u8 accessor type |
                      // i32 sender's base damage x1000 (0 = unknown); arrows (type 1):
                      // ProjectileInfo key | a << 8 | b
};
inline constexpr uint8_t kMaxEventKind = 12;  // newer kinds decode; the session drops them

// Wire: u32 copy key | u64 game clock ms | f32 x, y, z | f32 qx, qy, qz, qw.
inline constexpr size_t kEnemyPosEventSize = 40;

// Mirrored damage: the receiver applies it to ITS enemy of the same type
// nearest to `pos` (each world has its own enemies and keys).
// Wire: u32 enemy type | f32 x, y, z | i64 hp delta x1000 (negative) | u8 killed.
inline constexpr size_t kDamageEventSize = 25;
inline constexpr size_t kMaxEventPayload = 1024;

// Reliable message kinds (RelData.kind).
enum class RelKind : uint8_t {
    Spawn = 1,    // SpawnInfo: what the receiver needs to load a copy of us
    Despawn = 2,  // u32 generation of the spawn to remove
    Equip = 3,    // OtherEquipItemAck payload: a change of equipment
    Relay = 4,    // like EventKind::Relay, for messages that must not get lost (death...)
    EnemySpawn = 5,   // a copy of one of the sender's enemies (enemy_relay.h)
    EnemyRemove = 6,  // n x u32 copy key
    EnemyState = 7,   // u16 opcode + server->client message about such a copy (HP, death)
    TrocFrame = 8,    // option D: a batch of raw game packets (troc::encode_batch)
};
inline constexpr uint8_t kMaxRelKind = 8;  // newer kinds are acknowledged and dropped

// In a sender's enemy messages, the receiver itself (the sender's copy of
// the receiver, 0xA010F001 there; the receiver's own player key is not
// known to the sender). The receiver writes its own player key back.
inline constexpr uint32_t kSelfMarker = 0xA010F00F;
inline constexpr size_t kRelChunk = 1100;  // payload bytes per fragment
inline constexpr size_t kMaxRelMessage = 256 * 1024;

struct Vec3 {
    float x = 0, y = 0, z = 0;
};
struct Quat {
    float x = 0, y = 0, z = 0, w = 1;
};

enum StateFlags : uint8_t {
    kStateSynthetic = 1 << 0,  // position is generated, not read from the game
};

// `nonce` is random per session: a repeated Hello with the same nonce is a
// duplicate (Steam may deliver several queued ones at once), a different one
// means the other side restarted.
struct Hello {
    std::string name;
    uint32_t mod_build = 0;
    uint32_t nonce = 0;
};
struct Welcome {
    std::string name;
    uint32_t nonce = 0;
    uint32_t mod_build = 0;  // 0 = not a mod (cdmp_peer's relay)
};
struct Bye {};
struct Ping {
    uint32_t origin_ms = 0;
};
struct Pong {
    uint32_t origin_ms = 0;  // copied from the Ping being answered
};
struct PlayerState {
    Vec3 pos;
    Quat rot;
    float health = 0;      // current HP
    float health_max = 0;  // 0 = unknown
    uint8_t flags = 0;
    // The sender's character in the game's own terms (0 = not known), and what it stands on: the key of its hierarchy
    // parent (0 = nothing) with the character's pose local to that parent. The game's server sends the other player
    // blank Moves for a character on a ship's deck, so this is the only way the receiver learns where it stands.
    uint32_t self_key = 0;
    uint32_t anchor = 0;
    Vec3 anchor_pos;
    Quat anchor_rot;
};

struct GameEvent {
    EventKind kind = EventKind::Move;
    std::vector<uint8_t> payload;
};
struct RelData {
    // The sender's stream: the id of its first message since its channel
    // started or was reset. Messages are delivered in msg_id order from it.
    uint32_t stream = 0;
    uint32_t msg_id = 0;
    uint16_t index = 0;
    uint16_t count = 1;
    RelKind kind = RelKind::Spawn;
    std::vector<uint8_t> chunk;
};
struct RelAck {
    uint32_t msg_id = 0;
    uint16_t index = 0;
};

using Body = std::variant<Hello, Welcome, Bye, Ping, Pong, PlayerState, GameEvent, RelData, RelAck>;

struct Packet {
    uint16_t version = kVersion;  // decoded: != kVersion only for a Hello/Welcome of another version
    uint32_t seq = 0;
    uint32_t send_ms = 0;
    Body body;
};

Type type_of(const Body& body);
const char* type_name(Type type);

std::vector<uint8_t> encode(const Packet& packet);

// Returns nullopt for anything malformed: wrong magic, unknown type,
// truncated body, non-finite floats, oversize datagram, or another version
// (except a Hello/Welcome: only its name is read, see Packet::version).
// Unknown GameEvent and RelData kinds decode (newer peers): the session drops
// them, and acknowledges reliable ones so the sender does not resend forever.
std::optional<Packet> decode(std::span<const uint8_t> bytes);

// What a receiver needs to load a copy of the sender's character: the
// sender's own ActorLoadDataAck payloads (user actor + body) and the keys
// inside them, which the receiver replaces with keys of its own.
struct SpawnInfo {
    uint32_t generation = 0;  // increases with every spawn the sender announces
    uint32_t user_key = 0;
    uint32_t player_key = 0;
    uint32_t body_key = 0;
    Vec3 pos;
    Quat rot;
    std::vector<uint8_t> user;
    std::vector<uint8_t> body;
    // OtherEquipItemAck payload with every equipment slot changed since the
    // templates were captured (empty if none).
    std::vector<uint8_t> equip;
    // The sender's horse: its single ActorLoadDataAck payload (empty if none
    // was captured), its key and where it is now.
    uint32_t horse_key = 0;
    Vec3 horse_pos;
    std::vector<uint8_t> horse;
};
std::vector<uint8_t> encode_spawn(const SpawnInfo& info);
std::optional<SpawnInfo> decode_spawn(std::span<const uint8_t> bytes);

}  // namespace cdmp::proto
