#pragma once
// [session2] housing_share = 0 (default) | probe | 1, HOST. Pure logic (tests: tests/optd_housing_share_tests.cpp).
//
// The houses and their furniture are per character: at login the server sends each client its own character's set
// (live, 3549, 2026-11-06, both copies): SyncPlayerHouseDataListAck (its houses: house key -> housing stage),
// AddHousingGimmickAck, AddHousingPlacedFieldGimmickSaveKeyListAck (per house: the placed field gimmicks' save keys),
// SetLoadedHousingObjectSyncDataIdMaxAck, SyncHousingPlacedSceneObjectListAck (per housing stage: the placed objects,
// 0xA0-byte records in the stage's grid, in parts) and SyncHousingPlacedPathDataListAck. A guest is user 2 at the host's
// server with ITS OWN save (slot 204), so it gets its own houses: it never sees what the host built or placed.
// With 1 the host's server sends user 2 the host's set instead: every housing Ack of these opcodes the server writes for
// user 2 is dropped, and the host client's latest packets of the same opcode (its login burst, then its live updates)
// are queued for user 2 with the host's character key replaced by user 2's. Live updates of the host's housing
// (place / remove / clear ...) reach user 2 the same way.
//
// Wire: logical opcodes (2976 ids; the ones added in 3527 are 0x8000 + native). The owner character key is in the
// first 8 bytes of the payload (after a kind / flags byte or at 0).
// Build 1.0.0.3663 (static, 2026-11-13; never run): 3663 renumbered the natives, not these ids. The sniffer's tap and
// the server's out path hand this module logical packets (native_opcode::decode_copy / decode_packet) and the guest
// re-encodes what server_push_extra queues, so nothing here changes. Every id below is in kEntries3663 with the same
// message name as in 3527 (3663 natives: 35245 -> 2182, 2733 -> 2965, 2500 -> 2836, 2408 -> 2943, 2623 -> 2739,
// 2344 -> 2669, ...). The 3663 client's 2733 handler (0xCF7740) still reads [flags u8][key u32][stage u32] and then
// 160-byte records (the count is (size - 9) / 160).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace cdmp::session2::hsh {

inline constexpr size_t kHeader = 5;

// The set a client gets at login (and again on some requests).
inline constexpr std::array<uint16_t, 6> kLoginSet = {
    35245,  // SyncPlayerHouseDataListAck
    2719,   // AddHousingGimmickAck
    2343,   // AddHousingPlacedFieldGimmickSaveKeyListAck
    35741,  // SetLoadedHousingObjectSyncDataIdMaxAck
    2733,   // SyncHousingPlacedSceneObjectListAck
    35274,  // SyncHousingPlacedPathDataListAck
};
// Changes of the owner's housing while it plays.
inline constexpr std::array<uint16_t, 13> kUpdates = {
    2623,   // PlaceHousingItemAck
    2859,   // RemoveHousingGimmickAck
    2902,   // RemoveHousingPlacedFieldGimmickSaveKeyListAck
    2398,   // ClearHousingSyncDataAck
    2500,   // UpdateWaitingCustomHousingGimmickSyncDataListAck
    3085,   // DiscardHousingGimmickAck
    3087,   // PushHousingObjectToInventoryAck
    2182,   // ChangeHouseAck
    2187,   // SyncAndConsumeCustomHouseSyncDataAck
    2971,   // ChangeCustomHouseOwnerGamePlayTriggerInfoAck
    35426,  // ChangeHouseOwnerCharacterAck
    35006,  // ChangeHousingObjectOwnerGamePlayTriggerInfoAck
    34973,  // SyncAndConsumeHousingPathDataAck
};

inline uint16_t op_of(std::span<const uint8_t> p) noexcept {
    return p.size() >= kHeader ? static_cast<uint16_t>(p[0] | p[1] << 8) : 0;
}
template <size_t N>
bool in(const std::array<uint16_t, N>& set, uint16_t op) noexcept {
    for (const uint16_t o : set) {
        if (o == op) return true;
    }
    return false;
}
inline bool is_login(uint16_t op) noexcept { return in(kLoginSet, op); }
inline bool is_update(uint16_t op) noexcept { return in(kUpdates, op); }
inline bool is_housing(uint16_t op) noexcept { return is_login(op) || is_update(op); }

// Live changes of the host's housing reach user 2 only with housing_share=live, never with 1 (2026-11-06, 3576: the
// host's UpdateWaitingCustomHousingGimmickSyncDataListAck 2500 -- sent when its client spawns its own housing gimmicks,
// on approaching its house and in the design mode -- crashed the guest's client: it names objects by sync ids only the
// host's client created). The login set is the only thing housing_share=1 gives.
inline constexpr uint16_t kWaitingSyncList = 2500;
// `allowed` (housing_share_live_ops): the live changes to forward, one at a time while each is tested; empty = every
// update but 2500. 2500 is never forwarded, whatever the list says.
inline bool forward_live(bool live_mode, uint16_t op, std::span<const uint16_t> allowed = {}) noexcept {
    if (!live_mode || !is_update(op) || op == kWaitingSyncList) return false;
    if (allowed.empty()) return true;
    for (const uint16_t a : allowed) {
        if (a == op) return true;
    }
    return false;
}
// "2623, 2859" -> {2623, 2859}: the opcodes `ok` accepts; anything else is left out (and counted in `bad`).
template <class Ok>
std::vector<uint16_t> parse_ops(std::string_view text, Ok&& ok, size_t* bad = nullptr) {
    std::vector<uint16_t> out;
    size_t wrong = 0;
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && (text[i] == ',' || text[i] == ' ' || text[i] == '\t')) ++i;
        if (i >= text.size()) break;
        uint32_t v = 0;
        bool digits = false, junk = false;
        while (i < text.size() && text[i] != ',' && text[i] != ' ' && text[i] != '\t') {
            if (text[i] >= '0' && text[i] <= '9' && v < 100000) {
                v = v * 10 + static_cast<uint32_t>(text[i] - '0');
                digits = true;
            } else {
                junk = true;
            }
            ++i;
        }
        if (!digits || junk || v > 0xFFFF || !ok(static_cast<uint16_t>(v))) {
            ++wrong;
        } else {
            out.push_back(static_cast<uint16_t>(v));
        }
    }
    if (bad) *bad = wrong;
    return out;
}
// housing_share_live_ops: live-change opcodes, never 2500.
inline std::vector<uint16_t> parse_live_ops(std::string_view text, size_t* bad = nullptr) {
    return parse_ops(text, [](uint16_t op) { return is_update(op) && op != kWaitingSyncList; }, bad);
}

// housing_share_rekey: which of the host's housing packets get user 2's character key. "0" or empty = none (the house
// stays the host's; the default), "1" = all (the guest owns the house), or a list of housing opcodes, e.g. "35245,2733".
// 3576, two copies, 2026-11-07: 1 and 35245,2733 show the guest the whole house (walls, roof), but its client then
// crashes when the host opens the construction mode (exe+0x4632EA / +0x46313D, the housing tick on entries of sync ids
// it never spawned); 0 shows the host's props (doors, furniture, pets: the gimmicks its client spawns, which the server
// shows everyone) and survived the approach, the construction mode and an edit.
struct RekeySet {
    bool all = false;
    std::vector<uint16_t> ops;
    bool has(uint16_t op) const noexcept {
        if (all) return true;
        for (const uint16_t o : ops) {
            if (o == op) return true;
        }
        return false;
    }
};
inline RekeySet parse_rekey(std::string_view text, size_t* bad = nullptr) {
    RekeySet r;
    if (bad) *bad = 0;
    if (text == "1") {
        r.all = true;
    } else if (!text.empty() && text != "0") {
        r.ops = parse_ops(text, [](uint16_t op) { return is_housing(op); }, bad);
    }
    return r;
}

inline bool is_character_key(uint32_t k) noexcept { return (k & 0xFFF00000u) == 0xA0100000u; }

// The owner character key of a housing packet: the first u32 in payload[0..8) that is a character key.
inline std::optional<uint32_t> owner_of(std::span<const uint8_t> p) noexcept {
    if (p.size() < kHeader + 4) return std::nullopt;
    const size_t end = std::min(p.size(), kHeader + 8);
    for (size_t i = kHeader; i + 4 <= end; ++i) {
        uint32_t k = 0;
        std::memcpy(&k, p.data() + i, 4);
        if (is_character_key(k)) return k;
    }
    return std::nullopt;
}

// A copy of `p` with every 4-byte occurrence of `from` in its payload replaced by `to`; the count in *n.
inline std::vector<uint8_t> rekey(std::span<const uint8_t> p, uint32_t from, uint32_t to, size_t* n = nullptr) {
    std::vector<uint8_t> v(p.begin(), p.end());
    size_t c = 0;
    for (size_t i = kHeader; i + 4 <= v.size(); ++i) {
        uint32_t x = 0;
        std::memcpy(&x, v.data() + i, 4);
        if (x == from) {
            std::memcpy(v.data() + i, &to, 4);
            ++c;
            i += 3;
        }
    }
    if (n) *n = c;
    return v;
}

// Construction mode (3576, 2026-11-07, the host alone at its house, packet log): confirming an edit sends the server
// nothing item by item. The host's CLIENT sends the whole new object list of the edited housing stage,
// SyncHousingPlacedSceneObjectListReq 2408 (parts of up to 32 KB: [flags u8, 1 then 3 on the last][stage u32]
// [records...]), and the server only answers with small Acks (RemoveItemToInventoryAck for the cost,
// RemoveHousingGimmickAck 2859 with the owner key, SyncAndConsumeCustomHouseSyncDataAck 2187). The server sends nobody
// the new list, so no Ack forwarding (housing_share=live) can show an edit to the guest. The login Ack 2733 is the same
// list with the owner's key after the flags byte: [flags][key u32][stage u32][records...] (the Req part of 32645 B and
// the login Ack part of 32649 B of the same stage, same night). housing_share_edits=1 turns each Req part into that Ack.
inline constexpr uint16_t kSceneListReq = 2408;
inline constexpr uint16_t kSceneListAck = 2733;
inline constexpr size_t kMaxPacket = 0x8000;  // the game's packet buffers (and the sniffer's copy)

// The 2733 Ack of one 2408 Req part, owned by `key`; nullopt if it is not a whole 2408 part or would not fit.
inline std::optional<std::vector<uint8_t>> scene_req_to_ack(std::span<const uint8_t> req, uint32_t key) {
    if (op_of(req) != kSceneListReq || req.size() < kHeader + 5) return std::nullopt;
    const size_t pay = req.size() - kHeader;
    if (static_cast<size_t>(req[3] | req[4] << 8) != pay) return std::nullopt;
    const size_t out_pay = pay + 4;
    if (kHeader + out_pay > kMaxPacket) return std::nullopt;
    std::vector<uint8_t> v;
    v.reserve(kHeader + out_pay);
    v.push_back(static_cast<uint8_t>(kSceneListAck & 0xFF));
    v.push_back(static_cast<uint8_t>(kSceneListAck >> 8));
    v.push_back(0xFF);  // slot -1, as the server writes its Acks
    v.push_back(static_cast<uint8_t>(out_pay & 0xFF));
    v.push_back(static_cast<uint8_t>(out_pay >> 8));
    v.push_back(req[kHeader]);
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>(key >> (8 * i)));
    v.insert(v.end(), req.begin() + kHeader + 1, req.end());
    return v;
}
inline bool is_last_part(uint8_t flags) noexcept { return (flags & 2) != 0; }
// The housing stage of a 2733 Ack part.
inline std::optional<uint32_t> stage_of_list_ack(std::span<const uint8_t> ack) noexcept {
    if (op_of(ack) != kSceneListAck || ack.size() < kHeader + 9) return std::nullopt;
    uint32_t s = 0;
    std::memcpy(&s, ack.data() + kHeader + 5, 4);
    return s;
}

// The guest's own spawn of the housing gimmicks (3576, 2026-11-07, two copies). With the host's set re-keyed to it, the
// guest's client is the owner of the host's house: approaching it, it asks the server to spawn the placed housing
// gimmicks itself (SpawnPlacedHousingGimmickFromSyncDataReq 2492 + SpawnOrUnspawnHousingGimmickReq 2446) and the server
// answers it with its own waiting list (2500: the same sync ids, 0x80..., the host's client already spawned). ~20 s
// later, 80 m from the house, the guest's client crashed in the housing tick (exe+0x462BDA: an entry for sync id 0x84
// emptied by the release of the object it replaced, 0x3D7FA0 -- the release of the 2026-11-06 crash too).
// housing_share_guest_spawn=0 drops those two requests of user 2 at the host's server: only the host's client spawns.
inline constexpr std::array<uint16_t, 2> kGuestSpawnReqs = {
    2492,  // SpawnPlacedHousingGimmickFromSyncDataReq
    2446,  // SpawnOrUnspawnHousingGimmickReq
};
inline bool is_guest_spawn_req(uint16_t op) noexcept { return in(kGuestSpawnReqs, op); }

// The records of a 2733 part (3576, the host's house, 282 records, 2026-11-07): after [flags][key u32][stage u32], 160-byte
// records [sync id u32][...]; +0x25 is a category: 0 = structure (floors, walls, roof, paths: never in a waiting list),
// 4 = objects the client spawns as gimmicks (doors, furniture...: the 11 ids of the host's 2500 waiting list were all
// category 4), 2 = one other. Slots with id 0xFFFFFFFF follow the records in the last part. housing_share_drop_gimmicks
// takes the category-4 records out of what user 2 gets, so a guest that owns the house (rekey 2733) builds its walls
// and has no gimmick of its own to spawn: the host's are shown to it by the server like any gimmick.
inline constexpr size_t kSceneRecord = 160;
inline constexpr size_t kSceneRecordsAt = kHeader + 9;  // flags, key, stage
inline constexpr size_t kRecordCategory = 0x25;
inline constexpr uint8_t kCategoryGimmick = 4;
enum class DropGimmicks : uint8_t { None, All, Waiting };
inline DropGimmicks parse_drop_gimmicks(std::string_view v) noexcept {
    if (v == "all" || v == "1") return DropGimmicks::All;
    if (v == "waiting") return DropGimmicks::Waiting;
    return DropGimmicks::None;
}
// The sync ids of a 2500 (UpdateWaitingCustomHousingGimmickSyncDataListAck): [kind][key u32][stage u32][ids u32...].
inline std::vector<uint32_t> waiting_ids(std::span<const uint8_t> p, uint32_t* stage = nullptr) {
    std::vector<uint32_t> ids;
    if (p.size() < kHeader + 9) return ids;
    if (stage) std::memcpy(stage, p.data() + kHeader + 5, 4);
    for (size_t o = kHeader + 9; o + 4 <= p.size(); o += 4) {
        uint32_t v = 0;
        std::memcpy(&v, p.data() + o, 4);
        ids.push_back(v);
    }
    return ids;
}
// A copy of a 2733 part without its gimmick records: every category-4 record (`waiting` empty) or only those whose sync
// id is in `waiting`. The part is returned unchanged if its records do not tile it exactly (another format).
inline std::vector<uint8_t> drop_gimmick_records(std::span<const uint8_t> p, std::span<const uint32_t> waiting,
                                                 size_t* dropped = nullptr) {
    if (dropped) *dropped = 0;
    if (op_of(p) != kSceneListAck || p.size() < kSceneRecordsAt || (p.size() - kSceneRecordsAt) % kSceneRecord != 0) {
        return std::vector<uint8_t>(p.begin(), p.end());
    }
    std::vector<uint8_t> v(p.begin(), p.begin() + kSceneRecordsAt);
    size_t n = 0;
    for (size_t o = kSceneRecordsAt; o < p.size(); o += kSceneRecord) {
        uint32_t id = 0;
        std::memcpy(&id, p.data() + o, 4);
        bool drop = id != 0xFFFFFFFFu && p[o + kRecordCategory] == kCategoryGimmick;
        if (drop && !waiting.empty()) {
            drop = false;
            for (const uint32_t w : waiting) {
                if (w == id) drop = true;
            }
        }
        if (drop) {
            ++n;
        } else {
            v.insert(v.end(), p.begin() + o, p.begin() + o + kSceneRecord);
        }
    }
    const size_t pay = v.size() - kHeader;
    v[3] = static_cast<uint8_t>(pay & 0xFF);
    v[4] = static_cast<uint8_t>(pay >> 8);
    if (dropped) *dropped = n;
    return v;
}

// The host's latest packets of one opcode: a burst (packets less than kBurstMs apart) replaces the previous one.
inline constexpr uint64_t kBurstMs = 3000;
struct Slot {
    std::vector<std::vector<uint8_t>> packets;
    uint64_t last_ms = 0;
};
inline void record(Slot& s, std::span<const uint8_t> p, uint64_t now_ms) {
    if (!s.last_ms || now_ms - s.last_ms > kBurstMs) s.packets.clear();
    if (s.packets.size() < 64) s.packets.emplace_back(p.begin(), p.end());
    s.last_ms = now_ms;
}

// The recorded 2733 parts with `stage`'s replaced by `parts` (where its first old part was; at the end if it had
// none). The other stages (other houses) stay as the login gave them. last_ms is left alone: this is not a login burst.
inline void replace_stage(Slot& s, uint32_t stage, const std::vector<std::vector<uint8_t>>& parts) {
    std::vector<std::vector<uint8_t>> out;
    bool placed = false;
    for (auto& p : s.packets) {
        if (stage_of_list_ack(p) == stage) {
            if (!placed) out.insert(out.end(), parts.begin(), parts.end());
            placed = true;
        } else {
            out.push_back(std::move(p));
        }
    }
    if (!placed) out.insert(out.end(), parts.begin(), parts.end());
    if (out.size() > 64) out.resize(64);
    s.packets = std::move(out);
}

// The house plot's scene phase (3576, 2026-11-12): the host's client loads House_Del_0002_Phase04_00 (the developed
// plot: level ground, grass), the guest's loaded House_Del_0002_Phase00_00 (the plot before the house: a pond). The
// phase levels of House_Del_0002 are bound to the level key 0xF439B (in the level data, host memory), and the client
// gets each level's state in ChangeGameLevelStateAck (logical 2344, native 3081): [flags u8 = 4][owner u32][u32 = 1]
// [u8 = 1][(level key u32, state hash u32, u8)...]; 0xF439B is 0xAD24F618 for both copies. The host's client gets it at
// login, before it travels to its house; user 2's got it only at the end of a load, 60 ms after it had picked
// Phase00 (two copies, 13:33 run). Trigger states (2238, all 85 of them) did not change the phase.
// housing_share_level_states=1 gives user 2 the host's level states with its house list, at login.
inline constexpr uint16_t kLevelStateAck = 2344;
inline constexpr size_t kLevelHead = 10;   // flags, owner, u32, u8
inline constexpr size_t kLevelEntry = 9;   // level key, state hash, u8
inline constexpr size_t kLevelMaxEntries = 3500;  // a packet's payload stays under 32710 bytes
// Every level the host's client was told of, its latest state; the header bytes after the owner from its latest packet.
struct LevelStates {
    std::array<uint8_t, 5> head{};
    std::map<uint32_t, std::array<uint8_t, 5>> levels;
};
// false (nothing kept) if `p` is not a whole 2344.
inline bool merge_level_states(LevelStates& s, std::span<const uint8_t> p) {
    if (op_of(p) != kLevelStateAck || p.size() < kHeader + kLevelHead ||
        (p.size() - kHeader - kLevelHead) % kLevelEntry != 0) {
        return false;
    }
    std::memcpy(s.head.data(), p.data() + kHeader + 5, 5);
    for (size_t o = kHeader + kLevelHead; o + kLevelEntry <= p.size(); o += kLevelEntry) {
        uint32_t k = 0;
        std::memcpy(&k, p.data() + o, 4);
        auto& v = s.levels[k];
        std::memcpy(v.data(), p.data() + o + 4, 5);
    }
    return true;
}
// The merged states as 2344 packets for `owner` (more than one only past kLevelMaxEntries levels).
inline std::vector<std::vector<uint8_t>> level_states_for(const LevelStates& s, uint32_t owner) {
    std::vector<std::vector<uint8_t>> out;
    auto it = s.levels.begin();
    while (it != s.levels.end()) {
        std::vector<uint8_t> v = {static_cast<uint8_t>(kLevelStateAck), static_cast<uint8_t>(kLevelStateAck >> 8), 0xFF,
                                  0, 0, 0x04};
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>(owner >> (8 * i)));
        v.insert(v.end(), s.head.begin(), s.head.end());
        for (size_t n = 0; it != s.levels.end() && n < kLevelMaxEntries; ++it, ++n) {
            for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>(it->first >> (8 * i)));
            v.insert(v.end(), it->second.begin(), it->second.end());
        }
        const size_t pay = v.size() - kHeader;
        v[3] = static_cast<uint8_t>(pay & 0xFF);
        v[4] = static_cast<uint8_t>(pay >> 8);
        out.push_back(std::move(v));
    }
    return out;
}

}  // namespace cdmp::session2::hsh
